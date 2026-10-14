package providerresult

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"

	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/celld"
	"github.com/hancomac/circulusd/internal/dependency"
	"github.com/hancomac/circulusd/internal/effectledger"
	"github.com/hancomac/circulusd/internal/mcpgateway"
	"github.com/hancomac/circulusd/internal/modelgateway"
	"github.com/hancomac/circulusd/internal/stateappbroker"
	"github.com/hancomac/circulusd/internal/stateappclient"
)

const (
	maximumPersistedRecordBytes    = MaximumCommittedLedgerResultBytes + stateappclient.MaximumProviderResultBytes + 4096
	maximumPersistenceReceiptBytes = 128
	persistenceProtocol            = "circulus.provider-result-record.v1"
	persistenceReceiptID           = "provider-result.publish.v1"
)

var (
	ErrRecordConflict    = errors.New("provider result: immutable committed record conflict")
	ErrRecordUnavailable = errors.New("provider result: committed record unavailable")
)

// TransactionStorage must challenge the exact source that performs both celld
// transactions and barriers. A native storage driver is supplied by trusted
// composition; this interface does not qualify process-local/file test stores.
type TransactionStorage interface {
	celld.Storage
	dependency.ProductionProbe
}

// RecordCommit acknowledges only an immutable record publication after its
// durability barrier. It grants no Session settlement or provider-start permit.
type RecordCommit struct {
	Revision     uint64
	RecordDigest broker.Digest
	Replayed     bool
}

type PersistentRecords struct {
	storage    TransactionStorage
	binding    dependency.Verified[TransactionStorage]
	mcpBounds  mcpgateway.Bounds
	mcpEnabled bool
}

// NewPersistentRecords binds all record operations and its native probe to one
// independently qualified transaction source. Command-receipt and effect-
// lifecycle evidence must both attest that source's atomic domain. The resulting
// Records object requires a fresh qualification before NewRecordResolver uses
// it; no signed evidence or live proof is minted by this adapter.
func NewPersistentRecords(binding dependency.Verified[TransactionStorage], config RecordResolverConfig) (*PersistentRecords, error) {
	storage, descriptor, err := binding.Open()
	if err != nil || nilInterface(storage) ||
		!slices.Contains(descriptor.AtomicGroups, dependency.AtomicCommandReceipt) ||
		!slices.Contains(descriptor.AtomicGroups, dependency.AtomicEffectLifecycle) {
		return nil, dependency.ErrUnverifiedDependency
	}
	store := &PersistentRecords{storage: storage, binding: binding}
	if config.MCPBounds != nil {
		bounds := *config.MCPBounds
		if err := mcpgateway.ValidateSessionPiResultBounds(bounds); err != nil {
			return nil, dependency.ErrInvalidConfiguration
		}
		store.mcpBounds, store.mcpEnabled = bounds, true
	}
	return store, nil
}

func (store *PersistentRecords) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	if err := store.ready(ctx); err != nil {
		return dependency.ProbeResponse{}, err
	}
	response, err := store.storage.ProbeProduction(ctx, challenge)
	if err != nil {
		return dependency.ProbeResponse{}, recordError(ctx, err)
	}
	if err := ctx.Err(); err != nil {
		return dependency.ProbeResponse{}, err
	}
	return response, nil
}

// WriteCommittedResult is a trusted provider-terminal publication operation,
// not a public admission endpoint. The producer must authenticate the original
// terminal facts and their exact reference binding before calling it. This
// method never invokes providers or changes effect phases. It validates and
// stores the supplied immutable facts and Pi body together; it invents no model
// metadata or costs and cannot replace an existing publication.
func (store *PersistentRecords) WriteCommittedResult(ctx context.Context, input CommittedRecord) (RecordCommit, error) {
	if err := store.ready(ctx); err != nil {
		return RecordCommit{}, err
	}
	record, err := store.validateRecord(input)
	if err != nil {
		return RecordCommit{}, err
	}
	state, err := encodePersistedRecord(record)
	if err != nil {
		return RecordCommit{}, stateappclient.ErrInvalidResponse
	}
	objectID, err := persistenceObjectID(record.Request)
	if err != nil {
		return RecordCommit{}, broker.ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return RecordCommit{}, err
	}
	digest := broker.Digest(sha256.Sum256(state))
	var invoked, complete, replayed bool
	commit, err := store.storage.Transaction(ctx, objectID, func(tx celld.Transaction) error {
		invoked, complete, replayed = true, false, false
		if nilInterface(tx) {
			return celld.ErrStorageContract
		}
		stored, exists, err := readPersistedRecord(tx)
		if err != nil {
			return err
		}
		if exists {
			// A receipt is accepted only after its complete state and terminal
			// body have passed integrity and normalization checks again.
			existing, err := decodePersistedRecord(stored)
			if err != nil {
				return celld.ErrStorageContract
			}
			if _, err := store.validateRecord(existing); err != nil {
				return celld.ErrStorageContract
			}
			if !bytes.Equal(stored, state) {
				return ErrRecordConflict
			}
			replayed = true
		} else {
			if err := tx.WriteState(bytes.Clone(state)); err != nil {
				return err
			}
			if err := tx.WriteReceipt(persistenceReceiptID, celld.StoredReceipt{
				CommandDigest: celld.Digest(digest), Response: persistenceReceipt(digest),
			}); err != nil {
				return err
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		complete = true
		return nil
	})
	if err := store.confirm(ctx, objectID, invoked, complete, commit, err); err != nil {
		return RecordCommit{}, err
	}
	return RecordCommit{Revision: commit.Revision, RecordDigest: digest, Replayed: replayed}, nil
}

// ReadCommittedResult verifies the full stored record and its atomic receipt,
// then confirms the exact transaction token's barrier before exposing any bytes.
// It has no cache, retry authority or process-local durability fallback.
func (store *PersistentRecords) ReadCommittedResult(ctx context.Context, request stateappbroker.ResultRequest) (CommittedRecord, error) {
	if err := store.ready(ctx); err != nil {
		return CommittedRecord{}, err
	}
	objectID, err := persistenceObjectID(request)
	if err != nil {
		return CommittedRecord{}, broker.ErrInvalidRequest
	}
	var invoked, complete bool
	var result CommittedRecord
	commit, err := store.storage.Transaction(ctx, objectID, func(tx celld.Transaction) error {
		invoked, complete, result = true, false, CommittedRecord{}
		if nilInterface(tx) {
			return celld.ErrStorageContract
		}
		stored, exists, err := readPersistedRecord(tx)
		if err != nil {
			return err
		}
		if !exists {
			return ErrRecordUnavailable
		}
		record, err := decodePersistedRecord(stored)
		if err != nil {
			return celld.ErrStorageContract
		}
		if record.Request != request {
			return broker.ErrFenceMismatch
		}
		result, err = store.validateRecord(record)
		if err != nil {
			return celld.ErrStorageContract
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		complete = true
		return nil
	})
	if err := store.confirm(ctx, objectID, invoked, complete, commit, err); err != nil {
		return CommittedRecord{}, err
	}
	return result, nil
}

func (store *PersistentRecords) ready(ctx context.Context) error {
	if ctx == nil {
		return broker.ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if store == nil || nilInterface(store.storage) {
		return dependency.ErrUnverifiedDependency
	}
	_, _, err := store.binding.Open()
	return err
}

func (store *PersistentRecords) confirm(ctx context.Context, objectID string, invoked, complete bool, commit celld.CommitToken, transactionErr error) error {
	if transactionErr != nil {
		return persistenceError(ctx, transactionErr)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !invoked || !complete || commit.ObjectID != objectID || commit.Revision == 0 {
		return celld.ErrStorageContract
	}
	if err := store.storage.DurabilityBarrier(ctx, commit); err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
		return celld.ErrDurabilityBarrier
	}
	return ctx.Err()
}

func (store *PersistentRecords) validateRecord(record CommittedRecord) (CommittedRecord, error) {
	if err := stateappclient.ValidateProviderResultRequest(requestWire(record.Request)); err != nil {
		return CommittedRecord{}, broker.ErrInvalidRequest
	}
	if record.Status != effectledger.TerminalCommitted {
		return CommittedRecord{}, broker.ErrInvalidEffectState
	}
	if record.Service != broker.ServiceModel && (record.Service != broker.ServiceMCP || !store.mcpEnabled) {
		return CommittedRecord{}, ErrUnsupportedService
	}
	if len(record.LedgerResult) < 1 || len(record.LedgerResult) > MaximumCommittedLedgerResultBytes ||
		len(record.CanonicalCBOR) < 1 || len(record.CanonicalCBOR) > stateappclient.MaximumProviderResultBytes {
		return CommittedRecord{}, stateappclient.ErrInvalidResponse
	}
	ledger, body := bytes.Clone(record.LedgerResult), bytes.Clone(record.CanonicalCBOR)
	if broker.Digest(sha256.Sum256(body)) != record.PayloadDigest || !validBody(body) {
		return CommittedRecord{}, stateappclient.ErrInvalidResponse
	}
	var err error
	if record.Service == broker.ServiceModel {
		body, err = modelgateway.ValidateSessionPiResult(ledger, body)
	} else {
		body, err = mcpgateway.ValidateSessionPiResult(ledger, body, store.mcpBounds)
	}
	if err != nil {
		return CommittedRecord{}, stateappclient.ErrInvalidResponse
	}
	record.LedgerResult, record.CanonicalCBOR = ledger, body
	return record, nil
}

func persistenceObjectID(request stateappbroker.ResultRequest) (string, error) {
	if err := stateappclient.ValidateProviderResultRequest(requestWire(request)); err != nil {
		return "", err
	}
	// Each occurrence owns one publication. Relabeling its request digest,
	// external commit or artifact cannot create another object beside it.
	key, err := canonical.Encode(canonical.Array{persistenceProtocol, request.TenantID.String(), request.WorkspaceID.String(),
		request.SessionID.String(), request.EffectID.String(), request.InvocationID.String()}, canonical.Options{MaxBytes: 1024, MaxDepth: 2, MaxItems: 16})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(key)
	return "provider-result.v1/" + hex.EncodeToString(digest[:]), nil
}

func encodePersistedRecord(record CommittedRecord) ([]byte, error) {
	return canonical.Encode(canonical.Map{"protocol": persistenceProtocol, "version": int64(1), "request": requestValue(record.Request),
		"service": string(record.Service), "status": string(record.Status), "ledgerResult": canonical.Bytes(record.LedgerResult),
		"payloadDigest": canonical.Bytes(record.PayloadDigest[:]), "canonicalCbor": canonical.Bytes(record.CanonicalCBOR)},
		canonical.Options{MaxBytes: maximumPersistedRecordBytes, MaxDepth: 4, MaxItems: 64})
}

func decodePersistedRecord(state []byte) (CommittedRecord, error) {
	value, err := canonical.Decode(state, canonical.Options{MaxBytes: maximumPersistedRecordBytes, MaxDepth: 4, MaxItems: 64})
	if err != nil {
		return CommittedRecord{}, celld.ErrStorageContract
	}
	m, ok := value.(canonical.Map)
	if !ok || len(m) != 8 || m["protocol"] != persistenceProtocol || m["version"] != int64(1) {
		return CommittedRecord{}, celld.ErrStorageContract
	}
	request, ok := m["request"].(canonical.Map)
	if !ok || len(request) != 8 {
		return CommittedRecord{}, celld.ErrStorageContract
	}
	binding, err := parseRequest(request)
	if err != nil {
		return CommittedRecord{}, celld.ErrStorageContract
	}
	service, serviceOK := m["service"].(string)
	status, statusOK := m["status"].(string)
	ledger, ledgerOK := m["ledgerResult"].(canonical.Bytes)
	digest, digestOK := m["payloadDigest"].(canonical.Bytes)
	body, bodyOK := m["canonicalCbor"].(canonical.Bytes)
	if !serviceOK || !statusOK || !ledgerOK || !digestOK || len(digest) != 32 || !bodyOK ||
		len(ledger) < 1 || len(ledger) > MaximumCommittedLedgerResultBytes || len(body) < 1 || len(body) > stateappclient.MaximumProviderResultBytes {
		return CommittedRecord{}, celld.ErrStorageContract
	}
	result := CommittedRecord{Request: binding, Service: broker.EffectService(service), Status: effectledger.TerminalStatus(status),
		LedgerResult: ledger, CanonicalCBOR: body}
	copy(result.PayloadDigest[:], digest)
	return result, nil
}

func persistenceReceipt(digest broker.Digest) []byte {
	// This fixed response binds the exact record, rather than carrying a second
	// copy of its potentially large body or a settlement capability.
	return append([]byte("circulus.provider-result.receipt.v1\x00"), digest[:]...)
}

func readPersistedRecord(tx celld.Transaction) ([]byte, bool, error) {
	state, err := tx.ReadState()
	if err != nil {
		return nil, false, err
	}
	if len(state) > maximumPersistedRecordBytes {
		return nil, false, celld.ErrStorageContract
	}
	receipt, found, err := tx.LookupReceipt(persistenceReceiptID)
	if err != nil {
		return nil, false, err
	}
	if len(state) == 0 && !found {
		return nil, false, nil
	}
	if len(state) == 0 || !found || len(receipt.Response) > maximumPersistenceReceiptBytes || len(receipt.CapabilityClaims) != 0 {
		return nil, false, celld.ErrStorageContract
	}
	state = bytes.Clone(state)
	digest := broker.Digest(sha256.Sum256(state))
	if receipt.CommandDigest != celld.Digest(digest) || !bytes.Equal(receipt.Response, persistenceReceipt(digest)) {
		return nil, false, celld.ErrStorageContract
	}
	return state, true, nil
}

func persistenceError(ctx context.Context, err error) error {
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	for _, safe := range []error{ErrRecordConflict, ErrRecordUnavailable, celld.ErrStorageContract, celld.ErrDurabilityBarrier,
		celld.ErrStateTooLarge, broker.ErrFenceMismatch, broker.ErrInvalidRequest, broker.ErrInvalidEffectState, ErrUnsupportedService} {
		if errors.Is(err, safe) {
			return safe
		}
	}
	return recordError(ctx, err)
}

var _ Records = (*PersistentRecords)(nil)
