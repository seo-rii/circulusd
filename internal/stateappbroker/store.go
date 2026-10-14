// Package stateappbroker adapts the single authoritative Session transaction
// domain to broker.DurableStore. It owns no program counter or receipt cache.
package stateappbroker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"time"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/dependency"
	"github.com/hancomac/circulusd/internal/identity"
	"github.com/hancomac/circulusd/internal/stateappclient"
	"github.com/hancomac/circulusd/internal/stateappcodec"
)

type ResultRequest struct {
	TenantID, WorkspaceID, SessionID, EffectID, InvocationID identity.ID
	RequestDigest                                            broker.Digest
	ExternalCommitID, ResultRef                              identity.ID
}
type Result struct {
	Request       ResultRequest
	PayloadDigest broker.Digest
	CanonicalCBOR []byte
}

// ResultResolver returns the immutable, authenticated body for this complete
// reference identity. The artifact identifier alone contains no engine input.
type ResultResolver interface {
	ResolveResult(context.Context, ResultRequest) (Result, error)
	dependency.ProductionProbe
}

// ProductionDurableStore lets bootstrap seal the same object that serves all
// DurableStore operations, rather than an unrelated probe-only object.
type ProductionDurableStore interface {
	broker.DurableStore
	dependency.ProductionProbe
}

type Config struct {
	Scope            stateappclient.BrokerScope
	UserID           identity.ID
	EngineStepLimits broker.EngineStepBudget
	Results          dependency.Verified[ResultResolver]
}

type stateClient interface {
	ExecuteSessionBroker(context.Context, stateappclient.BrokerRequest) (canonical.Value, error)
	ReadSessionBlob(context.Context, stateappclient.ReadSessionBlobRequest) (*stateappclient.SessionBlob, error)
	dependency.ProductionProbe
}

type Store struct {
	client  stateClient
	scope   stateappclient.BrokerScope
	user    identity.ID
	limits  broker.EngineStepBudget
	codec   *stateappcodec.Codec
	results ResultResolver
}

// New constructs a candidate around the exact immutable client serving both
// operations and its native production challenge. A service graph must verify
// this Store independently before it can enable admission or provider I/O.
func New(client *stateappclient.Client, config Config) (*Store, error) {
	if !client.SessionBrokerConfigured() {
		return nil, stateappclient.ErrInvalidConfig
	}
	return newStore(client, config)
}

func newStore(client stateClient, config Config) (*Store, error) {
	if isNil(client) || config.UserID.Kind() != identity.Subject || config.UserID.String() != config.Scope.ActorSubjectID || config.Scope.ExpectedAuthorizationGeneration < 1 ||
		config.EngineStepLimits.MaximumEvents != 1 || config.EngineStepLimits.MaximumEphemeralBytes < 1 || config.EngineStepLimits.MaximumEphemeralBytes > stateappcodec.MaximumSafeInteger ||
		config.EngineStepLimits.MaximumWallClock <= 0 || config.EngineStepLimits.MaximumWallClock%time.Millisecond != 0 {
		return nil, broker.ErrInvalidRequest
	}
	for kind, value := range map[identity.Kind]string{identity.Tenant: config.Scope.TenantID, identity.Workspace: config.Scope.WorkspaceID, identity.Session: config.Scope.SessionID, identity.Subject: config.Scope.ActorSubjectID} {
		if _, err := identity.Parse(kind, value); err != nil {
			return nil, broker.ErrInvalidRequest
		}
	}
	results, descriptor, err := config.Results.Open()
	if err != nil || isNil(results) || !hasGroup(descriptor, dependency.AtomicEffectLifecycle) {
		return nil, dependency.ErrUnverifiedDependency
	}
	store := &Store{client: client, scope: config.Scope, user: config.UserID, limits: config.EngineStepLimits, results: results}
	store.codec, err = stateappcodec.New(stateappcodec.Scope{TenantID: store.scope.TenantID, ActorSubjectID: store.scope.ActorSubjectID, SessionID: store.scope.SessionID, AuthorizationGeneration: store.scope.ExpectedAuthorizationGeneration},
		func(ctx context.Context, request stateappcodec.BlobRequest) (*stateappcodec.Blob, error) {
			blob, err := client.ReadSessionBlob(ctx, stateappclient.ReadSessionBlobRequest{TenantID: request.TenantID, ActorSubjectID: request.ActorSubjectID, SessionID: request.SessionID, ExpectedAuthorizationGeneration: request.AuthorizationGeneration, Digest: request.Digest})
			if err != nil || blob == nil {
				return nil, err
			}
			return &stateappcodec.Blob{Digest: blob.Digest, EncodedBytes: blob.EncodedBytes, Bytes: bytes.Clone(blob.Bytes)}, nil
		})
	if err != nil {
		return nil, err
	}
	return store, nil
}

func (store *Store) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	if store == nil || isNil(store.client) {
		return dependency.ProbeResponse{}, dependency.ErrInvalidConfiguration
	}
	return store.client.ProbeProduction(ctx, challenge)
}

func (store *Store) call(ctx context.Context, operation string, body canonical.Map) (canonical.Value, error) {
	if store == nil || ctx == nil || isNil(store.client) {
		return nil, broker.ErrInvalidRequest
	}
	value, err := store.client.ExecuteSessionBroker(ctx, stateappclient.BrokerRequest{Scope: store.scope, Operation: operation, Body: body})
	if err == nil {
		return value, nil
	}
	var remote *stateappclient.RemoteError
	if errors.As(err, &remote) {
		switch remote.Code {
		case "IDEMPOTENCY_CONFLICT":
			return nil, broker.ErrIdempotencyConflict
		case "DISPATCH_ALREADY_STARTED":
			return nil, broker.ErrDispatchAlreadyStarted
		case "LEASE_EXPIRED":
			return nil, broker.ErrLeaseExpired
		case "STALE_GENERATION", "STALE_DISPATCH_ATTEMPT":
			return nil, broker.ErrStaleGeneration
		case "CONFLICT", "PERMISSION_DENIED", "DIGEST_MISMATCH":
			return nil, broker.ErrFenceMismatch
		case "FAILED_PRECONDITION", "ABORTED", "NEEDS_CONFIRMATION":
			return nil, broker.ErrInvalidEffectState
		case "INVALID_ARGUMENT":
			return nil, broker.ErrInvalidRequest
		case "STORAGE_CONTRACT":
			return nil, broker.ErrDurabilityBarrier
		}
	}
	return nil, err
}

func (store *Store) ReadTurn(ctx context.Context, session identity.ID) (broker.TurnSnapshot, error) {
	if store == nil || session.String() != store.scope.SessionID {
		return broker.TurnSnapshot{}, broker.ErrFenceMismatch
	}
	value, err := store.call(ctx, "read-turn", canonical.Map{})
	if err != nil {
		return broker.TurnSnapshot{}, err
	}
	return store.decodeTurn(ctx, value)
}

func (store *Store) AcquireEngineStep(ctx context.Context, command broker.AcquireStepCommand) (broker.EngineStepPermit, error) {
	body, err := store.snapshotBody(command.Snapshot, command.OperationKey)
	if err != nil {
		return broker.EngineStepPermit{}, err
	}
	now, err := millis(command.Now)
	if err != nil {
		return broker.EngineStepPermit{}, err
	}
	budget, err := budgetValue(command.Budget)
	if err != nil || command.Budget.MaximumEvents != 1 || command.Budget.MaximumEphemeralBytes > store.limits.MaximumEphemeralBytes || command.Budget.MaximumWallClock > store.limits.MaximumWallClock {
		return broker.EngineStepPermit{}, broker.ErrInvalidRequest
	}
	body["nowUnixMs"], body["budget"] = now, budget
	value, err := store.call(ctx, "acquire-step", body)
	if err != nil {
		return broker.EngineStepPermit{}, err
	}
	return store.decodeGrant(ctx, value)
}

func (store *Store) CommitEngineStep(ctx context.Context, command broker.CommitStepCommand) (broker.EngineStepReceipt, error) {
	body, err := store.snapshotBody(command.Snapshot, command.OperationKey)
	if err != nil {
		return broker.EngineStepReceipt{}, err
	}
	now, err := millis(command.Now)
	if err != nil {
		return broker.EngineStepReceipt{}, err
	}
	step, err := stateappcodec.BoundaryToValue(command.Boundary.Message)
	if err != nil {
		return broker.EngineStepReceipt{}, err
	}
	digest, err := stateappcodec.CheckpointDigest(command.Boundary.Message.Checkpoint)
	if err != nil || digest != command.Boundary.CheckpointDigest || command.Permit.Opaque == "" || !command.Permit.Durable || !store.matchesPermit(command.Permit.TenantID, command.Permit.WorkspaceID, command.Permit.UserID, command.Permit.SessionID) {
		return broker.EngineStepReceipt{}, broker.ErrFenceMismatch
	}
	body["nowUnixMs"], body["step"], body["requestDigest"], body["permitOpaque"] = now, step, digestValue(command.RequestDigest), canonical.Bytes([]byte(command.Permit.Opaque))
	value, err := store.call(ctx, "commit-step", body)
	if err != nil {
		return broker.EngineStepReceipt{}, err
	}
	return store.decodeStep(value)
}

func (store *Store) MarkDispatched(ctx context.Context, command broker.MarkDispatchedCommand) (broker.DispatchPermit, error) {
	body, err := store.effectBody(command.Snapshot, command.Key, command.OperationKey, command.OperationDigest)
	if err != nil {
		return broker.DispatchPermit{}, err
	}
	now, err := millis(command.Now)
	if err != nil {
		return broker.DispatchPermit{}, err
	}
	deadline, err := millis(command.Deadline)
	if err != nil {
		return broker.DispatchPermit{}, err
	}
	if command.PreparationPermit.Opaque == "" || !command.PreparationPermit.Durable || !store.matchesPermit(command.PreparationPermit.TenantID, command.PreparationPermit.WorkspaceID, command.PreparationPermit.UserID, command.PreparationPermit.SessionID) || command.PreparationPermit.EffectKey != command.Key || command.Service != command.PreparationPermit.Service || command.Operation != command.PreparationPermit.Operation {
		return broker.DispatchPermit{}, broker.ErrFenceMismatch
	}
	body["nowUnixMs"], body["deadlineUnixMs"], body["preparationOpaque"] = now, deadline, canonical.Bytes([]byte(command.PreparationPermit.Opaque))
	body["providerRequestId"], body["providerRouteDigest"] = optionalID(command.ProviderRequestID), digestValue(command.ProviderRouteDigest)
	value, err := store.call(ctx, "dispatch", body)
	if err != nil {
		return broker.DispatchPermit{}, err
	}
	d := decoder{store: store}
	permit := d.dispatch(value)
	return permit, d.err
}

func (store *Store) ClaimDispatchStart(ctx context.Context, command broker.ClaimDispatchStartCommand) (broker.DispatchStartClaim, error) {
	body, err := store.snapshotBody(command.Snapshot, "")
	if err != nil {
		return broker.DispatchStartClaim{}, err
	}
	delete(body, "operationKey")
	now, err := millis(command.Now)
	if err != nil {
		return broker.DispatchStartClaim{}, err
	}
	if !command.Dispatch.Durable || command.Dispatch.Opaque == "" || !store.matchesPermit(command.Dispatch.TenantID, command.Dispatch.WorkspaceID, command.Dispatch.UserID, command.Dispatch.SessionID) {
		return broker.DispatchStartClaim{}, broker.ErrFenceMismatch
	}
	body["key"], body["dispatchOpaque"], body["commandDigest"], body["nowUnixMs"] = keyValue(command.Dispatch.EffectKey), canonical.Bytes([]byte(command.Dispatch.Opaque)), digestValue(command.CommandDigest), now
	value, err := store.call(ctx, "claim-start", body)
	if err != nil {
		return broker.DispatchStartClaim{}, err
	}
	d := decoder{store: store}
	claim := d.claim(value)
	return claim, d.err
}

func (store *Store) MarkExternallyCommitted(ctx context.Context, command broker.MarkExternalCommand) (broker.ConfirmationReceipt, error) {
	body, err := store.effectBody(command.Snapshot, command.Key, command.OperationKey, command.OperationDigest)
	if err != nil {
		return broker.ConfirmationReceipt{}, err
	}
	if command.Record.Status != broker.LedgerCommitted || command.Record.TenantID != command.Snapshot.TenantID || command.Record.WorkspaceID != command.Snapshot.WorkspaceID || command.Record.EffectID != command.Key.EffectID || command.Record.InvocationID != command.Key.InvocationID || command.Record.RequestDigest != command.Key.RequestDigest || command.Record.DispatchAttempt != command.DispatchAttempt {
		return broker.ConfirmationReceipt{}, broker.ErrFenceMismatch
	}
	body["dispatchAttempt"], body["providerRequestId"], body["providerRouteDigest"] = command.DispatchAttempt, optionalID(command.Record.ProviderRequestID), digestValue(command.Record.ProviderRouteDigest)
	body["externalCommitId"], body["resultRef"] = command.Record.ExternalCommitID.String(), optionalID(command.Record.ResultRef)
	value, err := store.call(ctx, "confirm", body)
	if err != nil {
		return broker.ConfirmationReceipt{}, err
	}
	d := decoder{store: store}
	receipt := d.confirmation(value)
	return receipt, d.err
}

func (store *Store) SettleEffect(ctx context.Context, command broker.SettleCommand) (broker.SettlementReceipt, error) {
	body, err := store.effectBody(command.Snapshot, command.Key, command.OperationKey, command.SettlementDigest)
	if err != nil {
		return broker.SettlementReceipt{}, err
	}
	var settlement canonical.Map
	if command.Error != nil {
		// Preserve the complete PublicError independently in its typed receipt;
		// the engine's bounded error message uses an allowlisted normalized value.
		settlement = canonical.Map{"kind": "error", "code": "effect.failed", "message": "The effect failed.", "retryable": command.Error.Retryable}
	} else {
		request := ResultRequest{TenantID: command.Snapshot.TenantID, WorkspaceID: command.Snapshot.WorkspaceID, SessionID: command.Key.SessionID, EffectID: command.Key.EffectID, InvocationID: command.Key.InvocationID, RequestDigest: command.Key.RequestDigest, ExternalCommitID: command.ExternalCommitID, ResultRef: command.ResultRef}
		if command.ResultRef.Kind() != identity.Artifact || isNil(store.results) {
			return broker.SettlementReceipt{}, broker.ErrInvalidRequest
		}
		result, err := store.results.ResolveResult(ctx, request)
		if err != nil {
			return broker.SettlementReceipt{}, err
		}
		owned := bytes.Clone(result.CanonicalCBOR)
		if result.Request != request || broker.Digest(sha256.Sum256(owned)) != result.PayloadDigest {
			return broker.SettlementReceipt{}, broker.ErrLedgerMismatch
		}
		value, err := canonical.Decode(owned, canonical.Options{MaxBytes: 4 << 20, MaxDepth: 64, MaxItems: 100_000})
		if err != nil {
			return broker.SettlementReceipt{}, broker.ErrLedgerMismatch
		}
		settlement = canonical.Map{"kind": "success", "result": value}
	}
	publicError, err := errorValue(command.Error)
	if err != nil {
		return broker.SettlementReceipt{}, err
	}
	body["dispatchAttempt"], body["externalCommitId"], body["resultRef"], body["error"], body["settlement"] = command.DispatchAttempt, command.ExternalCommitID.String(), optionalID(command.ResultRef), publicError, settlement
	value, err := store.call(ctx, "settle", body)
	if err != nil {
		return broker.SettlementReceipt{}, err
	}
	d := decoder{store: store}
	receipt := d.settlement(value)
	return receipt, d.err
}

func (store *Store) BlockEffect(ctx context.Context, command broker.BlockCommand) (broker.BlockReceipt, error) {
	body, err := store.effectBody(command.Snapshot, command.Key, command.OperationKey, command.OperationDigest)
	if err != nil {
		return broker.BlockReceipt{}, err
	}
	reason, err := errorValue(command.Reason)
	if err != nil || reason == nil {
		return broker.BlockReceipt{}, broker.ErrInvalidRequest
	}
	body["reason"] = reason
	value, err := store.call(ctx, "block", body)
	if err != nil {
		return broker.BlockReceipt{}, err
	}
	d := decoder{store: store}
	receipt := d.block(value)
	return receipt, d.err
}

func (store *Store) PrepareRetry(ctx context.Context, command broker.PrepareRetryCommand) (broker.EffectPreparationPermit, error) {
	body, err := store.effectBody(command.Snapshot, command.Key, command.OperationKey, command.OperationDigest)
	if err != nil {
		return broker.EffectPreparationPermit{}, err
	}
	now, err := millis(command.Now)
	if err != nil {
		return broker.EffectPreparationPermit{}, err
	}
	deadline, err := millis(command.Deadline)
	if err != nil {
		return broker.EffectPreparationPermit{}, err
	}
	body["nowUnixMs"], body["deadlineUnixMs"], body["userConfirmed"] = now, deadline, command.UserConfirmed
	value, err := store.call(ctx, "prepare-retry", body)
	if err != nil {
		return broker.EffectPreparationPermit{}, err
	}
	d := decoder{store: store}
	permit := d.preparation(value)
	return permit, d.err
}

func (store *Store) SettleRecovery(ctx context.Context, command broker.SettleRecoveryCommand) (broker.SettlementReceipt, error) {
	body, err := store.effectBody(command.Snapshot, command.Key, command.OperationKey, command.OperationDigest)
	if err != nil {
		return broker.SettlementReceipt{}, err
	}
	errorValue, err := errorValue(command.Error)
	if err != nil || errorValue == nil {
		return broker.SettlementReceipt{}, broker.ErrInvalidRequest
	}
	// The state app stores a non-empty interrupted reason as the settlement's
	// bounded identifier and rejects any other reason, so fail before sending.
	if command.Kind == broker.RecoverySettlementInterrupted && command.Error.Reason != "" {
		var d decoder
		if d.identifier(command.Error.Reason); d.err != nil {
			return broker.SettlementReceipt{}, broker.ErrInvalidRequest
		}
	}
	body["kind"], body["error"] = string(command.Kind), errorValue
	value, err := store.call(ctx, "settle-recovery", body)
	if err != nil {
		return broker.SettlementReceipt{}, err
	}
	d := decoder{store: store}
	receipt := d.settlement(value)
	return receipt, d.err
}

func (store *Store) LookupOperation(ctx context.Context, request broker.OperationLookup) (broker.OperationReceipt, error) {
	if store == nil || request.TenantID.String() != store.scope.TenantID || request.WorkspaceID.String() != store.scope.WorkspaceID || request.SessionID.String() != store.scope.SessionID {
		return broker.OperationReceipt{}, broker.ErrFenceMismatch
	}
	value, err := store.call(ctx, "lookup-operation", canonical.Map{"kind": string(request.Kind), "operationKey": request.OperationKey, "operationDigest": digestValue(request.OperationDigest)})
	if err != nil {
		return broker.OperationReceipt{}, err
	}
	d := decoder{store: store}
	m := d.record(value, "found", "kind", "operationDigest", "receipt")
	receipt := broker.OperationReceipt{Found: d.boolean(m["found"]), Kind: broker.OperationKind(d.text(m["kind"])), OperationDigest: d.digest(m["operationDigest"])}
	if receipt.Kind != request.Kind || receipt.OperationDigest != request.OperationDigest {
		d.fail()
	}
	if !receipt.Found {
		if m["receipt"] != nil {
			d.fail()
		}
		return receipt, d.err
	}
	switch receipt.Kind {
	case broker.OperationDispatch:
		r := d.dispatch(m["receipt"])
		receipt.Dispatch = &r
	case broker.OperationConfirmation:
		r := d.confirmation(m["receipt"])
		receipt.Confirmation = &r
	case broker.OperationSettlement, broker.OperationRecoverySettlement:
		r := d.settlement(m["receipt"])
		receipt.Settlement = &r
	case broker.OperationBlock:
		r := d.block(m["receipt"])
		receipt.Block = &r
	default:
		d.fail()
	}
	return receipt, d.err
}

func (store *Store) matchesPermit(tenant, workspace, user, session identity.ID) bool {
	return store != nil && tenant.String() == store.scope.TenantID && workspace.String() == store.scope.WorkspaceID && session.String() == store.scope.SessionID && user == store.user
}

func (store *Store) snapshotBody(snapshot broker.TurnSnapshot, operationKey string) (canonical.Map, error) {
	if !store.matchesPermit(snapshot.TenantID, snapshot.WorkspaceID, snapshot.UserID, snapshot.SessionID) || snapshot.Generations.Authorization != store.scope.ExpectedAuthorizationGeneration || snapshot.TurnID.Kind() != identity.Turn || snapshot.EventSequence > stateappcodec.MaximumSafeInteger || snapshot.CheckpointDigest == (broker.Digest{}) {
		return nil, broker.ErrFenceMismatch
	}
	var effect canonical.Value
	if snapshot.ActiveEffect != nil {
		effect = canonical.Map{"effectId": snapshot.ActiveEffect.EffectID.String(), "invocationId": snapshot.ActiveEffect.InvocationID.String(), "requestDigest": digestValue(snapshot.ActiveEffect.RequestDigest), "phase": string(snapshot.ActiveEffect.State), "dispatchAttempt": snapshot.ActiveEffect.DispatchAttempt}
	}
	return canonical.Map{"operationKey": operationKey, "snapshot": canonical.Map{"turnId": snapshot.TurnID.String(), "eventSequence": snapshot.EventSequence, "checkpointDigest": digestValue(snapshot.CheckpointDigest), "fence": fenceValue(snapshot.Generations), "activeEffect": effect}}, nil
}

func (store *Store) effectBody(snapshot broker.TurnSnapshot, key broker.EffectKey, operationKey string, digest broker.Digest) (canonical.Map, error) {
	body, err := store.snapshotBody(snapshot, operationKey)
	if err != nil {
		return nil, err
	}
	if key.SessionID != snapshot.SessionID || key.TurnID != snapshot.TurnID || key.EffectID.Kind() != identity.Effect || key.InvocationID.Kind() != identity.Invocation || key.RequestDigest == (broker.Digest{}) || digest == (broker.Digest{}) || operationKey == "" {
		return nil, broker.ErrInvalidRequest
	}
	body["key"], body["operationDigest"] = keyValue(key), digestValue(digest)
	return body, nil
}

var _ broker.DurableStore = (*Store)(nil)
var _ dependency.ProductionProbe = (*Store)(nil)
var _ = (*v1.PublicError)(nil)
