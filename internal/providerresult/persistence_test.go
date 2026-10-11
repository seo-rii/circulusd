package providerresult

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/celld"
	"github.com/hancomac/circulusd/internal/dependency"
	proof "github.com/hancomac/circulusd/internal/dependency/contracttest"
	"github.com/hancomac/circulusd/internal/effectledger"
	"github.com/hancomac/circulusd/internal/identity"
	"github.com/hancomac/circulusd/internal/stateappbroker"
	"github.com/hancomac/circulusd/internal/stateappclient"
)

// This fault-injectable memory implementation is a test fixture, never a
// production driver or evidence that an actual host storage passed conformance.
type persistenceTestObject struct {
	state    []byte
	receipt  celld.StoredReceipt
	found    bool
	revision uint64
}

type persistenceTestStorage struct {
	*proof.ProductionProofs
	mu               sync.Mutex
	objects          map[string]persistenceTestObject
	fault            celld.FaultPoint
	tokenMode        string
	transactionError error
	barrierError     error
	probeError       error
	cancelCommit     context.CancelFunc
	cancelBarrier    context.CancelFunc
	callbackRetries  int
	transactions     int
	commits          int
	barriers         int
	probes           atomic.Int32
}

var persistenceTestResponseLoss = errors.New("test: lost response with secret implementation details")

func (storage *persistenceTestStorage) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	storage.probes.Add(1)
	if storage.probeError != nil {
		return dependency.ProbeResponse{}, storage.probeError
	}
	return storage.ProductionProofs.ProbeProduction(ctx, challenge)
}

func (storage *persistenceTestStorage) Transaction(ctx context.Context, objectID string, callback func(celld.Transaction) error) (celld.CommitToken, error) {
	storage.mu.Lock()
	defer storage.mu.Unlock()
	storage.transactions++
	if err := ctx.Err(); err != nil {
		return celld.CommitToken{}, err
	}
	if storage.transactionError != nil {
		return celld.CommitToken{}, storage.transactionError
	}
	if storage.tokenMode == "callback skipped" {
		return celld.CommitToken{ObjectID: objectID, Revision: 1}, nil
	}
	if storage.tokenMode == "nil transaction" {
		return celld.CommitToken{}, callback(nil)
	}
	object := storage.objects[objectID]
	var tx *persistenceTestTransaction
	for attempt := 0; attempt <= storage.callbackRetries; attempt++ {
		tx = &persistenceTestTransaction{object: clonePersistenceObject(object)}
		if err := callback(tx); err != nil {
			return celld.CommitToken{}, err
		}
	}
	if storage.fault == celld.FaultBeforeCommit {
		return celld.CommitToken{}, persistenceTestResponseLoss
	}
	if tx.dirty {
		tx.object.revision++
		storage.objects[objectID] = clonePersistenceObject(tx.object)
		storage.commits++
	}
	if storage.cancelCommit != nil {
		storage.cancelCommit()
	}
	if storage.fault == celld.FaultAfterCommit {
		return celld.CommitToken{}, persistenceTestResponseLoss
	}
	token := celld.CommitToken{ObjectID: objectID, Revision: tx.object.revision}
	if storage.tokenMode == "wrong object" {
		token.ObjectID += "-other"
	}
	if storage.tokenMode == "zero revision" {
		token.Revision = 0
	}
	return token, nil
}

func (storage *persistenceTestStorage) DurabilityBarrier(ctx context.Context, token celld.CommitToken) error {
	storage.mu.Lock()
	defer storage.mu.Unlock()
	storage.barriers++
	if err := ctx.Err(); err != nil {
		return err
	}
	object := storage.objects[token.ObjectID]
	if object.revision == 0 || token.Revision == 0 || token.Revision > object.revision {
		return errors.New("test: wrong exact token")
	}
	if storage.fault == celld.FaultBeforeBarrier || storage.barrierError != nil {
		if storage.barrierError != nil {
			return storage.barrierError
		}
		return persistenceTestResponseLoss
	}
	if storage.cancelBarrier != nil {
		storage.cancelBarrier()
	}
	if storage.fault == celld.FaultAfterBarrier || storage.fault == celld.FaultBeforeResponse {
		return persistenceTestResponseLoss
	}
	return nil
}

type persistenceTestTransaction struct {
	object persistenceTestObject
	dirty  bool
}

func (tx *persistenceTestTransaction) ReadState() ([]byte, error) {
	return bytes.Clone(tx.object.state), nil
}
func (tx *persistenceTestTransaction) LookupReceipt(id string) (celld.StoredReceipt, bool, error) {
	if id != persistenceReceiptID {
		return celld.StoredReceipt{}, false, fmt.Errorf("test: unexpected receipt %q", id)
	}
	return clonePersistenceObject(tx.object).receipt, tx.object.found, nil
}
func (tx *persistenceTestTransaction) WriteState(state []byte) error {
	tx.object.state, tx.dirty = bytes.Clone(state), true
	return nil
}
func (tx *persistenceTestTransaction) WriteReceipt(id string, receipt celld.StoredReceipt) error {
	if id != persistenceReceiptID {
		return errors.New("test: unexpected receipt write")
	}
	tx.object.receipt, tx.object.found, tx.dirty = receipt, true, true
	return nil
}
func clonePersistenceObject(object persistenceTestObject) persistenceTestObject {
	object.state, object.receipt.Response = bytes.Clone(object.state), bytes.Clone(object.receipt.Response)
	object.receipt.CapabilityClaims = append([]celld.RawCapabilityClaims(nil), object.receipt.CapabilityClaims...)
	return object
}

func newPersistenceFixture(t *testing.T, name string) (*persistenceTestStorage, dependency.Verified[TransactionStorage], *PersistentRecords, CommittedRecord) {
	t.Helper()
	groups := []dependency.AtomicGroup{dependency.AtomicCommandReceipt, dependency.AtomicEffectLifecycle}
	p := proof.NewProductionProofs(t, groups)
	storage := &persistenceTestStorage{ProductionProofs: p, objects: make(map[string]persistenceTestObject)}
	binding := proof.Verify[TransactionStorage](t, p, storage, groups)
	bounds := recordsMCPBounds()
	store, err := NewPersistentRecords(binding, RecordResolverConfig{MCPBounds: &bounds})
	if err != nil {
		t.Fatal(err)
	}
	body := recordsPiBody(t, name)
	record := CommittedRecord{Request: requestFixture(t), Service: broker.ServiceModel, Status: effectledger.TerminalCommitted,
		CanonicalCBOR: body, PayloadDigest: broker.Digest(sha256.Sum256(body))}
	if name == "tool_result" {
		record.Service, record.LedgerResult = broker.ServiceMCP, recordsMCPLedger(t, body)
	} else {
		record.LedgerResult = recordsModelLedger(t, body)
	}
	return storage, binding, store, record
}

func TestPersistentRecordsAtomicallyRetainActualPiBodiesReplayAndRestart(t *testing.T) {
	for _, name := range []string{"model_tool_call", "model_final", "tool_result"} {
		t.Run(name, func(t *testing.T) {
			storage, binding, store, record := newPersistenceFixture(t, name)
			original := record
			original.CanonicalCBOR, original.LedgerResult = bytes.Clone(record.CanonicalCBOR), bytes.Clone(record.LedgerResult)
			first, err := store.WriteCommittedResult(context.Background(), record)
			if err != nil || first.Replayed || first.Revision != 1 || first.RecordDigest == (broker.Digest{}) {
				t.Fatalf("first immutable publication: %+v, %v", first, err)
			}
			record.CanonicalCBOR[0] ^= 1
			record.LedgerResult[0] ^= 1
			bounds := recordsMCPBounds()
			restarted, err := NewPersistentRecords(binding, RecordResolverConfig{MCPBounds: &bounds})
			if err != nil {
				t.Fatal(err)
			}
			replay, err := restarted.WriteCommittedResult(context.Background(), original)
			if err != nil || !replay.Replayed || replay.Revision != first.Revision || replay.RecordDigest != first.RecordDigest {
				t.Fatalf("restart changed original publication: %+v, %v", replay, err)
			}
			result, err := restarted.ReadCommittedResult(context.Background(), original.Request)
			if err != nil || result.Request != original.Request || result.Service != original.Service || result.Status != effectledger.TerminalCommitted ||
				result.PayloadDigest != original.PayloadDigest || !bytes.Equal(result.CanonicalCBOR, original.CanonicalCBOR) || !bytes.Equal(result.LedgerResult, original.LedgerResult) {
				t.Fatalf("cold read lost immutable complete record: %v", err)
			}
			result.CanonicalCBOR[0] ^= 1
			result.LedgerResult[0] ^= 1
			if got, err := restarted.ReadCommittedResult(context.Background(), original.Request); err != nil || !bytes.Equal(got.CanonicalCBOR, original.CanonicalCBOR) || !bytes.Equal(got.LedgerResult, original.LedgerResult) {
				t.Fatal("read aliases retained transaction state")
			}
			if storage.commits != 1 || storage.barriers != 4 {
				t.Fatalf("replay/read rewrote record or bypassed exact barriers: commits=%d barriers=%d", storage.commits, storage.barriers)
			}
		})
	}
}

func TestPersistentRecordsRejectRelabeledReferencesAndChangedBodies(t *testing.T) {
	for _, field := range []string{"request digest", "external commit", "artifact", "cost", "ledger"} {
		t.Run(field, func(t *testing.T) {
			storage, _, store, record := newPersistenceFixture(t, "model_final")
			if _, err := store.WriteCommittedResult(context.Background(), record); err != nil {
				t.Fatal(err)
			}
			changed := record
			switch field {
			case "request digest":
				changed.Request.RequestDigest = broker.Digest{8}
			case "external commit":
				changed.Request.ExternalCommitID = tid(t, identity.Commit, 8)
			case "artifact":
				changed.Request.ResultRef = tid(t, identity.Artifact, 8)
			case "cost":
				value := recordsDecode(t, changed.CanonicalCBOR)
				value["message"].(canonical.Map)["usage"].(canonical.Map)["cost"].(canonical.Map)["input"] = "0.25"
				recordsReplaceBody(t, &changed, value)
			case "ledger":
				// Still valid normalized facts, but not the original terminal.
				changed.LedgerResult = bytes.Replace(record.LedgerResult, []byte("1000"), []byte("1001"), 1)
			}
			if commit, err := store.WriteCommittedResult(context.Background(), changed); commit != (RecordCommit{}) || !errors.Is(err, ErrRecordConflict) {
				t.Fatalf("immutable publication replaced: %v", err)
			}
			if field == "request digest" || field == "external commit" || field == "artifact" {
				if result, err := store.ReadCommittedResult(context.Background(), changed.Request); result.CanonicalCBOR != nil || !errors.Is(err, broker.ErrFenceMismatch) {
					t.Fatal("relabeled reference recovered original body")
				}
			}
			if storage.commits != 1 || storage.barriers != 1 {
				t.Fatal("conflict reached durability barrier or mutated stored facts")
			}
		})
	}
}

func TestPersistentRecordsSerializesConcurrentExactPublicationWithoutLocalLock(t *testing.T) {
	storage, _, store, record := newPersistenceFixture(t, "model_tool_call")
	const callers = 16
	var wg sync.WaitGroup
	var fresh atomic.Int32
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			commit, err := store.WriteCommittedResult(context.Background(), record)
			if err != nil {
				t.Errorf("concurrent publication: %v", err)
				return
			}
			if !commit.Replayed {
				fresh.Add(1)
			}
		}()
	}
	wg.Wait()
	if fresh.Load() != 1 || storage.commits != 1 || storage.barriers != callers {
		t.Fatal("storage transaction did not serialize immutable record publication")
	}
}

func TestPersistentRecordsResponseLossWindowsRecoverOriginalPublication(t *testing.T) {
	for _, point := range []celld.FaultPoint{celld.FaultBeforeCommit, celld.FaultAfterCommit, celld.FaultBeforeBarrier, celld.FaultAfterBarrier, celld.FaultBeforeResponse} {
		t.Run(string(point), func(t *testing.T) {
			storage, binding, store, record := newPersistenceFixture(t, "model_tool_call")
			storage.fault = point
			if commit, err := store.WriteCommittedResult(context.Background(), record); err == nil || commit != (RecordCommit{}) {
				t.Fatal("response-loss window exposed unconfirmed publication")
			}
			storage.fault = ""
			bounds := recordsMCPBounds()
			restarted, err := NewPersistentRecords(binding, RecordResolverConfig{MCPBounds: &bounds})
			if err != nil {
				t.Fatal(err)
			}
			commit, err := restarted.WriteCommittedResult(context.Background(), record)
			if err != nil || commit.Replayed != (point != celld.FaultBeforeCommit) || storage.commits != 1 {
				t.Fatalf("restart did not recover exact original publication: %+v, %v", commit, err)
			}
			result, err := restarted.ReadCommittedResult(context.Background(), record.Request)
			if err != nil || !bytes.Equal(result.CanonicalCBOR, record.CanonicalCBOR) || !bytes.Equal(result.LedgerResult, record.LedgerResult) {
				t.Fatalf("response-loss restart altered result: %v", err)
			}
		})
	}
}

func TestPersistentRecordsRequiresBothAtomicGroupsAndSameProbeSource(t *testing.T) {
	if _, err := NewPersistentRecords(dependency.Verified[TransactionStorage]{}, RecordResolverConfig{}); !errors.Is(err, dependency.ErrUnverifiedDependency) {
		t.Fatal("unqualified raw transaction store accepted")
	}
	for _, group := range []dependency.AtomicGroup{dependency.AtomicCommandReceipt, dependency.AtomicEffectLifecycle} {
		p := proof.NewProductionProofs(t, []dependency.AtomicGroup{group})
		storage := &persistenceTestStorage{ProductionProofs: p}
		binding := proof.Verify[TransactionStorage](t, p, storage, []dependency.AtomicGroup{group})
		if _, err := NewPersistentRecords(binding, RecordResolverConfig{}); !errors.Is(err, dependency.ErrUnverifiedDependency) {
			t.Fatal("single atomic group promoted to committed record persistence")
		}
	}
	storage, _, store, record := newPersistenceFixture(t, "model_final")
	if _, err := store.WriteCommittedResult(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	groups := []dependency.AtomicGroup{dependency.AtomicCommandReceipt, dependency.AtomicEffectLifecycle}
	records := proof.Verify[Records](t, storage.ProductionProofs, store, groups)
	resolver, err := NewRecordResolver(records, RecordResolverConfig{})
	if err != nil {
		t.Fatal(err)
	}
	verified := proof.Verify[stateappbroker.ResultResolver](t, storage.ProductionProofs, resolver, groups)
	operational, _, err := verified.Open()
	if err != nil || storage.probes.Load() != 3 {
		t.Fatal("storage, records and resolver did not challenge the exact source independently")
	}
	if result, err := operational.ResolveResult(context.Background(), record.Request); err != nil || !bytes.Equal(result.CanonicalCBOR, record.CanonicalCBOR) {
		t.Fatalf("persistent record did not serve the same qualified resolver: %v", err)
	}
}

func TestPersistentRecordsMissingForeignScopesAndInputBoundsDoNotPublish(t *testing.T) {
	storage, _, store, record := newPersistenceFixture(t, "model_final")
	if result, err := store.ReadCommittedResult(context.Background(), record.Request); result.CanonicalCBOR != nil || !errors.Is(err, ErrRecordUnavailable) {
		t.Fatal("missing result supplied a fallback body")
	}
	if _, err := store.WriteCommittedResult(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []identity.Kind{identity.Tenant, identity.Workspace, identity.Session, identity.Effect, identity.Invocation} {
		request := record.Request
		switch kind {
		case identity.Tenant:
			request.TenantID = tid(t, kind, 3)
		case identity.Workspace:
			request.WorkspaceID = tid(t, kind, 3)
		case identity.Session:
			request.SessionID = tid(t, kind, 3)
		case identity.Effect:
			request.EffectID = tid(t, kind, 3)
		case identity.Invocation:
			request.InvocationID = tid(t, kind, 3)
		}
		if result, err := store.ReadCommittedResult(context.Background(), request); result.CanonicalCBOR != nil || !errors.Is(err, ErrRecordUnavailable) {
			t.Fatal("foreign scope recovered another occurrence's publication")
		}
	}
	before := storage.transactions
	for _, edit := range []func(*CommittedRecord){
		func(r *CommittedRecord) { r.Request.ResultRef = identity.ID{} },
		func(r *CommittedRecord) { r.Status = effectledger.TerminalUnknown },
		func(r *CommittedRecord) { r.Service = broker.ServiceExecutor },
		func(r *CommittedRecord) { r.PayloadDigest = broker.Digest{} },
		func(r *CommittedRecord) { r.CanonicalCBOR = make([]byte, stateappclient.MaximumProviderResultBytes+1) },
		func(r *CommittedRecord) { r.LedgerResult = make([]byte, MaximumCommittedLedgerResultBytes+1) },
	} {
		invalid := record
		edit(&invalid)
		if commit, err := store.WriteCommittedResult(context.Background(), invalid); err == nil || commit != (RecordCommit{}) {
			t.Fatal("invalid terminal publication accepted")
		}
	}
	if storage.transactions != before || storage.commits != 1 {
		t.Fatal("invalid publication reached transaction storage")
	}
}

func TestPersistentRecordsRetainsExplicitImmutableMCPPolicy(t *testing.T) {
	storage, binding, _, record := newPersistenceFixture(t, "tool_result")
	bounds := recordsMCPBounds()
	bounds.MaxOutputBytes = 0
	if _, err := NewPersistentRecords(binding, RecordResolverConfig{MCPBounds: &bounds}); !errors.Is(err, dependency.ErrInvalidConfiguration) {
		t.Fatal("invalid MCP policy accepted")
	}
	modelOnly, err := NewPersistentRecords(binding, RecordResolverConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := modelOnly.WriteCommittedResult(context.Background(), record); !errors.Is(err, ErrUnsupportedService) || storage.transactions != 0 {
		t.Fatal("unspecified MCP policy reached source storage")
	}
	bounds = recordsMCPBounds()
	store, err := NewPersistentRecords(binding, RecordResolverConfig{MCPBounds: &bounds})
	if err != nil {
		t.Fatal(err)
	}
	bounds.MaxOutputBytes = 0
	if _, err := store.WriteCommittedResult(context.Background(), record); err != nil {
		t.Fatal("caller mutation changed retained MCP policy")
	}
}

func TestPersistentRecordsRejectsCorruptAtomicStateAndReceipts(t *testing.T) {
	for _, mode := range []string{"missing receipt", "missing state", "receipt digest", "receipt response", "receipt claims", "oversized state", "malformed state", "wrong stored request", "corrupt ledger", "corrupt body", "unknown field"} {
		t.Run(mode, func(t *testing.T) {
			storage, _, store, record := newPersistenceFixture(t, "model_final")
			if _, err := store.WriteCommittedResult(context.Background(), record); err != nil {
				t.Fatal(err)
			}
			id, err := persistenceObjectID(record.Request)
			if err != nil {
				t.Fatal(err)
			}
			object := storage.objects[id]
			want := celld.ErrStorageContract
			switch mode {
			case "missing receipt":
				object.found = false
			case "missing state":
				object.state = nil
			case "receipt digest":
				object.receipt.CommandDigest = celld.Digest{7}
			case "receipt response":
				object.receipt.Response = make([]byte, maximumPersistenceReceiptBytes+1)
			case "receipt claims":
				object.receipt.CapabilityClaims = []celld.RawCapabilityClaims{{Kind: "unexpected", Payload: []byte{1}}}
			case "oversized state":
				object.state = make([]byte, maximumPersistedRecordBytes+1)
			default:
				value := recordsDecode(t, object.state)
				switch mode {
				case "malformed state":
					value["version"] = canonical.Map{}
				case "wrong stored request":
					value["request"].(canonical.Map)["invocationId"] = tid(t, identity.Invocation, 9).String()
					want = broker.ErrFenceMismatch
				case "corrupt ledger":
					value["ledgerResult"] = canonical.Bytes([]byte(`{"ok":true}`))
				case "corrupt body":
					value["canonicalCbor"] = canonical.Bytes([]byte{0xf6})
					value["payloadDigest"] = canonical.Bytes(record.PayloadDigest[:])
				case "unknown field":
					value["invented"] = true
				}
				object.state, err = canonical.Encode(value, canonical.DefaultOptions())
				if err != nil {
					t.Fatal(err)
				}
				digest := broker.Digest(sha256.Sum256(object.state))
				object.receipt.CommandDigest, object.receipt.Response = celld.Digest(digest), persistenceReceipt(digest)
			}
			storage.objects[id] = object
			if result, err := store.ReadCommittedResult(context.Background(), record.Request); result.CanonicalCBOR != nil || !errors.Is(err, want) {
				t.Fatalf("corrupt atomic record escaped: %v, want %v", err, want)
			}
			if commit, err := store.WriteCommittedResult(context.Background(), record); commit != (RecordCommit{}) || err == nil {
				t.Fatal("corrupted existing publication replaced during replay")
			}
			if storage.barriers != 1 || storage.commits != 1 {
				t.Fatal("corrupt record mutation or barrier happened")
			}
		})
	}
}

func TestPersistentRecordsRejectsBadStorageTokensAndSanitizesFailures(t *testing.T) {
	for _, mode := range []string{"callback skipped", "nil transaction", "wrong object", "zero revision"} {
		t.Run(mode, func(t *testing.T) {
			storage, _, store, record := newPersistenceFixture(t, "model_final")
			storage.tokenMode = mode
			if commit, err := store.WriteCommittedResult(context.Background(), record); commit != (RecordCommit{}) || !errors.Is(err, celld.ErrStorageContract) {
				t.Fatalf("bad storage callback/token trusted: %v", err)
			}
			if storage.barriers != 0 {
				t.Fatal("bad commit token reached barrier")
			}
		})
	}
	storage, _, store, record := newPersistenceFixture(t, "model_final")
	storage.transactionError = persistenceTestResponseLoss
	if _, err := store.WriteCommittedResult(context.Background(), record); err != stateappclient.ErrTransport {
		t.Fatalf("arbitrary storage diagnostic escaped: %v", err)
	}
	storage.transactionError = nil
	storage.barrierError = persistenceTestResponseLoss
	if _, err := store.WriteCommittedResult(context.Background(), record); err != celld.ErrDurabilityBarrier {
		t.Fatalf("arbitrary barrier diagnostic escaped: %v", err)
	}
	if result, err := store.ReadCommittedResult(context.Background(), record.Request); result.CanonicalCBOR != nil || err != celld.ErrDurabilityBarrier {
		t.Fatal("read exposed body before its barrier succeeded")
	}
	storage.probeError = persistenceTestResponseLoss
	if _, err := store.ProbeProduction(context.Background(), dependency.ProbeChallenge{Nonce: bytes.Repeat([]byte{1}, dependency.ChallengeBytes)}); err != stateappclient.ErrTransport {
		t.Fatal("arbitrary same-storage probe diagnostic escaped")
	}
}

func TestPersistentRecordsCancellationAndCallbackRetries(t *testing.T) {
	for _, point := range []string{"before transaction", "after commit", "after barrier"} {
		t.Run(point, func(t *testing.T) {
			storage, _, store, record := newPersistenceFixture(t, "model_final")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch point {
			case "before transaction":
				cancel()
			case "after commit":
				storage.cancelCommit = cancel
			case "after barrier":
				storage.cancelBarrier = cancel
			}
			if commit, err := store.WriteCommittedResult(ctx, record); commit != (RecordCommit{}) || !errors.Is(err, context.Canceled) {
				t.Fatalf("late/canceled publication exposed confirmation: %v", err)
			}
		})
	}
	for _, point := range []string{"after transaction", "after barrier"} {
		t.Run("read "+point, func(t *testing.T) {
			storage, _, store, record := newPersistenceFixture(t, "model_final")
			if _, err := store.WriteCommittedResult(context.Background(), record); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if point == "after transaction" {
				storage.cancelCommit = cancel
			} else {
				storage.cancelBarrier = cancel
			}
			if result, err := store.ReadCommittedResult(ctx, record.Request); result.CanonicalCBOR != nil || !errors.Is(err, context.Canceled) {
				t.Fatalf("late/canceled read exposed result body: %v", err)
			}
		})
	}
	storage, _, store, record := newPersistenceFixture(t, "model_final")
	storage.callbackRetries = 2
	if first, err := store.WriteCommittedResult(context.Background(), record); err != nil || first.Replayed || storage.commits != 1 {
		t.Fatalf("retryable storage callback committed twice: %v", err)
	}
	if replay, err := store.WriteCommittedResult(context.Background(), record); err != nil || !replay.Replayed || storage.commits != 1 {
		t.Fatalf("retryable replay callback changed publication: %v", err)
	}
	if _, err := store.WriteCommittedResult(nil, record); !errors.Is(err, broker.ErrInvalidRequest) {
		t.Fatal("nil context panicked or published")
	}
	var zero *PersistentRecords
	if _, err := zero.ReadCommittedResult(context.Background(), record.Request); !errors.Is(err, dependency.ErrUnverifiedDependency) {
		t.Fatal("nil store supplied fallback storage")
	}
}
