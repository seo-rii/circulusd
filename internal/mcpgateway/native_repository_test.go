package mcpgateway

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/celld"
	"github.com/hancomac/circulusd/internal/dependency"
)

type nativeRepositoryFixtureSource struct {
	mcpRuntimeProof
	mu           sync.Mutex
	state        []byte
	revision     uint64
	barriers     []celld.CommitToken
	barrierError error
	skipCallback bool
	wrongObject  bool
	failCommit   bool
}

type nativeRepositoryFixtureTransaction struct{ state []byte }

func (transaction *nativeRepositoryFixtureTransaction) ReadState() ([]byte, error) {
	return bytes.Clone(transaction.state), nil
}
func (transaction *nativeRepositoryFixtureTransaction) WriteState(value []byte) error {
	transaction.state = bytes.Clone(value)
	return nil
}
func (*nativeRepositoryFixtureTransaction) LookupReceipt(string) (celld.StoredReceipt, bool, error) {
	return celld.StoredReceipt{}, false, nil
}
func (*nativeRepositoryFixtureTransaction) WriteReceipt(string, celld.StoredReceipt) error {
	return celld.ErrStorageContract
}

func (source *nativeRepositoryFixtureSource) Transaction(ctx context.Context, objectID string, callback func(celld.Transaction) error) (celld.CommitToken, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.skipCallback {
		return celld.CommitToken{ObjectID: objectID, Revision: 1}, nil
	}
	transaction := &nativeRepositoryFixtureTransaction{bytes.Clone(source.state)}
	if err := callback(transaction); err != nil {
		return celld.CommitToken{}, err
	}
	if source.failCommit {
		return celld.CommitToken{}, celld.ErrStorageContract
	}
	if !bytes.Equal(source.state, transaction.state) {
		source.revision++
		source.state = bytes.Clone(transaction.state)
	}
	if source.wrongObject {
		objectID = "different-object"
	}
	return celld.CommitToken{ObjectID: objectID, Revision: source.revision}, ctx.Err()
}
func (source *nativeRepositoryFixtureSource) DurabilityBarrier(_ context.Context, commit celld.CommitToken) error {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.barriers = append(source.barriers, commit)
	return source.barrierError
}
func (source *nativeRepositoryFixtureSource) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	return source.mcpRuntimeProof.respond(ctx, challenge)
}

func nativeRepositoryFixture(t *testing.T) (*NativeRepository, *nativeRepositoryFixtureSource) {
	t.Helper()
	proofs := newMCPProductionProofs(t, "native-mcp-test", nativeRepositoryGroups())
	source := &nativeRepositoryFixtureSource{mcpRuntimeProof: proofs.runtimeProof}
	binding := verifyMCPProduction(t, proofs, nativeRepositorySource(source))
	repository, err := newNativeRepository(source, binding, func() error { _, _, err := binding.Open(); return err }, "mcp-test", 128, 1<<20, func() time.Time { return time.Unix(1_800_000_000, 123456789) })
	if err != nil {
		t.Fatal(err)
	}
	return repository, source
}

func TestNativeRepositoryRejectsUnqualifiedAndStorageOnlySources(t *testing.T) {
	if _, err := NewNativeRepository(NativeRepositoryConfig{ObjectID: "mcp-test", MaximumRecords: 128, MaximumStateBytes: 1 << 20}); !errors.Is(err, dependency.ErrUnverifiedDependency) {
		t.Fatalf("zero qualified concrete source: %v", err)
	}
	proofs := newMCPProductionProofs(t, "storage-only", []dependency.AtomicGroup{dependency.AtomicCommandReceipt, dependency.AtomicGroup("native-storage")})
	source := &nativeRepositoryFixtureSource{mcpRuntimeProof: proofs.runtimeProof}
	binding := verifyMCPProduction(t, proofs, nativeRepositorySource(source))
	if _, err := newNativeRepository(source, binding, func() error { return nil }, "mcp-test", 128, 1<<20, time.Now); !errors.Is(err, dependency.ErrRequirementMismatch) {
		t.Fatalf("storage-only evidence promoted to MCP: %v", err)
	}
}

func TestNativeRepositoryRequiresPersistedFenceAndReconstructsWithoutCache(t *testing.T) {
	repository, source := nativeRepositoryFixture(t)
	fixture := newGatewayFixture(t, ReplayNever)
	effect := admitFixtureEffect(t, fixture)
	ctx := context.Background()
	if _, err := repository.Admit(ctx, effect); !errors.Is(err, ErrStaleAuthority) || len(source.state) != 0 {
		t.Fatalf("unprovisioned authority admitted: %v", err)
	}
	if err := repository.SetCurrentAuthority(ctx, effect.Scope); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Admit(ctx, effect); err != nil {
		t.Fatal(err)
	}
	reopened := *repository
	loaded, err := reopened.Load(ctx, effect.Scope.InvocationID)
	if err != nil || !loaded.Durable || !sameEffect(loaded.Effect, effect) {
		t.Fatalf("reconstructed native state differs: %v", err)
	}
	loaded.Effect.InputCanonical[0] ^= 1
	again, err := repository.Load(ctx, effect.Scope.InvocationID)
	if err != nil || !sameEffect(again.Effect, effect) {
		t.Fatal("returned bytes alias native authoritative state")
	}
	if len(source.barriers) != 4 || source.barriers[3].Revision != source.revision || source.barriers[3].ObjectID != repository.objectID {
		t.Fatal("a result escaped without its exact native barrier")
	}
	rotated := effect.Scope
	rotated.Generations.Policy++
	if err := reopened.SetCurrentAuthority(ctx, rotated); err != nil {
		t.Fatal(err)
	}
	request := AdmissionReplayRequest{CurrentScope: effect.Scope, EffectID: effect.Scope.EffectID, InvocationID: effect.Scope.InvocationID, RequestDigest: effect.RequestDigest, ServerID: effect.ServerID, ToolName: effect.ToolName, InputCanonical: effect.InputCanonical}
	if _, err := repository.ReplayAdmission(ctx, request); !errors.Is(err, ErrStaleAuthority) {
		t.Fatalf("old process cached an obsolete authority fence: %v", err)
	}
}

func TestNativeRepositoryNoResultsBeforeBarrierOrActualCallback(t *testing.T) {
	for _, kind := range []string{"barrier", "skip", "wrong-object", "commit"} {
		t.Run(kind, func(t *testing.T) {
			repository, source := nativeRepositoryFixture(t)
			fixture := newGatewayFixture(t, ReplayNever)
			effect := admitFixtureEffect(t, fixture)
			if err := repository.SetCurrentAuthority(context.Background(), effect.Scope); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "barrier":
				source.barrierError = errors.New("private backend detail")
			case "skip":
				source.skipCallback = true
			case "wrong-object":
				source.wrongObject = true
			case "commit":
				source.failCommit = true
			}
			stored, err := repository.Admit(context.Background(), effect)
			if !errors.Is(err, ErrStoreUnavailable) || !reflect.DeepEqual(stored, StoredEffect{}) {
				t.Fatalf("unconfirmed result escaped: %v", err)
			}
		})
	}
}

func TestNativeRepositoryAtomicDispatchOutboxAndStaleCAS(t *testing.T) {
	repository, source := nativeRepositoryFixture(t)
	ctx := context.Background()
	fixture := newGatewayFixture(t, ReplayNever)
	effect := admitFixtureEffect(t, fixture)
	if err := repository.SetCurrentAuthority(ctx, effect.Scope); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Admit(ctx, effect); err != nil {
		t.Fatal(err)
	}
	next := applyFixtureEvent(t, fixture.gateway, effect, Event{Kind: EventBeginDispatch})
	authorization, err := fixture.authorizer.Authorize(ctx, ToolAuthorizationRequest{Scope: effect.Scope, ServerID: effect.ServerID, ToolName: effect.ToolName, RequestDigest: effect.RequestDigest})
	if err != nil {
		t.Fatal(err)
	}
	request := DispatchClaimRequest{ExpectedRevision: effect.Revision, CurrentScope: effect.Scope, Previous: effect, Next: next, Authorization: authorization}
	claim, err := repository.CommitAndClaimDispatch(ctx, request)
	if err != nil || !claim.Durable || claim.Proof == (OpaqueDispatchPermit{}) {
		t.Fatalf("durable dispatch claim: %v", err)
	}
	before := bytes.Clone(source.state)
	if _, err := repository.CommitAndClaimDispatch(ctx, request); !errors.Is(err, ErrConcurrentTransition) || !bytes.Equal(before, source.state) {
		t.Fatalf("stale dispatch CAS mutated native aggregate: %v", err)
	}
	negotiated := negotiateFixtureEffect(t, fixture.gateway, next)
	event := AuditEvent{TenantID: effect.Scope.TenantID, UserID: effect.Scope.UserID, SessionID: effect.Scope.SessionID, TurnID: effect.Scope.TurnID, InvocationID: effect.Scope.InvocationID, ServerID: effect.ServerID, Method: "tools/call", Decision: "allow"}
	stored, err := repository.Commit(ctx, TransitionCommitRequest{ExpectedRevision: next.Revision, CurrentScope: effect.Scope, Previous: next, Next: negotiated, Audit: &event})
	if err != nil || stored.Audit == nil {
		t.Fatalf("atomic state/outbox commit: %v", err)
	}
	reopened := *repository
	outbox, err := reopened.PendingAudits(ctx, 16)
	if err != nil || len(outbox) != 1 || outbox[0] != *stored.Audit {
		t.Fatalf("outbox disappeared on reconstruction: %v", err)
	}
	loaded, err := reopened.Load(ctx, effect.Scope.InvocationID)
	if err != nil || !sameEffect(loaded.Effect, negotiated) {
		t.Fatal("outbox and invocation state were split")
	}
	if err := reopened.AcknowledgeAudit(ctx, outbox[0].Sequence); err != nil {
		t.Fatal(err)
	}
	outbox, err = repository.PendingAudits(ctx, 16)
	if err != nil || len(outbox) != 0 {
		t.Fatal("acknowledged outbox replayed from process memory")
	}
}

func TestNativeRepositoryCanonicalSnapshotPreservesNanosecondsAndRejectsDrift(t *testing.T) {
	repository, source := nativeRepositoryFixture(t)
	ctx := context.Background()
	fixture := newGatewayFixture(t, ReplayNever)
	effect := admitFixtureEffect(t, fixture)
	if err := repository.SetCurrentAuthority(ctx, effect.Scope); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Admit(ctx, effect); err != nil {
		t.Fatal(err)
	}
	working, err := decodeNativeRepository(source.state, repository.objectID, 128, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	key := dispatchClaimKey(effect.Scope.InvocationID.String(), 7)
	working.providerStarts[key] = providerStartRecord{Status: providerStartActive, Permit: ProviderStartPermit{LeaseExpiresAtUnixNano: 1_800_000_000_123456789}}
	encoded, err := encodeNativeRepository(working, repository.objectID, 128, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	roundtrip, err := decodeNativeRepository(encoded, repository.objectID, 128, 1<<20)
	if err != nil || roundtrip.providerStarts[key].Permit.LeaseExpiresAtUnixNano != 1_800_000_000_123456789 {
		t.Fatalf("nanosecond or binary claim key truncated: %v", err)
	}
	value, err := canonical.Decode(encoded, nativeStateOptions(1<<20))
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"extra-field", "wrong-object", "duplicate-map-key", "capacity", "bytes"} {
		t.Run(kind, func(t *testing.T) {
			fresh, err := canonical.Decode(encoded, nativeStateOptions(1<<20))
			if err != nil {
				t.Fatal(err)
			}
			wire := fresh.(canonical.Map)
			switch kind {
			case "extra-field":
				wire["Invented"] = true
			case "wrong-object":
				wire["ObjectID"] = canonical.Bytes("wrong")
			case "duplicate-map-key":
				a := wire["Effects"].(canonical.Array)
				wire["Effects"] = append(a, a[0])
			}
			modified, err := canonical.Encode(wire, nativeStateOptions(1<<20))
			if err != nil {
				t.Fatal(err)
			}
			records, maximum := 128, 1<<20
			if kind == "capacity" {
				records = 0
			}
			if kind == "bytes" {
				maximum = len(modified) - 1
			}
			if _, err := decodeNativeRepository(modified, repository.objectID, records, maximum); err == nil {
				t.Fatal("invalid bounded snapshot accepted")
			}
		})
	}
	_ = value
}
