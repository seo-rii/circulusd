package mcpgateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/celld"
	"github.com/hancomac/circulusd/internal/celldbridge"
	"github.com/hancomac/circulusd/internal/dependency"
	dependencycontract "github.com/hancomac/circulusd/internal/dependency/contracttest"
	"github.com/hancomac/circulusd/internal/effectledger"
	"github.com/hancomac/circulusd/internal/identity"
)

// One fixture native transport serves both repository and NativeLedger through
// the same concrete Storage. It models CAS/barriers; it is never live evidence.
type nativeHTTPSharedSource struct {
	mcpRuntimeProof
	mu       sync.Mutex
	objects  map[string]celldbridge.Snapshot
	barriers uint64
}

type nativeHTTPObservedStarter struct {
	starter *SessionDispatchStarter
	err     error
}

func (observed *nativeHTTPObservedStarter) RouteDigest() broker.Digest {
	return observed.starter.RouteDigest()
}
func (observed *nativeHTTPObservedStarter) Start(ctx context.Context, claim broker.ClaimedDispatchStart) error {
	observed.err = observed.starter.Start(ctx, claim)
	return observed.err
}

func (source *nativeHTTPSharedSource) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	return source.respond(ctx, challenge)
}

func (source *nativeHTTPSharedSource) snapshot(object string) celldbridge.Snapshot {
	state, found := source.objects[object]
	if !found {
		state = celldbridge.Snapshot{SnapshotRef: celldbridge.SnapshotRef{ObjectID: object, StateDigest: sha256.Sum256(nil)}}
	}
	state.State = bytes.Clone(state.State)
	return state
}
func (source *nativeHTTPSharedSource) ReadSnapshot(_ context.Context, request celldbridge.SnapshotRequest) (celldbridge.Snapshot, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.snapshot(request.ObjectID), nil
}
func (source *nativeHTTPSharedSource) ReadReceipt(_ context.Context, request celldbridge.ReceiptRequest) (celldbridge.ReceiptResult, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.snapshot(request.Snapshot.ObjectID).SnapshotRef != request.Snapshot {
		return celldbridge.ReceiptResult{}, celldbridge.ErrSnapshotConflict
	}
	return celldbridge.ReceiptResult{Snapshot: request.Snapshot, CommandID: request.CommandID}, nil
}
func (source *nativeHTTPSharedSource) CompareAndCommit(_ context.Context, request celldbridge.CommitRequest) (celldbridge.CommitResult, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	current := source.snapshot(request.Snapshot.ObjectID)
	if current.SnapshotRef != request.Snapshot {
		return celldbridge.CommitResult{}, celldbridge.ErrSnapshotConflict
	}
	if len(request.Receipts) != 0 {
		return celldbridge.CommitResult{}, celldbridge.ErrInvalidRequest
	}
	if request.StateWritten {
		current.State = bytes.Clone(request.State)
	}
	current.Exists = true
	current.Revision++
	current.StateDigest = sha256.Sum256(current.State)
	source.objects[current.ObjectID] = current
	return celldbridge.CommitResult{Snapshot: current.SnapshotRef, RequestDigest: request.RequestDigest, Token: celld.CommitToken{ObjectID: current.ObjectID, Revision: current.Revision}}, nil
}
func (source *nativeHTTPSharedSource) ConfirmBarrier(_ context.Context, request celldbridge.BarrierRequest) (celldbridge.BarrierResult, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	current := source.snapshot(request.Token.ObjectID)
	if current.Revision < request.Token.Revision {
		return celldbridge.BarrierResult{}, celldbridge.ErrInvalidRequest
	}
	source.barriers++
	return celldbridge.BarrierResult{Token: request.Token, Marker: request.Marker, ObservedRevision: current.Revision, BarrierSerial: source.barriers}, nil
}

func TestNativeHTTPProductionSessionUsesSameConcreteStorageAndActualToolResponse(t *testing.T) {
	var calls atomic.Int32
	server := nativeHTTPTestServer(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); nativeHTTPResult(w, r) })
	fixture := newNativeHTTPFixture(t, server.URL)
	source := &nativeHTTPSharedSource{mcpRuntimeProof: fixture.proofs.runtimeProof, objects: make(map[string]celldbridge.Snapshot)}
	storage, err := celldbridge.New(celldbridge.Config{Transport: verifyMCPProduction(t, fixture.proofs, celldbridge.NativeTransport(source)), Bounds: celldbridge.Bounds{MaxStateBytes: 1 << 20, MaxReceiptResponseBytes: 4096, MaxCapabilityClaims: 8, MaxCapabilityClaimBytes: 1024, MaxReceiptLookups: 4, MaxReceiptWrites: 4, MaxTransactionBytes: 2 << 20}, MaximumAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	verified := verifyMCPProduction(t, fixture.proofs, storage)
	wire := testMCPHTTPConfig(server.URL)
	factory, err := NewNativeFactory(NativeFactoryConfig{Repository: NativeRepositoryConfig{Source: verified, ObjectID: "native-session-http-fixture", MaximumRecords: 128, MaximumStateBytes: 1 << 20}, Configuration: fixture.configuration, Providers: map[string]NativeProviderConfig{fixture.effect.ProviderID: {StreamableHTTP: &wire}}})
	if err != nil {
		t.Fatal(err)
	}
	fixture.factory = factory
	fixture.grant.ExpiresAtUnixNano = time.Now().Add(time.Minute).UnixNano()
	if err := factory.ProvisionGrant(context.Background(), fixture.grant); err != nil {
		t.Fatal(err)
	}
	gateway, err := NewProductionGateway(fixture.configuration, qualifyNativeFactory(t, fixture))
	if err != nil {
		t.Fatal(err)
	}
	route := broker.Digest(digestWithByte(97))
	ledger, err := effectledger.NewNativeLedger(effectledger.NativeConfig{Storage: verified, Service: broker.ServiceMCP, RouteDigest: route, Limits: effectledger.ReferenceLimits{MaximumPayloadBytes: 1 << 16, MaximumResultBytes: 1 << 16}, MaximumStateBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	starter, err := NewProductionSessionDispatchStarter(gateway, verifyMCPProduction(t, fixture.proofs, ledger), route)
	if err != nil {
		t.Fatal(err)
	}
	call := sessionCall(fixture.reference)
	dispatch := sessionDispatch(t, fixture.reference, call, route)
	dispatch.EffectID = fixture.effect.Scope.EffectID
	dispatch.InvocationID = fixture.effect.Scope.InvocationID
	dispatch.WorkspaceID = fixture.effect.Scope.WorkspaceID
	command, err := starter.Prepare(context.Background(), dispatch, fixture.effect.Scope.RuntimeRevision, call)
	if err != nil {
		t.Fatal(err)
	}
	claimer := newSessionClaimer(t, dispatch, command)
	observed := &nativeHTTPObservedStarter{starter: starter}
	consumer, err := broker.NewDispatchConsumer(dependencycontract.Verify(t, claimer.ProductionProofs, broker.DispatchStartClaimer(claimer), []dependency.AtomicGroup{dependency.AtomicCommandReceipt, dependency.AtomicEffectLifecycle}), map[broker.EffectService]broker.DispatchStarter{broker.ServiceMCP: observed}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := consumer.StartExactAttempt(context.Background(), broker.DispatchStartRequest{Dispatch: dispatch, CommandDigest: command}); err != nil {
		t.Fatalf("native Session start: %v; underlying: %v", err, observed.err)
	}
	facts, err := ledger.Inspect(context.Background(), sessionLookup(dispatch))
	if err != nil || facts.Terminal.Status != effectledger.TerminalCommitted || facts.ExternalProviderRequestID == "" || calls.Load() != 1 {
		t.Fatalf("actual Session terminal observation: %v/%s/%d", err, facts.Terminal.Status, calls.Load())
	}
	result, err := DecodeSessionDispatchResult(facts.Terminal.Result, testBounds())
	if err != nil || len(result.Output) == 0 || result.ExternalCommitID != "" {
		t.Fatal("native Session result was missing or invented a commit ID")
	}
	loaded, err := factory.repository.Load(context.Background(), fixture.effect.Scope.InvocationID)
	if !errors.Is(err, ErrInvocationNotFound) || loaded.Effect.Scope.InvocationID != (identity.ID{}) {
		t.Fatal("Session path invented a second gateway effect authority")
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.barriers < 8 || len(source.objects) < 2 {
		t.Fatal("native Session/provider facts did not cross shared source barriers")
	}
}
