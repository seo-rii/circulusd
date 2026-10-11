package modelgateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"math"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/celld"
	"github.com/hancomac/circulusd/internal/celldbridge"
	"github.com/hancomac/circulusd/internal/dependency"
	dependencycontract "github.com/hancomac/circulusd/internal/dependency/contracttest"
	"github.com/hancomac/circulusd/internal/identity"
)

// This fault-injecting source is explicitly an unqualified in-process fixture.
// contracttest signatures exercise constructors; they are never live evidence.
type nativeModelFixture struct {
	*dependencycontract.ProductionProofs
	mu               sync.Mutex
	objects          map[string]celldbridge.Snapshot
	reads            int
	commits          int
	barriers         uint64
	conflicts        int
	commitLoss       bool
	barrierLoss      bool
	lastObject       string
	conflictMutation func(*celldbridge.Snapshot)
}

func (fixture *nativeModelFixture) ReadSnapshot(ctx context.Context, request celldbridge.SnapshotRequest) (celldbridge.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return celldbridge.Snapshot{}, err
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.reads++
	fixture.lastObject = request.ObjectID
	snapshot, found := fixture.objects[request.ObjectID]
	if !found {
		snapshot = celldbridge.Snapshot{SnapshotRef: celldbridge.SnapshotRef{ObjectID: request.ObjectID, StateDigest: celld.Digest(sha256.Sum256(nil))}}
	}
	snapshot.State = bytes.Clone(snapshot.State)
	return snapshot, nil
}

func (fixture *nativeModelFixture) ReadReceipt(_ context.Context, request celldbridge.ReceiptRequest) (celldbridge.ReceiptResult, error) {
	return celldbridge.ReceiptResult{Snapshot: request.Snapshot, CommandID: request.CommandID}, nil
}

func (fixture *nativeModelFixture) CompareAndCommit(ctx context.Context, request celldbridge.CommitRequest) (celldbridge.CommitResult, error) {
	if err := ctx.Err(); err != nil {
		return celldbridge.CommitResult{}, err
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.commits++
	if fixture.conflictMutation != nil {
		current := fixture.objects[request.Snapshot.ObjectID]
		fixture.conflictMutation(&current)
		fixture.conflictMutation = nil
		current.StateDigest = celld.Digest(sha256.Sum256(current.State))
		current.Revision++
		fixture.objects[request.Snapshot.ObjectID] = current
		return celldbridge.CommitResult{}, celldbridge.ErrSnapshotConflict
	}
	if fixture.conflicts != 0 {
		fixture.conflicts--
		return celldbridge.CommitResult{}, celldbridge.ErrSnapshotConflict
	}
	current, found := fixture.objects[request.Snapshot.ObjectID]
	if !found {
		current = celldbridge.Snapshot{SnapshotRef: celldbridge.SnapshotRef{ObjectID: request.Snapshot.ObjectID, StateDigest: celld.Digest(sha256.Sum256(nil))}}
	}
	if current.SnapshotRef != request.Snapshot {
		return celldbridge.CommitResult{}, celldbridge.ErrSnapshotConflict
	}
	if len(request.Receipts) != 0 {
		return celldbridge.CommitResult{}, errors.New("fixture does not implement receipts")
	}
	if request.StateWritten {
		current.State = bytes.Clone(request.State)
		current.StateDigest = celld.Digest(sha256.Sum256(current.State))
	}
	current.Exists = true
	current.Revision++
	fixture.objects[current.ObjectID] = current
	if fixture.commitLoss {
		fixture.commitLoss = false
		return celldbridge.CommitResult{}, errors.New("persisted native commit response lost")
	}
	return celldbridge.CommitResult{Snapshot: current.SnapshotRef, RequestDigest: request.RequestDigest,
		Token: celld.CommitToken{ObjectID: current.ObjectID, Revision: current.Revision}}, nil
}

func (fixture *nativeModelFixture) ConfirmBarrier(ctx context.Context, request celldbridge.BarrierRequest) (celldbridge.BarrierResult, error) {
	if err := ctx.Err(); err != nil {
		return celldbridge.BarrierResult{}, err
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	current, found := fixture.objects[request.Token.ObjectID]
	if !found || current.Revision < request.Token.Revision {
		return celldbridge.BarrierResult{}, errors.New("missing committed revision")
	}
	fixture.barriers++
	if fixture.barrierLoss {
		fixture.barrierLoss = false
		return celldbridge.BarrierResult{}, errors.New("barrier response lost")
	}
	return celldbridge.BarrierResult{Token: request.Token, Marker: request.Marker, ObservedRevision: current.Revision, BarrierSerial: fixture.barriers}, nil
}

func nativeModelStorage(t *testing.T, missing dependency.AtomicGroup) (*nativeModelFixture, dependency.Verified[*celldbridge.Storage]) {
	t.Helper()
	groups := append(nativeModelGroups(), celldbridge.AtomicNativeStorage)
	groups = slices.DeleteFunc(groups, func(group dependency.AtomicGroup) bool { return group == missing })
	slices.Sort(groups)
	proofs := dependencycontract.NewProductionProofs(t, groups)
	fixture := &nativeModelFixture{ProductionProofs: proofs, objects: make(map[string]celldbridge.Snapshot)}
	transport := dependencycontract.Verify[celldbridge.NativeTransport](t, proofs, fixture, groups)
	storage, err := celldbridge.New(celldbridge.Config{Transport: transport, MaximumAttempts: 8,
		Bounds: celldbridge.Bounds{MaxStateBytes: 131072, MaxReceiptResponseBytes: 1024, MaxCapabilityClaims: 1,
			MaxCapabilityClaimBytes: 1024, MaxReceiptLookups: 1, MaxReceiptWrites: 1, MaxTransactionBytes: 262144}})
	if err != nil {
		t.Fatal(err)
	}
	return fixture, dependencycontract.Verify(t, proofs, storage, groups)
}

func nativeModelConfig(storage dependency.Verified[*celldbridge.Storage], reference *fixture) NativeFactoryConfig {
	configuration := reference.configuration()
	configuration.AllowReferenceMemory = false
	return NativeFactoryConfig{Storage: storage, ObjectID: "native-model-test", MaximumRecords: 64, MaximumStateBytes: 131072,
		Configuration: configuration, QuotaLimits: []NativeQuotaLimit{{reference.scope.TenantID, reference.scope.UserID, 100}},
		Providers: map[string]NativeProviderConfig{"provider-a": {UnavailableReason: "model port is not configured"}}}
}

func nativeModelSetup(t *testing.T) (*NativeFactory, *nativeModelFixture, NativeFactoryConfig, *fixture) {
	t.Helper()
	reference := newFixture(t)
	source, storage := nativeModelStorage(t, "")
	config := nativeModelConfig(storage, reference)
	factory, err := NewNativeFactory(config)
	if err != nil {
		t.Fatal(err)
	}
	return factory, source, config, reference
}

func nativeModelGrant(t *testing.T, reference *fixture, scope ValidatedAuthority, bearer string) NativeAuthorityGrant {
	t.Helper()
	digest, err := NativeBearerDigest(OpaqueAuthority(bearer))
	if err != nil {
		t.Fatal(err)
	}
	return NativeAuthorityGrant{BearerDigest: digest, Scope: scope, RequestDigest: reference.admissionRequest().RequestDigest,
		ExpiresAtUnixNano: time.Now().Add(time.Hour).UnixNano(), Permissions: []string{"model.cancel", "model.dispatch", "model.resume"}}
}

func nativeModelQuotaRequest(reference *fixture, scope ValidatedAuthority) QuotaRequest {
	return QuotaRequest{TenantID: scope.TenantID, UserID: scope.UserID, SessionID: scope.SessionID, TurnID: scope.TurnID,
		EffectID: scope.EffectID, InvocationID: scope.InvocationID, RuntimeRevision: scope.RuntimeRevision, Generations: scope.Generations,
		RequestDigest: reference.admissionRequest().RequestDigest, ContextTokens: 10, OutputTokens: 10}
}

func TestNativeModelRequiresConcreteQualifiedStorageAndImmutableUnavailablePolicy(t *testing.T) {
	reference := newFixture(t)
	for _, group := range nativeModelGroups() {
		// Concrete Storage construction already rejects missing command-receipt
		// and native-storage contracts before this factory can receive it.
		if group == dependency.AtomicCommandReceipt {
			continue
		}
		_, storage := nativeModelStorage(t, group)
		if factory, err := NewNativeFactory(nativeModelConfig(storage, reference)); factory != nil || !errors.Is(err, dependency.ErrRequirementMismatch) {
			t.Fatalf("missing %s: factory=%v err=%v", group, factory, err)
		}
	}
	if factory, err := NewNativeFactory(NativeFactoryConfig{}); factory != nil || !errors.Is(err, dependency.ErrUnverifiedDependency) {
		t.Fatalf("zero source: %v %v", factory, err)
	}
	factory, source, config, _ := nativeModelSetup(t)
	for _, mutate := range []func(*NativeFactoryConfig){
		func(c *NativeFactoryConfig) { c.Configuration.AllowReferenceMemory = true },
		func(c *NativeFactoryConfig) { c.ObjectID = "" },
		func(c *NativeFactoryConfig) { c.MaximumRecords = 0 },
		func(c *NativeFactoryConfig) { c.MaximumStateBytes = celldbridge.MaximumStateBytes + 1 },
		func(c *NativeFactoryConfig) { c.QuotaLimits = []NativeQuotaLimit{c.QuotaLimits[0], c.QuotaLimits[0]} },
		func(c *NativeFactoryConfig) { c.QuotaLimits = []NativeQuotaLimit{{MaximumTokens: 100}} },
	} {
		candidate := config
		mutate(&candidate)
		if _, err := NewNativeFactory(candidate); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("invalid policy: %v", err)
		}
	}
	config.TokenCounter = reference.counter
	if _, err := NewNativeFactory(config); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("raw counter admitted: %v", err)
	}
	config.TokenCounter = nil
	config.Providers = map[string]NativeProviderConfig{"provider-a": {Port: reference.provider, UnavailableReason: "unavailable"}}
	if _, err := NewNativeFactory(config); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("raw provider admitted: %v", err)
	}
	config.Configuration.Grants[0].MaxTotalTokens = 1
	config.QuotaLimits[0].MaximumTokens = 1
	if factory.configuration.Grants[0].MaxTotalTokens == 1 || factory.quotaLimits[0].MaximumTokens == 1 {
		t.Fatal("mutable policy retained")
	}
	candidates := factory.Candidates()
	delete(candidates.Providers, "provider-a")
	if len(factory.Candidates().Providers) != 1 {
		t.Fatal("candidate map leaked")
	}
	if source.reads != 0 {
		t.Fatal("constructors performed native mutations")
	}
}

func TestNativeModelAuthorityRetainsDigestAndCurrentFenceAcrossReopenAndExpiry(t *testing.T) {
	factory, source, config, reference := nativeModelSetup(t)
	grant := nativeModelGrant(t, reference, reference.scope, "retained-secret-bearer")
	if err := factory.ProvisionGrant(context.Background(), grant); err != nil {
		t.Fatal(err)
	}
	source.mu.Lock()
	stored := bytes.Clone(source.objects[config.ObjectID].State)
	source.mu.Unlock()
	if bytes.Contains(stored, []byte("retained-secret-bearer")) {
		t.Fatal("bearer persisted")
	}
	reopened, err := NewNativeFactory(config)
	if err != nil {
		t.Fatal(err)
	}
	request := AdmissionAuthorityRequest{EffectID: grant.Scope.EffectID, InvocationID: grant.Scope.InvocationID, RequestDigest: grant.RequestDigest, Permission: "model.dispatch"}
	before := source.barriers
	validated, err := reopened.authority.ValidateAdmission(context.Background(), OpaqueAuthority("retained-secret-bearer"), request)
	if err != nil || validated != grant.Scope || source.barriers != before+1 {
		t.Fatalf("fresh validation: %v %v", validated, err)
	}
	quotaRequest := nativeModelQuotaRequest(reference, grant.Scope)
	if _, err := reopened.quota.Admit(context.Background(), quotaRequest); err != nil {
		t.Fatal(err)
	}
	current := grant.Scope
	current.Generations.Placement++
	if err := reopened.SetCurrentAuthority(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	if err := reopened.SetCurrentAuthority(context.Background(), grant.Scope); !errors.Is(err, ErrStaleAuthority) {
		t.Fatalf("fence rollback: %v", err)
	}
	if scope, err := reopened.authority.ValidateAdmission(context.Background(), OpaqueAuthority("retained-secret-bearer"), request); scope != (ValidatedAuthority{}) || !errors.Is(err, ErrStaleAuthority) {
		t.Fatalf("stale bearer: %v %v", scope, err)
	}
	currentGrant := nativeModelGrant(t, reference, current, "current-bearer")
	if err := reopened.ProvisionGrant(context.Background(), currentGrant); err != nil {
		t.Fatal(err)
	}
	reopened.now = func() time.Time { return time.Unix(0, currentGrant.ExpiresAtUnixNano+1) }
	if scope, err := reopened.authority.ValidateAdmission(context.Background(), OpaqueAuthority("current-bearer"), request); scope != (ValidatedAuthority{}) || !errors.Is(err, ErrStaleAuthority) {
		t.Fatalf("expired admission: %v %v", scope, err)
	}
	settlement := SettlementAuthorityRequest{TenantID: grant.Scope.TenantID, UserID: grant.Scope.UserID, SessionID: grant.Scope.SessionID, TurnID: grant.Scope.TurnID,
		EffectID: grant.Scope.EffectID, InvocationID: grant.Scope.InvocationID, RuntimeRevision: grant.Scope.RuntimeRevision, Generations: grant.Scope.Generations,
		RequestDigest: grant.RequestDigest, ProviderRequestID: "provider-request", Attempt: 1, EffectRevision: 4, State: StateCompleted, Outcome: OutcomeCompleted, TerminalDigest: testDigest(9)}
	if scope, err := reopened.authority.ValidateSettlement(context.Background(), OpaqueAuthority("current-bearer"), settlement); scope != current || err != nil {
		t.Fatalf("cleanup incorrectly depended on TTL: %v %v", scope, err)
	}
	settlement.InvocationID = mustID(t, identity.Invocation, 99)
	if _, err := reopened.authority.ValidateSettlement(context.Background(), OpaqueAuthority("current-bearer"), settlement); !errors.Is(err, ErrStaleAuthority) {
		t.Fatalf("wrong admitted identity: %v", err)
	}
}

func TestNativeModelQuotaConcurrentReplayCapacityAndReopen(t *testing.T) {
	factory, source, config, reference := nativeModelSetup(t)
	grant := nativeModelGrant(t, reference, reference.scope, "quota-bearer")
	if err := factory.ProvisionGrant(context.Background(), grant); err != nil {
		t.Fatal(err)
	}
	request := nativeModelQuotaRequest(reference, reference.scope)
	const workers = 6
	errorsOut := make(chan error, workers)
	permits := make(chan QuotaPermit, workers)
	var group sync.WaitGroup
	for i := 0; i < workers; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			p, err := factory.quota.Admit(context.Background(), request)
			errorsOut <- err
			permits <- p
		}()
	}
	group.Wait()
	close(errorsOut)
	close(permits)
	for err := range errorsOut {
		if err != nil {
			t.Fatal(err)
		}
	}
	for permit := range permits {
		if permit != nativeQuotaPermit(request) {
			t.Fatalf("replay changed reservation: %v", permit)
		}
	}
	conflict := request
	conflict.OutputTokens++
	if p, err := factory.quota.Admit(context.Background(), conflict); p != (QuotaPermit{}) || !errors.Is(err, ErrQuotaConflict) {
		t.Fatalf("conflicting budget: %v %v", p, err)
	}
	requests := make([]QuotaRequest, 6)
	for i := range requests {
		scope := reference.scope
		scope.EffectID = mustID(t, identity.Effect, byte(32+i))
		scope.InvocationID = mustID(t, identity.Invocation, byte(32+i))
		if err := factory.ProvisionGrant(context.Background(), nativeModelGrant(t, reference, scope, scope.InvocationID.String())); err != nil {
			t.Fatal(err)
		}
		requests[i] = nativeModelQuotaRequest(reference, scope)
	}
	errorsOut = make(chan error, len(requests))
	for _, req := range requests {
		group.Add(1)
		go func(req QuotaRequest) {
			defer group.Done()
			_, err := factory.quota.Admit(context.Background(), req)
			errorsOut <- err
		}(req)
	}
	group.Wait()
	close(errorsOut)
	success, limited := 0, 0
	for err := range errorsOut {
		if err == nil {
			success++
		} else if errors.Is(err, ErrQuotaExceeded) {
			limited++
		} else {
			t.Fatal(err)
		}
	}
	if success != 4 || limited != 2 {
		t.Fatalf("atomic capacity: success=%d limited=%d", success, limited)
	}
	reopened, err := NewNativeFactory(config)
	if err != nil {
		t.Fatal(err)
	}
	before := source.barriers
	permit, found, err := reopened.InspectReservation(context.Background(), request)
	if err != nil || !found || permit != nativeQuotaPermit(request) || source.barriers != before+1 {
		t.Fatalf("durable reopen: %v %v %v", permit, found, err)
	}
	request.OutputTokens = math.MaxUint64
	if _, err := factory.quota.Admit(context.Background(), request); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("overflow accepted: %v", err)
	}
}

func TestNativeModelLostRepliesAndBarriersNeverExposeSuccess(t *testing.T) {
	for _, loss := range []string{"commit", "barrier"} {
		t.Run(loss, func(t *testing.T) {
			factory, source, config, reference := nativeModelSetup(t)
			grant := nativeModelGrant(t, reference, reference.scope, "loss-bearer")
			if err := factory.ProvisionGrant(context.Background(), grant); err != nil {
				t.Fatal(err)
			}
			request := nativeModelQuotaRequest(reference, grant.Scope)
			source.mu.Lock()
			source.commitLoss, source.barrierLoss = loss == "commit", loss == "barrier"
			source.mu.Unlock()
			if permit, err := factory.quota.Admit(context.Background(), request); permit != (QuotaPermit{}) || !errors.Is(err, ErrStateDependenciesNotDurable) {
				t.Fatalf("ambiguous reservation published: permit=%v err=%v", permit, err)
			}
			reopened, err := NewNativeFactory(config)
			if err != nil {
				t.Fatal(err)
			}
			permit, found, err := reopened.InspectReservation(context.Background(), request)
			if err != nil || !found || permit != nativeQuotaPermit(request) {
				t.Fatalf("persisted facts missing: %v %v %v", permit, found, err)
			}
			if replay, err := reopened.quota.Admit(context.Background(), request); err != nil || replay != permit {
				t.Fatalf("ambiguous replay restarted reservation: %v %v", replay, err)
			}
			source.mu.Lock()
			source.barrierLoss = true
			source.mu.Unlock()
			admission := AdmissionAuthorityRequest{EffectID: grant.Scope.EffectID, InvocationID: grant.Scope.InvocationID, RequestDigest: grant.RequestDigest, Permission: "model.dispatch"}
			if scope, err := reopened.authority.ValidateAdmission(context.Background(), OpaqueAuthority("loss-bearer"), admission); scope != (ValidatedAuthority{}) || !errors.Is(err, ErrStateDependenciesNotDurable) {
				t.Fatalf("validation survived ambiguous barrier: %v %v", scope, err)
			}
		})
	}
}

func TestNativeModelCallbackRetryRechecksActualCurrentFence(t *testing.T) {
	factory, source, config, reference := nativeModelSetup(t)
	grant := nativeModelGrant(t, reference, reference.scope, "retry-bearer")
	if err := factory.ProvisionGrant(context.Background(), grant); err != nil {
		t.Fatal(err)
	}
	source.mu.Lock()
	source.conflictMutation = func(snapshot *celldbridge.Snapshot) {
		state, err := factory.decodeState(snapshot.State)
		if err != nil {
			t.Fatal(err)
		}
		fence := state.Fences[nativeFenceKey(grant.Scope)]
		fence.Generations.Policy++
		state.Fences[nativeFenceKey(grant.Scope)] = fence
		snapshot.State, err = factory.encodeState(state)
		if err != nil {
			t.Fatal(err)
		}
	}
	source.mu.Unlock()
	request := nativeModelQuotaRequest(reference, grant.Scope)
	if permit, err := factory.quota.Admit(context.Background(), request); permit != (QuotaPermit{}) || !errors.Is(err, ErrStaleAuthority) {
		t.Fatalf("previous callback result escaped retry: %v %v", permit, err)
	}
	if permit, found, err := factory.InspectReservation(context.Background(), request); err != nil || found || permit != (QuotaPermit{}) {
		t.Fatalf("failed retry retained reservation: %v %v %v", permit, found, err)
	}
	source.mu.Lock()
	state, err := factory.decodeState(source.objects[config.ObjectID].State)
	source.mu.Unlock()
	if err != nil || len(state.Reservations) != 0 {
		t.Fatalf("stale reservation persisted: %v", err)
	}
}

func TestNativeModelRejectsCorruptionAliasingAndDifferentPolicy(t *testing.T) {
	factory, source, config, reference := nativeModelSetup(t)
	grant := nativeModelGrant(t, reference, reference.scope, "corruption-bearer")
	if err := factory.ProvisionGrant(context.Background(), grant); err != nil {
		t.Fatal(err)
	}
	request := nativeModelQuotaRequest(reference, grant.Scope)
	if _, err := factory.quota.Admit(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	source.mu.Lock()
	original := bytes.Clone(source.objects[config.ObjectID].State)
	source.mu.Unlock()
	mutations := []func(canonical.Map){
		func(w canonical.Map) { w["Unknown"] = true },
		func(w canonical.Map) { w["ObjectID"] = canonical.Bytes("different-object") },
		func(w canonical.Map) { w["PolicyDigest"] = canonical.Bytes(make([]byte, 32)) },
		func(w canonical.Map) {
			grants := w["Grants"].(canonical.Array)
			w["Grants"] = append(grants, grants[0])
		},
		func(w canonical.Map) { w["Fences"] = nil },
		func(w canonical.Map) {
			reservations := w["Reservations"].(canonical.Array)
			r := reservations[0].(canonical.Array)[1].(canonical.Map)
			r["Permit"].(canonical.Map)["OutputTokens"] = canonical.Bytes(make([]byte, 8))
		},
	}
	for _, mutate := range mutations {
		value, err := canonical.Decode(original, factory.stateOptions())
		if err != nil {
			t.Fatal(err)
		}
		mutate(value.(canonical.Map))
		encoded, err := canonical.Encode(value, factory.stateOptions())
		if err != nil {
			t.Fatal(err)
		}
		source.mu.Lock()
		snapshot := source.objects[config.ObjectID]
		snapshot.State = encoded
		snapshot.StateDigest = celld.Digest(sha256.Sum256(encoded))
		source.objects[config.ObjectID] = snapshot
		source.mu.Unlock()
		if permit, found, err := factory.InspectReservation(context.Background(), request); permit != (QuotaPermit{}) || found || !errors.Is(err, ErrStateDependenciesNotDurable) {
			t.Fatalf("corrupt facts admitted: %v %v %v", permit, found, err)
		}
	}
	source.mu.Lock()
	snapshot := source.objects[config.ObjectID]
	snapshot.State = original
	snapshot.StateDigest = celld.Digest(sha256.Sum256(original))
	source.objects[config.ObjectID] = snapshot
	source.mu.Unlock()
	changed := config
	changed.QuotaLimits = slices.Clone(config.QuotaLimits)
	changed.QuotaLimits[0].MaximumTokens++
	reopened, err := NewNativeFactory(changed)
	if err != nil {
		t.Fatal(err)
	}
	if permit, found, err := reopened.InspectReservation(context.Background(), request); permit != (QuotaPermit{}) || found || !errors.Is(err, ErrStateDependenciesNotDurable) {
		t.Fatalf("different immutable policy admitted: %v %v %v", permit, found, err)
	}
}

func nativeModelVerifiedDependencies(t *testing.T, factory *NativeFactory, fixture *nativeModelFixture) ProductionDependencies {
	t.Helper()
	candidates := factory.Candidates()
	groups := append(nativeModelGroups(), celldbridge.AtomicNativeStorage)
	slices.Sort(groups)
	return ProductionDependencies{
		Authority:    dependencycontract.Verify[ProductionAuthorityValidator](t, fixture.ProductionProofs, candidates.Authority, groups),
		Quota:        dependencycontract.Verify[ProductionQuotaAdmitter](t, fixture.ProductionProofs, candidates.Quota, groups),
		Dispatches:   dependencycontract.Verify[ProductionDispatchCoordinator](t, fixture.ProductionProofs, candidates.Dispatches, groups),
		TokenCounter: candidates.TokenCounter, Providers: candidates.Providers,
	}
}

func TestNativeModelExactFactorySealStillFailsClosedForUnimplementedPaths(t *testing.T) {
	factory, source, config, reference := nativeModelSetup(t)
	verified := nativeModelVerifiedDependencies(t, factory, source)
	sealed, err := factory.SealDependencies(verified)
	if err != nil {
		t.Fatal(err)
	}
	if sealed.factory != factory {
		t.Fatal("missing exact seal")
	}
	if gateway, err := NewProductionGateway(config.Configuration, sealed); gateway != nil || !errors.Is(err, ErrStateDependenciesNotDurable) {
		t.Fatalf("primitive factory became admitted gateway: %v %v", gateway, err)
	}
	other, err := NewNativeFactory(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.SealDependencies(verified); !errors.Is(err, ErrStateDependenciesNotDurable) {
		t.Fatalf("cross-factory adapters accepted: %v", err)
	}
	copyDeps := verified
	copyDeps.TokenCounter = reference.counter
	if _, err := factory.SealDependencies(copyDeps); !errors.Is(err, ErrStateDependenciesNotDurable) {
		t.Fatalf("counter injection: %v", err)
	}
	copyDeps = verified
	copyDeps.Providers = map[string]Provider{"provider-a": reference.provider}
	if _, err := factory.SealDependencies(copyDeps); !errors.Is(err, ErrStateDependenciesNotDurable) {
		t.Fatalf("provider injection: %v", err)
	}
	delete(verified.Providers, "provider-a")
	if len(sealed.Providers) != 1 {
		t.Fatal("sealed provider map changed")
	}
	candidates := factory.Candidates()
	if candidates.Quota.Durability().AtomicReservationSettlement || candidates.Dispatches.Durability() != (DispatchDurability{}) {
		t.Fatal("unimplemented capability advertised")
	}
	if n, err := candidates.TokenCounter.Count(context.Background(), TokenCountRequest{}); n != 0 || !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("unavailable count: %d %v", n, err)
	}
	availability, err := candidates.Providers["provider-a"].Availability(context.Background())
	if err != nil || availability.Available {
		t.Fatalf("available provider invented: %v %v", availability, err)
	}
	if receipt, err := candidates.Quota.Settle(context.Background(), QuotaSettlementRequest{}); receipt != (QuotaSettlementReceipt{}) || !errors.Is(err, ErrSettlementNotReady) {
		t.Fatalf("unsealed settlement: %v %v", receipt, err)
	}
	if permit, err := candidates.Dispatches.CommitAndClaimDispatch(context.Background(), DispatchCommitRequest{}); permit != (DispatchPermit{}) || !errors.Is(err, ErrDispatchNotDurable) {
		t.Fatalf("independent start authority: %v %v", permit, err)
	}
	if permit, err := candidates.Dispatches.CommitAndClaimCancellation(context.Background(), CancellationCommitRequest{}); permit != (CancellationPermit{}) || !errors.Is(err, ErrDispatchNotDurable) {
		t.Fatalf("independent cancellation: %v %v", permit, err)
	}
	if permit, err := candidates.Dispatches.CommitAndClaimResume(context.Background(), ResumeCommitRequest{}); permit != (ResumePermit{}) || !errors.Is(err, ErrDispatchNotDurable) {
		t.Fatalf("independent resume: %v %v", permit, err)
	}
	if permit, err := candidates.Dispatches.CommitAndClaimSettlement(context.Background(), SettlementCommitRequest{}); permit != (SettlementPermit{}) || !errors.Is(err, ErrSettlementNotReady) {
		t.Fatalf("independent settlement: %v %v", permit, err)
	}
	if permit, err := candidates.Dispatches.CommitAndClaimUncertainResolution(context.Background(), UncertainResolutionCommitRequest{}); permit != (UncertainResolutionPermit{}) || !errors.Is(err, ErrSettlementNotReady) {
		t.Fatalf("independent resolution: %v %v", permit, err)
	}
	if err := candidates.Dispatches.BeginProviderDispatch(context.Background(), DispatchPermit{}); !errors.Is(err, ErrDispatchNotDurable) {
		t.Fatal(err)
	}
	if err := candidates.Dispatches.CommitProviderAccepted(context.Background(), ProviderAcceptedCommitRequest{}); !errors.Is(err, ErrDispatchNotDurable) {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(factory.configuration, config.Configuration) {
		t.Fatal("configuration binding changed")
	}
}
