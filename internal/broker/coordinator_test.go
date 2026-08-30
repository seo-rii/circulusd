package broker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/identity"
	"google.golang.org/protobuf/proto"
)

var (
	tenantID     = mustID(identity.Tenant, "A")
	workspaceID  = mustID(identity.Workspace, "W")
	sessionID    = mustID(identity.Session, "B")
	turnID       = mustID(identity.Turn, "C")
	effectID     = mustID(identity.Effect, "D")
	invocationID = mustID(identity.Invocation, "E")
	commitID     = mustID(identity.Commit, "F")
	resultID     = mustID(identity.Artifact, "G")
)

func TestAcquireEngineStepClampsBudgetAndRequiresCurrentAdmission(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0).UTC()
	store := newFakeStore(baseSnapshot(now))
	coordinator := mustCoordinator(t, store, nil)

	permit, err := coordinator.AcquireEngineStep(context.Background(), EngineStepRequest{
		Authority: baseAuthority(now),
		Now:       now,
		Budget: EngineStepBudget{
			MaximumEvents:         99,
			MaximumEphemeralBytes: 4096,
			MaximumWallClock:      time.Minute,
		},
		OperationKey: "step-1",
	})
	if err != nil {
		t.Fatalf("AcquireEngineStep() error = %v", err)
	}
	if permit.Budget.MaximumEvents != 1 {
		t.Fatalf("maximum events = %d, want 1", permit.Budget.MaximumEvents)
	}
	if permit.Budget.MaximumEphemeralBytes != 4096 {
		t.Fatalf("maximum ephemeral bytes = %d, want 4096", permit.Budget.MaximumEphemeralBytes)
	}
	if !permit.Durable {
		t.Fatal("permit escaped before the durability barrier")
	}
	limited, err := coordinator.AcquireEngineStep(context.Background(), EngineStepRequest{
		Authority: baseAuthority(now), Now: now,
		Budget:       EngineStepBudget{MaximumEvents: 2, MaximumEphemeralBytes: 1 << 30, MaximumWallClock: 24 * time.Hour},
		OperationKey: "step-policy-limit",
	})
	if err != nil {
		t.Fatalf("AcquireEngineStep(policy clamp) error = %v", err)
	}
	if limited.Budget.MaximumEphemeralBytes != store.snapshot.EngineStepLimits.MaximumEphemeralBytes || limited.Budget.MaximumWallClock != store.snapshot.EngineStepLimits.MaximumWallClock {
		t.Fatalf("policy-clamped budget = %#v, want limits %#v", limited.Budget, store.snapshot.EngineStepLimits)
	}
	shortAuthority := baseAuthority(now)
	shortAuthority.ExpiresAt = now.Add(30 * time.Second)
	short, err := coordinator.AcquireEngineStep(context.Background(), EngineStepRequest{
		Authority: shortAuthority, Now: now,
		Budget:       EngineStepBudget{MaximumEvents: 1, MaximumEphemeralBytes: 1, MaximumWallClock: time.Minute},
		OperationKey: "step-authority-limit",
	})
	if err != nil {
		t.Fatalf("AcquireEngineStep(authority clamp) error = %v", err)
	}
	if short.Budget.MaximumWallClock != 30*time.Second {
		t.Fatalf("authority-clamped wall clock = %s, want 30s", short.Budget.MaximumWallClock)
	}

	tests := []struct {
		name   string
		mutate func(*EngineStepRequest)
		want   error
	}{
		{name: "authority expired", mutate: func(request *EngineStepRequest) { request.Now = request.Authority.ExpiresAt }, want: ErrAdmissionExpired},
		{name: "lease expired", mutate: func(request *EngineStepRequest) {
			request.Now = store.snapshot.LeaseExpiresAt
			request.Authority.ExpiresAt = request.Now.Add(time.Hour)
		}, want: ErrLeaseExpired},
		{name: "stale placement", mutate: func(request *EngineStepRequest) { request.Authority.Generations.Placement++ }, want: ErrStaleGeneration},
		{name: "zero trusted time", mutate: func(request *EngineStepRequest) { request.Now = time.Time{} }, want: ErrInvalidRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := EngineStepRequest{
				Authority:    baseAuthority(now),
				Now:          now,
				Budget:       EngineStepBudget{MaximumEvents: 1, MaximumEphemeralBytes: 1, MaximumWallClock: time.Second},
				OperationKey: "separate-" + test.name,
			}
			test.mutate(&request)
			_, err := coordinator.AcquireEngineStep(context.Background(), request)
			if !errors.Is(err, test.want) {
				t.Fatalf("AcquireEngineStep() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestAcquireEngineStepRejectsStructurallyInvalidAuthoritativeFence(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_050, 0).UTC()
	tests := []struct {
		name   string
		mutate func(*TurnSnapshot, *ValidatedTurnFence)
	}{
		{name: "empty identity", mutate: func(snapshot *TurnSnapshot, fence *ValidatedTurnFence) {
			snapshot.TenantID = identity.ID{}
			fence.TenantID = identity.ID{}
		}},
		{name: "empty workspace", mutate: func(snapshot *TurnSnapshot, fence *ValidatedTurnFence) {
			snapshot.WorkspaceID = identity.ID{}
			fence.WorkspaceID = identity.ID{}
		}},
		{name: "wrong workspace kind", mutate: func(snapshot *TurnSnapshot, fence *ValidatedTurnFence) {
			snapshot.WorkspaceID = sessionID
			fence.WorkspaceID = sessionID
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := baseSnapshot(now)
			fence := baseAuthority(now)
			test.mutate(&snapshot, &fence)
			coordinator := mustCoordinator(t, newFakeStore(snapshot), nil)
			_, err := coordinator.AcquireEngineStep(context.Background(), EngineStepRequest{
				Authority: fence, Now: now,
				Budget:       EngineStepBudget{MaximumEvents: 1, MaximumEphemeralBytes: 1, MaximumWallClock: time.Second},
				OperationKey: "invalid-" + test.name,
			})
			if !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("AcquireEngineStep() error = %v, want %v", err, ErrInvalidRequest)
			}
		})
	}
}

func TestAcquireEngineStepRejectsMismatchedWorkspaceFence(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_075, 0).UTC()
	store := newFakeStore(baseSnapshot(now))
	authority := baseAuthority(now)
	authority.WorkspaceID = mustID(identity.Workspace, "other-workspace")

	_, err := mustCoordinator(t, store, nil).AcquireEngineStep(context.Background(), EngineStepRequest{
		Authority: authority,
		Now:       now,
		Budget: EngineStepBudget{
			MaximumEvents:         1,
			MaximumEphemeralBytes: 1,
			MaximumWallClock:      time.Second,
		},
		OperationKey: "mismatched-workspace",
	})
	if !errors.Is(err, ErrFenceMismatch) {
		t.Fatalf("AcquireEngineStep() error = %v, want %v", err, ErrFenceMismatch)
	}
	store.mu.Lock()
	permits := len(store.stepPermits)
	store.mu.Unlock()
	if permits != 0 {
		t.Fatalf("engine-step permits = %d, want 0", permits)
	}
}

func TestCorePermitsRejectCorruptedAuthorityRoutes(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_090, 0).UTC()

	for _, route := range []struct {
		name       string
		corruption receiptRouteCorruption
	}{
		{name: "tenant", corruption: corruptTenantRoute},
		{name: "workspace", corruption: corruptWorkspaceRoute},
	} {
		t.Run(route.name+"/engine", func(t *testing.T) {
			store := newFakeStore(baseSnapshot(now))
			store.corruptReceiptRoute = route.corruption
			_, err := mustCoordinator(t, store, nil).AcquireEngineStep(context.Background(), EngineStepRequest{
				Authority: baseAuthority(now), Now: now,
				Budget:       EngineStepBudget{MaximumEvents: 1, MaximumEphemeralBytes: 1, MaximumWallClock: time.Second},
				OperationKey: "corrupt-engine-route-" + route.name,
			})
			if !errors.Is(err, ErrFenceMismatch) {
				t.Fatalf("AcquireEngineStep() error = %v, want %v", err, ErrFenceMismatch)
			}
		})

		t.Run(route.name+"/preparation", func(t *testing.T) {
			store := newFakeStore(baseSnapshot(now))
			coordinator := mustCoordinator(t, store, nil)
			permit := acquirePermit(t, coordinator, now, "corrupt-preparation-permit-"+route.name)
			store.mu.Lock()
			store.corruptReceiptRoute = route.corruption
			store.mu.Unlock()
			_, err := coordinator.CommitEngineStep(context.Background(), EngineStepCommit{
				Permit: permit, Now: now, OperationKey: "corrupt-preparation-route-" + route.name,
				RequestDigest: digest(121),
				Boundary: EngineBoundary{Kind: BoundaryEffectRequest, CheckpointDigest: digest(122), Effect: &EffectIntent{
					Service: ServiceExecutor, Operation: "run", ReplayPolicy: ReplayIdempotencyKey, RequestDigest: digest(2),
				}},
			})
			if !errors.Is(err, ErrFenceMismatch) {
				t.Fatalf("CommitEngineStep() error = %v, want %v", err, ErrFenceMismatch)
			}
		})

		t.Run(route.name+"/dispatch", func(t *testing.T) {
			snapshot := baseSnapshot(now)
			snapshot.ActiveEffect = baseEffect(EffectPrepared)
			store := newFakeStore(snapshot)
			store.corruptReceiptRoute = route.corruption
			_, err := mustCoordinator(t, store, nil).AdmitDispatch(context.Background(), baseDispatchRequest(now))
			if !errors.Is(err, ErrFenceMismatch) {
				t.Fatalf("AdmitDispatch() error = %v, want %v", err, ErrFenceMismatch)
			}
		})
	}
}

func TestEngineStepCommitIsBoundedIdempotentAndFailClosed(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_100, 0).UTC()
	store := newFakeStore(baseSnapshot(now))
	coordinator := mustCoordinator(t, store, nil)
	permit := acquirePermit(t, coordinator, now, "step-commit")
	boundary := EngineBoundary{Kind: BoundaryEffectRequest, CheckpointDigest: digest(1), Effect: &EffectIntent{
		Service: ServiceExecutor, Operation: "run", ReplayPolicy: ReplayIdempotencyKey, RequestDigest: digest(2),
	}}

	receipt, err := coordinator.CommitEngineStep(context.Background(), EngineStepCommit{
		Permit: permit, Now: now, OperationKey: "commit-1", RequestDigest: digest(3), Boundary: boundary,
	})
	if err != nil {
		t.Fatalf("CommitEngineStep() error = %v", err)
	}
	// Model a crash after the durable effect boundary committed but before its
	// receipt reached the caller. The same operation must still reach the
	// store's idempotency record even though an effect is now active.
	store.mu.Lock()
	store.snapshot.ActiveEffect = baseEffect(EffectPrepared)
	store.mu.Unlock()
	duplicate, err := coordinator.CommitEngineStep(context.Background(), EngineStepCommit{
		Permit: permit, Now: now, OperationKey: "commit-1", RequestDigest: digest(3), Boundary: boundary,
	})
	if err != nil {
		t.Fatalf("duplicate CommitEngineStep() error = %v", err)
	}
	if duplicate != receipt {
		t.Fatalf("duplicate receipt = %#v, want %#v", duplicate, receipt)
	}
	_, err = coordinator.CommitEngineStep(context.Background(), EngineStepCommit{
		Permit: permit, Now: now, OperationKey: "commit-1", RequestDigest: digest(4), Boundary: boundary,
	})
	if !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflicting CommitEngineStep() error = %v, want %v", err, ErrIdempotencyConflict)
	}

	store.mu.Lock()
	store.snapshot.ActiveEffect = &EffectSnapshot{State: EffectPrepared}
	store.mu.Unlock()
	_, err = coordinator.CommitEngineStep(context.Background(), EngineStepCommit{
		Permit: permit, Now: now, OperationKey: "commit-2", RequestDigest: digest(5), Boundary: boundary,
	})
	if !errors.Is(err, ErrEffectInFlight) {
		t.Fatalf("second effect CommitEngineStep() error = %v, want %v", err, ErrEffectInFlight)
	}

	store.mu.Lock()
	store.forceNonDurable = true
	store.snapshot.ActiveEffect = nil
	store.mu.Unlock()
	_, err = coordinator.CommitEngineStep(context.Background(), EngineStepCommit{
		Permit: permit, Now: now, OperationKey: "commit-3", RequestDigest: digest(6), Boundary: EngineBoundary{Kind: BoundaryCheckpoint, CheckpointDigest: digest(7)},
	})
	if !errors.Is(err, ErrDurabilityBarrier) {
		t.Fatalf("non-durable CommitEngineStep() error = %v, want %v", err, ErrDurabilityBarrier)
	}
}

func TestDispatchPermitRequiresDurablePreparedIdentityAndAllFences(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_200, 0).UTC()
	snapshot := baseSnapshot(now)
	snapshot.ActiveEffect = baseEffect(EffectPrepared)
	store := newFakeStore(snapshot)
	coordinator := mustCoordinator(t, store, nil)
	request := baseDispatchRequest(now)

	permit, err := coordinator.AdmitDispatch(context.Background(), request)
	if err != nil {
		t.Fatalf("AdmitDispatch() error = %v", err)
	}
	if !permit.Durable || permit.DispatchAttempt != 1 {
		t.Fatalf("permit = %#v, want durable attempt 1", permit)
	}
	duplicate, err := coordinator.AdmitDispatch(context.Background(), request)
	if err != nil {
		t.Fatalf("duplicate AdmitDispatch() error = %v", err)
	}
	if duplicate != permit {
		t.Fatalf("duplicate permit = %#v, want %#v", duplicate, permit)
	}
	nonDurableSnapshot := baseSnapshot(now)
	nonDurableSnapshot.ActiveEffect = baseEffect(EffectPrepared)
	nonDurableStore := newFakeStore(nonDurableSnapshot)
	nonDurableStore.forceNonDurable = true
	_, err = mustCoordinator(t, nonDurableStore, nil).AdmitDispatch(context.Background(), baseDispatchRequest(now))
	if !errors.Is(err, ErrDurabilityBarrier) {
		t.Fatalf("non-durable AdmitDispatch() error = %v, want %v", err, ErrDurabilityBarrier)
	}

	mutations := []struct {
		name string
		edit func(*DispatchRequest)
	}{
		{name: "effect", edit: func(request *DispatchRequest) { request.EffectID = mustID(identity.Effect, "H") }},
		{name: "invocation", edit: func(request *DispatchRequest) { request.InvocationID = mustID(identity.Invocation, "I") }},
		{name: "digest", edit: func(request *DispatchRequest) { request.RequestDigest = digest(9) }},
		{name: "turn lease", edit: func(request *DispatchRequest) { request.Authority.Generations.TurnLease++ }},
		{name: "placement", edit: func(request *DispatchRequest) { request.Authority.Generations.Placement++ }},
		{name: "sandbox", edit: func(request *DispatchRequest) { request.Authority.Generations.Sandbox++ }},
		{name: "authorization", edit: func(request *DispatchRequest) { request.Authority.Generations.Authorization++ }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			fresh := newFakeStore(func() TurnSnapshot {
				value := baseSnapshot(now)
				value.ActiveEffect = baseEffect(EffectPrepared)
				return value
			}())
			underTest := mustCoordinator(t, fresh, nil)
			changed := baseDispatchRequest(now)
			mutation.edit(&changed)
			_, err := underTest.AdmitDispatch(context.Background(), changed)
			if !errors.Is(err, ErrFenceMismatch) && !errors.Is(err, ErrStaleGeneration) {
				t.Fatalf("AdmitDispatch() error = %v, want identity or generation fence error", err)
			}
		})
	}
}

func TestDispatchRejectsWrongIdentityKindsEvenWhenValuesMatch(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_250, 0).UTC()
	snapshot := baseSnapshot(now)
	snapshot.ActiveEffect = baseEffect(EffectPrepared)
	snapshot.ActiveEffect.EffectID = sessionID
	coordinator := mustCoordinator(t, newFakeStore(snapshot), nil)
	request := baseDispatchRequest(now)
	request.EffectID = sessionID

	_, err := coordinator.AdmitDispatch(context.Background(), request)
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("AdmitDispatch() error = %v, want %v", err, ErrInvalidRequest)
	}
}

func TestConcurrentDispatchHasOneDurableTransitionAndStablePermit(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_300, 0).UTC()
	snapshot := baseSnapshot(now)
	snapshot.ActiveEffect = baseEffect(EffectPrepared)
	store := newFakeStore(snapshot)
	coordinator := mustCoordinator(t, store, nil)

	const workers = 64
	results := make(chan DispatchPermit, workers)
	errorsChannel := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			permit, err := coordinator.AdmitDispatch(context.Background(), baseDispatchRequest(now))
			results <- permit
			errorsChannel <- err
		}()
	}
	wait.Wait()
	close(results)
	close(errorsChannel)
	for err := range errorsChannel {
		if err != nil {
			t.Fatalf("concurrent AdmitDispatch() error = %v", err)
		}
	}
	var first DispatchPermit
	for permit := range results {
		if first == (DispatchPermit{}) {
			first = permit
		}
		if permit != first {
			t.Fatalf("permit = %#v, want stable %#v", permit, first)
		}
	}
	if store.markDispatchTransitions != 1 {
		t.Fatalf("durable dispatch transitions = %d, want 1", store.markDispatchTransitions)
	}
}

func TestSettlementIgnoresOriginalTTLButRequiresExactCurrentFence(t *testing.T) {
	t.Parallel()
	issuedAt := time.Unix(1_800_000_400, 0).UTC()
	now := issuedAt.Add(40 * time.Minute)
	snapshot := baseSnapshot(issuedAt)
	snapshot.LeaseExpiresAt = now.Add(time.Minute)
	snapshot.ActiveEffect = baseEffect(EffectExternallyCommitted)
	store := newFakeStore(snapshot)
	coordinator := mustCoordinator(t, store, nil)
	authority := baseAuthority(issuedAt)
	authority.ExpiresAt = issuedAt.Add(15 * time.Minute)

	receipt, err := coordinator.SettleEffect(context.Background(), SettlementRequest{
		Authority: authority, Now: now, EffectID: effectID, InvocationID: invocationID,
		RequestDigest: digest(2), DispatchAttempt: 1, ExternalCommitID: commitID, ResultRef: resultID,
		OperationKey: "settle-1", SettlementDigest: digest(10),
	})
	if err != nil {
		t.Fatalf("SettleEffect() after authority TTL error = %v", err)
	}
	if !receipt.Durable {
		t.Fatal("settlement escaped before durability barrier")
	}
	duplicate, err := coordinator.SettleEffect(context.Background(), SettlementRequest{
		Authority: authority, Now: now, EffectID: effectID, InvocationID: invocationID,
		RequestDigest: digest(2), DispatchAttempt: 1, ExternalCommitID: commitID, ResultRef: resultID,
		OperationKey: "settle-1", SettlementDigest: digest(10),
	})
	if err != nil || duplicate != receipt {
		t.Fatalf("duplicate settlement = %#v, %v; want %#v, nil", duplicate, err, receipt)
	}

	fresh := newFakeStore(snapshot)
	staleCoordinator := mustCoordinator(t, fresh, nil)
	stale := authority
	stale.Generations.Placement++
	_, err = staleCoordinator.SettleEffect(context.Background(), SettlementRequest{
		Authority: stale, Now: now, EffectID: effectID, InvocationID: invocationID,
		RequestDigest: digest(2), DispatchAttempt: 1, ExternalCommitID: commitID, ResultRef: resultID,
		OperationKey: "settle-stale", SettlementDigest: digest(10),
	})
	if !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("stale SettleEffect() error = %v, want %v", err, ErrStaleGeneration)
	}
}

func TestSettlementRejectsWrongExternalCommitIdentityKind(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_450, 0).UTC()
	snapshot := baseSnapshot(now)
	snapshot.ActiveEffect = baseEffect(EffectExternallyCommitted)
	snapshot.ActiveEffect.ExternalCommitID = sessionID
	coordinator := mustCoordinator(t, newFakeStore(snapshot), nil)

	_, err := coordinator.SettleEffect(context.Background(), SettlementRequest{
		Authority: baseAuthority(now), Now: now, EffectID: effectID, InvocationID: invocationID,
		RequestDigest: digest(2), DispatchAttempt: 1, ExternalCommitID: sessionID, ResultRef: resultID,
		OperationKey: "settle-wrong-commit-kind", SettlementDigest: digest(10),
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("SettleEffect() error = %v, want %v", err, ErrInvalidRequest)
	}
}

func TestConfirmExternalCommitRequiresExactLedgerProof(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_500, 0).UTC()
	snapshot := baseSnapshot(now)
	snapshot.ActiveEffect = baseEffect(EffectDispatched)
	store := newFakeStore(snapshot)
	ledger := &fakeLedger{record: LedgerRecord{
		Status: LedgerCommitted, TenantID: tenantID, WorkspaceID: workspaceID,
		EffectID: effectID, InvocationID: invocationID,
		RequestDigest: digest(2), Service: ServiceExecutor, Operation: "run",
		DispatchAttempt: 1, ProviderRequestID: mustID(identity.Request, "R"), ExternalCommitID: commitID, ResultRef: resultID,
	}}
	coordinator := mustCoordinator(t, store, ledger)

	receipt, err := coordinator.ConfirmExternalCommit(context.Background(), ConfirmationRequest{
		Authority: baseAuthority(now), Now: now.Add(time.Second), EffectID: effectID,
		InvocationID: invocationID, RequestDigest: digest(2), Service: ServiceExecutor, Operation: "run", DispatchAttempt: 1, ProviderRequestID: mustID(identity.Request, "R"), OperationKey: "confirm-1", OperationDigest: digest(91),
	})
	if err != nil {
		t.Fatalf("ConfirmExternalCommit() error = %v", err)
	}
	if receipt.ExternalCommitID != commitID || receipt.ResultRef != resultID || !receipt.Durable {
		t.Fatalf("confirmation receipt = %#v", receipt)
	}
	ledger.mu.Lock()
	lookups := append([]LedgerLookup(nil), ledger.lookups...)
	ledger.mu.Unlock()
	wantLookup := LedgerLookup{
		EffectKey:         EffectKey{SessionID: sessionID, TurnID: turnID, EffectID: effectID, InvocationID: invocationID, RequestDigest: digest(2)},
		TenantID:          tenantID,
		WorkspaceID:       workspaceID,
		Service:           ServiceExecutor,
		Operation:         "run",
		DispatchAttempt:   1,
		ProviderRequestID: mustID(identity.Request, "R"),
	}
	if len(lookups) != 1 || lookups[0] != wantLookup {
		t.Fatalf("ledger lookups = %#v, want [%#v]", lookups, wantLookup)
	}

	for _, mutation := range []struct {
		name string
		edit func(*LedgerRecord)
	}{
		{name: "effect", edit: func(record *LedgerRecord) { record.EffectID = mustID(identity.Effect, "J") }},
		{name: "invocation", edit: func(record *LedgerRecord) { record.InvocationID = mustID(identity.Invocation, "K") }},
		{name: "digest", edit: func(record *LedgerRecord) { record.RequestDigest = digest(33) }},
		{name: "tenant", edit: func(record *LedgerRecord) { record.TenantID = mustID(identity.Tenant, "other-tenant") }},
		{name: "workspace", edit: func(record *LedgerRecord) { record.WorkspaceID = mustID(identity.Workspace, "other-workspace") }},
		{name: "service", edit: func(record *LedgerRecord) { record.Service = ServiceWorkspace }},
		{name: "operation", edit: func(record *LedgerRecord) { record.Operation = "write" }},
		{name: "missing commit", edit: func(record *LedgerRecord) { record.ExternalCommitID = identity.ID{} }},
		{name: "wrong commit kind", edit: func(record *LedgerRecord) { record.ExternalCommitID = sessionID }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			badRecord := ledger.record
			mutation.edit(&badRecord)
			fresh := newFakeStore(snapshot)
			underTest := mustCoordinator(t, fresh, &fakeLedger{record: badRecord})
			_, err := underTest.ConfirmExternalCommit(context.Background(), ConfirmationRequest{
				Authority: baseAuthority(now), Now: now.Add(time.Second), EffectID: effectID,
				InvocationID: invocationID, RequestDigest: digest(2), Service: ServiceExecutor, Operation: "run", DispatchAttempt: 1, ProviderRequestID: mustID(identity.Request, "R"), OperationKey: "bad-proof", OperationDigest: digest(92),
			})
			if !errors.Is(err, ErrLedgerMismatch) {
				t.Fatalf("ConfirmExternalCommit() error = %v, want %v", err, ErrLedgerMismatch)
			}
			if fresh.markExternalTransitions != 0 {
				t.Fatalf("external commit transitions = %d, want 0", fresh.markExternalTransitions)
			}
		})
	}
}

func TestConfirmExternalCommitAllowsAbsentProviderRequestIdentity(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_525, 0).UTC()
	snapshot := baseSnapshot(now)
	snapshot.ActiveEffect = baseEffect(EffectDispatched)
	snapshot.ActiveEffect.LastDispatch.ProviderRequestID = identity.ID{}
	record := committedRecord()
	record.ProviderRequestID = identity.ID{}

	receipt, err := mustCoordinator(t, newFakeStore(snapshot), &fakeLedger{record: record}).ConfirmExternalCommit(context.Background(), ConfirmationRequest{
		Authority: baseAuthority(now), Now: now, EffectID: effectID, InvocationID: invocationID, RequestDigest: digest(2),
		Service: ServiceExecutor, Operation: "run", DispatchAttempt: 1, OperationKey: "confirm-without-provider", OperationDigest: digest(93),
	})
	if err != nil {
		t.Fatalf("ConfirmExternalCommit() error = %v", err)
	}
	if receipt.ProviderRequestID != (identity.ID{}) || receipt.OperationDigest != digest(93) {
		t.Fatalf("confirmation receipt = %#v", receipt)
	}
}

func TestConcurrentRecoveryLedgerLookupsPreserveAuthoritativeRouteAndEffectBoundary(t *testing.T) {
	t.Parallel()
	const recoveries = 64
	now := time.Unix(1_800_000_550, 0).UTC()
	ledger := &fakeLedger{lookup: func(ctx context.Context, query LedgerLookup) (LedgerRecord, error) {
		if err := ctx.Err(); err != nil {
			return LedgerRecord{}, err
		}
		return LedgerRecord{
			Status: LedgerCommitted, TenantID: query.TenantID, WorkspaceID: query.WorkspaceID,
			EffectID: query.EffectID, InvocationID: query.InvocationID,
			RequestDigest: query.RequestDigest, Service: query.Service, Operation: query.Operation,
			DispatchAttempt: query.DispatchAttempt, ProviderRequestID: query.ProviderRequestID, ExternalCommitID: commitID, ResultRef: resultID,
		}, nil
	}}

	var wait sync.WaitGroup
	errorsByRecovery := make(chan error, recoveries)
	wantLookups := make(map[LedgerLookup]int, recoveries)
	for index := 0; index < recoveries; index++ {
		tenant := mustID(identity.Tenant, fmt.Sprintf("tenant-%d", index))
		workspace := mustID(identity.Workspace, fmt.Sprintf("workspace-%d", index))
		service := ServiceExecutor
		if index%2 == 1 {
			service = ServiceWorkspace
		}
		operation := fmt.Sprintf("operation-%d", index)
		snapshot := baseSnapshot(now)
		snapshot.TenantID = tenant
		snapshot.WorkspaceID = workspace
		snapshot.ActiveEffect = baseEffect(EffectDispatched)
		snapshot.ActiveEffect.Service = service
		snapshot.ActiveEffect.Operation = operation
		coordinator := mustCoordinator(t, newFakeStore(snapshot), ledger)
		lookup := LedgerLookup{
			EffectKey:         EffectKey{SessionID: sessionID, TurnID: turnID, EffectID: effectID, InvocationID: invocationID, RequestDigest: digest(2)},
			TenantID:          tenant,
			WorkspaceID:       workspace,
			Service:           service,
			Operation:         operation,
			DispatchAttempt:   1,
			ProviderRequestID: mustID(identity.Request, "R"),
		}
		wantLookups[lookup]++
		request := baseRecoveryRequest(now, fmt.Sprintf("recover-concurrent-%d", index))
		request.Authority.TenantID = tenant
		request.Authority.WorkspaceID = workspace
		wait.Add(1)
		go func(index int, coordinator *Coordinator, request RecoveryRequest) {
			defer wait.Done()
			decision, err := coordinator.RecoverEffect(context.Background(), request)
			if err != nil {
				errorsByRecovery <- fmt.Errorf("recovery %d: %w", index, err)
				return
			}
			if decision.Action != RecoverySettleOnly || decision.ExternalCommitID != commitID || decision.ResultRef != resultID {
				errorsByRecovery <- fmt.Errorf("recovery %d decision = %#v", index, decision)
			}
		}(index, coordinator, request)
	}
	wait.Wait()
	close(errorsByRecovery)
	for err := range errorsByRecovery {
		t.Error(err)
	}

	ledger.mu.Lock()
	gotLookups := append([]LedgerLookup(nil), ledger.lookups...)
	ledger.mu.Unlock()
	if len(gotLookups) != recoveries {
		t.Fatalf("ledger lookup count = %d, want %d", len(gotLookups), recoveries)
	}
	for _, lookup := range gotLookups {
		if wantLookups[lookup] == 0 {
			t.Errorf("unexpected ledger lookup: %#v", lookup)
			continue
		}
		wantLookups[lookup]--
	}
	for lookup, remaining := range wantLookups {
		if remaining != 0 {
			t.Errorf("ledger lookup %#v remaining count = %d", lookup, remaining)
		}
	}
}

func TestRecoveryClassificationCoversEveryCrashBoundary(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_600, 0).UTC()
	tests := []struct {
		name       string
		state      EffectState
		policy     ReplayPolicy
		ledger     LedgerRecord
		want       RecoveryAction
		wantMarked bool
	}{
		{name: "prepared before dispatch", state: EffectPrepared, policy: ReplayNever, want: RecoveryDispatch},
		{name: "dispatched committed", state: EffectDispatched, policy: ReplayNever, ledger: committedRecord(), want: RecoverySettleOnly, wantMarked: true},
		{name: "dispatched absent safe", state: EffectDispatched, policy: ReplaySafe, ledger: routedRecord(LedgerAbsent), want: RecoveryReplay},
		{name: "dispatched absent idempotency", state: EffectDispatched, policy: ReplayIdempotencyKey, ledger: routedRecord(LedgerAbsent), want: RecoveryReplay},
		{name: "dispatched unknown never", state: EffectDispatched, policy: ReplayNever, ledger: routedRecord(LedgerUnknown), want: RecoverySettleInterrupted},
		{name: "dispatched unknown confirm", state: EffectDispatched, policy: ReplayConfirm, ledger: routedRecord(LedgerUnknown), want: RecoveryNeedsConfirmation},
		{name: "externally committed", state: EffectExternallyCommitted, policy: ReplaySafe, want: RecoverySettleOnly},
		{name: "blocked", state: EffectBlocked, policy: ReplayConfirm, want: RecoveryAwaitConfirmation},
		{name: "settled", state: EffectSettled, policy: ReplaySafe, want: RecoveryNone},
	}
	rand.New(rand.NewSource(42)).Shuffle(len(tests), func(left, right int) { tests[left], tests[right] = tests[right], tests[left] })
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := baseSnapshot(now)
			effect := baseEffect(test.state)
			effect.ReplayPolicy = test.policy
			if effect.PreparationPermit != nil {
				effect.PreparationPermit.ReplayPolicy = test.policy
			}
			snapshot.ActiveEffect = effect
			store := newFakeStore(snapshot)
			ledger := &fakeLedger{record: test.ledger}
			coordinator := mustCoordinator(t, store, ledger)
			request := baseRecoveryRequest(now.Add(time.Second), "recover-"+test.name)
			decision, err := coordinator.RecoverEffect(context.Background(), request)
			if err != nil {
				t.Fatalf("RecoverEffect() error = %v", err)
			}
			if decision.Action != test.want {
				t.Fatalf("recovery action = %q, want %q", decision.Action, test.want)
			}
			if (store.markExternalTransitions == 1) != test.wantMarked {
				t.Fatalf("external commit transitions = %d, wantMarked %t", store.markExternalTransitions, test.wantMarked)
			}
		})
	}
}

func TestRecoveryNeverInfersExternalOutcomeFromCancellationOrTime(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_700, 0).UTC()
	snapshot := baseSnapshot(now)
	effect := baseEffect(EffectDispatched)
	effect.ReplayPolicy = ReplayConfirm
	snapshot.ActiveEffect = effect
	store := newFakeStore(snapshot)
	ledger := &fakeLedger{record: routedRecord(LedgerUnknown)}
	coordinator := mustCoordinator(t, store, ledger)

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := coordinator.RecoverEffect(cancelled, baseRecoveryRequest(now.Add(24*time.Hour), "cancelled"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled RecoverEffect() error = %v, want context.Canceled", err)
	}

	decision, err := coordinator.RecoverEffect(context.Background(), baseRecoveryRequest(now.Add(24*time.Hour), "late"))
	if err != nil {
		t.Fatalf("late RecoverEffect() error = %v", err)
	}
	if decision.Action != RecoveryNeedsConfirmation {
		t.Fatalf("late recovery action = %q, want %q", decision.Action, RecoveryNeedsConfirmation)
	}
}

func TestRecoveryValidatesEveryDurableMutationReceipt(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_750, 0).UTC()

	t.Run("external commit", func(t *testing.T) {
		snapshot := baseSnapshot(now)
		snapshot.ActiveEffect = baseEffect(EffectDispatched)
		store := newFakeStore(snapshot)
		store.corruptExternalReceipt = true
		coordinator := mustCoordinator(t, store, &fakeLedger{record: committedRecord()})

		_, err := coordinator.RecoverEffect(context.Background(), baseRecoveryRequest(now, "recover-corrupt-external-receipt"))
		if !errors.Is(err, ErrFenceMismatch) {
			t.Fatalf("RecoverEffect() error = %v, want %v", err, ErrFenceMismatch)
		}
	})

	t.Run("confirmation block", func(t *testing.T) {
		snapshot := baseSnapshot(now)
		effect := baseEffect(EffectDispatched)
		effect.ReplayPolicy = ReplayConfirm
		snapshot.ActiveEffect = effect
		store := newFakeStore(snapshot)
		store.corruptBlockReceipt = true
		coordinator := mustCoordinator(t, store, &fakeLedger{record: routedRecord(LedgerUnknown)})

		_, err := coordinator.RecoverEffect(context.Background(), baseRecoveryRequest(now, "recover-corrupt-block-receipt"))
		if !errors.Is(err, ErrFenceMismatch) {
			t.Fatalf("RecoverEffect() error = %v, want %v", err, ErrFenceMismatch)
		}
	})
}

func TestCrashBeforeAndAfterDispatchBarrierAreDistinguishable(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_800, 0).UTC()
	prepared := baseSnapshot(now)
	prepared.ActiveEffect = baseEffect(EffectPrepared)
	beforeStore := newFakeStore(prepared)
	before := mustCoordinator(t, beforeStore, &fakeLedger{record: routedRecord(LedgerUnknown)})
	beforeDecision, err := before.RecoverEffect(context.Background(), baseRecoveryRequest(now, "before"))
	if err != nil || beforeDecision.Action != RecoveryDispatch {
		t.Fatalf("before-barrier decision = %#v, %v", beforeDecision, err)
	}

	afterStore := newFakeStore(prepared)
	after := mustCoordinator(t, afterStore, &fakeLedger{record: routedRecord(LedgerUnknown)})
	if _, err := after.AdmitDispatch(context.Background(), baseDispatchRequest(now)); err != nil {
		t.Fatalf("AdmitDispatch() error = %v", err)
	}
	afterStore.mu.Lock()
	afterStore.snapshot.ActiveEffect.ReplayPolicy = ReplayConfirm
	afterStore.mu.Unlock()
	afterDecision, err := after.RecoverEffect(context.Background(), baseRecoveryRequest(now, "after"))
	if err != nil || afterDecision.Action != RecoveryNeedsConfirmation {
		t.Fatalf("after-barrier decision = %#v, %v", afterDecision, err)
	}
}

func baseSnapshot(now time.Time) TurnSnapshot {
	return TurnSnapshot{
		TenantID: tenantID, WorkspaceID: workspaceID, UserID: mustID(identity.Subject, "U"), SessionID: sessionID, TurnID: turnID, Active: true,
		LeaseExpiresAt: now.Add(time.Hour), Generations: Generations{TurnLease: 11, Placement: 12, Sandbox: 13, Authorization: 14},
		CheckpointDigest: digest(90), EventSequence: 7,
		EngineStepLimits: EngineStepBudget{MaximumEvents: 1, MaximumEphemeralBytes: 8192, MaximumWallClock: 2 * time.Minute},
	}
}

func baseAuthority(now time.Time) ValidatedTurnFence {
	return ValidatedTurnFence{
		TenantID: tenantID, WorkspaceID: workspaceID, SessionID: sessionID, TurnID: turnID,
		Generations: Generations{TurnLease: 11, Placement: 12, Sandbox: 13, Authorization: 14},
		ExpiresAt:   now.Add(15 * time.Minute),
	}
}

func baseRecoveryRequest(now time.Time, operationKey string) RecoveryRequest {
	return RecoveryRequest{
		Authority: baseAuthority(now), Now: now, EffectID: effectID, InvocationID: invocationID,
		RequestDigest: digest(2), OperationKey: operationKey, OperationDigest: digest(88),
		ProviderRequestID: mustID(identity.Request, "R"), Deadline: now.Add(time.Minute),
	}
}

func baseEffect(state EffectState) *EffectSnapshot {
	effect := &EffectSnapshot{
		EffectID: effectID, InvocationID: invocationID, RequestDigest: digest(2),
		Service: ServiceExecutor, Operation: "run", ReplayPolicy: ReplayIdempotencyKey,
		State: state, DispatchAttempt: map[bool]uint64{true: 1, false: 0}[state != EffectPrepared],
		Generations: Generations{TurnLease: 11, Placement: 12, Sandbox: 13, Authorization: 14},
		ExternalCommitID: func() identity.ID {
			if state == EffectExternallyCommitted || state == EffectSettled {
				return commitID
			}
			return identity.ID{}
		}(),
		ResultRef: func() identity.ID {
			if state == EffectExternallyCommitted || state == EffectSettled {
				return resultID
			}
			return identity.ID{}
		}(),
	}
	if state != EffectPrepared {
		effect.LastDispatch = &DispatchMetadata{DispatchAttempt: effect.DispatchAttempt, Generations: effect.Generations, ProviderRequestID: mustID(identity.Request, "R"), Deadline: time.Unix(2_000_000_000, 0).UTC()}
	}
	if state == EffectPrepared {
		permit := EffectPreparationPermit{
			EffectKey: EffectKey{SessionID: sessionID, TurnID: turnID, EffectID: effectID, InvocationID: invocationID, RequestDigest: digest(2)},
			Opaque:    opaque(1), TenantID: tenantID, WorkspaceID: workspaceID,
			UserID: mustID(identity.Subject, "U"), Service: ServiceExecutor,
			Operation: "run", ReplayPolicy: ReplayIdempotencyKey, Generations: effect.Generations,
			DispatchAttempt: 1, Deadline: time.Unix(2_000_000_000, 0).UTC(), EventSequence: 8, Durable: true,
		}
		effect.PreparationPermit = &permit
	}
	if state == EffectSettled {
		effect.Settlement = &v1.EffectRecord{State: v1.EffectState_EFFECT_STATE_SETTLED, DispatchAttempt: effect.DispatchAttempt}
	}
	return effect
}

func baseDispatchRequest(now time.Time) DispatchRequest {
	snapshot := baseSnapshot(now)
	return DispatchRequest{
		Authority: baseAuthority(now), Now: now, EffectID: effectID, InvocationID: invocationID,
		RequestDigest: digest(2), Service: ServiceExecutor, Operation: "run", OperationKey: "dispatch-1", OperationDigest: digest(81),
		PreparationPermit: preparationPermit(snapshot, 1, now.Add(time.Minute)), ProviderRequestID: mustID(identity.Request, "R"), Deadline: now.Add(time.Minute),
	}
}

func preparationPermit(snapshot TurnSnapshot, attempt uint64, deadline time.Time) EffectPreparationPermit {
	return EffectPreparationPermit{
		EffectKey: EffectKey{SessionID: snapshot.SessionID, TurnID: snapshot.TurnID, EffectID: effectID, InvocationID: invocationID, RequestDigest: digest(2)},
		Opaque:    opaque(byte(attempt)), TenantID: snapshot.TenantID, WorkspaceID: snapshot.WorkspaceID,
		UserID:  snapshot.UserID,
		Service: ServiceExecutor, Operation: "run", ReplayPolicy: ReplayIdempotencyKey,
		Generations: snapshot.Generations, DispatchAttempt: attempt, Deadline: deadline, EventSequence: snapshot.EventSequence, Durable: true,
	}
}

func opaque(fill byte) OpaquePermit {
	return OpaquePermit(bytes.Repeat([]byte{fill}, 32))
}

func acquirePermit(t *testing.T, coordinator *Coordinator, now time.Time, key string) EngineStepPermit {
	t.Helper()
	permit, err := coordinator.AcquireEngineStep(context.Background(), EngineStepRequest{
		Authority: baseAuthority(now), Now: now,
		Budget:       EngineStepBudget{MaximumEvents: 1, MaximumEphemeralBytes: 1, MaximumWallClock: time.Second},
		OperationKey: key,
	})
	if err != nil {
		t.Fatalf("AcquireEngineStep() error = %v", err)
	}
	return permit
}

func committedRecord() LedgerRecord {
	return LedgerRecord{Status: LedgerCommitted, TenantID: tenantID, WorkspaceID: workspaceID, EffectID: effectID, InvocationID: invocationID, RequestDigest: digest(2), Service: ServiceExecutor, Operation: "run", DispatchAttempt: 1, ProviderRequestID: mustID(identity.Request, "R"), ExternalCommitID: commitID, ResultRef: resultID}
}

func routedRecord(status LedgerStatus) LedgerRecord {
	return LedgerRecord{Status: status, TenantID: tenantID, WorkspaceID: workspaceID}
}

func digest(fill byte) Digest {
	var value Digest
	for index := range value {
		value[index] = fill
	}
	return value
}

func mustID(kind identity.Kind, fill string) identity.ID {
	id, err := (identity.Generator{Random: bytes.NewReader(bytes.Repeat([]byte(fill), 16))}).New(kind)
	if err != nil {
		panic(err)
	}
	return id
}

func mustCoordinator(t *testing.T, store DurableStore, ledger InvocationLedger) *Coordinator {
	t.Helper()
	coordinator, err := NewCoordinator(store, ledger)
	if err != nil {
		t.Fatalf("NewCoordinator() error = %v", err)
	}
	return coordinator
}

type fakeLedger struct {
	mu      sync.Mutex
	record  LedgerRecord
	lookup  func(context.Context, LedgerLookup) (LedgerRecord, error)
	lookups []LedgerLookup
}

func (ledger *fakeLedger) Lookup(ctx context.Context, query LedgerLookup) (LedgerRecord, error) {
	if err := ctx.Err(); err != nil {
		return LedgerRecord{}, err
	}
	ledger.mu.Lock()
	ledger.lookups = append(ledger.lookups, query)
	lookup := ledger.lookup
	record := ledger.record
	ledger.mu.Unlock()
	if lookup != nil {
		return lookup(ctx, query)
	}
	return record, nil
}

type fakeStore struct {
	mu sync.Mutex

	snapshot            TurnSnapshot
	stepPermits         map[string]EngineStepPermit
	stepCommits         map[string]storedStepCommit
	dispatches          map[string]storedDispatch
	settlements         map[string]storedSettlement
	recoverySettlements map[string]storedSettlement
	preparations        map[string]storedPreparation
	blocks              map[string]storedBlock
	confirmations       map[string]ConfirmationReceipt
	confirmationDigests map[string]Digest
	operationLookups    []OperationLookup
	readTurnCalls       int

	eventSequence                      uint64
	forceNonDurable                    bool
	corruptExternalReceipt             bool
	corruptExternalReceiptDomain       bool
	corruptBlockReceipt                bool
	corruptPreparedReceipt             bool
	corruptSettlementIdentity          bool
	corruptBlockIdentity               bool
	corruptRecoverySettlementIdentity  bool
	corruptReceiptRoute                receiptRouteCorruption
	markDispatchTransitions            int
	markExternalTransitions            int
	prepareRetryTransitions            int
	recoverySettlementTransitions      int
	zeroStepEvent                      bool
	zeroDispatchEvent                  bool
	zeroConfirmationEvent              bool
	zeroSettlementEvent                bool
	zeroBlockEvent                     bool
	lastStepBoundary                   *v1.EngineStepBoundary
	lastSettlementError                *v1.PublicError
	lastBlockReason                    *v1.PublicError
	loseDispatchResponseOnce           bool
	losePrepareRetryResponseOnce       bool
	loseRecoverySettlementResponseOnce bool
	loseBlockResponseOnce              bool
	blockTransitions                   int
}

type receiptRouteCorruption uint8

const (
	corruptTenantRoute receiptRouteCorruption = iota + 1
	corruptWorkspaceRoute
)

type storedStepCommit struct {
	digest  Digest
	receipt EngineStepReceipt
}

type storedDispatch struct {
	key    EffectKey
	digest Digest
	permit DispatchPermit
}

type storedSettlement struct {
	digest  Digest
	receipt SettlementReceipt
}

type storedPreparation struct {
	digest Digest
	permit EffectPreparationPermit
}

type storedBlock struct {
	digest  Digest
	receipt BlockReceipt
}

func newFakeStore(snapshot TurnSnapshot) *fakeStore {
	return &fakeStore{
		snapshot: snapshot, eventSequence: snapshot.EventSequence,
		stepPermits: make(map[string]EngineStepPermit), stepCommits: make(map[string]storedStepCommit),
		dispatches: make(map[string]storedDispatch), settlements: make(map[string]storedSettlement), recoverySettlements: make(map[string]storedSettlement), preparations: make(map[string]storedPreparation), blocks: make(map[string]storedBlock),
		confirmations:       make(map[string]ConfirmationReceipt),
		confirmationDigests: make(map[string]Digest),
	}
}

func (store *fakeStore) applyReceiptRouteCorruption(tenant *identity.ID, workspace *identity.ID) {
	switch store.corruptReceiptRoute {
	case corruptTenantRoute:
		*tenant = mustID(identity.Tenant, "corrupt-tenant-route")
	case corruptWorkspaceRoute:
		*workspace = mustID(identity.Workspace, "corrupt-workspace-route")
	}
}

func (store *fakeStore) LookupOperation(ctx context.Context, lookup OperationLookup) (OperationReceipt, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.operationLookups = append(store.operationLookups, lookup)
	switch lookup.Kind {
	case OperationDispatch:
		stored, found := store.dispatches[lookup.OperationKey]
		if !found {
			return OperationReceipt{}, nil
		}
		if stored.digest != lookup.OperationDigest {
			return OperationReceipt{}, ErrIdempotencyConflict
		}
		permit := stored.permit
		return OperationReceipt{Found: true, Kind: lookup.Kind, OperationDigest: stored.digest, Dispatch: &permit}, nil
	case OperationConfirmation:
		receipt, found := store.confirmations[lookup.OperationKey]
		if !found {
			return OperationReceipt{}, nil
		}
		digest := store.confirmationDigests[lookup.OperationKey]
		if digest != lookup.OperationDigest {
			return OperationReceipt{}, ErrIdempotencyConflict
		}
		return OperationReceipt{Found: true, Kind: lookup.Kind, OperationDigest: digest, Confirmation: &receipt}, nil
	case OperationSettlement:
		stored, found := store.settlements[lookup.OperationKey]
		if !found {
			return OperationReceipt{}, nil
		}
		if stored.digest != lookup.OperationDigest {
			return OperationReceipt{}, ErrIdempotencyConflict
		}
		receipt := stored.receipt
		return OperationReceipt{Found: true, Kind: lookup.Kind, OperationDigest: stored.digest, Settlement: &receipt}, nil
	case OperationRecoverySettlement:
		stored, found := store.recoverySettlements[lookup.OperationKey]
		if !found {
			return OperationReceipt{}, nil
		}
		if stored.digest != lookup.OperationDigest {
			return OperationReceipt{}, ErrIdempotencyConflict
		}
		receipt := stored.receipt
		return OperationReceipt{Found: true, Kind: lookup.Kind, OperationDigest: stored.digest, Settlement: &receipt}, nil
	case OperationBlock:
		stored, found := store.blocks[lookup.OperationKey]
		if !found {
			return OperationReceipt{}, nil
		}
		if stored.digest != lookup.OperationDigest {
			return OperationReceipt{}, ErrIdempotencyConflict
		}
		receipt := stored.receipt
		return OperationReceipt{Found: true, Kind: lookup.Kind, OperationDigest: stored.digest, Block: &receipt}, nil
	default:
		return OperationReceipt{}, ErrInvalidRequest
	}
}

func (store *fakeStore) ReadTurn(ctx context.Context, session identity.ID) (TurnSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return TurnSnapshot{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.readTurnCalls++
	copy := store.snapshot
	if store.snapshot.ActiveEffect != nil {
		effect := *store.snapshot.ActiveEffect
		copy.ActiveEffect = &effect
	}
	return copy, nil
}

func (store *fakeStore) AcquireEngineStep(ctx context.Context, command AcquireStepCommand) (EngineStepPermit, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, found := store.stepPermits[command.OperationKey]; found {
		return existing, nil
	}
	permit := EngineStepPermit{
		Opaque: opaque(1), TenantID: command.Snapshot.TenantID, WorkspaceID: command.Snapshot.WorkspaceID, UserID: command.Snapshot.UserID,
		OperationKey: command.OperationKey, SessionID: command.Snapshot.SessionID, TurnID: command.Snapshot.TurnID,
		Generations: command.Snapshot.Generations, ExpectedEventSequence: command.Snapshot.EventSequence,
		CheckpointDigest: command.Snapshot.CheckpointDigest, Budget: command.Budget, Deadline: command.Now.Add(command.Budget.MaximumWallClock), Durable: !store.forceNonDurable,
		Checkpoint: command.Snapshot.Checkpoint, UnconsumedSettlement: command.Snapshot.UnconsumedSettlement,
	}
	store.applyReceiptRouteCorruption(&permit.TenantID, &permit.WorkspaceID)
	store.stepPermits[command.OperationKey] = permit
	return permit, nil
}

func (store *fakeStore) CommitEngineStep(ctx context.Context, command CommitStepCommand) (EngineStepReceipt, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, found := store.stepCommits[command.OperationKey]; found {
		if existing.digest != command.RequestDigest {
			return EngineStepReceipt{}, ErrIdempotencyConflict
		}
		return existing.receipt, nil
	}
	if store.snapshot.ActiveEffect != nil && store.snapshot.ActiveEffect.State != EffectSettled {
		return EngineStepReceipt{}, ErrEffectInFlight
	}
	store.eventSequence++
	if command.Boundary.Message != nil {
		store.lastStepBoundary = proto.Clone(command.Boundary.Message).(*v1.EngineStepBoundary)
	}
	receipt := EngineStepReceipt{OperationKey: command.OperationKey, EventSequence: store.eventSequence, Durable: !store.forceNonDurable}
	if store.zeroStepEvent {
		receipt.EventSequence = 0
	}
	if command.Boundary.Message != nil && command.Boundary.Message.GetEffectRequest() != nil || command.Boundary.Message == nil && command.Boundary.Kind == BoundaryEffectRequest {
		service := ServiceExecutor
		operation := "run"
		replayPolicy := ReplaySafe
		requestDigest := digest(105)
		if intent := command.Boundary.Message.GetEffectRequest(); intent != nil {
			operation = intent.Operation
			copy(requestDigest[:], intent.RequestDigest.Value)
			switch intent.Service {
			case v1.EffectService_EFFECT_SERVICE_EXECUTOR:
				service = ServiceExecutor
			}
			switch intent.ReplayPolicy {
			case v1.ReplayPolicy_REPLAY_POLICY_IDEMPOTENCY_KEY:
				replayPolicy = ReplayIdempotencyKey
			case v1.ReplayPolicy_REPLAY_POLICY_NEVER:
				replayPolicy = ReplayNever
			case v1.ReplayPolicy_REPLAY_POLICY_CONFIRM:
				replayPolicy = ReplayConfirm
			}
		} else if command.Boundary.Effect != nil {
			service = command.Boundary.Effect.Service
			operation = command.Boundary.Effect.Operation
			replayPolicy = command.Boundary.Effect.ReplayPolicy
			requestDigest = command.Boundary.Effect.RequestDigest
		}
		preparation := EffectPreparationPermit{EffectKey: EffectKey{SessionID: command.Snapshot.SessionID, TurnID: command.Snapshot.TurnID, EffectID: effectID, InvocationID: invocationID, RequestDigest: requestDigest}, Opaque: opaque(9), TenantID: command.Snapshot.TenantID, WorkspaceID: command.Snapshot.WorkspaceID, UserID: command.Snapshot.UserID, Service: service, Operation: operation, ReplayPolicy: replayPolicy, Generations: command.Snapshot.Generations, DispatchAttempt: 1, Deadline: command.Permit.Deadline, EventSequence: store.eventSequence, Durable: !store.forceNonDurable}
		store.applyReceiptRouteCorruption(&preparation.TenantID, &preparation.WorkspaceID)
		if store.corruptPreparedReceipt {
			preparation.InvocationID = mustID(identity.Invocation, "bad-prepared")
		}
		receipt.PreparedEffect = &v1.EffectRecord{
			TenantId: &v1.OpaqueId{Value: []byte(command.Snapshot.TenantID.String())}, UserId: &v1.OpaqueId{Value: []byte(command.Snapshot.UserID.String())},
			SessionId: &v1.OpaqueId{Value: []byte(command.Snapshot.SessionID.String())}, TurnId: &v1.OpaqueId{Value: []byte(command.Snapshot.TurnID.String())},
			EffectId: &v1.OpaqueId{Value: []byte(effectID.String())}, InvocationId: &v1.OpaqueId{Value: []byte(invocationID.String())},
			RequestDigest: &v1.Digest{Algorithm: v1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: requestDigest[:]}, Operation: operation,
			State: v1.EffectState_EFFECT_STATE_PREPARED, DispatchAttempt: 0,
			TurnLeaseGeneration: command.Snapshot.Generations.TurnLease, PlacementGeneration: command.Snapshot.Generations.Placement,
			SandboxGeneration: command.Snapshot.Generations.Sandbox, AuthorizationGeneration: command.Snapshot.Generations.Authorization,
			DeadlineUnixMs: uint64(command.Permit.Deadline.UnixMilli()),
		}
		receipt.PreparationPermit = &preparation
	}
	store.stepCommits[command.OperationKey] = storedStepCommit{digest: command.RequestDigest, receipt: receipt}
	return receipt, nil
}

func (store *fakeStore) MarkDispatched(ctx context.Context, command MarkDispatchedCommand) (DispatchPermit, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, found := store.dispatches[command.OperationKey]; found {
		if existing.key != command.Key {
			return DispatchPermit{}, ErrIdempotencyConflict
		}
		return existing.permit, nil
	}
	if store.snapshot.ActiveEffect == nil || (store.snapshot.ActiveEffect.State != EffectPrepared && store.snapshot.ActiveEffect.State != EffectDispatched && store.snapshot.ActiveEffect.State != EffectBlocked) {
		return DispatchPermit{}, ErrInvalidEffectState
	}
	if command.PreparationPermit.DispatchAttempt != store.snapshot.ActiveEffect.DispatchAttempt+1 {
		return DispatchPermit{}, ErrStaleGeneration
	}
	store.eventSequence++
	store.snapshot.ActiveEffect.State = EffectDispatched
	store.snapshot.ActiveEffect.DispatchAttempt++
	store.snapshot.ActiveEffect.LastDispatch = &DispatchMetadata{DispatchAttempt: store.snapshot.ActiveEffect.DispatchAttempt, Generations: command.Snapshot.Generations, ProviderRequestID: command.ProviderRequestID, Deadline: command.Deadline}
	store.snapshot.EventSequence = store.eventSequence
	store.markDispatchTransitions++
	permit := DispatchPermit{
		EffectKey: command.Key, Opaque: opaque(byte(store.snapshot.ActiveEffect.DispatchAttempt + 20)),
		TenantID: command.Snapshot.TenantID, WorkspaceID: command.Snapshot.WorkspaceID, UserID: command.Snapshot.UserID,
		Service: command.Service, Operation: command.Operation, ReplayPolicy: store.snapshot.ActiveEffect.ReplayPolicy,
		ParentOperationID: store.snapshot.ActiveEffect.ParentOperationID, Ordinal: store.snapshot.ActiveEffect.Ordinal,
		Generations: command.Snapshot.Generations, DispatchAttempt: store.snapshot.ActiveEffect.DispatchAttempt,
		ProviderRequestID: command.ProviderRequestID, Deadline: command.Deadline,
		EventSequence: store.eventSequence, Durable: !store.forceNonDurable,
	}
	store.applyReceiptRouteCorruption(&permit.TenantID, &permit.WorkspaceID)
	if store.zeroDispatchEvent {
		permit.EventSequence = 0
	}
	store.dispatches[command.OperationKey] = storedDispatch{key: command.Key, digest: command.OperationDigest, permit: permit}
	if store.loseDispatchResponseOnce {
		store.loseDispatchResponseOnce = false
		return DispatchPermit{}, errors.New("simulated response loss after dispatch commit")
	}
	return permit, nil
}

func (store *fakeStore) PrepareRetry(ctx context.Context, command PrepareRetryCommand) (EffectPreparationPermit, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, found := store.preparations[command.OperationKey]; found {
		if existing.digest != command.OperationDigest {
			return EffectPreparationPermit{}, ErrIdempotencyConflict
		}
		return existing.permit, nil
	}
	if store.snapshot.ActiveEffect == nil {
		return EffectPreparationPermit{}, ErrInvalidEffectState
	}
	store.prepareRetryTransitions++
	store.eventSequence++
	store.snapshot.EventSequence = store.eventSequence
	permit := EffectPreparationPermit{
		EffectKey: command.Key, Opaque: opaque(byte(store.snapshot.ActiveEffect.DispatchAttempt + 1)),
		TenantID: store.snapshot.TenantID, WorkspaceID: store.snapshot.WorkspaceID, UserID: store.snapshot.UserID,
		Service: store.snapshot.ActiveEffect.Service, Operation: store.snapshot.ActiveEffect.Operation,
		ParentOperationID: store.snapshot.ActiveEffect.ParentOperationID, Ordinal: store.snapshot.ActiveEffect.Ordinal,
		ReplayPolicy: store.snapshot.ActiveEffect.ReplayPolicy, Generations: store.snapshot.Generations,
		DispatchAttempt: store.snapshot.ActiveEffect.DispatchAttempt + 1, Deadline: command.Deadline, EventSequence: store.eventSequence, Durable: true,
	}
	store.applyReceiptRouteCorruption(&permit.TenantID, &permit.WorkspaceID)
	store.preparations[command.OperationKey] = storedPreparation{digest: command.OperationDigest, permit: permit}
	if store.losePrepareRetryResponseOnce {
		store.losePrepareRetryResponseOnce = false
		return EffectPreparationPermit{}, errors.New("simulated response loss after retry preparation commit")
	}
	return permit, nil
}

func (store *fakeStore) SettleRecovery(ctx context.Context, command SettleRecoveryCommand) (SettlementReceipt, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, found := store.recoverySettlements[command.OperationKey]; found {
		if existing.digest != command.OperationDigest {
			return SettlementReceipt{}, ErrIdempotencyConflict
		}
		return existing.receipt, nil
	}
	if store.snapshot.ActiveEffect == nil {
		return SettlementReceipt{}, ErrInvalidEffectState
	}
	store.eventSequence++
	store.snapshot.EventSequence = store.eventSequence
	store.snapshot.ActiveEffect.State = EffectSettled
	store.snapshot.ActiveEffect.Settlement = &v1.EffectRecord{State: v1.EffectState_EFFECT_STATE_SETTLED, DispatchAttempt: store.snapshot.ActiveEffect.DispatchAttempt}
	store.recoverySettlementTransitions++
	if command.Error != nil {
		store.lastSettlementError = proto.Clone(command.Error).(*v1.PublicError)
	}
	receipt := SettlementReceipt{EffectKey: command.Key, TenantID: command.Snapshot.TenantID, WorkspaceID: command.Snapshot.WorkspaceID, State: EffectSettled, DispatchAttempt: store.snapshot.ActiveEffect.DispatchAttempt, Error: command.Error, OperationDigest: command.OperationDigest, RecoveryKind: command.Kind, Effect: store.snapshot.ActiveEffect.Settlement, EventSequence: store.eventSequence, Durable: true}
	store.applyReceiptRouteCorruption(&receipt.TenantID, &receipt.WorkspaceID)
	if store.corruptRecoverySettlementIdentity {
		receipt.DispatchAttempt++
	}
	store.recoverySettlements[command.OperationKey] = storedSettlement{digest: command.OperationDigest, receipt: receipt}
	if store.loseRecoverySettlementResponseOnce {
		store.loseRecoverySettlementResponseOnce = false
		return SettlementReceipt{}, errors.New("simulated response loss after recovery settlement commit")
	}
	return receipt, nil
}

func (store *fakeStore) MarkExternallyCommitted(ctx context.Context, command MarkExternalCommand) (ConfirmationReceipt, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, found := store.confirmations[command.OperationKey]; found {
		if store.confirmationDigests[command.OperationKey] != command.OperationDigest {
			return ConfirmationReceipt{}, ErrIdempotencyConflict
		}
		return existing, nil
	}
	if store.snapshot.ActiveEffect == nil || (store.snapshot.ActiveEffect.State != EffectDispatched && store.snapshot.ActiveEffect.State != EffectBlocked) {
		return ConfirmationReceipt{}, ErrInvalidEffectState
	}
	store.eventSequence++
	store.snapshot.ActiveEffect.State = EffectExternallyCommitted
	store.snapshot.ActiveEffect.ExternalCommitID = command.Record.ExternalCommitID
	store.snapshot.ActiveEffect.ResultRef = command.Record.ResultRef
	store.snapshot.EventSequence = store.eventSequence
	store.markExternalTransitions++
	receipt := ConfirmationReceipt{EffectKey: command.Key, TenantID: command.Snapshot.TenantID, WorkspaceID: command.Snapshot.WorkspaceID, Service: command.Record.Service, Operation: command.Record.Operation, DispatchAttempt: command.DispatchAttempt, ProviderRequestID: command.Record.ProviderRequestID, ExternalCommitID: command.Record.ExternalCommitID, ResultRef: command.Record.ResultRef, OperationDigest: command.OperationDigest, EventSequence: store.eventSequence, Durable: !store.forceNonDurable}
	store.applyReceiptRouteCorruption(&receipt.TenantID, &receipt.WorkspaceID)
	if store.zeroConfirmationEvent {
		receipt.EventSequence = 0
	}
	if store.corruptExternalReceipt {
		receipt.EffectID = mustID(identity.Effect, "Z")
	}
	if store.corruptExternalReceiptDomain {
		receipt.Operation = "write"
	}
	store.confirmations[command.OperationKey] = receipt
	store.confirmationDigests[command.OperationKey] = command.OperationDigest
	return receipt, nil
}

func (store *fakeStore) SettleEffect(ctx context.Context, command SettleCommand) (SettlementReceipt, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, found := store.settlements[command.OperationKey]; found {
		if existing.digest != command.SettlementDigest {
			return SettlementReceipt{}, ErrIdempotencyConflict
		}
		return existing.receipt, nil
	}
	if store.snapshot.ActiveEffect == nil || store.snapshot.ActiveEffect.State != EffectExternallyCommitted {
		return SettlementReceipt{}, ErrInvalidEffectState
	}
	store.eventSequence++
	store.snapshot.ActiveEffect.State = EffectSettled
	store.snapshot.ActiveEffect.Settlement = &v1.EffectRecord{State: v1.EffectState_EFFECT_STATE_SETTLED, DispatchAttempt: store.snapshot.ActiveEffect.DispatchAttempt}
	store.snapshot.EventSequence = store.eventSequence
	if command.Error != nil {
		store.lastSettlementError = proto.Clone(command.Error).(*v1.PublicError)
	}
	receipt := SettlementReceipt{EffectKey: command.Key, TenantID: command.Snapshot.TenantID, WorkspaceID: command.Snapshot.WorkspaceID, State: EffectSettled, DispatchAttempt: command.DispatchAttempt, ExternalCommitID: command.ExternalCommitID, ResultRef: command.ResultRef, Error: command.Error, OperationDigest: command.SettlementDigest, Effect: store.snapshot.ActiveEffect.Settlement, EventSequence: store.eventSequence, Durable: !store.forceNonDurable}
	store.applyReceiptRouteCorruption(&receipt.TenantID, &receipt.WorkspaceID)
	if store.corruptSettlementIdentity {
		receipt.DispatchAttempt++
	}
	if store.zeroSettlementEvent {
		receipt.EventSequence = 0
	}
	store.settlements[command.OperationKey] = storedSettlement{digest: command.SettlementDigest, receipt: receipt}
	return receipt, nil
}

func (store *fakeStore) BlockEffect(ctx context.Context, command BlockCommand) (BlockReceipt, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, found := store.blocks[command.OperationKey]; found {
		if existing.digest != command.OperationDigest {
			return BlockReceipt{}, ErrIdempotencyConflict
		}
		return existing.receipt, nil
	}
	if store.snapshot.ActiveEffect == nil || store.snapshot.ActiveEffect.State != EffectDispatched {
		return BlockReceipt{}, ErrInvalidEffectState
	}
	store.eventSequence++
	store.snapshot.ActiveEffect.State = EffectBlocked
	store.snapshot.EventSequence = store.eventSequence
	store.blockTransitions++
	if command.Reason != nil {
		store.lastBlockReason = proto.Clone(command.Reason).(*v1.PublicError)
	}
	receipt := BlockReceipt{EffectKey: command.Key, TenantID: command.Snapshot.TenantID, WorkspaceID: command.Snapshot.WorkspaceID, State: EffectBlocked, ReplayPolicy: store.snapshot.ActiveEffect.ReplayPolicy, DispatchAttempt: store.snapshot.ActiveEffect.DispatchAttempt, OperationDigest: command.OperationDigest, Reason: command.Reason, EventSequence: store.eventSequence, Durable: !store.forceNonDurable}
	store.applyReceiptRouteCorruption(&receipt.TenantID, &receipt.WorkspaceID)
	if store.corruptBlockIdentity {
		receipt.DispatchAttempt++
	}
	if store.zeroBlockEvent {
		receipt.EventSequence = 0
	}
	if store.corruptBlockReceipt {
		receipt.EffectID = mustID(identity.Effect, "Y")
	}
	store.blocks[command.OperationKey] = storedBlock{digest: command.OperationDigest, receipt: receipt}
	if store.loseBlockResponseOnce {
		store.loseBlockResponseOnce = false
		return BlockReceipt{}, errors.New("simulated response loss after block commit")
	}
	return receipt, nil
}
