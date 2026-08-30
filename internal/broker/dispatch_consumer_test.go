package broker

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/identity"
)

func TestConcurrentStartExactAttemptClaimsAndStartsOnce(t *testing.T) {
	t.Parallel()
	const callers = 64
	now := time.Unix(1_900_001_000, 0).UTC()
	snapshot := baseSnapshot(now)
	snapshot.ActiveEffect = baseEffect(EffectPrepared)
	store := newFakeStore(snapshot)
	coordinator := mustCoordinator(t, store, nil)
	dispatch, err := coordinator.AdmitDispatch(context.Background(), baseDispatchRequest(now))
	if err != nil {
		t.Fatalf("AdmitDispatch() error = %v", err)
	}
	starter := &recordingDispatchStarter{}
	consumer, err := NewDispatchConsumer(coordinator, map[EffectService]DispatchStarter{
		ServiceExecutor: starter,
	}, time.Second)
	if err != nil {
		t.Fatalf("NewDispatchConsumer() error = %v", err)
	}
	request := DispatchStartRequest{
		Authority: baseAuthority(now), Now: now, Dispatch: dispatch, CommandDigest: digest(130),
	}

	errorsSeen := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, startErr := consumer.StartExactAttempt(context.Background(), request)
			errorsSeen <- startErr
		}()
	}
	wait.Wait()
	close(errorsSeen)

	started, alreadyStarted := 0, 0
	for startErr := range errorsSeen {
		switch {
		case startErr == nil:
			started++
		case errors.Is(startErr, ErrDispatchAlreadyStarted):
			alreadyStarted++
		default:
			t.Fatalf("StartExactAttempt() error = %v", startErr)
		}
	}
	starter.mu.Lock()
	startCalls := starter.calls
	starter.mu.Unlock()
	store.mu.Lock()
	claimTransitions := store.dispatchStartTransitions
	store.mu.Unlock()
	if started != 1 || alreadyStarted != callers-1 || startCalls != 1 || claimTransitions != 1 {
		t.Fatalf("started=%d already=%d adapter=%d claims=%d", started, alreadyStarted, startCalls, claimTransitions)
	}
}

func TestDispatchConsumerRejectsInvalidConfigurationBeforeClaim(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_900_001_050, 0).UTC()
	snapshot := baseSnapshot(now)
	snapshot.ActiveEffect = baseEffect(EffectDispatched)
	store := newFakeStore(snapshot)
	coordinator := mustCoordinator(t, store, nil)
	var typedNil *recordingDispatchStarter
	tests := []struct {
		name     string
		starters map[EffectService]DispatchStarter
		timeout  time.Duration
	}{
		{name: "missing starter", starters: map[EffectService]DispatchStarter{}, timeout: time.Second},
		{name: "nil starter", starters: map[EffectService]DispatchStarter{ServiceExecutor: typedNil}, timeout: time.Second},
		{name: "missing route digest", starters: map[EffectService]DispatchStarter{ServiceExecutor: &zeroRouteDispatchStarter{}}, timeout: time.Second},
		{name: "zero timeout", starters: map[EffectService]DispatchStarter{ServiceExecutor: &recordingDispatchStarter{}}},
		{name: "unbounded timeout", starters: map[EffectService]DispatchStarter{ServiceExecutor: &recordingDispatchStarter{}}, timeout: 24 * time.Hour},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if consumer, err := NewDispatchConsumer(coordinator, test.starters, test.timeout); err == nil || consumer != nil {
				t.Fatalf("NewDispatchConsumer() = %#v, %v; want rejection", consumer, err)
			}
		})
	}
	store.mu.Lock()
	claims := store.dispatchStartTransitions
	store.mu.Unlock()
	if claims != 0 {
		t.Fatalf("dispatch start transitions = %d, want 0", claims)
	}
}

func TestDispatchConsumerCopiesStarterRegistryBeforeUse(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_900_001_075, 0).UTC()
	snapshot := baseSnapshot(now)
	snapshot.ActiveEffect = baseEffect(EffectPrepared)
	store := newFakeStore(snapshot)
	coordinator := mustCoordinator(t, store, nil)
	dispatch, err := coordinator.AdmitDispatch(context.Background(), baseDispatchRequest(now))
	if err != nil {
		t.Fatalf("AdmitDispatch() error = %v", err)
	}
	selected := &recordingDispatchStarter{}
	replacement := &recordingDispatchStarter{}
	starters := map[EffectService]DispatchStarter{ServiceExecutor: selected}
	consumer, err := NewDispatchConsumer(coordinator, starters, time.Second)
	if err != nil {
		t.Fatalf("NewDispatchConsumer() error = %v", err)
	}
	starters[ServiceExecutor] = replacement
	if _, err := consumer.StartExactAttempt(context.Background(), DispatchStartRequest{
		Authority: baseAuthority(now), Now: now, Dispatch: dispatch, CommandDigest: digest(129),
	}); err != nil {
		t.Fatalf("StartExactAttempt() error = %v", err)
	}
	selected.mu.Lock()
	selectedCalls := selected.calls
	selected.mu.Unlock()
	replacement.mu.Lock()
	replacementCalls := replacement.calls
	replacement.mu.Unlock()
	if selectedCalls != 1 || replacementCalls != 0 {
		t.Fatalf("selected/replacement calls = %d/%d, want 1/0", selectedCalls, replacementCalls)
	}
}

func TestDispatchConsumerRejectsRewiredStarterRouteBeforeClaim(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_900_001_025, 0).UTC()
	snapshot := baseSnapshot(now)
	snapshot.ActiveEffect = baseEffect(EffectPrepared)
	store := newFakeStore(snapshot)
	coordinator := mustCoordinator(t, store, nil)
	dispatch, err := coordinator.AdmitDispatch(context.Background(), baseDispatchRequest(now))
	if err != nil {
		t.Fatalf("AdmitDispatch() error = %v", err)
	}
	starter := &recordingDispatchStarter{routeDigest: digest(153)}
	consumer, err := NewDispatchConsumer(
		coordinator,
		map[EffectService]DispatchStarter{ServiceExecutor: starter},
		time.Second,
	)
	if err != nil {
		t.Fatalf("NewDispatchConsumer() error = %v", err)
	}
	execution, err := consumer.StartExactAttempt(context.Background(), DispatchStartRequest{
		Authority: baseAuthority(now), Now: now, Dispatch: dispatch, CommandDigest: digest(154),
	})
	if !errors.Is(err, ErrFenceMismatch) || execution != (DispatchStartExecution{}) {
		t.Fatalf("StartExactAttempt() = %#v, %v; want route mismatch", execution, err)
	}
	starter.mu.Lock()
	calls := starter.calls
	starter.mu.Unlock()
	store.mu.Lock()
	claims := store.dispatchStartTransitions
	store.mu.Unlock()
	if calls != 0 || claims != 0 {
		t.Fatalf("starter/claim calls = %d/%d, want 0/0", calls, claims)
	}
}

func TestDispatchStartClaimResponseLossAndRestartNeverReachStarter(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_900_001_100, 0).UTC()
	snapshot := baseSnapshot(now)
	snapshot.ActiveEffect = baseEffect(EffectPrepared)
	store := newFakeStore(snapshot)
	coordinator := mustCoordinator(t, store, nil)
	dispatch, err := coordinator.AdmitDispatch(context.Background(), baseDispatchRequest(now))
	if err != nil {
		t.Fatalf("AdmitDispatch() error = %v", err)
	}
	store.mu.Lock()
	store.loseDispatchStartResponseOnce = true
	store.mu.Unlock()
	starter := &recordingDispatchStarter{}
	consumer, err := NewDispatchConsumer(coordinator, map[EffectService]DispatchStarter{ServiceExecutor: starter}, time.Second)
	if err != nil {
		t.Fatalf("NewDispatchConsumer() error = %v", err)
	}
	request := DispatchStartRequest{Authority: baseAuthority(now), Now: now, Dispatch: dispatch, CommandDigest: digest(131)}

	if execution, startErr := consumer.StartExactAttempt(context.Background(), request); startErr == nil || execution != (DispatchStartExecution{}) {
		t.Fatalf("first StartExactAttempt() = %#v, %v; want lost durable response", execution, startErr)
	}
	restarted := mustCoordinator(t, store, nil)
	restartedConsumer, err := NewDispatchConsumer(restarted, map[EffectService]DispatchStarter{ServiceExecutor: starter}, time.Second)
	if err != nil {
		t.Fatalf("NewDispatchConsumer(restart) error = %v", err)
	}
	execution, startErr := restartedConsumer.StartExactAttempt(context.Background(), request)
	if !errors.Is(startErr, ErrDispatchAlreadyStarted) || execution.Outcome != DispatchStartOutcomeUnknown || execution.Claim.Fresh {
		t.Fatalf("restarted StartExactAttempt() = %#v, %v", execution, startErr)
	}
	starter.mu.Lock()
	startCalls := starter.calls
	starter.mu.Unlock()
	store.mu.Lock()
	claimTransitions := store.dispatchStartTransitions
	store.mu.Unlock()
	if startCalls != 0 || claimTransitions != 1 {
		t.Fatalf("adapter calls=%d claim transitions=%d, want 0/1", startCalls, claimTransitions)
	}
}

func TestStarterErrorIsUnknownAndNeverRetried(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_900_001_200, 0).UTC()
	snapshot := baseSnapshot(now)
	snapshot.ActiveEffect = baseEffect(EffectPrepared)
	store := newFakeStore(snapshot)
	coordinator := mustCoordinator(t, store, nil)
	dispatch, err := coordinator.AdmitDispatch(context.Background(), baseDispatchRequest(now))
	if err != nil {
		t.Fatalf("AdmitDispatch() error = %v", err)
	}
	starter := &recordingDispatchStarter{err: errors.New("response lost after possible send")}
	consumer, err := NewDispatchConsumer(coordinator, map[EffectService]DispatchStarter{ServiceExecutor: starter}, time.Second)
	if err != nil {
		t.Fatalf("NewDispatchConsumer() error = %v", err)
	}
	request := DispatchStartRequest{Authority: baseAuthority(now), Now: now, Dispatch: dispatch, CommandDigest: digest(132)}

	execution, startErr := consumer.StartExactAttempt(context.Background(), request)
	if !errors.Is(startErr, ErrDispatchStartUnknown) || execution.Outcome != DispatchStartOutcomeUnknown || !execution.Claim.Fresh {
		t.Fatalf("first StartExactAttempt() = %#v, %v", execution, startErr)
	}
	execution, startErr = consumer.StartExactAttempt(context.Background(), request)
	if !errors.Is(startErr, ErrDispatchAlreadyStarted) || execution.Outcome != DispatchStartOutcomeUnknown || execution.Claim.Fresh {
		t.Fatalf("replayed StartExactAttempt() = %#v, %v", execution, startErr)
	}
	starter.mu.Lock()
	startCalls := starter.calls
	starter.mu.Unlock()
	if startCalls != 1 {
		t.Fatalf("adapter calls = %d, want 1", startCalls)
	}
}

func TestFreshClaimDecouplesBoundedStarterContextFromCallerCancellation(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_900_001_300, 0).UTC()
	snapshot := baseSnapshot(now)
	snapshot.ActiveEffect = baseEffect(EffectPrepared)
	store := newFakeStore(snapshot)
	coordinator := mustCoordinator(t, store, nil)
	dispatch, err := coordinator.AdmitDispatch(context.Background(), baseDispatchRequest(now))
	if err != nil {
		t.Fatalf("AdmitDispatch() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	store.mu.Lock()
	store.afterFreshDispatchStartClaim = cancel
	store.mu.Unlock()
	starter := &recordingDispatchStarter{}
	consumer, err := NewDispatchConsumer(coordinator, map[EffectService]DispatchStarter{ServiceExecutor: starter}, time.Second)
	if err != nil {
		t.Fatalf("NewDispatchConsumer() error = %v", err)
	}
	execution, startErr := consumer.StartExactAttempt(ctx, DispatchStartRequest{
		Authority: baseAuthority(now), Now: now, Dispatch: dispatch, CommandDigest: digest(133),
	})
	if startErr != nil || execution.Outcome != DispatchStartOutcomeStarted || !execution.Claim.Fresh || ctx.Err() == nil {
		t.Fatalf("StartExactAttempt() = %#v, %v; caller error=%v", execution, startErr, ctx.Err())
	}
	starter.mu.Lock()
	starterContextErr := starter.contextErr
	starterHadDeadline := starter.hadDeadline
	starter.mu.Unlock()
	if starterContextErr != nil || !starterHadDeadline {
		t.Fatalf("starter context error/deadline = %v/%t", starterContextErr, starterHadDeadline)
	}
}

func TestDispatchStartReceiptBindsExactRouteEffectAndAttempt(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_900_001_350, 0).UTC()
	tests := []struct {
		name   string
		mutate func(*DispatchStartPermit)
	}{
		{name: "tenant", mutate: func(permit *DispatchStartPermit) { permit.Dispatch.TenantID = mustID(identity.Tenant, "wrong-tenant") }},
		{name: "workspace", mutate: func(permit *DispatchStartPermit) {
			permit.Dispatch.WorkspaceID = mustID(identity.Workspace, "wrong-workspace")
		}},
		{name: "effect", mutate: func(permit *DispatchStartPermit) { permit.Dispatch.EffectID = mustID(identity.Effect, "wrong-effect") }},
		{name: "service", mutate: func(permit *DispatchStartPermit) { permit.Dispatch.Service = ServiceWorkspace }},
		{name: "operation", mutate: func(permit *DispatchStartPermit) { permit.Dispatch.Operation = "write" }},
		{name: "request", mutate: func(permit *DispatchStartPermit) { permit.Dispatch.RequestDigest = digest(140) }},
		{name: "attempt", mutate: func(permit *DispatchStartPermit) { permit.Dispatch.DispatchAttempt++ }},
		{name: "provider", mutate: func(permit *DispatchStartPermit) {
			permit.Dispatch.ProviderRequestID = mustID(identity.Request, "wrong-provider")
		}},
		{name: "provider route", mutate: func(permit *DispatchStartPermit) {
			permit.Dispatch.ProviderRouteDigest = digest(155)
		}},
		{name: "generation", mutate: func(permit *DispatchStartPermit) { permit.Dispatch.Generations.Placement++ }},
		{name: "deadline", mutate: func(permit *DispatchStartPermit) {
			permit.Dispatch.Deadline = permit.Dispatch.Deadline.Add(time.Second)
		}},
		{name: "command digest", mutate: func(permit *DispatchStartPermit) { permit.CommandDigest = digest(141) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := baseSnapshot(now)
			snapshot.ActiveEffect = baseEffect(EffectPrepared)
			store := newFakeStore(snapshot)
			coordinator := mustCoordinator(t, store, nil)
			dispatch, err := coordinator.AdmitDispatch(context.Background(), baseDispatchRequest(now))
			if err != nil {
				t.Fatalf("AdmitDispatch() error = %v", err)
			}
			store.mu.Lock()
			store.corruptDispatchStartReceipt = test.mutate
			store.mu.Unlock()
			claim, err := coordinator.ClaimDispatchStart(context.Background(), DispatchStartRequest{
				Authority: baseAuthority(now), Now: now, Dispatch: dispatch, CommandDigest: digest(142),
			})
			if !errors.Is(err, ErrFenceMismatch) || claim != (DispatchStartClaim{}) {
				t.Fatalf("ClaimDispatchStart() = %#v, %v; want ErrFenceMismatch", claim, err)
			}
		})
	}
}

func TestMalformedDispatchStartReceiptNeverReachesStarter(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		mutate func(*DispatchStartPermit)
	}{
		{name: "missing opaque permit", mutate: func(permit *DispatchStartPermit) { permit.Opaque = "" }},
		{name: "forged opaque permit", mutate: func(permit *DispatchStartPermit) { permit.Opaque = opaque(249) }},
		{name: "missing durable event", mutate: func(permit *DispatchStartPermit) { permit.EventSequence = 0 }},
		{name: "forged durable event", mutate: func(permit *DispatchStartPermit) { permit.EventSequence++ }},
		{name: "non-durable", mutate: func(permit *DispatchStartPermit) { permit.Durable = false }},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Unix(1_900_001_360, 0).UTC()
			snapshot := baseSnapshot(now)
			snapshot.ActiveEffect = baseEffect(EffectPrepared)
			store := newFakeStore(snapshot)
			coordinator := mustCoordinator(t, store, nil)
			dispatch, err := coordinator.AdmitDispatch(context.Background(), baseDispatchRequest(now))
			if err != nil {
				t.Fatalf("AdmitDispatch() error = %v", err)
			}
			store.mu.Lock()
			store.corruptDispatchStartReceipt = test.mutate
			store.mu.Unlock()
			starter := &recordingDispatchStarter{}
			consumer, err := NewDispatchConsumer(coordinator, map[EffectService]DispatchStarter{ServiceExecutor: starter}, time.Second)
			if err != nil {
				t.Fatalf("NewDispatchConsumer() error = %v", err)
			}
			if execution, startErr := consumer.StartExactAttempt(context.Background(), DispatchStartRequest{
				Authority: baseAuthority(now), Now: now, Dispatch: dispatch, CommandDigest: digest(146),
			}); startErr == nil || execution != (DispatchStartExecution{}) {
				t.Fatalf("StartExactAttempt() = %#v, %v; want malformed receipt rejection", execution, startErr)
			}
			starter.mu.Lock()
			calls := starter.calls
			starter.mu.Unlock()
			if calls != 0 {
				t.Fatalf("starter calls = %d, want 0", calls)
			}
		})
	}
}

func TestDispatchStartRequestRelabelIsRejectedBeforeDurableClaim(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_900_001_375, 0).UTC()
	tests := []struct {
		name   string
		mutate func(*DispatchStartRequest)
	}{
		{name: "tenant", mutate: func(request *DispatchStartRequest) {
			request.Dispatch.TenantID = mustID(identity.Tenant, "other-tenant")
		}},
		{name: "workspace", mutate: func(request *DispatchStartRequest) {
			request.Dispatch.WorkspaceID = mustID(identity.Workspace, "other-workspace")
		}},
		{name: "service", mutate: func(request *DispatchStartRequest) { request.Dispatch.Service = ServiceWorkspace }},
		{name: "operation", mutate: func(request *DispatchStartRequest) { request.Dispatch.Operation = "write" }},
		{name: "request digest", mutate: func(request *DispatchStartRequest) { request.Dispatch.RequestDigest = digest(143) }},
		{name: "attempt", mutate: func(request *DispatchStartRequest) { request.Dispatch.DispatchAttempt++ }},
		{name: "provider", mutate: func(request *DispatchStartRequest) {
			request.Dispatch.ProviderRequestID = mustID(identity.Request, "other-provider")
		}},
		{name: "provider route", mutate: func(request *DispatchStartRequest) {
			request.Dispatch.ProviderRouteDigest = digest(156)
		}},
		{name: "command digest", mutate: func(request *DispatchStartRequest) { request.CommandDigest = Digest{} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := baseSnapshot(now)
			snapshot.ActiveEffect = baseEffect(EffectPrepared)
			store := newFakeStore(snapshot)
			coordinator := mustCoordinator(t, store, nil)
			dispatch, err := coordinator.AdmitDispatch(context.Background(), baseDispatchRequest(now))
			if err != nil {
				t.Fatalf("AdmitDispatch() error = %v", err)
			}
			request := DispatchStartRequest{Authority: baseAuthority(now), Now: now, Dispatch: dispatch, CommandDigest: digest(144)}
			test.mutate(&request)
			if claim, err := coordinator.ClaimDispatchStart(context.Background(), request); err == nil || claim != (DispatchStartClaim{}) {
				t.Fatalf("ClaimDispatchStart() = %#v, %v; want rejection", claim, err)
			}
			store.mu.Lock()
			claims := store.dispatchStartTransitions
			store.mu.Unlock()
			if claims != 0 {
				t.Fatalf("dispatch start transitions = %d, want 0", claims)
			}
		})
	}
}

func TestForgedDispatchPermitProofIsRejectedBeforeDurableClaim(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		mutate func(*DispatchPermit)
	}{
		{name: "opaque", mutate: func(permit *DispatchPermit) { permit.Opaque = opaque(250) }},
		{name: "event sequence", mutate: func(permit *DispatchPermit) { permit.EventSequence++ }},
		{name: "durability", mutate: func(permit *DispatchPermit) { permit.Durable = false }},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Unix(1_900_001_380, 0).UTC()
			snapshot := baseSnapshot(now)
			snapshot.ActiveEffect = baseEffect(EffectPrepared)
			store := newFakeStore(snapshot)
			coordinator := mustCoordinator(t, store, nil)
			dispatch, err := coordinator.AdmitDispatch(context.Background(), baseDispatchRequest(now))
			if err != nil {
				t.Fatalf("AdmitDispatch() error = %v", err)
			}
			test.mutate(&dispatch)
			if claim, claimErr := coordinator.ClaimDispatchStart(context.Background(), DispatchStartRequest{
				Authority: baseAuthority(now), Now: now, Dispatch: dispatch, CommandDigest: digest(147),
			}); claimErr == nil || claim != (DispatchStartClaim{}) {
				t.Fatalf("ClaimDispatchStart() = %#v, %v; want forged proof rejection", claim, claimErr)
			}
			store.mu.Lock()
			claims := store.dispatchStartTransitions
			store.mu.Unlock()
			if claims != 0 {
				t.Fatalf("dispatch start transitions = %d, want 0", claims)
			}
		})
	}
}

func TestAbortAndElapsedDeadlinePreventClaimAndStarter(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		mutate func(*fakeStore, *DispatchStartRequest)
	}{
		{name: "abort", mutate: func(store *fakeStore, _ *DispatchStartRequest) {
			store.mu.Lock()
			store.snapshot.AbortRequested = true
			store.mu.Unlock()
		}},
		{name: "deadline", mutate: func(_ *fakeStore, request *DispatchStartRequest) {
			request.Now = request.Dispatch.Deadline
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Unix(1_900_001_390, 0).UTC()
			snapshot := baseSnapshot(now)
			snapshot.ActiveEffect = baseEffect(EffectPrepared)
			store := newFakeStore(snapshot)
			coordinator := mustCoordinator(t, store, nil)
			dispatch, err := coordinator.AdmitDispatch(context.Background(), baseDispatchRequest(now))
			if err != nil {
				t.Fatalf("AdmitDispatch() error = %v", err)
			}
			starter := &recordingDispatchStarter{}
			consumer, err := NewDispatchConsumer(coordinator, map[EffectService]DispatchStarter{ServiceExecutor: starter}, time.Second)
			if err != nil {
				t.Fatalf("NewDispatchConsumer() error = %v", err)
			}
			request := DispatchStartRequest{Authority: baseAuthority(now), Now: now, Dispatch: dispatch, CommandDigest: digest(145)}
			test.mutate(store, &request)
			if execution, err := consumer.StartExactAttempt(context.Background(), request); err == nil || execution != (DispatchStartExecution{}) {
				t.Fatalf("StartExactAttempt() = %#v, %v; want rejection", execution, err)
			}
			starter.mu.Lock()
			calls := starter.calls
			starter.mu.Unlock()
			store.mu.Lock()
			claims := store.dispatchStartTransitions
			store.mu.Unlock()
			if calls != 0 || claims != 0 {
				t.Fatalf("starter/claim calls = %d/%d, want 0/0", calls, claims)
			}
		})
	}
}

func TestClaimedDispatchStartMakesAbsentLedgerRecoveryWait(t *testing.T) {
	t.Parallel()
	for index, test := range []struct {
		name            string
		status          LedgerStatus
		abort           bool
		wantAction      RecoveryAction
		wantSettlements int
	}{
		{name: "absent", status: LedgerAbsent, wantAction: RecoveryWaitExternal},
		{name: "absent after abort", status: LedgerAbsent, abort: true, wantAction: RecoveryWaitExternal},
		{name: "authoritative failed after abort", status: LedgerFailed, abort: true, wantAction: RecoverySettleFailed, wantSettlements: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Unix(1_900_001_400+int64(index), 0).UTC()
			snapshot := baseSnapshot(now)
			snapshot.ActiveEffect = baseEffect(EffectPrepared)
			store := newFakeStore(snapshot)
			ledgerRecord := routedRecord(test.status)
			if test.status == LedgerFailed {
				ledgerRecord = committedRecord()
				ledgerRecord.Status = LedgerFailed
				ledgerRecord.ExternalCommitID = identity.ID{}
				ledgerRecord.ResultRef = identity.ID{}
			}
			coordinator := mustCoordinator(t, store, &fakeLedger{record: ledgerRecord})
			dispatch, err := coordinator.AdmitDispatch(context.Background(), baseDispatchRequest(now))
			if err != nil {
				t.Fatalf("AdmitDispatch() error = %v", err)
			}
			claim, err := coordinator.ClaimDispatchStart(context.Background(), DispatchStartRequest{
				Authority: baseAuthority(now), Now: now, Dispatch: dispatch, CommandDigest: digest(134),
			})
			if err != nil || !claim.Fresh {
				t.Fatalf("ClaimDispatchStart() = %#v, %v", claim, err)
			}
			if test.abort {
				store.mu.Lock()
				store.snapshot.AbortRequested = true
				store.mu.Unlock()
			}
			decision, err := coordinator.RecoverEffect(context.Background(), baseRecoveryRequest(now, "claimed-start-recovery"))
			if err != nil || decision.Action != test.wantAction || decision.DispatchAttempt != dispatch.DispatchAttempt {
				t.Fatalf("RecoverEffect() = %#v, %v", decision, err)
			}
			store.mu.Lock()
			preparations := store.prepareRetryTransitions
			dispatches := store.markDispatchTransitions
			settlements := store.recoverySettlementTransitions
			blocks := store.blockTransitions
			store.mu.Unlock()
			if preparations != 0 || dispatches != 1 || settlements != test.wantSettlements || blocks != 0 {
				t.Fatalf("retry/dispatch/settle/block transitions = %d/%d/%d/%d", preparations, dispatches, settlements, blocks)
			}
		})
	}
}

func TestClaimedDispatchStartMakesExactRecoveryDispatchReplayWait(t *testing.T) {
	t.Parallel()
	for index, abort := range []bool{false, true} {
		t.Run(map[bool]string{false: "active", true: "aborting"}[abort], func(t *testing.T) {
			now := time.Unix(1_900_001_450+int64(index), 0).UTC()
			snapshot := baseSnapshot(now)
			snapshot.ActiveEffect = baseEffect(EffectPrepared)
			store := newFakeStore(snapshot)
			coordinator := mustCoordinator(t, store, nil)
			dispatchRequest := baseDispatchRequest(now)
			dispatchRequest.OperationKey = "claimed-start-operation-replay"
			dispatchRequest.OperationDigest = digest(149)
			dispatch, err := coordinator.AdmitDispatch(context.Background(), dispatchRequest)
			if err != nil {
				t.Fatalf("AdmitDispatch() error = %v", err)
			}
			if claim, claimErr := coordinator.ClaimDispatchStart(context.Background(), DispatchStartRequest{
				Authority: baseAuthority(now), Now: now, Dispatch: dispatch, CommandDigest: digest(150),
			}); claimErr != nil || !claim.Fresh {
				t.Fatalf("ClaimDispatchStart() = %#v, %v", claim, claimErr)
			}
			if abort {
				store.mu.Lock()
				store.snapshot.AbortRequested = true
				store.mu.Unlock()
			}
			recovery := baseRecoveryRequest(now, dispatchRequest.OperationKey)
			recovery.OperationDigest = dispatchRequest.OperationDigest
			recovery.ProviderRequestID = dispatch.ProviderRequestID
			recovery.Deadline = dispatch.Deadline
			decision, err := coordinator.RecoverEffect(context.Background(), recovery)
			if err != nil || decision.Action != RecoveryWaitExternal || decision.DispatchPermit != nil {
				t.Fatalf("RecoverEffect() = %#v, %v; want wait without replay permit", decision, err)
			}
		})
	}
}

func TestDispatchStartClaimRejectsAuthoritativeAbortAfterSnapshotRead(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_900_001_475, 0).UTC()
	snapshot := baseSnapshot(now)
	snapshot.ActiveEffect = baseEffect(EffectPrepared)
	store := newFakeStore(snapshot)
	coordinator := mustCoordinator(t, store, nil)
	dispatch, err := coordinator.AdmitDispatch(context.Background(), baseDispatchRequest(now))
	if err != nil {
		t.Fatalf("AdmitDispatch() error = %v", err)
	}
	stale, err := store.ReadTurn(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("ReadTurn() error = %v", err)
	}
	store.mu.Lock()
	store.snapshot.AbortRequested = true
	store.mu.Unlock()
	claim, err := store.ClaimDispatchStart(context.Background(), ClaimDispatchStartCommand{
		Snapshot: stale, Dispatch: dispatch, CommandDigest: digest(151), Now: now,
	})
	if !errors.Is(err, ErrInvalidEffectState) || claim != (DispatchStartClaim{}) {
		t.Fatalf("ClaimDispatchStart() = %#v, %v; want authoritative abort rejection", claim, err)
	}
	store.mu.Lock()
	transitions := store.dispatchStartTransitions
	store.mu.Unlock()
	if transitions != 0 {
		t.Fatalf("dispatch start transitions = %d, want 0", transitions)
	}
}

func TestRecoveryStaleReadMapsConcurrentStartClaimToWaitExternal(t *testing.T) {
	t.Parallel()
	for index, test := range []struct {
		name   string
		policy ReplayPolicy
		status LedgerStatus
	}{
		{name: "safe absent", policy: ReplayIdempotencyKey, status: LedgerAbsent},
		{name: "never unknown", policy: ReplayNever, status: LedgerUnknown},
		{name: "confirm unknown", policy: ReplayConfirm, status: LedgerUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Unix(1_900_001_500+int64(index), 0).UTC()
			snapshot := baseSnapshot(now)
			snapshot.ActiveEffect = baseEffect(EffectPrepared)
			snapshot.ActiveEffect.ReplayPolicy = test.policy
			snapshot.ActiveEffect.PreparationPermit.ReplayPolicy = test.policy
			store := newFakeStore(snapshot)
			var coordinator *Coordinator
			var dispatch DispatchPermit
			ledger := &fakeLedger{lookup: func(_ context.Context, _ LedgerLookup) (LedgerRecord, error) {
				claim, claimErr := coordinator.ClaimDispatchStart(context.Background(), DispatchStartRequest{
					Authority: baseAuthority(now), Now: now, Dispatch: dispatch, CommandDigest: digest(135),
				})
				if claimErr != nil || !claim.Fresh {
					return LedgerRecord{}, errors.New("concurrent start claim failed")
				}
				return routedRecord(test.status), nil
			}}
			coordinator = mustCoordinator(t, store, ledger)
			dispatchRequest := baseDispatchRequest(now)
			dispatchRequest.PreparationPermit.ReplayPolicy = test.policy
			dispatch, err := coordinator.AdmitDispatch(context.Background(), dispatchRequest)
			if err != nil {
				t.Fatalf("AdmitDispatch() error = %v", err)
			}
			store.mu.Lock()
			readsBeforeRecovery := store.readTurnCalls
			store.mu.Unlock()
			decision, err := coordinator.RecoverEffect(context.Background(), baseRecoveryRequest(now, "stale-read-start-race"))
			if err != nil || decision.Action != RecoveryWaitExternal {
				t.Fatalf("RecoverEffect() = %#v, %v", decision, err)
			}
			store.mu.Lock()
			preparations := store.prepareRetryTransitions
			settlements := store.recoverySettlementTransitions
			blocks := store.blockTransitions
			readsAfterRecovery := store.readTurnCalls
			store.mu.Unlock()
			if preparations != 0 || settlements != 0 || blocks != 0 {
				t.Fatalf("retry/settle/block transitions = %d/%d/%d, want 0/0/0", preparations, settlements, blocks)
			}
			if readsAfterRecovery-readsBeforeRecovery != 4 {
				t.Fatalf("recovery ReadTurn calls = %d, want 4 (stale read, claim validation, durable-claim read, exact conflict re-read)", readsAfterRecovery-readsBeforeRecovery)
			}
		})
	}
}

func TestDispatchStartClaimAndRetryPreparationAreMutuallyExclusive(t *testing.T) {
	t.Parallel()
	const races = 64
	for index := range races {
		now := time.Unix(1_900_001_600+int64(index), 0).UTC()
		snapshot := baseSnapshot(now)
		snapshot.ActiveEffect = baseEffect(EffectPrepared)
		store := newFakeStore(snapshot)
		coordinator := mustCoordinator(t, store, nil)
		dispatch, err := coordinator.AdmitDispatch(context.Background(), baseDispatchRequest(now))
		if err != nil {
			t.Fatalf("race %d AdmitDispatch() error = %v", index, err)
		}
		current, err := store.ReadTurn(context.Background(), sessionID)
		if err != nil {
			t.Fatalf("race %d ReadTurn() error = %v", index, err)
		}
		results := make(chan error, 2)
		go func() {
			_, claimErr := coordinator.ClaimDispatchStart(context.Background(), DispatchStartRequest{
				Authority: baseAuthority(now), Now: now, Dispatch: dispatch, CommandDigest: digest(136),
			})
			results <- claimErr
		}()
		go func() {
			_, prepareErr := store.PrepareRetry(context.Background(), PrepareRetryCommand{
				Snapshot: current, Key: dispatch.EffectKey, OperationKey: "claim-retry-race", OperationDigest: digest(137),
				Now: now, Deadline: now.Add(time.Minute),
			})
			results <- prepareErr
		}()
		first, second := <-results, <-results
		close(results)
		if (first == nil) == (second == nil) {
			t.Fatalf("race %d errors = %v / %v; want exactly one winner", index, first, second)
		}
		store.mu.Lock()
		claims := store.dispatchStartTransitions
		preparations := store.prepareRetryTransitions
		store.mu.Unlock()
		if claims+preparations != 1 {
			t.Fatalf("race %d claims/preparations = %d/%d", index, claims, preparations)
		}
	}
}

func TestPreparedRetrySurvivesRestartAndRejectsLateOldAttemptClaim(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_900_001_750, 0).UTC()
	snapshot := baseSnapshot(now)
	snapshot.ActiveEffect = baseEffect(EffectPrepared)
	store := newFakeStore(snapshot)
	coordinator := mustCoordinator(t, store, nil)
	dispatch, err := coordinator.AdmitDispatch(context.Background(), baseDispatchRequest(now))
	if err != nil {
		t.Fatalf("AdmitDispatch() error = %v", err)
	}
	current, err := store.ReadTurn(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("ReadTurn() error = %v", err)
	}
	if _, err := store.PrepareRetry(context.Background(), PrepareRetryCommand{
		Snapshot: current, Key: dispatch.EffectKey, OperationKey: "prepared-retry-wins", OperationDigest: digest(146),
		Now: now, Deadline: now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("PrepareRetry() error = %v", err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		restarted := mustCoordinator(t, store, nil)
		if claim, err := restarted.ClaimDispatchStart(context.Background(), DispatchStartRequest{
			Authority: baseAuthority(now), Now: now, Dispatch: dispatch, CommandDigest: digest(147),
		}); err == nil || claim != (DispatchStartClaim{}) {
			t.Fatalf("late claim %d = %#v, %v; want rejection", attempt, claim, err)
		}
	}
	store.mu.Lock()
	claims := store.dispatchStartTransitions
	preparations := store.prepareRetryTransitions
	store.mu.Unlock()
	if claims != 0 || preparations != 1 {
		t.Fatalf("claims/preparations = %d/%d, want 0/1", claims, preparations)
	}
}

func TestReadTurnDeepCopiesDispatchStartMetadata(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_900_001_800, 0).UTC()
	snapshot := baseSnapshot(now)
	snapshot.ActiveEffect = baseEffect(EffectPrepared)
	store := newFakeStore(snapshot)
	coordinator := mustCoordinator(t, store, nil)
	dispatch, err := coordinator.AdmitDispatch(context.Background(), baseDispatchRequest(now))
	if err != nil {
		t.Fatalf("AdmitDispatch() error = %v", err)
	}
	if _, err := coordinator.ClaimDispatchStart(context.Background(), DispatchStartRequest{
		Authority: baseAuthority(now), Now: now, Dispatch: dispatch, CommandDigest: digest(138),
	}); err != nil {
		t.Fatalf("ClaimDispatchStart() error = %v", err)
	}
	first, err := store.ReadTurn(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("ReadTurn(first) error = %v", err)
	}
	first.ActiveEffect.LastDispatch.ProviderRequestID = identity.ID{}
	first.ActiveEffect.LastDispatch.ProviderRouteDigest = digest(157)
	first.ActiveEffect.LastDispatch.Start.CommandDigest = digest(139)
	first.ActiveEffect.LastDispatch.Start.Dispatch.Operation = "mutated"
	second, err := store.ReadTurn(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("ReadTurn(second) error = %v", err)
	}
	if second.ActiveEffect.LastDispatch.ProviderRequestID != dispatch.ProviderRequestID ||
		second.ActiveEffect.LastDispatch.ProviderRouteDigest != dispatch.ProviderRouteDigest ||
		second.ActiveEffect.LastDispatch.Start.CommandDigest != digest(138) ||
		second.ActiveEffect.LastDispatch.Start.Dispatch.Operation != dispatch.Operation {
		t.Fatalf("stored dispatch metadata was mutated through a read snapshot: %#v", second.ActiveEffect.LastDispatch)
	}
}

type recordingDispatchStarter struct {
	mu          sync.Mutex
	calls       int
	err         error
	contextErr  error
	hadDeadline bool
	routeDigest Digest
}

type zeroRouteDispatchStarter struct{}

func (*zeroRouteDispatchStarter) RouteDigest() Digest { return Digest{} }

func (*zeroRouteDispatchStarter) Start(context.Context, DispatchStartPermit) error { return nil }

func (starter *recordingDispatchStarter) RouteDigest() Digest {
	starter.mu.Lock()
	defer starter.mu.Unlock()
	if starter.routeDigest == (Digest{}) {
		return digest(152)
	}
	return starter.routeDigest
}

func (starter *recordingDispatchStarter) Start(ctx context.Context, _ DispatchStartPermit) error {
	starter.mu.Lock()
	starter.calls++
	starter.contextErr = ctx.Err()
	_, starter.hadDeadline = ctx.Deadline()
	err := starter.err
	starter.mu.Unlock()
	return err
}
