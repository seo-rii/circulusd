package broker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/identity"
	"google.golang.org/protobuf/proto"
)

func TestFullEngineBoundaryAndResumeContextReachDurableStore(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_900_000_000, 0).UTC()
	snapshot := baseSnapshot(now)
	snapshot.Checkpoint = &v1.AgentCheckpoint{PayloadBytes: []byte("durable-checkpoint")}
	snapshot.UnconsumedSettlement = &v1.EffectRecord{ResultRef: &v1.OpaqueId{Value: []byte("result-ref")}}
	store := newFakeStore(snapshot)
	coordinator := mustCoordinator(t, store, nil)

	permit := acquirePermit(t, coordinator, now, "full-context")
	if string(permit.Checkpoint.PayloadBytes) != "durable-checkpoint" {
		t.Fatalf("checkpoint payload = %q", permit.Checkpoint.PayloadBytes)
	}
	if string(permit.UnconsumedSettlement.ResultRef.Value) != "result-ref" {
		t.Fatalf("settlement result ref = %q", permit.UnconsumedSettlement.ResultRef.Value)
	}

	message := &v1.EngineStepBoundary{
		Checkpoint: &v1.AgentCheckpoint{PayloadBytes: []byte("next-checkpoint")},
		Boundary: &v1.EngineStepBoundary_EffectRequest{EffectRequest: &v1.EffectIntent{
			Service:           v1.EffectService_EFFECT_SERVICE_EXECUTOR,
			Operation:         "run",
			ReplayPolicy:      v1.ReplayPolicy_REPLAY_POLICY_IDEMPOTENCY_KEY,
			RequestDigest:     &v1.Digest{Algorithm: v1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: make([]byte, 32)},
			Payload:           []byte("full-effect-payload"),
			ParentOperationId: &v1.OpaqueId{Value: []byte("parent")},
			Ordinal:           3,
		}},
	}
	receipt, err := coordinator.CommitEngineStep(context.Background(), EngineStepCommit{
		Permit: permit, Now: now, OperationKey: "full-boundary", RequestDigest: digest(70),
		Boundary: EngineBoundary{Message: message, CheckpointDigest: digest(71)},
	})
	if err != nil {
		t.Fatalf("CommitEngineStep() error = %v", err)
	}
	if got := string(store.lastStepBoundary.GetEffectRequest().Payload); got != "full-effect-payload" {
		t.Fatalf("stored effect payload = %q", got)
	}
	if receipt.PreparedEffect == nil || receipt.PreparationPermit == nil {
		t.Fatalf("effect boundary receipt lost prepared response: %#v", receipt)
	}
}

func TestDispatchAndRecoveryBindOpaqueAttemptProviderAndDeadline(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_900_000_100, 0).UTC()
	providerID := mustID(identity.Request, "P")
	snapshot := baseSnapshot(now)
	snapshot.ActiveEffect = baseEffect(EffectPrepared)
	preparation := preparationPermit(snapshot, 1, now.Add(time.Minute))
	snapshot.ActiveEffect.PreparationPermit = &preparation
	store := newFakeStore(snapshot)
	coordinator := mustCoordinator(t, store, &fakeLedger{lookup: func(_ context.Context, lookup LedgerLookup) (LedgerRecord, error) {
		return exactLedgerRecord(lookup, LedgerAbsent), nil
	}})

	request := baseDispatchRequest(now)
	request.PreparationPermit = *snapshot.ActiveEffect.PreparationPermit
	request.ProviderRequestID = providerID
	request.Deadline = now.Add(time.Minute)
	permit, err := coordinator.AdmitDispatch(context.Background(), request)
	if err != nil {
		t.Fatalf("AdmitDispatch() error = %v", err)
	}
	if permit.Opaque == "" || permit.DispatchAttempt != 1 || permit.ProviderRequestID != providerID || permit.ProviderRouteDigest != request.ProviderRouteDigest || !permit.Deadline.Equal(request.Deadline) {
		t.Fatalf("dispatch permit did not bind opaque attempt/provider/deadline: %#v", permit)
	}

	decision, err := coordinator.RecoverEffect(context.Background(), RecoveryRequest{
		Authority: baseAuthority(now), Now: now.Add(time.Second), Deadline: now.Add(2 * time.Minute),
		ProviderRequestID: mustID(identity.Request, "Q"), ProviderRouteDigest: digest(152), EffectID: effectID, InvocationID: invocationID,
		RequestDigest: digest(2), OperationKey: "retry-attempt-2", OperationDigest: digest(72),
	})
	if err != nil {
		t.Fatalf("RecoverEffect() error = %v", err)
	}
	if decision.DispatchPermit == nil || decision.DispatchPermit.DispatchAttempt != 2 || store.prepareRetryTransitions != 1 || store.markDispatchTransitions != 2 {
		t.Fatalf("recovery did not durably issue attempt 2: decision=%#v store=%#v", decision, store)
	}
}

func TestNeverRecoveryDurablySettlesInsteadOfReturningAnUnenactedDecision(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_900_000_200, 0).UTC()
	snapshot := baseSnapshot(now)
	effect := baseEffect(EffectDispatched)
	effect.ReplayPolicy = ReplayNever
	snapshot.ActiveEffect = effect
	store := newFakeStore(snapshot)
	coordinator := mustCoordinator(t, store, &fakeLedger{record: routedRecord(LedgerUnknown)})

	decision, err := coordinator.RecoverEffect(context.Background(), RecoveryRequest{
		Authority: baseAuthority(now), Now: now, Deadline: now.Add(time.Minute),
		EffectID: effectID, InvocationID: invocationID, RequestDigest: digest(2),
		OperationKey: "never-settlement", OperationDigest: digest(73),
	})
	if err != nil {
		t.Fatalf("RecoverEffect() error = %v", err)
	}
	if decision.Action != RecoverySettleInterrupted || decision.SettlementReceipt == nil || store.recoverySettlementTransitions != 1 {
		t.Fatalf("never recovery was not durably settled: %#v", decision)
	}
}

func TestAbortRecoveryNeverAdmitsDispatchOrReplay(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_900_000_300, 0).UTC()
	for _, test := range []struct {
		name      string
		state     EffectState
		policy    ReplayPolicy
		confirmed bool
		want      RecoveryAction
	}{
		{name: "prepared", state: EffectPrepared, policy: ReplaySafe, want: RecoverySettleInterrupted},
		{name: "dispatched safe", state: EffectDispatched, policy: ReplaySafe, want: RecoverySettleInterrupted},
		{name: "blocked confirmed", state: EffectBlocked, policy: ReplayConfirm, confirmed: true, want: RecoverySettleInterrupted},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := baseSnapshot(now)
			snapshot.AbortRequested = true
			effect := baseEffect(test.state)
			effect.ReplayPolicy = test.policy
			if effect.PreparationPermit != nil {
				effect.PreparationPermit.ReplayPolicy = test.policy
			}
			snapshot.ActiveEffect = effect
			store := newFakeStore(snapshot)
			coordinator := mustCoordinator(t, store, &fakeLedger{record: routedRecord(LedgerUnknown)})
			decision, err := coordinator.RecoverEffect(context.Background(), RecoveryRequest{
				Authority: baseAuthority(now), Now: now, Deadline: now.Add(time.Minute),
				EffectID: effectID, InvocationID: invocationID, RequestDigest: digest(2),
				OperationKey: "abort-" + test.name, OperationDigest: digest(74), UserConfirmed: test.confirmed,
			})
			if err != nil {
				t.Fatalf("RecoverEffect() error = %v", err)
			}
			if decision.Action != test.want || decision.DispatchPermit != nil {
				t.Fatalf("abort recovery = %#v, want %q without dispatch", decision, test.want)
			}
		})
	}
}

func TestMutationReceiptReplaySurvivesLaterStateProgress(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_900_000_400, 0).UTC()

	t.Run("dispatch", func(t *testing.T) {
		snapshot := baseSnapshot(now)
		snapshot.ActiveEffect = baseEffect(EffectPrepared)
		store := newFakeStore(snapshot)
		coordinator := mustCoordinator(t, store, nil)
		request := baseDispatchRequest(now)
		first, err := coordinator.AdmitDispatch(context.Background(), request)
		if err != nil {
			t.Fatalf("first AdmitDispatch() error = %v", err)
		}
		replayed, err := coordinator.AdmitDispatch(context.Background(), request)
		if err != nil || replayed != first {
			t.Fatalf("dispatch replay while exact attempt is current = %#v, %v; want %#v", replayed, err, first)
		}
	})

	t.Run("confirmation and settlement", func(t *testing.T) {
		snapshot := baseSnapshot(now)
		snapshot.ActiveEffect = baseEffect(EffectDispatched)
		store := newFakeStore(snapshot)
		coordinator := mustCoordinator(t, store, &fakeLedger{record: committedRecord()})
		confirmationRequest := ConfirmationRequest{Authority: baseAuthority(now), Now: now, EffectID: effectID, InvocationID: invocationID, RequestDigest: digest(2), Service: ServiceExecutor, Operation: "run", DispatchAttempt: 1, ProviderRequestID: mustID(identity.Request, "R"), OperationKey: "lost-confirm", OperationDigest: digest(75)}
		confirmation, err := coordinator.ConfirmExternalCommit(context.Background(), confirmationRequest)
		if err != nil {
			t.Fatalf("first ConfirmExternalCommit() error = %v", err)
		}
		settlementRequest := SettlementRequest{Authority: baseAuthority(now), Now: now, EffectID: effectID, InvocationID: invocationID, RequestDigest: digest(2), DispatchAttempt: 1, ExternalCommitID: commitID, ResultRef: resultID, OperationKey: "lost-settle", SettlementDigest: digest(76)}
		settlement, err := coordinator.SettleEffect(context.Background(), settlementRequest)
		if err != nil {
			t.Fatalf("first SettleEffect() error = %v", err)
		}
		store.mu.Lock()
		store.snapshot.ActiveEffect = nil
		store.mu.Unlock()
		replayedConfirmation, confirmationErr := mustCoordinator(t, store, nil).ConfirmExternalCommit(context.Background(), confirmationRequest)
		replayedSettlement, settlementErr := coordinator.SettleEffect(context.Background(), settlementRequest)
		if confirmationErr != nil || replayedConfirmation != confirmation {
			t.Fatalf("confirmation replay = %#v, %v; want %#v", replayedConfirmation, confirmationErr, confirmation)
		}
		if settlementErr != nil || replayedSettlement != settlement {
			t.Fatalf("settlement replay = %#v, %v; want %#v", replayedSettlement, settlementErr, settlement)
		}
	})
}

func TestReplayFirstReceiptsRejectForeignAuthorityRouteWithoutStateOrLedgerUse(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_900_000_410, 0).UTC()
	for _, route := range []struct {
		name   string
		mutate func(*ValidatedTurnFence)
	}{
		{name: "tenant", mutate: func(authority *ValidatedTurnFence) {
			authority.TenantID = mustID(identity.Tenant, "foreign-tenant")
		}},
		{name: "workspace", mutate: func(authority *ValidatedTurnFence) {
			authority.WorkspaceID = mustID(identity.Workspace, "foreign-workspace")
		}},
	} {
		t.Run(route.name+"/confirmation", func(t *testing.T) {
			snapshot := baseSnapshot(now)
			snapshot.ActiveEffect = baseEffect(EffectDispatched)
			store := newFakeStore(snapshot)
			ledger := &fakeLedger{record: committedRecord()}
			coordinator := mustCoordinator(t, store, ledger)
			request := ConfirmationRequest{
				Authority: baseAuthority(now), Now: now, EffectID: effectID, InvocationID: invocationID,
				RequestDigest: digest(2), Service: ServiceExecutor, Operation: "run", DispatchAttempt: 1,
				ProviderRequestID: mustID(identity.Request, "R"), OperationKey: "route-confirm-" + route.name, OperationDigest: digest(123),
			}
			if _, err := coordinator.ConfirmExternalCommit(context.Background(), request); err != nil {
				t.Fatalf("first ConfirmExternalCommit() error = %v", err)
			}
			store.mu.Lock()
			reads := store.readTurnCalls
			transitions := store.markExternalTransitions
			store.mu.Unlock()
			ledger.mu.Lock()
			lookups := len(ledger.lookups)
			ledger.mu.Unlock()
			route.mutate(&request.Authority)
			if receipt, err := coordinator.ConfirmExternalCommit(context.Background(), request); !errors.Is(err, ErrFenceMismatch) || receipt != (ConfirmationReceipt{}) {
				t.Fatalf("foreign-route confirmation replay = %#v, %v; want ErrFenceMismatch", receipt, err)
			}
			store.mu.Lock()
			if store.readTurnCalls != reads || store.markExternalTransitions != transitions {
				t.Fatalf("confirmation replay side effects: reads=%d transitions=%d, want %d/%d", store.readTurnCalls, store.markExternalTransitions, reads, transitions)
			}
			store.mu.Unlock()
			ledger.mu.Lock()
			if len(ledger.lookups) != lookups {
				t.Fatalf("confirmation replay ledger lookups = %d, want %d", len(ledger.lookups), lookups)
			}
			ledger.mu.Unlock()
		})

		t.Run(route.name+"/settlement", func(t *testing.T) {
			snapshot := baseSnapshot(now)
			snapshot.ActiveEffect = baseEffect(EffectExternallyCommitted)
			store := newFakeStore(snapshot)
			coordinator := mustCoordinator(t, store, nil)
			request := SettlementRequest{
				Authority: baseAuthority(now), Now: now, EffectID: effectID, InvocationID: invocationID,
				RequestDigest: digest(2), DispatchAttempt: 1, ExternalCommitID: commitID, ResultRef: resultID,
				OperationKey: "route-settle-" + route.name, SettlementDigest: digest(124),
			}
			if _, err := coordinator.SettleEffect(context.Background(), request); err != nil {
				t.Fatalf("first SettleEffect() error = %v", err)
			}
			store.mu.Lock()
			reads := store.readTurnCalls
			settlements := len(store.settlements)
			store.mu.Unlock()
			route.mutate(&request.Authority)
			if receipt, err := coordinator.SettleEffect(context.Background(), request); !errors.Is(err, ErrFenceMismatch) || receipt != (SettlementReceipt{}) {
				t.Fatalf("foreign-route settlement replay = %#v, %v; want ErrFenceMismatch", receipt, err)
			}
			store.mu.Lock()
			if store.readTurnCalls != reads || len(store.settlements) != settlements {
				t.Fatalf("settlement replay side effects: reads=%d settlements=%d, want %d/%d", store.readTurnCalls, len(store.settlements), reads, settlements)
			}
			store.mu.Unlock()
		})

		for _, recovery := range []struct {
			name             string
			policy           ReplayPolicy
			want             RecoveryAction
			settleTransition bool
		}{
			{name: "recovery-settlement", policy: ReplayNever, want: RecoverySettleInterrupted, settleTransition: true},
			{name: "recovery-block", policy: ReplayConfirm, want: RecoveryNeedsConfirmation},
		} {
			t.Run(route.name+"/"+recovery.name, func(t *testing.T) {
				snapshot := baseSnapshot(now)
				effect := baseEffect(EffectDispatched)
				effect.ReplayPolicy = recovery.policy
				snapshot.ActiveEffect = effect
				store := newFakeStore(snapshot)
				ledger := &fakeLedger{record: routedRecord(LedgerUnknown)}
				coordinator := mustCoordinator(t, store, ledger)
				request := baseRecoveryRequest(now, "route-"+recovery.name+"-"+route.name)
				first, err := coordinator.RecoverEffect(context.Background(), request)
				if err != nil || first.Action != recovery.want {
					t.Fatalf("first RecoverEffect() = %#v, %v; want %q", first, err, recovery.want)
				}
				store.mu.Lock()
				reads := store.readTurnCalls
				settlements := store.recoverySettlementTransitions
				blocks := store.blockTransitions
				store.mu.Unlock()
				ledger.mu.Lock()
				lookups := len(ledger.lookups)
				ledger.mu.Unlock()
				route.mutate(&request.Authority)
				if decision, err := coordinator.RecoverEffect(context.Background(), request); !errors.Is(err, ErrFenceMismatch) || decision != (RecoveryDecision{}) {
					t.Fatalf("foreign-route recovery replay = %#v, %v; want ErrFenceMismatch", decision, err)
				}
				store.mu.Lock()
				if store.readTurnCalls != reads || store.recoverySettlementTransitions != settlements || store.blockTransitions != blocks {
					t.Fatalf("recovery replay side effects: reads=%d settlements=%d blocks=%d, want %d/%d/%d", store.readTurnCalls, store.recoverySettlementTransitions, store.blockTransitions, reads, settlements, blocks)
				}
				store.mu.Unlock()
				ledger.mu.Lock()
				if len(ledger.lookups) != lookups {
					t.Fatalf("recovery replay ledger lookups = %d, want %d", len(ledger.lookups), lookups)
				}
				ledger.mu.Unlock()
				if recovery.settleTransition && settlements == 0 {
					t.Fatal("expected durable recovery settlement before replay")
				}
			})
		}
	}
}

func TestConfirmationReplayRejectsForeignEffectDomain(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_900_000_425, 0).UTC()
	for _, mismatch := range []struct {
		name   string
		mutate func(*ConfirmationReceipt)
	}{
		{name: "service", mutate: func(receipt *ConfirmationReceipt) { receipt.Service = ServiceWorkspace }},
		{name: "operation", mutate: func(receipt *ConfirmationReceipt) { receipt.Operation = "write" }},
		{name: "provider request", mutate: func(receipt *ConfirmationReceipt) {
			receipt.ProviderRequestID = mustID(identity.Request, "wrong-provider")
		}},
		{name: "operation digest", mutate: func(receipt *ConfirmationReceipt) { receipt.OperationDigest = digest(78) }},
		{name: "result kind", mutate: func(receipt *ConfirmationReceipt) { receipt.ResultRef = sessionID }},
	} {
		t.Run(mismatch.name, func(t *testing.T) {
			store := newFakeStore(baseSnapshot(now))
			receipt := ConfirmationReceipt{
				EffectKey: EffectKey{SessionID: sessionID, TurnID: turnID, EffectID: effectID, InvocationID: invocationID, RequestDigest: digest(2)},
				Service:   ServiceExecutor, Operation: "run", DispatchAttempt: 1, ProviderRequestID: mustID(identity.Request, "R"), ExternalCommitID: commitID, ResultRef: resultID, OperationDigest: digest(77), EventSequence: 8, Durable: true,
			}
			mismatch.mutate(&receipt)
			store.confirmations["foreign-confirmation"] = receipt
			store.confirmationDigests["foreign-confirmation"] = digest(77)
			ledger := &fakeLedger{record: committedRecord()}
			_, err := mustCoordinator(t, store, ledger).ConfirmExternalCommit(context.Background(), ConfirmationRequest{
				Authority: baseAuthority(now), Now: now, EffectID: effectID, InvocationID: invocationID, RequestDigest: digest(2),
				Service: ServiceExecutor, Operation: "run", DispatchAttempt: 1, ProviderRequestID: mustID(identity.Request, "R"), OperationKey: "foreign-confirmation", OperationDigest: digest(77),
			})
			if !errors.Is(err, ErrFenceMismatch) {
				t.Fatalf("ConfirmExternalCommit() error = %v, want %v", err, ErrFenceMismatch)
			}
			ledger.mu.Lock()
			ledgerLookups := len(ledger.lookups)
			ledger.mu.Unlock()
			if ledgerLookups != 0 {
				t.Fatalf("ledger lookups = %d, want 0", ledgerLookups)
			}
			store.mu.Lock()
			transitions := store.markExternalTransitions
			store.mu.Unlock()
			if transitions != 0 {
				t.Fatalf("external commit transitions = %d, want 0", transitions)
			}
		})
	}
}

func TestConfirmationReplayRejectsZeroDispatchAttempt(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_900_000_426, 0).UTC()
	store := newFakeStore(baseSnapshot(now))
	store.confirmations["zero-attempt-confirmation"] = ConfirmationReceipt{
		EffectKey: EffectKey{SessionID: sessionID, TurnID: turnID, EffectID: effectID, InvocationID: invocationID, RequestDigest: digest(2)},
		Service:   ServiceExecutor, Operation: "run", ProviderRequestID: mustID(identity.Request, "R"), ExternalCommitID: commitID, ResultRef: resultID, OperationDigest: digest(79), EventSequence: 8, Durable: true,
	}
	store.confirmationDigests["zero-attempt-confirmation"] = digest(79)
	_, err := mustCoordinator(t, store, &fakeLedger{record: committedRecord()}).ConfirmExternalCommit(context.Background(), ConfirmationRequest{
		Authority: baseAuthority(now), Now: now, EffectID: effectID, InvocationID: invocationID, RequestDigest: digest(2),
		Service: ServiceExecutor, Operation: "run", ProviderRequestID: mustID(identity.Request, "R"), OperationKey: "zero-attempt-confirmation", OperationDigest: digest(79),
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("ConfirmExternalCommit() error = %v, want %v", err, ErrInvalidRequest)
	}
}

func TestConcurrentConfirmationDigestConflictTransitionsOnce(t *testing.T) {
	t.Parallel()
	const callers = 64
	now := time.Unix(1_900_000_427, 0).UTC()
	snapshot := baseSnapshot(now)
	snapshot.ActiveEffect = baseEffect(EffectDispatched)
	store := newFakeStore(snapshot)
	coordinator := mustCoordinator(t, store, &fakeLedger{record: committedRecord()})
	digests := [2]Digest{digest(80), digest(81)}
	type outcome struct {
		digest  Digest
		receipt ConfirmationReceipt
		err     error
	}
	outcomes := make(chan outcome, callers)
	var wait sync.WaitGroup
	for index := 0; index < callers; index++ {
		operationDigest := digests[index%len(digests)]
		wait.Add(1)
		go func() {
			defer wait.Done()
			receipt, err := coordinator.ConfirmExternalCommit(context.Background(), ConfirmationRequest{
				Authority: baseAuthority(now), Now: now, EffectID: effectID, InvocationID: invocationID, RequestDigest: digest(2),
				Service: ServiceExecutor, Operation: "run", DispatchAttempt: 1, ProviderRequestID: mustID(identity.Request, "R"), OperationKey: "concurrent-confirmation", OperationDigest: operationDigest,
			})
			outcomes <- outcome{digest: operationDigest, receipt: receipt, err: err}
		}()
	}
	wait.Wait()
	close(outcomes)

	var winningDigest Digest
	successes := 0
	conflicts := 0
	for result := range outcomes {
		if result.err == nil {
			successes++
			if result.receipt.OperationDigest != result.digest {
				t.Errorf("successful receipt digest = %x, want %x", result.receipt.OperationDigest, result.digest)
			}
			if winningDigest == (Digest{}) {
				winningDigest = result.digest
			} else if winningDigest != result.digest {
				t.Errorf("multiple winning digests: %x and %x", winningDigest, result.digest)
			}
			continue
		}
		if errors.Is(result.err, ErrIdempotencyConflict) {
			conflicts++
			continue
		}
		t.Errorf("unexpected confirmation error: %v", result.err)
	}
	if successes != callers/2 || conflicts != callers/2 {
		t.Fatalf("confirmation outcomes: success=%d conflict=%d, want %d each", successes, conflicts, callers/2)
	}
	store.mu.Lock()
	transitions := store.markExternalTransitions
	store.mu.Unlock()
	if transitions != 1 {
		t.Fatalf("external commit transitions = %d, want 1", transitions)
	}
}

func TestDispatchCapabilityReplayRejectsStateProgressAbortAndGenerationRotation(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_900_000_450, 0).UTC()

	for _, test := range []struct {
		name   string
		mutate func(*TurnSnapshot)
	}{
		{name: "externally committed", mutate: func(snapshot *TurnSnapshot) {
			snapshot.ActiveEffect.State = EffectExternallyCommitted
			snapshot.ActiveEffect.ExternalCommitID = commitID
			snapshot.ActiveEffect.ResultRef = resultID
		}},
		{name: "settled", mutate: func(snapshot *TurnSnapshot) {
			snapshot.ActiveEffect.State = EffectSettled
			snapshot.ActiveEffect.Settlement = &v1.EffectRecord{State: v1.EffectState_EFFECT_STATE_SETTLED, DispatchAttempt: snapshot.ActiveEffect.DispatchAttempt}
		}},
		{name: "effect cleared", mutate: func(snapshot *TurnSnapshot) {
			snapshot.ActiveEffect = nil
		}},
		{name: "abort requested", mutate: func(snapshot *TurnSnapshot) {
			snapshot.AbortRequested = true
		}},
		{name: "generation rotated", mutate: func(snapshot *TurnSnapshot) {
			snapshot.Generations.Authorization++
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := baseSnapshot(now)
			snapshot.ActiveEffect = baseEffect(EffectPrepared)
			store := newFakeStore(snapshot)
			coordinator := mustCoordinator(t, store, nil)
			request := baseDispatchRequest(now)
			if _, err := coordinator.AdmitDispatch(context.Background(), request); err != nil {
				t.Fatalf("first AdmitDispatch() error = %v", err)
			}
			store.mu.Lock()
			test.mutate(&store.snapshot)
			store.mu.Unlock()

			permit, err := coordinator.AdmitDispatch(context.Background(), request)
			if err == nil || permit != (DispatchPermit{}) {
				t.Fatalf("stale dispatch capability replay = %#v, %v; want rejection", permit, err)
			}
			if store.markDispatchTransitions != 1 {
				t.Fatalf("dispatch transitions = %d, want 1", store.markDispatchTransitions)
			}
		})
	}
}

func TestRecoveryDispatchCapabilityReplayRequiresCurrentExactAttempt(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_900_000_475, 0).UTC()
	snapshot := baseSnapshot(now)
	snapshot.ActiveEffect = baseEffect(EffectDispatched)
	store := newFakeStore(snapshot)
	store.loseDispatchResponseOnce = true
	coordinator := mustCoordinator(t, store, &fakeLedger{record: routedRecord(LedgerAbsent)})
	request := baseRecoveryRequest(now, "lost-recovery-capability-progressed")
	if _, err := coordinator.RecoverEffect(context.Background(), request); err == nil {
		t.Fatal("first RecoverEffect() unexpectedly observed durable dispatch response")
	}
	store.mu.Lock()
	store.snapshot.ActiveEffect.State = EffectExternallyCommitted
	store.snapshot.ActiveEffect.ExternalCommitID = commitID
	store.snapshot.ActiveEffect.ResultRef = resultID
	store.mu.Unlock()

	decision, err := coordinator.RecoverEffect(context.Background(), request)
	if err == nil || decision.DispatchPermit != nil {
		t.Fatalf("stale recovery capability replay = %#v, %v; want rejection", decision, err)
	}
	if store.markDispatchTransitions != 1 {
		t.Fatalf("dispatch transitions = %d, want 1", store.markDispatchTransitions)
	}
}

func TestRecoveryRejectsMismatchedInflightAndFailedLedgerProofs(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_900_000_480, 0).UTC()

	for _, status := range []LedgerStatus{LedgerInflight, LedgerFailed} {
		for _, mismatch := range []struct {
			name   string
			mutate func(*LedgerRecord)
		}{
			{name: "effect", mutate: func(record *LedgerRecord) { record.EffectID = mustID(identity.Effect, "wrong-effect") }},
			{name: "invocation", mutate: func(record *LedgerRecord) { record.InvocationID = mustID(identity.Invocation, "wrong-invocation") }},
			{name: "digest", mutate: func(record *LedgerRecord) { record.RequestDigest = digest(117) }},
			{name: "tenant", mutate: func(record *LedgerRecord) { record.TenantID = mustID(identity.Tenant, "wrong-tenant") }},
			{name: "workspace", mutate: func(record *LedgerRecord) { record.WorkspaceID = mustID(identity.Workspace, "wrong-workspace") }},
			{name: "service", mutate: func(record *LedgerRecord) { record.Service = ServiceWorkspace }},
			{name: "operation", mutate: func(record *LedgerRecord) { record.Operation = "write" }},
			{name: "attempt", mutate: func(record *LedgerRecord) { record.DispatchAttempt++ }},
			{name: "provider request", mutate: func(record *LedgerRecord) { record.ProviderRequestID = mustID(identity.Request, "wrong-provider") }},
			{name: "provider route", mutate: func(record *LedgerRecord) { record.ProviderRouteDigest = digest(158) }},
		} {
			t.Run(string(status)+"/"+mismatch.name, func(t *testing.T) {
				snapshot := baseSnapshot(now)
				snapshot.ActiveEffect = baseEffect(EffectDispatched)
				store := newFakeStore(snapshot)
				record := LedgerRecord{
					Status: status, TenantID: tenantID, WorkspaceID: workspaceID,
					EffectID: effectID, InvocationID: invocationID,
					RequestDigest: digest(2), Service: ServiceExecutor, Operation: "run", DispatchAttempt: 1,
					ProviderRequestID: mustID(identity.Request, "R"), ProviderRouteDigest: digest(152),
				}
				mismatch.mutate(&record)
				decision, err := mustCoordinator(t, store, &fakeLedger{record: record}).RecoverEffect(
					context.Background(),
					baseRecoveryRequest(now, "mismatched-ledger-"+string(status)+"-"+mismatch.name),
				)
				if !errors.Is(err, ErrLedgerMismatch) || decision != (RecoveryDecision{}) {
					t.Fatalf("RecoverEffect() = %#v, %v; want ErrLedgerMismatch", decision, err)
				}
				if store.recoverySettlementTransitions != 0 {
					t.Fatalf("recovery settlements = %d, want 0", store.recoverySettlementTransitions)
				}
			})
		}
	}
}

func TestRecoveryRejectsMismatchedAbsentAndUnknownLedgerRoutes(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_900_000_485, 0).UTC()

	for _, status := range []LedgerStatus{LedgerAbsent, LedgerUnknown} {
		for _, mismatch := range []struct {
			name   string
			mutate func(*LedgerRecord)
		}{
			{name: "effect", mutate: func(record *LedgerRecord) { record.EffectID = mustID(identity.Effect, "wrong-effect") }},
			{name: "invocation", mutate: func(record *LedgerRecord) { record.InvocationID = mustID(identity.Invocation, "wrong-invocation") }},
			{name: "digest", mutate: func(record *LedgerRecord) { record.RequestDigest = digest(160) }},
			{name: "tenant", mutate: func(record *LedgerRecord) { record.TenantID = mustID(identity.Tenant, "wrong-tenant") }},
			{name: "workspace", mutate: func(record *LedgerRecord) { record.WorkspaceID = mustID(identity.Workspace, "wrong-workspace") }},
			{name: "service", mutate: func(record *LedgerRecord) { record.Service = ServiceWorkspace }},
			{name: "operation", mutate: func(record *LedgerRecord) { record.Operation = "write" }},
			{name: "attempt", mutate: func(record *LedgerRecord) { record.DispatchAttempt++ }},
			{name: "provider request", mutate: func(record *LedgerRecord) { record.ProviderRequestID = mustID(identity.Request, "wrong-provider") }},
			{name: "provider route", mutate: func(record *LedgerRecord) { record.ProviderRouteDigest = digest(159) }},
		} {
			t.Run(string(status)+"/"+mismatch.name, func(t *testing.T) {
				snapshot := baseSnapshot(now)
				snapshot.ActiveEffect = baseEffect(EffectDispatched)
				store := newFakeStore(snapshot)
				record := routedRecord(status)
				mismatch.mutate(&record)

				decision, err := mustCoordinator(t, store, &fakeLedger{record: record}).RecoverEffect(
					context.Background(),
					baseRecoveryRequest(now, "mismatched-route-"+string(status)+"-"+mismatch.name),
				)
				if !errors.Is(err, ErrLedgerMismatch) || decision != (RecoveryDecision{}) {
					t.Fatalf("RecoverEffect() = %#v, %v; want ErrLedgerMismatch", decision, err)
				}
				if store.prepareRetryTransitions != 0 || store.markDispatchTransitions != 0 ||
					store.markExternalTransitions != 0 || store.recoverySettlementTransitions != 0 ||
					store.blockTransitions != 0 {
					t.Fatalf(
						"durable transitions = prepare:%d dispatch:%d external:%d settle:%d block:%d, want all zero",
						store.prepareRetryTransitions,
						store.markDispatchTransitions,
						store.markExternalTransitions,
						store.recoverySettlementTransitions,
						store.blockTransitions,
					)
				}
			})
		}
	}
}

func TestEngineBoundaryRejectsAmbiguousDualRepresentation(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_900_000_490, 0).UTC()
	store := newFakeStore(baseSnapshot(now))
	coordinator := mustCoordinator(t, store, nil)
	permit := acquirePermit(t, coordinator, now, "ambiguous-boundary-permit")
	message := &v1.EngineStepBoundary{
		Checkpoint: &v1.AgentCheckpoint{},
		Boundary:   &v1.EngineStepBoundary_CheckpointOnly{CheckpointOnly: &v1.Empty{}},
	}
	_, err := coordinator.CommitEngineStep(context.Background(), EngineStepCommit{
		Permit: permit, Now: now, OperationKey: "ambiguous-boundary", RequestDigest: digest(118),
		Boundary: EngineBoundary{Kind: BoundaryCheckpoint, Message: message, CheckpointDigest: digest(119)},
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("CommitEngineStep(ambiguous) error = %v, want ErrInvalidRequest", err)
	}
}

func TestRecoveryRejectsEveryInvalidEffectSnapshotShape(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_900_000_500, 0).UTC()
	tests := []struct {
		name   string
		mutate func(*EffectSnapshot)
	}{
		{name: "prepared with attempt", mutate: func(effect *EffectSnapshot) { effect.State = EffectPrepared; effect.DispatchAttempt = 1 }},
		{name: "prepared without durable permit", mutate: func(effect *EffectSnapshot) {
			effect.State = EffectPrepared
			effect.DispatchAttempt = 0
			effect.LastDispatch = nil
			effect.PreparationPermit = nil
		}},
		{name: "dispatched without attempt", mutate: func(effect *EffectSnapshot) {
			effect.State = EffectDispatched
			effect.DispatchAttempt = 0
			effect.LastDispatch = nil
		}},
		{name: "blocked non-confirm", mutate: func(effect *EffectSnapshot) { effect.State = EffectBlocked; effect.ReplayPolicy = ReplaySafe }},
		{name: "dispatched stale dispatch generations", mutate: func(effect *EffectSnapshot) { effect.LastDispatch.Generations.Placement++ }},
		{name: "external wrong commit kind", mutate: func(effect *EffectSnapshot) {
			effect.State = EffectExternallyCommitted
			effect.ExternalCommitID = sessionID
		}},
		{name: "settled without settlement", mutate: func(effect *EffectSnapshot) { effect.State = EffectSettled; effect.Settlement = nil }},
		{name: "settled with non-settled reinjection", mutate: func(effect *EffectSnapshot) {
			effect.State = EffectSettled
			effect.Settlement = &v1.EffectRecord{State: v1.EffectState_EFFECT_STATE_DISPATCHED}
		}},
		{name: "settled impossible attempt shape", mutate: func(effect *EffectSnapshot) {
			effect.State = EffectSettled
			effect.DispatchAttempt = 0
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := baseSnapshot(now)
			effect := baseEffect(EffectDispatched)
			test.mutate(effect)
			snapshot.ActiveEffect = effect
			coordinator := mustCoordinator(t, newFakeStore(snapshot), &fakeLedger{record: routedRecord(LedgerUnknown)})
			_, err := coordinator.RecoverEffect(context.Background(), RecoveryRequest{Authority: baseAuthority(now), Now: now, Deadline: now.Add(time.Minute), EffectID: effectID, InvocationID: invocationID, RequestDigest: digest(2), OperationKey: "shape-" + test.name, OperationDigest: digest(77)})
			if !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("RecoverEffect() error = %v, want %v", err, ErrInvalidRequest)
			}
		})
	}
}

func TestEveryDurableReceiptRejectsZeroEventSequence(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_900_000_600, 0).UTC()

	t.Run("engine", func(t *testing.T) {
		store := newFakeStore(baseSnapshot(now))
		store.zeroStepEvent = true
		coordinator := mustCoordinator(t, store, nil)
		permit := acquirePermit(t, coordinator, now, "zero-step-acquire")
		_, err := coordinator.CommitEngineStep(context.Background(), EngineStepCommit{Permit: permit, Now: now, OperationKey: "zero-step", RequestDigest: digest(78), Boundary: EngineBoundary{Kind: BoundaryCheckpoint, CheckpointDigest: digest(79)}})
		if !errors.Is(err, ErrFenceMismatch) {
			t.Fatalf("CommitEngineStep() error = %v, want %v", err, ErrFenceMismatch)
		}
	})

	t.Run("dispatch", func(t *testing.T) {
		snapshot := baseSnapshot(now)
		snapshot.ActiveEffect = baseEffect(EffectPrepared)
		store := newFakeStore(snapshot)
		store.zeroDispatchEvent = true
		_, err := mustCoordinator(t, store, nil).AdmitDispatch(context.Background(), baseDispatchRequest(now))
		if !errors.Is(err, ErrFenceMismatch) {
			t.Fatalf("AdmitDispatch() error = %v, want %v", err, ErrFenceMismatch)
		}
	})

	t.Run("confirmation", func(t *testing.T) {
		snapshot := baseSnapshot(now)
		snapshot.ActiveEffect = baseEffect(EffectDispatched)
		store := newFakeStore(snapshot)
		store.zeroConfirmationEvent = true
		_, err := mustCoordinator(t, store, &fakeLedger{record: committedRecord()}).ConfirmExternalCommit(context.Background(), ConfirmationRequest{Authority: baseAuthority(now), Now: now, EffectID: effectID, InvocationID: invocationID, RequestDigest: digest(2), Service: ServiceExecutor, Operation: "run", DispatchAttempt: 1, ProviderRequestID: mustID(identity.Request, "R"), OperationKey: "zero-confirm", OperationDigest: digest(80)})
		if !errors.Is(err, ErrFenceMismatch) {
			t.Fatalf("ConfirmExternalCommit() error = %v, want %v", err, ErrFenceMismatch)
		}
	})

	t.Run("settlement", func(t *testing.T) {
		snapshot := baseSnapshot(now)
		snapshot.ActiveEffect = baseEffect(EffectExternallyCommitted)
		store := newFakeStore(snapshot)
		store.zeroSettlementEvent = true
		_, err := mustCoordinator(t, store, nil).SettleEffect(context.Background(), SettlementRequest{Authority: baseAuthority(now), Now: now, EffectID: effectID, InvocationID: invocationID, RequestDigest: digest(2), DispatchAttempt: 1, ExternalCommitID: commitID, ResultRef: resultID, OperationKey: "zero-settle", SettlementDigest: digest(82)})
		if !errors.Is(err, ErrFenceMismatch) {
			t.Fatalf("SettleEffect() error = %v, want %v", err, ErrFenceMismatch)
		}
	})

	t.Run("block", func(t *testing.T) {
		snapshot := baseSnapshot(now)
		effect := baseEffect(EffectDispatched)
		effect.ReplayPolicy = ReplayConfirm
		snapshot.ActiveEffect = effect
		store := newFakeStore(snapshot)
		store.zeroBlockEvent = true
		_, err := mustCoordinator(t, store, &fakeLedger{record: routedRecord(LedgerUnknown)}).RecoverEffect(context.Background(), RecoveryRequest{Authority: baseAuthority(now), Now: now, Deadline: now.Add(time.Minute), EffectID: effectID, InvocationID: invocationID, RequestDigest: digest(2), OperationKey: "zero-block", OperationDigest: digest(83)})
		if !errors.Is(err, ErrFenceMismatch) {
			t.Fatalf("RecoverEffect() error = %v, want %v", err, ErrFenceMismatch)
		}
	})
}

func TestGenerationZeroIsAValidInitialProtoValue(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_900_000_700, 0).UTC()
	snapshot := baseSnapshot(now)
	snapshot.Generations = Generations{}
	fence := baseAuthority(now)
	fence.Generations = Generations{}
	store := newFakeStore(snapshot)
	_, err := mustCoordinator(t, store, nil).AcquireEngineStep(context.Background(), EngineStepRequest{Authority: fence, Now: now, Budget: EngineStepBudget{MaximumEvents: 1, MaximumEphemeralBytes: 1, MaximumWallClock: time.Second}, OperationKey: "generation-zero"})
	if err != nil {
		t.Fatalf("AcquireEngineStep() rejected proto-valid initial generation zero: %v", err)
	}
}

func TestEngineStepPermitCarriesOpaqueFullFenceAndDeadline(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_002_700, 0).UTC()
	store := newFakeStore(baseSnapshot(now))
	coordinator := mustCoordinator(t, store, nil)

	permit, err := coordinator.AcquireEngineStep(context.Background(), EngineStepRequest{
		Authority: baseAuthority(now), Now: now,
		Budget:       EngineStepBudget{MaximumEvents: 1, MaximumEphemeralBytes: 1024, MaximumWallClock: time.Minute},
		OperationKey: "opaque-engine-permit",
	})
	if err != nil {
		t.Fatalf("AcquireEngineStep() error = %v", err)
	}
	if permit.Opaque == "" || permit.TenantID != tenantID || permit.UserID != store.snapshot.UserID || !permit.Deadline.Equal(now.Add(time.Minute)) {
		t.Fatalf("incomplete engine permit = %#v", permit)
	}
}

func TestDurableMutationReceiptsBindStateAttemptAndOperation(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_002_800, 0).UTC()

	t.Run("confirmation effect domain", func(t *testing.T) {
		snapshot := baseSnapshot(now)
		snapshot.ActiveEffect = baseEffect(EffectDispatched)
		store := newFakeStore(snapshot)
		store.corruptExternalReceiptDomain = true
		_, err := mustCoordinator(t, store, &fakeLedger{record: committedRecord()}).ConfirmExternalCommit(context.Background(), ConfirmationRequest{
			Authority: baseAuthority(now), Now: now, EffectID: effectID, InvocationID: invocationID,
			RequestDigest: digest(2), Service: ServiceExecutor, Operation: "run", DispatchAttempt: 1, ProviderRequestID: mustID(identity.Request, "R"),
			OperationKey: "receipt-confirmation-domain", OperationDigest: digest(100),
		})
		if !errors.Is(err, ErrFenceMismatch) {
			t.Fatalf("ConfirmExternalCommit() error = %v, want %v", err, ErrFenceMismatch)
		}
	})

	t.Run("settlement", func(t *testing.T) {
		snapshot := baseSnapshot(now)
		snapshot.ActiveEffect = baseEffect(EffectExternallyCommitted)
		store := newFakeStore(snapshot)
		store.corruptSettlementIdentity = true
		_, err := mustCoordinator(t, store, nil).SettleEffect(context.Background(), SettlementRequest{
			Authority: baseAuthority(now), Now: now, EffectID: effectID, InvocationID: invocationID,
			RequestDigest: digest(2), DispatchAttempt: 1, ExternalCommitID: commitID, ResultRef: resultID,
			OperationKey: "receipt-settle-identity", SettlementDigest: digest(101),
		})
		if !errors.Is(err, ErrFenceMismatch) {
			t.Fatalf("SettleEffect() error = %v, want %v", err, ErrFenceMismatch)
		}
	})

	t.Run("block", func(t *testing.T) {
		snapshot := baseSnapshot(now)
		effect := baseEffect(EffectDispatched)
		effect.ReplayPolicy = ReplayConfirm
		snapshot.ActiveEffect = effect
		store := newFakeStore(snapshot)
		store.corruptBlockIdentity = true
		_, err := mustCoordinator(t, store, &fakeLedger{record: routedRecord(LedgerUnknown)}).RecoverEffect(context.Background(), baseRecoveryRequest(now, "receipt-block-identity"))
		if !errors.Is(err, ErrFenceMismatch) {
			t.Fatalf("RecoverEffect() error = %v, want %v", err, ErrFenceMismatch)
		}
	})

	t.Run("recovery settlement", func(t *testing.T) {
		snapshot := baseSnapshot(now)
		snapshot.ActiveEffect = baseEffect(EffectDispatched)
		store := newFakeStore(snapshot)
		store.corruptRecoverySettlementIdentity = true
		_, err := mustCoordinator(t, store, &fakeLedger{record: LedgerRecord{
			Status: LedgerFailed, TenantID: tenantID, WorkspaceID: workspaceID,
			EffectID: effectID, InvocationID: invocationID,
			RequestDigest: digest(2), Service: ServiceExecutor, Operation: "run", DispatchAttempt: 1,
			ProviderRequestID: mustID(identity.Request, "R"), ProviderRouteDigest: digest(152),
		}}).RecoverEffect(context.Background(), baseRecoveryRequest(now, "receipt-recovery-identity"))
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
		store.loseBlockResponseOnce = true
		coordinator := mustCoordinator(t, store, &fakeLedger{record: routedRecord(LedgerUnknown)})
		request := baseRecoveryRequest(now, "lost-recovery-block")
		if _, err := coordinator.RecoverEffect(context.Background(), request); err == nil {
			t.Fatal("first RecoverEffect() unexpectedly observed durable block response")
		}
		decision, err := coordinator.RecoverEffect(context.Background(), request)
		if err != nil || decision.Action != RecoveryNeedsConfirmation || decision.BlockReceipt == nil || store.blockTransitions != 1 {
			t.Fatalf("replayed block = %#v, %v; transitions=%d", decision, err, store.blockTransitions)
		}
	})
}

func TestExternalCommitAndSettlementFenceTheExactDispatchAttempt(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_900_000_800, 0).UTC()
	snapshot := baseSnapshot(now)
	effect := baseEffect(EffectDispatched)
	effect.DispatchAttempt = 2
	effect.LastDispatch.DispatchAttempt = 2
	snapshot.ActiveEffect = effect
	staleLedger := committedRecord()
	staleLedger.DispatchAttempt = 1
	coordinator := mustCoordinator(t, newFakeStore(snapshot), &fakeLedger{record: staleLedger})
	_, err := coordinator.ConfirmExternalCommit(context.Background(), ConfirmationRequest{Authority: baseAuthority(now), Now: now, EffectID: effectID, InvocationID: invocationID, RequestDigest: digest(2), Service: ServiceExecutor, Operation: "run", DispatchAttempt: 2, ProviderRequestID: mustID(identity.Request, "R"), OperationKey: "stale-ledger-attempt", OperationDigest: digest(84)})
	if !errors.Is(err, ErrLedgerMismatch) {
		t.Fatalf("ConfirmExternalCommit() error = %v, want %v", err, ErrLedgerMismatch)
	}

	providerMismatch := baseSnapshot(now)
	providerMismatch.ActiveEffect = baseEffect(EffectDispatched)
	wrongProviderLedger := committedRecord()
	wrongProviderLedger.ProviderRequestID = mustID(identity.Request, "wrong-provider")
	_, err = mustCoordinator(t, newFakeStore(providerMismatch), &fakeLedger{record: wrongProviderLedger}).ConfirmExternalCommit(context.Background(), ConfirmationRequest{Authority: baseAuthority(now), Now: now, EffectID: effectID, InvocationID: invocationID, RequestDigest: digest(2), Service: ServiceExecutor, Operation: "run", DispatchAttempt: 1, ProviderRequestID: mustID(identity.Request, "R"), OperationKey: "wrong-ledger-provider", OperationDigest: digest(102)})
	if !errors.Is(err, ErrLedgerMismatch) {
		t.Fatalf("provider-mismatched ConfirmExternalCommit() error = %v, want %v", err, ErrLedgerMismatch)
	}

	external := baseSnapshot(now)
	externalEffect := baseEffect(EffectExternallyCommitted)
	externalEffect.DispatchAttempt = 2
	externalEffect.LastDispatch.DispatchAttempt = 2
	external.ActiveEffect = externalEffect
	_, err = mustCoordinator(t, newFakeStore(external), nil).SettleEffect(context.Background(), SettlementRequest{Authority: baseAuthority(now), Now: now, EffectID: effectID, InvocationID: invocationID, RequestDigest: digest(2), DispatchAttempt: 1, ExternalCommitID: commitID, ResultRef: resultID, OperationKey: "stale-settlement-attempt", SettlementDigest: digest(85)})
	if !errors.Is(err, ErrFenceMismatch) {
		t.Fatalf("SettleEffect() error = %v, want %v", err, ErrFenceMismatch)
	}
}

func TestRecoveryRetryRequiresCurrentTrustedAdmissionDeadline(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_900_000_900, 0).UTC()
	snapshot := baseSnapshot(now)
	snapshot.ActiveEffect = baseEffect(EffectDispatched)
	request := baseRecoveryRequest(now, "expired-recovery-retry")
	request.Deadline = now

	_, err := mustCoordinator(t, newFakeStore(snapshot), &fakeLedger{record: routedRecord(LedgerAbsent)}).RecoverEffect(context.Background(), request)
	if !errors.Is(err, ErrAdmissionExpired) {
		t.Fatalf("RecoverEffect() error = %v, want %v", err, ErrAdmissionExpired)
	}
}

func TestEffectBoundaryRejectsMismatchedPreparationReceipt(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_900_001_000, 0).UTC()
	store := newFakeStore(baseSnapshot(now))
	store.corruptPreparedReceipt = true
	coordinator := mustCoordinator(t, store, nil)
	permit := acquirePermit(t, coordinator, now, "bad-prepared-acquire")

	_, err := coordinator.CommitEngineStep(context.Background(), EngineStepCommit{
		Permit: permit, Now: now, OperationKey: "bad-prepared-commit", RequestDigest: digest(103),
		Boundary: EngineBoundary{Kind: BoundaryEffectRequest, CheckpointDigest: digest(104), Effect: &EffectIntent{Service: ServiceExecutor, Operation: "run", ReplayPolicy: ReplaySafe, RequestDigest: digest(105)}},
	})
	if !errors.Is(err, ErrFenceMismatch) {
		t.Fatalf("CommitEngineStep() error = %v, want %v", err, ErrFenceMismatch)
	}
}

func TestSettlementAndBlockPreserveFullPublicErrorPayload(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_900_001_100, 0).UTC()
	publicError := &v1.PublicError{Code: v1.ErrorCode_ERROR_CODE_UNAVAILABLE, Reason: "provider_failed", Message: "redacted", Retryable: false, Metadata: map[string]string{"detail": "full-details"}}

	external := baseSnapshot(now)
	externalEffect := baseEffect(EffectExternallyCommitted)
	externalEffect.ResultRef = identity.ID{}
	external.ActiveEffect = externalEffect
	settleStore := newFakeStore(external)
	_, err := mustCoordinator(t, settleStore, nil).SettleEffect(context.Background(), SettlementRequest{
		Authority: baseAuthority(now), Now: now, EffectID: effectID, InvocationID: invocationID,
		RequestDigest: digest(2), DispatchAttempt: 1, ExternalCommitID: commitID, Error: publicError,
		OperationKey: "full-error-settlement", SettlementDigest: digest(106),
	})
	if err != nil {
		t.Fatalf("SettleEffect() error = %v", err)
	}
	if !proto.Equal(settleStore.lastSettlementError, publicError) {
		t.Fatalf("settlement error = %#v, want %#v", settleStore.lastSettlementError, publicError)
	}

	dispatched := baseSnapshot(now)
	dispatchedEffect := baseEffect(EffectDispatched)
	dispatchedEffect.ReplayPolicy = ReplayConfirm
	dispatched.ActiveEffect = dispatchedEffect
	blockStore := newFakeStore(dispatched)
	recovery := baseRecoveryRequest(now, "full-error-block")
	recovery.Reason = publicError
	_, err = mustCoordinator(t, blockStore, &fakeLedger{record: routedRecord(LedgerUnknown)}).RecoverEffect(context.Background(), recovery)
	if err != nil {
		t.Fatalf("RecoverEffect() error = %v", err)
	}
	if !proto.Equal(blockStore.lastBlockReason, publicError) {
		t.Fatalf("block reason = %#v, want %#v", blockStore.lastBlockReason, publicError)
	}
}

func TestRecoveryMutationResponseLossReplaysDurableReceipt(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_900_001_200, 0).UTC()

	t.Run("retry dispatch", func(t *testing.T) {
		snapshot := baseSnapshot(now)
		snapshot.ActiveEffect = baseEffect(EffectDispatched)
		store := newFakeStore(snapshot)
		store.loseDispatchResponseOnce = true
		coordinator := mustCoordinator(t, store, &fakeLedger{record: routedRecord(LedgerAbsent)})
		request := baseRecoveryRequest(now, "lost-recovery-dispatch")
		if _, err := coordinator.RecoverEffect(context.Background(), request); err == nil {
			t.Fatal("first RecoverEffect() unexpectedly observed durable dispatch response")
		}
		decision, err := coordinator.RecoverEffect(context.Background(), request)
		if err != nil || decision.Action != RecoveryReplay || decision.DispatchPermit == nil || decision.DispatchPermit.DispatchAttempt != 2 || store.markDispatchTransitions != 1 {
			t.Fatalf("replayed recovery dispatch = %#v, %v; transitions=%d", decision, err, store.markDispatchTransitions)
		}
	})

	t.Run("retry preparation", func(t *testing.T) {
		snapshot := baseSnapshot(now)
		snapshot.ActiveEffect = baseEffect(EffectDispatched)
		store := newFakeStore(snapshot)
		store.losePrepareRetryResponseOnce = true
		coordinator := mustCoordinator(t, store, &fakeLedger{record: routedRecord(LedgerAbsent)})
		request := baseRecoveryRequest(now, "lost-recovery-preparation")
		if _, err := coordinator.RecoverEffect(context.Background(), request); err == nil {
			t.Fatal("first RecoverEffect() unexpectedly observed durable preparation response")
		}
		decision, err := coordinator.RecoverEffect(context.Background(), request)
		if err != nil || decision.Action != RecoveryReplay || decision.DispatchPermit == nil || store.prepareRetryTransitions != 1 {
			t.Fatalf("replayed recovery preparation = %#v, %v; transitions=%d", decision, err, store.prepareRetryTransitions)
		}
	})

	t.Run("recovery settlement", func(t *testing.T) {
		snapshot := baseSnapshot(now)
		effect := baseEffect(EffectDispatched)
		effect.ReplayPolicy = ReplayNever
		snapshot.ActiveEffect = effect
		store := newFakeStore(snapshot)
		store.loseRecoverySettlementResponseOnce = true
		coordinator := mustCoordinator(t, store, &fakeLedger{record: routedRecord(LedgerUnknown)})
		request := baseRecoveryRequest(now, "lost-recovery-settlement")
		if _, err := coordinator.RecoverEffect(context.Background(), request); err == nil {
			t.Fatal("first RecoverEffect() unexpectedly observed durable settlement response")
		}
		decision, err := coordinator.RecoverEffect(context.Background(), request)
		if err != nil || decision.Action != RecoverySettleInterrupted || decision.SettlementReceipt == nil || store.recoverySettlementTransitions != 1 {
			t.Fatalf("replayed recovery settlement = %#v, %v; transitions=%d", decision, err, store.recoverySettlementTransitions)
		}
	})
}

func TestDispatchPermitBindsParentOperationAndOrdinal(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_900_001_300, 0).UTC()
	parentOperationID := mustID(identity.Operation, "parent-operation")
	snapshot := baseSnapshot(now)
	effect := baseEffect(EffectPrepared)
	effect.ParentOperationID = parentOperationID
	effect.Ordinal = 7
	effect.PreparationPermit.ParentOperationID = parentOperationID
	effect.PreparationPermit.Ordinal = 7
	snapshot.ActiveEffect = effect
	request := baseDispatchRequest(now)
	effect.PreparationPermit.Deadline = request.Deadline
	request.PreparationPermit = *effect.PreparationPermit

	permit, err := mustCoordinator(t, newFakeStore(snapshot), nil).AdmitDispatch(context.Background(), request)
	if err != nil {
		t.Fatalf("AdmitDispatch() error = %v", err)
	}
	if permit.ParentOperationID != parentOperationID || permit.Ordinal != 7 {
		t.Fatalf("dispatch permit parent/ordinal = %v/%d", permit.ParentOperationID, permit.Ordinal)
	}
}

func TestEngineCommitRequiresExplicitTrustedNow(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_900_001_400, 0).UTC()
	coordinator := mustCoordinator(t, newFakeStore(baseSnapshot(now)), nil)
	permit := acquirePermit(t, coordinator, now, "trusted-now-acquire")
	_, err := coordinator.CommitEngineStep(context.Background(), EngineStepCommit{Permit: permit, OperationKey: "trusted-now-commit", RequestDigest: digest(107), Boundary: EngineBoundary{Kind: BoundaryCheckpoint, CheckpointDigest: digest(108)}})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("CommitEngineStep() error = %v, want %v", err, ErrInvalidRequest)
	}
}

func TestOpaquePermitFormattingNeverLeaksAuthorityBytes(t *testing.T) {
	t.Parallel()
	secret := "permit-secret-\x00\xff"
	permit := OpaquePermit(secret)
	for _, formatted := range []string{fmt.Sprintf("%v", permit), fmt.Sprintf("%s", permit), fmt.Sprintf("%#v", permit)} {
		if strings.Contains(formatted, secret) || formatted != "opaque-permit<redacted>" {
			t.Fatalf("opaque permit formatting leaked or was not redacted: %q", formatted)
		}
	}
}
