package broker

import (
	"context"
	"errors"
	"testing"
	"time"
)

type interruptedRetryStore struct {
	*fakeStore
	interruptDispatch bool
}

func (store *interruptedRetryStore) MarkDispatched(ctx context.Context, command MarkDispatchedCommand) (DispatchPermit, error) {
	if store.interruptDispatch {
		store.interruptDispatch = false
		return DispatchPermit{}, errors.New("process stopped between retry preparation and dispatch")
	}
	return store.fakeStore.MarkDispatched(ctx, command)
}

func TestRecoveryRetryPreparationResumesAfterRestart(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0).UTC()
	for _, policy := range []ReplayPolicy{ReplaySafe, ReplayIdempotencyKey, ReplayConfirm} {
		for _, losePreparationReply := range []bool{false, true} {
			name := string(policy) + map[bool]string{false: "/before dispatch", true: "/lost preparation reply"}[losePreparationReply]
			t.Run(name, func(t *testing.T) {
				snapshot := baseSnapshot(now)
				snapshot.ActiveEffect = baseEffect(EffectDispatched)
				snapshot.ActiveEffect.ReplayPolicy = policy
				if policy == ReplayConfirm {
					snapshot.ActiveEffect.State = EffectBlocked
				}
				store := &interruptedRetryStore{fakeStore: newFakeStore(snapshot), interruptDispatch: !losePreparationReply}
				store.losePrepareRetryResponseOnce = losePreparationReply
				ledger := &fakeLedger{record: routedRecord(LedgerAbsent)}
				request := baseRecoveryRequest(now, "restart-retry")
				request.UserConfirmed = policy == ReplayConfirm
				if _, err := mustCoordinator(t, store, ledger).RecoverEffect(context.Background(), request); err == nil {
					t.Fatal("first recovery unexpectedly completed")
				}
				prepared, found := store.preparations[request.OperationKey+":prepare"]
				if !found || prepared.digest != request.OperationDigest || prepared.permit.EventSequence != snapshot.EventSequence+1 || store.prepareRetryTransitions != 1 || store.markDispatchTransitions != 0 {
					t.Fatalf("unexpected reservation after interruption: %#v, prepare=%d dispatch=%d", prepared, store.prepareRetryTransitions, store.markDispatchTransitions)
				}
				// Recreate the coordinator: it can only reread the advanced durable
				// snapshot and replay the original :prepare operation receipt.
				request.Now = now.Add(time.Millisecond)
				decision, err := mustCoordinator(t, store, ledger).RecoverEffect(context.Background(), request)
				if err != nil || decision.Action != RecoveryReplay || decision.PreparationPermit == nil || decision.DispatchPermit == nil {
					t.Fatalf("resumed recovery = %#v, %v", decision, err)
				}
				if decision.PreparationPermit.Opaque != prepared.permit.Opaque || decision.DispatchPermit.DispatchAttempt != 2 ||
					decision.DispatchPermit.EventSequence != prepared.permit.EventSequence+1 || store.prepareRetryTransitions != 1 || store.markDispatchTransitions != 1 {
					t.Fatalf("resumed recovery replaced the reservation or repeated a transition: %#v", decision)
				}
				if dispatch, found := store.dispatches[request.OperationKey]; !found || dispatch.digest != request.OperationDigest || dispatch.permit.Opaque != decision.DispatchPermit.Opaque {
					t.Fatalf("dispatch did not retain the recovery operation identity: %#v", dispatch)
				}
			})
		}
	}
}

func TestRecoveryRetryRejectsSupersededReservation(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0).UTC()
	for _, policy := range []ReplayPolicy{ReplaySafe, ReplayConfirm} {
		t.Run(string(policy), func(t *testing.T) {
			snapshot := baseSnapshot(now)
			snapshot.ActiveEffect = baseEffect(EffectDispatched)
			snapshot.ActiveEffect.ReplayPolicy = policy
			if policy == ReplayConfirm {
				snapshot.ActiveEffect.State = EffectBlocked
			}
			store := newFakeStore(snapshot)
			store.losePrepareRetryResponseOnce = true
			request := baseRecoveryRequest(now, "superseded-retry")
			request.UserConfirmed = policy == ReplayConfirm
			ledger := &fakeLedger{record: routedRecord(LedgerAbsent)}
			if _, err := mustCoordinator(t, store, ledger).RecoverEffect(context.Background(), request); err == nil {
				t.Fatal("expected preparation response loss")
			}
			store.eventSequence++
			store.snapshot.EventSequence = store.eventSequence
			if _, err := mustCoordinator(t, store, ledger).RecoverEffect(context.Background(), request); !errors.Is(err, ErrFenceMismatch) {
				t.Fatalf("superseded reservation error = %v, want %v", err, ErrFenceMismatch)
			}
			if store.markDispatchTransitions != 0 {
				t.Fatal("superseded reservation authorized a dispatch")
			}
		})
	}
}
