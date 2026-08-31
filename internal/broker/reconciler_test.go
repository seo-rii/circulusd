package broker

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/identity"
	"google.golang.org/protobuf/proto"
)

func TestEffectReconcilerSettlesOnlyAfterAuthoritativeRecovery(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_010_000, 0).UTC()
	snapshot := baseSnapshot(now)
	snapshot.ActiveEffect = baseEffect(EffectDispatched)
	store := newFakeStore(snapshot)
	ledger := &fakeLedger{record: committedRecord()}
	reconciler := mustEffectReconciler(t, mustCoordinator(t, store, ledger))
	request := baseEffectReconcileRequest(now, "recover-terminal", "settle-terminal")

	decision, err := reconciler.Reconcile(context.Background(), request)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if decision.Action != RecoverySettleOnly || decision.SettlementReceipt == nil {
		t.Fatalf("Reconcile() = %#v, want settle-only receipt", decision)
	}
	receipt := decision.SettlementReceipt
	if receipt.DispatchAttempt != request.DispatchAttempt || receipt.ExternalCommitID != request.ExternalCommitID || receipt.ResultRef != request.ResultRef || receipt.OperationDigest != request.SettlementDigest {
		t.Fatalf("settlement receipt = %#v, want exact recovered terminal and caller settlement digest", receipt)
	}
	ledger.mu.Lock()
	lookupCount := len(ledger.lookups)
	ledger.mu.Unlock()
	if lookupCount != 1 {
		t.Fatalf("ledger lookups = %d, want exactly one recovery lookup", lookupCount)
	}
	if store.readTurnCalls != 2 {
		t.Fatalf("turn reads = %d, want one recovery read and one settlement read", store.readTurnCalls)
	}
	if store.markExternalTransitions != 1 || len(store.settlements) != 1 {
		t.Fatalf("external transitions = %d, settlements = %d; want one each", store.markExternalTransitions, len(store.settlements))
	}
	if _, ok := store.settlements[request.SettlementOperationKey]; !ok {
		t.Fatalf("settlement operation %q was not persisted", request.SettlementOperationKey)
	}
}

func TestEffectReconcilerExactReplayReturnsOriginalSettlement(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_010_100, 0).UTC()
	snapshot := baseSnapshot(now)
	snapshot.ActiveEffect = baseEffect(EffectExternallyCommitted)
	store := newFakeStore(snapshot)
	reconciler := mustEffectReconciler(t, mustCoordinator(t, store, nil))
	request := baseEffectReconcileRequest(now, "recover-replay", "settle-replay")

	first, err := reconciler.Reconcile(context.Background(), request)
	if err != nil {
		t.Fatalf("first Reconcile() error = %v", err)
	}
	eventSequence := store.eventSequence
	second, err := reconciler.Reconcile(context.Background(), request)
	if err != nil {
		t.Fatalf("replayed Reconcile() error = %v", err)
	}
	if first.Action != RecoverySettleOnly || second.Action != RecoveryNone {
		t.Fatalf("actions = %q then %q, want settle-only then none", first.Action, second.Action)
	}
	if first.SettlementReceipt == nil || second.SettlementReceipt == nil || !reflect.DeepEqual(*first.SettlementReceipt, *second.SettlementReceipt) {
		t.Fatalf("receipts = %#v then %#v, want exact original receipt", first.SettlementReceipt, second.SettlementReceipt)
	}
	if store.eventSequence != eventSequence || len(store.settlements) != 1 {
		t.Fatalf("replay mutated state: event sequence = %d (want %d), settlements = %d", store.eventSequence, eventSequence, len(store.settlements))
	}
}

func TestEffectReconcilerSettlesTerminalError(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_010_200, 0).UTC()
	snapshot := baseSnapshot(now)
	snapshot.ActiveEffect = baseEffect(EffectExternallyCommitted)
	snapshot.ActiveEffect.ResultRef = identity.ID{}
	store := newFakeStore(snapshot)
	reconciler := mustEffectReconciler(t, mustCoordinator(t, store, nil))
	request := baseEffectReconcileRequest(now, "recover-error", "settle-error")
	request.ResultRef = identity.ID{}
	request.TerminalError = &v1.PublicError{Code: v1.ErrorCode_ERROR_CODE_UNAVAILABLE, Reason: "provider_failed", Message: "provider failed"}

	decision, err := reconciler.Reconcile(context.Background(), request)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if decision.SettlementReceipt == nil || decision.SettlementReceipt.ResultRef != (identity.ID{}) || !proto.Equal(decision.SettlementReceipt.Error, request.TerminalError) {
		t.Fatalf("settlement receipt = %#v, want exact terminal error", decision.SettlementReceipt)
	}
}

func TestEffectReconcilerReturnsAlreadyEnactedRecoveryFailure(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_010_300, 0).UTC()
	snapshot := baseSnapshot(now)
	snapshot.ActiveEffect = baseEffect(EffectDispatched)
	store := newFakeStore(snapshot)
	ledger := &fakeLedger{record: routedRecord(LedgerFailed)}
	reconciler := mustEffectReconciler(t, mustCoordinator(t, store, ledger))
	request := baseEffectReconcileRequest(now, "recover-failed", "settle-must-not-run")
	request.Recovery.Reason = &v1.PublicError{Code: v1.ErrorCode_ERROR_CODE_UNAVAILABLE, Reason: "provider_failed", Message: "provider failed"}

	decision, err := reconciler.Reconcile(context.Background(), request)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if decision.Action != RecoverySettleFailed || decision.SettlementReceipt == nil || decision.SettlementReceipt.RecoveryKind != RecoverySettlementFailed {
		t.Fatalf("Reconcile() = %#v, want enacted recovery failure", decision)
	}
	if store.recoverySettlementTransitions != 1 || len(store.settlements) != 0 {
		t.Fatalf("recovery settlements = %d, terminal settlements = %d; want 1 and 0", store.recoverySettlementTransitions, len(store.settlements))
	}
}

func TestEffectReconcilerLeavesOtherRecoveryActionsUnchanged(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_010_400, 0).UTC()
	tests := []struct {
		name     string
		snapshot TurnSnapshot
		ledger   InvocationLedger
		want     RecoveryAction
	}{
		{name: "dispatch", snapshot: func() TurnSnapshot {
			snapshot := baseSnapshot(now)
			snapshot.ActiveEffect = baseEffect(EffectPrepared)
			return snapshot
		}(), want: RecoveryDispatch},
		{name: "wait external", snapshot: func() TurnSnapshot {
			snapshot := baseSnapshot(now)
			snapshot.ActiveEffect = baseEffect(EffectDispatched)
			return snapshot
		}(), ledger: &fakeLedger{record: routedRecord(LedgerInflight)}, want: RecoveryWaitExternal},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := newFakeStore(test.snapshot)
			reconciler := mustEffectReconciler(t, mustCoordinator(t, store, test.ledger))

			decision, err := reconciler.Reconcile(context.Background(), baseEffectReconcileRequest(now, "recover-"+test.name, "settle-"+test.name))
			if err != nil {
				t.Fatalf("Reconcile() error = %v", err)
			}
			if decision.Action != test.want {
				t.Fatalf("action = %q, want %q", decision.Action, test.want)
			}
			if decision.SettlementReceipt != nil || len(store.settlements) != 0 {
				t.Fatalf("unexpected settlement for %q: %#v", decision.Action, decision.SettlementReceipt)
			}
		})
	}
}

func TestEffectReconcilerRejectsInvalidRequestBeforeRecovery(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_010_500, 0).UTC()
	tests := []struct {
		name   string
		mutate func(*EffectReconcileRequest)
	}{
		{name: "zero dispatch attempt", mutate: func(request *EffectReconcileRequest) { request.DispatchAttempt = 0 }},
		{name: "missing external commit", mutate: func(request *EffectReconcileRequest) { request.ExternalCommitID = identity.ID{} }},
		{name: "wrong external commit kind", mutate: func(request *EffectReconcileRequest) { request.ExternalCommitID = resultID }},
		{name: "missing operation key", mutate: func(request *EffectReconcileRequest) { request.SettlementOperationKey = "" }},
		{name: "missing settlement digest", mutate: func(request *EffectReconcileRequest) { request.SettlementDigest = Digest{} }},
		{name: "missing terminal", mutate: func(request *EffectReconcileRequest) { request.ResultRef = identity.ID{} }},
		{name: "two terminals", mutate: func(request *EffectReconcileRequest) {
			request.TerminalError = &v1.PublicError{Code: v1.ErrorCode_ERROR_CODE_INTERNAL, Reason: "failed"}
		}},
		{name: "wrong result kind", mutate: func(request *EffectReconcileRequest) { request.ResultRef = commitID }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			snapshot := baseSnapshot(now)
			snapshot.ActiveEffect = baseEffect(EffectExternallyCommitted)
			store := newFakeStore(snapshot)
			reconciler := mustEffectReconciler(t, mustCoordinator(t, store, nil))
			request := baseEffectReconcileRequest(now, "recover-invalid", "settle-invalid")
			test.mutate(&request)

			decision, err := reconciler.Reconcile(context.Background(), request)
			if !errors.Is(err, ErrInvalidRequest) || decision != (RecoveryDecision{}) {
				t.Fatalf("Reconcile() = %#v, %v; want ErrInvalidRequest", decision, err)
			}
			if store.readTurnCalls != 0 || len(store.operationLookups) != 0 {
				t.Fatalf("invalid request reached recovery: reads = %d, lookups = %d", store.readTurnCalls, len(store.operationLookups))
			}
		})
	}
}

func TestNewEffectReconcilerRejectsNilCoordinator(t *testing.T) {
	t.Parallel()
	var coordinator *Coordinator

	reconciler, err := NewEffectReconciler(coordinator)
	if !errors.Is(err, ErrInvalidRequest) || reconciler != nil {
		t.Fatalf("NewEffectReconciler(nil) = %#v, %v; want ErrInvalidRequest", reconciler, err)
	}
}

func TestEffectReconcilerPreservesContextAndGenerationFailures(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_010_600, 0).UTC()
	t.Run("cancelled context", func(t *testing.T) {
		t.Parallel()
		snapshot := baseSnapshot(now)
		snapshot.ActiveEffect = baseEffect(EffectExternallyCommitted)
		store := newFakeStore(snapshot)
		reconciler := mustEffectReconciler(t, mustCoordinator(t, store, nil))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		decision, err := reconciler.Reconcile(ctx, baseEffectReconcileRequest(now, "recover-cancelled", "settle-cancelled"))
		if !errors.Is(err, context.Canceled) || decision != (RecoveryDecision{}) {
			t.Fatalf("Reconcile() = %#v, %v; want context.Canceled", decision, err)
		}
		if store.readTurnCalls != 0 {
			t.Fatalf("cancelled reconciliation read turn %d times", store.readTurnCalls)
		}
	})
	t.Run("stale generation", func(t *testing.T) {
		t.Parallel()
		snapshot := baseSnapshot(now)
		snapshot.ActiveEffect = baseEffect(EffectExternallyCommitted)
		snapshot.Generations.Authorization++
		store := newFakeStore(snapshot)
		reconciler := mustEffectReconciler(t, mustCoordinator(t, store, nil))

		decision, err := reconciler.Reconcile(context.Background(), baseEffectReconcileRequest(now, "recover-stale", "settle-stale"))
		if !errors.Is(err, ErrStaleGeneration) || decision != (RecoveryDecision{}) {
			t.Fatalf("Reconcile() = %#v, %v; want ErrStaleGeneration", decision, err)
		}
		if len(store.settlements) != 0 {
			t.Fatalf("stale recovery wrote %d settlements", len(store.settlements))
		}
	})
}

func TestEffectReconcilerRejectsTerminalThatDiffersFromRecovery(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_010_700, 0).UTC()
	tests := []struct {
		name   string
		mutate func(*EffectReconcileRequest)
	}{
		{name: "dispatch attempt", mutate: func(request *EffectReconcileRequest) { request.DispatchAttempt++ }},
		{name: "external commit", mutate: func(request *EffectReconcileRequest) { request.ExternalCommitID = mustID(identity.Commit, "X") }},
		{name: "result", mutate: func(request *EffectReconcileRequest) { request.ResultRef = mustID(identity.Artifact, "X") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			snapshot := baseSnapshot(now)
			snapshot.ActiveEffect = baseEffect(EffectExternallyCommitted)
			store := newFakeStore(snapshot)
			reconciler := mustEffectReconciler(t, mustCoordinator(t, store, nil))
			request := baseEffectReconcileRequest(now, "recover-mismatch", "settle-mismatch")
			test.mutate(&request)

			decision, err := reconciler.Reconcile(context.Background(), request)
			if !errors.Is(err, ErrLedgerMismatch) || decision != (RecoveryDecision{}) {
				t.Fatalf("Reconcile() = %#v, %v; want ErrLedgerMismatch", decision, err)
			}
			if len(store.settlements) != 0 {
				t.Fatalf("mismatched terminal wrote %d settlements", len(store.settlements))
			}
		})
	}
}

func baseEffectReconcileRequest(now time.Time, recoveryOperationKey, settlementOperationKey string) EffectReconcileRequest {
	return EffectReconcileRequest{
		Recovery:               baseRecoveryRequest(now, recoveryOperationKey),
		DispatchAttempt:        1,
		ExternalCommitID:       commitID,
		ResultRef:              resultID,
		SettlementOperationKey: settlementOperationKey,
		SettlementDigest:       digest(201),
	}
}

func mustEffectReconciler(t *testing.T, coordinator *Coordinator) *EffectReconciler {
	t.Helper()
	reconciler, err := NewEffectReconciler(coordinator)
	if err != nil {
		t.Fatalf("NewEffectReconciler() error = %v", err)
	}
	return reconciler
}
