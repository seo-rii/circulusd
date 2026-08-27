package mcpgateway

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/identity"
)

func TestCancellationUnknownNeverBecomesAutomaticReplay(t *testing.T) {
	fixture := newGatewayFixture(t, ReplaySafe)
	effect := admitFixtureEffect(t, fixture)
	fixture.provider.start = func(context.Context, ProviderCommand) (ProviderStartResult, error) {
		return ProviderStartResult{
			ProviderRequestID: "rpc-cancel-safe",
			Call: &functionCall{next: func(context.Context) (ProviderEvent, error) {
				return ProviderEvent{Kind: ProviderOutputChunk, Chunk: []byte("partial")}, nil
			}},
		}, nil
	}
	fixture.provider.cancel = func(context.Context, CancelCommand) (CancellationResult, error) {
		return CancellationResult{Status: CancellationUnknown}, nil
	}
	sinkErr := errors.New("client went away")
	uncertain, err := fixture.gateway.Execute(context.Background(), OpaqueAuthority("turn-secret"), effect,
		OutputSinkFunc(func(context.Context, []byte) error { return sinkErr }))
	if !errors.Is(err, ErrBackpressure) || uncertain.State != StateUncertain {
		t.Fatalf("cancel result state=%s err=%v", uncertain.State, err)
	}
	fixture.provider.mu.Lock()
	fixture.provider.lookup = func(_ context.Context, query LedgerQuery) (LedgerRecord, error) {
		return LedgerRecord{InvocationID: query.InvocationID, RequestDigest: query.RequestDigest, Status: LedgerUnknown}, nil
	}
	fixture.provider.mu.Unlock()

	recovered, err := fixture.gateway.Recover(context.Background(), OpaqueAuthority("renewed"), uncertain)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Action != RecoveryInterrupted || recovered.Effect.State != StateUncertain {
		t.Fatalf("cancelled unknown effect became replayable: %+v", recovered)
	}
}

func TestCancellationUnknownStillSettlesLaterCommittedLedgerWithoutReplay(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-cancel-unknown-late-ledger")
	fixture.provider.cancel = func(context.Context, CancelCommand) (CancellationResult, error) {
		return CancellationResult{Status: CancellationUnknown}, nil
	}
	uncertain, err := fixture.gateway.Cancel(context.Background(), OpaqueAuthority("renewed"), effect)
	if err != nil || uncertain.State != StateUncertain || !uncertain.CancellationRequested {
		t.Fatalf("unknown cancellation=%+v err=%v", uncertain, err)
	}
	lookups := 0
	fixture.provider.lookup = func(_ context.Context, query LedgerQuery) (LedgerRecord, error) {
		lookups++
		return LedgerRecord{
			InvocationID: query.InvocationID, RequestDigest: query.RequestDigest, Status: LedgerCommitted,
			ProviderRequestID: "rpc-cancel-unknown-late-ledger", ExternalCommitID: "commit-after-unknown-cancel",
			Output: []byte(`{"late":true}`),
		}, nil
	}
	startsBefore := fixture.provider.startCount()
	recovered, err := fixture.gateway.Recover(context.Background(), OpaqueAuthority("renewed"), uncertain)
	if err != nil || recovered.Action != RecoverySettled || recovered.Effect.State != StateCompleted ||
		recovered.Effect.ExternalCommitID != "commit-after-unknown-cancel" {
		t.Fatalf("late committed recovery=%+v err=%v", recovered, err)
	}
	if lookups != 1 || fixture.provider.startCount() != startsBefore {
		t.Fatalf("lookups=%d starts-before=%d starts-after=%d", lookups, startsBefore, fixture.provider.startCount())
	}
}

func TestRetriesExhaustedUnknownFailureCanRecoverLateCommittedLedger(t *testing.T) {
	fixture := newGatewayFixture(t, ReplaySafe)
	current := admitFixtureEffect(t, fixture)
	fixture.provider.start = func(context.Context, ProviderCommand) (ProviderStartResult, error) {
		return ProviderStartResult{}, errors.New("provider response lost after possible send")
	}
	var err error
	for attempt := uint32(0); attempt <= current.MaxAutomaticRetries; attempt++ {
		current, err = fixture.gateway.Execute(context.Background(), OpaqueAuthority("renewed"), current, discardSink())
		if err != nil {
			t.Fatal(err)
		}
	}
	lastAttempt, ok := current.CurrentAttempt()
	if !ok || current.State != StateFailed || lastAttempt.Failure != FailureUnknown {
		t.Fatalf("exhausted effect=%+v", current)
	}
	startsBefore := fixture.provider.startCount()
	fixture.provider.lookup = func(_ context.Context, query LedgerQuery) (LedgerRecord, error) {
		return LedgerRecord{
			InvocationID: query.InvocationID, RequestDigest: query.RequestDigest, Status: LedgerCommitted,
			ExternalCommitID: "commit-after-retries-exhausted", Output: []byte(`{"late":true}`),
		}, nil
	}
	recovered, err := fixture.gateway.Recover(context.Background(), OpaqueAuthority("renewed"), current)
	if err != nil || recovered.Action != RecoverySettled || recovered.Effect.State != StateCompleted {
		t.Fatalf("failed-unknown recovery=%+v err=%v", recovered, err)
	}
	if fixture.provider.startCount() != startsBefore {
		t.Fatalf("recovery replayed provider Start: before=%d after=%d", startsBefore, fixture.provider.startCount())
	}
}

func TestKnownProviderInflightRecoveryAfterPartialOutputIsBudgetNeutral(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	effect := admitFixtureEffect(t, fixture)
	step := 0
	fixture.provider.start = func(context.Context, ProviderCommand) (ProviderStartResult, error) {
		return ProviderStartResult{
			ProviderRequestID: "rpc-partial-inflight",
			Call: &functionCall{next: func(context.Context) (ProviderEvent, error) {
				if step == 0 {
					step++
					return ProviderEvent{Kind: ProviderOutputChunk, Chunk: []byte("partial")}, nil
				}
				return ProviderEvent{}, errors.New("stream response lost")
			}},
		}, nil
	}
	uncertain, err := fixture.gateway.Execute(context.Background(), OpaqueAuthority("renewed"), effect, discardSink())
	if err != nil || uncertain.State != StateUncertain || uncertain.ChunkCount != 1 {
		t.Fatalf("partial stream result=%+v err=%v", uncertain, err)
	}
	fixture.provider.lookup = func(_ context.Context, query LedgerQuery) (LedgerRecord, error) {
		return LedgerRecord{
			InvocationID: query.InvocationID, RequestDigest: query.RequestDigest,
			Status: LedgerInflight, ProviderRequestID: "rpc-partial-inflight",
		}, nil
	}
	recovered, err := fixture.gateway.Recover(context.Background(), OpaqueAuthority("renewed"), uncertain)
	if err != nil || recovered.Action != RecoveryWait || !sameEffect(recovered.Effect, uncertain) {
		t.Fatalf("partial inflight recovery=%+v err=%v", recovered, err)
	}
	if err := fixture.gateway.validateEffect(recovered.Effect); err != nil {
		t.Fatalf("recovery persisted corrupt effect: %v", err)
	}
	stored, err := fixture.repository.Load(context.Background(), effect.Scope.InvocationID)
	if err != nil || !sameEffect(stored.Effect, recovered.Effect) {
		t.Fatalf("stored partial recovery=%+v err=%v", stored, err)
	}
}

func TestPartialOutputWithoutDurableLedgerCannotAutomaticallyReplay(t *testing.T) {
	fixture := newGatewayFixture(t, ReplaySafe)
	fixture.provider.availability.SupportsInvocationLedger = false
	effect := admitFixtureEffect(t, fixture)
	step := 0
	fixture.provider.start = func(context.Context, ProviderCommand) (ProviderStartResult, error) {
		return ProviderStartResult{
			ProviderRequestID: "rpc-partial-without-ledger",
			Call: &functionCall{next: func(context.Context) (ProviderEvent, error) {
				if step == 0 {
					step++
					return ProviderEvent{Kind: ProviderOutputChunk, Chunk: []byte("already-delivered")}, nil
				}
				return ProviderEvent{}, errors.New("stream lost after partial delivery")
			}},
		}, nil
	}
	var delivered []byte
	uncertain, err := fixture.gateway.Execute(
		context.Background(), OpaqueAuthority("renewed"), effect,
		OutputSinkFunc(func(_ context.Context, chunk []byte) error {
			delivered = append(delivered, chunk...)
			return nil
		}),
	)
	if err != nil || uncertain.State != StateUncertain || uncertain.AutomaticRetriesUsed != 0 ||
		string(delivered) != "already-delivered" || uncertain.SupportsInvocationLedger {
		t.Fatalf("partial no-ledger result=%+v delivered=%q err=%v", uncertain, delivered, err)
	}
	starts := fixture.provider.startCount()
	_, executeErr := fixture.gateway.Execute(
		context.Background(), OpaqueAuthority("renewed"), uncertain, discardSink(),
	)
	if !errors.Is(executeErr, ErrInvalidTransition) || fixture.provider.startCount() != starts {
		t.Fatalf("unresolved partial output replayed: starts=%d->%d err=%v",
			starts, fixture.provider.startCount(), executeErr)
	}
	recovered, recoverErr := fixture.gateway.Recover(context.Background(), OpaqueAuthority("renewed"), uncertain)
	if recoverErr != nil || recovered.Action != RecoveryInterrupted ||
		!sameEffect(recovered.Effect, uncertain) || fixture.provider.startCount() != starts {
		t.Fatalf("no-ledger recovery replayed: result=%+v starts=%d->%d err=%v",
			recovered, starts, fixture.provider.startCount(), recoverErr)
	}
}

func TestCancellationUnknownCommitsWithinTheExactPreDispatchReserve(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-exact-cancellation-tail")
	effect.EventCount = fixture.gateway.bounds.MaxEvents - 6
	effect.Revision = uint64(effect.EventCount) + 1
	fixture.repository.mu.Lock()
	fixture.repository.effects[effect.Scope.InvocationID.String()] = cloneEffect(effect)
	fixture.repository.mu.Unlock()
	unknown, err := fixture.gateway.Apply(effect, Event{
		ExpectedRevision: effect.Revision, Kind: EventDispatchFailed,
		Failure: FailureUnknown, Reason: "provider outcome unknown",
	})
	if err != nil {
		t.Fatalf("reserved unknown classification failed: %v", err)
	}
	persistFixtureEffect(t, fixture.repository, effect, unknown.Effect)
	cancels := 0
	fixture.provider.cancel = func(context.Context, CancelCommand) (CancellationResult, error) {
		cancels++
		return CancellationResult{Status: CancellationUnknown}, nil
	}
	resolved, err := fixture.gateway.Cancel(context.Background(), OpaqueAuthority("renewed"), unknown.Effect)
	if err != nil || resolved.State != StateUncertain || !resolved.CancellationRequested {
		t.Fatalf("exact-tail cancellation result=%+v err=%v", resolved, err)
	}
	if cancels != 1 || resolved.EventCount != fixture.gateway.bounds.MaxEvents-3 {
		t.Fatalf("cancels=%d event-count=%d", cancels, resolved.EventCount)
	}
	stored, loadErr := fixture.repository.Load(context.Background(), effect.Scope.InvocationID)
	if loadErr != nil || !sameEffect(stored.Effect, resolved) {
		t.Fatalf("unknown cancellation outcome was not durable: stored=%+v err=%v", stored, loadErr)
	}

	insufficient := cloneEffect(unknown.Effect)
	insufficient.EventCount = fixture.gateway.bounds.MaxEvents - 3
	insufficient.Revision = uint64(insufficient.EventCount) + 1
	insufficient.CancellationRequested = false
	fixture.repository.mu.Lock()
	fixture.repository.effects[effect.Scope.InvocationID.String()] = cloneEffect(insufficient)
	fixture.repository.mu.Unlock()
	cancels = 0
	_, err = fixture.gateway.Cancel(context.Background(), OpaqueAuthority("renewed"), insufficient)
	if !errors.Is(err, ErrEventLimit) || cancels != 0 {
		t.Fatalf("insufficient cancellation tail err=%v provider-cancels=%d", err, cancels)
	}
}

func TestCancellationRequestedConfirmationReserveIsFiniteAndNonRecursive(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayConfirm)
	effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-confirm-cancellation-reserve")
	confirmation := applyFixtureEvent(t, fixture.gateway, effect, Event{
		Kind: EventDispatchFailed, Failure: FailureUnknown, Reason: "provider outcome unknown",
	})
	pending := applyFixtureEvent(t, fixture.gateway, confirmation, Event{Kind: EventCancelRequested})
	requested := applyFixtureEvent(t, fixture.gateway, pending, Event{
		Kind: EventCancellationResolved, Cancellation: CancellationUnknown,
	})
	automatic := requested.MaxAutomaticRetries - requested.AutomaticRetriesUsed
	confirmations := requested.MaxConfirmationRetries - requested.ConfirmationRetriesUsed
	base := 3*automatic + 10*confirmations
	if got, want := minimumRemainingEvents(pending), base+4; got != want {
		t.Fatalf("known-ID pending reserve=%d, want %d", got, want)
	}
	if got, want := minimumRemainingEvents(requested), base+3; got != want {
		t.Fatalf("known-ID requested confirmation reserve=%d, want %d", got, want)
	}

	withoutIDPending := cloneEffect(pending)
	withoutIDPending.Attempts[len(withoutIDPending.Attempts)-1].ProviderRequestID = ""
	withoutIDRequested := cloneEffect(requested)
	withoutIDRequested.Attempts[len(withoutIDRequested.Attempts)-1].ProviderRequestID = ""
	if got, want := minimumRemainingEvents(withoutIDPending), base+7; got != want {
		t.Fatalf("no-ID pending reserve=%d, want %d", got, want)
	}
	if got, want := minimumRemainingEvents(withoutIDRequested), base+6; got != want {
		t.Fatalf("no-ID requested confirmation reserve=%d, want %d", got, want)
	}

	exhausted := cloneEffect(requested)
	exhausted.ConfirmationRetriesUsed = exhausted.MaxConfirmationRetries
	withoutIDExhausted := cloneEffect(exhausted)
	withoutIDExhausted.Attempts[len(withoutIDExhausted.Attempts)-1].ProviderRequestID = ""
	if got := minimumRemainingEvents(exhausted); got != 3 {
		t.Fatalf("known-ID exhausted confirmation reserve=%d, want 3", got)
	}
	if got := minimumRemainingEvents(withoutIDExhausted); got != 6 {
		t.Fatalf("no-ID exhausted confirmation reserve=%d, want 6", got)
	}

	for _, test := range []struct {
		name    string
		effect  Effect
		reserve uint32
		want    uint32
	}{
		{name: "known_id", effect: pending, reserve: base + 4, want: base + 3},
		{name: "no_id", effect: withoutIDPending, reserve: base + 7, want: base + 6},
	} {
		t.Run(test.name, func(t *testing.T) {
			exact := cloneEffect(test.effect)
			exact.EventCount = fixture.gateway.bounds.MaxEvents - test.reserve
			exact.Revision = uint64(exact.EventCount) + 1
			fixture.repository.mu.Lock()
			fixture.repository.effects[exact.Scope.InvocationID.String()] = cloneEffect(exact)
			delete(fixture.repository.cancellationClaims, dispatchClaimKey(exact.Scope.InvocationID.String(), 1))
			fixture.repository.mu.Unlock()
			cancels := 0
			fixture.provider.cancel = func(context.Context, CancelCommand) (CancellationResult, error) {
				cancels++
				return CancellationResult{Status: CancellationUnknown}, nil
			}
			result, err := fixture.gateway.Cancel(context.Background(), OpaqueAuthority("renewed"), exact)
			if err != nil || result.State != StateNeedsConfirmation || !result.CancellationRequested ||
				minimumRemainingEvents(result) != test.want || cancels != 1 {
				t.Fatalf("exact confirmation cancellation result=%+v reserve=%d cancels=%d err=%v",
					result, minimumRemainingEvents(result), cancels, err)
			}
			if test.name == "known_id" {
				retried, retryErr := fixture.gateway.Confirm(
					context.Background(), OpaqueAuthority("renewed"), result, ConfirmationRetry,
				)
				if retryErr != nil || retried.State != StateRetryPending ||
					minimumRemainingEvents(retried) != base-10+12 {
					t.Fatalf("exact requested confirmation retry=%+v reserve=%d err=%v",
						retried, minimumRemainingEvents(retried), retryErr)
				}
			}
		})
	}
}

func TestLiveCancellationUnknownConfirmationRetryProducesValidNextAttempt(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayConfirm)
	effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-live-cancel-confirm-retry")
	fixture.provider.cancel = func(context.Context, CancelCommand) (CancellationResult, error) {
		return CancellationResult{Status: CancellationUnknown}, nil
	}
	confirmation, err := fixture.gateway.Cancel(context.Background(), OpaqueAuthority("renewed"), effect)
	if err != nil || confirmation.State != StateNeedsConfirmation || !confirmation.CancellationRequested {
		t.Fatalf("live cancellation confirmation=%+v err=%v", confirmation, err)
	}
	retried, err := fixture.gateway.Confirm(
		context.Background(), OpaqueAuthority("renewed"), confirmation, ConfirmationRetry,
	)
	if err != nil || retried.State != StateRetryPending {
		t.Fatalf("confirmation retry=%+v err=%v", retried, err)
	}
	if validateErr := fixture.gateway.validateEffect(retried); validateErr != nil {
		t.Fatalf("confirmation retry persisted invalid effect: %v; effect=%+v", validateErr, retried)
	}
	fixture.provider.start = func(context.Context, ProviderCommand) (ProviderStartResult, error) {
		return ProviderStartResult{
			ProviderRequestID: "rpc-live-cancel-confirm-retry-2",
			Call:              completedCall(`{"retried":true}`),
		}, nil
	}
	completed, err := fixture.gateway.Execute(
		context.Background(), OpaqueAuthority("renewed"), retried, discardSink(),
	)
	if err != nil || completed.State != StateCompleted || fixture.provider.startCount() != 1 {
		t.Fatalf("confirmed retry execution=%+v starts=%d err=%v",
			completed, fixture.provider.startCount(), err)
	}
}

func TestExplicitCancelFencesEveryUnresolvedTerminalClassification(t *testing.T) {
	tests := []struct {
		name  string
		state State
		make  func(*testing.T) (gatewayFixture, Effect)
	}{
		{
			name: "uncertain", state: StateUncertain,
			make: func(t *testing.T) (gatewayFixture, Effect) {
				fixture := newGatewayFixture(t, ReplayNever)
				effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-cancel-unresolved-uncertain")
				uncertain := applyFixtureEvent(t, fixture.gateway, effect, Event{
					Kind: EventDispatchFailed, Failure: FailureUnknown, Reason: "provider outcome unknown",
				})
				persistFixtureEffect(t, fixture.repository, effect, uncertain)
				return fixture, uncertain
			},
		},
		{
			name: "needs_confirmation", state: StateNeedsConfirmation,
			make: func(t *testing.T) (gatewayFixture, Effect) {
				fixture := newGatewayFixture(t, ReplayConfirm)
				effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-cancel-unresolved-confirm")
				confirmation := applyFixtureEvent(t, fixture.gateway, effect, Event{
					Kind: EventDispatchFailed, Failure: FailureUnknown, Reason: "provider outcome unknown",
				})
				persistFixtureEffect(t, fixture.repository, effect, confirmation)
				return fixture, confirmation
			},
		},
		{
			name: "failed_unknown", state: StateFailed,
			make: func(t *testing.T) (gatewayFixture, Effect) {
				fixture := newGatewayFixture(t, ReplaySafe)
				current := admitFixtureEffect(t, fixture)
				fixture.provider.start = func(context.Context, ProviderCommand) (ProviderStartResult, error) {
					return ProviderStartResult{}, errors.New("provider outcome unknown")
				}
				var err error
				for attempt := uint32(0); attempt <= current.MaxAutomaticRetries; attempt++ {
					current, err = fixture.gateway.Execute(context.Background(), OpaqueAuthority("renewed"), current, discardSink())
					if err != nil {
						t.Fatal(err)
					}
				}
				return fixture, current
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture, effect := test.make(t)
			if effect.State != test.state {
				t.Fatalf("setup state=%s want=%s", effect.State, test.state)
			}
			cancels := 0
			fixture.provider.cancel = func(_ context.Context, command CancelCommand) (CancellationResult, error) {
				cancels++
				if command.Start == (ProviderStartPermit{}) {
					t.Fatal("unresolved cancellation lost historical provider-start proof")
				}
				return CancellationResult{Status: CancellationAbsent}, nil
			}
			cancelled, err := fixture.gateway.Cancel(context.Background(), OpaqueAuthority("renewed"), effect)
			if err != nil || cancelled.State != StateCancelled || cancels != 1 {
				t.Fatalf("cancelled=%+v cancels=%d err=%v", cancelled, cancels, err)
			}
		})
	}
}

func TestNeedsConfirmationStillChecksLedgerForCommittedProof(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayConfirm)
	effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-confirm-ledger")
	unknown := applyFixtureEvent(t, fixture.gateway, effect, Event{
		Kind: EventDispatchFailed, Failure: FailureUnknown, Reason: "transport unknown",
	})
	persistFixtureEffect(t, fixture.repository, effect, unknown)
	fixture.provider.mu.Lock()
	fixture.provider.lookup = func(_ context.Context, query LedgerQuery) (LedgerRecord, error) {
		return LedgerRecord{
			InvocationID: query.InvocationID, RequestDigest: query.RequestDigest, Status: LedgerCommitted,
			ProviderRequestID: "rpc-confirm-ledger", ExternalCommitID: "commit-confirm-ledger",
			Output: []byte(`{"already":"done"}`),
		}, nil
	}
	fixture.provider.mu.Unlock()

	recovered, err := fixture.gateway.Recover(context.Background(), OpaqueAuthority("renewed"), unknown)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Action != RecoverySettled || recovered.Effect.State != StateCompleted {
		t.Fatalf("committed proof was hidden behind confirmation: %+v", recovered)
	}
}

func TestConfirmedReplayPersistsLedgerAbsenceOnceAndAbandonReleasesTurn(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayConfirm)
	dispatched := durablyDispatchedFixtureEffect(t, fixture, "rpc-confirm-ledger-absent")
	automatic := dispatched.MaxAutomaticRetries - dispatched.AutomaticRetriesUsed
	confirmations := dispatched.MaxConfirmationRetries - dispatched.ConfirmationRetriesUsed
	confirmationBase := 3*automatic + 10*confirmations
	dispatched.EventCount = fixture.gateway.bounds.MaxEvents - (confirmationBase + 7)
	dispatched.Revision = uint64(dispatched.EventCount) + 1
	fixture.repository.mu.Lock()
	fixture.repository.effects[dispatched.Scope.InvocationID.String()] = cloneEffect(dispatched)
	fixture.repository.mu.Unlock()
	confirmation := applyFixtureEvent(t, fixture.gateway, dispatched, Event{
		Kind: EventDispatchFailed, Failure: FailureUnknown, Reason: "provider outcome unknown",
	})
	if got, want := minimumRemainingEvents(confirmation), confirmationBase+6; got != want {
		t.Fatalf("unknown confirmation reserve=%d, want %d", got, want)
	}
	persistFixtureEffect(t, fixture.repository, dispatched, confirmation)
	lookups := 0
	fixture.provider.lookup = func(_ context.Context, query LedgerQuery) (LedgerRecord, error) {
		lookups++
		return LedgerRecord{
			InvocationID: query.InvocationID, RequestDigest: query.RequestDigest, Status: LedgerAbsent,
		}, nil
	}
	first, err := fixture.gateway.Recover(context.Background(), OpaqueAuthority("renewed"), confirmation)
	if err != nil || first.Action != RecoveryConfirmation || first.Effect.State != StateNeedsConfirmation {
		t.Fatalf("first absent recovery=%+v err=%v", first, err)
	}
	attempt, ok := first.Effect.CurrentAttempt()
	if !ok || attempt.Failure != FailureLedgerAbsent || first.Effect.Revision != confirmation.Revision+1 {
		t.Fatalf("absence was not durably classified: %+v", first.Effect)
	}
	if got, want := minimumRemainingEvents(first.Effect), confirmationBase+5; got != want {
		t.Fatalf("classified absence reserve=%d, want %d", got, want)
	}
	second, err := fixture.gateway.Recover(context.Background(), OpaqueAuthority("renewed"), first.Effect)
	if err != nil || !sameEffect(second.Effect, first.Effect) || lookups != 2 {
		t.Fatalf("repeated absence recovery=%+v lookups=%d err=%v", second, lookups, err)
	}
	abandoned, err := fixture.gateway.Confirm(context.Background(), OpaqueAuthority("renewed"), first.Effect, ConfirmationAbandon)
	if err != nil || abandoned.State != StateFailed {
		t.Fatalf("abandon after absence=%+v err=%v", abandoned, err)
	}
	call := CallRequest{ServerID: dispatched.ServerID, ToolName: dispatched.ToolName, Input: mapInput("after-definitive-absence")}
	digest, err := CallRequestDigest(call, testBounds())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.gateway.Admit(context.Background(), AdmissionRequest{
		Authority: OpaqueAuthority("turn-secret"), EffectID: mustID(t, identity.Effect),
		InvocationID: mustID(t, identity.Invocation), RequestDigest: digest, Call: call,
	}); err != nil {
		t.Fatalf("definitive absence did not release turn: %v", err)
	}
}

func TestConfirmationAbandonThenLedgerAbsentIsDefinitiveAtExactTail(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayConfirm)
	dispatched := durablyDispatchedFixtureEffect(t, fixture, "rpc-confirm-abandon-then-absent")
	confirmation := applyFixtureEvent(t, fixture.gateway, dispatched, Event{
		Kind: EventDispatchFailed, Failure: FailureUnknown, Reason: "provider outcome unknown",
	})
	roomyAbandoned := applyFixtureEvent(t, fixture.gateway, confirmation, Event{
		Kind: EventConfirmationDecided, Decision: ConfirmationAbandon,
	})
	failedTail := minimumRemainingEvents(roomyAbandoned)
	confirmation.EventCount = fixture.gateway.bounds.MaxEvents - (failedTail + 1)
	confirmation.Revision = uint64(confirmation.EventCount) + 1
	fixture.repository.mu.Lock()
	fixture.repository.effects[confirmation.Scope.InvocationID.String()] = cloneEffect(confirmation)
	fixture.repository.mu.Unlock()
	abandoned, err := fixture.gateway.Confirm(
		context.Background(), OpaqueAuthority("renewed"), confirmation, ConfirmationAbandon,
	)
	if err != nil || abandoned.State != StateFailed || minimumRemainingEvents(abandoned) != failedTail {
		t.Fatalf("exact-tail abandon=%+v reserve=%d err=%v", abandoned, minimumRemainingEvents(abandoned), err)
	}
	fixture.provider.lookup = func(_ context.Context, query LedgerQuery) (LedgerRecord, error) {
		return LedgerRecord{InvocationID: query.InvocationID, RequestDigest: query.RequestDigest, Status: LedgerAbsent}, nil
	}
	recovered, err := fixture.gateway.Recover(context.Background(), OpaqueAuthority("renewed"), abandoned)
	if err != nil || recovered.Effect.State != StateFailed || recovered.Action != RecoveryInterrupted {
		t.Fatalf("abandoned absent recovery=%+v err=%v", recovered, err)
	}
	attempt, ok := recovered.Effect.CurrentAttempt()
	if !ok || attempt.Failure != FailureLedgerAbsent || minimumRemainingEvents(recovered.Effect) != 0 {
		t.Fatalf("absence was not definitive after abandon: %+v", recovered.Effect)
	}
	nextCall := CallRequest{ServerID: dispatched.ServerID, ToolName: dispatched.ToolName, Input: mapInput("after-abandoned-absence")}
	nextDigest, err := CallRequestDigest(nextCall, testBounds())
	if err != nil {
		t.Fatal(err)
	}
	_, err = fixture.gateway.Admit(context.Background(), AdmissionRequest{
		Authority: OpaqueAuthority("turn-secret"), EffectID: mustID(t, identity.Effect),
		InvocationID: mustID(t, identity.Invocation), RequestDigest: nextDigest, Call: nextCall,
	})
	if err != nil {
		t.Fatalf("definitive abandoned absence retained active slot: %v", err)
	}
}

func TestMalformedProviderFrameIsDurablyCancelled(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	effect := admitFixtureEffect(t, fixture)
	fixture.provider.start = func(context.Context, ProviderCommand) (ProviderStartResult, error) {
		return ProviderStartResult{
			ProviderRequestID: "rpc-malformed",
			Call: &functionCall{next: func(context.Context) (ProviderEvent, error) {
				return ProviderEvent{Kind: ProviderOutputChunk}, nil
			}},
		}, nil
	}
	cancelled := 0
	fixture.provider.cancel = func(_ context.Context, command CancelCommand) (CancellationResult, error) {
		cancelled++
		stored, err := fixture.repository.Load(context.Background(), command.InvocationID)
		if err != nil {
			t.Fatal(err)
		}
		if stored.Effect.State != StateCancellationPending {
			t.Fatalf("malformed frame cancellation was not durable first: %s", stored.Effect.State)
		}
		return CancellationResult{Status: CancellationUnknown}, nil
	}

	result, err := fixture.gateway.Execute(context.Background(), OpaqueAuthority("turn-secret"), effect, discardSink())
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("malformed frame error = %v", err)
	}
	if cancelled != 1 || result.State != StateUncertain {
		t.Fatalf("malformed frame cancel count=%d state=%s", cancelled, result.State)
	}
}

func TestErroredCancellationCannotClaimDefiniteAbsence(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	effect := admitFixtureEffect(t, fixture)
	fixture.provider.start = func(context.Context, ProviderCommand) (ProviderStartResult, error) {
		return ProviderStartResult{
			ProviderRequestID: "rpc-cancel-error",
			Call: &functionCall{next: func(context.Context) (ProviderEvent, error) {
				return ProviderEvent{Kind: ProviderOutputChunk, Chunk: []byte("partial")}, nil
			}},
		}, nil
	}
	transportErr := errors.New("cancel response truncated")
	fixture.provider.cancel = func(context.Context, CancelCommand) (CancellationResult, error) {
		return CancellationResult{Status: CancellationAbsent}, transportErr
	}
	result, err := fixture.gateway.Execute(context.Background(), OpaqueAuthority("turn-secret"), effect,
		OutputSinkFunc(func(context.Context, []byte) error { return errors.New("stop") }))
	if !errors.Is(err, ErrProviderUnavailable) || strings.Contains(err.Error(), transportErr.Error()) {
		t.Fatalf("cancel transport error was not safely classified: %v", err)
	}
	if result.State != StateUncertain {
		t.Fatalf("errored absence proof produced state %s, want uncertain", result.State)
	}
}

func TestMemoryRepositoryEnforcesOneActiveEffectPerTurn(t *testing.T) {
	fixture := newGatewayFixture(t, ReplaySafe)
	first := admitFixtureEffect(t, fixture)
	call := CallRequest{ServerID: first.ServerID, ToolName: first.ToolName, Input: mapInput("second")}
	digest, err := CallRequestDigest(call, testBounds())
	if err != nil {
		t.Fatal(err)
	}
	_, err = fixture.gateway.Admit(context.Background(), AdmissionRequest{
		Authority: OpaqueAuthority("turn-secret"), EffectID: mustID(t, identity.Effect),
		InvocationID: mustID(t, identity.Invocation), RequestDigest: digest, Call: call,
	})
	if !errors.Is(err, ErrEffectInFlight) {
		t.Fatalf("second active effect error = %v, want %v", err, ErrEffectInFlight)
	}
}

func TestGatewayRejectsReferenceMemoryWithoutExplicitOptIn(t *testing.T) {
	fixture := newGatewayFixture(t, ReplaySafe)
	configuration := Configuration{
		Bounds: testBounds(), Servers: []ServerRegistration{fixture.server}, Tools: []ToolRegistration{fixture.tool},
	}
	dependencies := Dependencies{
		Authority: fixture.authority, Authorizer: fixture.authorizer, Credentials: fixture.credentials,
		Repository: NewMemoryRepository(), Audit: &auditStub{}, Providers: map[string]Provider{"stdio": fixture.provider},
	}

	if _, err := NewGateway(configuration, dependencies); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("reference memory without opt-in error = %v, want %v", err, ErrStoreUnavailable)
	}
	configuration.AllowReferenceMemory = true
	if _, err := NewGateway(configuration, dependencies); err != nil {
		t.Fatalf("explicit reference memory opt-in: %v", err)
	}

	durability := dependencies.Repository.Durability()
	if durability.CrashDurable || !durability.ReferenceMemory || !durability.AtomicAdmissionCAS || !durability.AtomicAdmissionReplay ||
		!durability.AtomicTransitionCAS || !durability.ExclusiveDispatchClaim ||
		!durability.ExclusiveProviderStartClaim || !durability.ExclusiveCancellationClaim ||
		!durability.AtomicCurrentFence || !durability.AtomicActiveEffect || !durability.AtomicAuditOutbox {
		t.Fatalf("memory durability capability = %+v", durability)
	}
}

func TestRawGatewayRejectsSelfReportedProductionDurability(t *testing.T) {
	fixture := newGatewayFixture(t, ReplaySafe)
	durability := fixture.repository.Durability()
	durability.CrashDurable = true
	durability.ReferenceMemory = false
	repository := &durabilityOverrideRepository{
		MemoryRepository: NewMemoryRepository(),
		durability:       durability,
	}
	configuration := Configuration{Bounds: testBounds(), Servers: []ServerRegistration{fixture.server}, Tools: []ToolRegistration{fixture.tool}}

	_, err := NewGateway(configuration, Dependencies{
		Authority: fixture.authority, Authorizer: fixture.authorizer, Credentials: fixture.credentials,
		Repository: repository, Audit: &auditStub{}, Providers: map[string]Provider{"stdio": fixture.provider},
	})
	if !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("NewGateway(self-reported production durability) error = %v, want %v", err, ErrStoreUnavailable)
	}
}

func TestGatewayRejectsRepositoriesMissingAtomicReplayOrAuditOutbox(t *testing.T) {
	fixture := newGatewayFixture(t, ReplaySafe)
	base := NewMemoryRepository().Durability()
	tests := []struct {
		name   string
		mutate func(*RepositoryDurability)
	}{
		{name: "admission replay", mutate: func(value *RepositoryDurability) { value.AtomicAdmissionReplay = false }},
		{name: "audit outbox", mutate: func(value *RepositoryDurability) { value.AtomicAuditOutbox = false }},
		{name: "provider start claim", mutate: func(value *RepositoryDurability) { value.ExclusiveProviderStartClaim = false }},
		{name: "cancellation claim", mutate: func(value *RepositoryDurability) { value.ExclusiveCancellationClaim = false }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			durability := base
			test.mutate(&durability)
			repository := &durabilityOverrideRepository{MemoryRepository: NewMemoryRepository(), durability: durability}
			_, err := NewGateway(Configuration{
				Bounds: testBounds(), Servers: []ServerRegistration{fixture.server}, Tools: []ToolRegistration{fixture.tool},
				AllowReferenceMemory: true,
			}, Dependencies{
				Authority: fixture.authority, Authorizer: fixture.authorizer, Credentials: fixture.credentials,
				Repository: repository, Audit: &auditStub{}, Providers: map[string]Provider{"stdio": fixture.provider},
			})
			if !errors.Is(err, ErrStoreUnavailable) {
				t.Fatalf("missing %s capability error = %v", test.name, err)
			}
		})
	}
}

func TestProductionGatewayRequiresVerifiedRuntimeDependencies(t *testing.T) {
	typeOfDependencies := reflect.TypeOf(ProductionDependencies{})
	for _, name := range []string{"Authorizer", "Credentials", "Providers", "Sampling", "Elicitation", "Roots"} {
		field, ok := typeOfDependencies.FieldByName(name)
		if !ok || !strings.Contains(field.Type.String(), "dependency.Verified") {
			t.Errorf("ProductionDependencies.%s type = %v, want dependency.Verified binding", name, field.Type)
		}
	}
}

func TestProviderSettlementCannotCommitAfterCurrentFenceRotation(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	effect := admitFixtureEffect(t, fixture)
	started := make(chan struct{})
	release := make(chan struct{})
	fixture.provider.start = func(context.Context, ProviderCommand) (ProviderStartResult, error) {
		close(started)
		<-release
		return ProviderStartResult{ProviderRequestID: "rpc-stale-settlement", Call: completedCall(`{"ok":true}`)}, nil
	}

	done := make(chan struct{})
	var executeErr error
	go func() {
		_, executeErr = fixture.gateway.Execute(context.Background(), OpaqueAuthority("turn-secret"), effect, discardSink())
		close(done)
	}()
	<-started
	rotated := effect.Scope
	rotated.Generations.Placement++
	if err := fixture.repository.SetCurrentAuthority(rotated); err != nil {
		t.Fatal(err)
	}
	close(release)
	<-done
	if !errors.Is(executeErr, ErrStaleAuthority) {
		t.Fatalf("stale settlement error = %v, want %v", executeErr, ErrStaleAuthority)
	}
	stored, err := fixture.repository.Load(context.Background(), effect.Scope.InvocationID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Effect.State != StateDispatching {
		t.Fatalf("stale provider advanced durable state to %s", stored.Effect.State)
	}
}

func TestTakeoverCanRetryWithCurrentGenerationWithoutRewritingEffectOrigin(t *testing.T) {
	fixture := newGatewayFixture(t, ReplaySafe)
	effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-before-takeover")
	retry := applyFixtureEvent(t, fixture.gateway, effect, Event{
		Kind: EventDispatchFailed, Failure: FailureUnknown, Reason: "agent disappeared",
	})
	persistFixtureEffect(t, fixture.repository, effect, retry)
	rotated := retry.Scope
	rotated.Generations.Placement++
	if err := fixture.repository.SetCurrentAuthority(rotated); err != nil {
		t.Fatal(err)
	}
	fixture.authority.mu.Lock()
	fixture.authority.scope = rotated
	fixture.authority.mu.Unlock()
	fixture.provider.start = func(_ context.Context, command ProviderCommand) (ProviderStartResult, error) {
		if command.Scope.Generations != rotated.Generations {
			t.Fatalf("provider command generations = %+v, want %+v", command.Scope.Generations, rotated.Generations)
		}
		return ProviderStartResult{ProviderRequestID: "rpc-after-takeover", Call: completedCall(`{"ok":true}`)}, nil
	}

	completed, err := fixture.gateway.Execute(context.Background(), OpaqueAuthority("renewed-turn-secret"), retry, discardSink())
	if err != nil {
		t.Fatal(err)
	}
	if completed.State != StateCompleted || completed.Scope.Generations != retry.Scope.Generations {
		t.Fatalf("takeover retry = %+v", completed)
	}
}

func TestStdioAffinityIsDerivedFromValidatedSessionScope(t *testing.T) {
	fixture := newGatewayFixture(t, ReplaySafe)
	sessionID := mustID(t, identity.Session)
	fixture.authority.mu.Lock()
	fixture.authority.scope.SessionID = sessionID
	fixture.authority.mu.Unlock()
	fixture.provider.mu.Lock()
	fixture.provider.availability.Affinity.ScopeID = sessionID
	fixture.provider.mu.Unlock()
	call := CallRequest{ServerID: fixture.server.ServerID, ToolName: fixture.tool.ToolName, Input: mapInput("session scoped")}
	digest, err := CallRequestDigest(call, testBounds())
	if err != nil {
		t.Fatal(err)
	}

	effect, err := fixture.gateway.Admit(context.Background(), AdmissionRequest{
		Authority: OpaqueAuthority("turn-secret"), EffectID: mustID(t, identity.Effect),
		InvocationID: mustID(t, identity.Invocation), RequestDigest: digest, Call: call,
	})
	if err != nil {
		t.Fatal(err)
	}
	if effect.Scope.SessionID != sessionID || effect.Affinity.ScopeID != sessionID {
		t.Fatalf("session affinity was not derived exactly: scope=%s affinity=%s", effect.Scope.SessionID, effect.Affinity.ScopeID)
	}
}

func TestWorkspaceAffinityRequiresAndUsesValidatedWorkspaceIdentity(t *testing.T) {
	fixture := newGatewayFixture(t, ReplaySafe)
	workspaceID := mustID(t, identity.Workspace)
	fixture.authority.mu.Lock()
	fixture.authority.scope.WorkspaceID = workspaceID
	fixture.authority.mu.Unlock()
	server := fixture.server
	server.Affinity.Scope = ScopeWorkspace
	server.Affinity.ScopeID = identity.ID{}
	availability := fixture.provider.availability
	availability.Affinity = server.Affinity
	availability.Affinity.ScopeID = workspaceID
	fixture.provider.availability = availability
	gateway, err := NewGateway(Configuration{
		Bounds: testBounds(), Servers: []ServerRegistration{server}, Tools: []ToolRegistration{fixture.tool}, AllowReferenceMemory: true,
	}, Dependencies{
		Authority: fixture.authority, Authorizer: fixture.authorizer, Credentials: fixture.credentials,
		Repository: NewMemoryRepository(), Audit: &auditStub{}, Providers: map[string]Provider{"stdio": fixture.provider},
	})
	if err != nil {
		t.Fatal(err)
	}
	call := CallRequest{ServerID: server.ServerID, ToolName: fixture.tool.ToolName, Input: mapInput("workspace scoped")}
	digest, err := CallRequestDigest(call, testBounds())
	if err != nil {
		t.Fatal(err)
	}
	effect, err := gateway.Admit(context.Background(), AdmissionRequest{
		Authority: OpaqueAuthority("turn-secret"), EffectID: mustID(t, identity.Effect),
		InvocationID: mustID(t, identity.Invocation), RequestDigest: digest, Call: call,
	})
	if err != nil {
		t.Fatal(err)
	}
	if effect.Scope.WorkspaceID != workspaceID || effect.Affinity.ScopeID != workspaceID {
		t.Fatalf("workspace affinity was not derived exactly: scope=%s affinity=%s", effect.Scope.WorkspaceID, effect.Affinity.ScopeID)
	}
}

func TestCancellingUnknownIdempotentRetryConsultsProviderLedger(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayIdempotencyKey)
	effect := admitFixtureEffect(t, fixture)
	fixture.provider.start = func(context.Context, ProviderCommand) (ProviderStartResult, error) {
		return ProviderStartResult{
			ProviderRequestID: "rpc-unknown-before-cancel",
			Call: &functionCall{next: func(context.Context) (ProviderEvent, error) {
				return ProviderEvent{}, errors.New("response lost")
			}},
		}, nil
	}
	retry, err := fixture.gateway.Execute(context.Background(), OpaqueAuthority("turn-secret"), effect, discardSink())
	if err != nil {
		t.Fatal(err)
	}
	if retry.State != StateRetryPending {
		t.Fatalf("failed attempt state = %s, want retry_pending", retry.State)
	}
	cancelCalls := 0
	fixture.provider.cancel = func(_ context.Context, command CancelCommand) (CancellationResult, error) {
		cancelCalls++
		return CancellationResult{Status: CancellationCommitted, Record: LedgerRecord{
			InvocationID: command.InvocationID, RequestDigest: command.RequestDigest,
			Status: LedgerCommitted, ProviderRequestID: command.ProviderRequestID,
			ExternalCommitID: "commit-before-cancel", Output: []byte(`{"created":true}`),
		}}, nil
	}

	completed, err := fixture.gateway.Cancel(context.Background(), OpaqueAuthority("renewed-turn-secret"), retry)
	if err != nil {
		t.Fatal(err)
	}
	if cancelCalls != 1 || completed.State != StateCompleted || completed.ExternalCommitID != "commit-before-cancel" {
		t.Fatalf("cancel calls=%d result=%+v", cancelCalls, completed)
	}
}

func TestRecoveryReissuesDurablyPendingCancellation(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	dispatched := durablyDispatchedFixtureEffect(t, fixture, "rpc-cancel-crash")
	pending := applyFixtureEvent(t, fixture.gateway, dispatched, Event{Kind: EventCancelRequested})
	persistFixtureEffect(t, fixture.repository, dispatched, pending)

	cancelCalls := 0
	fixture.provider.cancel = func(_ context.Context, command CancelCommand) (CancellationResult, error) {
		cancelCalls++
		if command.ProviderRequestID != "rpc-cancel-crash" {
			t.Fatalf("cancel provider request id = %q", command.ProviderRequestID)
		}
		return CancellationResult{Status: CancellationAbsent}, nil
	}
	fixture.provider.lookup = func(_ context.Context, query LedgerQuery) (LedgerRecord, error) {
		return LedgerRecord{
			InvocationID: query.InvocationID, RequestDigest: query.RequestDigest,
			Status: LedgerInflight, ProviderRequestID: "rpc-cancel-crash",
		}, nil
	}

	recovered, err := fixture.gateway.Recover(context.Background(), OpaqueAuthority("renewed"), pending)
	if err != nil {
		t.Fatal(err)
	}
	if cancelCalls != 1 || recovered.Effect.State != StateCancelled {
		t.Fatalf("pending cancellation recovery calls=%d result=%+v", cancelCalls, recovered)
	}
}

func TestCancellationLeaseTakeoverFencesLateOwnerResult(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	dispatched := durablyDispatchedFixtureEffect(t, fixture, "rpc-cancel-takeover")
	pending := applyFixtureEvent(t, fixture.gateway, dispatched, Event{Kind: EventCancelRequested})
	persistFixtureEffect(t, fixture.repository, dispatched, pending)
	now := time.Unix(1_800_000_000, 0)
	fixture.repository.now = func() time.Time { return now }
	first, err := fixture.repository.ClaimCancellation(context.Background(), CancellationClaimRequest{
		CurrentScope: pending.Scope, Effect: pending, Lease: time.Second,
	})
	if err != nil || !first.Fresh {
		t.Fatalf("first cancellation claim=%+v err=%v", first, err)
	}
	now = now.Add(2 * time.Second)
	second, err := fixture.repository.ClaimCancellation(context.Background(), CancellationClaimRequest{
		CurrentScope: pending.Scope, Effect: pending, Lease: time.Second,
	})
	if err != nil || !second.Fresh || second.Permit.ClaimGeneration != first.Permit.ClaimGeneration+1 ||
		second.Permit.Proof != first.Permit.Proof {
		t.Fatalf("takeover cancellation claim=%+v first=%+v err=%v", second, first, err)
	}
	resolved := applyFixtureEvent(t, fixture.gateway, pending, Event{
		Kind: EventCancellationResolved, Cancellation: CancellationAbsent,
	})
	_, err = fixture.repository.Commit(context.Background(), TransitionCommitRequest{
		ExpectedRevision: pending.Revision, CurrentScope: pending.Scope, Previous: pending,
		Next: resolved, Cancellation: &first.Permit,
	})
	if !errors.Is(err, ErrConcurrentTransition) {
		t.Fatalf("late cancellation owner commit error=%v, want %v", err, ErrConcurrentTransition)
	}
	stored, err := fixture.repository.Commit(context.Background(), TransitionCommitRequest{
		ExpectedRevision: pending.Revision, CurrentScope: pending.Scope, Previous: pending,
		Next: resolved, Cancellation: &second.Permit,
	})
	if err != nil || stored.Effect.State != StateCancelled {
		t.Fatalf("current cancellation owner commit=%+v err=%v", stored, err)
	}
}

func TestDependencyErrorsNeverExposeRawProviderOrCredentialDetails(t *testing.T) {
	secretErr := errors.New("Bearer raw-secret endpoint=https://credential.internal")
	assertRedacted := func(t *testing.T, err error) {
		t.Helper()
		if err == nil || strings.Contains(err.Error(), "raw-secret") || strings.Contains(err.Error(), "credential.internal") {
			t.Fatalf("dependency error was not safely redacted: %v", err)
		}
	}

	t.Run("availability", func(t *testing.T) {
		fixture := newGatewayFixture(t, ReplaySafe)
		fixture.provider.availabilityErr = secretErr
		_, err := admitFixtureEffectResult(t, fixture)
		assertRedacted(t, err)
	})
	t.Run("authority", func(t *testing.T) {
		fixture := newGatewayFixture(t, ReplaySafe)
		fixture.authority.err = secretErr
		_, err := admitFixtureEffectResult(t, fixture)
		assertRedacted(t, err)
	})
	t.Run("authorizer admission", func(t *testing.T) {
		fixture := newGatewayFixture(t, ReplaySafe)
		fixture.authorizer.err = secretErr
		_, err := admitFixtureEffectResult(t, fixture)
		assertRedacted(t, err)
	})
	t.Run("authorizer dispatch", func(t *testing.T) {
		fixture := newGatewayFixture(t, ReplaySafe)
		effect := admitFixtureEffect(t, fixture)
		fixture.authorizer.err = secretErr
		_, err := fixture.gateway.Execute(context.Background(), OpaqueAuthority("renewed"), effect, discardSink())
		assertRedacted(t, err)
	})
	t.Run("credential", func(t *testing.T) {
		fixture := newGatewayFixture(t, ReplaySafe)
		fixture.credentials.err = secretErr
		_, err := admitFixtureEffectResult(t, fixture)
		assertRedacted(t, err)
	})
	t.Run("repository", func(t *testing.T) {
		fixture := newGatewayFixture(t, ReplaySafe)
		repository := &admitErrorRepository{MemoryRepository: NewMemoryRepository(), err: secretErr}
		gateway, err := NewGateway(Configuration{
			Bounds: testBounds(), Servers: []ServerRegistration{fixture.server}, Tools: []ToolRegistration{fixture.tool}, AllowReferenceMemory: true,
		}, Dependencies{
			Authority: fixture.authority, Authorizer: fixture.authorizer, Credentials: fixture.credentials,
			Repository: repository, Audit: &auditStub{}, Providers: map[string]Provider{"stdio": fixture.provider},
		})
		if err != nil {
			t.Fatal(err)
		}
		fixture.gateway = gateway
		_, err = admitFixtureEffectResult(t, fixture)
		assertRedacted(t, err)
	})
	t.Run("cancel", func(t *testing.T) {
		fixture := newGatewayFixture(t, ReplayNever)
		effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-redacted-cancel")
		fixture.provider.cancel = func(context.Context, CancelCommand) (CancellationResult, error) {
			return CancellationResult{Status: CancellationUnknown}, secretErr
		}
		_, err := fixture.gateway.Cancel(context.Background(), OpaqueAuthority("turn-secret"), effect)
		assertRedacted(t, err)
	})
	t.Run("lookup", func(t *testing.T) {
		fixture := newGatewayFixture(t, ReplayNever)
		effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-redacted-lookup")
		uncertain := applyFixtureEvent(t, fixture.gateway, effect, Event{
			Kind: EventDispatchFailed, Failure: FailureUnknown, Reason: "unknown",
		})
		persistFixtureEffect(t, fixture.repository, effect, uncertain)
		fixture.provider.lookup = func(context.Context, LedgerQuery) (LedgerRecord, error) {
			return LedgerRecord{}, secretErr
		}
		_, err := fixture.gateway.Recover(context.Background(), OpaqueAuthority("renewed"), uncertain)
		assertRedacted(t, err)
	})
	t.Run("audit", func(t *testing.T) {
		fixture := newGatewayFixture(t, ReplayConfirm)
		fixture.gateway.audit = &auditStub{err: secretErr}
		effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-redacted-audit")
		confirmation := applyFixtureEvent(t, fixture.gateway, effect, Event{
			Kind: EventDispatchFailed, Failure: FailureUnknown, Reason: "unknown",
		})
		persistFixtureEffect(t, fixture.repository, effect, confirmation)
		_, err := fixture.gateway.Confirm(context.Background(), OpaqueAuthority("renewed"), confirmation, ConfirmationAbandon)
		assertRedacted(t, err)
	})
	t.Run("output sink", func(t *testing.T) {
		fixture := newGatewayFixture(t, ReplayNever)
		effect := admitFixtureEffect(t, fixture)
		fixture.provider.start = func(context.Context, ProviderCommand) (ProviderStartResult, error) {
			return ProviderStartResult{ProviderRequestID: "rpc-redacted-sink", Call: &functionCall{next: func(context.Context) (ProviderEvent, error) {
				return ProviderEvent{Kind: ProviderOutputChunk, Chunk: []byte("partial")}, nil
			}}}, nil
		}
		_, err := fixture.gateway.Execute(context.Background(), OpaqueAuthority("turn-secret"), effect,
			OutputSinkFunc(func(context.Context, []byte) error { return secretErr }))
		assertRedacted(t, err)
	})
}

func TestProviderCompletionConvergesWithConcurrentCancellation(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	effect := admitFixtureEffect(t, fixture)
	nextStarted := make(chan struct{})
	releaseCompletion := make(chan struct{})
	fixture.provider.start = func(context.Context, ProviderCommand) (ProviderStartResult, error) {
		return ProviderStartResult{ProviderRequestID: "rpc-complete-cancel-race", Call: &functionCall{next: func(context.Context) (ProviderEvent, error) {
			close(nextStarted)
			<-releaseCompletion
			return ProviderEvent{Kind: ProviderCompleted, Output: []byte(`{"committed":true}`), ExternalCommitID: "commit-race"}, nil
		}}}, nil
	}
	cancelCalled := make(chan struct{})
	releaseCancel := make(chan struct{})
	fixture.provider.cancel = func(context.Context, CancelCommand) (CancellationResult, error) {
		close(cancelCalled)
		<-releaseCancel
		return CancellationResult{Status: CancellationUnknown}, nil
	}

	executeDone := make(chan struct{})
	var executeResult Effect
	var executeErr error
	go func() {
		executeResult, executeErr = fixture.gateway.Execute(context.Background(), OpaqueAuthority("turn-secret"), effect, discardSink())
		close(executeDone)
	}()
	<-nextStarted
	dispatched, err := fixture.repository.Load(context.Background(), effect.Scope.InvocationID)
	if err != nil {
		t.Fatal(err)
	}
	cancelDone := make(chan struct{})
	var cancelResult Effect
	var cancelErr error
	go func() {
		cancelResult, cancelErr = fixture.gateway.Cancel(context.Background(), OpaqueAuthority("renewed"), dispatched.Effect)
		close(cancelDone)
	}()
	<-cancelCalled
	close(releaseCompletion)
	<-executeDone
	close(releaseCancel)
	<-cancelDone

	if executeErr != nil || cancelErr != nil || executeResult.State != StateCompleted || cancelResult.State != StateCompleted {
		t.Fatalf("execute=(%s,%v) cancel=(%s,%v)", executeResult.State, executeErr, cancelResult.State, cancelErr)
	}
	stored, err := fixture.repository.Load(context.Background(), effect.Scope.InvocationID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Effect.State != StateCompleted || stored.Effect.ExternalCommitID != "commit-race" {
		t.Fatalf("durable race result = %+v", stored.Effect)
	}
}

func TestLateProviderCompletionOverridesUnknownCancellation(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	effect := admitFixtureEffect(t, fixture)
	nextStarted := make(chan struct{})
	releaseCompletion := make(chan struct{})
	fixture.provider.start = func(context.Context, ProviderCommand) (ProviderStartResult, error) {
		return ProviderStartResult{ProviderRequestID: "rpc-late-after-cancel", Call: &functionCall{next: func(context.Context) (ProviderEvent, error) {
			close(nextStarted)
			<-releaseCompletion
			return ProviderEvent{Kind: ProviderCompleted, Output: []byte(`{"committed":true}`), ExternalCommitID: "commit-after-cancel"}, nil
		}}}, nil
	}
	fixture.provider.cancel = func(context.Context, CancelCommand) (CancellationResult, error) {
		return CancellationResult{Status: CancellationUnknown}, nil
	}

	executeDone := make(chan struct{})
	var executeResult Effect
	var executeErr error
	go func() {
		executeResult, executeErr = fixture.gateway.Execute(context.Background(), OpaqueAuthority("turn-secret"), effect, discardSink())
		close(executeDone)
	}()
	<-nextStarted
	dispatched, err := fixture.repository.Load(context.Background(), effect.Scope.InvocationID)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, err := fixture.gateway.Cancel(context.Background(), OpaqueAuthority("renewed"), dispatched.Effect)
	if err != nil || cancelled.State != StateUncertain {
		t.Fatalf("unknown cancellation state=%s err=%v", cancelled.State, err)
	}
	secondCall := CallRequest{ServerID: effect.ServerID, ToolName: effect.ToolName, Input: mapInput("must-wait-for-late-owner")}
	secondDigest, digestErr := CallRequestDigest(secondCall, testBounds())
	if digestErr != nil {
		t.Fatal(digestErr)
	}
	_, secondErr := fixture.gateway.Admit(context.Background(), AdmissionRequest{
		Authority: OpaqueAuthority("turn-secret"), EffectID: mustID(t, identity.Effect),
		InvocationID: mustID(t, identity.Invocation), RequestDigest: secondDigest, Call: secondCall,
	})
	close(releaseCompletion)
	<-executeDone
	if !errors.Is(secondErr, ErrEffectInFlight) {
		t.Fatalf("uncertain A allowed overlapping B admission: err=%v", secondErr)
	}
	if executeErr != nil || executeResult.State != StateCompleted || executeResult.ExternalCommitID != "commit-after-cancel" {
		t.Fatalf("late completion result=%+v err=%v", executeResult, executeErr)
	}
	stored, err := fixture.repository.Load(context.Background(), effect.Scope.InvocationID)
	if err != nil {
		t.Fatal(err)
	}
	if !sameEffect(stored.Effect, executeResult) {
		t.Fatalf("late completion did not converge durably: %+v", stored.Effect)
	}
}

func TestConfirmationAbandonCannotEraseUnknownCancellationOrLateCommit(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayConfirm)
	effect := admitFixtureEffect(t, fixture)
	nextStarted := make(chan struct{})
	releaseCompletion := make(chan struct{})
	fixture.provider.start = func(context.Context, ProviderCommand) (ProviderStartResult, error) {
		return ProviderStartResult{ProviderRequestID: "rpc-confirm-abandon-late", Call: &functionCall{next: func(context.Context) (ProviderEvent, error) {
			close(nextStarted)
			<-releaseCompletion
			return ProviderEvent{Kind: ProviderCompleted, Output: []byte(`{"committed":true}`), ExternalCommitID: "commit-confirm-abandon-late"}, nil
		}}}, nil
	}
	fixture.provider.cancel = func(context.Context, CancelCommand) (CancellationResult, error) {
		return CancellationResult{Status: CancellationUnknown}, nil
	}
	executed := make(chan struct{})
	var executeResult Effect
	var executeErr error
	go func() {
		executeResult, executeErr = fixture.gateway.Execute(context.Background(), OpaqueAuthority("renewed"), effect, discardSink())
		close(executed)
	}()
	<-nextStarted
	dispatched, err := fixture.repository.Load(context.Background(), effect.Scope.InvocationID)
	if err != nil {
		t.Fatal(err)
	}
	confirmation, err := fixture.gateway.Cancel(context.Background(), OpaqueAuthority("renewed"), dispatched.Effect)
	if err != nil || confirmation.State != StateNeedsConfirmation {
		close(releaseCompletion)
		<-executed
		t.Fatalf("unknown cancellation state=%s err=%v", confirmation.State, err)
	}
	abandoned, err := fixture.gateway.Confirm(context.Background(), OpaqueAuthority("renewed"), confirmation, ConfirmationAbandon)
	if err != nil {
		close(releaseCompletion)
		<-executed
		t.Fatal(err)
	}
	secondCall := CallRequest{ServerID: effect.ServerID, ToolName: effect.ToolName, Input: mapInput("blocked-after-abandon")}
	secondDigest, err := CallRequestDigest(secondCall, testBounds())
	if err != nil {
		close(releaseCompletion)
		<-executed
		t.Fatal(err)
	}
	_, secondErr := fixture.gateway.Admit(context.Background(), AdmissionRequest{
		Authority: OpaqueAuthority("turn-secret"), EffectID: mustID(t, identity.Effect),
		InvocationID: mustID(t, identity.Invocation), RequestDigest: secondDigest, Call: secondCall,
	})
	close(releaseCompletion)
	<-executed
	if abandoned.State != StateUncertain || !abandoned.CancellationRequested {
		t.Fatalf("confirmation abandon falsely proved absence: %+v", abandoned)
	}
	if !errors.Is(secondErr, ErrEffectInFlight) {
		t.Fatalf("confirmation abandon allowed overlapping effect: err=%v", secondErr)
	}
	if executeErr != nil || executeResult.State != StateCompleted || executeResult.ExternalCommitID != "commit-confirm-abandon-late" {
		stored, loadErr := fixture.repository.Load(context.Background(), effect.Scope.InvocationID)
		t.Fatalf("late completion state=%s revision=%d err=%T/%v stored-state=%s stored-revision=%d load=%v",
			executeResult.State, executeResult.Revision, executeErr, executeErr, stored.Effect.State, stored.Effect.Revision, loadErr)
	}
}

func TestStaleCancellationConvergesToCompletedEffect(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	effect := admitFixtureEffect(t, fixture)
	nextStarted := make(chan struct{})
	releaseCompletion := make(chan struct{})
	fixture.provider.start = func(context.Context, ProviderCommand) (ProviderStartResult, error) {
		return ProviderStartResult{ProviderRequestID: "rpc-complete-before-cancel", Call: &functionCall{next: func(context.Context) (ProviderEvent, error) {
			close(nextStarted)
			<-releaseCompletion
			return ProviderEvent{Kind: ProviderCompleted, Output: []byte(`{"done":true}`), ExternalCommitID: "commit-before-cancel"}, nil
		}}}, nil
	}
	executeDone := make(chan struct{})
	var completed Effect
	var executeErr error
	go func() {
		completed, executeErr = fixture.gateway.Execute(context.Background(), OpaqueAuthority("turn-secret"), effect, discardSink())
		close(executeDone)
	}()
	<-nextStarted
	dispatched, err := fixture.repository.Load(context.Background(), effect.Scope.InvocationID)
	if err != nil {
		t.Fatal(err)
	}
	close(releaseCompletion)
	<-executeDone
	if executeErr != nil || completed.State != StateCompleted {
		t.Fatalf("completion state=%s err=%v", completed.State, executeErr)
	}

	converged, err := fixture.gateway.Cancel(context.Background(), OpaqueAuthority("renewed"), dispatched.Effect)
	if err != nil || !sameEffect(converged, completed) {
		t.Fatalf("stale cancellation result=%+v err=%v", converged, err)
	}
}

func TestCancellationCASLossRetriesAgainstUnresolvedDurableWinner(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	dispatched := durablyDispatchedFixtureEffect(t, fixture, "rpc-cancel-cas-unresolved")
	barrier := &cancellationCommitBarrierRepository{
		MemoryRepository: fixture.repository, entered: make(chan struct{}), release: make(chan struct{}),
	}
	fixture.gateway.repository = barrier
	cancels := 0
	fixture.provider.cancel = func(context.Context, CancelCommand) (CancellationResult, error) {
		cancels++
		return CancellationResult{Status: CancellationAbsent}, nil
	}
	done := make(chan struct{})
	var result Effect
	var cancelErr error
	go func() {
		result, cancelErr = fixture.gateway.Cancel(context.Background(), OpaqueAuthority("renewed"), dispatched)
		close(done)
	}()
	<-barrier.entered
	uncertain := applyFixtureEvent(t, fixture.gateway, dispatched, Event{
		Kind: EventDispatchFailed, Failure: FailureUnknown, Reason: "concurrent provider stream failure",
	})
	persistFixtureEffect(t, fixture.repository, dispatched, uncertain)
	close(barrier.release)
	<-done
	if cancelErr != nil || result.State != StateCancelled || cancels != 1 {
		t.Fatalf("cancel convergence=%+v cancels=%d err=%v", result, cancels, cancelErr)
	}
}

func TestConfirmationAuditIsAtomicallyOutboxedBeforeDelivery(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayConfirm)
	secretErr := errors.New("audit endpoint bearer=raw-secret")
	audit := &auditStub{err: secretErr}
	fixture.gateway.audit = audit
	effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-audit-outbox")
	confirmation := applyFixtureEvent(t, fixture.gateway, effect, Event{
		Kind: EventDispatchFailed, Failure: FailureUnknown, Reason: "outcome unknown",
	})
	persistFixtureEffect(t, fixture.repository, effect, confirmation)

	next, err := fixture.gateway.Confirm(context.Background(), OpaqueAuthority("renewed"), confirmation, ConfirmationAbandon)
	if !errors.Is(err, ErrAuditUnavailable) || strings.Contains(err.Error(), "raw-secret") {
		t.Fatalf("confirmation audit error = %v", err)
	}
	if next.State != StateFailed {
		t.Fatalf("confirmation decision was not committed with audit: %s", next.State)
	}
	pending, err := fixture.repository.PendingAudits(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Sequence == 0 || pending[0].Event.OutboxSequence != pending[0].Sequence ||
		pending[0].Event.InvocationID != effect.Scope.InvocationID {
		t.Fatalf("durable pending audit = %+v", pending)
	}

	audit.mu.Lock()
	audit.err = nil
	audit.mu.Unlock()
	if err := fixture.gateway.FlushAudit(context.Background(), 10); err != nil {
		t.Fatal(err)
	}
	pending, err = fixture.repository.PendingAudits(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("acknowledged audit remains pending: %+v", pending)
	}
}

type admitErrorRepository struct {
	*MemoryRepository
	err error
}

type durabilityOverrideRepository struct {
	*MemoryRepository
	durability RepositoryDurability
}

type negotiationCommitErrorRepository struct {
	*MemoryRepository
	err error
}

type negotiationBarrierRepository struct {
	*MemoryRepository
	committed chan struct{}
	release   chan struct{}
}

type cancellationCommitBarrierRepository struct {
	*MemoryRepository
	entered chan struct{}
	release chan struct{}
	blocked bool
}

func (repository *cancellationCommitBarrierRepository) Commit(ctx context.Context, request TransitionCommitRequest) (StoredEffect, error) {
	if request.Next.State == StateCancellationPending && !repository.blocked {
		repository.blocked = true
		close(repository.entered)
		select {
		case <-repository.release:
		case <-ctx.Done():
			return StoredEffect{}, ctx.Err()
		}
	}
	return repository.MemoryRepository.Commit(ctx, request)
}

func (repository *negotiationBarrierRepository) Commit(ctx context.Context, request TransitionCommitRequest) (StoredEffect, error) {
	stored, err := repository.MemoryRepository.Commit(ctx, request)
	if err != nil {
		return StoredEffect{}, err
	}
	previousAttempt, previousOK := request.Previous.CurrentAttempt()
	nextAttempt, nextOK := request.Next.CurrentAttempt()
	if previousOK && nextOK && previousAttempt.Negotiation == (StartNegotiationReceipt{}) &&
		nextAttempt.Negotiation != (StartNegotiationReceipt{}) {
		close(repository.committed)
		select {
		case <-repository.release:
		case <-ctx.Done():
			return StoredEffect{}, ctx.Err()
		}
	}
	return stored, nil
}

func (repository *negotiationCommitErrorRepository) Commit(_ context.Context, request TransitionCommitRequest) (StoredEffect, error) {
	if request.Previous.State == StateDispatching && request.Next.State == StateDispatching {
		previousAttempt, previousOK := request.Previous.CurrentAttempt()
		nextAttempt, nextOK := request.Next.CurrentAttempt()
		if previousOK && nextOK && previousAttempt.Negotiation == (StartNegotiationReceipt{}) &&
			nextAttempt.Negotiation != (StartNegotiationReceipt{}) {
			return StoredEffect{}, repository.err
		}
	}
	return repository.MemoryRepository.Commit(context.Background(), request)
}

func (repository *durabilityOverrideRepository) Durability() RepositoryDurability {
	return repository.durability
}

func (repository *admitErrorRepository) Admit(context.Context, Effect) (StoredEffect, error) {
	return StoredEffect{}, repository.err
}

func admitFixtureEffectResult(t *testing.T, fixture gatewayFixture) (Effect, error) {
	t.Helper()
	call := CallRequest{ServerID: fixture.server.ServerID, ToolName: fixture.tool.ToolName, Input: mapInput("redaction")}
	digest, err := CallRequestDigest(call, testBounds())
	if err != nil {
		return Effect{}, err
	}
	return fixture.gateway.Admit(context.Background(), AdmissionRequest{
		Authority: OpaqueAuthority("turn-secret"), EffectID: mustID(t, identity.Effect),
		InvocationID: mustID(t, identity.Invocation), RequestDigest: digest, Call: call,
	})
}

func TestAdmissionReplayReturnsAdvancedDurableInvocation(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayIdempotencyKey)
	effect := admitFixtureEffect(t, fixture)
	fixture.provider.start = func(context.Context, ProviderCommand) (ProviderStartResult, error) {
		return ProviderStartResult{ProviderRequestID: "rpc-admit-replay", Call: completedCall(`{"ok":true}`)}, nil
	}
	completed, err := fixture.gateway.Execute(context.Background(), OpaqueAuthority("turn-secret"), effect, discardSink())
	if err != nil {
		t.Fatal(err)
	}
	call := CallRequest{ServerID: effect.ServerID, ToolName: effect.ToolName, Input: canonical.Map{
		"repository": "org/repo", "private": true,
	}}
	replayed, err := fixture.gateway.Admit(context.Background(), AdmissionRequest{
		Authority: OpaqueAuthority("turn-secret"), EffectID: effect.Scope.EffectID,
		InvocationID: effect.Scope.InvocationID, RequestDigest: effect.RequestDigest, Call: call,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !sameEffect(replayed, completed) || replayed.State != StateCompleted {
		t.Fatalf("admission replay lost advanced durable state: %+v", replayed)
	}
}

func TestAdmissionReplayPrecedesProviderAvailabilityAndCredentialRedemption(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayIdempotencyKey)
	effect := admitFixtureEffect(t, fixture)
	fixture.provider.start = func(context.Context, ProviderCommand) (ProviderStartResult, error) {
		return ProviderStartResult{ProviderRequestID: "rpc-replay-before-dependencies", Call: completedCall(`{"ok":true}`)}, nil
	}
	completed, err := fixture.gateway.Execute(context.Background(), OpaqueAuthority("turn-secret"), effect, discardSink())
	if err != nil {
		t.Fatal(err)
	}
	request := AdmissionRequest{
		Authority: OpaqueAuthority("renewed"), EffectID: effect.Scope.EffectID,
		InvocationID: effect.Scope.InvocationID, RequestDigest: effect.RequestDigest,
		Call: CallRequest{ServerID: effect.ServerID, ToolName: effect.ToolName, Input: canonical.Map{
			"repository": "org/repo", "private": true,
		}},
	}

	fixture.provider.availabilityErr = errors.New("provider control plane unavailable")
	replayed, err := fixture.gateway.Admit(context.Background(), request)
	if err != nil || !sameEffect(replayed, completed) {
		t.Fatalf("availability blocked exact durable replay: state=%s err=%v", replayed.State, err)
	}
	fixture.provider.availabilityErr = nil
	fixture.credentials.err = errors.New("credential broker unavailable")
	replayed, err = fixture.gateway.Admit(context.Background(), request)
	if err != nil || !sameEffect(replayed, completed) {
		t.Fatalf("credential redemption blocked exact durable replay: state=%s err=%v", replayed.State, err)
	}
}

func TestRecoveryDurablyCapturesInflightProviderRequestIdentity(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	effect := admitFixtureEffect(t, fixture)
	begin := applyFixtureEvent(t, fixture.gateway, effect, Event{Kind: EventBeginDispatch})
	permit, err := fixture.repository.CommitAndClaimDispatch(context.Background(), DispatchClaimRequest{
		ExpectedRevision: effect.Revision, CurrentScope: effect.Scope,
		Previous: effect, Next: begin, Authorization: permitForEffect(begin),
	})
	if err != nil || !permit.Durable {
		t.Fatalf("durable dispatch claim: permit=%+v err=%v", permit, err)
	}
	negotiated := negotiateFixtureEffect(t, fixture.gateway, begin)
	persistFixtureEffect(t, fixture.repository, begin, negotiated)
	expireProviderStartForRecovery(t, fixture, negotiated, permit)
	fixture.provider.lookup = func(_ context.Context, query LedgerQuery) (LedgerRecord, error) {
		return LedgerRecord{
			InvocationID: query.InvocationID, RequestDigest: query.RequestDigest,
			Status: LedgerInflight, ProviderRequestID: "rpc-restored-inflight",
		}, nil
	}

	recovered, err := fixture.gateway.Recover(context.Background(), OpaqueAuthority("renewed"), negotiated)
	if err != nil {
		t.Fatal(err)
	}
	attempt, ok := recovered.Effect.CurrentAttempt()
	if recovered.Action != RecoveryWait || recovered.Effect.State != StateDispatched || !ok ||
		attempt.ProviderRequestID != "rpc-restored-inflight" {
		t.Fatalf("inflight recovery = %+v", recovered)
	}
	stored, err := fixture.repository.Load(context.Background(), effect.Scope.InvocationID)
	if err != nil {
		t.Fatal(err)
	}
	if !sameEffect(stored.Effect, recovered.Effect) {
		t.Fatalf("recovered provider request identity was not durable: %+v", stored.Effect)
	}

	again, err := fixture.gateway.Recover(context.Background(), OpaqueAuthority("renewed"), recovered.Effect)
	if err != nil || again.Effect.EventCount != recovered.Effect.EventCount || again.Action != RecoveryWait {
		t.Fatalf("repeated inflight polling consumed an event: first=%+v second=%+v err=%v", recovered, again, err)
	}
}

func TestConcurrentInflightIdentityRecoveryConverges(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	effect := admitFixtureEffect(t, fixture)
	begin := applyFixtureEvent(t, fixture.gateway, effect, Event{Kind: EventBeginDispatch})
	permit, err := fixture.repository.CommitAndClaimDispatch(context.Background(), DispatchClaimRequest{
		ExpectedRevision: effect.Revision, CurrentScope: effect.Scope,
		Previous: effect, Next: begin, Authorization: permitForEffect(begin),
	})
	if err != nil {
		t.Fatal(err)
	}
	negotiated := negotiateFixtureEffect(t, fixture.gateway, begin)
	persistFixtureEffect(t, fixture.repository, begin, negotiated)
	expireProviderStartForRecovery(t, fixture, negotiated, permit)
	arrived := make(chan struct{}, 2)
	release := make(chan struct{})
	fixture.provider.lookup = func(_ context.Context, query LedgerQuery) (LedgerRecord, error) {
		arrived <- struct{}{}
		<-release
		return LedgerRecord{
			InvocationID: query.InvocationID, RequestDigest: query.RequestDigest,
			Status: LedgerInflight, ProviderRequestID: "rpc-concurrent-inflight",
		}, nil
	}
	results := make(chan RecoveryResult, 2)
	errs := make(chan error, 2)
	for range 2 {
		go func() {
			result, err := fixture.gateway.Recover(context.Background(), OpaqueAuthority("renewed"), negotiated)
			results <- result
			errs <- err
		}()
	}
	<-arrived
	<-arrived
	close(release)
	for range 2 {
		result := <-results
		err := <-errs
		attempt, ok := result.Effect.CurrentAttempt()
		if err != nil || result.Action != RecoveryWait || result.Effect.State != StateDispatched || !ok ||
			attempt.ProviderRequestID != "rpc-concurrent-inflight" {
			t.Fatalf("concurrent inflight recovery=%+v err=%v", result, err)
		}
	}
}

func TestRepeatedUnknownIdempotencyRecoveryIsBudgetNeutral(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayIdempotencyKey)
	dispatched := durablyDispatchedFixtureEffect(t, fixture, "rpc-idempotency-unknown")
	dispatched.AutomaticRetriesUsed = dispatched.MaxAutomaticRetries
	fixture.repository.mu.Lock()
	fixture.repository.effects[dispatched.Scope.InvocationID.String()] = cloneEffect(dispatched)
	fixture.repository.mu.Unlock()
	uncertain := applyFixtureEvent(t, fixture.gateway, dispatched, Event{
		Kind: EventDispatchFailed, Failure: FailureUnknown, Reason: "ledger lookup required",
	})
	persistFixtureEffect(t, fixture.repository, dispatched, uncertain)
	if uncertain.State != StateUncertain {
		t.Fatalf("exhausted idempotent effect state=%s, want %s", uncertain.State, StateUncertain)
	}
	lookups := 0
	fixture.provider.lookup = func(_ context.Context, query LedgerQuery) (LedgerRecord, error) {
		lookups++
		return LedgerRecord{InvocationID: query.InvocationID, RequestDigest: query.RequestDigest, Status: LedgerUnknown}, nil
	}

	first, err := fixture.gateway.Recover(context.Background(), OpaqueAuthority("renewed"), uncertain)
	if err != nil {
		t.Fatal(err)
	}
	second, err := fixture.gateway.Recover(context.Background(), OpaqueAuthority("renewed"), first.Effect)
	if err != nil {
		t.Fatal(err)
	}
	if lookups != 2 || first.Action != RecoveryInterrupted || second.Action != RecoveryInterrupted ||
		first.Effect.Revision != uncertain.Revision || second.Effect.Revision != uncertain.Revision ||
		first.Effect.EventCount != uncertain.EventCount || second.Effect.EventCount != uncertain.EventCount {
		t.Fatalf("unknown recovery consumed budget: initial=%+v first=%+v second=%+v lookups=%d", uncertain, first, second, lookups)
	}
}

func TestRecoveryRejectsMismatchedFailedProviderRequestIdentity(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-expected-failure")
	fixture.provider.lookup = func(_ context.Context, query LedgerQuery) (LedgerRecord, error) {
		return LedgerRecord{
			InvocationID: query.InvocationID, RequestDigest: query.RequestDigest, Status: LedgerFailed,
			ProviderRequestID: "rpc-different-failure", FailureReason: "external failure",
		}, nil
	}
	_, err := fixture.gateway.Recover(context.Background(), OpaqueAuthority("renewed"), effect)
	if !errors.Is(err, ErrLedgerMismatch) {
		t.Fatalf("mismatched failed ledger error = %v, want %v", err, ErrLedgerMismatch)
	}
}

func TestStaleRecoveryConvergesToCompletedEffect(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	dispatched := durablyDispatchedFixtureEffect(t, fixture, "rpc-stale-recovery")
	committed := applyFixtureEvent(t, fixture.gateway, dispatched, Event{
		Kind: EventCallCommitted, Output: []byte(`{"done":true}`), ExternalCommitID: "commit-stale-recovery",
	})
	persistFixtureEffect(t, fixture.repository, dispatched, committed)
	completed := applyFixtureEvent(t, fixture.gateway, committed, Event{Kind: EventSettlementCompleted})
	persistFixtureEffect(t, fixture.repository, committed, completed)
	fixture.provider.lookup = func(_ context.Context, query LedgerQuery) (LedgerRecord, error) {
		return LedgerRecord{
			InvocationID: query.InvocationID, RequestDigest: query.RequestDigest, Status: LedgerCommitted,
			ProviderRequestID: "rpc-stale-recovery", ExternalCommitID: "commit-stale-recovery", Output: []byte(`{"done":true}`),
		}, nil
	}

	recovered, err := fixture.gateway.Recover(context.Background(), OpaqueAuthority("renewed"), dispatched)
	if err != nil || recovered.Action != RecoverySettled || !sameEffect(recovered.Effect, completed) {
		t.Fatalf("stale recovery=%+v err=%v", recovered, err)
	}
}

func TestStaleSettlementOnlyRecoveryConverges(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	dispatched := durablyDispatchedFixtureEffect(t, fixture, "rpc-stale-settlement-recovery")
	committed := applyFixtureEvent(t, fixture.gateway, dispatched, Event{
		Kind: EventCallCommitted, Output: []byte(`{"done":true}`), ExternalCommitID: "commit-stale-settlement",
	})
	persistFixtureEffect(t, fixture.repository, dispatched, committed)
	completed := applyFixtureEvent(t, fixture.gateway, committed, Event{Kind: EventSettlementCompleted})
	persistFixtureEffect(t, fixture.repository, committed, completed)

	recovered, err := fixture.gateway.Recover(context.Background(), OpaqueAuthority("renewed"), committed)
	if err != nil || recovered.Action != RecoverySettled || !sameEffect(recovered.Effect, completed) {
		t.Fatalf("stale settlement recovery=%+v err=%v", recovered, err)
	}
}

func TestStaleDispatchedRecoveryAdoptsDurableExternalCommitBeforeLedgerIO(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	dispatched := durablyDispatchedFixtureEffect(t, fixture, "rpc-stale-durable-commit")
	committed := applyFixtureEvent(t, fixture.gateway, dispatched, Event{
		Kind: EventCallCommitted, Output: []byte(`{"done":true}`), ExternalCommitID: "commit-stale-durable",
	})
	persistFixtureEffect(t, fixture.repository, dispatched, committed)
	lookups := 0
	fixture.provider.lookup = func(context.Context, LedgerQuery) (LedgerRecord, error) {
		lookups++
		return LedgerRecord{}, ErrLedgerUnavailable
	}

	recovered, err := fixture.gateway.Recover(context.Background(), OpaqueAuthority("renewed"), dispatched)
	if err != nil || recovered.Action != RecoverySettled || recovered.Effect.State != StateCompleted ||
		recovered.Effect.ExternalCommitID != committed.ExternalCommitID {
		t.Fatalf("stale durable commit recovery=%+v err=%v", recovered, err)
	}
	if lookups != 0 {
		t.Fatalf("settlement-only recovery consulted provider ledger %d times", lookups)
	}
}

func TestStaleDispatchedRecoveryAdoptsDurableCancellationIntent(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	dispatched := durablyDispatchedFixtureEffect(t, fixture, "rpc-stale-durable-cancel")
	pending := applyFixtureEvent(t, fixture.gateway, dispatched, Event{Kind: EventCancelRequested})
	persistFixtureEffect(t, fixture.repository, dispatched, pending)
	cancels := 0
	fixture.provider.cancel = func(context.Context, CancelCommand) (CancellationResult, error) {
		cancels++
		return CancellationResult{Status: CancellationAbsent}, nil
	}

	recovered, err := fixture.gateway.Recover(context.Background(), OpaqueAuthority("renewed"), dispatched)
	if err != nil || recovered.Effect.State != StateCancelled {
		t.Fatalf("stale durable cancellation recovery=%+v err=%v", recovered, err)
	}
	if cancels != 1 {
		t.Fatalf("durable cancellation intent dispatched %d cancels", cancels)
	}
}

func TestStaleRecoveryConvergesToDurableRetryPendingWithoutLedgerIO(t *testing.T) {
	fixture := newGatewayFixture(t, ReplaySafe)
	dispatched := durablyDispatchedFixtureEffect(t, fixture, "rpc-stale-retry-pending")
	lookups := 0
	fixture.provider.lookup = func(_ context.Context, query LedgerQuery) (LedgerRecord, error) {
		lookups++
		return LedgerRecord{InvocationID: query.InvocationID, RequestDigest: query.RequestDigest, Status: LedgerAbsent}, nil
	}
	first, err := fixture.gateway.Recover(context.Background(), OpaqueAuthority("renewed"), dispatched)
	if err != nil || first.Action != RecoveryRetry || first.Effect.State != StateRetryPending {
		t.Fatalf("first recovery=%+v err=%v", first, err)
	}
	second, err := fixture.gateway.Recover(context.Background(), OpaqueAuthority("renewed"), dispatched)
	if err != nil || second.Action != RecoveryRetry || !sameEffect(second.Effect, first.Effect) {
		t.Fatalf("stale retry convergence=%+v err=%v", second, err)
	}
	if lookups != 1 {
		t.Fatalf("stale retry recovery repeated provider lookup %d times", lookups)
	}
}

func TestEventBudgetReservesSettlementBeforeProviderDispatch(t *testing.T) {
	fixture := newGatewayFixture(t, ReplaySafe)
	effect := admitFixtureEffect(t, fixture)
	begin := applyFixtureEvent(t, fixture.gateway, effect, Event{Kind: EventBeginDispatch})
	if _, err := fixture.repository.CommitAndClaimDispatch(context.Background(), DispatchClaimRequest{
		ExpectedRevision: effect.Revision, CurrentScope: effect.Scope,
		Previous: effect, Next: begin, Authorization: permitForEffect(begin),
	}); err != nil {
		t.Fatal(err)
	}
	retry := applyFixtureEvent(t, fixture.gateway, begin, Event{
		Kind: EventDispatchFailed, Failure: FailureDefinitelyNotSent, Reason: "not sent",
	})
	persistFixtureEffect(t, fixture.repository, begin, retry)
	// Leave enough room for the old local reserve to commit Begin and the
	// negotiation receipt, but not enough for acceptance plus cancellation and
	// terminal settlement. Provider I/O must still not start.
	retry.EventCount = testBounds().MaxEvents - 5
	retry.Revision = uint64(retry.EventCount) + 1
	fixture.repository.mu.Lock()
	fixture.repository.effects[retry.Scope.InvocationID.String()] = cloneEffect(retry)
	fixture.repository.mu.Unlock()
	starts := 0
	fixture.provider.start = func(context.Context, ProviderCommand) (ProviderStartResult, error) {
		starts++
		return ProviderStartResult{ProviderRequestID: "rpc-budget-overrun", Call: completedCall(`{"unsafe":true}`)}, nil
	}

	_, err := fixture.gateway.Execute(context.Background(), OpaqueAuthority("renewed"), retry, discardSink())
	if !errors.Is(err, ErrEventLimit) {
		t.Fatalf("event budget error = %v, want %v", err, ErrEventLimit)
	}
	if starts != 0 {
		t.Fatalf("provider received %d calls without a settlement event reserve", starts)
	}
	if negotiations := fixture.provider.negotiationCount(); negotiations != 0 {
		t.Fatalf("provider received %d negotiation calls without a full retry-path reserve", negotiations)
	}
	stored, loadErr := fixture.repository.Load(context.Background(), retry.Scope.InvocationID)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if !sameEffect(stored.Effect, retry) {
		t.Fatalf("event-limit rejection mutated durable state: %+v", stored.Effect)
	}
}

func TestFinalUnknownDispatchFailureReservesExplicitCancellationPath(t *testing.T) {
	for _, policy := range []ReplayPolicy{ReplaySafe, ReplayIdempotencyKey, ReplayNever, ReplayConfirm} {
		t.Run(string(policy), func(t *testing.T) {
			fixture := newGatewayFixture(t, policy)
			effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-final-unknown-budget")
			effect.AutomaticRetriesUsed = effect.MaxAutomaticRetries
			effect.ConfirmationRetriesUsed = effect.MaxConfirmationRetries
			transitionEvents := uint32(5)
			successorEvents := uint32(4)
			dispatchEvents := uint32(6)
			if policy == ReplayConfirm {
				transitionEvents = 7
				successorEvents = 6
				dispatchEvents = 7
			}
			if reserve := minimumRemainingEvents(effect); reserve != dispatchEvents {
				t.Fatalf("final dispatch reserve=%d, want %d", reserve, dispatchEvents)
			}
			effect.EventCount = fixture.gateway.bounds.MaxEvents - (transitionEvents - 1)
			effect.Revision = uint64(effect.EventCount) + 1
			_, err := fixture.gateway.Apply(effect, Event{
				ExpectedRevision: effect.Revision, Kind: EventDispatchFailed,
				Failure: FailureUnknown, Reason: "final provider outcome unknown",
			})
			if !errors.Is(err, ErrEventLimit) {
				t.Fatalf("short tail error=%v, want %v", err, ErrEventLimit)
			}
			effect.EventCount = fixture.gateway.bounds.MaxEvents - transitionEvents
			effect.Revision = uint64(effect.EventCount) + 1
			transition, err := fixture.gateway.Apply(effect, Event{
				ExpectedRevision: effect.Revision, Kind: EventDispatchFailed,
				Failure: FailureUnknown, Reason: "final provider outcome unknown",
			})
			if err != nil {
				t.Fatalf("exact tail rejected: %v", err)
			}
			if minimumRemainingEvents(transition.Effect) != successorEvents {
				t.Fatalf("unresolved successor reserve=%d, want %d",
					minimumRemainingEvents(transition.Effect), successorEvents)
			}
		})
	}
}

func TestNegotiationReceiptMustCommitBeforeProviderStart(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	repository := &negotiationCommitErrorRepository{
		MemoryRepository: NewMemoryRepository(), err: errors.New("negotiation receipt commit failed"),
	}
	gateway, err := NewGateway(Configuration{
		Bounds: testBounds(), Servers: []ServerRegistration{fixture.server}, Tools: []ToolRegistration{fixture.tool},
		AllowReferenceMemory: true,
	}, Dependencies{
		Authority: fixture.authority, Authorizer: fixture.authorizer, Credentials: fixture.credentials,
		Repository: repository, Audit: fixture.gateway.audit, Providers: map[string]Provider{"stdio": fixture.provider},
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.gateway = gateway
	effect := admitFixtureEffect(t, fixture)
	fixture.provider.start = func(context.Context, ProviderCommand) (ProviderStartResult, error) {
		return ProviderStartResult{ProviderRequestID: "must-not-dispatch", Call: completedCall(`{"unsafe":true}`)}, nil
	}

	_, err = fixture.gateway.Execute(context.Background(), OpaqueAuthority("renewed"), effect, discardSink())
	if !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("negotiation commit error = %v, want %v", err, ErrStoreUnavailable)
	}
	if got := fixture.provider.startCount(); got != 0 {
		t.Fatalf("provider Start ran %d times before negotiation receipt commit", got)
	}
}

func TestCancellationWinningAfterNegotiationCommitFencesProviderStart(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	repository := &negotiationBarrierRepository{
		MemoryRepository: NewMemoryRepository(), committed: make(chan struct{}), release: make(chan struct{}),
	}
	gateway, err := NewGateway(Configuration{
		Bounds: testBounds(), Servers: []ServerRegistration{fixture.server}, Tools: []ToolRegistration{fixture.tool},
		AllowReferenceMemory: true,
	}, Dependencies{
		Authority: fixture.authority, Authorizer: fixture.authorizer, Credentials: fixture.credentials,
		Repository: repository, Audit: fixture.gateway.audit, Providers: map[string]Provider{"stdio": fixture.provider},
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.gateway = gateway
	effect := admitFixtureEffect(t, fixture)
	fixture.provider.start = func(context.Context, ProviderCommand) (ProviderStartResult, error) {
		return ProviderStartResult{ProviderRequestID: "must-not-start-after-cancel", Call: completedCall(`{"unsafe":true}`)}, nil
	}
	fixture.provider.cancel = func(context.Context, CancelCommand) (CancellationResult, error) {
		return CancellationResult{Status: CancellationAbsent}, nil
	}
	type executeResult struct {
		effect Effect
		err    error
	}
	executed := make(chan executeResult, 1)
	go func() {
		result, executeErr := gateway.Execute(context.Background(), OpaqueAuthority("renewed"), effect, discardSink())
		executed <- executeResult{effect: result, err: executeErr}
	}()
	<-repository.committed
	stored, err := repository.Load(context.Background(), effect.Scope.InvocationID)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, err := gateway.Cancel(context.Background(), OpaqueAuthority("renewed"), stored.Effect)
	if err != nil || cancelled.State != StateCancelled {
		t.Fatalf("barrier cancellation state=%s err=%v", cancelled.State, err)
	}
	close(repository.release)
	result := <-executed
	if got := fixture.provider.startCount(); got != 0 {
		t.Fatalf("stale Execute called Provider.Start %d times after cancellation won", got)
	}
	if result.err != nil || result.effect.State != StateCancelled {
		t.Fatalf("stale Execute did not converge to cancellation: state=%s err=%v", result.effect.State, result.err)
	}
}

func TestRecoveryWinningAfterNegotiationCommitFencesProviderStart(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	repository := &negotiationBarrierRepository{
		MemoryRepository: NewMemoryRepository(), committed: make(chan struct{}), release: make(chan struct{}),
	}
	gateway, err := NewGateway(Configuration{
		Bounds: testBounds(), Servers: []ServerRegistration{fixture.server}, Tools: []ToolRegistration{fixture.tool},
		AllowReferenceMemory: true,
	}, Dependencies{
		Authority: fixture.authority, Authorizer: fixture.authorizer, Credentials: fixture.credentials,
		Repository: repository, Audit: fixture.gateway.audit, Providers: map[string]Provider{"stdio": fixture.provider},
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.gateway = gateway
	effect := admitFixtureEffect(t, fixture)
	fixture.provider.start = func(context.Context, ProviderCommand) (ProviderStartResult, error) {
		return ProviderStartResult{ProviderRequestID: "must-not-start-after-recovery", Call: completedCall(`{"unsafe":true}`)}, nil
	}
	fixture.provider.lookup = func(_ context.Context, query LedgerQuery) (LedgerRecord, error) {
		return LedgerRecord{InvocationID: query.InvocationID, RequestDigest: query.RequestDigest, Status: LedgerAbsent}, nil
	}
	type executeResult struct {
		effect Effect
		err    error
	}
	executed := make(chan executeResult, 1)
	go func() {
		result, executeErr := gateway.Execute(context.Background(), OpaqueAuthority("renewed"), effect, discardSink())
		executed <- executeResult{effect: result, err: executeErr}
	}()
	<-repository.committed
	stored, err := repository.Load(context.Background(), effect.Scope.InvocationID)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := gateway.Recover(context.Background(), OpaqueAuthority("renewed"), stored.Effect)
	if err != nil || (recovered.Effect.State != StateFailed && recovered.Effect.State != StateRetryPending) {
		t.Fatalf("barrier recovery state=%s err=%v", recovered.Effect.State, err)
	}
	close(repository.release)
	result := <-executed
	if got := fixture.provider.startCount(); got != 0 {
		t.Fatalf("stale Execute called Provider.Start %d times after recovery won", got)
	}
	if result.err != nil || result.effect.State != recovered.Effect.State {
		t.Fatalf("stale Execute did not converge to recovery: state=%s err=%v", result.effect.State, result.err)
	}
}

func TestActiveProviderStartDoesNotDelayDurableCancellationIntent(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	now := time.Unix(1_900_000_000, 0)
	fixture.repository.now = func() time.Time { return now }
	effect, start := activelyClaimedProviderStartFixture(t, fixture)
	cancelCalls := 0
	fixture.provider.cancel = func(_ context.Context, command CancelCommand) (CancellationResult, error) {
		cancelCalls++
		if command.Start != start || command.Cancellation.Start != start {
			t.Fatalf("cancel did not receive the exact active start proof: command=%+v", command)
		}
		stored, err := fixture.repository.Load(context.Background(), effect.Scope.InvocationID)
		if err != nil {
			t.Fatal(err)
		}
		if stored.Effect.State != StateCancellationPending {
			t.Fatalf("provider cancel ran before intent commit: state=%s", stored.Effect.State)
		}
		return CancellationResult{Status: CancellationUnknown}, nil
	}

	result, err := fixture.gateway.Cancel(context.Background(), OpaqueAuthority("renewed"), effect)
	if err != nil {
		t.Fatal(err)
	}
	if cancelCalls != 1 || result.State != StateUncertain {
		t.Fatalf("active-start cancellation calls=%d state=%s", cancelCalls, result.State)
	}
}

func TestExpiredProviderStartProofSurvivesRecoveryAndCancellation(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	now := time.Unix(1_900_000_000, 0)
	fixture.repository.now = func() time.Time { return now }
	effect, start := activelyClaimedProviderStartFixture(t, fixture)
	now = now.Add(testBounds().CancelTimeout + time.Nanosecond)
	fixture.provider.lookup = func(_ context.Context, query LedgerQuery) (LedgerRecord, error) {
		return LedgerRecord{
			InvocationID: query.InvocationID, RequestDigest: query.RequestDigest,
			Status: LedgerInflight, ProviderRequestID: "rpc-lost-start-response",
		}, nil
	}

	recovered, err := fixture.gateway.Recover(context.Background(), OpaqueAuthority("renewed"), effect)
	if err != nil || recovered.Action != RecoveryWait || recovered.Effect.State != StateDispatched {
		t.Fatalf("lost start response recovery=%+v err=%v", recovered, err)
	}
	cancelCalls := 0
	fixture.provider.cancel = func(_ context.Context, command CancelCommand) (CancellationResult, error) {
		cancelCalls++
		if command.Start != start || command.Cancellation.Start != start {
			t.Fatalf("revoked start proof was discarded: command=%+v", command)
		}
		return CancellationResult{Status: CancellationUnknown}, nil
	}
	result, err := fixture.gateway.Cancel(context.Background(), OpaqueAuthority("renewed"), recovered.Effect)
	if err != nil {
		t.Fatal(err)
	}
	if cancelCalls != 1 || result.State != StateUncertain {
		t.Fatalf("post-recovery cancellation calls=%d state=%s", cancelCalls, result.State)
	}
}

func TestActiveProviderStartRecoveryWaitsWithoutTrustingLedgerAbsence(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	now := time.Unix(1_900_000_000, 0)
	fixture.repository.now = func() time.Time { return now }
	effect, _ := activelyClaimedProviderStartFixture(t, fixture)
	lookups := 0
	fixture.provider.lookup = func(_ context.Context, query LedgerQuery) (LedgerRecord, error) {
		lookups++
		return LedgerRecord{
			InvocationID: query.InvocationID, RequestDigest: query.RequestDigest, Status: LedgerAbsent,
		}, nil
	}

	recovered, err := fixture.gateway.Recover(context.Background(), OpaqueAuthority("renewed"), effect)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Action != RecoveryWait || !sameEffect(recovered.Effect, effect) || lookups != 0 {
		t.Fatalf("active start was resolved by a racy lookup: result=%+v lookups=%d", recovered, lookups)
	}
}

func TestContextCancellationDuringNegotiationOrStartIsDurablyCancelled(t *testing.T) {
	t.Run("negotiation", func(t *testing.T) {
		fixture := newGatewayFixture(t, ReplayNever)
		effect := admitFixtureEffect(t, fixture)
		ctx, cancel := context.WithCancel(context.Background())
		fixture.provider.negotiate = func(context.Context, NegotiationCommand) (StartNegotiationReceipt, error) {
			cancel()
			return StartNegotiationReceipt{}, context.Canceled
		}
		providerCancels := 0
		fixture.provider.cancel = func(context.Context, CancelCommand) (CancellationResult, error) {
			providerCancels++
			return CancellationResult{Status: CancellationUnknown}, nil
		}
		result, err := fixture.gateway.Execute(ctx, OpaqueAuthority("renewed"), effect, discardSink())
		if !errors.Is(err, context.Canceled) || result.State != StateCancelled ||
			!result.CancellationRequested || providerCancels != 0 {
			t.Fatalf("negotiation cancellation state=%s requested=%v provider-cancels=%d err=%v",
				result.State, result.CancellationRequested, providerCancels, err)
		}
		stored, loadErr := fixture.repository.Load(context.Background(), effect.Scope.InvocationID)
		if loadErr != nil || !sameEffect(stored.Effect, result) {
			t.Fatalf("negotiation cancellation was not durable: stored=%+v err=%v", stored, loadErr)
		}
	})

	t.Run("start", func(t *testing.T) {
		fixture := newGatewayFixture(t, ReplayNever)
		effect := admitFixtureEffect(t, fixture)
		ctx, cancel := context.WithCancel(context.Background())
		fixture.provider.start = func(context.Context, ProviderCommand) (ProviderStartResult, error) {
			cancel()
			return ProviderStartResult{}, context.Canceled
		}
		providerCancels := 0
		fixture.provider.cancel = func(_ context.Context, command CancelCommand) (CancellationResult, error) {
			providerCancels++
			if command.Start == (ProviderStartPermit{}) {
				t.Fatal("start cancellation discarded the provider admission proof")
			}
			return CancellationResult{Status: CancellationUnknown}, nil
		}
		result, err := fixture.gateway.Execute(ctx, OpaqueAuthority("renewed"), effect, discardSink())
		if !errors.Is(err, context.Canceled) || result.State != StateUncertain ||
			!result.CancellationRequested || providerCancels != 1 {
			t.Fatalf("start cancellation state=%s requested=%v provider-cancels=%d err=%v",
				result.State, result.CancellationRequested, providerCancels, err)
		}
		stored, loadErr := fixture.repository.Load(context.Background(), effect.Scope.InvocationID)
		if loadErr != nil || !sameEffect(stored.Effect, result) {
			t.Fatalf("start cancellation was not durable: stored=%+v err=%v", stored, loadErr)
		}
	})
}

func TestPreventedProviderStartTombstoneSurvivesRecoveryCrash(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	effect := admitFixtureEffect(t, fixture)
	begin := applyFixtureEvent(t, fixture.gateway, effect, Event{Kind: EventBeginDispatch})
	_, err := fixture.repository.CommitAndClaimDispatch(context.Background(), DispatchClaimRequest{
		ExpectedRevision: effect.Revision, CurrentScope: effect.Scope, Previous: effect,
		Next: begin, Authorization: permitForEffect(begin),
	})
	if err != nil {
		t.Fatal(err)
	}
	negotiated := negotiateFixtureEffect(t, fixture.gateway, begin)
	persistFixtureEffect(t, fixture.repository, begin, negotiated)
	resolved, err := fixture.repository.ResolveProviderStart(context.Background(), ProviderStartResolutionRequest{
		CurrentScope: negotiated.Scope, Effect: negotiated,
	})
	if err != nil || !resolved.Durable || resolved.Present {
		t.Fatalf("initial prevented resolution=%+v err=%v", resolved, err)
	}

	recovered, err := fixture.gateway.Recover(context.Background(), OpaqueAuthority("renewed"), negotiated)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Effect.State != StateRetryPending || recovered.Action != RecoveryRetry {
		t.Fatalf("prevented start tombstone recovery=%+v", recovered)
	}
}

func TestNegotiationGenerationBindsProviderLifecycleCommands(t *testing.T) {
	t.Run("start", func(t *testing.T) {
		fixture := newGatewayFixture(t, ReplayNever)
		effect := admitFixtureEffect(t, fixture)
		fixture.provider.negotiate = func(_ context.Context, command NegotiationCommand) (StartNegotiationReceipt, error) {
			receipt := StartNegotiationReceipt{
				Durable: true, Scope: command.Scope, Server: command.Server,
				InvocationID: command.InvocationID, RequestDigest: command.RequestDigest, Attempt: command.Attempt,
				NegotiatedProtocolVersion: command.Server.ProtocolVersion, Affinity: command.Server.Affinity,
				SupportsInvocationLedger: true, SupportsIdempotencyKey: true, ConnectionGeneration: 7,
			}
			return receipt, nil
		}
		fixture.provider.start = func(_ context.Context, command ProviderCommand) (ProviderStartResult, error) {
			stored, err := fixture.repository.Load(context.Background(), command.InvocationID)
			if err != nil {
				t.Fatal(err)
			}
			attempt, ok := stored.Effect.CurrentAttempt()
			if !ok || stored.Effect.State != StateDispatching || command.Negotiation.ConnectionGeneration != 7 ||
				attempt.Negotiation != command.Negotiation {
				t.Fatalf("Start did not receive the committed negotiation: stored=%+v command=%+v", attempt, command)
			}
			return ProviderStartResult{ProviderRequestID: "rpc-generation-start", Call: completedCall(`{"ok":true}`)}, nil
		}
		completed, err := fixture.gateway.Execute(context.Background(), OpaqueAuthority("renewed"), effect, discardSink())
		if err != nil || completed.State != StateCompleted {
			t.Fatalf("negotiated start result=%s err=%v", completed.State, err)
		}
	})

	t.Run("cancel", func(t *testing.T) {
		fixture := newGatewayFixture(t, ReplayNever)
		effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-generation-cancel")
		attempt, _ := effect.CurrentAttempt()
		fixture.provider.cancel = func(_ context.Context, command CancelCommand) (CancellationResult, error) {
			if command.Negotiation != attempt.Negotiation {
				t.Fatalf("Cancel negotiation=%+v, want %+v", command.Negotiation, attempt.Negotiation)
			}
			return CancellationResult{Status: CancellationAbsent}, nil
		}
		cancelled, err := fixture.gateway.Cancel(context.Background(), OpaqueAuthority("renewed"), effect)
		if err != nil || cancelled.State != StateCancelled {
			t.Fatalf("negotiated cancel result=%s err=%v", cancelled.State, err)
		}
	})

	t.Run("lookup", func(t *testing.T) {
		fixture := newGatewayFixture(t, ReplayNever)
		effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-generation-lookup")
		attempt, _ := effect.CurrentAttempt()
		fixture.provider.lookup = func(_ context.Context, query LedgerQuery) (LedgerRecord, error) {
			if query.Negotiation != attempt.Negotiation {
				t.Fatalf("Lookup negotiation=%+v, want %+v", query.Negotiation, attempt.Negotiation)
			}
			return LedgerRecord{
				InvocationID: query.InvocationID, RequestDigest: query.RequestDigest,
				Status: LedgerInflight, ProviderRequestID: "rpc-generation-lookup",
			}, nil
		}
		recovered, err := fixture.gateway.Recover(context.Background(), OpaqueAuthority("renewed"), effect)
		if err != nil || recovered.Action != RecoveryWait {
			t.Fatalf("negotiated lookup result=%+v err=%v", recovered, err)
		}
	})
}

func TestNegotiateRejectsActualReceiptMismatchBeforeStart(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	effect := admitFixtureEffect(t, fixture)
	fixture.provider.negotiate = func(_ context.Context, command NegotiationCommand) (StartNegotiationReceipt, error) {
		return StartNegotiationReceipt{
			Durable: true, Scope: command.Scope, Server: command.Server,
			InvocationID: command.InvocationID, RequestDigest: command.RequestDigest, Attempt: command.Attempt,
			NegotiatedProtocolVersion: "2024-11-05", Affinity: command.Server.Affinity,
			SupportsInvocationLedger: true, SupportsIdempotencyKey: true, ConnectionGeneration: 1,
		}, nil
	}
	fixture.provider.start = func(context.Context, ProviderCommand) (ProviderStartResult, error) {
		t.Fatal("provider Start must not run for an uncommitted mismatched negotiation")
		return ProviderStartResult{}, nil
	}

	result, err := fixture.gateway.Execute(context.Background(), OpaqueAuthority("renewed"), effect, discardSink())
	if !errors.Is(err, ErrProtocolMismatch) {
		t.Fatalf("actual negotiation mismatch error = %v, want %v", err, ErrProtocolMismatch)
	}
	if result.State != StateRetryPending || fixture.provider.startCount() != 0 {
		t.Fatalf("mismatched negotiation result=%s starts=%d", result.State, fixture.provider.startCount())
	}
	attempt, ok := result.CurrentAttempt()
	if !ok || attempt.ProviderRequestID != "" || attempt.Negotiation != (StartNegotiationReceipt{}) {
		t.Fatalf("mismatched negotiation invented dispatch evidence: %+v", result.Attempts)
	}
}

func TestUncertainEffectBlocksNewActiveEffectUntilRecovery(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	first := admitFixtureEffect(t, fixture)
	fixture.provider.start = func(context.Context, ProviderCommand) (ProviderStartResult, error) {
		return ProviderStartResult{
			ProviderRequestID: "rpc-old-uncertain",
			Call: &functionCall{next: func(context.Context) (ProviderEvent, error) {
				return ProviderEvent{}, errors.New("server died")
			}},
		}, nil
	}
	uncertain, err := fixture.gateway.Execute(context.Background(), OpaqueAuthority("turn-secret"), first, discardSink())
	if err != nil || uncertain.State != StateUncertain {
		t.Fatalf("first effect state=%s err=%v", uncertain.State, err)
	}
	secondCall := CallRequest{ServerID: first.ServerID, ToolName: first.ToolName, Input: mapInput("new active")}
	secondDigest, err := CallRequestDigest(secondCall, testBounds())
	if err != nil {
		t.Fatal(err)
	}
	_, err = fixture.gateway.Admit(context.Background(), AdmissionRequest{
		Authority: OpaqueAuthority("turn-secret"), EffectID: mustID(t, identity.Effect),
		InvocationID: mustID(t, identity.Invocation), RequestDigest: secondDigest, Call: secondCall,
	})
	if !errors.Is(err, ErrEffectInFlight) {
		t.Fatalf("uncertain effect allowed new active admission: err=%v", err)
	}
	fixture.provider.mu.Lock()
	fixture.provider.lookup = func(_ context.Context, query LedgerQuery) (LedgerRecord, error) {
		return LedgerRecord{
			InvocationID: query.InvocationID, RequestDigest: query.RequestDigest, Status: LedgerCommitted,
			ProviderRequestID: "rpc-old-uncertain", ExternalCommitID: "late-commit", Output: []byte(`{"late":true}`),
		}, nil
	}
	fixture.provider.mu.Unlock()
	recovered, err := fixture.gateway.Recover(context.Background(), OpaqueAuthority("renewed"), uncertain)
	if err != nil || recovered.Action != RecoverySettled || recovered.Effect.State != StateCompleted {
		t.Fatalf("late recovery did not settle protected effect: result=%+v err=%v", recovered, err)
	}
}

func mapInput(value string) canonical.Value {
	return canonical.Map{"value": value}
}

func activelyClaimedProviderStartFixture(t *testing.T, fixture gatewayFixture) (Effect, ProviderStartPermit) {
	t.Helper()
	effect := admitFixtureEffect(t, fixture)
	begin := applyFixtureEvent(t, fixture.gateway, effect, Event{Kind: EventBeginDispatch})
	dispatch, err := fixture.repository.CommitAndClaimDispatch(context.Background(), DispatchClaimRequest{
		ExpectedRevision: effect.Revision, CurrentScope: effect.Scope, Previous: effect,
		Next: begin, Authorization: permitForEffect(begin),
	})
	if err != nil {
		t.Fatal(err)
	}
	negotiated := negotiateFixtureEffect(t, fixture.gateway, begin)
	persistFixtureEffect(t, fixture.repository, begin, negotiated)
	start, err := fixture.repository.ClaimProviderStart(context.Background(), ProviderStartClaimRequest{
		CurrentScope: effect.Scope, Effect: negotiated, Dispatch: dispatch, Lease: testBounds().CancelTimeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	return negotiated, start
}

func expireProviderStartForRecovery(
	t *testing.T,
	fixture gatewayFixture,
	effect Effect,
	dispatch DispatchPermit,
) {
	t.Helper()
	now := time.Unix(1_900_000_000, 0)
	fixture.repository.now = func() time.Time { return now }
	if _, err := fixture.repository.ClaimProviderStart(context.Background(), ProviderStartClaimRequest{
		CurrentScope: effect.Scope, Effect: effect, Dispatch: dispatch, Lease: testBounds().CancelTimeout,
	}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(testBounds().CancelTimeout + time.Nanosecond)
}
