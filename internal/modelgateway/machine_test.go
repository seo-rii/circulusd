package modelgateway

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestModelEffectDispatchStreamAndSettlement(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)

	begin := apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch})
	if begin.Effect.State != StateDispatching || begin.Effect.Attempt != 1 || begin.Dispatch == nil {
		t.Fatalf("begin dispatch = %#v", begin)
	}
	if begin.Dispatch.EffectID != fixture.scope.EffectID || begin.Dispatch.InvocationID != fixture.scope.InvocationID || begin.Dispatch.RequestDigest != effect.RequestDigest || begin.Dispatch.Attempt != 1 {
		t.Fatalf("dispatch command = %#v", begin.Dispatch)
	}

	accepted := apply(t, gateway, begin.Effect, Event{ExpectedRevision: begin.Effect.Revision, Kind: EventProviderAccepted, ProviderRequestID: "provider-request-42"})
	if accepted.Effect.State != StateDispatched || accepted.Effect.ProviderRequestID != "provider-request-42" {
		t.Fatalf("provider accepted = %#v", accepted.Effect)
	}
	delta := apply(t, gateway, accepted.Effect, Event{ExpectedRevision: accepted.Effect.Revision, Kind: EventDelta, Delta: "hello"})
	if delta.Effect.State != StateStreaming || !delta.Effect.PartialOutput || delta.Effect.StreamBytes != 5 {
		t.Fatalf("delta = %#v", delta.Effect)
	}
	completed := apply(t, gateway, delta.Effect, Event{
		ExpectedRevision: delta.Effect.Revision,
		Kind:             EventResponseCompleted,
		Response:         &ModelResponse{Text: "hello world", FinishReason: "stop", Usage: Usage{InputTokens: 11, OutputTokens: 2}},
	})
	if completed.Effect.State != StateCompleted || completed.Effect.Response == nil || completed.Effect.Response.Text != "hello world" {
		t.Fatalf("completed = %#v", completed.Effect)
	}

	settlement, err := gateway.AuthorizeSettlement(context.Background(), completed.Effect, OpaqueAuthority("renewed-authority"))
	if err != nil {
		t.Fatalf("AuthorizeSettlement() error = %v", err)
	}
	if settlement.Outcome != OutcomeCompleted || settlement.ProviderRequestID != "provider-request-42" || settlement.Response == nil || settlement.PartialOutput {
		t.Fatalf("settlement = %#v", settlement)
	}
	if fixture.authority.settlements != 1 || fixture.authority.lastSettlement.EffectID != fixture.scope.EffectID || fixture.authority.lastSettlement.Generations != fixture.scope.Generations {
		t.Fatalf("settlement authority check = %#v", fixture.authority.lastSettlement)
	}
	if settlement.QuotaReceipt.Disposition != QuotaDispositionConsume || settlement.QuotaReceipt.Usage != completed.Effect.Response.Usage || !settlement.QuotaReceipt.Durable {
		t.Fatalf("completed quota settlement = %#v", settlement.QuotaReceipt)
	}
	replayed, err := gateway.AuthorizeSettlement(context.Background(), completed.Effect, OpaqueAuthority("renewed-authority"))
	if err != nil || replayed.QuotaReceipt != settlement.QuotaReceipt || fixture.quota.settlements != 1 {
		t.Fatalf("idempotent quota settlement = %#v, %v; mutations=%d", replayed.QuotaReceipt, err, fixture.quota.settlements)
	}
}

func TestCancelledAndUncertainOutcomesReleaseOrHoldQuota(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		terminal func(*testing.T, *Gateway, Effect) Effect
		want     QuotaDisposition
	}{
		{
			name: "cancelled before dispatch",
			terminal: func(t *testing.T, gateway *Gateway, effect Effect) Effect {
				return apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventCancelRequested}).Effect
			},
			want: QuotaDispositionRelease,
		},
		{
			name: "unknown dispatch",
			terminal: func(t *testing.T, gateway *Gateway, effect Effect) Effect {
				effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch}).Effect
				return apply(t, gateway, effect, Event{
					ExpectedRevision: effect.Revision, Kind: EventDispatchFailed,
					Failure: FailureTransportUnknown, Reason: "write acknowledgement lost",
				}).Effect
			},
			want: QuotaDispositionHold,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFixture(t)
			gateway := fixture.gateway(t)
			terminal := test.terminal(t, gateway, fixture.admit(t, gateway))
			settlement, err := gateway.AuthorizeSettlement(context.Background(), terminal, OpaqueAuthority("renewed"))
			if err != nil {
				t.Fatalf("AuthorizeSettlement() error = %v", err)
			}
			if settlement.QuotaReceipt.Disposition != test.want || !settlement.QuotaReceipt.Durable {
				t.Fatalf("quota settlement = %#v, want %q", settlement.QuotaReceipt, test.want)
			}
		})
	}
}

func TestPreDispatchFailureCanRetryOnlyWithinBound(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)

	first := apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch})
	retry := apply(t, gateway, first.Effect, Event{ExpectedRevision: first.Effect.Revision, Kind: EventDispatchFailed, Failure: FailurePreDispatch, Reason: "dial refused"})
	if retry.Effect.State != StateRetryPending || retry.Effect.Attempt != 1 {
		t.Fatalf("first failure = %#v", retry.Effect)
	}
	second := apply(t, gateway, retry.Effect, Event{ExpectedRevision: retry.Effect.Revision, Kind: EventBeginDispatch})
	if second.Dispatch == nil || second.Dispatch.Attempt != 2 {
		t.Fatalf("second dispatch = %#v", second)
	}
	exhausted := apply(t, gateway, second.Effect, Event{ExpectedRevision: second.Effect.Revision, Kind: EventDispatchFailed, Failure: FailurePreDispatch, Reason: "still refused"})
	if exhausted.Effect.State != StateFailed || exhausted.Effect.Outcome != OutcomeFailed {
		t.Fatalf("exhausted = %#v", exhausted.Effect)
	}
	if _, err := gateway.Apply(exhausted.Effect, Event{ExpectedRevision: exhausted.Effect.Revision, Kind: EventBeginDispatch}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("retry exhausted Apply() error = %v, want ErrInvalidTransition", err)
	}
}

func TestRetryPendingCancellationProducesASettleableSnapshot(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch}).Effect
	effect = apply(t, gateway, effect, Event{
		ExpectedRevision: effect.Revision, Kind: EventDispatchFailed,
		Failure: FailurePreDispatch, Reason: "dial refused",
	}).Effect
	cancelled := apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventCancelRequested}).Effect

	if cancelled.State != StateCancelled || cancelled.FailureReason != "" {
		t.Fatalf("cancelled retry = %#v", cancelled)
	}
	if _, err := gateway.AuthorizeSettlement(context.Background(), cancelled, OpaqueAuthority("renewed")); err != nil {
		t.Fatalf("AuthorizeSettlement(cancelled retry) error = %v", err)
	}
}

func TestPartialStreamFailureIsUncertainAndNeverAutomaticallyRetried(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch}).Effect
	effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventProviderAccepted, ProviderRequestID: "req-1"}).Effect
	effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventDelta, Delta: "partial"}).Effect
	failed := apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventDispatchFailed, Failure: FailureTransportUnknown, Reason: "connection reset"})

	if failed.Effect.State != StateUncertain || failed.Effect.Outcome != OutcomeUncertain || !failed.Effect.PartialOutput {
		t.Fatalf("partial failure = %#v", failed.Effect)
	}
	if _, err := gateway.Apply(failed.Effect, Event{ExpectedRevision: failed.Effect.Revision, Kind: EventBeginDispatch}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("uncertain retry error = %v, want ErrInvalidTransition", err)
	}
	settlement, err := gateway.AuthorizeSettlement(context.Background(), failed.Effect, OpaqueAuthority("renewed"))
	if err != nil {
		t.Fatalf("AuthorizeSettlement() error = %v", err)
	}
	if !settlement.PartialOutput || !settlement.NeedsConfirmation || settlement.Response != nil {
		t.Fatalf("uncertain settlement = %#v", settlement)
	}
}

func TestUnknownFailureAfterProviderAcceptanceIsUncertain(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch}).Effect
	effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventProviderAccepted, ProviderRequestID: "req-accepted"}).Effect
	effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventDispatchFailed, Failure: FailureTransportUnknown, Reason: "timeout"}).Effect
	if effect.State != StateUncertain || effect.ProviderRequestID != "req-accepted" {
		t.Fatalf("unknown post-accept failure = %#v", effect)
	}
}

func TestCancellationClassifiesDispatchUncertaintyConservatively(t *testing.T) {
	t.Parallel()
	t.Run("before dispatch", func(t *testing.T) {
		fixture := newFixture(t)
		gateway := fixture.gateway(t)
		effect := fixture.admit(t, gateway)
		cancelled := apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventCancelRequested})
		if cancelled.Effect.State != StateCancelled || cancelled.Effect.Outcome != OutcomeCancelled || cancelled.Cancel != nil {
			t.Fatalf("cancel before dispatch = %#v", cancelled)
		}
	})
	t.Run("dispatch definitely prevented", func(t *testing.T) {
		fixture := newFixture(t)
		gateway := fixture.gateway(t)
		effect := fixture.admit(t, gateway)
		begin := apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch})
		if _, err := fixture.dispatches.CommitAndClaimDispatch(context.Background(), DispatchCommitRequest{
			ExpectedRevision: effect.Revision, CurrentScope: effect.Scope, Effect: begin.Effect, Command: *begin.Dispatch,
		}); err != nil {
			t.Fatalf("CommitAndClaimDispatch() error = %v", err)
		}
		requested := apply(t, gateway, begin.Effect, Event{ExpectedRevision: begin.Effect.Revision, Kind: EventCancelRequested})
		if requested.Effect.State != StateCancellationPending || requested.Cancel == nil {
			t.Fatalf("cancel requested = %#v", requested)
		}
		execution, err := gateway.ExecuteCancel(context.Background(), OpaqueAuthority("renewed"), requested)
		if err != nil || !execution.Permit.DispatchPrevented {
			t.Fatalf("ExecuteCancel() = %#v, %v", execution, err)
		}
		resolved := apply(t, gateway, execution.Effect, execution.Resolution)
		if resolved.Effect.State != StateCancelled {
			t.Fatalf("prevented cancellation = %#v", resolved.Effect)
		}
	})
	t.Run("accepted request remains uncertain", func(t *testing.T) {
		fixture := newFixture(t)
		gateway := fixture.gateway(t)
		effect := fixture.admit(t, gateway)
		effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch}).Effect
		effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventProviderAccepted, ProviderRequestID: "req-cancel"}).Effect
		effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventCancelRequested}).Effect
		effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventCancellationResolved, DispatchPrevented: false}).Effect
		if effect.State != StateUncertain || effect.Outcome != OutcomeUncertain {
			t.Fatalf("accepted cancellation = %#v", effect)
		}
	})
}

func TestApplyIsDeterministicAndRevisionFenced(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	event := Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch}
	left, err := gateway.Apply(effect, event)
	if err != nil {
		t.Fatalf("Apply(left) error = %v", err)
	}
	right, err := gateway.Apply(effect, event)
	if err != nil {
		t.Fatalf("Apply(right) error = %v", err)
	}
	if !reflect.DeepEqual(left, right) {
		t.Fatalf("Apply() is nondeterministic:\nleft=%#v\nright=%#v", left, right)
	}
	if _, err := gateway.Apply(effect, Event{ExpectedRevision: effect.Revision + 1, Kind: EventBeginDispatch}); !errors.Is(err, ErrConcurrentTransition) {
		t.Fatalf("Apply(stale) error = %v, want ErrConcurrentTransition", err)
	}
}

func TestApplyRejectsOversizedOrOutOfOrderProviderEventsWithoutMutation(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch}).Effect

	tests := []Event{
		{ExpectedRevision: effect.Revision, Kind: EventProviderAccepted, ProviderRequestID: "provider-request-id-that-is-too-long"},
		{ExpectedRevision: effect.Revision, Kind: EventDelta, Delta: "before acceptance"},
		{ExpectedRevision: effect.Revision, Kind: EventDispatchFailed, Failure: FailurePreDispatch, Reason: "reason that is much too long for the configured bound"},
	}
	for _, event := range tests {
		before := effect
		if _, err := gateway.Apply(effect, event); err == nil {
			t.Fatalf("Apply(%#v) error = nil", event)
		}
		if !reflect.DeepEqual(effect, before) {
			t.Fatalf("Apply(%#v) mutated input", event)
		}
	}
}

func TestApplyRejectsCorruptedDurableSnapshotBeforeEmittingACommand(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*Effect)
	}{
		{name: "oversized restored input", mutate: func(effect *Effect) {
			effect.Request.Messages[0].Content = string(make([]byte, 65))
		}},
		{name: "restored request digest mismatch", mutate: func(effect *Effect) {
			effect.Request.Messages[0].Content = "different but still bounded"
		}},
		{name: "inconsistent outcome", mutate: func(effect *Effect) {
			effect.Outcome = OutcomeCompleted
		}},
		{name: "inconsistent revision", mutate: func(effect *Effect) {
			effect.Revision++
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newFixture(t)
			gateway := fixture.gateway(t)
			effect := fixture.admit(t, gateway)
			test.mutate(&effect)
			if transition, err := gateway.Apply(effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch}); !errors.Is(err, ErrInvalidRequest) || transition.Dispatch != nil {
				t.Fatalf("Apply(corrupt snapshot) = %#v, %v; want ErrInvalidRequest and no command", transition, err)
			}
		})
	}
}

func TestApplyRejectsAControlCharacterInARestoredProviderRequestID(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch}).Effect
	effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventProviderAccepted, ProviderRequestID: "request-id"}).Effect
	effect.ProviderRequestID = "request\nid"

	if _, err := gateway.Apply(effect, Event{ExpectedRevision: effect.Revision, Kind: EventDelta, Delta: "x"}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Apply(control provider request ID) error = %v, want ErrInvalidRequest", err)
	}
}

func TestApplyRejectsRestoredStreamBytesThatExceedRecordedEventBytes(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch}).Effect
	effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventProviderAccepted, ProviderRequestID: "request-id"}).Effect
	effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventDelta, Delta: "partial"}).Effect
	effect.EventBytes = effect.StreamBytes - 1

	if _, err := gateway.Apply(effect, Event{ExpectedRevision: effect.Revision, Kind: EventDelta, Delta: "x"}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Apply(corrupt stream accounting) error = %v, want ErrInvalidRequest", err)
	}
}

func TestSettlementRejectsAUnicodeControlCharacterInARestoredFailureReason(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch}).Effect
	effect = apply(t, gateway, effect, Event{
		ExpectedRevision: effect.Revision, Kind: EventDispatchFailed,
		Failure: FailureTransportUnknown, Reason: "timeout",
	}).Effect
	effect.FailureReason = "\u0085"

	if _, err := gateway.AuthorizeSettlement(context.Background(), effect, OpaqueAuthority("renewed")); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("AuthorizeSettlement(control reason) error = %v, want ErrInvalidRequest", err)
	}
}

func TestApplyEnforcesEventAndStreamBounds(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	fixture.bounds.MaxEvents = 5
	fixture.grant.MaxPreDispatchRetries = 0
	fixture.bounds.MaxStreamBytes = 5
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch}).Effect
	effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventProviderAccepted, ProviderRequestID: "r"}).Effect
	if _, err := gateway.Apply(effect, Event{ExpectedRevision: effect.Revision, Kind: EventDelta, Delta: "123456"}); !errors.Is(err, ErrEventLimit) {
		t.Fatalf("Apply(stream overflow) error = %v, want ErrEventLimit", err)
	}
	effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventDelta, Delta: "12345"}).Effect
	if _, err := gateway.Apply(effect, Event{ExpectedRevision: effect.Revision, Kind: EventDelta, Delta: "x"}); !errors.Is(err, ErrEventLimit) {
		t.Fatalf("Apply(event overflow) error = %v, want ErrEventLimit", err)
	}
}

func TestEventBudgetAlwaysLeavesRoomToCancelAndClassifyAnActiveRequest(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	fixture.bounds.MaxEvents = 5
	fixture.grant.MaxPreDispatchRetries = 0
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch}).Effect
	effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventProviderAccepted, ProviderRequestID: "req-budget"}).Effect
	effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventDelta, Delta: "first"}).Effect

	if _, err := gateway.Apply(effect, Event{ExpectedRevision: effect.Revision, Kind: EventDelta, Delta: "would consume terminal reserve"}); !errors.Is(err, ErrEventLimit) {
		t.Fatalf("Apply(delta consuming reserve) error = %v, want ErrEventLimit", err)
	}
	cancellation := apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventCancelRequested})
	resolved := apply(t, gateway, cancellation.Effect, Event{
		ExpectedRevision: cancellation.Effect.Revision, Kind: EventCancellationResolved,
		DispatchPrevented: false,
	})
	if resolved.Effect.State != StateUncertain || resolved.Effect.EventCount != fixture.bounds.MaxEvents {
		t.Fatalf("budgeted cancellation = %#v", resolved.Effect)
	}
}

func TestRestoredDispatchingSnapshotMustReserveAcceptanceAndCancellation(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	fixture.bounds.MaxEvents = 4
	fixture.grant.MaxPreDispatchRetries = 0
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch}).Effect
	effect.EventCount++
	effect.Revision++

	_, err := gateway.Apply(effect, Event{
		ExpectedRevision: effect.Revision, Kind: EventProviderAccepted, ProviderRequestID: "request-id",
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Apply(restored dispatching snapshot without terminal reserve) error = %v, want ErrInvalidRequest", err)
	}
}

func TestCompletionCannotReportMoreInputThanQuotaReserved(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch}).Effect
	effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventProviderAccepted, ProviderRequestID: "req-usage"}).Effect

	_, err := gateway.Apply(effect, Event{
		ExpectedRevision: effect.Revision, Kind: EventResponseCompleted,
		Response: &ModelResponse{Text: "answer", FinishReason: "stop", Usage: Usage{InputTokens: 40, OutputTokens: 1}},
	})
	if !errors.Is(err, ErrQuotaMismatch) {
		t.Fatalf("Apply(over-reservation usage) error = %v, want ErrQuotaMismatch", err)
	}
}

func apply(t *testing.T, gateway *Gateway, effect Effect, event Event) Transition {
	t.Helper()
	transition, err := gateway.Apply(effect, event)
	if err != nil {
		t.Fatalf("Apply(%s) error = %v", event.Kind, err)
	}
	return transition
}
