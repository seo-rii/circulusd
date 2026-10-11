package modelgateway

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestAdmitRejectsInsufficientDurableRetrievalBudgetBeforeQuota(t *testing.T) {
	t.Parallel()
	for _, retries := range []uint32{0, 1, hardMaxPreDispatchRetries} {
		t.Run(fmt.Sprintf("retries_%d", retries), func(t *testing.T) {
			t.Parallel()
			fixture := newFixture(t)
			fixture.grant.MaxPreDispatchRetries = retries
			fixture.bounds.MaxEvents = 2*retries + 4
			fixture.provider.availability.DurableRequestRetrieval = true
			gateway := fixture.gateway(t)

			if _, err := gateway.Admit(context.Background(), fixture.admissionRequest()); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("Admit(insufficient recovery budget) error = %v, want ErrInvalidConfiguration", err)
			}
			if fixture.quota.calls != 0 || fixture.quota.reservations != 0 || fixture.provider.dispatchCalls != 0 {
				t.Fatalf("rejected admission reached quota or dispatch: calls=%d reservations=%d dispatch=%d", fixture.quota.calls, fixture.quota.reservations, fixture.provider.dispatchCalls)
			}

			// The same budget remains valid when the provider does not offer
			// retrieval; admission uses the currently advertised capability.
			fixture.provider.availability.DurableRequestRetrieval = false
			effect := fixture.admit(t, gateway)
			if effect.DurableRequestRetrieval || fixture.quota.reservations != 1 {
				t.Fatalf("admission without retrieval = %#v; reservations=%d", effect, fixture.quota.reservations)
			}
		})
	}
}

func TestMinimumEventBudgetSupportsEveryRetryAndTerminalReserve(t *testing.T) {
	t.Parallel()
	for _, retrieval := range []bool{false, true} {
		for _, retries := range []uint32{0, 1, hardMaxPreDispatchRetries} {
			t.Run(fmt.Sprintf("retrieval_%t/retries_%d", retrieval, retries), func(t *testing.T) {
				t.Parallel()
				fixture := newFixture(t)
				fixture.grant.MaxPreDispatchRetries = retries
				fixture.bounds.MaxEvents = 2*retries + 4
				if retrieval {
					fixture.bounds.MaxEvents++
				}
				fixture.provider.availability.DurableRequestRetrieval = retrieval
				fixture.provider.stream = &singleEventProviderStream{event: ProviderEvent{
					Kind: ProviderEventResponseCompleted,
					Response: &ProviderResponse{
						Text: "recovered", FinishReason: "stop", Usage: Usage{InputTokens: 11, OutputTokens: 1},
					},
				}}
				gateway := fixture.gateway(t)
				effect := fixture.admit(t, gateway)
				for attempt := uint32(1); attempt <= retries+1; attempt++ {
					effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch}).Effect
					if effect.Attempt != attempt {
						t.Fatalf("dispatch attempt = %d, want %d", effect.Attempt, attempt)
					}
					if attempt <= retries {
						effect = apply(t, gateway, effect, Event{
							ExpectedRevision: effect.Revision, Kind: EventDispatchFailed, Failure: FailurePreDispatch, Reason: "not sent",
						}).Effect
					}
				}
				effect = apply(t, gateway, effect, Event{
					ExpectedRevision: effect.Revision, Kind: EventProviderAccepted, ProviderRequestID: "provider-request-1",
				}).Effect
				if _, err := gateway.Apply(effect, Event{ExpectedRevision: effect.Revision, Kind: EventDelta, Delta: "x"}); !errors.Is(err, ErrEventLimit) {
					t.Fatalf("Apply(delta consuming terminal reserve) error = %v, want ErrEventLimit", err)
				}
				effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventCancelRequested}).Effect
				effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventCancellationResolved}).Effect
				hold, err := gateway.AuthorizeSettlement(context.Background(), effect, OpaqueAuthority("renewed"))
				if err != nil || hold.QuotaReceipt.Disposition != QuotaDispositionHold {
					t.Fatalf("AuthorizeSettlement(uncertain) = %#v, %v", hold, err)
				}
				if retrieval {
					if effect.EventCount != fixture.bounds.MaxEvents-1 {
						t.Fatalf("uncertain event count = %d, want one recovery event remaining", effect.EventCount)
					}
					stream, err := gateway.ResumeProviderRequest(context.Background(), OpaqueAuthority("renewed"), effect)
					if err != nil {
						t.Fatalf("ResumeProviderRequest() error = %v", err)
					}
					event, nextErr := stream.Next(context.Background())
					closeErr := stream.Close(context.Background())
					if nextErr != nil || closeErr != nil {
						t.Fatalf("resumed stream errors: Next=%v Close=%v", nextErr, closeErr)
					}
					event.ExpectedRevision = effect.Revision
					effect = apply(t, gateway, effect, event).Effect
					settlement, err := gateway.AuthorizeSettlement(context.Background(), effect, OpaqueAuthority("renewed"))
					if err != nil || effect.State != StateCompleted || settlement.QuotaReceipt.Disposition != QuotaDispositionConsume || fixture.quota.settlements != 2 {
						t.Fatalf("recovered settlement/state = %#v/%s, %v; mutations=%d", settlement, effect.State, err, fixture.quota.settlements)
					}
				}
				if effect.EventCount != fixture.bounds.MaxEvents || fixture.quota.reservations != 1 {
					t.Fatalf("final event count/reservations = %d/%d, want %d/1", effect.EventCount, fixture.quota.reservations, fixture.bounds.MaxEvents)
				}
			})
		}
	}
}
