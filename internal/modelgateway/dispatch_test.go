package modelgateway

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/hancomac/circulusd/internal/identity"
)

func TestExecuteDispatchRequiresAFreshFenceAndDurableClaimBeforeProviderIO(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	transition := apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch})

	fixture.authority.scope.Generations.Placement++
	if _, err := gateway.ExecuteDispatch(context.Background(), OpaqueAuthority("renewed"), transition); !errors.Is(err, ErrAuthorityMismatch) {
		t.Fatalf("ExecuteDispatch(stale effect) error = %v, want ErrAuthorityMismatch", err)
	}
	if fixture.dispatches.claims != 0 || fixture.provider.dispatchCalls != 0 {
		t.Fatalf("stale dispatch reached commit/provider: %d/%d", fixture.dispatches.claims, fixture.provider.dispatchCalls)
	}

	fixture.authority.scope = effect.Scope
	execution, err := gateway.ExecuteDispatch(context.Background(), OpaqueAuthority("renewed"), transition)
	if err != nil {
		t.Fatalf("ExecuteDispatch() error = %v", err)
	}
	if execution.Stream == nil || execution.Failure != nil || !execution.Permit.Durable {
		t.Fatalf("ExecuteDispatch() = %#v", execution)
	}
	if execution.Effect.State != StateDispatched || execution.Effect.ProviderRequestID != "provider-request-1" {
		t.Fatalf("durably accepted effect = %#v", execution.Effect)
	}
	if fixture.dispatches.claims != 1 || fixture.dispatches.acceptances != 1 || fixture.provider.dispatchCalls != 1 || fixture.provider.dispatchedWithoutClaim {
		t.Fatalf("commit/provider/accept order claims=%d accepts=%d calls=%d early=%t", fixture.dispatches.claims, fixture.dispatches.acceptances, fixture.provider.dispatchCalls, fixture.provider.dispatchedWithoutClaim)
	}
}

func TestExecuteDispatchPersistsProviderIdentityAfterCallerCancellation(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	fixture.provider.onDispatch = cancel
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	transition := apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch})

	execution, err := gateway.ExecuteDispatch(ctx, OpaqueAuthority("renewed"), transition)
	if err != nil {
		t.Fatalf("ExecuteDispatch() error = %v", err)
	}
	if execution.Effect.ProviderRequestID != "provider-request-1" || fixture.dispatches.acceptedContextErr != nil {
		t.Fatalf("provider identity was not durably recorded after cancellation: effect=%#v context=%v", execution.Effect, fixture.dispatches.acceptedContextErr)
	}
}

func TestConcurrentExecuteDispatchCallsProviderExactlyOnce(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	fixture.authority.concurrent = true
	fixture.dispatches.concurrent = true
	fixture.provider.concurrent = true
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	transition := apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch})

	const workers = 64
	errorsSeen := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := gateway.ExecuteDispatch(context.Background(), OpaqueAuthority("renewed"), transition)
			errorsSeen <- err
		}()
	}
	wait.Wait()
	close(errorsSeen)
	succeeded, rejected := 0, 0
	for err := range errorsSeen {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrConcurrentTransition):
			rejected++
		default:
			t.Fatalf("ExecuteDispatch() error = %v", err)
		}
	}
	if succeeded != 1 || rejected != workers-1 || fixture.dispatches.claims != 1 || fixture.provider.dispatchCalls != 1 {
		t.Fatalf("success=%d rejected=%d claims=%d provider=%d", succeeded, rejected, fixture.dispatches.claims, fixture.provider.dispatchCalls)
	}
}

func TestExecuteDispatchDoesNotShareCallerOwnedStateWithTheDurableCoordinator(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	fixture.dispatches.mutate = func(request *DispatchCommitRequest) {
		request.Effect.Request.Messages[0].Content = "coordinator mutation"
		request.Command.Request.Messages[0].Content = "command mutation"
	}
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	transition := apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch})
	wantEffectMessage := transition.Effect.Request.Messages[0]
	wantCommandMessage := transition.Dispatch.Request.Messages[0]

	if _, err := gateway.ExecuteDispatch(context.Background(), OpaqueAuthority("renewed"), transition); err != nil {
		t.Fatalf("ExecuteDispatch() error = %v", err)
	}
	if transition.Effect.Request.Messages[0] != wantEffectMessage || transition.Dispatch.Request.Messages[0] != wantCommandMessage {
		t.Fatalf("durable coordinator mutated caller state: effect=%#v command=%#v", transition.Effect.Request, transition.Dispatch.Request)
	}
}

func TestExecuteDispatchRejectsAReasoningMutationUnderThePreparedDigest(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	transition := apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch})
	transition.Dispatch.Request.Reasoning.Effort = ReasoningEffortHigh

	_, err := gateway.ExecuteDispatch(context.Background(), OpaqueAuthority("renewed"), transition)
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("ExecuteDispatch(mutated reasoning) error = %v, want ErrInvalidRequest", err)
	}
	if fixture.dispatches.claims != 0 || fixture.provider.dispatchCalls != 0 {
		t.Fatalf("mutated reasoning reached durable/provider boundary: %d/%d", fixture.dispatches.claims, fixture.provider.dispatchCalls)
	}
}

func TestResumeProviderRequestUsesOnlyThePreservedDurableRequestID(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	fixture.provider.availability.DurableRequestRetrieval = true
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	transition := apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch})
	execution, err := gateway.ExecuteDispatch(context.Background(), OpaqueAuthority("renewed"), transition)
	if err != nil {
		t.Fatalf("ExecuteDispatch() error = %v", err)
	}

	originalScope := fixture.authority.scope
	fixture.authority.scope.TurnID = mustID(t, identity.Turn, 'z')
	if _, err := gateway.ResumeProviderRequest(context.Background(), OpaqueAuthority("renewed"), execution.Effect); !errors.Is(err, ErrAuthorityMismatch) {
		t.Fatalf("ResumeProviderRequest(wrong effect owner) error = %v, want ErrAuthorityMismatch", err)
	}
	if fixture.provider.resumeCalls != 0 {
		t.Fatalf("wrong-owner resume calls = %d, want 0", fixture.provider.resumeCalls)
	}

	fixture.authority.scope = originalScope
	fixture.authority.scope.Generations.Policy++
	stream, err := gateway.ResumeProviderRequest(context.Background(), OpaqueAuthority("renewed"), execution.Effect)
	if err != nil || stream == nil {
		t.Fatalf("ResumeProviderRequest() = %v, %v", stream, err)
	}
	if fixture.provider.resumeCalls != 1 || fixture.provider.lastResume.ProviderRequestID != execution.Effect.ProviderRequestID ||
		fixture.provider.lastResume.EffectID != execution.Effect.Scope.EffectID || fixture.provider.lastResume.Attempt != execution.Effect.Attempt ||
		fixture.provider.lastResume.Scope.Generations != fixture.authority.scope.Generations || !fixture.provider.lastResume.Permit.Durable {
		t.Fatalf("resume command/calls = %#v/%d", fixture.provider.lastResume, fixture.provider.resumeCalls)
	}
}

func TestResumeProviderRequestFailsClosedWithoutAnAdvertisedDurableContract(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch}).Effect
	effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventProviderAccepted, ProviderRequestID: "provider-request-1"}).Effect

	if _, err := gateway.ResumeProviderRequest(context.Background(), OpaqueAuthority("renewed"), effect); !errors.Is(err, ErrDurableRetrievalUnavailable) {
		t.Fatalf("ResumeProviderRequest(no contract) error = %v, want ErrDurableRetrievalUnavailable", err)
	}
	if fixture.provider.resumeCalls != 0 {
		t.Fatalf("resume calls = %d, want 0", fixture.provider.resumeCalls)
	}
}

func TestExecuteDispatchClassifiesOnlyTypedProofAsDefinitelyNotSent(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		dispatchErr error
		want        FailureClass
	}{
		{name: "typed proof", dispatchErr: mustProviderDispatchError(t, DispatchFailureDefinitelyNotSent, "socket was never opened"), want: FailurePreDispatch},
		{name: "plain error is unknown", dispatchErr: errors.New("connection reset"), want: FailureTransportUnknown},
		{name: "typed unknown", dispatchErr: mustProviderDispatchError(t, DispatchFailureUnknown, "write acknowledgement missing"), want: FailureTransportUnknown},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFixture(t)
			fixture.provider.dispatchErr = test.dispatchErr
			gateway := fixture.gateway(t)
			effect := fixture.admit(t, gateway)
			transition := apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch})
			execution, err := gateway.ExecuteDispatch(context.Background(), OpaqueAuthority("renewed"), transition)
			if err != nil {
				t.Fatalf("ExecuteDispatch() error = %v", err)
			}
			if execution.Stream != nil || execution.Failure == nil || execution.Failure.Failure != test.want || execution.Failure.ExpectedRevision != transition.Effect.Revision {
				t.Fatalf("dispatch failure = %#v, want %q", execution, test.want)
			}
		})
	}
}

func TestExecuteDispatchBoundsItsFailureEventToTheConfiguredEventLimit(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	fixture.bounds.MaxEventBytes = 8
	fixture.provider.dispatchErr = mustProviderDispatchError(t, DispatchFailureDefinitelyNotSent, "socket was never opened")
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	transition := apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch})
	execution, err := gateway.ExecuteDispatch(context.Background(), OpaqueAuthority("renewed"), transition)
	if err != nil {
		t.Fatalf("ExecuteDispatch() error = %v", err)
	}
	if execution.Failure == nil || uint64(len(execution.Failure.Reason)) > fixture.bounds.MaxEventBytes {
		t.Fatalf("failure event = %#v", execution.Failure)
	}
	if _, err := gateway.Apply(execution.Effect, *execution.Failure); err != nil {
		t.Fatalf("Apply(bounded failure) error = %v", err)
	}
}

func TestExecuteDispatchPreservesAProviderRequestIDReturnedWithAnUnknownFailure(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	fixture.provider.dispatchErr = errors.New("stream setup failed after provider acceptance")
	fixture.provider.returnRequestIDOnError = true
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	transition := apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch})

	execution, err := gateway.ExecuteDispatch(context.Background(), OpaqueAuthority("renewed"), transition)
	if err != nil {
		t.Fatalf("ExecuteDispatch() error = %v", err)
	}
	if execution.Effect.ProviderRequestID != "provider-request-1" || execution.Effect.State != StateDispatched || execution.Failure == nil ||
		execution.Failure.Failure != FailureTransportUnknown || execution.Failure.ExpectedRevision != execution.Effect.Revision {
		t.Fatalf("dispatch execution = %#v", execution)
	}
	uncertain := apply(t, gateway, execution.Effect, *execution.Failure).Effect
	if uncertain.State != StateUncertain || uncertain.ProviderRequestID != "provider-request-1" {
		t.Fatalf("uncertain effect lost provider request identity: %#v", uncertain)
	}
}

func TestExecuteDispatchTurnsAnInvalidProviderRequestIDIntoASettleableUnknownOutcome(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	fixture.provider.providerRequestID = "request-id-that-exceeds-the-configured-bound"
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	transition := apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch})

	execution, err := gateway.ExecuteDispatch(context.Background(), OpaqueAuthority("renewed"), transition)
	if err != nil {
		t.Fatalf("ExecuteDispatch() error = %v, want conservative failure event", err)
	}
	if execution.Stream != nil || execution.Failure == nil || execution.Failure.Failure != FailureTransportUnknown ||
		execution.Failure.ExpectedRevision != transition.Effect.Revision {
		t.Fatalf("invalid provider identity execution = %#v", execution)
	}
	uncertain := apply(t, gateway, execution.Effect, *execution.Failure).Effect
	if uncertain.State != StateUncertain || uncertain.Outcome != OutcomeUncertain {
		t.Fatalf("invalid provider identity outcome = %#v", uncertain)
	}
}

func mustProviderDispatchError(t *testing.T, class ProviderDispatchFailureClass, reason string) error {
	t.Helper()
	err, createErr := NewProviderDispatchError(class, reason, nil)
	if createErr != nil {
		t.Fatalf("NewProviderDispatchError() error = %v", createErr)
	}
	return err
}
