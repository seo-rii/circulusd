package mcpgateway

import (
	"context"
	"errors"
	"testing"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/identity"
)

func TestReplayPolicyControlsUnknownAndPartialDispatch(t *testing.T) {
	tests := []struct {
		policy ReplayPolicy
		want   State
	}{
		{policy: ReplaySafe, want: StateRetryPending},
		{policy: ReplayIdempotencyKey, want: StateRetryPending},
		{policy: ReplayNever, want: StateUncertain},
		{policy: ReplayConfirm, want: StateNeedsConfirmation},
	}
	for _, test := range tests {
		t.Run(string(test.policy), func(t *testing.T) {
			fixture := newGatewayFixture(t, test.policy)
			effect := admitFixtureEffect(t, fixture)
			effect = applyFixtureEvent(t, fixture.gateway, effect, Event{Kind: EventBeginDispatch})
			effect = negotiateFixtureEffect(t, fixture.gateway, effect)
			effect = applyFixtureEvent(t, fixture.gateway, effect, Event{
				Kind: EventProviderAccepted, ProviderRequestID: "jsonrpc-17",
			})
			effect = applyFixtureEvent(t, fixture.gateway, effect, Event{
				Kind: EventOutputChunk, Chunk: []byte("partial"),
			})
			effect = applyFixtureEvent(t, fixture.gateway, effect, Event{
				Kind: EventDispatchFailed, Failure: FailureUnknown, Reason: "server died",
			})
			if effect.State != test.want {
				t.Fatalf("unknown dispatch state = %s, want %s", effect.State, test.want)
			}
			if effect.StreamBytes != uint64(len("partial")) || effect.ChunkCount != 1 || !effect.Attempts[0].HadOutput {
				t.Fatalf("partial-output evidence was lost: %+v", effect)
			}
			if (test.want == StateRetryPending) != (effect.AutomaticRetriesUsed == 1) {
				t.Fatalf("automatic retry accounting = %d for state %s", effect.AutomaticRetriesUsed, effect.State)
			}
		})
	}
}

func TestDefinitelyNotSentMayRetryEveryPolicyWithoutInventingAcceptance(t *testing.T) {
	for _, policy := range []ReplayPolicy{ReplaySafe, ReplayIdempotencyKey, ReplayNever, ReplayConfirm} {
		t.Run(string(policy), func(t *testing.T) {
			fixture := newGatewayFixture(t, policy)
			effect := admitFixtureEffect(t, fixture)
			effect = applyFixtureEvent(t, fixture.gateway, effect, Event{Kind: EventBeginDispatch})
			effect = applyFixtureEvent(t, fixture.gateway, effect, Event{
				Kind: EventDispatchFailed, Failure: FailureDefinitelyNotSent, Reason: "sandbox not started",
			})
			if effect.State != StateRetryPending || effect.AutomaticRetriesUsed != 1 {
				t.Fatalf("definitely-not-sent result = state %s retries %d", effect.State, effect.AutomaticRetriesUsed)
			}
			attempt, ok := effect.CurrentAttempt()
			if !ok || attempt.ProviderRequestID != "" || attempt.HadOutput {
				t.Fatalf("pre-dispatch failure invented provider evidence: %+v", attempt)
			}
		})
	}
}

func TestCommittedCallRequiresSettlementOnlyAndApplyIsImmutable(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	effect := admitFixtureEffect(t, fixture)
	effect = applyFixtureEvent(t, fixture.gateway, effect, Event{Kind: EventBeginDispatch})
	effect = negotiateFixtureEffect(t, fixture.gateway, effect)
	effect = applyFixtureEvent(t, fixture.gateway, effect, Event{Kind: EventProviderAccepted, ProviderRequestID: "rpc-1"})
	original := cloneEffect(effect)
	output := []byte(`{"ok":true}`)
	transition, err := fixture.gateway.Apply(effect, Event{
		ExpectedRevision: effect.Revision, Kind: EventCallCommitted,
		Output: output, ExternalCommitID: "commit-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	output[0] = 'X'
	if !sameEffect(effect, original) {
		t.Fatal("Apply mutated its input effect")
	}
	if string(transition.Effect.Output) != `{"ok":true}` || transition.Effect.State != StateExternallyCommitted {
		t.Fatalf("committed transition = %+v", transition.Effect)
	}
	if transition.Dispatch != nil {
		t.Fatal("externally committed call requested a second dispatch")
	}
	settled := applyFixtureEvent(t, fixture.gateway, transition.Effect, Event{Kind: EventSettlementCompleted})
	if settled.State != StateCompleted || !settled.Terminal() {
		t.Fatalf("settlement state = %s", settled.State)
	}
	_, err = fixture.gateway.Apply(settled, Event{
		ExpectedRevision: settled.Revision, Kind: EventBeginDispatch,
	})
	if !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("committed call was redispatched: %v", err)
	}
}

func TestConfirmationIsExplicitBoundedAndCASFenced(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayConfirm)
	effect := admitFixtureEffect(t, fixture)
	effect = applyFixtureEvent(t, fixture.gateway, effect, Event{Kind: EventBeginDispatch})
	effect = negotiateFixtureEffect(t, fixture.gateway, effect)
	effect = applyFixtureEvent(t, fixture.gateway, effect, Event{Kind: EventProviderAccepted, ProviderRequestID: "rpc-confirm"})
	effect = applyFixtureEvent(t, fixture.gateway, effect, Event{
		Kind: EventDispatchFailed, Failure: FailureUnknown, Reason: "connection reset",
	})
	if effect.State != StateNeedsConfirmation {
		t.Fatalf("state = %s, want needs_confirmation", effect.State)
	}

	transition, err := fixture.gateway.Apply(effect, Event{
		ExpectedRevision: effect.Revision, Kind: EventConfirmationDecided, Decision: ConfirmationRetry,
	})
	if err != nil {
		t.Fatal(err)
	}
	if transition.Effect.State != StateRetryPending || transition.Effect.ConfirmationRetriesUsed != 1 {
		t.Fatalf("confirmation transition = %+v", transition.Effect)
	}
	_, err = fixture.gateway.Apply(effect, Event{
		ExpectedRevision: effect.Revision - 1, Kind: EventConfirmationDecided, Decision: ConfirmationRetry,
	})
	if !errors.Is(err, ErrConcurrentTransition) {
		t.Fatalf("stale confirmation error = %v, want %v", err, ErrConcurrentTransition)
	}
}

func TestMachineBoundsEventsChunksAndTerminalReserve(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	effect := admitFixtureEffect(t, fixture)
	effect = applyFixtureEvent(t, fixture.gateway, effect, Event{Kind: EventBeginDispatch})
	effect = negotiateFixtureEffect(t, fixture.gateway, effect)
	effect = applyFixtureEvent(t, fixture.gateway, effect, Event{Kind: EventProviderAccepted, ProviderRequestID: "rpc-bound"})

	_, err := fixture.gateway.Apply(effect, Event{
		ExpectedRevision: effect.Revision, Kind: EventOutputChunk,
		Chunk: make([]byte, testBounds().MaxChunkBytes+1),
	})
	if !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("oversized chunk error = %v, want %v", err, ErrOutputLimit)
	}

	corrupt := cloneEffect(effect)
	corrupt.EventCount = testBounds().MaxEvents - 1
	corrupt.Revision = uint64(corrupt.EventCount) + 1
	_, err = fixture.gateway.Apply(corrupt, Event{
		ExpectedRevision: corrupt.Revision, Kind: EventOutputChunk, Chunk: []byte("x"),
	})
	if !errors.Is(err, ErrEventLimit) {
		t.Fatalf("event budget did not reserve cancellation/terminal events: %v", err)
	}
}

func admitFixtureEffect(t *testing.T, fixture gatewayFixture) Effect {
	t.Helper()
	call := CallRequest{
		ServerID: fixture.server.ServerID, ToolName: fixture.tool.ToolName,
		Input: canonical.Map{"repository": "org/repo", "private": true},
	}
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
	return effect
}

func applyFixtureEvent(t *testing.T, gateway *Gateway, effect Effect, event Event) Effect {
	t.Helper()
	event.ExpectedRevision = effect.Revision
	transition, err := gateway.Apply(effect, event)
	if err != nil {
		t.Fatalf("Apply(%s, %s): %v", effect.State, event.Kind, err)
	}
	return transition.Effect
}

func negotiationReceiptForEffect(effect Effect) StartNegotiationReceipt {
	attempt, _ := effect.CurrentAttempt()
	return StartNegotiationReceipt{
		Durable: true, Scope: effect.Scope, Server: serverForEffect(effect),
		InvocationID: effect.Scope.InvocationID, RequestDigest: effect.RequestDigest, Attempt: attempt.Attempt,
		NegotiatedProtocolVersion: effect.ProtocolVersion, Affinity: effect.Affinity,
		SupportsInvocationLedger: effect.SupportsInvocationLedger,
		SupportsIdempotencyKey:   effect.SupportsIdempotencyKey, ConnectionGeneration: 1,
	}
}

func negotiateFixtureEffect(t *testing.T, gateway *Gateway, effect Effect) Effect {
	t.Helper()
	return applyFixtureEvent(t, gateway, effect, Event{
		Kind: EventNegotiationRecorded, Negotiation: negotiationReceiptForEffect(effect),
	})
}
