package modelgateway

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
)

func TestQuotaSettlementRejectsATerminalBranchThatDidNotWinTheDurableCAS(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)

	localCancelled, err := gateway.Apply(effect, Event{
		ExpectedRevision: effect.Revision,
		Kind:             EventCancelRequested,
	})
	if err != nil {
		t.Fatalf("Apply(local cancellation) error = %v", err)
	}
	dispatch := apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch})
	if _, err := gateway.ExecuteDispatch(context.Background(), OpaqueAuthority("renewed"), dispatch); err != nil {
		t.Fatalf("ExecuteDispatch(competing durable branch) error = %v", err)
	}

	if _, err := gateway.AuthorizeSettlement(context.Background(), localCancelled.Effect, OpaqueAuthority("renewed")); !errors.Is(err, ErrConcurrentTransition) {
		t.Fatalf("AuthorizeSettlement(losing branch) error = %v, want ErrConcurrentTransition", err)
	}
	if fixture.quota.settlements != 0 {
		t.Fatalf("losing branch settled quota %d times", fixture.quota.settlements)
	}
}

func TestUnprovenCancellationCannotClassifyAnInFlightDispatchAsDefinitelyPrevented(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch}).Effect
	requested := apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventCancelRequested})

	resolved, err := gateway.Apply(requested.Effect, Event{
		ExpectedRevision:  requested.Effect.Revision,
		Kind:              EventCancellationResolved,
		DispatchPrevented: true,
	})
	if err != nil {
		t.Fatalf("Apply(unproven cancellation) error = %v", err)
	}
	if resolved.Effect.State != StateUncertain || resolved.Effect.Outcome != OutcomeUncertain {
		t.Fatalf("unproven cancellation = %#v, want uncertain", resolved.Effect)
	}
}

func TestCancellationAndProviderStartHaveOneLinearizationWinner(t *testing.T) {
	t.Parallel()
	for iteration := 0; iteration < 256; iteration++ {
		fixture := newFixture(t)
		gateway := fixture.gateway(t)
		effect := fixture.admit(t, gateway)
		begin := apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch})
		dispatchPermit, err := fixture.dispatches.CommitAndClaimDispatch(context.Background(), DispatchCommitRequest{
			ExpectedRevision: effect.Revision, CurrentScope: effect.Scope, Effect: begin.Effect, Command: *begin.Dispatch,
		})
		if err != nil {
			t.Fatalf("iteration %d CommitAndClaimDispatch() error = %v", iteration, err)
		}
		cancellation := apply(t, gateway, begin.Effect, Event{ExpectedRevision: begin.Effect.Revision, Kind: EventCancelRequested})

		var startErr error
		var cancellationPermit CancellationPermit
		var cancellationErr error
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			startErr = fixture.dispatches.BeginProviderDispatch(context.Background(), dispatchPermit)
		}()
		go func() {
			defer wait.Done()
			cancellationPermit, cancellationErr = fixture.dispatches.CommitAndClaimCancellation(context.Background(), CancellationCommitRequest{
				ExpectedRevision: begin.Effect.Revision, CurrentScope: effect.Scope,
				Effect: cancellation.Effect, Command: *cancellation.Cancel,
			})
		}()
		wait.Wait()
		if cancellationErr != nil {
			t.Fatalf("iteration %d CommitAndClaimCancellation() error = %v", iteration, cancellationErr)
		}
		providerStarted := startErr == nil
		if providerStarted == cancellationPermit.DispatchPrevented {
			t.Fatalf("iteration %d start=%t prevented=%t; want exactly one winner", iteration, providerStarted, cancellationPermit.DispatchPrevented)
		}
		if !providerStarted && !errors.Is(startErr, ErrConcurrentTransition) {
			t.Fatalf("iteration %d BeginProviderDispatch() error = %v", iteration, startErr)
		}
	}
}

func TestCompetingTerminalBranchesSettleQuotaExactlyOnce(t *testing.T) {
	t.Parallel()
	for iteration := 0; iteration < 32; iteration++ {
		fixture := newFixture(t)
		fixture.authority.concurrent = true
		fixture.dispatches.concurrent = true
		fixture.quota.concurrent = true
		gateway := fixture.gateway(t)
		effect := fixture.admit(t, gateway)
		begin := apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch})
		execution, err := gateway.ExecuteDispatch(context.Background(), OpaqueAuthority("renewed"), begin)
		if err != nil {
			t.Fatalf("iteration %d ExecuteDispatch() error = %v", iteration, err)
		}
		completed := apply(t, gateway, execution.Effect, Event{
			ExpectedRevision: execution.Effect.Revision, Kind: EventResponseCompleted,
			Response: &ModelResponse{Text: "answer", FinishReason: "stop", Usage: Usage{InputTokens: 11, OutputTokens: 1}},
		}).Effect
		failed := apply(t, gateway, execution.Effect, Event{
			ExpectedRevision: execution.Effect.Revision, Kind: EventDispatchFailed,
			Failure: FailureProviderRejected, Reason: "rejected",
		}).Effect
		errorsSeen := make(chan error, 2)
		var wait sync.WaitGroup
		for _, terminal := range []Effect{completed, failed} {
			terminal := terminal
			wait.Add(1)
			go func() {
				defer wait.Done()
				_, settleErr := gateway.AuthorizeSettlement(context.Background(), terminal, OpaqueAuthority("renewed"))
				errorsSeen <- settleErr
			}()
		}
		wait.Wait()
		close(errorsSeen)
		succeeded, conflicted := 0, 0
		for settleErr := range errorsSeen {
			switch {
			case settleErr == nil:
				succeeded++
			case errors.Is(settleErr, ErrConcurrentTransition):
				conflicted++
			default:
				t.Fatalf("iteration %d settlement error = %v", iteration, settleErr)
			}
		}
		if succeeded != 1 || conflicted != 1 || fixture.quota.settlements != 1 {
			t.Fatalf("iteration %d succeeded=%d conflicted=%d quota mutations=%d", iteration, succeeded, conflicted, fixture.quota.settlements)
		}
	}
}

func TestTerminalSettlementRecoversAfterQuotaCrashAndGenerationTakeover(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	begin := apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch})
	execution, err := gateway.ExecuteDispatch(context.Background(), OpaqueAuthority("owner-one"), begin)
	if err != nil {
		t.Fatalf("ExecuteDispatch() error = %v", err)
	}
	completed := apply(t, gateway, execution.Effect, Event{
		ExpectedRevision: execution.Effect.Revision,
		Kind:             EventResponseCompleted,
		Response: &ModelResponse{
			Text: "answer", FinishReason: "stop",
			Usage: Usage{InputTokens: 11, OutputTokens: 1},
		},
	}).Effect

	crashErr := errors.New("injected crash before quota commit")
	fixture.quota.settleErr = crashErr
	if _, err := gateway.AuthorizeSettlement(context.Background(), completed, OpaqueAuthority("owner-one")); !errors.Is(err, crashErr) {
		t.Fatalf("AuthorizeSettlement(before crash) error = %v, want injected crash", err)
	}
	if fixture.quota.settlements != 0 {
		t.Fatalf("quota mutations before recovery = %d, want 0", fixture.quota.settlements)
	}

	fixture.quota.settleErr = nil
	fixture.authority.scope.Generations.Placement++
	fixture.authority.scope.Generations.TurnLease++
	recovered, err := gateway.AuthorizeSettlement(context.Background(), completed, OpaqueAuthority("owner-two"))
	if err != nil {
		t.Fatalf("AuthorizeSettlement(after takeover) error = %v", err)
	}
	if recovered.QuotaReceipt.Disposition != QuotaDispositionConsume || fixture.quota.settlements != 1 {
		t.Fatalf("recovered quota settlement = %#v; mutations=%d", recovered.QuotaReceipt, fixture.quota.settlements)
	}

	fixture.authority.scope.Generations.Placement++
	fixture.authority.scope.Generations.Policy++
	replayed, err := gateway.AuthorizeSettlement(context.Background(), completed, OpaqueAuthority("owner-three"))
	if err != nil {
		t.Fatalf("AuthorizeSettlement(replay) error = %v", err)
	}
	if replayed.Scope != fixture.authority.scope {
		t.Fatalf("replayed settlement scope = %#v, want current scope %#v", replayed.Scope, fixture.authority.scope)
	}
	if replayed.QuotaReceipt != recovered.QuotaReceipt || fixture.quota.settlements != 1 {
		t.Fatalf("replayed settlement = %#v, want %#v; mutations=%d", replayed.QuotaReceipt, recovered.QuotaReceipt, fixture.quota.settlements)
	}
}

func TestProviderReportedUsageCannotLowerConservativeQuotaAccounting(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch}).Effect
	effect = apply(t, gateway, effect, Event{
		ExpectedRevision:  effect.Revision,
		Kind:              EventProviderAccepted,
		ProviderRequestID: "provider-request-1",
	}).Effect
	completed := apply(t, gateway, effect, Event{
		ExpectedRevision: effect.Revision,
		Kind:             EventResponseCompleted,
		Response: &ModelResponse{
			Text: "a non-empty answer", FinishReason: "stop",
			Usage: Usage{},
		},
	}).Effect

	want := Usage{InputTokens: completed.ContextTokens, OutputTokens: completed.RequestedOutputTokens}
	if completed.Response == nil || completed.Response.Usage != want {
		t.Fatalf("normalized response usage = %#v, want conservative reservation %#v", completed.Response, want)
	}
	settlement, err := gateway.AuthorizeSettlement(context.Background(), completed, OpaqueAuthority("renewed"))
	if err != nil {
		t.Fatalf("AuthorizeSettlement() error = %v", err)
	}
	if settlement.QuotaReceipt.Usage != want {
		t.Fatalf("quota usage = %#v, want %#v", settlement.QuotaReceipt.Usage, want)
	}
}

func TestExplicitUncertainResolutionRecoversAHeldQuotaAfterTakeover(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	fixture.provider.dispatchErr = errors.New("provider acknowledgement lost")
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	begin := apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch})
	execution, err := gateway.ExecuteDispatch(context.Background(), OpaqueAuthority("owner-one"), begin)
	if err != nil {
		t.Fatalf("ExecuteDispatch() error = %v", err)
	}
	if execution.Failure == nil {
		t.Fatal("ExecuteDispatch() returned no conservative failure")
	}
	uncertain := apply(t, gateway, execution.Effect, *execution.Failure).Effect
	held, err := gateway.AuthorizeSettlement(context.Background(), uncertain, OpaqueAuthority("owner-one"))
	if err != nil || held.QuotaReceipt.Disposition != QuotaDispositionHold {
		t.Fatalf("AuthorizeSettlement(hold) = %#v, %v", held, err)
	}

	crashErr := errors.New("injected crash after resolution commit")
	fixture.quota.settleErr = crashErr
	if _, err := gateway.ResolveUncertain(context.Background(), uncertain, OpaqueAuthority("operator-one"), UncertainResolutionRelease); !errors.Is(err, crashErr) {
		t.Fatalf("ResolveUncertain(before crash) error = %v, want injected crash", err)
	}
	fixture.quota.settleErr = nil
	fixture.authority.scope.Generations.Placement++
	fixture.authority.scope.Generations.Policy++

	resolved, err := gateway.ResolveUncertain(context.Background(), uncertain, OpaqueAuthority("operator-two"), UncertainResolutionRelease)
	if err != nil {
		t.Fatalf("ResolveUncertain(after takeover) error = %v", err)
	}
	if resolved.NeedsConfirmation || resolved.Scope != fixture.authority.scope || resolved.QuotaReceipt.Disposition != QuotaDispositionRelease ||
		!resolved.QuotaReceipt.Resolution.Durable || resolved.QuotaReceipt.Resolution.Decision != UncertainResolutionRelease {
		t.Fatalf("resolved settlement = %#v", resolved)
	}
	if fixture.authority.lastAdmission.Permission != "model.resolve-uncertain.release" {
		t.Fatalf("resolution permission = %q", fixture.authority.lastAdmission.Permission)
	}
	if fixture.quota.settlements != 2 {
		t.Fatalf("quota mutations = %d, want hold + release", fixture.quota.settlements)
	}

	replayed, err := gateway.ResolveUncertain(context.Background(), uncertain, OpaqueAuthority("operator-two"), UncertainResolutionRelease)
	if err != nil || replayed.QuotaReceipt != resolved.QuotaReceipt || fixture.quota.settlements != 2 {
		t.Fatalf("ResolveUncertain(replay) = %#v, %v; mutations=%d", replayed, err, fixture.quota.settlements)
	}
	if _, err := gateway.ResolveUncertain(context.Background(), uncertain, OpaqueAuthority("operator-two"), UncertainResolutionConsume); !errors.Is(err, ErrQuotaConflict) {
		t.Fatalf("ResolveUncertain(conflicting decision) error = %v, want ErrQuotaConflict", err)
	}
}

func TestResolveUncertainRejectsANonUncertainEffectBeforeDurableMutation(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	begin := apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch})
	execution, err := gateway.ExecuteDispatch(context.Background(), OpaqueAuthority("owner-one"), begin)
	if err != nil {
		t.Fatalf("ExecuteDispatch() error = %v", err)
	}
	completed := apply(t, gateway, execution.Effect, Event{
		ExpectedRevision: execution.Effect.Revision,
		Kind:             EventResponseCompleted,
		Response: &ModelResponse{
			Text: "answer", FinishReason: FinishReasonStop,
			Usage: Usage{InputTokens: 11, OutputTokens: 1},
		},
	}).Effect
	before := *fixture.dispatches.durable

	if _, err := gateway.ResolveUncertain(context.Background(), completed, OpaqueAuthority("operator"), UncertainResolutionRelease); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("ResolveUncertain(completed effect) error = %v, want ErrInvalidTransition", err)
	}
	if fixture.dispatches.durable.State != before.State || fixture.dispatches.durable.Revision != before.Revision || len(fixture.dispatches.settlementPermits) != 0 {
		t.Fatalf("ResolveUncertain durably mutated non-uncertain effect: before=%#v after=%#v permits=%d", before, *fixture.dispatches.durable, len(fixture.dispatches.settlementPermits))
	}
	if fixture.quota.settlements != 0 {
		t.Fatalf("ResolveUncertain settled quota %d times", fixture.quota.settlements)
	}
}

func TestDurableResumeAcceptsAFreshOwnerAfterGenerationTakeover(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	fixture.provider.availability.DurableRequestRetrieval = true
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch}).Effect
	effect = apply(t, gateway, effect, Event{
		ExpectedRevision:  effect.Revision,
		Kind:              EventProviderAccepted,
		ProviderRequestID: "provider-request-1",
	}).Effect
	fixture.authority.scope.Generations.Placement++

	stream, err := gateway.ResumeProviderRequest(context.Background(), OpaqueAuthority("takeover"), effect)
	if err != nil || stream == nil {
		t.Fatalf("ResumeProviderRequest(takeover) = %v, %v", stream, err)
	}
	if fixture.provider.lastResume.Scope.Generations != fixture.authority.scope.Generations {
		t.Fatalf("resume scope generations = %#v, want %#v", fixture.provider.lastResume.Scope.Generations, fixture.authority.scope.Generations)
	}
}

func TestUncertainDurableResumeCanCompleteAndConsumeAHeldReservation(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	fixture.provider.availability.DurableRequestRetrieval = true
	fixture.provider.stream = &singleEventProviderStream{event: ProviderEvent{
		Kind: ProviderEventResponseCompleted,
		Response: &ProviderResponse{
			Text: "recovered", FinishReason: "stop",
			Usage: Usage{InputTokens: 11, OutputTokens: 2},
		},
	}}
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch}).Effect
	effect = apply(t, gateway, effect, Event{
		ExpectedRevision: effect.Revision, Kind: EventProviderAccepted, ProviderRequestID: "provider-request-1",
	}).Effect
	effect = apply(t, gateway, effect, Event{
		ExpectedRevision: effect.Revision, Kind: EventDispatchFailed,
		Failure: FailureTransportUnknown, Reason: "stream acknowledgement lost",
	}).Effect
	held, err := gateway.AuthorizeSettlement(context.Background(), effect, OpaqueAuthority("renewed"))
	if err != nil || held.QuotaReceipt.Disposition != QuotaDispositionHold {
		t.Fatalf("AuthorizeSettlement(hold) = %#v, %v", held, err)
	}

	stream, err := gateway.ResumeProviderRequest(context.Background(), OpaqueAuthority("renewed"), effect)
	if err != nil {
		t.Fatalf("ResumeProviderRequest() error = %v", err)
	}
	event, err := stream.Next(context.Background())
	if err != nil {
		t.Fatalf("Next(recovered result) error = %v", err)
	}
	event.ExpectedRevision = effect.Revision
	recovered, err := gateway.Apply(effect, event)
	if err != nil {
		t.Fatalf("Apply(recovered completion) error = %v", err)
	}
	if recovered.Effect.State != StateCompleted || recovered.Effect.Outcome != OutcomeCompleted {
		t.Fatalf("recovered effect = %#v", recovered.Effect)
	}
	settled, err := gateway.AuthorizeSettlement(context.Background(), recovered.Effect, OpaqueAuthority("renewed"))
	if err != nil {
		t.Fatalf("AuthorizeSettlement(recovered) error = %v", err)
	}
	if settled.QuotaReceipt.Disposition != QuotaDispositionConsume || fixture.quota.settlements != 2 {
		t.Fatalf("recovered quota settlement = %#v; mutations=%d", settled.QuotaReceipt, fixture.quota.settlements)
	}
}

func TestDurableRetrievalReservesAnEventForRecoveryAfterUncertainCancellation(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	fixture.bounds.MaxEvents = 8
	fixture.provider.availability.DurableRequestRetrieval = true
	fixture.provider.stream = &singleEventProviderStream{event: ProviderEvent{
		Kind: ProviderEventResponseCompleted,
		Response: &ProviderResponse{
			Text: "recovered", FinishReason: "stop",
			Usage: Usage{InputTokens: 11, OutputTokens: 1},
		},
	}}
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch}).Effect
	effect = apply(t, gateway, effect, Event{
		ExpectedRevision: effect.Revision, Kind: EventProviderAccepted, ProviderRequestID: "provider-request-1",
	}).Effect
	for range 3 {
		effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventDelta, Delta: "x"}).Effect
	}
	if _, err := gateway.Apply(effect, Event{ExpectedRevision: effect.Revision, Kind: EventDelta, Delta: "x"}); !errors.Is(err, ErrEventLimit) {
		t.Fatalf("Apply(delta consuming durable recovery reserve) error = %v, want ErrEventLimit", err)
	}
	effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventCancelRequested}).Effect
	effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventCancellationResolved}).Effect
	if effect.State != StateUncertain || effect.EventCount != fixture.bounds.MaxEvents-1 {
		t.Fatalf("uncertain effect = %#v, want one recovery event remaining", effect)
	}
	stream, err := gateway.ResumeProviderRequest(context.Background(), OpaqueAuthority("renewed"), effect)
	if err != nil {
		t.Fatalf("ResumeProviderRequest() error = %v", err)
	}
	event, err := stream.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() error = %v", err)
	}
	event.ExpectedRevision = effect.Revision
	recovered, err := gateway.Apply(effect, event)
	if err != nil {
		t.Fatalf("Apply(recovered terminal event) error = %v", err)
	}
	if recovered.Effect.State != StateCompleted || recovered.Effect.EventCount != fixture.bounds.MaxEvents {
		t.Fatalf("recovered effect = %#v", recovered.Effect)
	}
}

func TestRepeatedUnknownRecoveryRefreshesTheQuotaHold(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	fixture.provider.availability.DurableRequestRetrieval = true
	fixture.provider.stream = &singleEventProviderStream{event: ProviderEvent{
		Kind: ProviderEventFailed, Failure: FailureTransportUnknown, Diagnostic: "still unknown",
	}}
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch}).Effect
	effect = apply(t, gateway, effect, Event{
		ExpectedRevision: effect.Revision, Kind: EventProviderAccepted, ProviderRequestID: "provider-request-1",
	}).Effect
	effect = apply(t, gateway, effect, Event{
		ExpectedRevision: effect.Revision, Kind: EventDispatchFailed,
		Failure: FailureTransportUnknown, Reason: "unknown",
	}).Effect
	first, err := gateway.AuthorizeSettlement(context.Background(), effect, OpaqueAuthority("renewed"))
	if err != nil || first.QuotaReceipt.Disposition != QuotaDispositionHold {
		t.Fatalf("AuthorizeSettlement(initial hold) = %#v, %v", first, err)
	}
	stream, err := gateway.ResumeProviderRequest(context.Background(), OpaqueAuthority("renewed"), effect)
	if err != nil {
		t.Fatalf("ResumeProviderRequest() error = %v", err)
	}
	event, err := stream.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() error = %v", err)
	}
	event.ExpectedRevision = effect.Revision
	recovered := apply(t, gateway, effect, event).Effect
	if recovered.State != StateUncertain || recovered.RecoveryPermit == (ResumePermit{}) {
		t.Fatalf("recovered unknown effect = %#v", recovered)
	}
	refreshed, err := gateway.AuthorizeSettlement(context.Background(), recovered, OpaqueAuthority("renewed"))
	if err != nil {
		t.Fatalf("AuthorizeSettlement(refreshed hold) error = %v", err)
	}
	if refreshed.QuotaReceipt.Disposition != QuotaDispositionHold ||
		refreshed.QuotaReceipt.Recovery != recovered.RecoveryPermit || fixture.quota.settlements != 2 {
		t.Fatalf("refreshed hold = %#v; mutations=%d", refreshed.QuotaReceipt, fixture.quota.settlements)
	}
}

func TestCancellationPendingCannotStartAnUnapplicableRecoveryStream(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	fixture.provider.availability.DurableRequestRetrieval = true
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch}).Effect
	effect = apply(t, gateway, effect, Event{
		ExpectedRevision: effect.Revision, Kind: EventProviderAccepted, ProviderRequestID: "provider-request-1",
	}).Effect
	effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventCancelRequested}).Effect

	if _, err := gateway.ResumeProviderRequest(context.Background(), OpaqueAuthority("renewed"), effect); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("ResumeProviderRequest(cancellation pending) error = %v, want ErrInvalidTransition", err)
	}
	if fixture.provider.resumeCalls != 0 {
		t.Fatalf("provider received %d unusable resume calls", fixture.provider.resumeCalls)
	}
}

func TestRestoredCancellationCannotFlipTheDurableDispatchPreventionResult(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	begin := apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch})
	if _, err := fixture.dispatches.CommitAndClaimDispatch(context.Background(), DispatchCommitRequest{
		ExpectedRevision: effect.Revision, CurrentScope: effect.Scope, Effect: begin.Effect, Command: *begin.Dispatch,
	}); err != nil {
		t.Fatalf("CommitAndClaimDispatch() error = %v", err)
	}
	cancellation := apply(t, gateway, begin.Effect, Event{ExpectedRevision: begin.Effect.Revision, Kind: EventCancelRequested})
	execution, err := gateway.ExecuteCancel(context.Background(), OpaqueAuthority("renewed"), cancellation)
	if err != nil {
		t.Fatalf("ExecuteCancel() error = %v", err)
	}
	if !execution.Permit.DispatchPrevented {
		t.Fatal("coordinator did not prove pre-I/O dispatch prevention")
	}
	cancelled := apply(t, gateway, execution.Effect, execution.Resolution).Effect
	cancelled.CancellationPermit.DispatchPrevented = false

	if _, err := gateway.AuthorizeSettlement(context.Background(), cancelled, OpaqueAuthority("renewed")); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("AuthorizeSettlement(flipped cancellation proof) error = %v, want ErrInvalidRequest", err)
	}
}

func TestCancellationResolutionRejectsADispatchPreventionFlagMismatch(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	begin := apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch})
	if _, err := fixture.dispatches.CommitAndClaimDispatch(context.Background(), DispatchCommitRequest{
		ExpectedRevision: effect.Revision, CurrentScope: effect.Scope, Effect: begin.Effect, Command: *begin.Dispatch,
	}); err != nil {
		t.Fatalf("CommitAndClaimDispatch() error = %v", err)
	}
	cancellation := apply(t, gateway, begin.Effect, Event{ExpectedRevision: begin.Effect.Revision, Kind: EventCancelRequested})
	execution, err := gateway.ExecuteCancel(context.Background(), OpaqueAuthority("renewed"), cancellation)
	if err != nil {
		t.Fatalf("ExecuteCancel() error = %v", err)
	}
	if !execution.Permit.DispatchPrevented {
		t.Fatal("coordinator did not prove dispatch prevention")
	}
	execution.Resolution.DispatchPrevented = false

	if _, err := gateway.Apply(execution.Effect, execution.Resolution); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Apply(mismatched prevention flag) error = %v, want ErrInvalidRequest", err)
	}
}

func TestProviderErrorsNeverCrossTheGatewayCredentialBoundary(t *testing.T) {
	t.Parallel()
	const secret = "Authorization: Bearer provider-secret"

	t.Run("availability", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.provider.availabilityErr = errors.New(secret)
		gateway := fixture.gateway(t)
		_, err := gateway.Admit(context.Background(), fixture.admissionRequest())
		if err == nil || strings.Contains(err.Error(), secret) {
			t.Fatalf("Admit() error = %q; provider secret was exposed", err)
		}
	})

	t.Run("dispatch", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.provider.dispatchErr = errors.New(secret)
		gateway := fixture.gateway(t)
		effect := fixture.admit(t, gateway)
		transition := apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch})
		execution, err := gateway.ExecuteDispatch(context.Background(), OpaqueAuthority("renewed"), transition)
		if err != nil {
			t.Fatalf("ExecuteDispatch() error = %v", err)
		}
		if execution.Failure == nil || strings.Contains(execution.Failure.Reason, secret) {
			t.Fatalf("dispatch failure = %#v; provider secret was exposed", execution.Failure)
		}
	})

	t.Run("typed dispatch classification", func(t *testing.T) {
		const typedSecret = "provider-secret"
		fixture := newFixture(t)
		fixture.provider.dispatchErr = mustProviderDispatchError(t, DispatchFailureDefinitelyNotSent, typedSecret)
		gateway := fixture.gateway(t)
		effect := fixture.admit(t, gateway)
		transition := apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch})
		execution, err := gateway.ExecuteDispatch(context.Background(), OpaqueAuthority("renewed"), transition)
		if err != nil {
			t.Fatalf("ExecuteDispatch() error = %v", err)
		}
		if execution.Failure == nil || execution.Failure.Failure != FailurePreDispatch || strings.Contains(execution.Failure.Reason, typedSecret) {
			t.Fatalf("typed dispatch failure = %#v; provider detail was exposed", execution.Failure)
		}
	})

	t.Run("resume", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.provider.availability.DurableRequestRetrieval = true
		fixture.provider.resumeErr = errors.New(secret)
		gateway := fixture.gateway(t)
		effect := fixture.admit(t, gateway)
		effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch}).Effect
		effect = apply(t, gateway, effect, Event{
			ExpectedRevision: effect.Revision, Kind: EventProviderAccepted, ProviderRequestID: "provider-request-1",
		}).Effect
		_, err := gateway.ResumeProviderRequest(context.Background(), OpaqueAuthority("renewed"), effect)
		if err == nil || strings.Contains(err.Error(), secret) {
			t.Fatalf("ResumeProviderRequest() error = %q; provider secret was exposed", err)
		}
	})

	t.Run("resume stream", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.provider.availability.DurableRequestRetrieval = true
		fixture.provider.stream = errorProviderStream{err: errors.New(secret)}
		gateway := fixture.gateway(t)
		effect := fixture.admit(t, gateway)
		effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch}).Effect
		effect = apply(t, gateway, effect, Event{
			ExpectedRevision: effect.Revision, Kind: EventProviderAccepted, ProviderRequestID: "provider-request-1",
		}).Effect
		stream, err := gateway.ResumeProviderRequest(context.Background(), OpaqueAuthority("renewed"), effect)
		if err != nil {
			t.Fatalf("ResumeProviderRequest() error = %v", err)
		}
		_, err = stream.Next(context.Background())
		if err == nil || strings.Contains(err.Error(), secret) {
			t.Fatalf("Next() error = %q; provider secret was exposed", err)
		}
	})

	t.Run("dispatch stream next", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.provider.stream = providerErrorStream{nextErr: errors.New(secret)}
		gateway := fixture.gateway(t)
		effect := fixture.admit(t, gateway)
		transition := apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch})
		execution, err := gateway.ExecuteDispatch(context.Background(), OpaqueAuthority("renewed"), transition)
		if err != nil {
			t.Fatalf("ExecuteDispatch() error = %v", err)
		}
		_, err = execution.Stream.Next(context.Background())
		if err == nil || !errors.Is(err, ErrProviderUnavailable) || strings.Contains(err.Error(), secret) {
			t.Fatalf("Next() error = %q; want redacted ErrProviderUnavailable", err)
		}
	})

	t.Run("dispatch stream close", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.provider.stream = providerErrorStream{closeErr: errors.New(secret)}
		gateway := fixture.gateway(t)
		effect := fixture.admit(t, gateway)
		transition := apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch})
		execution, err := gateway.ExecuteDispatch(context.Background(), OpaqueAuthority("renewed"), transition)
		if err != nil {
			t.Fatalf("ExecuteDispatch() error = %v", err)
		}
		err = execution.Stream.Close()
		if err == nil || !errors.Is(err, ErrProviderUnavailable) || strings.Contains(err.Error(), secret) {
			t.Fatalf("Close() error = %q; want redacted ErrProviderUnavailable", err)
		}
	})
}

func TestProviderFailureEventsNeverCrossTheGatewayCredentialBoundary(t *testing.T) {
	t.Parallel()
	const secret = "api-key-secret"

	for _, recovery := range []bool{false, true} {
		recovery := recovery
		name := "normal"
		if recovery {
			name = "resume"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newFixture(t)
			fixture.provider.availability.DurableRequestRetrieval = recovery
			fixture.provider.stream = &singleEventProviderStream{event: ProviderEvent{
				Kind: ProviderEventFailed, Failure: FailureTransportUnknown, Diagnostic: secret,
			}}
			gateway := fixture.gateway(t)
			effect := fixture.admit(t, gateway)
			begin := apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch})
			execution, err := gateway.ExecuteDispatch(context.Background(), OpaqueAuthority("renewed"), begin)
			if err != nil {
				t.Fatalf("ExecuteDispatch() error = %v", err)
			}
			stream := execution.Stream
			if recovery {
				stream, err = gateway.ResumeProviderRequest(context.Background(), OpaqueAuthority("renewed"), execution.Effect)
				if err != nil {
					t.Fatalf("ResumeProviderRequest() error = %v", err)
				}
			}
			event, err := stream.Next(context.Background())
			if err != nil {
				t.Fatalf("Next() error = %v", err)
			}
			event.ExpectedRevision = execution.Effect.Revision
			terminal := apply(t, gateway, execution.Effect, event).Effect
			settlement, err := gateway.AuthorizeSettlement(context.Background(), terminal, OpaqueAuthority("renewed"))
			if err != nil {
				t.Fatalf("AuthorizeSettlement() error = %v", err)
			}
			if strings.Contains(event.Reason, secret) || strings.Contains(terminal.FailureReason, secret) || strings.Contains(settlement.FailureReason, secret) {
				t.Fatalf("provider diagnostic crossed gateway: event=%q effect=%q settlement=%q", event.Reason, terminal.FailureReason, settlement.FailureReason)
			}
		})
	}
}

func TestProviderFinishReasonIsNormalizedBeforeDurableState(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	const untrustedFinishReason = "stop\napi-key-secret"
	fixture.provider.stream = &singleEventProviderStream{event: ProviderEvent{
		Kind: ProviderEventResponseCompleted,
		Response: &ProviderResponse{
			Text: "answer", FinishReason: untrustedFinishReason,
			Usage: Usage{InputTokens: 11, OutputTokens: 1},
		},
	}}
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	begin := apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch})
	execution, err := gateway.ExecuteDispatch(context.Background(), OpaqueAuthority("renewed"), begin)
	if err != nil {
		t.Fatalf("ExecuteDispatch() error = %v", err)
	}
	event, err := execution.Stream.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() error = %v", err)
	}
	if event.Response == nil || string(event.Response.FinishReason) == untrustedFinishReason || strings.Contains(string(event.Response.FinishReason), "api-key-secret") {
		t.Fatalf("normalized provider response = %#v", event.Response)
	}
	event.ExpectedRevision = execution.Effect.Revision
	completed := apply(t, gateway, execution.Effect, event).Effect
	settlement, err := gateway.AuthorizeSettlement(context.Background(), completed, OpaqueAuthority("renewed"))
	if err != nil {
		t.Fatalf("AuthorizeSettlement() error = %v", err)
	}
	if settlement.Response == nil || strings.Contains(string(settlement.Response.FinishReason), "api-key-secret") {
		t.Fatalf("settled provider response = %#v", settlement.Response)
	}
}

func TestRestoredEffectRejectsANonNormalizedProviderFailureReason(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch}).Effect
	effect = apply(t, gateway, effect, Event{
		ExpectedRevision: effect.Revision, Kind: EventDispatchFailed,
		Failure: FailureTransportUnknown, Reason: "provider diagnostic",
	}).Effect
	effect.FailureReason = "api-key-secret"

	if _, err := gateway.AuthorizeSettlement(context.Background(), effect, OpaqueAuthority("renewed")); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("AuthorizeSettlement(non-normalized failure) error = %v, want ErrInvalidRequest", err)
	}
}

type singleEventProviderStream struct {
	event ProviderEvent
	done  bool
}

func (stream *singleEventProviderStream) Next(context.Context) (ProviderEvent, error) {
	if stream.done {
		return ProviderEvent{}, io.EOF
	}
	stream.done = true
	return stream.event, nil
}

func (*singleEventProviderStream) Close() error { return nil }

type errorProviderStream struct{ err error }

func (stream errorProviderStream) Next(context.Context) (ProviderEvent, error) {
	return ProviderEvent{}, stream.err
}
func (errorProviderStream) Close() error { return nil }

type providerErrorStream struct {
	nextErr  error
	closeErr error
}

func (stream providerErrorStream) Next(context.Context) (ProviderEvent, error) {
	return ProviderEvent{}, stream.nextErr
}

func (stream providerErrorStream) Close() error { return stream.closeErr }
