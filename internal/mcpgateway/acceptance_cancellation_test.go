package mcpgateway

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/identity"
)

type acceptanceCancellationPoint uint8

const (
	acceptanceNotCancelled acceptanceCancellationPoint = iota
	acceptanceCancelBeforeExecute
	acceptanceCancelDuringNegotiation
	acceptanceCancelBeforeStartReturns
	acceptanceCancelBeforeCommit
	acceptanceCancelAfterCommit
	acceptanceCancelDuringNext
)

type acceptanceCancellationCase struct {
	point       acceptanceCancellationPoint
	providerID  string
	validID     bool
	payload     []byte
	startErr    error
	withoutCall bool
}

type acceptanceCommitRepository struct {
	*MemoryRepository
	before func(context.Context)
	after  func()
}

func (repository *acceptanceCommitRepository) Commit(ctx context.Context, request TransitionCommitRequest) (StoredEffect, error) {
	accepted := request.ProviderStart != nil && request.Next.State == StateDispatched
	if accepted {
		repository.before(ctx)
	}
	stored, err := repository.MemoryRepository.Commit(ctx, request)
	if accepted && err == nil {
		repository.after()
	}
	return stored, err
}

func TestExecuteRetainsAcceptanceAcrossCancellation(t *testing.T) {
	for _, test := range []struct {
		name  string
		point acceptanceCancellationPoint
	}{
		{"not_cancelled", acceptanceNotCancelled},
		{"before_execute", acceptanceCancelBeforeExecute},
		{"during_negotiation", acceptanceCancelDuringNegotiation},
		{"before_start_returns", acceptanceCancelBeforeStartReturns},
		{"before_acceptance_commit", acceptanceCancelBeforeCommit},
		{"after_acceptance_commit", acceptanceCancelAfterCommit},
		{"during_next", acceptanceCancelDuringNext},
	} {
		t.Run(test.name, func(t *testing.T) {
			runAcceptanceCancellationCase(t, acceptanceCancellationCase{
				point: test.point, providerID: "rpc-accepted-at-cancellation", validID: true,
				payload: []byte{0, '<', '\n', 0xff},
			})
		})
	}
}

func TestExecuteCancelledAcceptanceSurvivesStartErrors(t *testing.T) {
	notSent, err := NewProviderDispatchError(DispatchDefinitelyNotSent, "dispatch failed", io.ErrUnexpectedEOF)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name        string
		err         error
		withoutCall bool
	}{
		{name: "cancelled_error", err: context.Canceled},
		{name: "transport_error", err: io.ErrUnexpectedEOF},
		{name: "identity_overrides_not_sent", err: notSent},
		{name: "missing_call", withoutCall: true},
		{name: "error_and_missing_call", err: context.Canceled, withoutCall: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			runAcceptanceCancellationCase(t, acceptanceCancellationCase{
				point: acceptanceCancelBeforeStartReturns, providerID: strings.Repeat("r", 256), validID: true,
				startErr: test.err, withoutCall: test.withoutCall,
			})
		})
	}
}

func TestExecuteCancellationDoesNotAcceptInvalidProviderIdentity(t *testing.T) {
	for _, providerID := range []string{"", " rpc", "rpc ", "rpc\x00", "rpc\xff", strings.Repeat("r", 257)} {
		t.Run(providerID, func(t *testing.T) {
			runAcceptanceCancellationCase(t, acceptanceCancellationCase{
				point: acceptanceCancelBeforeStartReturns, providerID: providerID,
			})
		})
	}
}

// The schedule is injected at observable provider/repository boundaries, so
// the test and fuzzer explore ordering without scheduler-dependent sleeps.
func runAcceptanceCancellationCase(t *testing.T, test acceptanceCancellationCase) {
	t.Helper()
	fixture := newGatewayFixture(t, ReplayNever)
	fixture.gateway.bounds.CancelTimeout = time.Second
	fixture.provider.availability.SupportsInvocationLedger = false
	fixture.provider.availability.SupportsIdempotencyKey = false
	call := CallRequest{
		ServerID: fixture.server.ServerID, ToolName: fixture.tool.ToolName,
		Input: canonical.Map{"payload": canonical.Bytes(test.payload)},
	}
	digest, err := CallRequestDigest(call, fixture.gateway.bounds)
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	assertCleanupContext := func(cleanup context.Context) {
		t.Helper()
		deadline, bounded := cleanup.Deadline()
		if !bounded || time.Until(deadline) > fixture.gateway.bounds.CancelTimeout || cleanup.Err() != nil {
			t.Fatalf("external fact/cleanup context is not live and bounded: deadline=%v err=%v", deadline, cleanup.Err())
		}
	}
	acceptanceCommits := 0
	fixture.gateway.repository = &acceptanceCommitRepository{
		MemoryRepository: fixture.repository,
		before: func(durableCtx context.Context) {
			if test.point == acceptanceCancelBeforeCommit {
				cancel()
			}
			assertCleanupContext(durableCtx)
		},
		after: func() {
			acceptanceCommits++
			if test.point == acceptanceCancelAfterCommit {
				cancel()
			}
		},
	}
	if test.point == acceptanceCancelBeforeExecute {
		cancel()
	}
	if test.point == acceptanceCancelDuringNegotiation {
		fixture.provider.negotiate = func(context.Context, NegotiationCommand) (StartNegotiationReceipt, error) {
			cancel()
			return StartNegotiationReceipt{}, context.Canceled
		}
	}
	wantID := ""
	if test.validID {
		wantID = test.providerID
	}
	assertStoredIdentity := func() Effect {
		t.Helper()
		stored, loadErr := fixture.repository.Load(context.Background(), effect.Scope.InvocationID)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		attempt, _ := stored.Effect.CurrentAttempt()
		if attempt.ProviderRequestID != wantID {
			t.Fatalf("stored provider identity = %q, want %q", attempt.ProviderRequestID, wantID)
		}
		return stored.Effect
	}
	providerRunning, closes, cancels := false, 0, 0
	fixture.provider.start = func(_ context.Context, command ProviderCommand) (ProviderStartResult, error) {
		if !bytes.Equal(command.InputCanonical, effect.InputCanonical) || command.RequestDigest != effect.RequestDigest {
			t.Fatal("provider received a different request payload or digest")
		}
		providerRunning = test.validID
		if test.point == acceptanceCancelBeforeStartReturns {
			cancel()
		}
		result := ProviderStartResult{ProviderRequestID: test.providerID}
		if !test.withoutCall {
			result.Call = &functionCall{
				next: func(context.Context) (ProviderEvent, error) {
					if test.point == acceptanceCancelDuringNext {
						cancel()
						return ProviderEvent{}, context.Canceled
					}
					providerRunning = false
					return ProviderEvent{Kind: ProviderCompleted, Output: append([]byte{1}, test.payload...), ExternalCommitID: "commit-1"}, nil
				},
				close: func(cleanup context.Context) error {
					assertCleanupContext(cleanup)
					assertStoredIdentity()
					closes++
					return nil
				},
			}
		}
		return result, test.startErr
	}
	fixture.provider.cancel = func(cleanup context.Context, command CancelCommand) (CancellationResult, error) {
		assertCleanupContext(cleanup)
		assertStoredIdentity()
		cancels++
		if command.ProviderRequestID != wantID || command.Start == (ProviderStartPermit{}) {
			t.Fatalf("cancellation lost accepted identity or dispatch proof: id=%q want=%q start=%v", command.ProviderRequestID, wantID, command.Start)
		}
		if wantID != "" {
			providerRunning = false
			return CancellationResult{Status: CancellationAbsent}, nil
		}
		return CancellationResult{Status: CancellationUnknown}, nil
	}
	result, executeErr := fixture.gateway.Execute(ctx, OpaqueAuthority("renewed"), effect, discardSink())
	if ctx.Err() != nil && !errors.Is(executeErr, context.Canceled) {
		t.Fatalf("Execute lost caller cancellation: %v", executeErr)
	}
	if ctx.Err() == nil && executeErr != nil {
		t.Fatalf("Execute failed: %v", executeErr)
	}
	starts := fixture.provider.startCount()
	if test.point == acceptanceCancelBeforeExecute || test.point == acceptanceCancelDuringNegotiation {
		if starts != 0 || acceptanceCommits != 0 || closes != 0 || cancels != 0 {
			t.Fatalf("pre-dispatch cancellation reached provider: starts=%d commits=%d closes=%d cancels=%d", starts, acceptanceCommits, closes, cancels)
		}
		return
	}
	wantCommits, wantCloses := 0, 1
	if test.validID {
		wantCommits = 1
	}
	if test.withoutCall {
		wantCloses = 0
	}
	if starts != 1 || acceptanceCommits != wantCommits || closes != wantCloses {
		t.Fatalf("unexpected ownership counts: starts=%d commits=%d closes=%d", starts, acceptanceCommits, closes)
	}
	attempt, _ := result.CurrentAttempt()
	if attempt.ProviderRequestID != wantID || !sameEffect(result, assertStoredIdentity()) {
		t.Fatalf("returned effect lost durable acceptance: id=%q want=%q", attempt.ProviderRequestID, wantID)
	}
	if test.validID && ctx.Err() != nil && (result.State != StateCancelled || providerRunning || cancels != 1) {
		t.Fatalf("accepted request survived cancellation: state=%s running=%v cancels=%d", result.State, providerRunning, cancels)
	}
	if result.State == StateCompleted && !bytes.Equal(result.Output, append([]byte{1}, test.payload...)) {
		t.Fatal("completed payload changed")
	}
	recovered, recoverErr := fixture.gateway.Recover(context.Background(), OpaqueAuthority("renewed"), result)
	if recoverErr != nil {
		t.Fatalf("Recover failed: %v", recoverErr)
	}
	recoveredAttempt, _ := recovered.Effect.CurrentAttempt()
	if recoveredAttempt.ProviderRequestID != wantID {
		t.Fatalf("recovery lost acceptance: %q", recoveredAttempt.ProviderRequestID)
	}
	if test.validID {
		cancelled, cancelErr := fixture.gateway.Cancel(context.Background(), OpaqueAuthority("renewed"), recovered.Effect)
		if cancelErr != nil || (cancelled.State != StateCompleted && cancelled.State != StateCancelled) || providerRunning {
			t.Fatalf("known request could not be settled/cancelled: state=%s running=%v err=%v", cancelled.State, providerRunning, cancelErr)
		}
	}
	if _, replayErr := fixture.gateway.Execute(context.Background(), OpaqueAuthority("renewed"), effect, discardSink()); replayErr == nil {
		t.Fatal("stale admission replay was accepted")
	}
	if fixture.provider.startCount() != 1 {
		t.Fatal("cancellation, recovery, or stale replay dispatched the provider twice")
	}
}
