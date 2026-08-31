package mcpgateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

type functionCall struct {
	next  func(context.Context) (ProviderEvent, error)
	close func(context.Context) error
}

func (call *functionCall) Next(ctx context.Context) (ProviderEvent, error) {
	return call.next(ctx)
}

func (call *functionCall) Close(ctx context.Context) error {
	if call.close != nil {
		return call.close(ctx)
	}
	return nil
}

func completedCall(output string) ProviderCall {
	var once sync.Once
	return &functionCall{next: func(context.Context) (ProviderEvent, error) {
		var event ProviderEvent
		once.Do(func() {
			event = ProviderEvent{Kind: ProviderCompleted, Output: []byte(output), ExternalCommitID: "commit-1"}
		})
		if event.Kind == "" {
			return ProviderEvent{}, io.EOF
		}
		return event, nil
	}}
}

func discardSink() OutputSink {
	return OutputSinkFunc(func(context.Context, []byte) error { return nil })
}

func TestExecuteRechecksToolPolicyImmediatelyBeforeProviderIO(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayIdempotencyKey)
	effect := admitFixtureEffect(t, fixture)
	fixture.authorizer.setDenied(true)

	_, err := fixture.gateway.Execute(context.Background(), OpaqueAuthority("turn-secret"), effect, discardSink())
	if !errors.Is(err, ErrToolNotAllowed) {
		t.Fatalf("Execute error = %v, want %v", err, ErrToolNotAllowed)
	}
	if starts := fixture.provider.startCount(); starts != 0 {
		t.Fatalf("revoked tool reached provider %d times", starts)
	}
	stored, err := fixture.repository.Load(context.Background(), effect.Scope.InvocationID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Effect.State != StateAdmitted || stored.Effect.Revision != effect.Revision {
		t.Fatalf("revoked call mutated durable state: %+v", stored.Effect)
	}
}

func TestAtomicDispatchClaimAllowsOneConcurrentProviderCall(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayIdempotencyKey)
	effect := admitFixtureEffect(t, fixture)
	started := make(chan struct{})
	release := make(chan struct{})
	var signal sync.Once
	fixture.provider.start = func(_ context.Context, command ProviderCommand) (ProviderStartResult, error) {
		signal.Do(func() { close(started) })
		<-release
		return ProviderStartResult{ProviderRequestID: "rpc-concurrent", Call: completedCall(`{"ok":true}`)}, nil
	}

	const callers = 48
	errorsByCaller := make(chan error, callers)
	results := make(chan Effect, callers)
	var group sync.WaitGroup
	for range callers {
		group.Add(1)
		go func() {
			defer group.Done()
			result, err := fixture.gateway.Execute(context.Background(), OpaqueAuthority("turn-secret"), effect, discardSink())
			results <- result
			errorsByCaller <- err
		}()
	}
	<-started
	close(release)
	group.Wait()
	close(errorsByCaller)
	close(results)

	successes := 0
	conflicts := 0
	for err := range errorsByCaller {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrConcurrentTransition):
			conflicts++
		default:
			t.Fatalf("unexpected concurrent Execute error: %v", err)
		}
	}
	if successes != 1 || conflicts != callers-1 || fixture.provider.startCount() != 1 {
		t.Fatalf("dispatch results: success=%d conflict=%d starts=%d", successes, conflicts, fixture.provider.startCount())
	}
	stored, err := fixture.repository.Load(context.Background(), effect.Scope.InvocationID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Effect.State != StateCompleted || string(stored.Effect.Output) != `{"ok":true}` {
		t.Fatalf("durable completed effect = %+v", stored.Effect)
	}
	fixture.provider.mu.Lock()
	command := fixture.provider.lastCommand
	fixture.provider.mu.Unlock()
	if command.IdempotencyKey != effect.Scope.InvocationID.String() || !command.Dispatch.Durable {
		t.Fatalf("provider command lacks durable invocation binding: %#v", command)
	}
	formatted := fmt.Sprintf("%#v", command)
	if strings.Contains(formatted, fixture.credentials.rawValue) || strings.Contains(formatted, fixture.handle.value) {
		t.Fatalf("provider command formatting exposed credential material: %s", formatted)
	}
}

func TestExecuteAppliesSynchronousBackpressure(t *testing.T) {
	fixture := newGatewayFixture(t, ReplaySafe)
	effect := admitFixtureEffect(t, fixture)
	firstSink := make(chan struct{})
	releaseSink := make(chan struct{})
	secondNext := make(chan struct{}, 1)
	var mu sync.Mutex
	nextCalls := 0
	call := &functionCall{next: func(context.Context) (ProviderEvent, error) {
		mu.Lock()
		nextCalls++
		callNumber := nextCalls
		mu.Unlock()
		switch callNumber {
		case 1:
			return ProviderEvent{Kind: ProviderOutputChunk, Chunk: []byte("one")}, nil
		case 2:
			secondNext <- struct{}{}
			return ProviderEvent{Kind: ProviderOutputChunk, Chunk: []byte("two")}, nil
		case 3:
			return ProviderEvent{Kind: ProviderCompleted, Output: []byte(`{"done":true}`), ExternalCommitID: "commit-stream"}, nil
		default:
			return ProviderEvent{}, io.EOF
		}
	}}
	fixture.provider.start = func(context.Context, ProviderCommand) (ProviderStartResult, error) {
		return ProviderStartResult{ProviderRequestID: "rpc-stream", Call: call}, nil
	}
	sinkCalls := 0
	sink := OutputSinkFunc(func(context.Context, []byte) error {
		sinkCalls++
		if sinkCalls == 1 {
			close(firstSink)
			<-releaseSink
		}
		return nil
	})
	done := make(chan struct{})
	var result Effect
	var executeErr error
	go func() {
		result, executeErr = fixture.gateway.Execute(context.Background(), OpaqueAuthority("turn-secret"), effect, sink)
		close(done)
	}()
	<-firstSink
	select {
	case <-secondNext:
		t.Fatal("provider stream advanced while the output sink was blocked")
	default:
	}
	close(releaseSink)
	<-done
	if executeErr != nil {
		t.Fatal(executeErr)
	}
	if result.State != StateCompleted || sinkCalls != 2 {
		t.Fatalf("stream result state=%s sink calls=%d", result.State, sinkCalls)
	}
}

func TestOutputLimitDurablyRequestsCancellationBeforeProviderCancel(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	effect := admitFixtureEffect(t, fixture)
	fixture.provider.start = func(context.Context, ProviderCommand) (ProviderStartResult, error) {
		call := &functionCall{next: func(context.Context) (ProviderEvent, error) {
			return ProviderEvent{Kind: ProviderOutputChunk, Chunk: make([]byte, testBounds().MaxChunkBytes+1)}, nil
		}}
		return ProviderStartResult{ProviderRequestID: "rpc-too-large", Call: call}, nil
	}
	fixture.provider.cancel = func(_ context.Context, command CancelCommand) (CancellationResult, error) {
		stored, err := fixture.repository.Load(context.Background(), command.InvocationID)
		if err != nil {
			t.Fatal(err)
		}
		if stored.Effect.State != StateCancellationPending {
			t.Fatalf("provider cancel ran before durable cancellation: state=%s", stored.Effect.State)
		}
		return CancellationResult{Status: CancellationUnknown}, nil
	}

	result, err := fixture.gateway.Execute(context.Background(), OpaqueAuthority("turn-secret"), effect, discardSink())
	if !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("Execute error = %v, want output limit", err)
	}
	if result.State != StateUncertain || !result.Terminal() {
		t.Fatalf("unknown cancellation state = %s, want uncertain", result.State)
	}
	stored, loadErr := fixture.repository.Load(context.Background(), effect.Scope.InvocationID)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if !sameEffect(stored.Effect, result) {
		t.Fatalf("returned state differs from durable state")
	}
}

func TestSinkFailureCancelsAndClassifiesAbsentInvocation(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	effect := admitFixtureEffect(t, fixture)
	fixture.provider.start = func(context.Context, ProviderCommand) (ProviderStartResult, error) {
		call := &functionCall{next: func(context.Context) (ProviderEvent, error) {
			return ProviderEvent{Kind: ProviderOutputChunk, Chunk: []byte("chunk")}, nil
		}}
		return ProviderStartResult{ProviderRequestID: "rpc-sink", Call: call}, nil
	}
	fixture.provider.cancel = func(context.Context, CancelCommand) (CancellationResult, error) {
		return CancellationResult{Status: CancellationAbsent}, nil
	}
	sinkError := errors.New("consumer disconnected")
	result, err := fixture.gateway.Execute(context.Background(), OpaqueAuthority("turn-secret"), effect,
		OutputSinkFunc(func(context.Context, []byte) error { return sinkError }))
	if !errors.Is(err, ErrBackpressure) || errors.Is(err, sinkError) || strings.Contains(err.Error(), sinkError.Error()) {
		t.Fatalf("sink failure = %v, want redacted backpressure error", err)
	}
	if result.State != StateCancelled {
		t.Fatalf("ledger-absent cancellation state = %s, want cancelled", result.State)
	}
}

func TestCrashRecoverySettlesCommittedLedgerWithoutRedispatch(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	effect := admitFixtureEffect(t, fixture)
	fixture.provider.start = func(context.Context, ProviderCommand) (ProviderStartResult, error) {
		return ProviderStartResult{
			ProviderRequestID: "rpc-crash",
			Call: &functionCall{next: func(context.Context) (ProviderEvent, error) {
				return ProviderEvent{}, io.ErrUnexpectedEOF
			}},
		}, nil
	}
	uncertain, err := fixture.gateway.Execute(context.Background(), OpaqueAuthority("turn-secret"), effect, discardSink())
	if err != nil {
		t.Fatal(err)
	}
	if uncertain.State != StateUncertain {
		t.Fatalf("crash state = %s, want uncertain", uncertain.State)
	}
	fixture.provider.mu.Lock()
	fixture.provider.lookup = func(_ context.Context, query LedgerQuery) (LedgerRecord, error) {
		return LedgerRecord{
			InvocationID: query.InvocationID, RequestDigest: query.RequestDigest, Status: LedgerCommitted,
			ProviderRequestID: "rpc-crash", ExternalCommitID: "external-77", Output: []byte(`{"created":true}`),
		}, nil
	}
	fixture.provider.mu.Unlock()

	recovered, err := fixture.gateway.Recover(context.Background(), OpaqueAuthority("renewed-turn-secret"), uncertain)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Action != RecoverySettled || recovered.Effect.State != StateCompleted || string(recovered.Effect.Output) != `{"created":true}` {
		t.Fatalf("recovery result = %+v", recovered)
	}
	if fixture.provider.startCount() != 1 {
		t.Fatalf("committed recovery redispatched provider: starts=%d", fixture.provider.startCount())
	}
}

func TestDurableFenceRotationWinsAfterFreshGatewayValidation(t *testing.T) {
	fixture := newGatewayFixture(t, ReplaySafe)
	effect := admitFixtureEffect(t, fixture)
	rotated := effect.Scope
	rotated.Generations.Placement++
	if err := fixture.repository.SetCurrentAuthority(rotated); err != nil {
		t.Fatal(err)
	}
	fixture.provider.start = func(context.Context, ProviderCommand) (ProviderStartResult, error) {
		return ProviderStartResult{ProviderRequestID: "must-not-run", Call: completedCall(`{"bad":true}`)}, nil
	}

	_, err := fixture.gateway.Execute(context.Background(), OpaqueAuthority("old-but-validator-stub-accepts"), effect, discardSink())
	if !errors.Is(err, ErrStaleAuthority) {
		t.Fatalf("rotated durable fence error = %v, want %v", err, ErrStaleAuthority)
	}
	if fixture.provider.startCount() != 0 {
		t.Fatal("stale placement reached provider")
	}
}

func TestConfirmedRetryIsDurablyCASSerialized(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayConfirm)
	effect := admitFixtureEffect(t, fixture)
	begin := applyFixtureEvent(t, fixture.gateway, effect, Event{Kind: EventBeginDispatch})
	permit, err := fixture.repository.CommitAndClaimDispatch(context.Background(), DispatchClaimRequest{
		ExpectedRevision: effect.Revision, CurrentScope: effect.Scope, Previous: effect, Next: begin,
		Authorization: permitForEffect(begin),
	})
	if err != nil || !permit.Durable {
		t.Fatalf("claim dispatch: permit=%+v err=%v", permit, err)
	}
	negotiated := negotiateFixtureEffect(t, fixture.gateway, begin)
	persistFixtureEffect(t, fixture.repository, begin, negotiated)
	accepted := applyFixtureEvent(t, fixture.gateway, negotiated, Event{Kind: EventProviderAccepted, ProviderRequestID: "rpc-confirm-cas"})
	persistFixtureEffect(t, fixture.repository, negotiated, accepted)
	needsConfirmation := applyFixtureEvent(t, fixture.gateway, accepted, Event{
		Kind: EventDispatchFailed, Failure: FailureUnknown, Reason: "unknown",
	})
	persistFixtureEffect(t, fixture.repository, accepted, needsConfirmation)

	const callers = 24
	var group sync.WaitGroup
	errs := make(chan error, callers)
	for range callers {
		group.Add(1)
		go func() {
			defer group.Done()
			_, confirmErr := fixture.gateway.Confirm(context.Background(), OpaqueAuthority("turn-secret"), needsConfirmation, ConfirmationRetry)
			errs <- confirmErr
		}()
	}
	group.Wait()
	close(errs)
	successes := 0
	for confirmErr := range errs {
		if confirmErr == nil {
			successes++
		} else if !errors.Is(confirmErr, ErrConcurrentTransition) {
			t.Fatalf("unexpected confirmation error: %v", confirmErr)
		}
	}
	if successes != 1 {
		t.Fatalf("confirmation CAS successes = %d, want 1", successes)
	}
	stored, err := fixture.repository.Load(context.Background(), effect.Scope.InvocationID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Effect.State != StateRetryPending || stored.Effect.ConfirmationRetriesUsed != 1 {
		t.Fatalf("stored confirmation = %+v", stored.Effect)
	}
}

func permitForEffect(effect Effect) ToolAuthorizationPermit {
	proof := ToolAuthorizationProof{}
	proof[0] = 1
	return ToolAuthorizationPermit{
		Proof: proof, Durable: true, Scope: effect.Scope, ServerID: effect.ServerID,
		ToolName: effect.ToolName, RequestDigest: effect.RequestDigest,
	}
}

func persistFixtureEffect(t *testing.T, repository EffectRepository, previous, next Effect) {
	t.Helper()
	stored, err := repository.Commit(context.Background(), TransitionCommitRequest{
		ExpectedRevision: previous.Revision, CurrentScope: previous.Scope, Previous: previous, Next: next,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !stored.Durable || !sameEffect(stored.Effect, next) {
		t.Fatal("effect was not persisted exactly")
	}
}

func TestCancelTimeoutIsBounded(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	effect := admitFixtureEffect(t, fixture)
	fixture.provider.start = func(context.Context, ProviderCommand) (ProviderStartResult, error) {
		return ProviderStartResult{ProviderRequestID: "rpc-timeout", Call: &functionCall{next: func(ctx context.Context) (ProviderEvent, error) {
			<-ctx.Done()
			return ProviderEvent{}, ctx.Err()
		}}}, nil
	}
	fixture.provider.cancel = func(ctx context.Context, _ CancelCommand) (CancellationResult, error) {
		<-ctx.Done()
		return CancellationResult{Status: CancellationUnknown}, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	_, err := fixture.gateway.Execute(ctx, OpaqueAuthority("turn-secret"), effect, discardSink())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-dispatch cancelled Execute = %v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("pre-dispatch cancellation ignored caller context")
	}
}
