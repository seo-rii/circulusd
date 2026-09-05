package modelgateway

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/effectledger"
)

func TestModelGatewayValidatesStreamCloseTimeout(t *testing.T) {
	t.Parallel()
	for _, timeout := range []time.Duration{-time.Nanosecond, maximumStreamCloseTimeout + time.Nanosecond} {
		fixture := newFixture(t)
		configuration := fixture.configuration()
		configuration.StreamCloseTimeout = timeout
		if _, err := NewGateway(configuration, fixture.dependencies()); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("StreamCloseTimeout %s: %v", timeout, err)
		}
	}
	fixture := newFixture(t)
	if gateway := fixture.gateway(t); gateway.streamCloseTimeout != defaultStreamCloseTimeout {
		t.Fatalf("default cleanup timeout = %s", gateway.streamCloseTimeout)
	}
}

func TestSessionModelRetainsCompletedResultBeforeCleanupDeadline(t *testing.T) {
	t.Parallel()
	stream := &cleanupProviderStream{scriptedSessionProviderStream: &scriptedSessionProviderStream{
		events: []ProviderEvent{completedSessionProviderEvent()},
	}}
	fixture := newSessionDispatchTest(t, stream, nil, true)
	configuration := fixture.model.configuration()
	configuration.StreamCloseTimeout = 10 * time.Millisecond
	dependencies := fixture.model.dependencies()
	dependencies.Providers = map[string]Provider{"provider-a": fixture.provider}
	gateway, err := NewGateway(configuration, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	starter, err := NewReferenceSessionDispatchStarter(gateway, fixture.ledger, fixture.dispatch.ProviderRouteDigest)
	if err != nil {
		t.Fatal(err)
	}
	fixture.gateway, fixture.starter = gateway, starter
	cleanupFinished := false
	stream.close = func(ctx context.Context) error {
		deadline, bounded := ctx.Deadline()
		if !bounded || ctx.Err() != nil || time.Until(deadline) > configuration.StreamCloseTimeout {
			t.Fatalf("cleanup lacks its fresh finite lifetime: bounded=%t err=%v", bounded, ctx.Err())
		}
		facts, err := fixture.ledger.Inspect(context.Background(), sessionLookup(fixture.dispatch))
		if err != nil || facts.State != effectledger.StateTerminal || facts.Terminal.Status != effectledger.TerminalCommitted {
			t.Fatalf("completed result was not retained before Close: %v, %v", facts, err)
		}
		result, err := DecodeSessionDispatchResult(facts.Terminal.Result)
		if err != nil || result.Response == nil || result.Response.Text != "done" {
			t.Fatalf("completed output was lost before Close: %v", err)
		}
		<-ctx.Done()
		cleanupFinished = true
		return ctx.Err()
	}
	digest, err := starter.Prepare(context.Background(), fixture.dispatch, fixture.transition)
	if err != nil {
		t.Fatal(err)
	}
	consumer, _ := fixture.consumer(t, digest)
	started := time.Now()
	if _, err := consumer.StartExactAttempt(context.Background(), fixture.startRequest(digest)); !errors.Is(err, broker.ErrDispatchStartUnknown) {
		t.Fatalf("cleanup failure was not propagated: %v", err)
	}
	if !cleanupFinished || time.Since(started) > time.Second {
		t.Fatalf("cleanup was abandoned or exceeded its bound: finished=%t elapsed=%s", cleanupFinished, time.Since(started))
	}
	record, err := fixture.ledger.Lookup(context.Background(), sessionLookup(fixture.dispatch))
	if err != nil || record.Status != broker.LedgerCommitted {
		t.Fatalf("cleanup timeout changed committed recovery outcome: %v, %v", record, err)
	}
	if _, err := consumer.StartExactAttempt(context.Background(), fixture.startRequest(digest)); !errors.Is(err, broker.ErrDispatchAlreadyStarted) {
		t.Fatalf("cleanup timeout reopened the provider start: %v", err)
	}
	if _, calls := fixture.provider.snapshot(); calls != 1 {
		t.Fatalf("provider calls = %d, want one", calls)
	}
}

func TestModelStreamCloseHonorsCallerDeadlineAndRedactsProviderFailure(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	gateway := fixture.gateway(t)
	const sensitiveDetail = "Authorization: Bearer provider-secret"
	closed := false
	provider := &cleanupProviderStream{close: func(ctx context.Context) error {
		<-ctx.Done()
		closed = true
		return errors.New(sensitiveDetail)
	}}
	stream := &normalizedProviderStream{gateway: gateway, stream: provider}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	err := stream.Close(ctx)
	if !closed || !errors.Is(err, ErrProviderUnavailable) || !errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), sensitiveDetail) {
		t.Fatalf("Close() = %v, completed=%t; want bounded redacted deadline error", err, closed)
	}
}

func TestModelDispatchFailureCleanupSurvivesCallerCancellation(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fixture.provider.onDispatch = cancel
	fixture.provider.dispatchErr = errors.New("provider dispatch credential detail")
	fixture.provider.returnRequestIDOnError = true
	closed := false
	fixture.provider.stream = &cleanupProviderStream{close: func(cleanupContext context.Context) error {
		if cleanupContext.Err() != nil {
			t.Fatalf("caller cancellation prevented cleanup: %v", cleanupContext.Err())
		}
		if _, bounded := cleanupContext.Deadline(); !bounded {
			t.Fatal("dispatch failure cleanup has no deadline")
		}
		<-cleanupContext.Done()
		closed = true
		return errors.New("provider close credential detail")
	}}
	configuration := fixture.configuration()
	configuration.StreamCloseTimeout = 10 * time.Millisecond
	gateway, err := NewGateway(configuration, fixture.dependencies())
	if err != nil {
		t.Fatal(err)
	}
	effect := fixture.admit(t, gateway)
	transition := apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch})
	execution, err := gateway.ExecuteDispatch(ctx, OpaqueAuthority("renewed"), transition)
	if !closed || !errors.Is(err, ErrProviderUnavailable) || !errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "credential detail") {
		t.Fatalf("dispatch cleanup error = %v, completed=%t", err, closed)
	}
	if execution.Effect.ProviderRequestID == "" || execution.Failure == nil || execution.Failure.Failure != FailureTransportUnknown {
		t.Fatalf("cleanup failure discarded provider observation: %v", execution)
	}
}

type cleanupProviderStream struct {
	*scriptedSessionProviderStream
	close func(context.Context) error
}

func (stream *cleanupProviderStream) Close(ctx context.Context) error {
	return stream.close(ctx)
}
