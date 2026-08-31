package modelgateway

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/dependency"
	dependencycontract "github.com/hancomac/circulusd/internal/dependency/contracttest"
	"github.com/hancomac/circulusd/internal/effectledger"
	"github.com/hancomac/circulusd/internal/identity"
)

func TestReferenceSessionDispatchUsesFreshBrokerClaimWithoutSecondDispatchAuthority(t *testing.T) {
	t.Parallel()
	test := newSessionDispatchTest(t, &scriptedSessionProviderStream{events: []ProviderEvent{completedSessionProviderEvent()}}, nil, true)

	digest, err := test.starter.Prepare(context.Background(), test.dispatch, test.transition)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	prepared, err := test.ledger.Inspect(context.Background(), sessionLookup(test.dispatch))
	if err != nil {
		t.Fatalf("Inspect(prepared) error = %v", err)
	}
	if prepared.State != effectledger.StatePrepared || prepared.Command.Dispatch.Opaque != "" ||
		strings.Contains(string(prepared.Command.Payload), "opaque-authority") {
		t.Fatalf("prepared facts contain authority or wrong state: %#v", prepared)
	}

	consumer, _ := test.consumer(t, digest)
	execution, err := consumer.StartExactAttempt(context.Background(), test.startRequest(digest))
	if err != nil {
		t.Fatalf("StartExactAttempt() error = %v", err)
	}
	if execution.Outcome != broker.DispatchStartOutcomeStarted {
		t.Fatalf("StartExactAttempt() outcome = %q, want started", execution.Outcome)
	}
	if test.model.dispatches.claims != 0 || len(test.model.dispatches.dispatchStage) != 0 {
		t.Fatalf("model coordinator minted a second start authority: claims=%d stages=%#v", test.model.dispatches.claims, test.model.dispatches.dispatchStage)
	}
	command, calls := test.provider.snapshot()
	if calls != 1 || !command.Permit.Durable || command.Permit.Proof == (OpaqueDispatchPermit{}) ||
		command.EffectID != test.transition.Effect.Scope.EffectID || command.InvocationID != test.transition.Effect.Scope.InvocationID ||
		command.RequestDigest != test.transition.Effect.RequestDigest || command.Attempt != test.transition.Effect.Attempt {
		t.Fatalf("provider command/calls = %#v/%d", command, calls)
	}

	facts, err := test.ledger.Inspect(context.Background(), sessionLookup(test.dispatch))
	if err != nil {
		t.Fatalf("Inspect(terminal) error = %v", err)
	}
	if facts.State != effectledger.StateTerminal || facts.ExternalProviderRequestID != "provider-request-1" ||
		facts.Terminal.Status != effectledger.TerminalCommitted || facts.Terminal.ExternalCommitID.Kind() != identity.Commit ||
		facts.Terminal.ResultRef.Kind() != identity.Artifact {
		t.Fatalf("terminal facts = %#v", facts)
	}
	result, err := DecodeSessionDispatchResult(facts.Terminal.Result)
	if err != nil {
		t.Fatalf("DecodeSessionDispatchResult() error = %v", err)
	}
	if result.State != StateCompleted || result.Outcome != OutcomeCompleted || result.ProviderRequestID != "provider-request-1" ||
		result.Response == nil || result.Response.Text != "done" || result.Response.Usage != (Usage{InputTokens: 11, OutputTokens: 17}) {
		t.Fatalf("terminal result = %#v", result)
	}
}

func TestReferenceSessionDispatchPrepareDefensivelyCopiesTheTransition(t *testing.T) {
	t.Parallel()
	test := newSessionDispatchTest(t, &scriptedSessionProviderStream{events: []ProviderEvent{completedSessionProviderEvent()}}, nil, true)
	wantMessage := test.transition.Dispatch.Request.Messages[0]

	digest, err := test.starter.Prepare(context.Background(), test.dispatch, test.transition)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	test.transition.Effect.Request.Messages[0].Content = "mutated effect"
	test.transition.Dispatch.Request.Messages[0].Content = "mutated command"
	test.transition.Dispatch.Request.Reasoning.Effort = ReasoningEffortHigh

	consumer, _ := test.consumer(t, digest)
	if _, err := consumer.StartExactAttempt(context.Background(), test.startRequest(digest)); err != nil {
		t.Fatalf("StartExactAttempt() error = %v", err)
	}
	command, calls := test.provider.snapshot()
	if calls != 1 || command.Request.Messages[0] != wantMessage || command.Request.Reasoning.Effort == ReasoningEffortHigh {
		t.Fatalf("provider observed caller mutation: command=%#v calls=%d", command, calls)
	}
}

func TestReferenceSessionDispatchBoundsAcceptanceAndTerminalFactWrites(t *testing.T) {
	t.Parallel()
	test := newSessionDispatchTest(t, &scriptedSessionProviderStream{events: []ProviderEvent{completedSessionProviderEvent()}}, nil, true)
	observed := &deadlineObservingLedger{Ledger: test.ledger}
	starter, err := NewReferenceSessionDispatchStarter(test.gateway, observed, test.dispatch.ProviderRouteDigest)
	if err != nil {
		t.Fatalf("NewReferenceSessionDispatchStarter() error = %v", err)
	}
	test.starter = starter
	digest, err := starter.Prepare(context.Background(), test.dispatch, test.transition)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	consumer, _ := test.consumer(t, digest)
	if _, err := consumer.StartExactAttempt(context.Background(), test.startRequest(digest)); err != nil {
		t.Fatalf("StartExactAttempt() error = %v", err)
	}
	if !observed.acceptedDeadline.Load() || !observed.terminalDeadline.Load() {
		t.Fatalf("bounded fact deadlines accepted=%t terminal=%t", observed.acceptedDeadline.Load(), observed.terminalDeadline.Load())
	}
}

func TestReferenceSessionDispatchRejectsIdentityGenerationRouteAndCommandMismatches(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*broker.DispatchPermit, *Transition)
	}{
		{name: "tenant", mutate: func(dispatch *broker.DispatchPermit, _ *Transition) {
			dispatch.TenantID = mustID(t, identity.Tenant, 'q')
		}},
		{name: "user", mutate: func(dispatch *broker.DispatchPermit, _ *Transition) {
			dispatch.UserID = mustID(t, identity.Subject, 'q')
		}},
		{name: "session", mutate: func(dispatch *broker.DispatchPermit, _ *Transition) {
			dispatch.SessionID = mustID(t, identity.Session, 'q')
		}},
		{name: "turn", mutate: func(dispatch *broker.DispatchPermit, _ *Transition) { dispatch.TurnID = mustID(t, identity.Turn, 'q') }},
		{name: "effect", mutate: func(dispatch *broker.DispatchPermit, _ *Transition) {
			dispatch.EffectID = mustID(t, identity.Effect, 'q')
		}},
		{name: "invocation", mutate: func(dispatch *broker.DispatchPermit, _ *Transition) {
			dispatch.InvocationID = mustID(t, identity.Invocation, 'q')
		}},
		{name: "request digest", mutate: func(dispatch *broker.DispatchPermit, _ *Transition) { dispatch.RequestDigest = sessionBrokerDigest(91) }},
		{name: "turn generation", mutate: func(dispatch *broker.DispatchPermit, _ *Transition) { dispatch.Generations.TurnLease++ }},
		{name: "placement generation", mutate: func(dispatch *broker.DispatchPermit, _ *Transition) { dispatch.Generations.Placement++ }},
		{name: "authorization generation", mutate: func(dispatch *broker.DispatchPermit, _ *Transition) { dispatch.Generations.Authorization++ }},
		{name: "attempt", mutate: func(dispatch *broker.DispatchPermit, _ *Transition) { dispatch.DispatchAttempt++ }},
		{name: "route", mutate: func(dispatch *broker.DispatchPermit, _ *Transition) {
			dispatch.ProviderRouteDigest = sessionBrokerDigest(92)
		}},
		{name: "service", mutate: func(dispatch *broker.DispatchPermit, _ *Transition) { dispatch.Service = broker.ServiceMCP }},
		{name: "operation", mutate: func(dispatch *broker.DispatchPermit, _ *Transition) { dispatch.Operation = "model.other" }},
		{name: "typed command", mutate: func(_ *broker.DispatchPermit, transition *Transition) {
			transition.Dispatch.Request.Reasoning.Effort = ReasoningEffortHigh
		}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			test := newSessionDispatchTest(t, &scriptedSessionProviderStream{events: []ProviderEvent{completedSessionProviderEvent()}}, nil, true)
			testCase.mutate(&test.dispatch, &test.transition)
			if _, err := test.starter.Prepare(context.Background(), test.dispatch, test.transition); err == nil {
				t.Fatal("Prepare(mismatched binding) succeeded")
			}
			if _, calls := test.provider.snapshot(); calls != 0 {
				t.Fatalf("mismatched binding reached provider %d times", calls)
			}
		})
	}
}

func TestReferenceSessionDispatchRejectsEveryForeignClaimGenerationBeforeProviderIO(t *testing.T) {
	t.Parallel()
	mutations := []struct {
		name   string
		mutate func(*broker.Generations)
	}{
		{name: "turn lease", mutate: func(generations *broker.Generations) { generations.TurnLease++ }},
		{name: "placement", mutate: func(generations *broker.Generations) { generations.Placement++ }},
		{name: "sandbox", mutate: func(generations *broker.Generations) { generations.Sandbox++ }},
		{name: "authorization", mutate: func(generations *broker.Generations) { generations.Authorization++ }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			test := newSessionDispatchTest(t, &scriptedSessionProviderStream{events: []ProviderEvent{completedSessionProviderEvent()}}, nil, true)
			digest, err := test.starter.Prepare(context.Background(), test.dispatch, test.transition)
			if err != nil {
				t.Fatalf("Prepare() error = %v", err)
			}
			mutation.mutate(&test.dispatch.Generations)
			consumer, _ := test.consumer(t, digest)
			if _, err := consumer.StartExactAttempt(context.Background(), test.startRequest(digest)); !errors.Is(err, broker.ErrDispatchStartUnknown) {
				t.Fatalf("StartExactAttempt(foreign generation) error = %v", err)
			}
			if _, calls := test.provider.snapshot(); calls != 0 {
				t.Fatalf("foreign generation reached provider %d times", calls)
			}
		})
	}
}

func TestReferenceSessionDispatchRecordsAcceptedThenUnknownWithoutRetry(t *testing.T) {
	t.Parallel()
	test := newSessionDispatchTest(t, &scriptedSessionProviderStream{
		events:  []ProviderEvent{{Kind: ProviderEventDelta, Delta: "partial"}},
		nextErr: errors.New("stream reset"),
	}, nil, true)
	digest, err := test.starter.Prepare(context.Background(), test.dispatch, test.transition)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	consumer, _ := test.consumer(t, digest)
	if execution, err := consumer.StartExactAttempt(context.Background(), test.startRequest(digest)); err != nil || execution.Outcome != broker.DispatchStartOutcomeStarted {
		t.Fatalf("StartExactAttempt(accepted unknown) = %#v, %v", execution, err)
	}
	facts, err := test.ledger.Inspect(context.Background(), sessionLookup(test.dispatch))
	if err != nil || facts.ExternalProviderRequestID != "provider-request-1" || facts.Terminal.Status != effectledger.TerminalUnknown {
		t.Fatalf("unknown facts = %#v, %v", facts, err)
	}
	if _, calls := test.provider.snapshot(); calls != 1 {
		t.Fatalf("provider calls = %d, want one without internal retry", calls)
	}
}

func TestReferenceSessionDispatchRecordsPreAcceptanceFailureAndUnknown(t *testing.T) {
	t.Parallel()
	typedFailure, err := NewProviderDispatchError(DispatchFailureDefinitelyNotSent, "socket unopened", nil)
	if err != nil {
		t.Fatalf("NewProviderDispatchError() error = %v", err)
	}
	tests := []struct {
		name        string
		dispatchErr error
		want        effectledger.TerminalStatus
	}{
		{name: "definitely not sent", dispatchErr: typedFailure, want: effectledger.TerminalFailed},
		{name: "unknown send", dispatchErr: errors.New("write acknowledgement missing"), want: effectledger.TerminalUnknown},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			test := newSessionDispatchTest(t, nil, testCase.dispatchErr, false)
			digest, prepareErr := test.starter.Prepare(context.Background(), test.dispatch, test.transition)
			if prepareErr != nil {
				t.Fatalf("Prepare() error = %v", prepareErr)
			}
			consumer, _ := test.consumer(t, digest)
			if _, startErr := consumer.StartExactAttempt(context.Background(), test.startRequest(digest)); !errors.Is(startErr, broker.ErrDispatchStartUnknown) {
				t.Fatalf("StartExactAttempt() error = %v, want ErrDispatchStartUnknown", startErr)
			}
			facts, inspectErr := test.ledger.Inspect(context.Background(), sessionLookup(test.dispatch))
			if inspectErr != nil || facts.ExternalProviderRequestID != "" || facts.Terminal.Status != testCase.want {
				t.Fatalf("terminal facts = %#v, %v", facts, inspectErr)
			}
			if _, calls := test.provider.snapshot(); calls != 1 {
				t.Fatalf("provider calls = %d, want one without internal retry", calls)
			}
		})
	}
}

func TestReferenceSessionDispatchRejectsAnUnmintedClaimBeforeProviderIO(t *testing.T) {
	t.Parallel()
	test := newSessionDispatchTest(t, &scriptedSessionProviderStream{events: []ProviderEvent{completedSessionProviderEvent()}}, nil, true)
	if err := test.starter.Start(context.Background(), broker.ClaimedDispatchStart{}); err == nil {
		t.Fatal("Start(zero claim) succeeded")
	}
	if _, calls := test.provider.snapshot(); calls != 0 {
		t.Fatalf("zero claim reached provider %d times", calls)
	}
}

func TestConcurrentReferenceSessionDispatchCallsProviderExactlyOnce(t *testing.T) {
	t.Parallel()
	test := newSessionDispatchTest(t, &scriptedSessionProviderStream{events: []ProviderEvent{completedSessionProviderEvent()}}, nil, true)
	digest, err := test.starter.Prepare(context.Background(), test.dispatch, test.transition)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	consumer, _ := test.consumer(t, digest)
	request := test.startRequest(digest)

	const workers = 64
	errorsSeen := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, startErr := consumer.StartExactAttempt(context.Background(), request)
			errorsSeen <- startErr
		}()
	}
	wait.Wait()
	close(errorsSeen)

	started, rejected := 0, 0
	for startErr := range errorsSeen {
		switch {
		case startErr == nil:
			started++
		case errors.Is(startErr, broker.ErrDispatchAlreadyStarted):
			rejected++
		default:
			t.Fatalf("StartExactAttempt() error = %v", startErr)
		}
	}
	if _, calls := test.provider.snapshot(); started != 1 || rejected != workers-1 || calls != 1 || test.model.dispatches.claims != 0 {
		t.Fatalf("started=%d rejected=%d provider=%d model-claims=%d", started, rejected, calls, test.model.dispatches.claims)
	}
}

type sessionDispatchTest struct {
	model      *fixture
	gateway    *Gateway
	provider   *sessionTestProvider
	ledger     *effectledger.ReferenceLedger
	starter    *SessionDispatchStarter
	dispatch   broker.DispatchPermit
	transition Transition
	now        time.Time
}

func newSessionDispatchTest(t *testing.T, stream ProviderStream, dispatchErr error, accepted bool) *sessionDispatchTest {
	t.Helper()
	model := newFixture(t)
	provider := &sessionTestProvider{
		availability: ProviderAvailability{Available: true},
		result:       ProviderDispatchResult{Stream: stream},
		dispatchErr:  dispatchErr,
	}
	if accepted {
		provider.result.ProviderRequestID = "provider-request-1"
	}
	dependencies := model.dependencies()
	dependencies.Providers = map[string]Provider{"provider-a": provider}
	gateway, err := NewGateway(model.configuration(), dependencies)
	if err != nil {
		t.Fatalf("NewGateway() error = %v", err)
	}
	effect := model.admit(t, gateway)
	transition := apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch})
	route := sessionBrokerDigest(71)
	now := time.Unix(1_800_000_000, 0).UTC()
	dispatch := broker.DispatchPermit{
		EffectKey: broker.EffectKey{
			SessionID: transition.Effect.Scope.SessionID, TurnID: transition.Effect.Scope.TurnID,
			EffectID: transition.Effect.Scope.EffectID, InvocationID: transition.Effect.Scope.InvocationID,
			RequestDigest: broker.Digest(transition.Effect.RequestDigest),
		},
		Opaque: broker.OpaquePermit("session-dispatch-secret"), TenantID: transition.Effect.Scope.TenantID,
		WorkspaceID: mustID(t, identity.Workspace, 'w'), UserID: transition.Effect.Scope.UserID,
		Service: broker.ServiceModel, Operation: "model.generate", Ordinal: 1, ReplayPolicy: broker.ReplayNever,
		Generations: broker.Generations{
			TurnLease: transition.Effect.Scope.Generations.TurnLease, Placement: transition.Effect.Scope.Generations.Placement,
			Sandbox: 4, Authorization: transition.Effect.Scope.Generations.Policy,
		},
		DispatchAttempt: uint64(transition.Effect.Attempt), ProviderRequestID: mustID(t, identity.Request, 'r'),
		ProviderRouteDigest: route, Deadline: now.Add(time.Minute), EventSequence: 7, Durable: true,
	}
	store := effectledger.NewReferenceStore()
	ledger, err := effectledger.NewReferenceLedger(store, broker.ServiceModel, route, effectledger.ReferenceLimits{
		MaximumPayloadBytes: 1 << 20,
		MaximumResultBytes:  1 << 20,
	})
	if err != nil {
		t.Fatalf("NewReferenceLedger() error = %v", err)
	}
	starter, err := NewReferenceSessionDispatchStarter(gateway, ledger, route)
	if err != nil {
		t.Fatalf("NewReferenceSessionDispatchStarter() error = %v", err)
	}
	return &sessionDispatchTest{
		model: model, gateway: gateway, provider: provider, ledger: ledger, starter: starter,
		dispatch: dispatch, transition: transition, now: now,
	}
}

func (test *sessionDispatchTest) startRequest(digest broker.Digest) broker.DispatchStartRequest {
	return broker.DispatchStartRequest{
		Authority: broker.ValidatedTurnFence{
			TenantID: test.dispatch.TenantID, WorkspaceID: test.dispatch.WorkspaceID,
			SessionID: test.dispatch.SessionID, TurnID: test.dispatch.TurnID,
			Generations: test.dispatch.Generations, ExpiresAt: test.now.Add(time.Minute),
		},
		Now: test.now, Dispatch: test.dispatch, CommandDigest: digest,
	}
}

func (test *sessionDispatchTest) consumer(t *testing.T, digest broker.Digest) (*broker.DispatchConsumer, *sessionTestClaimer) {
	t.Helper()
	groups := []dependency.AtomicGroup{dependency.AtomicCommandReceipt, dependency.AtomicEffectLifecycle}
	proofs := dependencycontract.NewProductionProofs(t, groups)
	claimer := &sessionTestClaimer{
		ProductionProofs: proofs,
		request:          test.startRequest(digest),
		permit: broker.DispatchStartPermit{
			Dispatch: test.dispatch, Opaque: broker.OpaquePermit("session-start-secret"),
			CommandDigest: digest, EventSequence: test.dispatch.EventSequence + 1, Durable: true,
		},
	}
	verified := dependencycontract.Verify(t, proofs, broker.DispatchStartClaimer(claimer), groups)
	consumer, err := broker.NewDispatchConsumer(verified, map[broker.EffectService]broker.DispatchStarter{
		broker.ServiceModel: test.starter,
	}, time.Second)
	if err != nil {
		t.Fatalf("NewDispatchConsumer() error = %v", err)
	}
	return consumer, claimer
}

type sessionTestClaimer struct {
	*dependencycontract.ProductionProofs
	mu      sync.Mutex
	request broker.DispatchStartRequest
	permit  broker.DispatchStartPermit
	claimed bool
}

func (claimer *sessionTestClaimer) ClaimDispatchStart(_ context.Context, request broker.DispatchStartRequest) (broker.DispatchStartClaim, error) {
	claimer.mu.Lock()
	defer claimer.mu.Unlock()
	if request != claimer.request {
		return broker.DispatchStartClaim{}, broker.ErrFenceMismatch
	}
	fresh := !claimer.claimed
	claimer.claimed = true
	return broker.DispatchStartClaim{Permit: claimer.permit, Fresh: fresh}, nil
}

type sessionTestProvider struct {
	mu           sync.Mutex
	availability ProviderAvailability
	result       ProviderDispatchResult
	dispatchErr  error
	dispatches   int
	last         DispatchCommand
}

type deadlineObservingLedger struct {
	effectledger.Ledger
	acceptedDeadline atomic.Bool
	terminalDeadline atomic.Bool
}

func (ledger *deadlineObservingLedger) RecordAccepted(ctx context.Context, observation effectledger.Observation, providerRequestID string) error {
	_, bounded := ctx.Deadline()
	ledger.acceptedDeadline.Store(bounded)
	return ledger.Ledger.RecordAccepted(ctx, observation, providerRequestID)
}

func (ledger *deadlineObservingLedger) RecordTerminal(ctx context.Context, observation effectledger.Observation, terminal effectledger.Terminal) (effectledger.Terminal, error) {
	_, bounded := ctx.Deadline()
	ledger.terminalDeadline.Store(bounded)
	return ledger.Ledger.RecordTerminal(ctx, observation, terminal)
}

func (provider *sessionTestProvider) Availability(context.Context) (ProviderAvailability, error) {
	return provider.availability, nil
}

func (provider *sessionTestProvider) Dispatch(_ context.Context, command DispatchCommand) (ProviderDispatchResult, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	provider.dispatches++
	command.Request = cloneModelRequest(command.Request)
	provider.last = command
	return provider.result, provider.dispatchErr
}

func (*sessionTestProvider) Cancel(context.Context, CancelCommand) (ProviderCancellation, error) {
	return ProviderCancellation{}, nil
}

func (provider *sessionTestProvider) snapshot() (DispatchCommand, int) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	command := provider.last
	command.Request = cloneModelRequest(command.Request)
	return command, provider.dispatches
}

type scriptedSessionProviderStream struct {
	events  []ProviderEvent
	nextErr error
	next    int
	closed  bool
}

func (stream *scriptedSessionProviderStream) Next(context.Context) (ProviderEvent, error) {
	if stream.next < len(stream.events) {
		event := stream.events[stream.next]
		stream.next++
		return event, nil
	}
	if stream.nextErr != nil {
		err := stream.nextErr
		stream.nextErr = nil
		return ProviderEvent{}, err
	}
	return ProviderEvent{}, io.EOF
}

func (stream *scriptedSessionProviderStream) Close() error {
	stream.closed = true
	return nil
}

func completedSessionProviderEvent() ProviderEvent {
	return ProviderEvent{
		Kind: ProviderEventResponseCompleted,
		Response: &ProviderResponse{
			Text: "done", FinishReason: string(FinishReasonStop),
			Usage: Usage{InputTokens: 11, OutputTokens: 3},
		},
	}
}

func sessionLookup(dispatch broker.DispatchPermit) broker.LedgerLookup {
	return broker.LedgerLookup{
		EffectKey: dispatch.EffectKey, TenantID: dispatch.TenantID, WorkspaceID: dispatch.WorkspaceID,
		Service: dispatch.Service, Operation: dispatch.Operation, DispatchAttempt: dispatch.DispatchAttempt,
		ProviderRequestID: dispatch.ProviderRequestID, ProviderRouteDigest: dispatch.ProviderRouteDigest,
	}
}

func sessionBrokerDigest(fill byte) broker.Digest {
	var digest broker.Digest
	copy(digest[:], bytes.Repeat([]byte{fill}, len(digest)))
	return digest
}
