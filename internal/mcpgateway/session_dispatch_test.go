package mcpgateway

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/dependency"
	dependencycontract "github.com/hancomac/circulusd/internal/dependency/contracttest"
	"github.com/hancomac/circulusd/internal/effectledger"
	"github.com/hancomac/circulusd/internal/identity"
)

func TestSessionDispatchPrepareIsPureAndConcurrentStartCallsProviderOnce(t *testing.T) {
	const callers = 64
	fixture := newGatewayFixture(t, ReplayIdempotencyKey)
	repository := &countingSessionRepository{EffectRepository: fixture.repository}
	gateway := *fixture.gateway
	gateway.repository = repository
	route := broker.Digest(digestWithByte(81))
	store := effectledger.NewReferenceStore()
	ledger := newSessionLedger(t, store, route)
	observedLedger := &deadlineObservingMCPLedger{Ledger: ledger}
	starter := mustSessionStarter(t, &gateway, observedLedger, route)
	call := sessionCall(fixture)
	dispatch := sessionDispatch(t, fixture, call, route)

	commandDigest, err := starter.Prepare(context.Background(), dispatch, fixture.scope.RuntimeRevision, call)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if len(fixture.authorizer.calls) != 0 || fixture.credentials.request != (CredentialRequest{}) ||
		fixture.provider.negotiationCount() != 0 || fixture.provider.startCount() != 0 ||
		repository.totalCalls() != 0 {
		t.Fatal("Prepare reached a policy, credential, provider, or gateway repository dependency")
	}
	call.Input.(canonical.Map)["repository"] = "attacker/changed-after-prepare"

	fixture.provider.start = func(_ context.Context, command ProviderCommand) (ProviderStartResult, error) {
		if !command.Session.Durable || command.Session.CommandDigest != Digest(commandDigest) ||
			command.Session.RouteDigest != Digest(route) || command.Dispatch == (DispatchPermit{}) ||
			command.Start == (ProviderStartPermit{}) {
			t.Errorf("provider command lacks exact Session-derived authority: %#v", command)
			return ProviderStartResult{}, errors.New("invalid Session-derived authority")
		}
		opened, ok := command.Session.Open()
		expectedDispatch := dispatch
		expectedDispatch.Opaque = ""
		if !ok || opened.Opaque != "" || opened.Dispatch != expectedDispatch || command.Scope.SessionID != dispatch.SessionID ||
			command.Scope.Generations.Sandbox != dispatch.Generations.Sandbox {
			t.Errorf("provider Session authority did not reopen exactly: %#v, %t", opened, ok)
			return ProviderStartResult{}, errors.New("invalid Session provider binding")
		}
		forged := command.Session
		forged.DispatchAttempt++
		if _, opened := (SessionProviderPermit{}).Open(); opened {
			t.Error("zero Session provider permit opened")
			return ProviderStartResult{}, errors.New("zero Session provider permit opened")
		}
		if _, opened := forged.Open(); opened {
			t.Error("mutated Session provider permit opened")
			return ProviderStartResult{}, errors.New("mutated Session provider permit opened")
		}
		if digest, digestErr := digestCanonicalCall(command.Server.ServerID, command.ToolName, command.InputCanonical); digestErr != nil || broker.Digest(digest) != dispatch.RequestDigest {
			t.Errorf("prepared command payload was not copied exactly: %x, %v", digest, digestErr)
			return ProviderStartResult{}, errors.New("prepared command payload changed")
		}
		var next atomic.Int64
		call := &functionCall{next: func(context.Context) (ProviderEvent, error) {
			switch next.Add(1) {
			case 1:
				return ProviderEvent{Kind: ProviderOutputChunk, Chunk: []byte("progress")}, nil
			case 2:
				return ProviderEvent{Kind: ProviderCompleted, Output: []byte(`{"ok":true}`), ExternalCommitID: "commit-session"}, nil
			default:
				return ProviderEvent{}, io.EOF
			}
		}}
		return ProviderStartResult{ProviderRequestID: "mcp-session-request", Call: call}, nil
	}
	claimer := newSessionClaimer(t, dispatch, commandDigest)
	consumer := mustSessionConsumer(t, claimer, starter)
	errorsSeen := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, startErr := consumer.StartExactAttempt(context.Background(), broker.DispatchStartRequest{
				Dispatch: dispatch, CommandDigest: commandDigest,
			})
			errorsSeen <- startErr
		}()
	}
	wait.Wait()
	close(errorsSeen)

	successes := 0
	unknowns := 0
	for startErr := range errorsSeen {
		switch {
		case startErr == nil:
			successes++
		case errors.Is(startErr, broker.ErrDispatchStartUnknown):
			unknowns++
		default:
			t.Fatalf("StartExactAttempt() error = %v", startErr)
		}
	}
	if successes != 1 || unknowns != callers-1 || fixture.provider.startCount() != 1 ||
		fixture.provider.negotiationCount() != 1 {
		t.Fatalf("success/unknown/negotiate/start = %d/%d/%d/%d", successes, unknowns,
			fixture.provider.negotiationCount(), fixture.provider.startCount())
	}
	if repository.totalCalls() != 0 {
		t.Fatalf("Session path repository claim/commit calls = %d, want zero", repository.totalCalls())
	}
	if len(fixture.authorizer.calls) != 1 || fixture.credentials.request.ServerID != fixture.server.ServerID {
		t.Fatalf("post-claim authorization calls = %d, credential = %#v", len(fixture.authorizer.calls), fixture.credentials.request)
	}
	if !observedLedger.acceptedDeadline.Load() || !observedLedger.terminalDeadline.Load() {
		t.Fatalf("bounded fact deadlines accepted=%t terminal=%t",
			observedLedger.acceptedDeadline.Load(), observedLedger.terminalDeadline.Load())
	}

	reconstructed := newSessionLedger(t, store, route)
	facts, err := reconstructed.Inspect(context.Background(), sessionLookup(dispatch))
	if err != nil || facts.State != effectledger.StateTerminal ||
		facts.ExternalProviderRequestID != "mcp-session-request" ||
		facts.Command.Dispatch.Opaque != "" ||
		facts.Terminal.Status != effectledger.TerminalCommitted {
		t.Fatalf("reconstructed facts = %#v, %v", facts, err)
	}
	terminal, err := DecodeSessionDispatchResult(facts.Terminal.Result, testBounds())
	if err != nil || string(terminal.Output) != `{"ok":true}` || terminal.ExternalCommitID != "commit-session" {
		t.Fatalf("DecodeSessionDispatchResult() = %#v, %v", terminal, err)
	}
}

func TestReferenceSessionDispatchStarterEnforcesLedgerEnvelopeCapacity(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	route := broker.Digest(digestWithByte(80))
	minimumPayloadBytes := int(fixture.gateway.bounds.MaxInputBytes) + sessionDispatchEnvelopeBytes
	minimumResultBytes := int(fixture.gateway.bounds.MaxOutputBytes+fixture.gateway.bounds.MaxExternalCommitIDBytes) + sessionDispatchEnvelopeBytes
	tests := []struct {
		name      string
		limits    effectledger.ReferenceLimits
		wantError bool
	}{
		{
			name: "payload one byte short",
			limits: effectledger.ReferenceLimits{
				MaximumPayloadBytes: minimumPayloadBytes - 1, MaximumResultBytes: minimumResultBytes,
			},
			wantError: true,
		},
		{
			name: "result one byte short",
			limits: effectledger.ReferenceLimits{
				MaximumPayloadBytes: minimumPayloadBytes, MaximumResultBytes: minimumResultBytes - 1,
			},
			wantError: true,
		},
		{
			name: "exact minimum",
			limits: effectledger.ReferenceLimits{
				MaximumPayloadBytes: minimumPayloadBytes, MaximumResultBytes: minimumResultBytes,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ledger, err := effectledger.NewReferenceLedger(
				effectledger.NewReferenceStore(), broker.ServiceMCP, route, test.limits,
			)
			if err != nil {
				t.Fatalf("NewReferenceLedger() error = %v", err)
			}
			starter, err := NewReferenceSessionDispatchStarter(fixture.gateway, ledger, route)
			if test.wantError {
				if starter != nil || !errors.Is(err, ErrInvalidConfiguration) {
					t.Fatalf("NewReferenceSessionDispatchStarter(incompatible limits) = %#v, %v", starter, err)
				}
				return
			}
			if starter == nil || err != nil {
				t.Fatalf("NewReferenceSessionDispatchStarter(exact limits) = %#v, %v", starter, err)
			}
		})
	}
}

func TestSessionDispatchRejectsZeroAndForeignClaimsBeforeProviderIO(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	route := broker.Digest(digestWithByte(82))
	store := effectledger.NewReferenceStore()
	ledger := newSessionLedger(t, store, route)
	starter := mustSessionStarter(t, fixture.gateway, ledger, route)
	call := sessionCall(fixture)
	dispatch := sessionDispatch(t, fixture, call, route)
	commandDigest, err := starter.Prepare(context.Background(), dispatch, fixture.scope.RuntimeRevision, call)
	if err != nil {
		t.Fatal(err)
	}
	if err := starter.Start(context.Background(), broker.ClaimedDispatchStart{}); err == nil {
		t.Fatal("Start(zero claim) succeeded")
	}

	generationMutations := []struct {
		name   string
		mutate func(*broker.Generations)
	}{
		{name: "turn lease", mutate: func(generations *broker.Generations) { generations.TurnLease++ }},
		{name: "placement", mutate: func(generations *broker.Generations) { generations.Placement++ }},
		{name: "sandbox", mutate: func(generations *broker.Generations) { generations.Sandbox++ }},
		{name: "authorization", mutate: func(generations *broker.Generations) { generations.Authorization++ }},
	}
	for _, mutation := range generationMutations {
		t.Run(mutation.name, func(t *testing.T) {
			foreign := dispatch
			mutation.mutate(&foreign.Generations)
			foreignClaimer := newSessionClaimer(t, foreign, commandDigest)
			consumer := mustSessionConsumer(t, foreignClaimer, starter)
			_, err = consumer.StartExactAttempt(context.Background(), broker.DispatchStartRequest{
				Dispatch: foreign, CommandDigest: commandDigest,
			})
			if !errors.Is(err, broker.ErrDispatchStartUnknown) {
				t.Fatalf("foreign StartExactAttempt() error = %v, want unknown", err)
			}
		})
	}
	if fixture.provider.negotiationCount() != 0 || fixture.provider.startCount() != 0 || len(fixture.authorizer.calls) != 0 {
		t.Fatal("zero or foreign claim reached authorization/provider I/O")
	}
}

func TestSessionProviderProofBindsEveryNonSecretDispatchField(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	route := broker.Digest(digestWithByte(83))
	dispatch := sessionDispatch(t, fixture, sessionCall(fixture), route)
	dispatch.Opaque = ""
	start := broker.DispatchStartPermit{
		Dispatch: dispatch, CommandDigest: broker.Digest(digestWithByte(84)),
		EventSequence: dispatch.EventSequence + 1, Durable: true,
	}
	baseline, err := sessionProviderProof(start)
	if err != nil {
		t.Fatalf("sessionProviderProof() error = %v", err)
	}
	mutations := []struct {
		name   string
		mutate func(*broker.DispatchStartPermit)
	}{
		{name: "tenant", mutate: func(value *broker.DispatchStartPermit) { value.Dispatch.TenantID = mustID(t, identity.Tenant) }},
		{name: "workspace", mutate: func(value *broker.DispatchStartPermit) { value.Dispatch.WorkspaceID = mustID(t, identity.Workspace) }},
		{name: "user", mutate: func(value *broker.DispatchStartPermit) { value.Dispatch.UserID = mustID(t, identity.Subject) }},
		{name: "session", mutate: func(value *broker.DispatchStartPermit) { value.Dispatch.SessionID = mustID(t, identity.Session) }},
		{name: "turn", mutate: func(value *broker.DispatchStartPermit) { value.Dispatch.TurnID = mustID(t, identity.Turn) }},
		{name: "effect", mutate: func(value *broker.DispatchStartPermit) { value.Dispatch.EffectID = mustID(t, identity.Effect) }},
		{name: "invocation", mutate: func(value *broker.DispatchStartPermit) { value.Dispatch.InvocationID = mustID(t, identity.Invocation) }},
		{name: "request digest", mutate: func(value *broker.DispatchStartPermit) {
			value.Dispatch.RequestDigest = broker.Digest(digestWithByte(85))
		}},
		{name: "service", mutate: func(value *broker.DispatchStartPermit) { value.Dispatch.Service = broker.ServiceModel }},
		{name: "operation", mutate: func(value *broker.DispatchStartPermit) { value.Dispatch.Operation += ".other" }},
		{name: "parent operation", mutate: func(value *broker.DispatchStartPermit) {
			value.Dispatch.ParentOperationID = mustID(t, identity.Operation)
		}},
		{name: "ordinal", mutate: func(value *broker.DispatchStartPermit) { value.Dispatch.Ordinal++ }},
		{name: "replay policy", mutate: func(value *broker.DispatchStartPermit) { value.Dispatch.ReplayPolicy = broker.ReplaySafe }},
		{name: "turn lease generation", mutate: func(value *broker.DispatchStartPermit) { value.Dispatch.Generations.TurnLease++ }},
		{name: "placement generation", mutate: func(value *broker.DispatchStartPermit) { value.Dispatch.Generations.Placement++ }},
		{name: "sandbox generation", mutate: func(value *broker.DispatchStartPermit) { value.Dispatch.Generations.Sandbox++ }},
		{name: "authorization generation", mutate: func(value *broker.DispatchStartPermit) { value.Dispatch.Generations.Authorization++ }},
		{name: "dispatch attempt", mutate: func(value *broker.DispatchStartPermit) { value.Dispatch.DispatchAttempt++ }},
		{name: "platform request", mutate: func(value *broker.DispatchStartPermit) {
			value.Dispatch.ProviderRequestID = mustID(t, identity.Request)
		}},
		{name: "provider route", mutate: func(value *broker.DispatchStartPermit) {
			value.Dispatch.ProviderRouteDigest = broker.Digest(digestWithByte(86))
		}},
		{name: "deadline", mutate: func(value *broker.DispatchStartPermit) {
			value.Dispatch.Deadline = value.Dispatch.Deadline.Add(time.Second)
		}},
		{name: "dispatch event sequence", mutate: func(value *broker.DispatchStartPermit) { value.Dispatch.EventSequence++ }},
		{name: "dispatch durability", mutate: func(value *broker.DispatchStartPermit) { value.Dispatch.Durable = false }},
		{name: "command digest", mutate: func(value *broker.DispatchStartPermit) { value.CommandDigest = broker.Digest(digestWithByte(87)) }},
		{name: "start event sequence", mutate: func(value *broker.DispatchStartPermit) { value.EventSequence++ }},
		{name: "start durability", mutate: func(value *broker.DispatchStartPermit) { value.Durable = false }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			changed := start
			mutation.mutate(&changed)
			if proof, err := sessionProviderProof(changed); err != nil || proof == baseline {
				t.Fatal("Session provider proof ignored an exact dispatch field")
			}
		})
	}
	opaqueOnly := start
	opaqueOnly.Opaque = broker.OpaquePermit("start-secret")
	opaqueOnly.Dispatch.Opaque = broker.OpaquePermit("dispatch-secret")
	if proof, err := sessionProviderProof(opaqueOnly); err != nil || proof != baseline {
		t.Fatal("Session provider proof retained an opaque bearer")
	}
}

func TestSessionDispatchCanonicalEnvelopesAllowConfiguredPayloadPlusOverhead(t *testing.T) {
	bounds := testBounds()
	bounds.MaxInputBytes = hardMaxInputBytes
	maximumInput := bytes.Repeat([]byte{'i'}, int(bounds.MaxInputBytes))
	if _, _, err := encodeSessionDispatchPayload(
		mustID(t, identity.RuntimeRevision), "server", "tool", maximumInput, bounds,
	); err != nil {
		t.Fatalf("encodeSessionDispatchPayload(maximum input) error = %v", err)
	}

	bounds.MaxOutputBytes = hardMaxOutputBytes
	largeOutput := bytes.Repeat([]byte{'o'}, 16<<20)
	encoded, err := encodeSessionDispatchResult(SessionDispatchResult{
		Output: largeOutput, ExternalCommitID: "external-commit",
	}, bounds)
	if err != nil {
		t.Fatalf("encodeSessionDispatchResult(large output) error = %v", err)
	}
	decoded, err := DecodeSessionDispatchResult(encoded, bounds)
	if err != nil || !bytes.Equal(decoded.Output, largeOutput) || decoded.ExternalCommitID != "external-commit" {
		t.Fatalf("DecodeSessionDispatchResult(large output) = %#v, %v", decoded, err)
	}
}

func TestSessionDispatchRecordsFailedAndUnknownWithoutRetry(t *testing.T) {
	tests := []struct {
		name                  string
		start                 func(context.Context, ProviderCommand) (ProviderStartResult, error)
		wantStatus            effectledger.TerminalStatus
		wantProviderRequestID string
		wantStartUnknown      bool
	}{
		{
			name: "definitely not sent", wantStatus: effectledger.TerminalFailed,
			start: func(context.Context, ProviderCommand) (ProviderStartResult, error) {
				failure, _ := NewProviderDispatchError(DispatchDefinitelyNotSent, "rejected", errors.New("provider rejected"))
				return ProviderStartResult{}, failure
			},
		},
		{
			name: "unknown", wantStatus: effectledger.TerminalUnknown, wantStartUnknown: true,
			start: func(context.Context, ProviderCommand) (ProviderStartResult, error) {
				return ProviderStartResult{}, errors.New("connection lost")
			},
		},
		{
			name: "accepted then unknown", wantStatus: effectledger.TerminalUnknown,
			wantProviderRequestID: "accepted-before-loss",
			start: func(context.Context, ProviderCommand) (ProviderStartResult, error) {
				return ProviderStartResult{ProviderRequestID: "accepted-before-loss"}, errors.New("response stream lost")
			},
		},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newGatewayFixture(t, ReplayNever)
			route := broker.Digest(digestWithByte(byte(90 + index)))
			store := effectledger.NewReferenceStore()
			ledger := newSessionLedger(t, store, route)
			starter := mustSessionStarter(t, fixture.gateway, ledger, route)
			call := sessionCall(fixture)
			dispatch := sessionDispatch(t, fixture, call, route)
			digest, err := starter.Prepare(context.Background(), dispatch, fixture.scope.RuntimeRevision, call)
			if err != nil {
				t.Fatal(err)
			}
			fixture.provider.start = test.start
			consumer := mustSessionConsumer(t, newSessionClaimer(t, dispatch, digest), starter)
			execution, startErr := consumer.StartExactAttempt(context.Background(), broker.DispatchStartRequest{
				Dispatch: dispatch, CommandDigest: digest,
			})
			if test.wantStartUnknown {
				if !errors.Is(startErr, broker.ErrDispatchStartUnknown) || execution.Outcome != broker.DispatchStartOutcomeUnknown {
					t.Fatalf("StartExactAttempt() = %#v, %v, want unknown", execution, startErr)
				}
			} else if startErr != nil || execution.Outcome != broker.DispatchStartOutcomeStarted {
				t.Fatalf("StartExactAttempt() = %#v, %v, want started", execution, startErr)
			}
			if fixture.provider.startCount() != 1 {
				t.Fatalf("provider starts = %d, want one", fixture.provider.startCount())
			}
			facts, inspectErr := ledger.Inspect(context.Background(), sessionLookup(dispatch))
			if inspectErr != nil || facts.Terminal.Status != test.wantStatus ||
				facts.ExternalProviderRequestID != test.wantProviderRequestID {
				t.Fatalf("terminal facts = %#v, %v", facts, inspectErr)
			}
		})
	}
}

func TestSessionDispatchBoundsProviderCallCloseAfterAcceptedUnknown(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	route := broker.Digest(digestWithByte(97))
	store := effectledger.NewReferenceStore()
	ledger := newSessionLedger(t, store, route)
	starter := mustSessionStarter(t, fixture.gateway, ledger, route)
	callRequest := sessionCall(fixture)
	dispatch := sessionDispatch(t, fixture, callRequest, route)
	digest, err := starter.Prepare(context.Background(), dispatch, fixture.scope.RuntimeRevision, callRequest)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	providerCall := &deadlineSessionProviderCall{}
	fixture.provider.start = func(context.Context, ProviderCommand) (ProviderStartResult, error) {
		return ProviderStartResult{ProviderRequestID: "accepted-before-stream-loss", Call: providerCall}, nil
	}
	consumer := mustSessionConsumer(t, newSessionClaimer(t, dispatch, digest), starter)
	execution, err := consumer.StartExactAttempt(context.Background(), broker.DispatchStartRequest{
		Dispatch: dispatch, CommandDigest: digest,
	})
	if err != nil || execution.Outcome != broker.DispatchStartOutcomeStarted {
		t.Fatalf("StartExactAttempt() = %#v, %v", execution, err)
	}
	if !providerCall.closeDeadline.Load() {
		t.Fatal("ProviderCall.Close did not receive a bounded cleanup context")
	}
	facts, err := ledger.Inspect(context.Background(), sessionLookup(dispatch))
	if err != nil || facts.ExternalProviderRequestID != "accepted-before-stream-loss" ||
		facts.Terminal.Status != effectledger.TerminalUnknown {
		t.Fatalf("Inspect() = %#v, %v", facts, err)
	}
}

type countingSessionRepository struct {
	EffectRepository
	claims  atomic.Int64
	starts  atomic.Int64
	commits atomic.Int64
}

type deadlineObservingMCPLedger struct {
	effectledger.Ledger
	acceptedDeadline atomic.Bool
	terminalDeadline atomic.Bool
}

type deadlineSessionProviderCall struct {
	closeDeadline atomic.Bool
}

func (*deadlineSessionProviderCall) Next(context.Context) (ProviderEvent, error) {
	return ProviderEvent{}, errors.New("provider stream lost")
}

func (call *deadlineSessionProviderCall) Close(ctx context.Context) error {
	_, bounded := ctx.Deadline()
	call.closeDeadline.Store(bounded)
	return nil
}

func (ledger *deadlineObservingMCPLedger) RecordAccepted(ctx context.Context, observation effectledger.Observation, providerRequestID string) error {
	_, bounded := ctx.Deadline()
	ledger.acceptedDeadline.Store(bounded)
	return ledger.Ledger.RecordAccepted(ctx, observation, providerRequestID)
}

func (ledger *deadlineObservingMCPLedger) RecordTerminal(ctx context.Context, observation effectledger.Observation, terminal effectledger.Terminal) (effectledger.Terminal, error) {
	_, bounded := ctx.Deadline()
	ledger.terminalDeadline.Store(bounded)
	return ledger.Ledger.RecordTerminal(ctx, observation, terminal)
}

func (repository *countingSessionRepository) CommitAndClaimDispatch(ctx context.Context, request DispatchClaimRequest) (DispatchPermit, error) {
	repository.claims.Add(1)
	return repository.EffectRepository.CommitAndClaimDispatch(ctx, request)
}

func (repository *countingSessionRepository) ClaimProviderStart(ctx context.Context, request ProviderStartClaimRequest) (ProviderStartPermit, error) {
	repository.starts.Add(1)
	return repository.EffectRepository.ClaimProviderStart(ctx, request)
}

func (repository *countingSessionRepository) Commit(ctx context.Context, request TransitionCommitRequest) (StoredEffect, error) {
	repository.commits.Add(1)
	return repository.EffectRepository.Commit(ctx, request)
}

func (repository *countingSessionRepository) totalCalls() int64 {
	return repository.claims.Load() + repository.starts.Load() + repository.commits.Load()
}

type sessionDispatchClaimer struct {
	*dependencycontract.ProductionProofs
	dispatch      broker.DispatchPermit
	commandDigest broker.Digest
}

func newSessionClaimer(t *testing.T, dispatch broker.DispatchPermit, commandDigest broker.Digest) *sessionDispatchClaimer {
	t.Helper()
	return &sessionDispatchClaimer{
		ProductionProofs: dependencycontract.NewProductionProofs(t, []dependency.AtomicGroup{
			dependency.AtomicCommandReceipt, dependency.AtomicEffectLifecycle,
		}),
		dispatch: dispatch, commandDigest: commandDigest,
	}
}

func (claimer *sessionDispatchClaimer) ClaimDispatchStart(context.Context, broker.DispatchStartRequest) (broker.DispatchStartClaim, error) {
	return broker.DispatchStartClaim{Permit: broker.DispatchStartPermit{
		Dispatch: claimer.dispatch, Opaque: broker.OpaquePermit("session-start"),
		CommandDigest: claimer.commandDigest, EventSequence: 2, Durable: true,
	}, Fresh: true}, nil
}

func mustSessionConsumer(t *testing.T, claimer *sessionDispatchClaimer, starter *SessionDispatchStarter) *broker.DispatchConsumer {
	t.Helper()
	verified := dependencycontract.Verify(t, claimer.ProductionProofs, broker.DispatchStartClaimer(claimer),
		[]dependency.AtomicGroup{dependency.AtomicCommandReceipt, dependency.AtomicEffectLifecycle})
	consumer, err := broker.NewDispatchConsumer(verified, map[broker.EffectService]broker.DispatchStarter{
		broker.ServiceMCP: starter,
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return consumer
}

func mustSessionStarter(t *testing.T, gateway *Gateway, ledger effectledger.Ledger, route broker.Digest) *SessionDispatchStarter {
	t.Helper()
	starter, err := NewReferenceSessionDispatchStarter(gateway, ledger, route)
	if err != nil {
		t.Fatal(err)
	}
	return starter
}

func newSessionLedger(t *testing.T, store *effectledger.ReferenceStore, route broker.Digest) *effectledger.ReferenceLedger {
	t.Helper()
	ledger, err := effectledger.NewReferenceLedger(store, broker.ServiceMCP, route, effectledger.ReferenceLimits{
		MaximumPayloadBytes: 8192, MaximumResultBytes: 16 << 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	return ledger
}

func sessionCall(fixture gatewayFixture) CallRequest {
	return CallRequest{ServerID: fixture.server.ServerID, ToolName: fixture.tool.ToolName, Input: canonical.Map{
		"repository": "org/repo", "private": true,
	}}
}

func sessionDispatch(t *testing.T, fixture gatewayFixture, call CallRequest, route broker.Digest) broker.DispatchPermit {
	t.Helper()
	requestDigest, err := CallRequestDigest(call, testBounds())
	if err != nil {
		t.Fatal(err)
	}
	return broker.DispatchPermit{
		EffectKey: broker.EffectKey{
			SessionID: fixture.scope.SessionID, TurnID: fixture.scope.TurnID,
			EffectID: mustID(t, identity.Effect), InvocationID: mustID(t, identity.Invocation),
			RequestDigest: broker.Digest(requestDigest),
		},
		Opaque: broker.OpaquePermit("dispatch"), TenantID: fixture.scope.TenantID,
		WorkspaceID: mustID(t, identity.Workspace), UserID: fixture.scope.UserID,
		Service: broker.ServiceMCP, Operation: call.ToolName, Ordinal: 1,
		ReplayPolicy: broker.ReplayPolicy(fixture.tool.ReplayPolicy),
		Generations: broker.Generations{
			TurnLease: fixture.scope.Generations.TurnLease, Placement: fixture.scope.Generations.Placement,
			Sandbox: 11, Authorization: fixture.scope.Generations.Policy,
		},
		DispatchAttempt: 1, ProviderRequestID: mustID(t, identity.Request), ProviderRouteDigest: route,
		Deadline: time.Now().Add(time.Minute), EventSequence: 1, Durable: true,
	}
}

func sessionLookup(dispatch broker.DispatchPermit) broker.LedgerLookup {
	return broker.LedgerLookup{
		EffectKey: dispatch.EffectKey, TenantID: dispatch.TenantID, WorkspaceID: dispatch.WorkspaceID,
		Service: dispatch.Service, Operation: dispatch.Operation, DispatchAttempt: dispatch.DispatchAttempt,
		ProviderRequestID: dispatch.ProviderRequestID, ProviderRouteDigest: dispatch.ProviderRouteDigest,
	}
}
