package mcpgateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/identity"
)

type samplingStub struct {
	calls              int
	resumeCalls        int
	cancelCalls        int
	result             SamplingResult
	err                error
	resumeErr          error
	cancellationErr    error
	cancellationResult SamplingCancellationReceipt
}

func (stub *samplingStub) Cancel(_ context.Context, request SamplingCancellationRequest) (SamplingCancellationReceipt, error) {
	stub.cancelCalls++
	receipt := stub.cancellationResult
	if receipt.Proof == (OpaqueSamplingCancellationReceipt{}) {
		receipt.Proof = OpaqueSamplingCancellationReceipt(sha256.Sum256([]byte("sampling-cancel")))
	}
	if receipt.Scope == (ValidatedAuthority{}) {
		receipt.Scope = request.Scope
	}
	if receipt.ParentEffectID == (identity.ID{}) {
		receipt.ParentEffectID = request.ParentEffectID
	}
	if receipt.ParentInvocationID == (identity.ID{}) {
		receipt.ParentInvocationID = request.ParentInvocationID
	}
	if receipt.ChildEffectID == (identity.ID{}) {
		receipt.ChildEffectID = request.Claim.ChildEffectID
	}
	if receipt.ChildInvocationID == (identity.ID{}) {
		receipt.ChildInvocationID = request.Claim.ChildInvocationID
	}
	if receipt.RequestDigest == (Digest{}) {
		receipt.RequestDigest = request.RequestDigest
	}
	if receipt.ClaimProof == (OpaqueServerRequestPermit{}) {
		receipt.ClaimProof = request.Claim.Proof
	}
	if !receipt.Durable && stub.cancellationResult == (SamplingCancellationReceipt{}) {
		receipt.Durable = true
	}
	return receipt, stub.cancellationErr
}

func (stub *samplingStub) Sample(_ context.Context, request SamplingRequest) (SamplingResult, error) {
	stub.calls++
	return stub.resultForRequest(request, stub.err)
}

func (stub *samplingStub) Resume(_ context.Context, request SamplingRequest) (SamplingResult, error) {
	stub.resumeCalls++
	return stub.resultForRequest(request, stub.resumeErr)
}

func (stub *samplingStub) resultForRequest(request SamplingRequest, resultErr error) (SamplingResult, error) {
	if len(request.ParamsCanonical) == 0 {
		return SamplingResult{}, errors.New("sampling parameters were not canonicalized")
	}
	result := stub.result
	if result.Scope == (ValidatedAuthority{}) {
		result.Scope = request.Scope
	}
	if result.ParentEffectID == (identity.ID{}) {
		result.ParentEffectID = request.ParentEffectID
	}
	if result.ParentInvocationID == (identity.ID{}) {
		result.ParentInvocationID = request.ParentInvocationID
	}
	if result.RequestDigest == (Digest{}) {
		result.RequestDigest = request.RequestDigest
	}
	if result.EffectID == (identity.ID{}) {
		result.EffectID = request.ChildEffectID
	}
	if result.InvocationID == (identity.ID{}) {
		result.InvocationID = request.ChildInvocationID
	}
	if result.ParentLifecycle == (SamplingParentLifecycleReceipt{}) {
		result.ParentLifecycle = SamplingParentLifecycleReceipt{
			Proof:   OpaqueSamplingParentLifecycleReceipt(sha256.Sum256([]byte("sampling-parent-lifecycle"))),
			Durable: true, Scope: request.Scope, ParentEffectID: request.ParentEffectID,
			ParentInvocationID: request.ParentInvocationID, ChildEffectID: request.ChildEffectID,
			ChildInvocationID: request.ChildInvocationID, RequestDigest: request.RequestDigest,
			ClaimProof: request.Claim.Proof, Suspended: true, Resumed: true,
		}
	}
	return result, resultErr
}

type rootsStub struct{ roots []string }

func (stub rootsStub) Roots(context.Context, ValidatedAuthority) ([]string, error) {
	return append([]string(nil), stub.roots...), nil
}

type elicitationStub struct {
	mu          sync.Mutex
	started     chan struct{}
	release     chan struct{}
	cancelCalls int
	err         error
}

func (stub *elicitationStub) Elicit(context.Context, ElicitationRequest) (canonical.Value, error) {
	if stub.started != nil {
		close(stub.started)
	}
	if stub.release != nil {
		<-stub.release
	}
	return canonical.Map{"approved": true}, stub.err
}

func (stub *elicitationStub) Cancel(_ context.Context, request ElicitationCancellationRequest) (ElicitationCancellationReceipt, error) {
	stub.mu.Lock()
	stub.cancelCalls++
	stub.mu.Unlock()
	return ElicitationCancellationReceipt{
		Proof:   OpaqueElicitationCancellationReceipt(sha256.Sum256([]byte("elicitation-cancel"))),
		Durable: true, Scope: request.Scope, ParentEffectID: request.ParentEffectID,
		ParentInvocationID: request.ParentInvocationID, RequestDigest: request.RequestDigest,
		ClaimProof: request.Claim.Proof,
	}, nil
}

func (stub *elicitationStub) cancellations() int {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	return stub.cancelCalls
}

func connectionGenerationForEffect(effect Effect) uint64 {
	attempt, _ := effect.CurrentAttempt()
	return attempt.Negotiation.ConnectionGeneration
}

func TestServerInitiatedMethodsDefaultDenyWithJSONRPCErrorAndAudit(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	audit := &auditStub{}
	fixture.gateway.audit = audit
	effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-server-request")

	for index, method := range []string{
		string(ServerRequestSampling), string(ServerRequestElicitation), string(ServerRequestRoots),
		"resources/read", "prompts/get", "unknown/method",
	} {
		response, err := fixture.gateway.HandleServerRequest(context.Background(), ServerRequest{
			Authority: OpaqueAuthority("renewed-turn-secret"), Effect: effect,
			RequestID: fmt.Sprintf("server-request-%d", index+1), ProviderRequestID: "rpc-server-request",
			ConnectionGeneration: connectionGenerationForEffect(effect), Method: method, Params: canonical.Map{"value": "bounded"},
		})
		if err != nil {
			t.Fatalf("HandleServerRequest(%s): %v", method, err)
		}
		if response.Error == nil || response.Error.Code != -32601 || response.ResultCanonical != nil {
			t.Fatalf("denied %s response = %+v", method, response)
		}
	}
	audit.mu.Lock()
	defer audit.mu.Unlock()
	if len(audit.events) != 6 {
		t.Fatalf("denied server request audit count = %d, want 6", len(audit.events))
	}
	for _, event := range audit.events {
		if event.Decision != "denied" || event.TenantID != effect.Scope.TenantID || event.InvocationID != effect.Scope.InvocationID {
			t.Fatalf("invalid denial audit: %+v", event)
		}
	}
}

func TestUnsupportedServerMethodAuditUsesAllowlistedLabel(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	audit := &auditStub{}
	fixture.gateway.audit = audit
	effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-unsupported-audit")
	const untrustedMethod = "secret-token-from-provider"
	response, err := fixture.gateway.HandleServerRequest(context.Background(), ServerRequest{
		Authority: OpaqueAuthority("renewed"), Effect: effect, RequestID: "unsupported-audit",
		ProviderRequestID: "rpc-unsupported-audit", ConnectionGeneration: connectionGenerationForEffect(effect),
		Method: untrustedMethod, Params: canonical.Map{},
	})
	if err != nil || response.Error == nil || response.Error.Code != jsonRPCMethodNotFound {
		t.Fatalf("unsupported response=%+v err=%v", response, err)
	}
	audit.mu.Lock()
	defer audit.mu.Unlock()
	if len(audit.events) != 1 || audit.events[0].Method != "unsupported" ||
		strings.Contains(audit.events[0].Method, "secret-token") {
		t.Fatalf("unsupported audit leaked provider method: %+v", audit.events)
	}
}

func TestExplicitSamplingUsesDedicatedBrokerAndBoundsResult(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	sampling := &samplingStub{result: SamplingResult{
		Value: canonical.Map{"role": "assistant", "content": "approved"}, Durable: true,
	}}
	audit := &auditStub{}
	server := fixture.server
	server.AllowedServerRequests = []ServerRequestMethod{ServerRequestSampling}
	repository := NewMemoryRepository()
	gateway, err := NewGateway(Configuration{
		Bounds: testBounds(), Servers: []ServerRegistration{server}, Tools: []ToolRegistration{fixture.tool}, AllowReferenceMemory: true,
	}, Dependencies{
		Authority: fixture.authority, Authorizer: fixture.authorizer, Credentials: fixture.credentials,
		Repository: repository, Audit: audit, Providers: map[string]Provider{"stdio": fixture.provider}, Sampling: sampling,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.gateway = gateway
	fixture.repository = repository
	effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-sampling")
	response, err := gateway.HandleServerRequest(context.Background(), ServerRequest{
		Authority: OpaqueAuthority("renewed-turn-secret"), Effect: effect, RequestID: "sampling-1",
		ProviderRequestID: "rpc-sampling", ConnectionGeneration: connectionGenerationForEffect(effect), Method: string(ServerRequestSampling),
		Params: canonical.Map{"messages": canonical.Array{canonical.Map{"role": "user", "content": "hello"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.Error != nil || len(response.ResultCanonical) == 0 || sampling.calls != 1 {
		t.Fatalf("sampling response=%+v calls=%d", response, sampling.calls)
	}

	sampling.result.Value = canonical.Bytes(make([]byte, testBounds().MaxOutputBytes+1))
	response, err = gateway.HandleServerRequest(context.Background(), ServerRequest{
		Authority: OpaqueAuthority("renewed-turn-secret"), Effect: effect, RequestID: "sampling-2",
		ProviderRequestID: "rpc-sampling", ConnectionGeneration: connectionGenerationForEffect(effect), Method: string(ServerRequestSampling), Params: canonical.Map{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.Error == nil || response.Error.Code != -32603 || response.ResultCanonical != nil {
		t.Fatalf("oversized sampling response = %+v", response)
	}
}

func TestSamplingRejectsMissingDurableParentSuspendResumeProof(t *testing.T) {
	fixture, gateway, sampling := newSamplingGatewayFixture(t)
	sampling.result.ParentLifecycle.Proof[0] = 1
	effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-sampling-parent-proof")
	response, err := gateway.HandleServerRequest(context.Background(), ServerRequest{
		Authority: OpaqueAuthority("renewed"), Effect: effect, RequestID: "sampling-parent-proof",
		ProviderRequestID: "rpc-sampling-parent-proof", ConnectionGeneration: connectionGenerationForEffect(effect),
		Method: string(ServerRequestSampling), Params: canonical.Map{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.Error == nil || response.Error.Code != jsonRPCInternalError || response.ResultCanonical != nil {
		t.Fatalf("missing parent lifecycle proof response=%+v", response)
	}
}

func TestSamplingErrorCancelsPrecommittedChildBeforeTerminalResponse(t *testing.T) {
	fixture, gateway, sampling := newSamplingGatewayFixture(t)
	sampling.err = errors.New("model child response lost after admit")
	effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-sampling-error-child")
	response, err := gateway.HandleServerRequest(context.Background(), ServerRequest{
		Authority: OpaqueAuthority("renewed"), Effect: effect, RequestID: "sampling-error-child",
		ProviderRequestID: "rpc-sampling-error-child", ConnectionGeneration: connectionGenerationForEffect(effect),
		Method: string(ServerRequestSampling), Params: canonical.Map{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.Error == nil || response.Error.Code != jsonRPCInternalError || sampling.cancelCalls != 1 {
		t.Fatalf("sampling error response=%+v child-cancels=%d", response, sampling.cancelCalls)
	}
	fixture.repository.mu.RLock()
	record := fixture.repository.serverRequests[serverRequestKey{
		invocation: effect.Scope.InvocationID, providerRequestID: "rpc-sampling-error-child",
		connectionGeneration: connectionGenerationForEffect(effect), requestID: "sampling-error-child",
	}]
	fixture.repository.mu.RUnlock()
	if record.State != ServerRequestCompleted || record.ChildCancellation == (SamplingCancellationReceipt{}) {
		t.Fatalf("sampling error lost child resolution: %+v", record)
	}
}

func TestServerRequestRejectsStaleParentSnapshotBeforeBrokerSideEffect(t *testing.T) {
	fixture, gateway, sampling := newSamplingGatewayFixture(t)
	dispatched := durablyDispatchedFixtureEffect(t, fixture, "rpc-stale-parent")
	committed := applyFixtureEvent(t, gateway, dispatched, Event{
		Kind: EventCallCommitted, Output: []byte(`{"done":true}`), ExternalCommitID: "commit-parent",
	})
	persistFixtureEffect(t, fixture.repository, dispatched, committed)
	completed := applyFixtureEvent(t, gateway, committed, Event{Kind: EventSettlementCompleted})
	persistFixtureEffect(t, fixture.repository, committed, completed)

	_, err := gateway.HandleServerRequest(context.Background(), ServerRequest{
		Authority: OpaqueAuthority("renewed-turn-secret"), Effect: dispatched, RequestID: "sampling-stale",
		ProviderRequestID: "rpc-stale-parent", ConnectionGeneration: connectionGenerationForEffect(dispatched), Method: string(ServerRequestSampling), Params: canonical.Map{"value": "late"},
	})
	if !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("stale parent request error = %v, want %v", err, ErrInvalidTransition)
	}
	if sampling.calls != 0 {
		t.Fatalf("stale parent reached sampling broker %d times", sampling.calls)
	}
}

func TestServerRequestRejectsWrongConnectionGenerationBeforeBrokerSideEffect(t *testing.T) {
	fixture, gateway, sampling := newSamplingGatewayFixture(t)
	effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-wrong-connection")
	_, err := gateway.HandleServerRequest(context.Background(), ServerRequest{
		Authority: OpaqueAuthority("renewed"), Effect: effect, RequestID: "sampling-wrong-connection",
		ProviderRequestID: "rpc-wrong-connection", ConnectionGeneration: connectionGenerationForEffect(effect) + 1,
		Method: string(ServerRequestSampling), Params: canonical.Map{},
	})
	if !errors.Is(err, ErrAuthorityMismatch) {
		t.Fatalf("wrong connection generation error=%v, want %v", err, ErrAuthorityMismatch)
	}
	if sampling.calls != 0 || sampling.resumeCalls != 0 {
		t.Fatalf("wrong connection generation reached broker: sample=%d resume=%d", sampling.calls, sampling.resumeCalls)
	}
}

func TestCancellationPendingParentRejectsNewSamplingBeforeBrokerSideEffect(t *testing.T) {
	fixture, gateway, sampling := newSamplingGatewayFixture(t)
	dispatched := durablyDispatchedFixtureEffect(t, fixture, "rpc-cancelling-parent")
	requested := applyFixtureEvent(t, gateway, dispatched, Event{Kind: EventCancelRequested})
	persistFixtureEffect(t, fixture.repository, dispatched, requested)

	_, err := gateway.HandleServerRequest(context.Background(), ServerRequest{
		Authority: OpaqueAuthority("renewed"), Effect: requested, RequestID: "sampling-after-cancel",
		ProviderRequestID: "rpc-cancelling-parent", ConnectionGeneration: connectionGenerationForEffect(requested),
		Method: string(ServerRequestSampling), Params: canonical.Map{},
	})
	if !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("cancellation-pending server request error=%v, want %v", err, ErrInvalidTransition)
	}
	if sampling.calls != 0 || sampling.resumeCalls != 0 {
		t.Fatalf("cancellation-pending parent reached broker: sample=%d resume=%d", sampling.calls, sampling.resumeCalls)
	}
	fixture.provider.cancel = func(context.Context, CancelCommand) (CancellationResult, error) {
		return CancellationResult{Status: CancellationAbsent}, nil
	}
	cancelled, err := gateway.Cancel(context.Background(), OpaqueAuthority("renewed"), requested)
	if err != nil || cancelled.State != StateCancelled {
		t.Fatalf("parent cancellation did not remain live: state=%s err=%v", cancelled.State, err)
	}
}

func TestActiveSamplingClaimDoesNotDelayParentCancellationIntent(t *testing.T) {
	fixture, gateway, sampling := newSamplingGatewayFixture(t)
	effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-active-child-cancel")
	_, err := fixture.repository.ClaimServerRequest(context.Background(), ServerRequestClaimRequest{
		CurrentScope: effect.Scope, Parent: effect, ProviderRequestID: "rpc-active-child-cancel",
		ConnectionGeneration: connectionGenerationForEffect(effect), RequestID: "sampling-active-cancel",
		Method: string(ServerRequestSampling), RequestDigest: sha256.Sum256([]byte("active-child-cancel")),
		ChildEffectID: mustID(t, identity.Effect), ChildInvocationID: mustID(t, identity.Invocation),
		BrokerCancellationRequired: true,
		MaxRequests:                testBounds().MaxEvents, Lease: testBounds().CancelTimeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.provider.cancel = func(context.Context, CancelCommand) (CancellationResult, error) {
		return CancellationResult{Status: CancellationUnknown}, nil
	}

	result, err := gateway.Cancel(context.Background(), OpaqueAuthority("renewed"), effect)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != StateUncertain || sampling.cancelCalls != 1 {
		t.Fatalf("active child cancellation state=%s child-cancels=%d", result.State, sampling.cancelCalls)
	}
	stored, loadErr := fixture.repository.Load(context.Background(), effect.Scope.InvocationID)
	if loadErr != nil || stored.Effect.State != StateUncertain {
		t.Fatalf("durable cancellation result=%+v err=%v", stored, loadErr)
	}
}

func TestActiveElicitationIsDurablyFencedBeforeParentCancellationResolves(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	elicitation := &elicitationStub{started: make(chan struct{}), release: make(chan struct{})}
	server := fixture.server
	server.AllowedServerRequests = []ServerRequestMethod{ServerRequestElicitation}
	repository := NewMemoryRepository()
	gateway, err := NewGateway(Configuration{
		Bounds: testBounds(), Servers: []ServerRegistration{server}, Tools: []ToolRegistration{fixture.tool}, AllowReferenceMemory: true,
	}, Dependencies{
		Authority: fixture.authority, Authorizer: fixture.authorizer, Credentials: fixture.credentials,
		Repository: repository, Audit: &auditStub{}, Providers: map[string]Provider{"stdio": fixture.provider},
		Elicitation: elicitation,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.gateway = gateway
	fixture.repository = repository
	effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-active-elicitation")
	handled := make(chan error, 1)
	go func() {
		_, handleErr := gateway.HandleServerRequest(context.Background(), ServerRequest{
			Authority: OpaqueAuthority("renewed"), Effect: effect, RequestID: "active-elicitation",
			ProviderRequestID: "rpc-active-elicitation", ConnectionGeneration: connectionGenerationForEffect(effect),
			Method: string(ServerRequestElicitation), Params: canonical.Map{"prompt": "approve"},
		})
		handled <- handleErr
	}()
	<-elicitation.started
	fixture.provider.cancel = func(context.Context, CancelCommand) (CancellationResult, error) {
		return CancellationResult{Status: CancellationUnknown}, nil
	}
	cancelled, cancelErr := gateway.Cancel(context.Background(), OpaqueAuthority("renewed"), effect)
	close(elicitation.release)
	<-handled
	if cancelErr != nil || cancelled.State != StateUncertain || elicitation.cancellations() != 1 {
		t.Fatalf("elicitation parent cancel state=%s child-cancels=%d err=%v", cancelled.State, elicitation.cancellations(), cancelErr)
	}
}

func TestElicitationErrorInstallsDurableTombstoneBeforeTerminalResponse(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	elicitation := &elicitationStub{err: errors.New("prompt response lost after display")}
	server := fixture.server
	server.AllowedServerRequests = []ServerRequestMethod{ServerRequestElicitation}
	repository := NewMemoryRepository()
	gateway, err := NewGateway(Configuration{
		Bounds: testBounds(), Servers: []ServerRegistration{server}, Tools: []ToolRegistration{fixture.tool}, AllowReferenceMemory: true,
	}, Dependencies{
		Authority: fixture.authority, Authorizer: fixture.authorizer, Credentials: fixture.credentials,
		Repository: repository, Audit: &auditStub{}, Providers: map[string]Provider{"stdio": fixture.provider},
		Elicitation: elicitation,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.gateway = gateway
	fixture.repository = repository
	effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-elicitation-error")
	response, err := gateway.HandleServerRequest(context.Background(), ServerRequest{
		Authority: OpaqueAuthority("renewed"), Effect: effect, RequestID: "elicitation-error",
		ProviderRequestID: "rpc-elicitation-error", ConnectionGeneration: connectionGenerationForEffect(effect),
		Method: string(ServerRequestElicitation), Params: canonical.Map{"prompt": "approve"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.Error == nil || response.Error.Code != jsonRPCInternalError || elicitation.cancellations() != 1 {
		t.Fatalf("elicitation error response=%+v cancels=%d", response, elicitation.cancellations())
	}
	repository.mu.RLock()
	record := repository.serverRequests[serverRequestKey{
		invocation: effect.Scope.InvocationID, providerRequestID: "rpc-elicitation-error",
		connectionGeneration: connectionGenerationForEffect(effect), requestID: "elicitation-error",
	}]
	repository.mu.RUnlock()
	if record.State != ServerRequestCompleted || record.ElicitationCancellation == (ElicitationCancellationReceipt{}) {
		t.Fatalf("elicitation error lost tombstone: %+v", record)
	}
}

func TestServerRequestReplayReturnsDurableResponseWithoutRepeatingBroker(t *testing.T) {
	fixture, gateway, sampling := newSamplingGatewayFixture(t)
	effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-server-dedup")
	request := ServerRequest{
		Authority: OpaqueAuthority("renewed-turn-secret"), Effect: effect, RequestID: "sampling-dedup",
		ProviderRequestID: "rpc-server-dedup", ConnectionGeneration: connectionGenerationForEffect(effect), Method: string(ServerRequestSampling), Params: canonical.Map{"value": "same"},
	}
	first, err := gateway.HandleServerRequest(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := gateway.HandleServerRequest(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if sampling.calls != 1 || first.RequestID != second.RequestID || !bytes.Equal(first.ResultCanonical, second.ResultCanonical) {
		t.Fatalf("sampling calls=%d first=%+v second=%+v", sampling.calls, first, second)
	}

	changed := request
	changed.Params = canonical.Map{"value": "different"}
	if _, err := gateway.HandleServerRequest(context.Background(), changed); !errors.Is(err, ErrInvocationConflict) {
		t.Fatalf("same server request ID with different params error = %v, want %v", err, ErrInvocationConflict)
	}
}

func TestServerRequestClaimCanBeSafelyTakenOverAfterOwnerFenceRotation(t *testing.T) {
	fixture, gateway, sampling := newSamplingGatewayFixture(t)
	effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-server-takeover")
	request := ServerRequest{
		Authority: OpaqueAuthority("renewed"), Effect: effect, RequestID: "sampling-takeover",
		ProviderRequestID: "rpc-server-takeover", ConnectionGeneration: connectionGenerationForEffect(effect), Method: string(ServerRequestSampling), Params: canonical.Map{},
	}
	params, err := canonical.Encode(request.Params, canonical.Options{
		MaxDepth: testBounds().MaxInputDepth, MaxBytes: int(testBounds().MaxInputBytes),
		MaxItems: canonical.DefaultOptions().MaxItems,
	})
	if err != nil {
		t.Fatal(err)
	}
	digestInput, err := canonical.Encode(canonical.Array{
		"circulusd.hash", int64(1), "mcp.server.request", int64(1),
		canonical.Map{
			"parentInvocation": effect.Scope.InvocationID.String(), "parentDigest": canonical.Bytes(effect.RequestDigest[:]),
			"providerRequest": request.ProviderRequestID, "connectionGeneration": int64(request.ConnectionGeneration), "requestId": request.RequestID,
			"method": request.Method, "params": canonical.Bytes(params),
		},
	}, canonical.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	requestDigest := sha256.Sum256(digestInput)
	claimed, err := fixture.repository.ClaimServerRequest(context.Background(), ServerRequestClaimRequest{
		CurrentScope: effect.Scope, Parent: effect, ProviderRequestID: request.ProviderRequestID,
		ConnectionGeneration: request.ConnectionGeneration, RequestID: request.RequestID, Method: request.Method, RequestDigest: requestDigest,
		ChildEffectID: mustID(t, identity.Effect), ChildInvocationID: mustID(t, identity.Invocation),
		BrokerCancellationRequired: true,
		MaxRequests:                testBounds().MaxEvents, Lease: testBounds().CancelTimeout,
	})
	if err != nil || !claimed.Fresh {
		t.Fatalf("initial server request claim=%+v err=%v", claimed, err)
	}
	current := effect.Scope
	current.Generations.Placement++
	fixture.authority.mu.Lock()
	fixture.authority.scope = current
	fixture.authority.mu.Unlock()
	if err := fixture.repository.SetCurrentAuthority(current); err != nil {
		t.Fatal(err)
	}
	sampling.resumeErr = ErrInvocationNotFound

	response, err := gateway.HandleServerRequest(context.Background(), request)
	if errors.Is(err, ErrEffectInFlight) {
		t.Fatalf("expired server request owner permanently blocked takeover: %v", err)
	}
	if sampling.calls != 0 {
		t.Fatalf("unsafe sampling was executed again without a durable child receipt: calls=%d", sampling.calls)
	}
	if sampling.resumeCalls != 1 {
		t.Fatalf("takeover did not resume the precommitted child receipt: resumes=%d", sampling.resumeCalls)
	}
	if err != nil {
		t.Fatal(err)
	}
	if response.Error == nil || response.Error.Code != jsonRPCInternalError {
		t.Fatalf("unsafe takeover response=%+v, want durable safe failure", response)
	}
}

func TestExpiredServerRequestClaimDoesNotBlockParentRecovery(t *testing.T) {
	fixture, gateway, _ := newSamplingGatewayFixture(t)
	effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-expired-child-recovery")
	now := time.Unix(1_800_000_000, 0)
	fixture.repository.now = func() time.Time { return now }
	request := ServerRequest{
		Authority: OpaqueAuthority("renewed"), Effect: effect, RequestID: "sampling-expired-recovery",
		ProviderRequestID: "rpc-expired-child-recovery", ConnectionGeneration: connectionGenerationForEffect(effect),
		Method: string(ServerRequestSampling), Params: canonical.Map{},
	}
	params, err := canonical.Encode(request.Params, canonical.Options{
		MaxDepth: testBounds().MaxInputDepth, MaxBytes: int(testBounds().MaxInputBytes),
		MaxItems: canonical.DefaultOptions().MaxItems,
	})
	if err != nil {
		t.Fatal(err)
	}
	digestInput, err := canonical.Encode(canonical.Array{
		"circulusd.hash", int64(1), "mcp.server.request", int64(1),
		canonical.Map{
			"parentInvocation": effect.Scope.InvocationID.String(), "parentDigest": canonical.Bytes(effect.RequestDigest[:]),
			"providerRequest": request.ProviderRequestID, "connectionGeneration": int64(request.ConnectionGeneration),
			"requestId": request.RequestID, "method": request.Method, "params": canonical.Bytes(params),
		},
	}, canonical.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	requestDigest := sha256.Sum256(digestInput)
	claimed, err := fixture.repository.ClaimServerRequest(context.Background(), ServerRequestClaimRequest{
		CurrentScope: effect.Scope, Parent: effect, ProviderRequestID: request.ProviderRequestID,
		ConnectionGeneration: request.ConnectionGeneration, RequestID: request.RequestID,
		Method: request.Method, RequestDigest: requestDigest,
		ChildEffectID: mustID(t, identity.Effect), ChildInvocationID: mustID(t, identity.Invocation),
		BrokerCancellationRequired: true,
		MaxRequests:                testBounds().MaxEvents, Lease: testBounds().CancelTimeout,
	})
	if err != nil || !claimed.Fresh {
		t.Fatalf("server request claim=%+v err=%v", claimed, err)
	}
	now = now.Add(testBounds().CancelTimeout + time.Nanosecond)
	fixture.provider.lookup = func(_ context.Context, query LedgerQuery) (LedgerRecord, error) {
		return LedgerRecord{
			InvocationID: query.InvocationID, RequestDigest: query.RequestDigest, Status: LedgerCommitted,
			ProviderRequestID: "rpc-expired-child-recovery", ExternalCommitID: "commit-expired-child",
			Output: []byte(`{"done":true}`),
		}, nil
	}
	fixture.provider.cancel = func(_ context.Context, command CancelCommand) (CancellationResult, error) {
		return CancellationResult{Status: CancellationCommitted, Record: LedgerRecord{
			InvocationID: command.InvocationID, RequestDigest: command.RequestDigest, Status: LedgerCommitted,
			ProviderRequestID: command.ProviderRequestID, ExternalCommitID: "commit-expired-child",
			Output: []byte(`{"done":true}`),
		}}, nil
	}

	recovered, err := gateway.Recover(context.Background(), OpaqueAuthority("renewed"), effect)
	if err != nil || recovered.Action != RecoverySettled || recovered.Effect.State != StateCompleted {
		t.Fatalf("expired child blocked parent recovery: result=%+v err=%v", recovered, err)
	}
	_, err = fixture.repository.CompleteServerRequest(context.Background(), ServerRequestCommitRequest{
		CurrentScope: effect.Scope, Permit: claimed.Record.Permit,
		Response: ServerResponse{RequestID: request.RequestID, ResultCanonical: []byte(`{"late":true}`)},
		Audit: &AuditEvent{TenantID: effect.Scope.TenantID, UserID: effect.Scope.UserID,
			SessionID: effect.Scope.SessionID, TurnID: effect.Scope.TurnID, InvocationID: effect.Scope.InvocationID,
			ServerID: effect.ServerID, Method: string(ServerRequestSampling), Decision: "allowed", Reason: "late"},
	})
	if !errors.Is(err, ErrInvocationConflict) {
		t.Fatalf("late server-request owner error=%v, want %v", err, ErrInvocationConflict)
	}
}

func TestExpiredServerRequestClaimReconciliationLeavesKnownInflightParentBudgetNeutral(t *testing.T) {
	fixture, gateway, sampling := newSamplingGatewayFixture(t)
	effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-expired-child-inflight")
	now := time.Unix(1_800_000_000, 0)
	fixture.repository.now = func() time.Time { return now }
	claimed, err := fixture.repository.ClaimServerRequest(context.Background(), ServerRequestClaimRequest{
		CurrentScope: effect.Scope, Parent: effect, ProviderRequestID: "rpc-expired-child-inflight",
		ConnectionGeneration: connectionGenerationForEffect(effect), RequestID: "sampling-expired-inflight",
		Method: string(ServerRequestSampling), RequestDigest: sha256.Sum256([]byte("expired-inflight")),
		ChildEffectID: mustID(t, identity.Effect), ChildInvocationID: mustID(t, identity.Invocation),
		BrokerCancellationRequired: true,
		MaxRequests:                testBounds().MaxEvents, Lease: testBounds().CancelTimeout,
	})
	if err != nil || !claimed.Fresh {
		t.Fatalf("server request claim=%+v err=%v", claimed, err)
	}
	now = now.Add(testBounds().CancelTimeout + time.Nanosecond)
	fixture.provider.lookup = func(_ context.Context, query LedgerQuery) (LedgerRecord, error) {
		return LedgerRecord{
			InvocationID: query.InvocationID, RequestDigest: query.RequestDigest,
			Status: LedgerInflight, ProviderRequestID: "rpc-expired-child-inflight",
		}, nil
	}
	fixture.provider.cancel = func(context.Context, CancelCommand) (CancellationResult, error) {
		return CancellationResult{Status: CancellationUnknown}, nil
	}

	recovered, err := gateway.Recover(context.Background(), OpaqueAuthority("renewed"), effect)
	if err != nil || recovered.Action != RecoveryInterrupted || recovered.Effect.State != StateUncertain {
		t.Fatalf("inflight recovery=%+v err=%v", recovered, err)
	}
	again, err := gateway.Recover(context.Background(), OpaqueAuthority("renewed"), recovered.Effect)
	if err != nil || again.Action != RecoveryWait || !sameEffect(again.Effect, recovered.Effect) {
		t.Fatalf("known inflight ledger consumed another event: first=%+v again=%+v err=%v", recovered, again, err)
	}
	fixture.repository.mu.RLock()
	_, active := fixture.repository.activeServerRequests[effect.Scope.InvocationID.String()]
	record := fixture.repository.serverRequests[serverRequestKey{
		invocation: effect.Scope.InvocationID, providerRequestID: "rpc-expired-child-inflight",
		connectionGeneration: connectionGenerationForEffect(effect), requestID: "sampling-expired-inflight",
	}]
	fixture.repository.mu.RUnlock()
	if active || record.State != ServerRequestAbandoned || sampling.cancelCalls != 1 ||
		record.ChildCancellation == (SamplingCancellationReceipt{}) {
		t.Fatalf("expired child was not durably reconciled: active=%v child-cancels=%d record=%+v", active, sampling.cancelCalls, record)
	}
}

func TestReconciledServerRequestCrashRetainsDurableParentCancelObligation(t *testing.T) {
	tests := []struct {
		name     string
		method   ServerRequestMethod
		sampling bool
	}{
		{name: "sampling", method: ServerRequestSampling, sampling: true},
		{name: "roots", method: ServerRequestRoots},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture, gateway, sampling := newSamplingGatewayFixture(t)
			effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-reconcile-crash-"+test.name)
			now := time.Unix(1_800_000_000, 0)
			fixture.repository.now = func() time.Time { return now }
			claimRequest := ServerRequestClaimRequest{
				CurrentScope: effect.Scope, Parent: effect, ProviderRequestID: "rpc-reconcile-crash-" + test.name,
				ConnectionGeneration: connectionGenerationForEffect(effect), RequestID: "request-reconcile-crash-" + test.name,
				Method: string(test.method), RequestDigest: sha256.Sum256([]byte("reconcile-crash-" + test.name)),
				MaxRequests: testBounds().MaxEvents, Lease: testBounds().CancelTimeout,
			}
			if test.sampling {
				claimRequest.BrokerCancellationRequired = true
				claimRequest.ChildEffectID = mustID(t, identity.Effect)
				claimRequest.ChildInvocationID = mustID(t, identity.Invocation)
			}
			claimed, err := fixture.repository.ClaimServerRequest(context.Background(), claimRequest)
			if err != nil {
				t.Fatal(err)
			}
			now = now.Add(testBounds().CancelTimeout + time.Nanosecond)
			reconciled, err := fixture.repository.ReconcileServerRequests(context.Background(), ServerRequestReconcileRequest{
				CurrentScope: effect.Scope, Parent: effect,
			})
			if err != nil || !reconciled.Reconciled {
				t.Fatalf("reconcile=%+v err=%v", reconciled, err)
			}
			if test.sampling {
				request := SamplingCancellationRequest{
					Scope: effect.Scope, ParentEffectID: effect.Scope.EffectID,
					ParentInvocationID: effect.Scope.InvocationID,
					RequestDigest:      claimed.Record.Permit.RequestDigest, Claim: claimed.Record.Permit,
				}
				receipt, cancelErr := sampling.Cancel(context.Background(), request)
				if cancelErr != nil {
					t.Fatal(cancelErr)
				}
				if _, err := fixture.repository.CompleteServerRequestReconciliation(context.Background(), ServerRequestReconcileCommitRequest{
					CurrentScope: effect.Scope, Permit: claimed.Record.Permit, Cancellation: receipt,
				}); err != nil {
					t.Fatal(err)
				}
			}
			fixture.provider.lookup = func(_ context.Context, query LedgerQuery) (LedgerRecord, error) {
				return LedgerRecord{
					InvocationID: query.InvocationID, RequestDigest: query.RequestDigest,
					Status: LedgerInflight, ProviderRequestID: "rpc-reconcile-crash-" + test.name,
				}, nil
			}
			providerCancels := 0
			fixture.provider.cancel = func(context.Context, CancelCommand) (CancellationResult, error) {
				providerCancels++
				return CancellationResult{Status: CancellationUnknown}, nil
			}

			recovered, err := gateway.Recover(context.Background(), OpaqueAuthority("renewed"), effect)
			if err != nil || recovered.Effect.State != StateUncertain || recovered.Action != RecoveryInterrupted || providerCancels != 1 {
				t.Fatalf("post-crash recovery=%+v provider-cancels=%d err=%v", recovered, providerCancels, err)
			}
		})
	}
}

func TestExternallyCommittedParentSettlesAfterExpiredChildCleanup(t *testing.T) {
	fixture, gateway, sampling := newSamplingGatewayFixture(t)
	effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-committed-expired-child")
	now := time.Unix(1_800_000_000, 0)
	fixture.repository.now = func() time.Time { return now }
	_, err := fixture.repository.ClaimServerRequest(context.Background(), ServerRequestClaimRequest{
		CurrentScope: effect.Scope, Parent: effect, ProviderRequestID: "rpc-committed-expired-child",
		ConnectionGeneration: connectionGenerationForEffect(effect), RequestID: "committed-expired-child",
		Method: string(ServerRequestSampling), RequestDigest: sha256.Sum256([]byte("committed-expired-child")),
		ChildEffectID: mustID(t, identity.Effect), ChildInvocationID: mustID(t, identity.Invocation),
		BrokerCancellationRequired: true,
		MaxRequests:                testBounds().MaxEvents, Lease: testBounds().CancelTimeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(testBounds().CancelTimeout + time.Nanosecond)
	committed := applyFixtureEvent(t, gateway, effect, Event{
		Kind: EventCallCommitted, Output: []byte(`{"done":true}`), ExternalCommitID: "commit-expired-child-parent",
	})
	stored, err := fixture.repository.Commit(context.Background(), TransitionCommitRequest{
		ExpectedRevision: effect.Revision, CurrentScope: effect.Scope, Previous: effect, Next: committed,
	})
	if err != nil || !stored.Durable {
		t.Fatalf("external commit=%+v err=%v", stored, err)
	}
	providerCancels := 0
	fixture.provider.cancel = func(context.Context, CancelCommand) (CancellationResult, error) {
		providerCancels++
		return CancellationResult{Status: CancellationUnknown}, nil
	}
	recovered, err := gateway.Recover(context.Background(), OpaqueAuthority("renewed"), committed)
	if err != nil || recovered.Action != RecoverySettled || recovered.Effect.State != StateCompleted ||
		sampling.cancelCalls != 1 || providerCancels != 0 {
		t.Fatalf("committed child cleanup result=%+v child-cancels=%d provider-cancels=%d err=%v",
			recovered, sampling.cancelCalls, providerCancels, err)
	}
}

func TestParentCancelObligationFencesNewServerRequestClaims(t *testing.T) {
	fixture, gateway, sampling := newSamplingGatewayFixture(t)
	effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-parent-cancel-marker")
	now := time.Unix(1_800_000_000, 0)
	fixture.repository.now = func() time.Time { return now }
	_, err := fixture.repository.ClaimServerRequest(context.Background(), ServerRequestClaimRequest{
		CurrentScope: effect.Scope, Parent: effect, ProviderRequestID: "rpc-parent-cancel-marker",
		ConnectionGeneration: connectionGenerationForEffect(effect), RequestID: "expired-first-child",
		Method: string(ServerRequestSampling), RequestDigest: sha256.Sum256([]byte("expired-first-child")),
		ChildEffectID: mustID(t, identity.Effect), ChildInvocationID: mustID(t, identity.Invocation),
		BrokerCancellationRequired: true,
		MaxRequests:                testBounds().MaxEvents, Lease: testBounds().CancelTimeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(testBounds().CancelTimeout + time.Nanosecond)
	if _, err := fixture.repository.ReconcileServerRequests(context.Background(), ServerRequestReconcileRequest{
		CurrentScope: effect.Scope, Parent: effect,
	}); err != nil {
		t.Fatal(err)
	}

	_, err = gateway.HandleServerRequest(context.Background(), ServerRequest{
		Authority: OpaqueAuthority("renewed"), Effect: effect, RequestID: "must-be-fenced",
		ProviderRequestID: "rpc-parent-cancel-marker", ConnectionGeneration: connectionGenerationForEffect(effect),
		Method: string(ServerRequestSampling), Params: canonical.Map{},
	})
	if !errors.Is(err, ErrInvalidTransition) && !errors.Is(err, ErrEffectInFlight) {
		t.Fatalf("new claim under parent-cancel marker error=%v", err)
	}
	if sampling.calls != 0 || sampling.resumeCalls != 0 {
		t.Fatalf("parent-cancel marker reached broker: sample=%d resume=%d", sampling.calls, sampling.resumeCalls)
	}
}

func TestExpiredDefaultDeniedSamplingClaimDoesNotRequireMissingBroker(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-denied-sampling-crash")
	now := time.Unix(1_800_000_000, 0)
	fixture.repository.now = func() time.Time { return now }
	_, err := fixture.repository.ClaimServerRequest(context.Background(), ServerRequestClaimRequest{
		CurrentScope: effect.Scope, Parent: effect, ProviderRequestID: "rpc-denied-sampling-crash",
		ConnectionGeneration: connectionGenerationForEffect(effect), RequestID: "denied-sampling-crash",
		Method: string(ServerRequestSampling), RequestDigest: sha256.Sum256([]byte("denied-sampling-crash")),
		MaxRequests: testBounds().MaxEvents, Lease: testBounds().CancelTimeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(testBounds().CancelTimeout + time.Nanosecond)
	providerCancels := 0
	fixture.provider.cancel = func(context.Context, CancelCommand) (CancellationResult, error) {
		providerCancels++
		return CancellationResult{Status: CancellationAbsent}, nil
	}
	recovered, err := fixture.gateway.Recover(context.Background(), OpaqueAuthority("renewed"), effect)
	if err != nil || recovered.Effect.State != StateCancelled || providerCancels != 1 {
		t.Fatalf("default-denied crash recovery=%+v provider-cancels=%d err=%v", recovered, providerCancels, err)
	}
}

func TestServerRequestResponseAndAuditOutboxCommitAtomically(t *testing.T) {
	fixture, gateway, sampling := newSamplingGatewayFixture(t)
	audit := &auditStub{err: errors.New("audit unavailable")}
	gateway.audit = audit
	effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-server-audit")
	request := ServerRequest{
		Authority: OpaqueAuthority("renewed-turn-secret"), Effect: effect, RequestID: "sampling-audit",
		ProviderRequestID: "rpc-server-audit", ConnectionGeneration: connectionGenerationForEffect(effect), Method: string(ServerRequestSampling), Params: canonical.Map{"value": "same"},
	}
	first, err := gateway.HandleServerRequest(context.Background(), request)
	if !errors.Is(err, ErrAuditUnavailable) || len(first.ResultCanonical) == 0 {
		t.Fatalf("first response=%+v err=%v", first, err)
	}
	pending, err := fixture.repository.PendingAudits(context.Background(), 10)
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending server audit=%+v err=%v", pending, err)
	}
	second, err := gateway.HandleServerRequest(context.Background(), request)
	if err != nil || !bytes.Equal(second.ResultCanonical, first.ResultCanonical) || sampling.calls != 1 {
		t.Fatalf("durable replay response=%+v calls=%d err=%v", second, sampling.calls, err)
	}
	audit.mu.Lock()
	audit.err = nil
	audit.mu.Unlock()
	if err := gateway.FlushAudit(context.Background(), 10); err != nil {
		t.Fatal(err)
	}
	pending, err = fixture.repository.PendingAudits(context.Background(), 10)
	if err != nil || len(pending) != 0 {
		t.Fatalf("acknowledged server audit=%+v err=%v", pending, err)
	}
}

func TestInvalidServerRequestAuditUsesDurableSequenceOutbox(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	audit := &auditStub{err: errors.New("audit unavailable")}
	fixture.gateway.audit = audit
	effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-invalid-server-audit")
	response, err := fixture.gateway.HandleServerRequest(context.Background(), ServerRequest{
		Authority: OpaqueAuthority("renewed-turn-secret"), Effect: effect, RequestID: "invalid-audit",
		ProviderRequestID: "rpc-invalid-server-audit", ConnectionGeneration: connectionGenerationForEffect(effect), Method: "resources/read",
		Params: canonical.Bytes(make([]byte, testBounds().MaxInputBytes+1)),
	})
	if response.Error == nil || response.Error.Code != jsonRPCInvalidParams || !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("invalid response=%+v err=%v", response, err)
	}
	pending, pendingErr := fixture.repository.PendingAudits(context.Background(), 10)
	if pendingErr != nil || len(pending) != 1 || pending[0].Event.OutboxSequence == 0 ||
		pending[0].Event.Decision != "denied" {
		t.Fatalf("invalid-request pending audit=%+v err=%v", pending, pendingErr)
	}
}

func TestExpiredServerRequestClaimAtomicallyOutboxesCrashAudit(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-expired-audit")
	now := time.Unix(1_800_000_000, 0)
	fixture.repository.now = func() time.Time { return now }
	claimed, err := fixture.repository.ClaimServerRequest(context.Background(), ServerRequestClaimRequest{
		CurrentScope: effect.Scope, Parent: effect, ProviderRequestID: "rpc-expired-audit",
		ConnectionGeneration: connectionGenerationForEffect(effect), RequestID: "unsupported-crash",
		Method: "resources/read", RequestDigest: sha256.Sum256([]byte("unsupported-crash")),
		MaxRequests: testBounds().MaxEvents, Lease: testBounds().CancelTimeout,
	})
	if err != nil || !claimed.Fresh {
		t.Fatalf("claim=%+v err=%v", claimed, err)
	}
	now = now.Add(testBounds().CancelTimeout + time.Nanosecond)
	reconciled, err := fixture.repository.ReconcileServerRequests(context.Background(), ServerRequestReconcileRequest{
		CurrentScope: effect.Scope, Parent: effect,
	})
	if err != nil || !reconciled.Reconciled || reconciled.Record.State != ServerRequestAbandoned {
		t.Fatalf("reconcile=%+v err=%v", reconciled, err)
	}
	pending, err := fixture.repository.PendingAudits(context.Background(), 10)
	if err != nil || len(pending) != 1 || pending[0].Sequence == 0 ||
		pending[0].Sequence != reconciled.Record.AuditSequence || pending[0].Event.Method != "unsupported" ||
		pending[0].Event.Decision != "failed" {
		t.Fatalf("crash audit=%+v reconcile=%+v err=%v", pending, reconciled, err)
	}
}

func TestParentCommitAutoAbandonAtomicallyOutboxesServerRequestCrashAudit(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-parent-commit-audit")
	now := time.Unix(1_800_000_000, 0)
	fixture.repository.now = func() time.Time { return now }
	digest := sha256.Sum256([]byte("parent-commit-crash"))
	claimed, err := fixture.repository.ClaimServerRequest(context.Background(), ServerRequestClaimRequest{
		CurrentScope: effect.Scope, Parent: effect, ProviderRequestID: "rpc-parent-commit-audit",
		ConnectionGeneration: connectionGenerationForEffect(effect), RequestID: "unsupported-parent-commit",
		Method: "resources/read", RequestDigest: digest,
		MaxRequests: testBounds().MaxEvents, Lease: testBounds().CancelTimeout,
	})
	if err != nil || !claimed.Fresh {
		t.Fatalf("claim=%+v err=%v", claimed, err)
	}
	now = now.Add(testBounds().CancelTimeout + time.Nanosecond)
	committed := applyFixtureEvent(t, fixture.gateway, effect, Event{
		Kind: EventCallCommitted, Output: []byte(`{"done":true}`), ExternalCommitID: "commit-parent-audit",
	})
	if _, err := fixture.repository.Commit(context.Background(), TransitionCommitRequest{
		ExpectedRevision: effect.Revision, CurrentScope: effect.Scope, Previous: effect, Next: committed,
	}); err != nil {
		t.Fatal(err)
	}
	fixture.repository.mu.RLock()
	record := fixture.repository.serverRequests[serverRequestKey{
		invocation: effect.Scope.InvocationID, providerRequestID: "rpc-parent-commit-audit",
		connectionGeneration: connectionGenerationForEffect(effect), requestID: "unsupported-parent-commit",
	}]
	fixture.repository.mu.RUnlock()
	pending, err := fixture.repository.PendingAudits(context.Background(), 10)
	if err != nil || record.State != ServerRequestAbandoned || record.AuditSequence == 0 || len(pending) != 1 ||
		pending[0].Sequence != record.AuditSequence || pending[0].Event.Method != "unsupported" ||
		pending[0].Event.Decision != "failed" {
		t.Fatalf("record=%+v pending=%+v err=%v", record, pending, err)
	}
}

func TestDefinitiveParentRetainsTurnUntilExpiredChildCancellationReceiptCommits(t *testing.T) {
	fixture, gateway, sampling := newSamplingGatewayFixture(t)
	effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-terminal-parent-child")
	now := time.Unix(1_800_000_000, 0)
	fixture.repository.now = func() time.Time { return now }
	claimed, err := fixture.repository.ClaimServerRequest(context.Background(), ServerRequestClaimRequest{
		CurrentScope: effect.Scope, Parent: effect, ProviderRequestID: "rpc-terminal-parent-child",
		ConnectionGeneration: connectionGenerationForEffect(effect), RequestID: "sampling-terminal-parent-child",
		Method: string(ServerRequestSampling), RequestDigest: sha256.Sum256([]byte("sampling-terminal-parent-child")),
		ChildEffectID: mustID(t, identity.Effect), ChildInvocationID: mustID(t, identity.Invocation),
		BrokerCancellationRequired: true,
		MaxRequests:                testBounds().MaxEvents, Lease: testBounds().CancelTimeout,
	})
	if err != nil || !claimed.Fresh {
		t.Fatalf("claim=%+v err=%v", claimed, err)
	}
	now = now.Add(testBounds().CancelTimeout + time.Nanosecond)
	failed, err := gateway.Apply(effect, Event{
		ExpectedRevision: effect.Revision, Kind: EventRecoveryObserved,
		Ledger: LedgerRecord{
			InvocationID: effect.Scope.InvocationID, RequestDigest: effect.RequestDigest,
			Status: LedgerFailed, ProviderRequestID: "rpc-terminal-parent-child", FailureReason: "external failure",
		},
	})
	if err != nil || failed.Effect.State != StateFailed {
		t.Fatalf("failed transition=%+v err=%v", failed, err)
	}
	stored, err := fixture.repository.Commit(context.Background(), TransitionCommitRequest{
		ExpectedRevision: effect.Revision, CurrentScope: effect.Scope, Previous: effect, Next: failed.Effect,
	})
	if err != nil || stored.Effect.State != StateFailed {
		t.Fatalf("terminal parent commit=%+v err=%v", stored, err)
	}

	nextCall := CallRequest{ServerID: effect.ServerID, ToolName: effect.ToolName, Input: mapInput("after-child")}
	nextDigest, err := CallRequestDigest(nextCall, testBounds())
	if err != nil {
		t.Fatal(err)
	}
	nextRequest := AdmissionRequest{
		Authority: OpaqueAuthority("turn-secret"), EffectID: mustID(t, identity.Effect),
		InvocationID: mustID(t, identity.Invocation), RequestDigest: nextDigest, Call: nextCall,
	}
	_, err = gateway.Admit(context.Background(), nextRequest)
	if !errors.Is(err, ErrEffectInFlight) {
		t.Fatalf("terminal parent released turn before child cancellation receipt: %v", err)
	}

	recovered, err := gateway.Recover(context.Background(), OpaqueAuthority("renewed"), failed.Effect)
	if err != nil || recovered.Effect.State != StateFailed || sampling.cancelCalls != 1 {
		t.Fatalf("terminal child reconciliation=%+v child-cancels=%d err=%v", recovered, sampling.cancelCalls, err)
	}
	fixture.repository.mu.RLock()
	record := fixture.repository.serverRequests[serverRequestKey{
		invocation: effect.Scope.InvocationID, providerRequestID: "rpc-terminal-parent-child",
		connectionGeneration: connectionGenerationForEffect(effect), requestID: "sampling-terminal-parent-child",
	}]
	_, pending := fixture.repository.serverRequestReconciliations[effect.Scope.InvocationID.String()]
	fixture.repository.mu.RUnlock()
	if pending || record.ChildCancellation == (SamplingCancellationReceipt{}) {
		t.Fatalf("child cancellation receipt not durably consumed: pending=%t record=%+v", pending, record)
	}
	admitted, err := gateway.Admit(context.Background(), nextRequest)
	if err != nil || admitted.State != StateAdmitted {
		t.Fatalf("turn was not released after child cancellation receipt: effect=%+v err=%v", admitted, err)
	}
}

func TestUniqueServerRequestsAreBoundedAndLimitBreachFencesParentOnce(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-server-request-limit")
	fixture.gateway.bounds.MaxEvents = 8
	for index := 0; index < int(fixture.gateway.bounds.MaxEvents); index++ {
		response, err := fixture.gateway.HandleServerRequest(context.Background(), ServerRequest{
			Authority: OpaqueAuthority("renewed"), Effect: effect, RequestID: fmt.Sprintf("bounded-%d", index),
			ProviderRequestID: "rpc-server-request-limit", ConnectionGeneration: connectionGenerationForEffect(effect),
			Method: "resources/read", Params: canonical.Map{"index": int64(index)},
		})
		if err != nil || response.Error == nil || response.Error.Code != jsonRPCMethodNotFound {
			t.Fatalf("request %d response=%+v err=%v", index, response, err)
		}
	}
	_, err := fixture.gateway.HandleServerRequest(context.Background(), ServerRequest{
		Authority: OpaqueAuthority("renewed"), Effect: effect, RequestID: "over-limit",
		ProviderRequestID: "rpc-server-request-limit", ConnectionGeneration: connectionGenerationForEffect(effect),
		Method: "resources/read", Params: canonical.Map{"index": int64(8)},
	})
	if !errors.Is(err, ErrEventLimit) {
		t.Fatalf("over-limit request error=%v, want %v", err, ErrEventLimit)
	}
	fixture.repository.mu.RLock()
	records := len(fixture.repository.serverRequests)
	auditSequence := fixture.repository.auditSequence
	_, fenced := fixture.repository.parentCancellationRequired[effect.Scope.InvocationID.String()]
	fixture.repository.mu.RUnlock()
	if records != int(fixture.gateway.bounds.MaxEvents) || auditSequence != uint64(fixture.gateway.bounds.MaxEvents)+1 || !fenced {
		t.Fatalf("records=%d audit-sequence=%d fenced=%t", records, auditSequence, fenced)
	}
	_, err = fixture.gateway.HandleServerRequest(context.Background(), ServerRequest{
		Authority: OpaqueAuthority("renewed"), Effect: effect, RequestID: "over-limit-again",
		ProviderRequestID: "rpc-server-request-limit", ConnectionGeneration: connectionGenerationForEffect(effect),
		Method: "resources/read", Params: canonical.Map{"index": int64(9)},
	})
	if !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("request after durable limit fence error=%v", err)
	}
	_, err = fixture.gateway.HandleServerRequest(context.Background(), ServerRequest{
		Authority: OpaqueAuthority("renewed"), Effect: effect, RequestID: "oversized-after-limit",
		ProviderRequestID: "rpc-server-request-limit", ConnectionGeneration: connectionGenerationForEffect(effect),
		Method: "resources/read", Params: canonical.Bytes(make([]byte, testBounds().MaxInputBytes+1)),
	})
	if !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("oversized request bypassed durable limit fence: %v", err)
	}
	fixture.repository.mu.RLock()
	defer fixture.repository.mu.RUnlock()
	if len(fixture.repository.serverRequests) != records || fixture.repository.auditSequence != auditSequence {
		t.Fatalf("repeated breach grew durable state: records=%d audit-sequence=%d",
			len(fixture.repository.serverRequests), fixture.repository.auditSequence)
	}
}

func TestCompletedServerRequestReplayDoesNotConsumeAnotherQuotaSlot(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-server-request-replay-limit")
	claim := ServerRequestClaimRequest{
		CurrentScope: effect.Scope, Parent: effect, ProviderRequestID: "rpc-server-request-replay-limit",
		ConnectionGeneration: connectionGenerationForEffect(effect), RequestID: "replayed-request",
		Method: "resources/read", RequestDigest: sha256.Sum256([]byte("replayed-request")),
		MaxRequests: 1, Lease: testBounds().CancelTimeout,
	}
	claimed, err := fixture.repository.ClaimServerRequest(context.Background(), claim)
	if err != nil || !claimed.Fresh {
		t.Fatalf("initial claim=%+v err=%v", claimed, err)
	}
	completed, err := fixture.repository.CompleteServerRequest(context.Background(), ServerRequestCommitRequest{
		CurrentScope: effect.Scope, Permit: claimed.Record.Permit,
		Response: ServerResponse{RequestID: claim.RequestID, ResultCanonical: []byte(`{"ok":true}`)},
		Audit: &AuditEvent{
			TenantID: effect.Scope.TenantID, UserID: effect.Scope.UserID, SessionID: effect.Scope.SessionID,
			TurnID: effect.Scope.TurnID, InvocationID: effect.Scope.InvocationID, ServerID: effect.ServerID,
			Method: "unsupported", Decision: "denied", Reason: "method not allowed",
		},
	})
	if err != nil || !completed.Fresh {
		t.Fatalf("completion=%+v err=%v", completed, err)
	}
	replayed, err := fixture.repository.ClaimServerRequest(context.Background(), claim)
	if err != nil || replayed.Fresh || replayed.Record.State != ServerRequestCompleted {
		t.Fatalf("completed replay=%+v err=%v", replayed, err)
	}
	second := claim
	second.RequestID = "second-request"
	second.RequestDigest = sha256.Sum256([]byte("second-request"))
	_, err = fixture.repository.ClaimServerRequest(context.Background(), second)
	if !errors.Is(err, ErrEventLimit) {
		t.Fatalf("fresh request after replay error=%v, want %v", err, ErrEventLimit)
	}
	fixture.repository.mu.RLock()
	count := fixture.repository.serverRequestCounts[effect.Scope.InvocationID.String()]
	records := len(fixture.repository.serverRequests)
	fixture.repository.mu.RUnlock()
	if count != 1 || records != 1 {
		t.Fatalf("replay consumed quota: count=%d records=%d", count, records)
	}
}

func TestConcurrentBoundaryServerRequestClaimsHaveOneWinnerAndOneDurableLimitFence(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-server-request-concurrent-limit")
	claim := func(requestID string) ServerRequestClaimRequest {
		return ServerRequestClaimRequest{
			CurrentScope: effect.Scope, Parent: effect, ProviderRequestID: "rpc-server-request-concurrent-limit",
			ConnectionGeneration: connectionGenerationForEffect(effect), RequestID: requestID,
			Method: "resources/read", RequestDigest: sha256.Sum256([]byte(requestID)),
			MaxRequests: 1, Lease: testBounds().CancelTimeout,
		}
	}
	type claimResult struct {
		stored StoredServerRequest
		err    error
	}
	start := make(chan struct{})
	results := make(chan claimResult, 2)
	for _, requestID := range []string{"boundary-a", "boundary-b"} {
		requestID := requestID
		go func() {
			<-start
			stored, err := fixture.repository.ClaimServerRequest(context.Background(), claim(requestID))
			results <- claimResult{stored: stored, err: err}
		}()
	}
	close(start)
	fresh := 0
	limited := 0
	for range 2 {
		result := <-results
		if result.err == nil && result.stored.Fresh {
			fresh++
		} else if errors.Is(result.err, ErrEventLimit) {
			limited++
		} else {
			t.Fatalf("unexpected concurrent claim result=%+v err=%v", result.stored, result.err)
		}
	}
	fixture.repository.mu.RLock()
	count := fixture.repository.serverRequestCounts[effect.Scope.InvocationID.String()]
	records := len(fixture.repository.serverRequests)
	auditSequence := fixture.repository.auditSequence
	_, fenced := fixture.repository.parentCancellationRequired[effect.Scope.InvocationID.String()]
	fixture.repository.mu.RUnlock()
	if fresh != 1 || limited != 1 || count != 1 || records != 1 || auditSequence != 1 || !fenced {
		t.Fatalf("fresh=%d limited=%d count=%d records=%d audits=%d fenced=%t",
			fresh, limited, count, records, auditSequence, fenced)
	}
}

func TestRootsAreRestrictedToWorkspaceProjection(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	server := fixture.server
	server.AllowedServerRequests = []ServerRequestMethod{ServerRequestRoots}
	repository := NewMemoryRepository()
	gateway, err := NewGateway(Configuration{
		Bounds: testBounds(), Servers: []ServerRegistration{server}, Tools: []ToolRegistration{fixture.tool}, AllowReferenceMemory: true,
	}, Dependencies{
		Authority: fixture.authority, Authorizer: fixture.authorizer, Credentials: fixture.credentials,
		Repository: repository, Audit: &auditStub{}, Providers: map[string]Provider{"stdio": fixture.provider},
		Roots: rootsStub{roots: []string{"/workspace", "/workspace/repository", "/etc"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.gateway = gateway
	fixture.repository = repository
	effect := durablyDispatchedFixtureEffect(t, fixture, "rpc-roots")
	response, err := gateway.HandleServerRequest(context.Background(), ServerRequest{
		Authority: OpaqueAuthority("renewed-turn-secret"), Effect: effect, RequestID: "roots-1",
		ProviderRequestID: "rpc-roots", ConnectionGeneration: connectionGenerationForEffect(effect), Method: string(ServerRequestRoots), Params: canonical.Map{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.Error == nil || response.Error.Code != -32603 || response.ResultCanonical != nil {
		t.Fatalf("root projection escape response = %+v", response)
	}
}

func TestWorkspaceRootURIsAreCanonicalAndEscapeEncodedTraversal(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	encoded, err := fixture.gateway.workspaceRootsValue([]string{"/workspace/%2e%2e/etc"})
	if err != nil {
		t.Fatal(err)
	}
	encodedMap := encoded.(canonical.Map)
	encodedRoots := encodedMap["roots"].(canonical.Array)
	if got := encodedRoots[0].(canonical.Map)["uri"]; got != "file:///workspace/%252e%252e/etc" {
		t.Fatalf("encoded traversal root URI=%#v", got)
	}
	value, err := fixture.gateway.workspaceRootsValue([]string{"/workspace/name#fragment?query"})
	if err != nil {
		t.Fatal(err)
	}
	rootMap, ok := value.(canonical.Map)
	if !ok {
		t.Fatalf("roots value type=%T", value)
	}
	roots, ok := rootMap["roots"].(canonical.Array)
	if !ok || len(roots) != 1 {
		t.Fatalf("roots=%#v", rootMap["roots"])
	}
	entry, ok := roots[0].(canonical.Map)
	if !ok || entry["uri"] != "file:///workspace/name%23fragment%3Fquery" {
		t.Fatalf("root URI=%#v", roots[0])
	}
}

func TestToolListFilteringNeverExposesUnregisteredOrRevokedTools(t *testing.T) {
	fixture := newGatewayFixture(t, ReplaySafe)
	effect := admitFixtureEffect(t, fixture)
	visible, err := fixture.gateway.FilterAdvertisedTools(context.Background(), ToolListRequest{
		Authority: OpaqueAuthority("turn-secret"), EffectID: effect.Scope.EffectID,
		InvocationID: effect.Scope.InvocationID, RequestDigest: effect.RequestDigest,
		ServerID:   effect.ServerID,
		Advertised: []string{"organization.admin", effect.ToolName, "repository.delete"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(visible) != 1 || visible[0] != effect.ToolName {
		t.Fatalf("visible tools = %v", visible)
	}

	fixture.authorizer.setDenied(true)
	visible, err = fixture.gateway.FilterAdvertisedTools(context.Background(), ToolListRequest{
		Authority: OpaqueAuthority("turn-secret"), EffectID: effect.Scope.EffectID,
		InvocationID: effect.Scope.InvocationID, RequestDigest: effect.RequestDigest,
		ServerID: effect.ServerID, Advertised: []string{effect.ToolName},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(visible) != 0 {
		t.Fatalf("revoked tool remained visible after list refresh: %v", visible)
	}
}

func durablyDispatchedFixtureEffect(t *testing.T, fixture gatewayFixture, providerRequestID string) Effect {
	t.Helper()
	effect := admitFixtureEffect(t, fixture)
	begin := applyFixtureEvent(t, fixture.gateway, effect, Event{Kind: EventBeginDispatch})
	dispatch, err := fixture.repository.CommitAndClaimDispatch(context.Background(), DispatchClaimRequest{
		ExpectedRevision: effect.Revision, CurrentScope: effect.Scope, Previous: effect,
		Next: begin, Authorization: permitForEffect(begin),
	})
	if err != nil {
		t.Fatal(err)
	}
	negotiated := negotiateFixtureEffect(t, fixture.gateway, begin)
	persistFixtureEffect(t, fixture.repository, begin, negotiated)
	start, err := fixture.repository.ClaimProviderStart(context.Background(), ProviderStartClaimRequest{
		CurrentScope: effect.Scope, Effect: negotiated, Dispatch: dispatch, Lease: testBounds().CancelTimeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	accepted := applyFixtureEvent(t, fixture.gateway, negotiated, Event{
		Kind: EventProviderAccepted, ProviderRequestID: providerRequestID,
	})
	stored, err := fixture.repository.Commit(context.Background(), TransitionCommitRequest{
		ExpectedRevision: negotiated.Revision, CurrentScope: effect.Scope, Previous: negotiated,
		Next: accepted, ProviderStart: &start,
	})
	if err != nil || !stored.Durable || !sameEffect(stored.Effect, accepted) {
		t.Fatalf("provider acceptance commit=%+v err=%v", stored, err)
	}
	return accepted
}

func newSamplingGatewayFixture(t *testing.T) (gatewayFixture, *Gateway, *samplingStub) {
	t.Helper()
	fixture := newGatewayFixture(t, ReplayNever)
	sampling := &samplingStub{result: SamplingResult{
		Value: canonical.Map{"role": "assistant", "content": "approved"}, Durable: true,
	}}
	server := fixture.server
	server.AllowedServerRequests = []ServerRequestMethod{ServerRequestSampling}
	repository := NewMemoryRepository()
	gateway, err := NewGateway(Configuration{
		Bounds: testBounds(), Servers: []ServerRegistration{server}, Tools: []ToolRegistration{fixture.tool}, AllowReferenceMemory: true,
	}, Dependencies{
		Authority: fixture.authority, Authorizer: fixture.authorizer, Credentials: fixture.credentials,
		Repository: repository, Audit: &auditStub{}, Providers: map[string]Provider{"stdio": fixture.provider}, Sampling: sampling,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.gateway = gateway
	fixture.repository = repository
	return fixture, gateway, sampling
}
