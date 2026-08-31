package stateappadapter

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/dependency"
	dependencycontract "github.com/hancomac/circulusd/internal/dependency/contracttest"
	"github.com/hancomac/circulusd/internal/identity"
	"github.com/hancomac/circulusd/internal/stateappclient"
)

type recordingDispatchStartClient struct {
	mu       sync.Mutex
	requests []stateappclient.ClaimDispatchStartRequest
	claim    func(context.Context, stateappclient.ClaimDispatchStartRequest) (stateappclient.ClaimDispatchStartResult, error)
	probe    func(context.Context, dependency.ProbeChallenge) (dependency.ProbeResponse, error)
}

func (client *recordingDispatchStartClient) ClaimDispatchStart(
	ctx context.Context,
	request stateappclient.ClaimDispatchStartRequest,
) (stateappclient.ClaimDispatchStartResult, error) {
	client.mu.Lock()
	client.requests = append(client.requests, request)
	client.mu.Unlock()
	return client.claim(ctx, request)
}

func (client *recordingDispatchStartClient) ProbeProduction(
	ctx context.Context,
	challenge dependency.ProbeChallenge,
) (dependency.ProbeResponse, error) {
	return client.probe(ctx, challenge)
}

func (client *recordingDispatchStartClient) requestsSnapshot() []stateappclient.ClaimDispatchStartRequest {
	client.mu.Lock()
	defer client.mu.Unlock()
	return append([]stateappclient.ClaimDispatchStartRequest(nil), client.requests...)
}

func TestDispatchStartClaimerForwardsProductionProbeToItsOperationalClient(t *testing.T) {
	t.Parallel()

	var _ dependency.ProductionProbe = (*DispatchStartClaimer)(nil)
	challenge := dependency.ProbeChallenge{Nonce: make([]byte, dependency.ChallengeBytes)}
	challenge.Nonce[0] = 0x72
	want := dependency.ProbeResponse{
		Descriptor: dependency.Descriptor{
			InstanceID: "dispatch-state-instance",
			AtomicGroups: []dependency.AtomicGroup{
				dependency.AtomicCommandReceipt,
				dependency.AtomicEffectLifecycle,
			},
		},
		KeyID:     "dispatch-runtime-key",
		Signature: []byte{0x44, 0x55, 0x66},
	}
	ctx := context.WithValue(context.Background(), struct{ name string }{"dispatch-probe"}, "exact-context")
	probeErr := errors.New("probe sentinel")
	probeCalls := 0
	client := &recordingDispatchStartClient{
		claim: func(
			context.Context,
			stateappclient.ClaimDispatchStartRequest,
		) (stateappclient.ClaimDispatchStartResult, error) {
			return stateappclient.ClaimDispatchStartResult{}, nil
		},
		probe: func(gotContext context.Context, gotChallenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
			probeCalls++
			if gotContext != ctx || !reflect.DeepEqual(gotChallenge, challenge) {
				t.Fatalf("forwarded probe context/challenge = (%v, %#v), want exact inputs", gotContext, gotChallenge)
			}
			return want, probeErr
		},
	}
	claimer := &DispatchStartClaimer{client: client}

	got, err := claimer.ProbeProduction(ctx, challenge)
	if probeCalls != 1 || !reflect.DeepEqual(got, want) || !errors.Is(err, probeErr) {
		t.Fatalf("ProbeProduction() calls/response/error = %d/%#v/%v, want 1/%#v/%v", probeCalls, got, err, want, probeErr)
	}
}

func TestDispatchStartClaimerProductionProbeRejectsNilReceiverAndClient(t *testing.T) {
	t.Parallel()

	challenge := dependency.ProbeChallenge{Nonce: make([]byte, dependency.ChallengeBytes)}
	var nilClaimer *DispatchStartClaimer
	if response, err := nilClaimer.ProbeProduction(context.Background(), challenge); !reflect.DeepEqual(response, dependency.ProbeResponse{}) ||
		!errors.Is(err, dependency.ErrInvalidConfiguration) {
		t.Fatalf("nil claimer ProbeProduction() = (%#v, %v), want zero/ErrInvalidConfiguration", response, err)
	}
	if response, err := (&DispatchStartClaimer{}).ProbeProduction(context.Background(), challenge); !reflect.DeepEqual(response, dependency.ProbeResponse{}) ||
		!errors.Is(err, dependency.ErrInvalidConfiguration) {
		t.Fatalf("nil client ProbeProduction() = (%#v, %v), want zero/ErrInvalidConfiguration", response, err)
	}
	var nilClient *recordingDispatchStartClient
	claimer := &DispatchStartClaimer{client: nilClient}
	if response, err := claimer.ProbeProduction(context.Background(), challenge); !reflect.DeepEqual(response, dependency.ProbeResponse{}) ||
		!errors.Is(err, dependency.ErrInvalidConfiguration) {
		t.Fatalf("typed nil client ProbeProduction() = (%#v, %v), want zero/ErrInvalidConfiguration", response, err)
	}
}

type adapterTestDispatchStarter struct {
	mu          sync.Mutex
	routeDigest broker.Digest
	calls       int
}

func (starter *adapterTestDispatchStarter) RouteDigest() broker.Digest {
	return starter.routeDigest
}

func (starter *adapterTestDispatchStarter) Start(context.Context, broker.DispatchStartPermit) error {
	starter.mu.Lock()
	defer starter.mu.Unlock()
	starter.calls++
	return nil
}

func TestDispatchStartClaimerMapsExactFreshAndReplayReceipts(t *testing.T) {
	t.Parallel()
	request := validBrokerDispatchStartRequest(t, 1)
	var calls int
	client := &recordingDispatchStartClient{claim: func(
		_ context.Context,
		wire stateappclient.ClaimDispatchStartRequest,
	) (stateappclient.ClaimDispatchStartResult, error) {
		calls++
		result := validClientDispatchStartResult(wire, calls == 1, calls != 1)
		result.Permit.ClaimedEventSequence += 2
		result.Version += 2
		return result, nil
	}}
	claimer := &DispatchStartClaimer{client: client}

	fresh, err := claimer.ClaimDispatchStart(context.Background(), request)
	if err != nil {
		t.Fatalf("ClaimDispatchStart(fresh) error = %v", err)
	}
	replay, err := claimer.ClaimDispatchStart(context.Background(), request)
	if err != nil {
		t.Fatalf("ClaimDispatchStart(replay) error = %v", err)
	}
	if !fresh.Fresh || replay.Fresh || fresh.Permit.Dispatch != request.Dispatch ||
		replay.Permit.Dispatch != request.Dispatch || fresh.Permit.CommandDigest != request.CommandDigest ||
		fresh.Permit.EventSequence != request.Dispatch.EventSequence+3 || !fresh.Permit.Durable ||
		fresh.Permit.Opaque == "" || replay.Permit.Opaque != fresh.Permit.Opaque {
		t.Fatalf("fresh/replay claims = %#v / %#v", fresh, replay)
	}

	requests := client.requestsSnapshot()
	if len(requests) != 2 || requests[0] != requests[1] || requests[0].CommandID == "" {
		t.Fatalf("wire requests = %#v; want two identical deterministic commands", requests)
	}
	wire := requests[0]
	if wire.TenantID != request.Dispatch.TenantID.String() ||
		wire.WorkspaceID != request.Dispatch.WorkspaceID.String() ||
		wire.SessionID != request.Dispatch.SessionID.String() ||
		wire.ExpectedEventSequence != request.Dispatch.EventSequence ||
		wire.TurnID != request.Dispatch.TurnID.String() ||
		wire.EffectID != request.Dispatch.EffectID.String() ||
		wire.InvocationID != request.Dispatch.InvocationID.String() ||
		wire.DispatchAttempt != request.Dispatch.DispatchAttempt ||
		wire.ProviderRequestID != request.Dispatch.ProviderRequestID.String() ||
		wire.DispatchPermitClaims.UserID != request.Dispatch.UserID.String() ||
		wire.DispatchPermitClaims.DeadlineUnixMS != uint64(request.Dispatch.Deadline.UnixMilli()) {
		t.Fatalf("wire request did not preserve the dispatch proof: %#v", wire)
	}
}

func TestDispatchStartClaimerResponseLossAndReplayNeverStartProvider(t *testing.T) {
	t.Parallel()
	request := validBrokerDispatchStartRequest(t, 2)
	groups := []dependency.AtomicGroup{
		dependency.AtomicCommandReceipt,
		dependency.AtomicEffectLifecycle,
	}
	proofs := dependencycontract.NewProductionProofs(t, groups)
	var mu sync.Mutex
	calls := 0
	commandID := ""
	client := &recordingDispatchStartClient{
		claim: func(
			_ context.Context,
			wire stateappclient.ClaimDispatchStartRequest,
		) (stateappclient.ClaimDispatchStartResult, error) {
			mu.Lock()
			defer mu.Unlock()
			calls++
			if commandID == "" {
				commandID = wire.CommandID
			}
			if wire.CommandID != commandID {
				return stateappclient.ClaimDispatchStartResult{}, errors.New("command identity changed after response loss")
			}
			if calls == 1 {
				return stateappclient.ClaimDispatchStartResult{}, stateappclient.ErrTransport
			}
			return validClientDispatchStartResult(wire, false, true), nil
		},
		probe: proofs.ProbeProduction,
	}
	claimer := &DispatchStartClaimer{client: client}
	candidate := broker.DispatchStartClaimer(claimer)
	verified := dependencycontract.Verify(t, proofs, candidate, groups)
	opened, _, err := verified.Open()
	if err != nil || opened != claimer {
		t.Fatalf("verified.Open() = (%#v, %v), want exact claimer %p", opened, err, claimer)
	}
	starter := &adapterTestDispatchStarter{routeDigest: request.Dispatch.ProviderRouteDigest}
	consumer, err := broker.NewDispatchConsumer(
		verified,
		map[broker.EffectService]broker.DispatchStarter{request.Dispatch.Service: starter},
		time.Second,
	)
	if err != nil {
		t.Fatalf("NewDispatchConsumer() error = %v", err)
	}

	if execution, startErr := consumer.StartExactAttempt(context.Background(), request); !errors.Is(startErr, stateappclient.ErrTransport) || execution != (broker.DispatchStartExecution{}) {
		t.Fatalf("lost response StartExactAttempt() = %#v, %v", execution, startErr)
	}
	execution, startErr := consumer.StartExactAttempt(context.Background(), request)
	if !errors.Is(startErr, broker.ErrDispatchAlreadyStarted) || execution.Claim.Fresh || execution.Outcome != broker.DispatchStartOutcomeUnknown {
		t.Fatalf("replay StartExactAttempt() = %#v, %v", execution, startErr)
	}
	starter.mu.Lock()
	startCalls := starter.calls
	starter.mu.Unlock()
	if startCalls != 0 {
		t.Fatalf("provider starts = %d, want 0", startCalls)
	}
}

func TestConcurrentDispatchStartClaimersExposeOneFreshReceiptAndOneCommandIdentity(t *testing.T) {
	t.Parallel()
	request := validBrokerDispatchStartRequest(t, 3)
	var mu sync.Mutex
	transitions := 0
	client := &recordingDispatchStartClient{claim: func(
		_ context.Context,
		wire stateappclient.ClaimDispatchStartRequest,
	) (stateappclient.ClaimDispatchStartResult, error) {
		mu.Lock()
		defer mu.Unlock()
		fresh := transitions == 0
		if fresh {
			transitions++
		}
		return validClientDispatchStartResult(wire, fresh, !fresh), nil
	}}
	claimers := []*DispatchStartClaimer{{client: client}, {client: client}}

	const callers = 64
	results := make(chan broker.DispatchStartClaim, callers)
	errorsSeen := make(chan error, callers)
	var wait sync.WaitGroup
	for index := range callers {
		wait.Add(1)
		go func(claimer *DispatchStartClaimer) {
			defer wait.Done()
			claim, err := claimer.ClaimDispatchStart(context.Background(), request)
			results <- claim
			errorsSeen <- err
		}(claimers[index%len(claimers)])
	}
	wait.Wait()
	close(results)
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatalf("concurrent ClaimDispatchStart() error = %v", err)
		}
	}
	freshCount := 0
	var opaque broker.OpaquePermit
	for claim := range results {
		if claim.Fresh {
			freshCount++
		}
		if opaque == "" {
			opaque = claim.Permit.Opaque
		}
		if claim.Permit.Opaque != opaque || claim.Permit.EventSequence != request.Dispatch.EventSequence+1 {
			t.Fatalf("non-exact concurrent claim = %#v", claim)
		}
	}
	requests := client.requestsSnapshot()
	commandIDs := make(map[string]struct{}, len(requests))
	for _, wire := range requests {
		commandIDs[wire.CommandID] = struct{}{}
	}
	if freshCount != 1 || transitions != 1 || len(requests) != callers || len(commandIDs) != 1 {
		t.Fatalf("fresh/transitions/requests/commandIDs = %d/%d/%d/%d", freshCount, transitions, len(requests), len(commandIDs))
	}
}

func TestDispatchStartClaimerRejectsInvalidBrokerProofBeforeIngress(t *testing.T) {
	t.Parallel()
	base := validBrokerDispatchStartRequest(t, 4)
	differentWorkspace, err := identity.Parse(identity.Workspace, validTestID("ws", 40))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		edit func(*broker.DispatchStartRequest)
	}{
		{name: "zero time", edit: func(value *broker.DispatchStartRequest) { value.Now = time.Time{} }},
		{name: "expired authority", edit: func(value *broker.DispatchStartRequest) { value.Now = value.Authority.ExpiresAt }},
		{name: "workspace relabel", edit: func(value *broker.DispatchStartRequest) { value.Authority.WorkspaceID = differentWorkspace }},
		{name: "generation relabel", edit: func(value *broker.DispatchStartRequest) { value.Authority.Generations.Authorization++ }},
		{name: "volatile dispatch", edit: func(value *broker.DispatchStartRequest) { value.Dispatch.Durable = false }},
		{name: "missing opaque dispatch", edit: func(value *broker.DispatchStartRequest) { value.Dispatch.Opaque = "" }},
		{name: "missing dispatch event", edit: func(value *broker.DispatchStartRequest) { value.Dispatch.EventSequence = 0 }},
		{name: "missing user", edit: func(value *broker.DispatchStartRequest) { value.Dispatch.UserID = identity.ID{} }},
		{name: "unsupported service", edit: func(value *broker.DispatchStartRequest) { value.Dispatch.Service = "database" }},
		{name: "unsupported replay", edit: func(value *broker.DispatchStartRequest) { value.Dispatch.ReplayPolicy = "sometimes" }},
		{name: "zero request digest", edit: func(value *broker.DispatchStartRequest) { value.Dispatch.RequestDigest = broker.Digest{} }},
		{name: "zero command digest", edit: func(value *broker.DispatchStartRequest) { value.CommandDigest = broker.Digest{} }},
		{name: "expired dispatch", edit: func(value *broker.DispatchStartRequest) { value.Dispatch.Deadline = value.Now }},
		{name: "sub-millisecond deadline", edit: func(value *broker.DispatchStartRequest) {
			value.Dispatch.Deadline = value.Dispatch.Deadline.Add(time.Nanosecond)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := base
			test.edit(&request)
			client := &recordingDispatchStartClient{claim: func(context.Context, stateappclient.ClaimDispatchStartRequest) (stateappclient.ClaimDispatchStartResult, error) {
				t.Fatal("invalid broker proof reached state-app")
				return stateappclient.ClaimDispatchStartResult{}, nil
			}}
			if claim, claimErr := (&DispatchStartClaimer{client: client}).ClaimDispatchStart(context.Background(), request); claimErr == nil || claim != (broker.DispatchStartClaim{}) {
				t.Fatalf("ClaimDispatchStart() = %#v, %v; want rejection", claim, claimErr)
			}
			if calls := len(client.requestsSnapshot()); calls != 0 {
				t.Fatalf("invalid proof ingress calls = %d", calls)
			}
		})
	}
}

func TestDispatchStartClaimerRejectsRelabelledOrImpossibleResults(t *testing.T) {
	t.Parallel()
	base := validBrokerDispatchStartRequest(t, 5)
	tests := []struct {
		name string
		edit func(*stateappclient.ClaimDispatchStartResult)
	}{
		{name: "fresh host replay", edit: func(value *stateappclient.ClaimDispatchStartResult) { value.HostReplayed = true }},
		{name: "nonfresh without replay", edit: func(value *stateappclient.ClaimDispatchStartResult) { value.OutcomeFresh = false }},
		{name: "effect relabel", edit: func(value *stateappclient.ClaimDispatchStartResult) { value.EffectID = validTestID("effect", 50) }},
		{name: "tenant relabel", edit: func(value *stateappclient.ClaimDispatchStartResult) {
			value.Permit.DispatchPermitClaims.TenantID = validTestID("tenant", 50)
		}},
		{name: "provider relabel", edit: func(value *stateappclient.ClaimDispatchStartResult) {
			value.Permit.ProviderRequestID = validTestID("req", 50)
		}},
		{name: "command relabel", edit: func(value *stateappclient.ClaimDispatchStartResult) {
			value.Permit.CommandDigest = fmt.Sprintf("sha256:%064x", 50)
		}},
		{name: "wrong claim sequence", edit: func(value *stateappclient.ClaimDispatchStartResult) { value.Permit.ClaimedEventSequence-- }},
		{name: "version precedes claim", edit: func(value *stateappclient.ClaimDispatchStartResult) {
			value.Version = value.Permit.ClaimedEventSequence - 1
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &recordingDispatchStartClient{claim: func(
				_ context.Context,
				wire stateappclient.ClaimDispatchStartRequest,
			) (stateappclient.ClaimDispatchStartResult, error) {
				result := validClientDispatchStartResult(wire, true, false)
				test.edit(&result)
				return result, nil
			}}
			claim, err := (&DispatchStartClaimer{client: client}).ClaimDispatchStart(context.Background(), base)
			if !errors.Is(err, broker.ErrFenceMismatch) || claim != (broker.DispatchStartClaim{}) {
				t.Fatalf("ClaimDispatchStart() = %#v, %v; want fence mismatch", claim, err)
			}
		})
	}
}

func TestDispatchStartClaimerMapsOnlyStableRemoteStateErrors(t *testing.T) {
	t.Parallel()
	request := validBrokerDispatchStartRequest(t, 6)
	tests := []struct {
		code string
		want error
	}{
		{code: "INVALID_ARGUMENT", want: broker.ErrInvalidRequest},
		{code: "NOT_FOUND", want: broker.ErrInvalidEffectState},
		{code: "FAILED_PRECONDITION", want: broker.ErrInvalidEffectState},
		{code: "ABORTED", want: broker.ErrInvalidEffectState},
		{code: "STALE_GENERATION", want: broker.ErrStaleGeneration},
		{code: "STALE_DISPATCH_ATTEMPT", want: broker.ErrFenceMismatch},
		{code: "DIGEST_MISMATCH", want: broker.ErrFenceMismatch},
		{code: "IDEMPOTENCY_CONFLICT", want: broker.ErrIdempotencyConflict},
	}
	for _, test := range tests {
		t.Run(test.code, func(t *testing.T) {
			remote := &stateappclient.RemoteError{Code: test.code, Status: 400}
			client := &recordingDispatchStartClient{claim: func(context.Context, stateappclient.ClaimDispatchStartRequest) (stateappclient.ClaimDispatchStartResult, error) {
				return stateappclient.ClaimDispatchStartResult{}, remote
			}}
			claim, err := (&DispatchStartClaimer{client: client}).ClaimDispatchStart(context.Background(), request)
			if !errors.Is(err, test.want) || !errors.Is(err, stateappclient.ErrRemote) || claim != (broker.DispatchStartClaim{}) {
				t.Fatalf("ClaimDispatchStart() = %#v, %v; want %v wrapping remote", claim, err, test.want)
			}
		})
	}
}

func TestNewDispatchStartClaimerRejectsNilClient(t *testing.T) {
	t.Parallel()
	if claimer, err := NewDispatchStartClaimer(nil); claimer != nil || !errors.Is(err, broker.ErrInvalidRequest) {
		t.Fatalf("NewDispatchStartClaimer(nil) = %#v, %v", claimer, err)
	}
}

func validBrokerDispatchStartRequest(t *testing.T, index uint64) broker.DispatchStartRequest {
	t.Helper()
	ids := make(map[identity.Kind]identity.ID, 8)
	for _, kind := range []identity.Kind{
		identity.Tenant, identity.Workspace, identity.Subject, identity.Session,
		identity.Turn, identity.Effect, identity.Invocation, identity.Request,
	} {
		parsed, err := identity.Parse(kind, validTestID(string(kind), index))
		if err != nil {
			t.Fatalf("parse %s ID: %v", kind, err)
		}
		ids[kind] = parsed
	}
	now := time.UnixMilli(1_900_000_000_000).UTC()
	generations := broker.Generations{TurnLease: 4, Placement: 5, Sandbox: 6, Authorization: 7}
	requestDigest := broker.Digest{0: 0x61}
	routeDigest := broker.Digest{0: 0x72}
	commandDigest := broker.Digest{0: 0x83}
	dispatch := broker.DispatchPermit{
		EffectKey: broker.EffectKey{
			SessionID: ids[identity.Session], TurnID: ids[identity.Turn],
			EffectID: ids[identity.Effect], InvocationID: ids[identity.Invocation],
			RequestDigest: requestDigest,
		},
		Opaque:   broker.OpaquePermit(fmt.Sprintf("dispatch-permit-%d", index)),
		TenantID: ids[identity.Tenant], WorkspaceID: ids[identity.Workspace], UserID: ids[identity.Subject],
		Service: broker.ServiceExecutor, Operation: "process.spawn", ReplayPolicy: broker.ReplayIdempotencyKey,
		Generations: generations, DispatchAttempt: 3, ProviderRequestID: ids[identity.Request],
		ProviderRouteDigest: routeDigest, Deadline: now.Add(time.Minute), EventSequence: 12, Durable: true,
	}
	return broker.DispatchStartRequest{
		Authority: broker.ValidatedTurnFence{
			TenantID: ids[identity.Tenant], WorkspaceID: ids[identity.Workspace],
			SessionID: ids[identity.Session], TurnID: ids[identity.Turn],
			Generations: generations, ExpiresAt: now.Add(30 * time.Second),
		},
		Now: now.Add(time.Millisecond), Dispatch: dispatch, CommandDigest: commandDigest,
	}
}

func validClientDispatchStartResult(
	request stateappclient.ClaimDispatchStartRequest,
	fresh bool,
	replayed bool,
) stateappclient.ClaimDispatchStartResult {
	claimedEventSequence := request.ExpectedEventSequence + 1
	return stateappclient.ClaimDispatchStartResult{
		OutcomeFresh: fresh, HostReplayed: replayed,
		Version: claimedEventSequence, EffectID: request.EffectID,
		Permit: stateappclient.DispatchStartPermit{
			DispatchPermitClaims: request.DispatchPermitClaims,
			ProviderRequestID:    request.ProviderRequestID,
			CommandDigest:        request.CommandDigest,
			ClaimedEventSequence: claimedEventSequence,
		},
	}
}
