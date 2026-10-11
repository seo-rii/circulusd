//go:build linux

package referenceworkload

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	v1connect "github.com/hancomac/circulusd/api/generated/circulus/v1alpha/circulusv1alphaconnect"
	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/controlrpc"
	"github.com/hancomac/circulusd/internal/dependency"
	dependencycontract "github.com/hancomac/circulusd/internal/dependency/contracttest"
	"github.com/hancomac/circulusd/internal/identity"
	"google.golang.org/protobuf/proto"
)

func workloadID(t testing.TB, kind identity.Kind) identity.ID {
	t.Helper()
	id, err := identity.New(kind)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func workloadDispatch(t testing.TB, route broker.Digest) broker.DispatchPermit {
	t.Helper()
	return broker.DispatchPermit{
		EffectKey: broker.EffectKey{SessionID: workloadID(t, identity.Session), TurnID: workloadID(t, identity.Turn),
			EffectID: workloadID(t, identity.Effect), InvocationID: workloadID(t, identity.Invocation), RequestDigest: broker.Digest{2}},
		Opaque: broker.OpaquePermit("dispatch-proof"), TenantID: workloadID(t, identity.Tenant),
		WorkspaceID: workloadID(t, identity.Workspace), UserID: workloadID(t, identity.Subject),
		Service: broker.ServiceExecutor, Operation: "execute", ReplayPolicy: broker.ReplayNever, Ordinal: 0,
		Generations:     broker.Generations{TurnLease: 1, Placement: 2, Sandbox: 3, Authorization: 4},
		DispatchAttempt: 1, ProviderRouteDigest: route, Deadline: time.Now().UTC().Add(time.Minute).Truncate(time.Millisecond),
		EventSequence: 3, Durable: true,
	}
}

type workloadClaimer struct {
	*dependencycontract.ProductionProofs
	mu      sync.Mutex
	claimed bool
}

func (claimer *workloadClaimer) ClaimDispatchStart(_ context.Context, request broker.DispatchStartRequest) (broker.DispatchStartClaim, error) {
	claimer.mu.Lock()
	defer claimer.mu.Unlock()
	fresh := !claimer.claimed
	claimer.claimed = true
	return broker.DispatchStartClaim{Permit: broker.DispatchStartPermit{Dispatch: request.Dispatch,
		Opaque: broker.OpaquePermit("start-proof"), CommandDigest: request.CommandDigest,
		EventSequence: request.Dispatch.EventSequence + 1, Durable: true}, Fresh: fresh}, nil
}

func workloadConsumer(t testing.TB, starter broker.DispatchStarter) *broker.DispatchConsumer {
	t.Helper()
	groups := []dependency.AtomicGroup{dependency.AtomicCommandReceipt, dependency.AtomicEffectLifecycle}
	proofs := dependencycontract.NewProductionProofs(t, groups)
	claimer := &workloadClaimer{ProductionProofs: proofs}
	verified := dependencycontract.Verify(t, proofs, broker.DispatchStartClaimer(claimer), groups)
	consumer, err := broker.NewDispatchConsumer(verified, map[broker.EffectService]broker.DispatchStarter{broker.ServiceExecutor: starter}, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return consumer
}

type workloadReturnSink struct {
	mu     sync.Mutex
	permit broker.DispatchStartPermit
	steps  []string
	result ReferenceWorkloadResult
}

func (sink *workloadReturnSink) ConfirmExternalCommit(_ context.Context, claim broker.ClaimedDispatchStart, result ReferenceWorkloadResult) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	permit, ok := claim.Open()
	if !ok || len(sink.steps) != 0 {
		return errors.New("invalid original claim or commit ordering")
	}
	sink.permit, sink.result = permit, result
	sink.steps = append(sink.steps, "external-commit")
	return nil
}
func (sink *workloadReturnSink) SettleEffect(_ context.Context, claim broker.ClaimedDispatchStart, result ReferenceWorkloadResult) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	permit, ok := claim.Open()
	if !ok || permit != sink.permit || len(sink.steps) != 1 || result.ExternalCommitID != sink.result.ExternalCommitID || result.ResultRef != sink.result.ResultRef {
		return errors.New("settlement changed the original claim or result")
	}
	sink.steps = append(sink.steps, "settlement")
	return nil
}

func TestReferenceWorkloadDispatchCrossesUnixRPCOnceAndReturnsCommitThenSettlement(t *testing.T) {
	route := broker.Digest{1}
	dispatch := workloadDispatch(t, route)
	command := []byte("reference-executor-command")
	commandDigest, err := ReferenceWorkloadCommandDigest(command)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	result := ReferenceWorkloadResult{ExternalCommitID: workloadID(t, identity.Commit), ResultRef: workloadID(t, identity.Artifact), Result: []byte("done")}
	handler, err := NewReferenceWorkloadHandler(ReferenceWorkloadHandlerConfig{
		Service: broker.ServiceExecutor, RouteDigest: route, MaximumClaims: 8,
		Execute: func(_ context.Context, received ReceivedDispatchStart) (ReferenceWorkloadResult, error) {
			permit, payload, ok := received.Open()
			if !ok || permit.Dispatch != dispatch || permit.CommandDigest != commandDigest || string(payload) != string(command) {
				return ReferenceWorkloadResult{}, errors.New("wire changed claimed identity")
			}
			calls.Add(1)
			return result, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	server := startTestServer(t, controlrpc.ServerConfig{SocketPath: testSocketPath(t), ServerPeer: v1.ProtocolPeer_PROTOCOL_PEER_AGENTD,
		PeerUIDAuthorities: []controlrpc.PeerUIDAuthority{{UID: uint32(os.Getuid()), Peer: v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD}}, ReferenceWorkload: handler.Transport()})
	client, err := controlrpc.NewClient(controlrpc.ClientConfig{SocketPath: server.SocketPath(), Peer: v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD, ExpectedServerPeer: v1.ProtocolPeer_PROTOCOL_PEER_AGENTD})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	sink := &workloadReturnSink{}
	starter, err := NewReferenceDispatchStarter(ReferenceDispatchStarterConfig{Client: client, Service: broker.ServiceExecutor, RouteDigest: route,
		MaximumClaims: 8, Command: func(context.Context, broker.DispatchStartPermit) ([]byte, error) { return command, nil }, ReturnSink: sink})
	if err != nil {
		t.Fatal(err)
	}
	consumer := workloadConsumer(t, starter)
	request := broker.DispatchStartRequest{Dispatch: dispatch, CommandDigest: commandDigest}
	var wait sync.WaitGroup
	errorsSeen := make(chan error, 64)
	for range 64 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := consumer.StartExactAttempt(context.Background(), request)
			errorsSeen <- err
		}()
	}
	wait.Wait()
	close(errorsSeen)
	started, replayed := 0, 0
	for err := range errorsSeen {
		if err == nil {
			started++
		} else if errors.Is(err, broker.ErrDispatchAlreadyStarted) {
			replayed++
		} else {
			t.Fatalf("dispatch: %v", err)
		}
	}
	if started != 1 || replayed != 63 || calls.Load() != 1 {
		t.Fatalf("started=%d replayed=%d provider=%d", started, replayed, calls.Load())
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.steps) != 2 || sink.steps[0] != "external-commit" || sink.steps[1] != "settlement" {
		t.Fatalf("return steps=%v", sink.steps)
	}
}

// Capturing through the real consumer exercises the private broker seal without
// adding a constructor that could manufacture claimed-start authority.
type workloadCaptureStarter struct {
	route broker.Digest
	claim broker.ClaimedDispatchStart
}

func (starter *workloadCaptureStarter) RouteDigest() broker.Digest { return starter.route }
func (starter *workloadCaptureStarter) Start(_ context.Context, claim broker.ClaimedDispatchStart) error {
	starter.claim = claim
	return nil
}

type workloadFixture struct {
	http    *http.Client
	service *controlrpc.ReferenceWorkloadService
	server  *controlrpc.Server
	client  *controlrpc.Client
	starter *ReferenceDispatchStarter
	sink    *workloadReturnSink
	claim   broker.ClaimedDispatchStart
	permit  broker.DispatchStartPermit
	wire    *v1.ReferenceWorkloadClaim
	command []byte
	result  ReferenceWorkloadResult
	calls   atomic.Int64
}

func newWorkloadFixture(t *testing.T, maximum int, execute func(context.Context, ReceivedDispatchStart) (ReferenceWorkloadResult, error), wrap func(http.Handler) http.Handler) *workloadFixture {
	t.Helper()
	fixture := &workloadFixture{command: []byte("immutable-reference-command"), sink: &workloadReturnSink{},
		result: ReferenceWorkloadResult{ExternalCommitID: workloadID(t, identity.Commit), ResultRef: workloadID(t, identity.Artifact), Result: []byte("executor-output")}}
	route := broker.Digest{1}
	dispatch := workloadDispatch(t, route)
	digest, err := ReferenceWorkloadCommandDigest(fixture.command)
	if err != nil {
		t.Fatal(err)
	}
	capture := &workloadCaptureStarter{route: route}
	if _, err := workloadConsumer(t, capture).StartExactAttempt(context.Background(), broker.DispatchStartRequest{Dispatch: dispatch, CommandDigest: digest}); err != nil {
		t.Fatal(err)
	}
	fixture.claim = capture.claim
	var ok bool
	fixture.permit, ok = fixture.claim.Open()
	if !ok {
		t.Fatal("broker did not seal claim")
	}
	fixture.wire, err = encodeWorkloadClaim(fixture.permit)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewReferenceWorkloadHandler(ReferenceWorkloadHandlerConfig{Service: broker.ServiceExecutor, RouteDigest: route, MaximumClaims: maximum,
		Execute: func(ctx context.Context, claim ReceivedDispatchStart) (ReferenceWorkloadResult, error) {
			fixture.calls.Add(1)
			if execute != nil {
				return execute(ctx, claim)
			}
			return cloneReferenceWorkloadResult(fixture.result), nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	fixture.service = handler.Transport()
	fixture.server = startTestServer(t, controlrpc.ServerConfig{SocketPath: testSocketPath(t), ServerPeer: v1.ProtocolPeer_PROTOCOL_PEER_AGENTD,
		PeerUIDAuthorities: []controlrpc.PeerUIDAuthority{{UID: uint32(os.Getuid()), Peer: v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD}, {UID: uint32(os.Getuid()), Peer: v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL}}, ReferenceWorkload: fixture.service})
	socket := fixture.server.SocketPath()
	if wrap != nil {
		socket = workloadWireProxy(t, socket, wrap)
	}
	fixture.http = workloadHTTPClient(t, socket)
	fixture.client, err = controlrpc.NewClient(controlrpc.ClientConfig{SocketPath: socket, Peer: v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD, ExpectedServerPeer: v1.ProtocolPeer_PROTOCOL_PEER_AGENTD})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fixture.client.Close() })
	fixture.starter, err = NewReferenceDispatchStarter(ReferenceDispatchStarterConfig{Client: fixture.client, Service: broker.ServiceExecutor, RouteDigest: route, MaximumClaims: maximum,
		Command: func(context.Context, broker.DispatchStartPermit) ([]byte, error) { return fixture.command, nil }, ReturnSink: fixture.sink})
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (fixture *workloadFixture) raw(ctx context.Context, mutate func(*v1.StartClaimedWorkloadRequest), session string) (*connect.Response[v1.StartClaimedWorkloadResponse], error) {
	if session == "" {
		var err error
		session, err = workloadRawSession(ctx, fixture.http, v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD)
		if err != nil {
			return nil, err
		}
	}
	requestID := make([]byte, 16)
	if _, err := rand.Read(requestID); err != nil {
		return nil, err
	}
	message := &v1.StartClaimedWorkloadRequest{Meta: &v1.RpcRequestMeta{RequestId: &v1.OpaqueId{Value: requestID}, DeadlineUnixMs: uint64(time.Now().Add(time.Minute).UnixMilli()), ProtocolVersion: &v1.ProtocolVersion{Major: 1}},
		Claim: proto.Clone(fixture.wire).(*v1.ReferenceWorkloadClaim), Command: bytes.Clone(fixture.command)}
	if mutate != nil {
		mutate(message)
	}
	if message.Meta != nil && message.Meta.RequestDigest == nil {
		digest, err := testWorkloadRequestDigest(message)
		if err != nil {
			return nil, err
		}
		message.Meta.RequestDigest = digest
	}
	request := connect.NewRequest(message)
	request.Header().Set("Circulus-Protocol-Session", session)
	rpc := v1connect.NewReferenceWorkloadServiceClient(fixture.http, "http://control.invalid",
		connect.WithReadMaxBytes(1<<20), connect.WithSendMaxBytes(1<<20))
	return rpc.StartClaimedWorkload(ctx, request)
}

func TestReferenceWorkloadSenderAndReceiverEachConsumeConcurrentDuplicates(t *testing.T) {
	for _, boundary := range []string{"sender", "receiver"} {
		t.Run(boundary, func(t *testing.T) {
			fixture := newWorkloadFixture(t, 8, nil, nil)
			var wait sync.WaitGroup
			results := make(chan error, 64)
			for range 64 {
				wait.Add(1)
				go func() {
					defer wait.Done()
					if boundary == "sender" {
						results <- fixture.starter.Start(context.Background(), fixture.claim)
					} else {
						_, err := fixture.raw(context.Background(), nil, "")
						results <- err
					}
				}()
			}
			wait.Wait()
			close(results)
			success, duplicates := 0, 0
			for err := range results {
				if err == nil {
					success++
				} else if connect.CodeOf(err) == connect.CodeAlreadyExists {
					duplicates++
				} else {
					t.Fatalf("unexpected RPC error: %v", err)
				}
			}
			if success != 1 || duplicates != 63 || fixture.calls.Load() != 1 {
				t.Fatalf("success=%d duplicates=%d executions=%d", success, duplicates, fixture.calls.Load())
			}
		})
	}
}

func TestReferenceWorkloadReceiverRejectsChangedClaimAndExhaustionWithoutEviction(t *testing.T) {
	fixture := newWorkloadFixture(t, 1, nil, nil)
	if _, err := fixture.raw(context.Background(), nil, ""); err != nil {
		t.Fatal(err)
	}
	mutations := []struct {
		name   string
		mutate func(*v1.StartClaimedWorkloadRequest)
	}{
		{"tenant", func(m *v1.StartClaimedWorkloadRequest) {
			m.Claim.Dispatch.TenantId = workloadProtoID(workloadID(t, identity.Tenant))
		}},
		{"workspace", func(m *v1.StartClaimedWorkloadRequest) {
			m.Claim.WorkspaceId = workloadProtoID(workloadID(t, identity.Workspace))
		}},
		{"session", func(m *v1.StartClaimedWorkloadRequest) {
			m.Claim.Dispatch.SessionId = workloadProtoID(workloadID(t, identity.Session))
		}},
		{"generation", func(m *v1.StartClaimedWorkloadRequest) { m.Claim.Dispatch.AuthorizationGeneration++ }},
		{"proof", func(m *v1.StartClaimedWorkloadRequest) { m.Claim.StartProof = []byte("different-start-proof") }},
		{"command", func(m *v1.StartClaimedWorkloadRequest) {
			m.Command = []byte("different-command")
			d, _ := ReferenceWorkloadCommandDigest(m.Command)
			m.Claim.CommandDigest = workloadProtoDigest(d)
		}},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			if _, err := fixture.raw(context.Background(), test.mutate, ""); connect.CodeOf(err) != connect.CodeAlreadyExists {
				t.Fatalf("changed identity: %v", err)
			}
		})
	}
	_, err := fixture.raw(context.Background(), func(m *v1.StartClaimedWorkloadRequest) {
		m.Claim.Dispatch.EffectId = workloadProtoID(workloadID(t, identity.Effect))
		m.Claim.Dispatch.InvocationId = workloadProtoID(workloadID(t, identity.Invocation))
	}, "")
	if connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("capacity: %v", err)
	}
	if _, err := fixture.raw(context.Background(), nil, ""); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("old claim was evicted: %v", err)
	}
	if fixture.calls.Load() != 1 {
		t.Fatalf("executions=%d", fixture.calls.Load())
	}
}

func TestReferenceWorkloadRejectsMalformedRequestsBeforeExecuting(t *testing.T) {
	fixture := newWorkloadFixture(t, 8, nil, nil)
	unknown := []byte{0xa0, 0x06, 0x01}
	tests := []struct {
		name   string
		code   connect.Code
		mutate func(*v1.StartClaimedWorkloadRequest)
	}{
		{"unknown top", connect.CodeInvalidArgument, func(m *v1.StartClaimedWorkloadRequest) { m.ProtoReflect().SetUnknown(unknown) }},
		{"unknown nested", connect.CodeInvalidArgument, func(m *v1.StartClaimedWorkloadRequest) { m.Claim.Dispatch.SessionId.ProtoReflect().SetUnknown(unknown) }},
		{"claim absent", connect.CodeInvalidArgument, func(m *v1.StartClaimedWorkloadRequest) { m.Claim = nil }},
		{"request digest", connect.CodeInvalidArgument, func(m *v1.StartClaimedWorkloadRequest) { m.Meta.RequestDigest = workloadProtoDigest(broker.Digest{99}) }},
		{"metadata absent", connect.CodeInvalidArgument, func(m *v1.StartClaimedWorkloadRequest) { m.Meta = nil }},
		{"invalid typed id", connect.CodeInvalidArgument, func(m *v1.StartClaimedWorkloadRequest) {
			m.Claim.Dispatch.SessionId = workloadProtoID(workloadID(t, identity.Tenant))
		}},
		{"invalid command digest", connect.CodeFailedPrecondition, func(m *v1.StartClaimedWorkloadRequest) { m.Command[0] ^= 1 }},
		{"wrong route", connect.CodeFailedPrecondition, func(m *v1.StartClaimedWorkloadRequest) {
			m.Claim.ProviderRouteDigest = workloadProtoDigest(broker.Digest{6})
		}},
		{"expired", connect.CodeDeadlineExceeded, func(m *v1.StartClaimedWorkloadRequest) {
			m.Meta.DeadlineUnixMs = uint64(time.Now().Add(-time.Second).UnixMilli())
		}},
		{"unbounded deadline", connect.CodeInvalidArgument, func(m *v1.StartClaimedWorkloadRequest) {
			m.Meta.DeadlineUnixMs = uint64(time.Now().Add(time.Hour).UnixMilli())
		}},
		{"oversize command", connect.CodeFailedPrecondition, func(m *v1.StartClaimedWorkloadRequest) { m.Command = make([]byte, maximumWorkloadBytes+1) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := fixture.raw(context.Background(), test.mutate, "")
			if connect.CodeOf(err) != test.code {
				t.Fatalf("got %v, expected %v", err, test.code)
			}
		})
	}
	if fixture.calls.Load() != 0 {
		t.Fatal("invalid request reached executor")
	}
	if _, err := fixture.raw(context.Background(), nil, ""); err != nil {
		t.Fatalf("rejected request consumed valid claim: %v", err)
	}
}

func TestReferenceWorkloadAuthenticationFailureIsConsumedWithoutRetry(t *testing.T) {
	var handshakes, requests atomic.Int64
	fixture := newWorkloadFixture(t, 8, nil, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == v1connect.ControlServiceHandshakeProcedure {
				handshakes.Add(1)
			}
			if r.URL.Path == v1connect.ReferenceWorkloadServiceStartClaimedWorkloadProcedure {
				requests.Add(1)
				r.Header.Del("Circulus-Protocol-Session")
			}
			next.ServeHTTP(w, r)
		})
	})
	if err := fixture.starter.Start(context.Background(), fixture.claim); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("authentication failure: %v", err)
	}
	if err := fixture.starter.Start(context.Background(), fixture.claim); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("consumed sender claim: %v", err)
	}
	if handshakes.Load() != 1 || requests.Load() != 1 || fixture.calls.Load() != 0 {
		t.Fatalf("handshakes=%d requests=%d executor=%d", handshakes.Load(), requests.Load(), fixture.calls.Load())
	}
}

func TestReferenceWorkloadLostResponseNeverReexecutesOrSettles(t *testing.T) {
	var requests atomic.Int64
	fixture := newWorkloadFixture(t, 8, nil, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != v1connect.ReferenceWorkloadServiceStartClaimedWorkloadProcedure {
				next.ServeHTTP(w, r)
				return
			}
			requests.Add(1)
			recorder := httptest.NewRecorder()
			next.ServeHTTP(recorder, r)
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = connection.Close()
		})
	})
	consumer := workloadConsumer(t, fixture.starter)
	execution, err := consumer.StartExactAttempt(context.Background(), broker.DispatchStartRequest{Dispatch: fixture.permit.Dispatch, CommandDigest: fixture.permit.CommandDigest})
	if !errors.Is(err, broker.ErrDispatchStartUnknown) || execution.Outcome != broker.DispatchStartOutcomeUnknown {
		t.Fatalf("lost response must remain unknown: %v, %v", execution.Outcome, err)
	}
	if err := fixture.starter.Start(context.Background(), fixture.claim); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("lost response retried: %v", err)
	}
	if fixture.calls.Load() != 1 || requests.Load() != 1 || len(fixture.sink.steps) != 0 {
		t.Fatalf("executions=%d requests=%d returns=%v", fixture.calls.Load(), requests.Load(), fixture.sink.steps)
	}
	if _, err := fixture.raw(context.Background(), nil, ""); err == nil {
		t.Fatal("unexpected replay success")
	}
	if fixture.calls.Load() != 1 {
		t.Fatal("receiver replayed after response loss")
	}
}

func TestReferenceWorkloadCancellationAfterExecutionBeginsIsConsumed(t *testing.T) {
	entered := make(chan struct{})
	fixture := newWorkloadFixture(t, 8, func(ctx context.Context, _ ReceivedDispatchStart) (ReferenceWorkloadResult, error) {
		close(entered)
		<-ctx.Done()
		return ReferenceWorkloadResult{}, ctx.Err()
	}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() { finished <- fixture.starter.Start(ctx, fixture.claim) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("executor did not start")
	}
	cancel()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("canceled request succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled request did not stop")
	}
	if err := fixture.starter.Start(context.Background(), fixture.claim); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("canceled attempt replayed: %v", err)
	}
	if fixture.calls.Load() != 1 || len(fixture.sink.steps) != 0 {
		t.Fatal("cancellation repeated or settled execution")
	}
}

func TestReferenceWorkloadTamperedResponsesNeverReachReturnSink(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*v1.StartClaimedWorkloadResponse)
	}{
		{"unknown", func(m *v1.StartClaimedWorkloadResponse) { m.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01}) }},
		{"unknown nested", func(m *v1.StartClaimedWorkloadResponse) {
			m.Result.ResultDigest.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
		}},
		{"claim identity", func(m *v1.StartClaimedWorkloadResponse) { m.Claim.Dispatch.AuthorizationGeneration++ }},
		{"request identity", func(m *v1.StartClaimedWorkloadResponse) { m.Meta.RequestId.Value[0] ^= 1 }},
		{"request digest", func(m *v1.StartClaimedWorkloadResponse) { m.RequestDigest.Value[0] ^= 1 }},
		{"result digest", func(m *v1.StartClaimedWorkloadResponse) { m.Result.ResultDigest.Value[0] ^= 1 }},
		{"not reference", func(m *v1.StartClaimedWorkloadResponse) { m.ReferenceOnly = false }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newWorkloadFixture(t, 8, nil, func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != v1connect.ReferenceWorkloadServiceStartClaimedWorkloadProcedure {
						next.ServeHTTP(w, r)
						return
					}
					r.Header.Del("Accept-Encoding")
					recorder := httptest.NewRecorder()
					next.ServeHTTP(recorder, r)
					message := new(v1.StartClaimedWorkloadResponse)
					if err := proto.Unmarshal(recorder.Body.Bytes(), message); err != nil {
						t.Error(err)
						w.WriteHeader(500)
						return
					}
					test.mutate(message)
					body, err := proto.Marshal(message)
					if err != nil {
						t.Error(err)
						w.WriteHeader(500)
						return
					}
					for name, values := range recorder.Header() {
						if name != "Content-Length" {
							w.Header()[name] = values
						}
					}
					w.WriteHeader(recorder.Code)
					_, _ = w.Write(body)
				})
			})
			if err := fixture.starter.Start(context.Background(), fixture.claim); connect.CodeOf(err) != connect.CodeDataLoss {
				t.Fatalf("tampered response: %v", err)
			}
			if err := fixture.starter.Start(context.Background(), fixture.claim); connect.CodeOf(err) != connect.CodeAlreadyExists {
				t.Fatalf("tampered response retried: %v", err)
			}
			if fixture.calls.Load() != 1 || len(fixture.sink.steps) != 0 {
				t.Fatal("invalid response reached settlement")
			}
		})
	}
}

type nilWorkloadReturnFunc func()

func (nilWorkloadReturnFunc) ConfirmExternalCommit(context.Context, broker.ClaimedDispatchStart, ReferenceWorkloadResult) error {
	return nil
}
func (nilWorkloadReturnFunc) SettleEffect(context.Context, broker.ClaimedDispatchStart, ReferenceWorkloadResult) error {
	return nil
}

func TestReferenceWorkloadConstructorsAndSealsFailClosed(t *testing.T) {
	fixture := newWorkloadFixture(t, 8, nil, nil)
	config := ReferenceDispatchStarterConfig{Client: fixture.client, Service: broker.ServiceExecutor, RouteDigest: broker.Digest{1}, MaximumClaims: 8,
		Command: fixture.starter.command, ReturnSink: nilWorkloadReturnFunc(nil)}
	if _, err := NewReferenceDispatchStarter(config); !errors.Is(err, broker.ErrInvalidRequest) {
		t.Fatalf("nil func sink accepted: %v", err)
	}
	config.ReturnSink = (*workloadReturnSink)(nil)
	if _, err := NewReferenceDispatchStarter(config); !errors.Is(err, broker.ErrInvalidRequest) {
		t.Fatalf("nil pointer sink accepted: %v", err)
	}
	if _, _, ok := (ReceivedDispatchStart{}).Open(); ok {
		t.Fatal("zero receiver claim opened")
	}
	if err := fixture.starter.Start(context.Background(), broker.ClaimedDispatchStart{}); !errors.Is(err, broker.ErrFenceMismatch) {
		t.Fatalf("unsealed broker claim accepted: %v", err)
	}
	if err := (&ReferenceDispatchStarter{}).Start(context.Background(), fixture.claim); !errors.Is(err, broker.ErrInvalidRequest) {
		t.Fatalf("zero starter accepted: %v", err)
	}
	for _, role := range []v1.ProtocolPeer{v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD, v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL} {
		server, err := controlrpc.ListenServer(controlrpc.ServerConfig{SocketPath: testSocketPath(t), ServerPeer: role, ReferenceWorkload: fixture.service})
		if server != nil {
			_ = server.Close()
		}
		if err == nil {
			t.Fatalf("invalid server role %v accepted", role)
		}
	}
	if fixture.calls.Load() != 0 {
		t.Fatal("invalid constructor or seal executed")
	}
}

func TestReferenceWorkloadPreservesZeroOrdinalForParentlessAndFirstChildClaims(t *testing.T) {
	for _, parent := range []bool{false, true} {
		t.Run(map[bool]string{false: "parentless", true: "first child"}[parent], func(t *testing.T) {
			fixture := newWorkloadFixture(t, 8, nil, nil)
			dispatch := fixture.permit.Dispatch
			dispatch.Ordinal = 0
			if parent {
				dispatch.ParentOperationID = workloadID(t, identity.Operation)
			}
			capture := &workloadCaptureStarter{route: dispatch.ProviderRouteDigest}
			if _, err := workloadConsumer(t, capture).StartExactAttempt(context.Background(), broker.DispatchStartRequest{Dispatch: dispatch, CommandDigest: fixture.permit.CommandDigest}); err != nil {
				t.Fatal(err)
			}
			permit, ok := capture.claim.Open()
			if !ok {
				t.Fatal("unsealed claim")
			}
			wire, err := encodeWorkloadClaim(permit)
			if err != nil {
				t.Fatalf("valid zero ordinal: %v", err)
			}
			decoded, err := decodeWorkloadClaim(wire)
			if err != nil || decoded != permit {
				t.Fatalf("roundtrip=%#v %v", decoded, err)
			}
			if err := fixture.starter.Start(context.Background(), capture.claim); err != nil {
				t.Fatalf("valid sealed claim start: %v", err)
			}
			if fixture.calls.Load() != 1 || fixture.sink.permit != permit {
				t.Fatal("zero ordinal changed at executor/return boundary")
			}
		})
	}
}

func TestReferenceWorkloadRejectsUnsafeCrossLanguageClaimIntegers(t *testing.T) {
	const unsafe = uint64(1) << 53
	fixture := newWorkloadFixture(t, 8, nil, nil)
	tests := []struct {
		name   string
		mutate func(*broker.DispatchStartPermit)
	}{
		{"parentless ordinal", func(p *broker.DispatchStartPermit) {
			p.Dispatch.ParentOperationID = identity.ID{}
			p.Dispatch.Ordinal = 1
		}},
		{"ordinal", func(p *broker.DispatchStartPermit) {
			p.Dispatch.ParentOperationID = workloadID(t, identity.Operation)
			p.Dispatch.Ordinal = unsafe
		}},
		{"turn generation", func(p *broker.DispatchStartPermit) { p.Dispatch.Generations.TurnLease = unsafe }},
		{"placement generation", func(p *broker.DispatchStartPermit) { p.Dispatch.Generations.Placement = unsafe }},
		{"sandbox generation", func(p *broker.DispatchStartPermit) { p.Dispatch.Generations.Sandbox = unsafe }},
		{"authorization generation", func(p *broker.DispatchStartPermit) { p.Dispatch.Generations.Authorization = unsafe }},
		{"attempt", func(p *broker.DispatchStartPermit) { p.Dispatch.DispatchAttempt = unsafe }},
		{"claim sequence", func(p *broker.DispatchStartPermit) { p.EventSequence = unsafe }},
		{"dispatch sequence", func(p *broker.DispatchStartPermit) { p.Dispatch.EventSequence = unsafe; p.EventSequence = unsafe + 1 }},
		{"timestamp", func(p *broker.DispatchStartPermit) { p.Dispatch.Deadline = time.UnixMilli(int64(unsafe)).UTC() }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p := fixture.permit
			test.mutate(&p)
			if _, err := encodeWorkloadClaim(p); !errors.Is(err, broker.ErrInvalidRequest) {
				t.Fatalf("unsafe claim accepted: %v", err)
			}
		})
	}
}

type workloadSinkFunctions struct {
	confirm func(context.Context, broker.ClaimedDispatchStart, ReferenceWorkloadResult) error
	settle  func(context.Context, broker.ClaimedDispatchStart, ReferenceWorkloadResult) error
}

func (sink workloadSinkFunctions) ConfirmExternalCommit(ctx context.Context, claim broker.ClaimedDispatchStart, result ReferenceWorkloadResult) error {
	return sink.confirm(ctx, claim, result)
}
func (sink workloadSinkFunctions) SettleEffect(ctx context.Context, claim broker.ClaimedDispatchStart, result ReferenceWorkloadResult) error {
	return sink.settle(ctx, claim, result)
}

func TestReferenceWorkloadReturnErrorsRemainConsumedAndPreservePhaseOrder(t *testing.T) {
	for _, failedPhase := range []string{"confirm", "settle"} {
		t.Run(failedPhase, func(t *testing.T) {
			fixture := newWorkloadFixture(t, 8, nil, nil)
			var steps []string
			sentinel := errors.New("ambiguous durable return")
			fixture.starter.sink = workloadSinkFunctions{
				confirm: func(_ context.Context, claim broker.ClaimedDispatchStart, result ReferenceWorkloadResult) error {
					permit, ok := claim.Open()
					if !ok || permit != fixture.permit || result.ExternalCommitID != fixture.result.ExternalCommitID {
						t.Error("confirm lost original claim/result")
					}
					steps = append(steps, "confirm")
					if failedPhase == "confirm" {
						return sentinel
					}
					return nil
				},
				settle: func(_ context.Context, claim broker.ClaimedDispatchStart, result ReferenceWorkloadResult) error {
					permit, ok := claim.Open()
					if !ok || permit != fixture.permit || result.ExternalCommitID != fixture.result.ExternalCommitID {
						t.Error("settle lost original claim/result")
					}
					steps = append(steps, "settle")
					return sentinel
				},
			}
			if err := fixture.starter.Start(context.Background(), fixture.claim); !errors.Is(err, sentinel) {
				t.Fatalf("return error changed: %v", err)
			}
			if err := fixture.starter.Start(context.Background(), fixture.claim); connect.CodeOf(err) != connect.CodeAlreadyExists {
				t.Fatalf("return error retried: %v", err)
			}
			want := 1
			if failedPhase == "settle" {
				want = 2
			}
			if len(steps) != want || steps[0] != "confirm" || fixture.calls.Load() != 1 {
				t.Fatalf("steps=%v executions=%d", steps, fixture.calls.Load())
			}
		})
	}
}

func TestReferenceWorkloadCommandAndReturnPayloadsAreIndependentSnapshots(t *testing.T) {
	command := []byte("immutable-reference-command")
	output := []byte("immutable-executor-result")
	result := ReferenceWorkloadResult{ExternalCommitID: workloadID(t, identity.Commit), ResultRef: workloadID(t, identity.Artifact), Result: output}
	fixture := newWorkloadFixture(t, 8, func(_ context.Context, received ReceivedDispatchStart) (ReferenceWorkloadResult, error) {
		permit, first, ok := received.Open()
		if !ok || !bytes.Equal(first, command) {
			t.Error("received bytes differ")
		}
		first[0] ^= 1
		again, second, ok := received.Open()
		if !ok || again != permit || !bytes.Equal(second, command) {
			t.Error("Open leaked mutable command")
		}
		return result, nil
	}, nil)
	var confirmed bool
	fixture.starter.sink = workloadSinkFunctions{
		confirm: func(_ context.Context, _ broker.ClaimedDispatchStart, result ReferenceWorkloadResult) error {
			confirmed = true
			result.Result[0] ^= 1
			return nil
		},
		settle: func(_ context.Context, _ broker.ClaimedDispatchStart, result ReferenceWorkloadResult) error {
			if !confirmed || !bytes.Equal(result.Result, output) {
				t.Error("confirm mutated settlement result")
			}
			return nil
		},
	}
	if err := fixture.starter.Start(context.Background(), fixture.claim); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fixture.command, command) || string(output) != "immutable-executor-result" {
		t.Fatal("transport mutated caller-owned bytes")
	}
}

func testSocketPath(t *testing.T) string {
	t.Helper()
	root, err := os.MkdirTemp("", "circulusd-reference-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	return filepath.Join(root, "rpc.sock")
}
func startTestServer(t *testing.T, config controlrpc.ServerConfig) *controlrpc.Server {
	t.Helper()
	server, err := controlrpc.ListenServer(config)
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- server.Serve(context.Background()) }()
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
		select {
		case err := <-finished:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Error("reference server did not stop")
		}
	})
	return server
}
func workloadHTTPClient(t *testing.T, socket string) *http.Client {
	t.Helper()
	transport := &http.Transport{DisableCompression: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport}
}

// A second private UDS applies wire faults without exposing controlrpc's
// credentials, sessions, server internals, or authority through production APIs.
func workloadWireProxy(t *testing.T, target string, wrap func(http.Handler) http.Handler) string {
	t.Helper()
	socket := testSocketPath(t)
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(socket, 0o600); err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	client := workloadHTTPClient(t, target)
	proxy := &httputil.ReverseProxy{Director: func(request *http.Request) { request.URL.Scheme = "http"; request.URL.Host = "reference.invalid" }, Transport: client.Transport}
	server := &http.Server{Handler: wrap(proxy)}
	finished := make(chan error, 1)
	go func() { finished <- server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Close()
		err := <-finished
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Error(err)
		}
	})
	return socket
}
func testWorkloadDescriptor() *v1.Digest {
	wire, err := os.ReadFile("../../api/descriptors/circulus.v1alpha.pb")
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256(wire)
	return &v1.Digest{Algorithm: v1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: digest[:]}
}
func workloadRawSession(ctx context.Context, client *http.Client, peer v1.ProtocolPeer) (string, error) {
	rpc := v1connect.NewControlServiceClient(client, "http://control.invalid")
	response, err := rpc.Handshake(ctx, connect.NewRequest(&v1.HandshakeRequest{Peer: peer, MinimumVersion: &v1.ProtocolVersion{Major: 1}, MaximumVersion: &v1.ProtocolVersion{Major: 1}, MaximumFrameSize: 1 << 20, DescriptorDigest: testWorkloadDescriptor(), OneTimeNonce: bytes.Repeat([]byte{0x5a}, 32)}))
	if err != nil {
		return "", err
	}
	return response.Header().Get("Circulus-Protocol-Session"), nil
}
func testWorkloadRequestDigest(message *v1.StartClaimedWorkloadRequest) (*v1.Digest, error) {
	cloned := proto.Clone(message).(*v1.StartClaimedWorkloadRequest)
	if cloned.Meta != nil {
		cloned.Meta.RequestDigest = nil
	}
	wire, err := (proto.MarshalOptions{Deterministic: true}).Marshal(cloned)
	if err != nil {
		return nil, err
	}
	return sha256Digest(append([]byte("circulusd.controlrpc.StartClaimedWorkload.v1\x00"), wire...)), nil
}
