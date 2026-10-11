//go:build linux

package controlrpc

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	v1connect "github.com/hancomac/circulusd/api/generated/circulus/v1alpha/circulusv1alphaconnect"
)

type referenceTransportFixture struct {
	server     *Server
	client     *Client
	rpc        *ReferenceWorkloadClient
	calls      atomic.Int64
	handshakes atomic.Int64
	requests   atomic.Int64
}

func newReferenceTransportFixture(t *testing.T) *referenceTransportFixture {
	t.Helper()
	fixture := &referenceTransportFixture{}
	service, err := NewReferenceWorkloadService(func(ctx context.Context, claim *v1.ReferenceWorkloadClaim, command []byte) (*v1.ReferenceWorkloadResult, error) {
		if _, ok := ctx.Deadline(); !ok {
			return nil, errors.New("receiver lacks bounded deadline")
		}
		fixture.calls.Add(1)
		return &v1.ReferenceWorkloadResult{Result: bytes.Clone(command), ResultDigest: sha256Digest(command)}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.server, err = ListenServer(ServerConfig{SocketPath: testSocketPath(t), ServerPeer: v1.ProtocolPeer_PROTOCOL_PEER_AGENTD, PeerUIDAuthorities: []PeerUIDAuthority{{UID: uint32(os.Getuid()), Peer: v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD}, {UID: uint32(os.Getuid()), Peer: v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL}}, ReferenceWorkload: service})
	if err != nil {
		t.Fatal(err)
	}
	next := fixture.server.httpServer.Handler
	fixture.server.httpServer.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == v1connect.ControlServiceHandshakeProcedure {
			fixture.handshakes.Add(1)
		}
		if r.URL.Path == v1connect.ReferenceWorkloadServiceStartClaimedWorkloadProcedure {
			fixture.requests.Add(1)
		}
		next.ServeHTTP(w, r)
	})
	finished := make(chan error, 1)
	go func() { finished <- fixture.server.Serve(context.Background()) }()
	t.Cleanup(func() {
		if err := fixture.server.Close(); err != nil {
			t.Error(err)
		}
		select {
		case err := <-finished:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Error("reference transport did not stop")
		}
	})
	fixture.client, err = NewClient(ClientConfig{SocketPath: fixture.server.SocketPath(), Peer: v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD, ExpectedServerPeer: v1.ProtocolPeer_PROTOCOL_PEER_AGENTD})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fixture.client.Close() })
	fixture.rpc, err = NewReferenceWorkloadClient(fixture.client)
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}
func (fixture *referenceTransportFixture) raw(session string, mutate func(*v1.StartClaimedWorkloadRequest)) error {
	if session == "" {
		var err error
		session, err = fixture.client.ensureHandshake(context.Background())
		if err != nil {
			return err
		}
	}
	message := &v1.StartClaimedWorkloadRequest{Meta: &v1.RpcRequestMeta{RequestId: &v1.OpaqueId{Value: bytes.Repeat([]byte{1}, 16)}, DeadlineUnixMs: uint64(time.Now().Add(time.Minute).UnixMilli()), ProtocolVersion: protocolVersion()}, Claim: &v1.ReferenceWorkloadClaim{}, Command: []byte("opaque reference payload")}
	if mutate != nil {
		mutate(message)
	}
	if message.Meta != nil && message.Meta.RequestDigest == nil {
		digest, err := workloadRequestDigest(message)
		if err != nil {
			return err
		}
		message.Meta.RequestDigest = digest
	}
	request := connect.NewRequest(message)
	request.Header().Set(sessionHeader, session)
	rpc := v1connect.NewReferenceWorkloadServiceClient(&http.Client{Transport: fixture.client.transport}, "http://control.invalid")
	_, err := rpc.StartClaimedWorkload(context.Background(), request)
	return err
}

func TestReferenceWorkloadCapabilitiesPeerCannotExecuteAndTokenPinsUIDAndBoot(t *testing.T) {
	fixture := newReferenceTransportFixture(t)
	doctor, err := NewClient(ClientConfig{SocketPath: fixture.server.SocketPath(), Peer: v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL, ExpectedServerPeer: v1.ProtocolPeer_PROTOCOL_PEER_AGENTD})
	if err != nil {
		t.Fatal(err)
	}
	defer doctor.Close()
	if _, err := doctor.GetCapabilities(context.Background()); err != nil {
		t.Fatalf("doctor should retain capability access: %v", err)
	}
	session, err := doctor.ensureHandshake(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.raw(session, nil); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("doctor workload: %v", err)
	}
	wrongUID, err := fixture.server.handler.issueSession(uint32(os.Getuid())+1, v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.raw(wrongUID, nil); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("wrong UID: %v", err)
	}
	other := newReferenceTransportFixture(t)
	wrongBoot, err := other.client.ensureHandshake(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.raw(wrongBoot, nil); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("wrong boot: %v", err)
	}
	if fixture.calls.Load() != 0 {
		t.Fatal("unauthorized caller reached receiver")
	}
}

func TestReferenceWorkloadExpiredHandshakeIsNeverRetried(t *testing.T) {
	fixture := newReferenceTransportFixture(t)
	expired, err := fixture.server.handler.issueSession(uint32(os.Getuid()), v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD, time.Now().Add(-sessionLifetime-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	fixture.client.handshakeSession = expired
	if _, err := fixture.rpc.Start(context.Background(), &v1.ReferenceWorkloadClaim{}, []byte("opaque reference payload")); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("expired session: %v", err)
	}
	if fixture.handshakes.Load() != 0 || fixture.requests.Load() != 1 || fixture.calls.Load() != 0 {
		t.Fatalf("handshakes=%d requests=%d receiver=%d", fixture.handshakes.Load(), fixture.requests.Load(), fixture.calls.Load())
	}
	if fixture.client.handshakeSession != expired {
		t.Fatal("failed operation replaced its handshake")
	}
}

func TestReferenceWorkloadWireGuardsRunBeforeExplicitReceiver(t *testing.T) {
	fixture := newReferenceTransportFixture(t)
	tests := []struct {
		name   string
		code   connect.Code
		mutate func(*v1.StartClaimedWorkloadRequest)
	}{
		{"unknown field", connect.CodeInvalidArgument, func(m *v1.StartClaimedWorkloadRequest) { m.Claim.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 1}) }},
		{"metadata absent", connect.CodeInvalidArgument, func(m *v1.StartClaimedWorkloadRequest) { m.Meta = nil }},
		{"wrong digest", connect.CodeInvalidArgument, func(m *v1.StartClaimedWorkloadRequest) { m.Meta.RequestDigest = descriptorDigest() }},
		{"expired", connect.CodeDeadlineExceeded, func(m *v1.StartClaimedWorkloadRequest) {
			m.Meta.DeadlineUnixMs = uint64(time.Now().Add(-time.Second).UnixMilli())
		}},
		{"unbounded", connect.CodeInvalidArgument, func(m *v1.StartClaimedWorkloadRequest) {
			m.Meta.DeadlineUnixMs = uint64(time.Now().Add(time.Hour).UnixMilli())
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := fixture.raw("", test.mutate); connect.CodeOf(err) != test.code {
				t.Fatalf("wire guard: %v", err)
			}
		})
	}
	if fixture.calls.Load() != 0 {
		t.Fatal("invalid wire request reached callback")
	}
	if err := fixture.raw("", nil); err != nil {
		t.Fatal(err)
	}
	if fixture.calls.Load() != 1 {
		t.Fatal("valid explicit reference receiver not invoked")
	}
}

func TestReferenceWorkloadTransportRejectsUnqualifiedConstruction(t *testing.T) {
	fixture := newReferenceTransportFixture(t)
	if _, err := NewReferenceWorkloadService(nil); err == nil {
		t.Fatal("nil receiver accepted")
	}
	if _, err := NewReferenceWorkloadClient(nil); err == nil {
		t.Fatal("nil client accepted")
	}
	doctor, err := NewClient(ClientConfig{SocketPath: fixture.server.SocketPath(), Peer: v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL, ExpectedServerPeer: v1.ProtocolPeer_PROTOCOL_PEER_AGENTD})
	if err != nil {
		t.Fatal(err)
	}
	defer doctor.Close()
	if _, err := NewReferenceWorkloadClient(doctor); err == nil {
		t.Fatal("capability-only client obtained workload transport")
	}
	_ = fixture.client.Close()
	if _, err := NewReferenceWorkloadClient(fixture.client); err == nil {
		t.Fatal("closed client accepted")
	}
	if _, err := fixture.rpc.Start(context.Background(), &v1.ReferenceWorkloadClaim{}, []byte("command")); err == nil {
		t.Fatal("closed transport sent")
	}
}
