package controlrpc

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	v1connect "github.com/hancomac/circulusd/api/generated/circulus/v1alpha/circulusv1alphaconnect"
	"google.golang.org/protobuf/proto"
)

func TestControlRPCHandshakeCapabilitiesAndCloneBoundaries(t *testing.T) {
	capability := &v1.CapabilityStatus{
		Name:         "execution.docker",
		Availability: v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_AVAILABLE,
		Attributes:   map[string]string{"version": "1"},
	}
	server := startTestServer(t, ServerConfig{
		SocketPath:   testSocketPath(t),
		AllowedUIDs:  []uint32{uint32(os.Getuid())},
		AllowedPeers: []v1.ProtocolPeer{v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL},
		Capabilities: []*v1.CapabilityStatus{capability},
	})

	capability.Name = "mutated-after-listen"
	capability.Attributes["version"] = "mutated"

	client, err := NewClient(ClientConfig{
		SocketPath: server.SocketPath(),
		Peer:       v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL,
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	first, err := client.GetCapabilities(ctx)
	if err != nil {
		t.Fatalf("first GetCapabilities() error = %v", err)
	}
	if got := first.GetProtocolVersion(); got.GetMajor() != 1 || got.GetMinor() != 0 {
		t.Fatalf("protocol version = %v, want 1.0", got)
	}
	assertDescriptorDigest(t, first.GetDescriptorDigest())
	assertDescriptorDigest(t, first.GetMeta().GetDescriptorDigest())
	if first.GetMeta().GetServerSequence() != 1 {
		t.Fatalf("first server sequence = %d, want 1", first.GetMeta().GetServerSequence())
	}
	if got := first.GetCapabilities(); len(got) != 1 || got[0].GetName() != "execution.docker" || got[0].GetAttributes()["version"] != "1" {
		t.Fatalf("first capabilities = %v, want immutable configured value", got)
	}
	first.Capabilities[0].Name = "mutated-response"
	first.Capabilities[0].Attributes["version"] = "mutated-response"

	second, err := client.GetCapabilities(ctx)
	if err != nil {
		t.Fatalf("second GetCapabilities() error = %v", err)
	}
	if second.GetMeta().GetServerSequence() != 2 {
		t.Fatalf("second server sequence = %d, want 2", second.GetMeta().GetServerSequence())
	}
	if proto.Equal(first.GetMeta().GetRequestId(), second.GetMeta().GetRequestId()) {
		t.Fatal("two calls reused a request ID")
	}
	if got := second.GetCapabilities(); len(got) != 1 || got[0].GetName() != "execution.docker" || got[0].GetAttributes()["version"] != "1" {
		t.Fatalf("second capabilities = %v, want clone boundary", got)
	}
}

func TestControlRPCBindsAndAuthenticatesTheServerPeer(t *testing.T) {
	server := startTestServer(t, ServerConfig{
		SocketPath:   testSocketPath(t),
		AllowedUIDs:  []uint32{uint32(os.Getuid())},
		AllowedPeers: []v1.ProtocolPeer{v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL},
		ServerPeer:   v1.ProtocolPeer_PROTOCOL_PEER_AGENTD,
	})

	wrongClient, err := NewClient(ClientConfig{SocketPath: server.SocketPath()})
	if err != nil {
		t.Fatalf("NewClient(default peer) error = %v", err)
	}
	defer wrongClient.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := wrongClient.GetCapabilities(ctx); connect.CodeOf(err) != connect.CodeDataLoss {
		t.Fatalf("wrong-daemon GetCapabilities() error = %v, want data_loss", err)
	}

	rightClient, err := NewClient(ClientConfig{
		SocketPath:         server.SocketPath(),
		ExpectedServerPeer: v1.ProtocolPeer_PROTOCOL_PEER_AGENTD,
	})
	if err != nil {
		t.Fatalf("NewClient(expected agentd) error = %v", err)
	}
	defer rightClient.Close()
	if _, err := rightClient.GetCapabilities(ctx); err != nil {
		t.Fatalf("expected-agentd GetCapabilities() error = %v", err)
	}

	nonce := bytes.Repeat([]byte{0xa5}, handshakeNonceBytes)
	platformdProof := nonceProof(nonce, v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD)
	agentdProof := nonceProof(nonce, v1.ProtocolPeer_PROTOCOL_PEER_AGENTD)
	if bytes.Equal(platformdProof, agentdProof) {
		t.Fatal("nonce proof is not bound to the authenticated server peer")
	}
}

func TestControlRPCRejectsPeerUIDCrossProductEscalation(t *testing.T) {
	_, err := ListenServer(ServerConfig{
		SocketPath:  testSocketPath(t),
		AllowedUIDs: []uint32{uint32(os.Getuid()), uint32(os.Getuid()) + 1},
		AllowedPeers: []v1.ProtocolPeer{
			v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL,
			v1.ProtocolPeer_PROTOCOL_PEER_AGENTD,
		},
	})
	if err == nil {
		t.Fatal("ListenServer() accepted ambiguous UID/peer cross-product authority")
	}
}

func TestControlRPCAuthorizesEachProtocolPeerForItsMappedUID(t *testing.T) {
	server := startTestServer(t, ServerConfig{
		SocketPath: testSocketPath(t),
		PeerUIDAuthorities: []PeerUIDAuthority{
			{UID: uint32(os.Getuid()), Peer: v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL},
			{UID: uint32(os.Getuid()) + 1, Peer: v1.ProtocolPeer_PROTOCOL_PEER_AGENTD},
		},
	})
	raw, closeRaw := rawControlClient(t, server.SocketPath())
	defer closeRaw()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := raw.Handshake(ctx, connect.NewRequest(handshakeRequest(t, v1.ProtocolPeer_PROTOCOL_PEER_AGENTD)))
	if got := connect.CodeOf(err); got != connect.CodePermissionDenied {
		t.Fatalf("cross-product Handshake() code = %v error=%v, want permission_denied", got, err)
	}
	if _, err := raw.Handshake(ctx, connect.NewRequest(handshakeRequest(t, v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL))); err != nil {
		t.Fatalf("mapped Handshake() error = %v", err)
	}
}

func TestCompiledDescriptorDigestMatchesCheckedDescriptor(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller() did not return the test source path")
	}
	descriptorPath := filepath.Join(filepath.Dir(sourceFile), "..", "..", "api", "descriptors", "circulus.v1alpha.pb")
	descriptor, err := os.ReadFile(descriptorPath)
	if err != nil {
		t.Fatalf("read checked descriptor: %v", err)
	}
	digest := sha256.Sum256(descriptor)
	if got := hex.EncodeToString(digest[:]); got != descriptorSHA256 {
		t.Fatalf("checked descriptor digest = %s, compiled handshake digest = %s", got, descriptorSHA256)
	}
}

func TestListenServerValidatesSocketPathPermissionsAndUIDPolicy(t *testing.T) {
	t.Run("relative path", func(t *testing.T) {
		_, err := ListenServer(ServerConfig{SocketPath: "control.sock", AllowedUIDs: []uint32{uint32(os.Getuid())}})
		if err == nil {
			t.Fatal("ListenServer() accepted a relative socket path")
		}
	})

	t.Run("noncanonical path", func(t *testing.T) {
		path := t.TempDir() + "/missing/../control.sock"
		_, err := ListenServer(ServerConfig{SocketPath: path, AllowedUIDs: []uint32{uint32(os.Getuid())}})
		if err == nil {
			t.Fatal("ListenServer() accepted a noncanonical socket path")
		}
	})

	t.Run("empty allowed UIDs", func(t *testing.T) {
		_, err := ListenServer(ServerConfig{SocketPath: testSocketPath(t)})
		if err == nil {
			t.Fatal("ListenServer() accepted an empty UID allowlist")
		}
	})

	t.Run("existing filesystem entry", func(t *testing.T) {
		path := testSocketPath(t)
		if err := os.WriteFile(path, []byte("do not replace"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := ListenServer(ServerConfig{SocketPath: path, AllowedUIDs: []uint32{uint32(os.Getuid())}})
		if err == nil {
			t.Fatal("ListenServer() replaced an existing path")
		}
		contents, readErr := os.ReadFile(path)
		if readErr != nil || string(contents) != "do not replace" {
			t.Fatalf("existing path changed: contents=%q error=%v", contents, readErr)
		}
	})

	t.Run("socket mode", func(t *testing.T) {
		server, err := ListenServer(ServerConfig{
			SocketPath:  testSocketPath(t),
			AllowedUIDs: []uint32{uint32(os.Getuid())},
		})
		if err != nil {
			t.Fatalf("ListenServer() error = %v", err)
		}
		defer server.Close()
		info, err := os.Lstat(server.SocketPath())
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
			t.Fatalf("socket mode = %v, want socket 0600", info.Mode())
		}
	})

	t.Run("group or other writable parent", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "shared")
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(parent, 0o777); err != nil {
			t.Fatal(err)
		}
		server, err := ListenServer(ServerConfig{
			SocketPath:  filepath.Join(parent, "control.sock"),
			AllowedUIDs: []uint32{uint32(os.Getuid())},
		})
		if err == nil {
			_ = server.Close()
			t.Fatal("ListenServer() accepted a group/other-writable socket parent")
		}
	})

	t.Run("parent owned by another UID", func(t *testing.T) {
		parent := t.TempDir()
		if err := validateSocketDirectory(parent, uint32(os.Geteuid())+1); err == nil {
			t.Fatal("validateSocketDirectory() accepted a parent owned by another UID")
		}
	})
}

func TestControlServerBoundsWholeRequestAndResponseIO(t *testing.T) {
	server, err := ListenServer(ServerConfig{
		SocketPath:  testSocketPath(t),
		AllowedUIDs: []uint32{uint32(os.Getuid())},
	})
	if err != nil {
		t.Fatalf("ListenServer() error = %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	if server.httpServer.ReadTimeout != 5*time.Second {
		t.Fatalf("ReadTimeout = %s, want 5s", server.httpServer.ReadTimeout)
	}
	wantWriteTimeout := maximumRequestDeadline + controlHTTPIOTimeout
	if server.httpServer.WriteTimeout != wantWriteTimeout {
		t.Fatalf("WriteTimeout = %s, want %s", server.httpServer.WriteTimeout, wantWriteTimeout)
	}
	if !server.httpServer.DisableGeneralOptionsHandler {
		t.Fatal("general OPTIONS handler is enabled outside the Connect RPC routes")
	}
}

func TestControlServerRejectsGeneralOptionsAsteriskForm(t *testing.T) {
	server := startTestServer(t, ServerConfig{
		SocketPath:  testSocketPath(t),
		AllowedUIDs: []uint32{uint32(os.Getuid())},
	})
	connection, err := net.DialTimeout("unix", server.SocketPath(), time.Second)
	if err != nil {
		t.Fatalf("dial control socket: %v", err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	if err := connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set connection deadline: %v", err)
	}
	if _, err := connection.Write([]byte(
		"OPTIONS * HTTP/1.1\r\nHost: control.invalid\r\nConnection: close\r\n\r\n",
	)); err != nil {
		t.Fatalf("write OPTIONS request: %v", err)
	}
	response, err := http.ReadResponse(
		bufio.NewReader(connection),
		&http.Request{Method: http.MethodOptions},
	)
	if err != nil {
		t.Fatalf("read OPTIONS response: %v", err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("OPTIONS * status = %d, want 404", response.StatusCode)
	}
}

func TestServerRejectsDisallowedPeerUID(t *testing.T) {
	otherUID := uint32(os.Getuid()) + 1
	server := startTestServer(t, ServerConfig{
		SocketPath:  testSocketPath(t),
		AllowedUIDs: []uint32{otherUID},
	})
	client, err := NewClient(ClientConfig{SocketPath: server.SocketPath(), Peer: v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	if _, err := client.GetCapabilities(ctx); err == nil {
		t.Fatal("GetCapabilities() from disallowed UID succeeded")
	}
}

func TestClientRejectsInsecureOrNonSocketEndpoint(t *testing.T) {
	t.Run("insecure mode", func(t *testing.T) {
		server, err := ListenServer(ServerConfig{SocketPath: testSocketPath(t), AllowedUIDs: []uint32{uint32(os.Getuid())}})
		if err != nil {
			t.Fatal(err)
		}
		defer server.Close()
		if err := os.Chmod(server.SocketPath(), 0o660); err != nil {
			t.Fatal(err)
		}
		if _, err := NewClient(ClientConfig{SocketPath: server.SocketPath()}); err == nil {
			t.Fatal("NewClient() accepted socket mode 0660")
		}
	})

	t.Run("regular file", func(t *testing.T) {
		path := testSocketPath(t)
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewClient(ClientConfig{SocketPath: path}); err == nil {
			t.Fatal("NewClient() accepted a regular file")
		}
	})
}

func TestServerAndClientUseDistinctSocketDirectoryOwnershipPolicies(t *testing.T) {
	parent := filepath.Dir(testSocketPath(t))
	path := filepath.Join(parent, "control.sock")
	owner := uint32(os.Getuid())
	if err := validateServerSocketPath(path); err != nil {
		t.Fatalf("validateServerSocketPath() error = %v", err)
	}
	if err := validateClientSocketPath(path, owner); err != nil {
		t.Fatalf("validateClientSocketPath(socket owner) error = %v", err)
	}
	if err := validateClientSocketPath(path, owner+1); err == nil {
		t.Fatal("validateClientSocketPath() accepted a parent not owned by the socket UID")
	}
}

func TestClientPerformsHandshakeBeforeCapabilitiesAndChecksRequestDigest(t *testing.T) {
	service := &scriptedControlService{}
	path := startScriptedServer(t, service)
	client, err := NewClient(ClientConfig{SocketPath: path, Peer: v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := client.GetCapabilities(ctx); err != nil {
		t.Fatalf("GetCapabilities() error = %v", err)
	}
	if service.handshakeCalls.Load() != 1 || service.capabilityCalls.Load() != 1 {
		t.Fatalf("calls = handshake:%d capabilities:%d, want 1 then 1", service.handshakeCalls.Load(), service.capabilityCalls.Load())
	}
	if !service.sawValidDigest.Load() {
		t.Fatal("client sent a noncanonical request digest")
	}
}

func TestClientRejectsUnnegotiatedHandshakeFeatures(t *testing.T) {
	path := startScriptedServer(t, &scriptedControlService{mutateHandshake: func(response *v1.HandshakeResponse) {
		response.FeatureBitmap = 1 << uint64(v1.ProtocolFeature_PROTOCOL_FEATURE_PROCESS_STREAMING)
	}})
	client, err := NewClient(ClientConfig{SocketPath: path})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = client.GetCapabilities(ctx)
	if got := connect.CodeOf(err); got != connect.CodeDataLoss {
		t.Fatalf("GetCapabilities() code = %v error=%v, want data_loss", got, err)
	}
}

func TestHandshakeCannotNegotiateAnUnenforcedFrameLimit(t *testing.T) {
	t.Run("server rejects smaller proposal", func(t *testing.T) {
		server := startTestServer(t, ServerConfig{SocketPath: testSocketPath(t), AllowedUIDs: []uint32{uint32(os.Getuid())}})
		raw, closeRaw := rawControlClient(t, server.SocketPath())
		defer closeRaw()
		request := handshakeRequest(t, v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL)
		request.MaximumFrameSize = maximumMessageBytes - 1
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, err := raw.Handshake(ctx, connect.NewRequest(request))
		if got := connect.CodeOf(err); got != connect.CodeFailedPrecondition {
			t.Fatalf("Handshake() code = %v error=%v, want failed_precondition", got, err)
		}
	})

	t.Run("client rejects smaller selection", func(t *testing.T) {
		path := startScriptedServer(t, &scriptedControlService{mutateHandshake: func(response *v1.HandshakeResponse) {
			response.MaximumFrameSize = maximumMessageBytes - 1
		}})
		client, err := NewClient(ClientConfig{SocketPath: path})
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, err = client.GetCapabilities(ctx)
		if got := connect.CodeOf(err); got != connect.CodeDataLoss {
			t.Fatalf("GetCapabilities() code = %v error=%v, want data_loss", got, err)
		}
	})
}

func TestControlServerRejectsWrongPeerVersionAndDeadlineAtWireBoundary(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*v1.HandshakeRequest, *v1.GetCapabilitiesRequest)
		wantCode connect.Code
	}{
		{
			name: "wrong logical peer",
			mutate: func(handshake *v1.HandshakeRequest, _ *v1.GetCapabilitiesRequest) {
				handshake.Peer = v1.ProtocolPeer_PROTOCOL_PEER_AGENTD
			},
			wantCode: connect.CodePermissionDenied,
		},
		{
			name: "unsupported handshake version",
			mutate: func(handshake *v1.HandshakeRequest, _ *v1.GetCapabilitiesRequest) {
				handshake.MinimumVersion = &v1.ProtocolVersion{Major: 2}
				handshake.MaximumVersion = &v1.ProtocolVersion{Major: 2}
			},
			wantCode: connect.CodeFailedPrecondition,
		},
		{
			name: "unsupported request version",
			mutate: func(_ *v1.HandshakeRequest, request *v1.GetCapabilitiesRequest) {
				request.Meta.ProtocolVersion = &v1.ProtocolVersion{Major: 2}
			},
			wantCode: connect.CodeFailedPrecondition,
		},
		{
			name: "missing request deadline",
			mutate: func(_ *v1.HandshakeRequest, request *v1.GetCapabilitiesRequest) {
				request.Meta.DeadlineUnixMs = 0
			},
			wantCode: connect.CodeInvalidArgument,
		},
		{
			name: "expired request deadline",
			mutate: func(_ *v1.HandshakeRequest, request *v1.GetCapabilitiesRequest) {
				request.Meta.DeadlineUnixMs = uint64(time.Now().Add(-time.Second).UnixMilli())
			},
			wantCode: connect.CodeDeadlineExceeded,
		},
		{
			name: "unbounded future request deadline",
			mutate: func(_ *v1.HandshakeRequest, request *v1.GetCapabilitiesRequest) {
				request.Meta.DeadlineUnixMs = uint64(time.Now().Add(5*time.Minute + time.Second).UnixMilli())
			},
			wantCode: connect.CodeInvalidArgument,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := startTestServer(t, ServerConfig{
				SocketPath:  testSocketPath(t),
				AllowedUIDs: []uint32{uint32(os.Getuid())},
			})
			raw, closeRaw := rawControlClient(t, server.SocketPath())
			defer closeRaw()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			handshake := handshakeRequest(t, v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL)
			request := &v1.GetCapabilitiesRequest{Meta: &v1.RpcRequestMeta{
				RequestId:       &v1.OpaqueId{Value: []byte("0123456789abcdef")},
				DeadlineUnixMs:  uint64(time.Now().Add(time.Second).UnixMilli()),
				ProtocolVersion: protocolVersion(),
			}}
			test.mutate(handshake, request)
			handshakeResponse, err := raw.Handshake(ctx, connect.NewRequest(handshake))
			if test.name == "wrong logical peer" || test.name == "unsupported handshake version" {
				if got := connect.CodeOf(err); got != test.wantCode {
					t.Fatalf("Handshake() code = %v error=%v, want %v", got, err, test.wantCode)
				}
				return
			}
			if err != nil {
				t.Fatalf("Handshake() error = %v", err)
			}
			request.Meta.RequestDigest, err = getCapabilitiesRequestDigest(request)
			if err != nil {
				t.Fatal(err)
			}
			wrapped := connect.NewRequest(request)
			wrapped.Header().Set(sessionHeader, handshakeResponse.Header().Get(sessionHeader))
			_, err = raw.GetCapabilities(ctx, wrapped)
			if got := connect.CodeOf(err); got != test.wantCode {
				t.Fatalf("GetCapabilities() code = %v error=%v, want %v", got, err, test.wantCode)
			}
		})
	}
}

func TestControlRPCPropagatesExplicitInFlightCancellation(t *testing.T) {
	providerStarted := make(chan struct{})
	providerCanceled := make(chan struct{})
	server := startTestServer(t, ServerConfig{
		SocketPath:  testSocketPath(t),
		AllowedUIDs: []uint32{uint32(os.Getuid())},
		CapabilityProvider: func(ctx context.Context) ([]*v1.CapabilityStatus, error) {
			close(providerStarted)
			<-ctx.Done()
			close(providerCanceled)
			return nil, ctx.Err()
		},
	})
	client, err := NewClient(ClientConfig{SocketPath: server.SocketPath()})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, callErr := client.GetCapabilities(ctx)
		result <- callErr
	}()
	select {
	case <-providerStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("provider did not start")
	}
	cancel()
	select {
	case err := <-result:
		if got := connect.CodeOf(err); got != connect.CodeCanceled {
			t.Fatalf("GetCapabilities() code = %v error=%v, want canceled", got, err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("canceled call did not return")
	}
	select {
	case <-providerCanceled:
	case <-time.After(3 * time.Second):
		t.Fatal("provider did not observe cancellation")
	}
}

func TestGetCapabilitiesRequestDigestIsDeterministicAndNonMutating(t *testing.T) {
	request := &v1.GetCapabilitiesRequest{Meta: &v1.RpcRequestMeta{
		RequestId:       &v1.OpaqueId{Value: []byte("request-id")},
		RequestDigest:   &v1.Digest{Algorithm: v1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: []byte("leave-intact")},
		DeadlineUnixMs:  123456,
		IdempotencyKey:  []byte("idempotency"),
		ProtocolVersion: protocolVersion(),
	}}
	before := proto.Clone(request).(*v1.GetCapabilitiesRequest)
	first, err := getCapabilitiesRequestDigest(request)
	if err != nil {
		t.Fatalf("getCapabilitiesRequestDigest() error = %v", err)
	}
	second, err := getCapabilitiesRequestDigest(proto.Clone(request).(*v1.GetCapabilitiesRequest))
	if err != nil {
		t.Fatalf("second getCapabilitiesRequestDigest() error = %v", err)
	}
	if !proto.Equal(first, second) {
		t.Fatalf("deterministic digests differ: %x != %x", first.GetValue(), second.GetValue())
	}
	if !proto.Equal(request, before) {
		t.Fatal("getCapabilitiesRequestDigest() mutated its input")
	}
	changed := proto.Clone(request).(*v1.GetCapabilitiesRequest)
	changed.Meta.RequestId.Value[0] ^= 0xff
	third, err := getCapabilitiesRequestDigest(changed)
	if err != nil {
		t.Fatal(err)
	}
	if proto.Equal(first, third) {
		t.Fatal("different requests produced the same digest")
	}
}

func TestServerRejectsInvalidRequestDigestWithStructuredCode(t *testing.T) {
	server := startTestServer(t, ServerConfig{SocketPath: testSocketPath(t), AllowedUIDs: []uint32{uint32(os.Getuid())}})
	raw, closeRaw := rawControlClient(t, server.SocketPath())
	defer closeRaw()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	handshake := connect.NewRequest(handshakeRequest(t, v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL))
	handshakeResponse, err := raw.Handshake(ctx, handshake)
	if err != nil {
		t.Fatalf("Handshake() error = %v", err)
	}
	request := connect.NewRequest(&v1.GetCapabilitiesRequest{Meta: &v1.RpcRequestMeta{
		RequestId:       &v1.OpaqueId{Value: []byte("0123456789abcdef")},
		RequestDigest:   sha256Digest([]byte("wrong")),
		DeadlineUnixMs:  uint64(time.Now().Add(time.Second).UnixMilli()),
		ProtocolVersion: protocolVersion(),
	}})
	request.Header().Set(sessionHeader, handshakeResponse.Header().Get(sessionHeader))
	_, err = raw.GetCapabilities(ctx, request)
	if got := connect.CodeOf(err); got != connect.CodeInvalidArgument {
		t.Fatalf("GetCapabilities() code = %v error=%v, want invalid_argument", got, err)
	}
}

func TestPinnedProtocolRejectsUnknownFields(t *testing.T) {
	t.Run("server handshake request", func(t *testing.T) {
		server := startTestServer(t, ServerConfig{SocketPath: testSocketPath(t), AllowedUIDs: []uint32{uint32(os.Getuid())}})
		raw, closeRaw := rawControlClient(t, server.SocketPath())
		defer closeRaw()
		request := handshakeRequest(t, v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL)
		markUnknown(request)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, err := raw.Handshake(ctx, connect.NewRequest(request))
		if got := connect.CodeOf(err); got != connect.CodeInvalidArgument {
			t.Fatalf("Handshake() code = %v error=%v, want invalid_argument", got, err)
		}
	})

	t.Run("server capabilities request", func(t *testing.T) {
		server := startTestServer(t, ServerConfig{SocketPath: testSocketPath(t), AllowedUIDs: []uint32{uint32(os.Getuid())}})
		raw, closeRaw := rawControlClient(t, server.SocketPath())
		defer closeRaw()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		handshakeResponse, err := raw.Handshake(ctx, connect.NewRequest(handshakeRequest(t, v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL)))
		if err != nil {
			t.Fatal(err)
		}
		request := &v1.GetCapabilitiesRequest{Meta: &v1.RpcRequestMeta{
			RequestId:       &v1.OpaqueId{Value: []byte("0123456789abcdef")},
			DeadlineUnixMs:  uint64(time.Now().Add(time.Second).UnixMilli()),
			ProtocolVersion: protocolVersion(),
		}}
		markUnknown(request.Meta)
		request.Meta.RequestDigest, err = getCapabilitiesRequestDigest(request)
		if err != nil {
			t.Fatal(err)
		}
		wrapped := connect.NewRequest(request)
		wrapped.Header().Set(sessionHeader, handshakeResponse.Header().Get(sessionHeader))
		_, err = raw.GetCapabilities(ctx, wrapped)
		if got := connect.CodeOf(err); got != connect.CodeInvalidArgument {
			t.Fatalf("GetCapabilities() code = %v error=%v, want invalid_argument", got, err)
		}
	})

	t.Run("client handshake response", func(t *testing.T) {
		path := startScriptedServer(t, &scriptedControlService{mutateHandshake: func(response *v1.HandshakeResponse) {
			markUnknown(response)
		}})
		client, err := NewClient(ClientConfig{SocketPath: path})
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, err = client.GetCapabilities(ctx)
		if got := connect.CodeOf(err); got != connect.CodeDataLoss {
			t.Fatalf("GetCapabilities() code = %v error=%v, want data_loss", got, err)
		}
	})

	t.Run("client capabilities response", func(t *testing.T) {
		path := startScriptedServer(t, &scriptedControlService{mutateResponse: func(response *v1.GetCapabilitiesResponse) {
			markUnknown(response.Meta)
		}})
		client, err := NewClient(ClientConfig{SocketPath: path})
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, err = client.GetCapabilities(ctx)
		if got := connect.CodeOf(err); got != connect.CodeDataLoss {
			t.Fatalf("GetCapabilities() code = %v error=%v, want data_loss", got, err)
		}
	})
}

func TestClientRejectsMismatchedResponseBindings(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*v1.GetCapabilitiesResponse)
	}{
		{name: "request ID", mutate: func(response *v1.GetCapabilitiesResponse) { response.Meta.RequestId.Value[0] ^= 0xff }},
		{name: "metadata descriptor", mutate: func(response *v1.GetCapabilitiesResponse) { response.Meta.DescriptorDigest.Value[0] ^= 0xff }},
		{name: "body descriptor", mutate: func(response *v1.GetCapabilitiesResponse) { response.DescriptorDigest.Value[0] ^= 0xff }},
		{name: "protocol version", mutate: func(response *v1.GetCapabilitiesResponse) { response.ProtocolVersion.Minor = 1 }},
		{name: "zero sequence", mutate: func(response *v1.GetCapabilitiesResponse) { response.Meta.ServerSequence = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := startScriptedServer(t, &scriptedControlService{mutateResponse: test.mutate})
			client, err := NewClient(ClientConfig{SocketPath: path, Peer: v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, err = client.GetCapabilities(ctx)
			if got := connect.CodeOf(err); got != connect.CodeDataLoss {
				t.Fatalf("GetCapabilities() code = %v error=%v, want data_loss", got, err)
			}
		})
	}
}

func TestControlRPCLimitsMessagesToOneMiB(t *testing.T) {
	t.Run("server read", func(t *testing.T) {
		server := startTestServer(t, ServerConfig{SocketPath: testSocketPath(t), AllowedUIDs: []uint32{uint32(os.Getuid())}})
		raw, closeRaw := rawControlClient(t, server.SocketPath())
		defer closeRaw()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		handshakeResponse, err := raw.Handshake(ctx, connect.NewRequest(handshakeRequest(t, v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL)))
		if err != nil {
			t.Fatal(err)
		}
		request := &v1.GetCapabilitiesRequest{Meta: &v1.RpcRequestMeta{
			RequestId:       &v1.OpaqueId{Value: []byte("0123456789abcdef")},
			DeadlineUnixMs:  uint64(time.Now().Add(time.Second).UnixMilli()),
			IdempotencyKey:  make([]byte, maximumMessageBytes),
			ProtocolVersion: protocolVersion(),
		}}
		request.Meta.RequestDigest, err = getCapabilitiesRequestDigest(request)
		if err != nil {
			t.Fatal(err)
		}
		wrapped := connect.NewRequest(request)
		wrapped.Header().Set(sessionHeader, handshakeResponse.Header().Get(sessionHeader))
		_, err = raw.GetCapabilities(ctx, wrapped)
		if got := connect.CodeOf(err); got != connect.CodeResourceExhausted {
			t.Fatalf("oversize request code = %v error=%v, want resource_exhausted", got, err)
		}
	})

	t.Run("server send and client read", func(t *testing.T) {
		server := startTestServer(t, ServerConfig{
			SocketPath:  testSocketPath(t),
			AllowedUIDs: []uint32{uint32(os.Getuid())},
			Capabilities: []*v1.CapabilityStatus{{
				Name:         strings.Repeat("x", maximumMessageBytes),
				Availability: v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_AVAILABLE,
			}},
		})
		client, err := NewClient(ClientConfig{SocketPath: server.SocketPath()})
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, err = client.GetCapabilities(ctx)
		if got := connect.CodeOf(err); got != connect.CodeResourceExhausted {
			t.Fatalf("oversize response code = %v error=%v, want resource_exhausted", got, err)
		}
	})
}

func TestControlRPCPropagatesDeadlineCancellationAndConnectCodes(t *testing.T) {
	var calls atomic.Uint64
	cancelObserved := make(chan struct{}, 1)
	server := startTestServer(t, ServerConfig{
		SocketPath:  testSocketPath(t),
		AllowedUIDs: []uint32{uint32(os.Getuid())},
		CapabilityProvider: func(ctx context.Context) ([]*v1.CapabilityStatus, error) {
			if calls.Add(1) == 1 {
				return nil, nil
			}
			<-ctx.Done()
			cancelObserved <- struct{}{}
			return nil, ctx.Err()
		},
	})
	client, err := NewClient(ClientConfig{SocketPath: server.SocketPath()})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	warmup, warmupCancel := context.WithTimeout(context.Background(), 3*time.Second)
	_, err = client.GetCapabilities(warmup)
	warmupCancel()
	if err != nil {
		t.Fatalf("warmup GetCapabilities() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = client.GetCapabilities(ctx)
	if got := connect.CodeOf(err); got != connect.CodeDeadlineExceeded {
		t.Fatalf("deadline code = %v error=%v, want deadline_exceeded", got, err)
	}
	select {
	case <-cancelObserved:
	case <-time.After(time.Second):
		t.Fatal("server provider did not observe request cancellation")
	}

	errorServer := startTestServer(t, ServerConfig{
		SocketPath:  testSocketPath(t),
		AllowedUIDs: []uint32{uint32(os.Getuid())},
		CapabilityProvider: func(context.Context) ([]*v1.CapabilityStatus, error) {
			return nil, connect.NewError(connect.CodeUnavailable, errors.New("offline"))
		},
	})
	errorClient, err := NewClient(ClientConfig{SocketPath: errorServer.SocketPath()})
	if err != nil {
		t.Fatal(err)
	}
	defer errorClient.Close()
	errorCtx, errorCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer errorCancel()
	_, err = errorClient.GetCapabilities(errorCtx)
	if got := connect.CodeOf(err); got != connect.CodeUnavailable {
		t.Fatalf("provider code = %v error=%v, want unavailable", got, err)
	}
}

func TestServerEnforcesMetadataDeadlineOnProviderContext(t *testing.T) {
	providerCanceled := make(chan struct{}, 1)
	server := startTestServer(t, ServerConfig{
		SocketPath:  testSocketPath(t),
		AllowedUIDs: []uint32{uint32(os.Getuid())},
		CapabilityProvider: func(ctx context.Context) ([]*v1.CapabilityStatus, error) {
			<-ctx.Done()
			providerCanceled <- struct{}{}
			return nil, ctx.Err()
		},
	})
	raw, closeRaw := rawControlClient(t, server.SocketPath())
	defer closeRaw()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	handshakeResponse, err := raw.Handshake(ctx, connect.NewRequest(handshakeRequest(t, v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL)))
	if err != nil {
		t.Fatal(err)
	}
	request := &v1.GetCapabilitiesRequest{Meta: &v1.RpcRequestMeta{
		RequestId:       &v1.OpaqueId{Value: []byte("0123456789abcdef")},
		DeadlineUnixMs:  uint64(time.Now().Add(75 * time.Millisecond).UnixMilli()),
		ProtocolVersion: protocolVersion(),
	}}
	request.Meta.RequestDigest, err = getCapabilitiesRequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	wrapped := connect.NewRequest(request)
	wrapped.Header().Set(sessionHeader, handshakeResponse.Header().Get(sessionHeader))
	started := time.Now()
	_, err = raw.GetCapabilities(ctx, wrapped)
	if got := connect.CodeOf(err); got != connect.CodeDeadlineExceeded {
		t.Fatalf("metadata deadline code = %v error=%v, want deadline_exceeded", got, err)
	}
	if elapsed := time.Since(started); elapsed >= 500*time.Millisecond {
		t.Fatalf("metadata deadline took %v, want provider cancellation before transport deadline", elapsed)
	}
	select {
	case <-providerCanceled:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("provider did not observe metadata deadline cancellation")
	}
}

func TestServerRejectsProviderSuccessAfterMetadataDeadline(t *testing.T) {
	server := startTestServer(t, ServerConfig{
		SocketPath:  testSocketPath(t),
		AllowedUIDs: []uint32{uint32(os.Getuid())},
		CapabilityProvider: func(context.Context) ([]*v1.CapabilityStatus, error) {
			time.Sleep(125 * time.Millisecond)
			return []*v1.CapabilityStatus{{
				Name:         "stale.success",
				Availability: v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_AVAILABLE,
			}}, nil
		},
	})
	raw, closeRaw := rawControlClient(t, server.SocketPath())
	defer closeRaw()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	handshakeResponse, err := raw.Handshake(ctx, connect.NewRequest(handshakeRequest(t, v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL)))
	if err != nil {
		t.Fatal(err)
	}
	request := &v1.GetCapabilitiesRequest{Meta: &v1.RpcRequestMeta{
		RequestId:       &v1.OpaqueId{Value: []byte("0123456789abcdef")},
		DeadlineUnixMs:  uint64(time.Now().Add(50 * time.Millisecond).UnixMilli()),
		ProtocolVersion: protocolVersion(),
	}}
	request.Meta.RequestDigest, err = getCapabilitiesRequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	wrapped := connect.NewRequest(request)
	wrapped.Header().Set(sessionHeader, handshakeResponse.Header().Get(sessionHeader))
	response, err := raw.GetCapabilities(ctx, wrapped)
	if got := connect.CodeOf(err); got != connect.CodeDeadlineExceeded {
		t.Fatalf("late provider success response=%v code=%v error=%v, want deadline_exceeded", response, got, err)
	}
}

func TestConcurrentCallersReceiveUniqueMonotonicSequences(t *testing.T) {
	server := startTestServer(t, ServerConfig{SocketPath: testSocketPath(t), AllowedUIDs: []uint32{uint32(os.Getuid())}})
	client, err := NewClient(ClientConfig{SocketPath: server.SocketPath()})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	const callers = 64
	sequences := make([]uint64, callers)
	requestIDs := make([]string, callers)
	errorsByCaller := make([]error, callers)
	var wait sync.WaitGroup
	wait.Add(callers)
	for index := range callers {
		go func() {
			defer wait.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			response, callErr := client.GetCapabilities(ctx)
			errorsByCaller[index] = callErr
			if callErr == nil {
				sequences[index] = response.GetMeta().GetServerSequence()
				requestIDs[index] = hex.EncodeToString(response.GetMeta().GetRequestId().GetValue())
			}
		}()
	}
	wait.Wait()
	for index, callErr := range errorsByCaller {
		if callErr != nil {
			t.Fatalf("caller %d error = %v", index, callErr)
		}
	}
	sort.Slice(sequences, func(left, right int) bool { return sequences[left] < sequences[right] })
	for index, sequence := range sequences {
		if want := uint64(index + 1); sequence != want {
			t.Fatalf("sorted sequence[%d] = %d, want %d", index, sequence, want)
		}
	}
	seen := make(map[string]struct{}, callers)
	for _, requestID := range requestIDs {
		if requestID == "" {
			t.Fatal("empty request ID")
		}
		if _, exists := seen[requestID]; exists {
			t.Fatalf("duplicate request ID %q", requestID)
		}
		seen[requestID] = struct{}{}
	}
}

func TestClosedClientFailsWithoutNetworkReuse(t *testing.T) {
	server := startTestServer(t, ServerConfig{SocketPath: testSocketPath(t), AllowedUIDs: []uint32{uint32(os.Getuid())}})
	client, err := NewClient(ClientConfig{SocketPath: server.SocketPath()})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = client.GetCapabilities(ctx)
	if got := connect.CodeOf(err); got != connect.CodeFailedPrecondition {
		t.Fatalf("closed client code = %v error=%v, want failed_precondition", got, err)
	}
}

func TestServerClosePreservesFirstCleanupError(t *testing.T) {
	server, err := ListenServer(ServerConfig{
		SocketPath:  testSocketPath(t),
		AllowedUIDs: []uint32{uint32(os.Getuid())},
	})
	if err != nil {
		t.Fatalf("ListenServer() error = %v", err)
	}
	cleanupErr := errors.New("listener cleanup failed")
	server.listener = &closeErrorListener{
		Listener: server.listener,
		err:      cleanupErr,
	}

	if err := server.Close(); !errors.Is(err, cleanupErr) {
		t.Fatalf("first Close() error = %v, want %v", err, cleanupErr)
	}
	if err := server.Close(); !errors.Is(err, cleanupErr) {
		t.Fatalf("second Close() error = %v, want preserved %v", err, cleanupErr)
	}
}

func TestServerServeReturnsCleanupErrorOnContextCancellation(t *testing.T) {
	server, err := ListenServer(ServerConfig{
		SocketPath:  testSocketPath(t),
		AllowedUIDs: []uint32{uint32(os.Getuid())},
	})
	if err != nil {
		t.Fatalf("ListenServer() error = %v", err)
	}
	cleanupErr := errors.New("listener cleanup failed")
	acceptStarted := make(chan struct{})
	server.listener = &closeErrorListener{
		Listener:      server.listener,
		err:           cleanupErr,
		acceptStarted: acceptStarted,
	}

	ctx, cancel := context.WithCancel(context.Background())
	serveError := make(chan error, 1)
	go func() { serveError <- server.Serve(ctx) }()
	select {
	case <-acceptStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("Server.Serve() did not begin accepting connections")
	}
	cancel()
	select {
	case err := <-serveError:
		if !errors.Is(err, cleanupErr) {
			t.Fatalf("Server.Serve() error = %v, want cleanup error %v", err, cleanupErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Server.Serve() did not stop after context cancellation")
	}
}

type closeErrorListener struct {
	net.Listener
	err           error
	acceptStarted chan struct{}
	acceptOnce    sync.Once
}

func (listener *closeErrorListener) Accept() (net.Conn, error) {
	if listener.acceptStarted != nil {
		listener.acceptOnce.Do(func() { close(listener.acceptStarted) })
	}
	return listener.Listener.Accept()
}

func (listener *closeErrorListener) Close() error {
	_ = listener.Listener.Close()
	return listener.err
}

type scriptedControlService struct {
	v1connect.UnimplementedControlServiceHandler
	handshakeCalls  atomic.Uint64
	capabilityCalls atomic.Uint64
	sequence        atomic.Uint64
	sawValidDigest  atomic.Bool
	mutateHandshake func(*v1.HandshakeResponse)
	mutateResponse  func(*v1.GetCapabilitiesResponse)
}

func (service *scriptedControlService) Handshake(_ context.Context, request *connect.Request[v1.HandshakeRequest]) (*connect.Response[v1.HandshakeResponse], error) {
	service.handshakeCalls.Add(1)
	message := &v1.HandshakeResponse{
		SelectedVersion:  protocolVersion(),
		MaximumFrameSize: maximumMessageBytes,
		DescriptorDigest: descriptorDigest(),
		ServerPeer:       v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD,
		Status: &v1.CapabilityStatus{
			Name:         "control.protocol",
			Availability: v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_AVAILABLE,
		},
		NonceProof: nonceProof(request.Msg.GetOneTimeNonce(), v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD),
	}
	if service.mutateHandshake != nil {
		service.mutateHandshake(message)
	}
	response := connect.NewResponse(message)
	response.Header().Set(sessionHeader, "scripted-session")
	return response, nil
}

func (service *scriptedControlService) GetCapabilities(_ context.Context, request *connect.Request[v1.GetCapabilitiesRequest]) (*connect.Response[v1.GetCapabilitiesResponse], error) {
	if service.handshakeCalls.Load() == 0 {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("handshake required"))
	}
	service.capabilityCalls.Add(1)
	expected, err := getCapabilitiesRequestDigest(request.Msg)
	if err == nil && proto.Equal(expected, request.Msg.GetMeta().GetRequestDigest()) {
		service.sawValidDigest.Store(true)
	}
	response := &v1.GetCapabilitiesResponse{
		Meta: &v1.RpcResponseMeta{
			RequestId:        proto.Clone(request.Msg.GetMeta().GetRequestId()).(*v1.OpaqueId),
			ServerSequence:   service.sequence.Add(1),
			DescriptorDigest: descriptorDigest(),
		},
		ProtocolVersion:  protocolVersion(),
		DescriptorDigest: descriptorDigest(),
	}
	if service.mutateResponse != nil {
		service.mutateResponse(response)
	}
	return connect.NewResponse(response), nil
}

func startTestServer(t *testing.T, config ServerConfig) *Server {
	t.Helper()
	server, err := ListenServer(config)
	if err != nil {
		t.Fatalf("ListenServer() error = %v", err)
	}
	errorChannel := make(chan error, 1)
	go func() { errorChannel <- server.Serve(context.Background()) }()
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("Server.Close() error = %v", err)
		}
		select {
		case err := <-errorChannel:
			if err != nil {
				t.Errorf("Server.Serve() error = %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("Server.Serve() did not stop")
		}
	})
	return server
}

func startScriptedServer(t *testing.T, service v1connect.ControlServiceHandler) string {
	t.Helper()
	path := testSocketPath(t)
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		listener.Close()
		t.Fatal(err)
	}
	_, handler := v1connect.NewControlServiceHandler(service,
		connect.WithReadMaxBytes(maximumMessageBytes),
		connect.WithSendMaxBytes(maximumMessageBytes),
	)
	httpServer := &http.Server{Handler: handler}
	errorChannel := make(chan error, 1)
	go func() {
		err := httpServer.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errorChannel <- err
	}()
	t.Cleanup(func() {
		_ = httpServer.Close()
		select {
		case err := <-errorChannel:
			if err != nil {
				t.Errorf("scripted server error = %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("scripted server did not stop")
		}
	})
	return path
}

func rawControlClient(t *testing.T, socketPath string) (v1connect.ControlServiceClient, func()) {
	t.Helper()
	transport := &http.Transport{
		DisableCompression: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		},
	}
	httpClient := &http.Client{Transport: transport}
	return v1connect.NewControlServiceClient(httpClient, "http://control.invalid"), func() {
		transport.CloseIdleConnections()
	}
}

func handshakeRequest(t *testing.T, peer v1.ProtocolPeer) *v1.HandshakeRequest {
	t.Helper()
	nonce := make([]byte, handshakeNonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	return &v1.HandshakeRequest{
		Peer:             peer,
		MinimumVersion:   protocolVersion(),
		MaximumVersion:   protocolVersion(),
		MaximumFrameSize: maximumMessageBytes,
		DescriptorDigest: descriptorDigest(),
		OneTimeNonce:     nonce,
	}
}

func testSocketPath(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "cr-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Errorf("remove temporary socket directory: %v", err)
		}
	})
	return filepath.Join(directory, "control.sock")
}

func assertDescriptorDigest(t *testing.T, digest *v1.Digest) {
	t.Helper()
	if digest.GetAlgorithm() != v1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256 || hex.EncodeToString(digest.GetValue()) != descriptorSHA256 {
		t.Fatalf("descriptor digest = %v/%x, want sha256:%s", digest.GetAlgorithm(), digest.GetValue(), descriptorSHA256)
	}
}

func markUnknown(message proto.Message) {
	message.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
}
