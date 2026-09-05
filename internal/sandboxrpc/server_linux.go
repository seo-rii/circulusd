//go:build linux

package sandboxrpc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	v1connect "github.com/hancomac/circulusd/api/generated/circulus/v1alpha/circulusv1alphaconnect"
	"github.com/hancomac/circulusd/internal/sandboxd"
	"google.golang.org/protobuf/proto"
)

const (
	maximumUnixSocketPathBytes = 107
	sandboxHTTPIOTimeout       = 5 * time.Second
)

// ServerConfig contains launch-time authority. None of these fields can be
// supplied by a process RPC after the server begins listening.
type ServerConfig struct {
	SocketPath                 string
	AllowedClientUIDs          []uint32
	SandboxID                  []byte
	SandboxGeneration          uint64
	Backend                    v1.ExecutionBackend
	ExecutionEnvironmentDigest []byte
	OneTimeNonce               []byte
	Supervisor                 *sandboxd.Supervisor
}

// Server serves ControlService and SandboxProcessService on one private UDS.
type Server struct {
	socketPath string
	listener   net.Listener
	httpServer *http.Server
	handler    *rpcHandler

	serveMu  sync.Mutex
	served   bool
	closed   atomic.Bool
	close    sync.Once
	closeErr error
}

type rpcHandler struct {
	v1connect.UnimplementedControlServiceHandler
	v1connect.UnimplementedSandboxProcessServiceHandler

	sandboxID                  []byte
	generation                 uint64
	backend                    v1.ExecutionBackend
	executionEnvironmentDigest [sha256.Size]byte
	supervisor                 *sandboxd.Supervisor

	handshakeMu sync.Mutex
	nonce       [handshakeNonceBytes]byte
	nonceUsed   bool
	session     [sessionBytes]byte
	sessionUID  uint32

	processKey [sha256.Size]byte
	sequence   atomic.Uint64

	mu         sync.Mutex
	processes  map[string]*processBinding
	operations map[string]*operationCall
}

type processBinding struct {
	handle sandboxd.ProcessHandle
	wire   *v1.ProcessHandle

	stdinGate        chan struct{}
	acceptedSequence uint64
	acceptedDigest   [sha256.Size]byte
	acceptedBytes    uint64
}

type operationCall struct {
	digest   [sha256.Size]byte
	done     chan struct{}
	response proto.Message
	err      error
}

type peerCredential struct {
	pid int32
	uid uint32
	gid uint32
}

type peerCredentialContextKey struct{}

type credentialConn struct {
	net.Conn
	credential peerCredential
}

type credentialListener struct {
	net.Listener
	allowedUIDs map[uint32]struct{}
}

// ListenServer validates the private socket directory and begins listening.
// Serve must be called exactly once to process requests.
func ListenServer(config ServerConfig) (*Server, error) {
	if err := validateServerSocketPath(config.SocketPath); err != nil {
		return nil, err
	}
	if len(config.AllowedClientUIDs) == 0 {
		return nil, fmt.Errorf("sandboxrpc: allowed client UID list must not be empty")
	}
	allowedUIDs := make(map[uint32]struct{}, len(config.AllowedClientUIDs))
	for _, uid := range config.AllowedClientUIDs {
		allowedUIDs[uid] = struct{}{}
	}
	if !validOpaqueID(config.SandboxID, 256) {
		return nil, fmt.Errorf("sandboxrpc: sandbox ID is invalid")
	}
	if config.SandboxGeneration == 0 {
		return nil, fmt.Errorf("sandboxrpc: sandbox generation must be positive")
	}
	if config.Backend != v1.ExecutionBackend_EXECUTION_BACKEND_NSJAIL &&
		config.Backend != v1.ExecutionBackend_EXECUTION_BACKEND_DOCKER &&
		config.Backend != v1.ExecutionBackend_EXECUTION_BACKEND_FIRECRACKER {
		return nil, fmt.Errorf("sandboxrpc: launch backend is invalid")
	}
	if len(config.ExecutionEnvironmentDigest) != sha256.Size {
		return nil, fmt.Errorf("sandboxrpc: execution environment digest is invalid")
	}
	if len(config.OneTimeNonce) != handshakeNonceBytes {
		return nil, fmt.Errorf("sandboxrpc: one-time nonce must be 32 bytes")
	}
	if config.Supervisor == nil {
		return nil, fmt.Errorf("sandboxrpc: supervisor is required")
	}
	authority := config.Supervisor.LaunchAuthority()
	if authority.SandboxID != string(config.SandboxID) || authority.Generation != config.SandboxGeneration {
		return nil, fmt.Errorf("sandboxrpc: supervisor launch authority does not match the transport")
	}
	if _, err := os.Lstat(config.SocketPath); err == nil {
		return nil, fmt.Errorf("sandboxrpc: socket path already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("sandboxrpc: inspect socket path: %w", err)
	}

	unixListener, err := net.ListenUnix("unix", &net.UnixAddr{Name: config.SocketPath, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("sandboxrpc: listen on Unix socket: %w", err)
	}
	unixListener.SetUnlinkOnClose(true)
	cleanup := func() { _ = unixListener.Close() }
	if err := os.Chmod(config.SocketPath, 0o600); err != nil {
		cleanup()
		return nil, fmt.Errorf("sandboxrpc: set socket permissions: %w", err)
	}
	if _, err := inspectSocket(config.SocketPath); err != nil {
		cleanup()
		return nil, err
	}

	handler := &rpcHandler{
		sandboxID:  append([]byte(nil), config.SandboxID...),
		generation: config.SandboxGeneration,
		backend:    config.Backend,
		supervisor: config.Supervisor,
		processes:  make(map[string]*processBinding),
		operations: make(map[string]*operationCall),
	}
	copy(handler.executionEnvironmentDigest[:], config.ExecutionEnvironmentDigest)
	copy(handler.nonce[:], config.OneTimeNonce)
	if _, err := rand.Read(handler.processKey[:]); err != nil {
		cleanup()
		return nil, fmt.Errorf("sandboxrpc: generate process identity key: %w", err)
	}

	controlPath, controlHandler := v1connect.NewControlServiceHandler(
		handler,
		connect.WithReadMaxBytes(maximumMessageBytes),
		connect.WithSendMaxBytes(maximumMessageBytes),
	)
	processPath, processHandler := v1connect.NewSandboxProcessServiceHandler(
		handler,
		connect.WithReadMaxBytes(maximumMessageBytes),
		connect.WithSendMaxBytes(maximumMessageBytes),
	)
	mux := http.NewServeMux()
	mux.Handle(controlPath, controlHandler)
	mux.Handle(processPath, processHandler)
	listener := &credentialListener{Listener: unixListener, allowedUIDs: allowedUIDs}
	server := &Server{socketPath: config.SocketPath, listener: listener, handler: handler}
	server.httpServer = &http.Server{
		Handler:           mux,
		ReadTimeout:       sandboxHTTPIOTimeout,
		ReadHeaderTimeout: sandboxHTTPIOTimeout,
		// WaitProcess and AttachProcess may legitimately outlive the request-body
		// deadline. Keep the transport horizon beyond the maximum per-RPC
		// metadata deadline while still bounding a client that stops reading.
		WriteTimeout:                 maximumRPCDeadline + sandboxHTTPIOTimeout,
		IdleTimeout:                  30 * time.Second,
		MaxHeaderBytes:               16 << 10,
		DisableGeneralOptionsHandler: true,
		ConnContext: func(ctx context.Context, connection net.Conn) context.Context {
			credentialed, ok := connection.(*credentialConn)
			if !ok {
				return ctx
			}
			return context.WithValue(ctx, peerCredentialContextKey{}, credentialed.credential)
		},
	}
	return server, nil
}

func (server *Server) SocketPath() string {
	if server == nil {
		return ""
	}
	return server.socketPath
}

func (server *Server) Serve(ctx context.Context) error {
	if server == nil {
		return fmt.Errorf("sandboxrpc: server is nil")
	}
	if ctx == nil {
		return fmt.Errorf("sandboxrpc: serve context is nil")
	}
	server.serveMu.Lock()
	if server.served {
		server.serveMu.Unlock()
		return fmt.Errorf("sandboxrpc: server can only be served once")
	}
	server.served = true
	server.serveMu.Unlock()
	if server.closed.Load() {
		return server.Close()
	}
	finished := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = server.Close()
		case <-finished:
		}
	}()
	err := server.httpServer.Serve(server.listener)
	close(finished)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return server.Close()
	}
	if ctx.Err() != nil {
		return errors.Join(err, server.Close())
	}
	return err
}

func (server *Server) Close() error {
	if server == nil {
		return nil
	}
	server.close.Do(func() {
		server.closed.Store(true)
		httpError := server.httpServer.Close()
		listenerError := server.listener.Close()
		server.handler.handshakeMu.Lock()
		clear(server.handler.nonce[:])
		clear(server.handler.session[:])
		server.handler.handshakeMu.Unlock()
		if httpError != nil && !errors.Is(httpError, net.ErrClosed) {
			server.closeErr = httpError
		}
		if listenerError != nil && !errors.Is(listenerError, net.ErrClosed) {
			server.closeErr = errors.Join(server.closeErr, listenerError)
		}
	})
	return server.closeErr
}

func (listener *credentialListener) Accept() (net.Conn, error) {
	for {
		connection, err := listener.Listener.Accept()
		if err != nil {
			return nil, err
		}
		credential, err := socketPeerCredential(connection)
		if err != nil {
			_ = connection.Close()
			continue
		}
		if _, allowed := listener.allowedUIDs[credential.uid]; !allowed {
			_ = connection.Close()
			continue
		}
		return &credentialConn{Conn: connection, credential: credential}, nil
	}
}

func socketPeerCredential(connection net.Conn) (peerCredential, error) {
	syscallConnection, ok := connection.(syscall.Conn)
	if !ok {
		return peerCredential{}, fmt.Errorf("sandboxrpc: Unix connection has no syscall handle")
	}
	raw, err := syscallConnection.SyscallConn()
	if err != nil {
		return peerCredential{}, fmt.Errorf("sandboxrpc: get raw Unix connection: %w", err)
	}
	var credential *syscall.Ucred
	var optionError error
	if err := raw.Control(func(fileDescriptor uintptr) {
		credential, optionError = syscall.GetsockoptUcred(int(fileDescriptor), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return peerCredential{}, fmt.Errorf("sandboxrpc: inspect peer credential: %w", err)
	}
	if optionError != nil || credential == nil {
		return peerCredential{}, fmt.Errorf("sandboxrpc: peer credential is unavailable")
	}
	return peerCredential{pid: credential.Pid, uid: credential.Uid, gid: credential.Gid}, nil
}

func (handler *rpcHandler) Handshake(ctx context.Context, request *connect.Request[v1.HandshakeRequest]) (*connect.Response[v1.HandshakeResponse], error) {
	credential, ok := ctx.Value(peerCredentialContextKey{}).(peerCredential)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("peer credential is unavailable"))
	}
	if request == nil || request.Msg == nil || hasUnknownFields(request.Msg) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("handshake request is invalid"))
	}
	message := request.Msg
	if message.GetPeer() != v1.ProtocolPeer_PROTOCOL_PEER_EXECUTORD {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("protocol peer is not allowed"))
	}
	if !isProtocolVersion(message.GetMinimumVersion()) || !isProtocolVersion(message.GetMaximumVersion()) ||
		!isDescriptorDigest(message.GetDescriptorDigest()) || message.GetFeatureBitmap() != 0 ||
		message.GetMaximumFrameSize() != maximumMessageBytes {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("protocol negotiation failed"))
	}
	if !bytes.Equal(message.GetSandboxId().GetValue(), handler.sandboxID) || message.GetSandboxGeneration() != handler.generation {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("sandbox launch identity mismatch"))
	}
	if len(message.GetOneTimeNonce()) != handshakeNonceBytes {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("launch nonce is invalid"))
	}

	handler.handshakeMu.Lock()
	defer handler.handshakeMu.Unlock()
	if handler.nonceUsed || subtle.ConstantTimeCompare(message.GetOneTimeNonce(), handler.nonce[:]) != 1 {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("launch nonce is unavailable"))
	}
	proof := nonceProof(
		handler.nonce[:],
		handler.sandboxID,
		handler.generation,
		v1.ProtocolPeer_PROTOCOL_PEER_SANDBOXD,
	)
	if _, err := rand.Read(handler.session[:]); err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("cannot establish protocol session"))
	}
	handler.sessionUID = credential.uid
	handler.nonceUsed = true
	clear(handler.nonce[:])
	session := base64.RawURLEncoding.EncodeToString(handler.session[:])
	response := connect.NewResponse(&v1.HandshakeResponse{
		SelectedVersion:  protocolVersion(),
		FeatureBitmap:    0,
		MaximumFrameSize: maximumMessageBytes,
		DescriptorDigest: descriptorDigest(),
		ServerPeer:       v1.ProtocolPeer_PROTOCOL_PEER_SANDBOXD,
		Status: &v1.CapabilityStatus{
			Name:         "sandbox.process",
			Availability: v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_AVAILABLE,
		},
		NonceProof: proof,
	})
	response.Header().Set(sessionHeader, session)
	return response, nil
}

func (handler *rpcHandler) GetCapabilities(ctx context.Context, request *connect.Request[v1.GetCapabilitiesRequest]) (*connect.Response[v1.GetCapabilitiesResponse], error) {
	if request == nil || request.Msg == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("request is missing"))
	}
	requestContext, cancel, err := handler.authorize(ctx, request.Header(), request.Msg, request.Msg.GetMeta())
	if err != nil {
		return nil, err
	}
	defer cancel()
	if err := requestContext.Err(); err != nil {
		return nil, redactedError(err)
	}
	return connect.NewResponse(&v1.GetCapabilitiesResponse{
		Meta: handler.responseMeta(request.Msg.GetMeta()),
		Capabilities: []*v1.CapabilityStatus{{
			Name:         "sandbox.process",
			Availability: v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_AVAILABLE,
		}},
		ProtocolVersion:  protocolVersion(),
		DescriptorDigest: descriptorDigest(),
	}), nil
}

func (handler *rpcHandler) Spawn(ctx context.Context, request *connect.Request[v1.SpawnProcessRequest]) (*connect.Response[v1.SpawnProcessResponse], error) {
	if request == nil || request.Msg == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("request is missing"))
	}
	requestContext, cancel, err := handler.authorize(ctx, request.Header(), request.Msg, request.Msg.GetMeta())
	if err != nil {
		return nil, err
	}
	defer cancel()
	message := request.Msg
	if err := handler.validateSandbox(message.GetSandbox()); err != nil {
		return nil, err
	}
	if message.GetDispatchPermit() == nil || len(message.GetDispatchPermit().GetValue()) < 16 || len(message.GetDispatchPermit().GetValue()) > 4096 ||
		message.GetWorkspaceProtection() == nil || len(message.GetWorkspaceProtection().GetValue()) < 16 || len(message.GetWorkspaceProtection().GetValue()) > 4096 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("opaque execution permits are invalid"))
	}
	// executord authenticates the opaque permit signatures before opening this
	// private channel. sandboxd still fail-closes on every explicit field binding
	// so a valid permit cannot be confused across services, effects, invocations,
	// sandboxes, backends, or generations.
	dispatch := message.GetDispatchPermit()
	workspace := message.GetWorkspaceProtection()
	nowUnixMS := uint64(time.Now().UnixMilli())
	validBackend := message.GetSandbox().GetBackend() == v1.ExecutionBackend_EXECUTION_BACKEND_NSJAIL ||
		message.GetSandbox().GetBackend() == v1.ExecutionBackend_EXECUTION_BACKEND_DOCKER ||
		message.GetSandbox().GetBackend() == v1.ExecutionBackend_EXECUTION_BACKEND_FIRECRACKER
	validWorkspaceAccess := workspace.GetAccessMode() == v1.WorkspaceAccessMode_WORKSPACE_ACCESS_MODE_READ_ONLY ||
		workspace.GetAccessMode() == v1.WorkspaceAccessMode_WORKSPACE_ACCESS_MODE_READ_WRITE
	validReplayPolicy := dispatch.GetReplayPolicy() == v1.ReplayPolicy_REPLAY_POLICY_SAFE ||
		dispatch.GetReplayPolicy() == v1.ReplayPolicy_REPLAY_POLICY_IDEMPOTENCY_KEY ||
		dispatch.GetReplayPolicy() == v1.ReplayPolicy_REPLAY_POLICY_NEVER ||
		dispatch.GetReplayPolicy() == v1.ReplayPolicy_REPLAY_POLICY_CONFIRM
	parentOperation := dispatch.GetParentOperationId()
	validOccurrence := (parentOperation == nil && dispatch.GetOrdinal() == 0) ||
		(parentOperation != nil && validOpaqueID(parentOperation.GetValue(), 256))
	validWorkspaceLease := workspace.GetAccessMode() == v1.WorkspaceAccessMode_WORKSPACE_ACCESS_MODE_READ_ONLY ||
		(validOpaqueID(workspace.GetLeaseId().GetValue(), 256) &&
			workspace.GetLeaseGeneration() > 0 && workspace.GetEnqueueSequence() > 0)
	bindingsMatch := dispatch.GetService() == v1.EffectService_EFFECT_SERVICE_EXECUTOR &&
		dispatch.GetOperation() == "executor.run" && validReplayPolicy && validOccurrence &&
		validBackend && validWorkspaceAccess && validWorkspaceLease &&
		validOpaqueID(dispatch.GetTenantId().GetValue(), 256) &&
		validOpaqueID(dispatch.GetUserId().GetValue(), 256) &&
		validOpaqueID(dispatch.GetSessionId().GetValue(), 256) &&
		validOpaqueID(dispatch.GetTurnId().GetValue(), 256) &&
		validOpaqueID(dispatch.GetEffectId().GetValue(), 256) &&
		validOpaqueID(dispatch.GetInvocationId().GetValue(), 128) &&
		isSHA256Digest(dispatch.GetRequestDigest()) &&
		dispatch.GetDispatchAttempt() > 0 && dispatch.GetTurnLeaseGeneration() > 0 &&
		dispatch.GetPlacementGeneration() > 0 && dispatch.GetSandboxGeneration() > 0 &&
		dispatch.GetAuthorizationGeneration() > 0 && dispatch.GetDeadlineUnixMs() > nowUnixMS &&
		dispatch.GetDeadlineUnixMs() <= math.MaxInt64 &&
		validOpaqueID(workspace.GetTenantId().GetValue(), 256) &&
		validOpaqueID(workspace.GetUserId().GetValue(), 256) &&
		validOpaqueID(workspace.GetWorkspaceId().GetValue(), 256) &&
		validOpaqueID(workspace.GetInvocationId().GetValue(), 128) &&
		validOpaqueID(workspace.GetEffectId().GetValue(), 256) &&
		validOpaqueID(workspace.GetSessionId().GetValue(), 256) &&
		validOpaqueID(workspace.GetSandboxId().GetValue(), 256) &&
		isSHA256Digest(workspace.GetRequestDigest()) &&
		workspace.GetDispatchAttempt() > 0 && workspace.GetTurnLeaseGeneration() > 0 &&
		workspace.GetPlacementGeneration() > 0 && workspace.GetSandboxGeneration() > 0 &&
		workspace.GetProjectionGeneration() > 0 && workspace.GetAuthorizationGeneration() > 0 &&
		workspace.GetIssuedAtUnixMs() > 0 && workspace.GetIssuedAtUnixMs() <= nowUnixMS &&
		workspace.GetIssuedAtUnixMs() <= math.MaxInt64 && workspace.GetExpiresAtUnixMs() <= math.MaxInt64 &&
		workspace.GetMaximumHoldDeadlineUnixMs() <= math.MaxInt64 &&
		workspace.GetIssuedAtUnixMs() < workspace.GetExpiresAtUnixMs() &&
		workspace.GetExpiresAtUnixMs() > nowUnixMS && workspace.GetExpiresAtUnixMs() <= workspace.GetMaximumHoldDeadlineUnixMs() &&
		proto.Equal(dispatch.GetTenantId(), workspace.GetTenantId()) &&
		proto.Equal(dispatch.GetUserId(), workspace.GetUserId()) &&
		proto.Equal(dispatch.GetSessionId(), workspace.GetSessionId()) &&
		proto.Equal(dispatch.GetEffectId(), workspace.GetEffectId()) &&
		proto.Equal(dispatch.GetInvocationId(), message.GetInvocationId()) &&
		proto.Equal(workspace.GetInvocationId(), message.GetInvocationId()) &&
		proto.Equal(dispatch.GetRequestDigest(), message.GetRequestDigest()) &&
		proto.Equal(workspace.GetRequestDigest(), message.GetRequestDigest()) &&
		proto.Equal(workspace.GetSandboxId(), message.GetSandbox().GetSandboxId()) &&
		workspace.GetBackend() == message.GetSandbox().GetBackend() &&
		dispatch.GetDispatchAttempt() == workspace.GetDispatchAttempt() &&
		dispatch.GetTurnLeaseGeneration() == workspace.GetTurnLeaseGeneration() &&
		dispatch.GetPlacementGeneration() == workspace.GetPlacementGeneration() &&
		dispatch.GetSandboxGeneration() == message.GetSandbox().GetGeneration() &&
		workspace.GetSandboxGeneration() == message.GetSandbox().GetGeneration() &&
		dispatch.GetAuthorizationGeneration() == workspace.GetAuthorizationGeneration()
	if !bindingsMatch {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("execution authority bindings mismatch"))
	}
	if !validOpaqueID(message.GetInvocationId().GetValue(), 128) || !isSHA256Digest(message.GetRequestDigest()) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invocation identity or request digest is invalid"))
	}
	command, err := sandboxd.ParseCommandName(message.GetExecutable())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("logical executable is invalid"))
	}
	workingDirectory, err := sandboxd.ParseWorkspacePath(message.GetWorkingDirectory())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("workspace-relative working directory is invalid"))
	}
	if len(message.GetEnvironmentHandles()) != 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("environment handles require a trusted resolver"))
	}
	if message.GetTimeoutMs() == 0 || message.GetTimeoutMs() > uint64(maximumTimeout/time.Millisecond) ||
		message.GetOutputLimitBytes() == 0 || message.GetOutputLimitBytes() > maximumOutputBytes {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("process resource limits are invalid"))
	}
	stdinMode := sandboxd.StdinMode("")
	switch message.GetStdinMode() {
	case v1.StdinMode_STDIN_MODE_CLOSED:
		stdinMode = sandboxd.StdinClosed
	case v1.StdinMode_STDIN_MODE_STREAM:
		stdinMode = sandboxd.StdinStream
	default:
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("stdin mode is invalid"))
	}
	logicalDigest, err := logicalRequestDigest(message)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("cannot bind idempotent request"))
	}

	stored, err := handler.runOnce(requestContext, "spawn", message.GetMeta(), logicalDigest, func() (proto.Message, error) {
		processID := deriveProcessID(handler.processKey, message.GetMeta().GetIdempotencyKey(), logicalDigest)
		result, spawnError := handler.supervisor.Spawn(requestContext, sandboxd.SpawnRequest{
			RequestID:        base64.RawURLEncoding.EncodeToString(message.GetMeta().GetIdempotencyKey()),
			ProcessID:        base64.RawURLEncoding.EncodeToString(processID),
			InvocationID:     base64.RawURLEncoding.EncodeToString(message.GetInvocationId().GetValue()),
			Command:          command,
			Arguments:        append([]string(nil), message.GetArguments()...),
			WorkingDirectory: workingDirectory,
			StdinMode:        stdinMode,
			OutputLimitBytes: int64(message.GetOutputLimitBytes()),
			Deadline:         time.Now().Add(time.Duration(message.GetTimeoutMs()) * time.Millisecond),
		})
		if spawnError != nil {
			return nil, redactedError(spawnError)
		}
		wireHandle := &v1.ProcessHandle{
			SandboxId:    &v1.OpaqueId{Value: append([]byte(nil), handler.sandboxID...)},
			ProcessId:    &v1.OpaqueId{Value: processID},
			InvocationId: proto.Clone(message.GetInvocationId()).(*v1.OpaqueId),
			Generation:   handler.generation,
		}
		handler.mu.Lock()
		if existing := handler.processes[string(processID)]; existing != nil && !proto.Equal(existing.wire, wireHandle) {
			handler.mu.Unlock()
			return nil, connect.NewError(connect.CodeAlreadyExists, errors.New("process identity collision"))
		}
		handler.processes[string(processID)] = &processBinding{
			handle:    result.Handle,
			wire:      proto.Clone(wireHandle).(*v1.ProcessHandle),
			stdinGate: make(chan struct{}, 1),
		}
		handler.mu.Unlock()
		return &v1.SpawnProcessResponse{Process: wireHandle}, nil
	})
	if err != nil {
		return nil, err
	}
	response, ok := stored.(*v1.SpawnProcessResponse)
	if !ok {
		return nil, connect.NewError(connect.CodeInternal, errors.New("idempotency response type mismatch"))
	}
	response.Meta = handler.responseMeta(message.GetMeta())
	return connect.NewResponse(response), nil
}

func (handler *rpcHandler) Attach(ctx context.Context, request *connect.Request[v1.AttachProcessRequest], stream *connect.ServerStream[v1.ProcessEvent]) error {
	if request == nil || request.Msg == nil || stream == nil {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("request is missing"))
	}
	requestContext, cancel, err := handler.authorize(ctx, request.Header(), request.Msg, request.Msg.GetMeta())
	if err != nil {
		return err
	}
	defer cancel()
	binding, err := handler.process(request.Msg.GetProcess())
	if err != nil {
		return err
	}
	attachment, err := handler.supervisor.Attach(requestContext, binding.handle, request.Msg.GetAfterSequence())
	if err != nil {
		return redactedError(err)
	}
	defer attachment.Close()
	for event := range attachment.Events {
		wireEvent := &v1.ProcessEvent{
			Process:  proto.Clone(binding.wire).(*v1.ProcessHandle),
			Sequence: event.Sequence,
		}
		switch event.Type {
		case sandboxd.EventStarted:
			if event.OccurredAt.IsZero() || event.OccurredAt.UnixMilli() <= 0 {
				return connect.NewError(connect.CodeInternal, errors.New("process start event has no timestamp"))
			}
			wireEvent.Event = &v1.ProcessEvent_Started{Started: &v1.ProcessStarted{
				StartedAtUnixMs: uint64(event.OccurredAt.UnixMilli()),
			}}
		case sandboxd.EventStdout:
			if len(event.Data) == 0 || len(event.Data) > maximumMessageBytes {
				return connect.NewError(connect.CodeInternal, errors.New("process stdout event is invalid"))
			}
			wireEvent.Event = &v1.ProcessEvent_Stdout{Stdout: &v1.ProcessOutput{Data: append([]byte(nil), event.Data...)}}
		case sandboxd.EventStderr:
			if len(event.Data) == 0 || len(event.Data) > maximumMessageBytes {
				return connect.NewError(connect.CodeInternal, errors.New("process stderr event is invalid"))
			}
			wireEvent.Event = &v1.ProcessEvent_Stderr{Stderr: &v1.ProcessOutput{Data: append([]byte(nil), event.Data...)}}
		case sandboxd.EventError:
			if event.Error == "" {
				return connect.NewError(connect.CodeInternal, errors.New("process error event is empty"))
			}
			wireEvent.Event = &v1.ProcessEvent_Error{Error: &v1.PublicError{
				Code:    v1.ErrorCode_ERROR_CODE_INTERNAL,
				Reason:  "PROCESS_STREAM_ERROR",
				Message: "sandbox process stream failed",
			}}
		case sandboxd.EventExit:
			result, resultErr := wireProcessResult(event.Result)
			if resultErr != nil {
				return connect.NewError(connect.CodeInternal, resultErr)
			}
			wireEvent.Event = &v1.ProcessEvent_Exit{Exit: result}
		default:
			return connect.NewError(connect.CodeInternal, errors.New("process event type is invalid"))
		}
		if err := stream.Send(wireEvent); err != nil {
			return redactedError(err)
		}
	}
	if err := <-attachment.Done; err != nil {
		return redactedError(err)
	}
	return nil
}

func (handler *rpcHandler) WriteStdin(ctx context.Context, request *connect.Request[v1.WriteStdinRequest]) (*connect.Response[v1.WriteStdinResponse], error) {
	if request == nil || request.Msg == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("request is missing"))
	}
	requestContext, cancel, err := handler.authorize(ctx, request.Header(), request.Msg, request.Msg.GetMeta())
	if err != nil {
		return nil, err
	}
	defer cancel()
	message := request.Msg
	binding, err := handler.process(message.GetProcess())
	if err != nil {
		return nil, err
	}
	if message.GetChunkSequence() == 0 || len(message.GetData()) == 0 || len(message.GetData()) > maximumStdinChunkBytes {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("stdin chunk is invalid"))
	}
	logicalDigest, err := logicalRequestDigest(message)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("cannot bind idempotent request"))
	}
	stored, err := handler.runOnce(requestContext, "write-stdin", message.GetMeta(), logicalDigest, func() (proto.Message, error) {
		select {
		case binding.stdinGate <- struct{}{}:
			defer func() { <-binding.stdinGate }()
		case <-requestContext.Done():
			return nil, redactedError(requestContext.Err())
		}
		if err := requestContext.Err(); err != nil {
			return nil, redactedError(err)
		}
		dataDigest := sha256.Sum256(message.GetData())
		if message.GetChunkSequence() == binding.acceptedSequence {
			if subtle.ConstantTimeCompare(dataDigest[:], binding.acceptedDigest[:]) != 1 {
				return nil, connect.NewError(connect.CodeAlreadyExists, errors.New("stdin sequence conflicts with accepted data"))
			}
			return &v1.WriteStdinResponse{
				AcceptedSequence: binding.acceptedSequence,
				AcceptedBytes:    binding.acceptedBytes,
			}, nil
		}
		if message.GetChunkSequence() != binding.acceptedSequence+1 {
			return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("stdin sequence is not contiguous"))
		}
		if err := handler.supervisor.WriteStdin(requestContext, binding.handle, append([]byte(nil), message.GetData()...)); err != nil {
			return nil, redactedError(err)
		}
		binding.acceptedSequence = message.GetChunkSequence()
		binding.acceptedDigest = dataDigest
		binding.acceptedBytes = uint64(len(message.GetData()))
		return &v1.WriteStdinResponse{
			AcceptedSequence: binding.acceptedSequence,
			AcceptedBytes:    binding.acceptedBytes,
		}, nil
	})
	if err != nil {
		return nil, err
	}
	response, ok := stored.(*v1.WriteStdinResponse)
	if !ok {
		return nil, connect.NewError(connect.CodeInternal, errors.New("idempotency response type mismatch"))
	}
	response.Meta = handler.responseMeta(message.GetMeta())
	return connect.NewResponse(response), nil
}

func (handler *rpcHandler) CloseStdin(ctx context.Context, request *connect.Request[v1.CloseStdinRequest]) (*connect.Response[v1.CloseStdinResponse], error) {
	if request == nil || request.Msg == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("request is missing"))
	}
	requestContext, cancel, err := handler.authorize(ctx, request.Header(), request.Msg, request.Msg.GetMeta())
	if err != nil {
		return nil, err
	}
	defer cancel()
	binding, err := handler.process(request.Msg.GetProcess())
	if err != nil {
		return nil, err
	}
	logicalDigest, err := logicalRequestDigest(request.Msg)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("cannot bind idempotent request"))
	}
	stored, err := handler.runOnce(requestContext, "close-stdin", request.Msg.GetMeta(), logicalDigest, func() (proto.Message, error) {
		if err := handler.supervisor.CloseStdin(requestContext, binding.handle); err != nil {
			return nil, redactedError(err)
		}
		return &v1.CloseStdinResponse{Closed: true}, nil
	})
	if err != nil {
		return nil, err
	}
	response, ok := stored.(*v1.CloseStdinResponse)
	if !ok {
		return nil, connect.NewError(connect.CodeInternal, errors.New("idempotency response type mismatch"))
	}
	response.Meta = handler.responseMeta(request.Msg.GetMeta())
	return connect.NewResponse(response), nil
}

func (handler *rpcHandler) Signal(ctx context.Context, request *connect.Request[v1.SignalProcessRequest]) (*connect.Response[v1.SignalProcessResponse], error) {
	if request == nil || request.Msg == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("request is missing"))
	}
	requestContext, cancel, err := handler.authorize(ctx, request.Header(), request.Msg, request.Msg.GetMeta())
	if err != nil {
		return nil, err
	}
	defer cancel()
	binding, err := handler.process(request.Msg.GetProcess())
	if err != nil {
		return nil, err
	}
	var signal sandboxd.ProcessSignal
	switch request.Msg.GetSignal() {
	case v1.ProcessSignal_PROCESS_SIGNAL_INTERRUPT:
		signal = sandboxd.SignalInterrupt
	case v1.ProcessSignal_PROCESS_SIGNAL_TERMINATE:
		signal = sandboxd.SignalTerminate
	case v1.ProcessSignal_PROCESS_SIGNAL_KILL:
		signal = sandboxd.SignalKill
	default:
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("process signal is unsupported"))
	}
	logicalDigest, err := logicalRequestDigest(request.Msg)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("cannot bind idempotent request"))
	}
	stored, err := handler.runOnce(requestContext, "signal", request.Msg.GetMeta(), logicalDigest, func() (proto.Message, error) {
		if err := handler.supervisor.Signal(requestContext, binding.handle, signal); err != nil {
			return nil, redactedError(err)
		}
		return &v1.SignalProcessResponse{Delivered: true}, nil
	})
	if err != nil {
		return nil, err
	}
	response, ok := stored.(*v1.SignalProcessResponse)
	if !ok {
		return nil, connect.NewError(connect.CodeInternal, errors.New("idempotency response type mismatch"))
	}
	response.Meta = handler.responseMeta(request.Msg.GetMeta())
	return connect.NewResponse(response), nil
}

func (handler *rpcHandler) Cancel(ctx context.Context, request *connect.Request[v1.CancelProcessRequest]) (*connect.Response[v1.CancelProcessResponse], error) {
	if request == nil || request.Msg == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("request is missing"))
	}
	requestContext, cancel, err := handler.authorize(ctx, request.Header(), request.Msg, request.Msg.GetMeta())
	if err != nil {
		return nil, err
	}
	defer cancel()
	if !validProcessString(request.Msg.GetReason(), 1024) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("cancellation reason is invalid"))
	}
	binding, err := handler.process(request.Msg.GetProcess())
	if err != nil {
		return nil, err
	}
	logicalDigest, err := logicalRequestDigest(request.Msg)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("cannot bind idempotent request"))
	}
	stored, err := handler.runOnce(requestContext, "cancel", request.Msg.GetMeta(), logicalDigest, func() (proto.Message, error) {
		if err := handler.supervisor.Signal(requestContext, binding.handle, sandboxd.SignalCancel); err != nil {
			return nil, redactedError(err)
		}
		return &v1.CancelProcessResponse{
			ProcessGroupTerminationStarted: true,
		}, nil
	})
	if err != nil {
		return nil, err
	}
	response, ok := stored.(*v1.CancelProcessResponse)
	if !ok {
		return nil, connect.NewError(connect.CodeInternal, errors.New("idempotency response type mismatch"))
	}
	response.Meta = handler.responseMeta(request.Msg.GetMeta())
	return connect.NewResponse(response), nil
}

func (handler *rpcHandler) Wait(ctx context.Context, request *connect.Request[v1.WaitProcessRequest]) (*connect.Response[v1.WaitProcessResponse], error) {
	if request == nil || request.Msg == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("request is missing"))
	}
	requestContext, cancel, err := handler.authorize(ctx, request.Header(), request.Msg, request.Msg.GetMeta())
	if err != nil {
		return nil, err
	}
	defer cancel()
	binding, err := handler.process(request.Msg.GetProcess())
	if err != nil {
		return nil, err
	}
	logicalDigest, err := logicalRequestDigest(request.Msg)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("cannot bind idempotent request"))
	}
	stored, err := handler.runOnce(requestContext, "wait", request.Msg.GetMeta(), logicalDigest, func() (proto.Message, error) {
		result, waitError := handler.supervisor.Wait(requestContext, binding.handle)
		if waitError != nil {
			return nil, redactedError(waitError)
		}
		state := v1.ProcessLifecycleState_PROCESS_LIFECYCLE_STATE_EXITED
		if result.Reason == sandboxd.ExitReasonFailed || result.Reason == sandboxd.ExitReasonOutputLimit || result.Reason == sandboxd.ExitReasonFenced {
			state = v1.ProcessLifecycleState_PROCESS_LIFECYCLE_STATE_FAILED
		}
		processResult, resultError := wireProcessResult(result)
		if resultError != nil {
			return nil, connect.NewError(connect.CodeInternal, resultError)
		}
		return &v1.WaitProcessResponse{State: state, Result: processResult}, nil
	})
	if err != nil {
		return nil, err
	}
	response, ok := stored.(*v1.WaitProcessResponse)
	if !ok {
		return nil, connect.NewError(connect.CodeInternal, errors.New("idempotency response type mismatch"))
	}
	response.Meta = handler.responseMeta(request.Msg.GetMeta())
	return connect.NewResponse(response), nil
}

func wireProcessResult(result sandboxd.ProcessResult) (*v1.ProcessResult, error) {
	if result.ExitCode < -1<<31 || result.ExitCode > 1<<31-1 || result.FinishedAt.IsZero() || result.FinishedAt.UnixMilli() <= 0 {
		return nil, errors.New("process result is outside the wire representation")
	}
	processResult := &v1.ProcessResult{
		ExitCode:         int32(result.ExitCode),
		FinishedAtUnixMs: uint64(result.FinishedAt.UnixMilli()),
	}
	switch result.Reason {
	case sandboxd.ExitReasonExited, sandboxd.ExitReasonFailed, sandboxd.ExitReasonSignaled:
	case sandboxd.ExitReasonCanceled:
		processResult.Cancelled = true
	case sandboxd.ExitReasonDeadline:
		processResult.TimedOut = true
	case sandboxd.ExitReasonOutputLimit:
		processResult.OutputTruncated = true
	case sandboxd.ExitReasonFenced:
	default:
		return nil, errors.New("process result reason is invalid")
	}
	switch result.Signal {
	case "", sandboxd.SignalCancel:
	case sandboxd.SignalInterrupt:
		processResult.TerminatingSignal = v1.ProcessSignal_PROCESS_SIGNAL_INTERRUPT
	case sandboxd.SignalTerminate:
		processResult.TerminatingSignal = v1.ProcessSignal_PROCESS_SIGNAL_TERMINATE
	case sandboxd.SignalKill:
		processResult.TerminatingSignal = v1.ProcessSignal_PROCESS_SIGNAL_KILL
	default:
		return nil, errors.New("process result signal is invalid")
	}
	return processResult, nil
}

func (handler *rpcHandler) authorize(ctx context.Context, header http.Header, message proto.Message, meta *v1.RpcRequestMeta) (context.Context, context.CancelFunc, error) {
	credential, ok := ctx.Value(peerCredentialContextKey{}).(peerCredential)
	if !ok || !handler.verifySession(header.Get(sessionHeader), credential.uid) {
		return nil, nil, connect.NewError(connect.CodeUnauthenticated, errors.New("protocol session is invalid"))
	}
	if meta == nil || hasUnknownFields(message) {
		return nil, nil, connect.NewError(connect.CodeInvalidArgument, errors.New("request metadata or protocol fields are invalid"))
	}
	if len(meta.GetRequestId().GetValue()) != 16 || len(meta.GetIdempotencyKey()) < 16 || len(meta.GetIdempotencyKey()) > 64 {
		return nil, nil, connect.NewError(connect.CodeInvalidArgument, errors.New("request identity is invalid"))
	}
	if !isProtocolVersion(meta.GetProtocolVersion()) || meta.GetDeadlineUnixMs() == 0 || meta.GetDeadlineUnixMs() > math.MaxInt64 {
		return nil, nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("request protocol or deadline is invalid"))
	}
	deadline := time.UnixMilli(int64(meta.GetDeadlineUnixMs()))
	now := time.Now()
	if !now.Before(deadline) {
		return nil, nil, connect.NewError(connect.CodeDeadlineExceeded, errors.New("request deadline has expired"))
	}
	if deadline.Sub(now) > maximumRPCDeadline {
		return nil, nil, connect.NewError(connect.CodeInvalidArgument, errors.New("request deadline exceeds the protocol bound"))
	}
	expected, err := requestDigest(message)
	if err != nil || !proto.Equal(expected, meta.GetRequestDigest()) {
		return nil, nil, connect.NewError(connect.CodeInvalidArgument, errors.New("request digest mismatch"))
	}
	requestContext, cancel := context.WithDeadline(ctx, deadline)
	return requestContext, cancel, nil
}

func (handler *rpcHandler) verifySession(encoded string, uid uint32) bool {
	token, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(token) != sessionBytes {
		return false
	}
	handler.handshakeMu.Lock()
	defer handler.handshakeMu.Unlock()
	return handler.nonceUsed && handler.sessionUID == uid && subtle.ConstantTimeCompare(token, handler.session[:]) == 1
}

func (handler *rpcHandler) validateSandbox(handle *v1.SandboxHandle) error {
	if handle == nil || !bytes.Equal(handle.GetSandboxId().GetValue(), handler.sandboxID) ||
		handle.GetGeneration() != handler.generation || handle.GetBackend() != handler.backend ||
		!isSHA256Digest(handle.GetExecutionEnvironmentDigest()) ||
		!bytes.Equal(handle.GetExecutionEnvironmentDigest().GetValue(), handler.executionEnvironmentDigest[:]) {
		return connect.NewError(connect.CodeFailedPrecondition, errors.New("sandbox launch authority mismatch"))
	}
	return nil
}

func (handler *rpcHandler) process(handle *v1.ProcessHandle) (*processBinding, error) {
	if handle == nil || !bytes.Equal(handle.GetSandboxId().GetValue(), handler.sandboxID) ||
		handle.GetGeneration() != handler.generation || !validOpaqueID(handle.GetProcessId().GetValue(), 64) ||
		!validOpaqueID(handle.GetInvocationId().GetValue(), 128) {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("process handle is invalid or stale"))
	}
	handler.mu.Lock()
	binding := handler.processes[string(handle.GetProcessId().GetValue())]
	handler.mu.Unlock()
	if binding == nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("process handle is unknown"))
	}
	if !proto.Equal(binding.wire, handle) {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("process handle binding mismatch"))
	}
	return binding, nil
}

func (handler *rpcHandler) runOnce(ctx context.Context, method string, meta *v1.RpcRequestMeta, digest [sha256.Size]byte, execute func() (proto.Message, error)) (proto.Message, error) {
	key := method + "\x00" + string(meta.GetIdempotencyKey())
	handler.mu.Lock()
	if call := handler.operations[key]; call != nil {
		if subtle.ConstantTimeCompare(call.digest[:], digest[:]) != 1 {
			handler.mu.Unlock()
			return nil, connect.NewError(connect.CodeAlreadyExists, errors.New("idempotency key conflicts with another request"))
		}
		handler.mu.Unlock()
		select {
		case <-call.done:
			if call.err != nil {
				return nil, call.err
			}
			return proto.Clone(call.response), nil
		case <-ctx.Done():
			return nil, redactedError(ctx.Err())
		}
	}
	if len(handler.operations) >= maximumIdempotencyKeys {
		handler.mu.Unlock()
		return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("idempotency ledger is full"))
	}
	call := &operationCall{digest: digest, done: make(chan struct{})}
	handler.operations[key] = call
	handler.mu.Unlock()

	response, err := execute()
	if err == nil && response == nil {
		err = connect.NewError(connect.CodeInternal, errors.New("operation returned no response"))
	}
	if err != nil {
		err = redactedError(err)
	}
	handler.mu.Lock()
	if response != nil {
		call.response = proto.Clone(response)
	}
	call.err = err
	close(call.done)
	handler.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return proto.Clone(call.response), nil
}

func (handler *rpcHandler) responseMeta(meta *v1.RpcRequestMeta) *v1.RpcResponseMeta {
	return &v1.RpcResponseMeta{
		RequestId:        proto.Clone(meta.GetRequestId()).(*v1.OpaqueId),
		ServerSequence:   handler.sequence.Add(1),
		DescriptorDigest: descriptorDigest(),
	}
}

func redactedError(err error) error {
	if err == nil {
		return nil
	}
	var connectError *connect.Error
	if errors.As(err, &connectError) {
		message := "sandbox request failed"
		switch connectError.Code() {
		case connect.CodeInvalidArgument:
			message = "sandbox request is invalid"
		case connect.CodeUnauthenticated:
			message = "sandbox request is unauthenticated"
		case connect.CodePermissionDenied:
			message = "sandbox request is forbidden"
		case connect.CodeNotFound:
			message = "sandbox process was not found"
		case connect.CodeAlreadyExists:
			message = "sandbox request conflicts with prior state"
		case connect.CodeFailedPrecondition:
			message = "sandbox process state rejected the request"
		case connect.CodeResourceExhausted:
			message = "sandbox resource bound was exceeded"
		case connect.CodeCanceled:
			return connect.NewError(connect.CodeCanceled, context.Canceled)
		case connect.CodeDeadlineExceeded:
			return connect.NewError(connect.CodeDeadlineExceeded, context.DeadlineExceeded)
		}
		return connect.NewError(connectError.Code(), errors.New(message))
	}
	switch {
	case errors.Is(err, context.Canceled):
		return connect.NewError(connect.CodeCanceled, context.Canceled)
	case errors.Is(err, context.DeadlineExceeded):
		return connect.NewError(connect.CodeDeadlineExceeded, context.DeadlineExceeded)
	case errors.Is(err, sandboxd.ErrInvalidRequest), errors.Is(err, sandboxd.ErrInvalidSignal), errors.Is(err, sandboxd.ErrInvalidCursor):
		return connect.NewError(connect.CodeInvalidArgument, errors.New("process request is invalid"))
	case errors.Is(err, sandboxd.ErrIDConflict):
		return connect.NewError(connect.CodeAlreadyExists, errors.New("process request identity conflicts"))
	case errors.Is(err, sandboxd.ErrCommandNotAllowed):
		return connect.NewError(connect.CodePermissionDenied, errors.New("logical command is not allowed"))
	case errors.Is(err, sandboxd.ErrUnknownProcess):
		return connect.NewError(connect.CodeNotFound, errors.New("process handle is unknown"))
	case errors.Is(err, sandboxd.ErrStaleGeneration), errors.Is(err, sandboxd.ErrSandboxFenced),
		errors.Is(err, sandboxd.ErrStdinClosed), errors.Is(err, sandboxd.ErrProcessExited):
		return connect.NewError(connect.CodeFailedPrecondition, errors.New("process state does not permit this operation"))
	case errors.Is(err, sandboxd.ErrOutputBackpressure):
		return connect.NewError(connect.CodeResourceExhausted, errors.New("process output backpressure limit was exceeded"))
	case errors.Is(err, sandboxd.ErrReplayUnavailable):
		return connect.NewError(connect.CodeOutOfRange, errors.New("requested process replay is unavailable"))
	default:
		return connect.NewError(connect.CodeInternal, errors.New("sandbox process operation failed"))
	}
}

func validateCanonicalSocketPath(path string) error {
	if err := validateCanonicalSocketPathSyntax(path); err != nil {
		return err
	}
	parent := filepath.Dir(path)
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return fmt.Errorf("sandboxrpc: resolve socket directory: %w", err)
	}
	if resolved != parent {
		return fmt.Errorf("sandboxrpc: socket directory contains a symbolic link")
	}
	return nil
}

func validateCanonicalSocketPathSyntax(path string) error {
	if path == "" || strings.IndexByte(path, 0) >= 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return fmt.Errorf("sandboxrpc: socket path must be canonical and absolute")
	}
	if len(path) > maximumUnixSocketPathBytes {
		return fmt.Errorf("sandboxrpc: socket path exceeds Linux sockaddr limit")
	}
	return nil
}

func validateServerSocketPath(path string) error {
	if err := validateCanonicalSocketPath(path); err != nil {
		return err
	}
	return validateSocketDirectory(filepath.Dir(path), uint32(os.Geteuid()))
}

func validateClientSocketPath(path string, ownerUID uint32) error {
	if err := validateCanonicalSocketPath(path); err != nil {
		return err
	}
	return validateSocketDirectory(filepath.Dir(path), ownerUID)
}

func validateSocketDirectory(path string, ownerUID uint32) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("sandboxrpc: inspect socket directory: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("sandboxrpc: socket directory must be a private mode 0700 directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return fmt.Errorf("sandboxrpc: socket directory identity is unavailable")
	}
	if stat.Uid != ownerUID {
		return fmt.Errorf("sandboxrpc: socket directory owner mismatch")
	}
	return nil
}

type socketIdentity struct {
	device uint64
	inode  uint64
	uid    uint32
}

func inspectSocket(path string) (socketIdentity, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return socketIdentity{}, fmt.Errorf("sandboxrpc: inspect Unix socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		return socketIdentity{}, fmt.Errorf("sandboxrpc: endpoint must be a mode 0600 Unix socket")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return socketIdentity{}, fmt.Errorf("sandboxrpc: Unix socket identity is unavailable")
	}
	return socketIdentity{device: uint64(stat.Dev), inode: stat.Ino, uid: stat.Uid}, nil
}

var _ v1connect.ControlServiceHandler = (*rpcHandler)(nil)
var _ v1connect.SandboxProcessServiceHandler = (*rpcHandler)(nil)
