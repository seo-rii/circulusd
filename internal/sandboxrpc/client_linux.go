//go:build linux

package sandboxrpc

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	v1connect "github.com/hancomac/circulusd/api/generated/circulus/v1alpha/circulusv1alphaconnect"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

type ClientConfig struct {
	SocketPath        string
	ServerUID         uint32
	SandboxID         []byte
	SandboxGeneration uint64
	OneTimeNonce      []byte
}

type clientDependencies struct {
	dialUnix func(context.Context, string) (net.Conn, error)
}

// Client owns one use of a launch capability nonce. It never retries a failed
// handshake because the server may already have consumed that capability.
type Client struct {
	socketPath     string
	socketIdentity socketIdentity
	serverUID      uint32
	sandboxID      []byte
	generation     uint64
	transport      *http.Transport
	control        v1connect.ControlServiceClient
	process        v1connect.SandboxProcessServiceClient
	dialUnix       func(context.Context, string) (net.Conn, error)
	closed         atomic.Bool
	endpointMu     sync.Mutex
	endpointFD     int

	handshakeMu        sync.Mutex
	nonce              [handshakeNonceBytes]byte
	handshakeAttempted bool
	handshakeInFlight  chan struct{}
	handshakeSession   string
	handshakeError     error
}

// ProcessEventStream validates one ordered, generation-bound process stream.
// Receive and Msg are serialized; Close may safely race an in-flight Receive.
type ProcessEventStream struct {
	stream        *connect.ServerStreamForClient[v1.ProcessEvent]
	process       *v1.ProcessHandle
	nextSequence  uint64
	receiveMu     sync.Mutex
	current       *v1.ProcessEvent
	validationErr error
	terminal      bool
	closed        atomic.Bool
	closeOnce     sync.Once
	closeErr      error
}

func NewClient(config ClientConfig) (*Client, error) {
	return newClientWithDependencies(config, -1, clientDependencies{})
}

// NewClientFromPinnedSocketFD constructs a client whose dial authority is the
// Unix socket inode referenced by pinnedSocketFD. The descriptor is borrowed
// only for this call and is duplicated before the function returns.
func NewClientFromPinnedSocketFD(config ClientConfig, pinnedSocketFD int) (*Client, error) {
	if pinnedSocketFD < 0 {
		return nil, fmt.Errorf("sandboxrpc: pinned Unix socket descriptor is invalid")
	}
	return newClientWithDependencies(config, pinnedSocketFD, clientDependencies{})
}

func newClientWithDependencies(
	config ClientConfig,
	pinnedSocketFD int,
	dependencies clientDependencies,
) (*Client, error) {
	if dependencies.dialUnix == nil {
		dependencies.dialUnix = func(ctx context.Context, socketPath string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		}
	}
	if err := validateCanonicalSocketPathSyntax(config.SocketPath); err != nil {
		return nil, err
	}
	if !validOpaqueID(config.SandboxID, 256) || config.SandboxGeneration == 0 {
		return nil, fmt.Errorf("sandboxrpc: client sandbox launch identity is invalid")
	}
	if len(config.OneTimeNonce) != handshakeNonceBytes {
		return nil, fmt.Errorf("sandboxrpc: client one-time nonce must be 32 bytes")
	}
	ownedSocketFD := -1
	var err error
	if pinnedSocketFD >= 0 {
		ownedSocketFD, err = unix.FcntlInt(uintptr(pinnedSocketFD), unix.F_DUPFD_CLOEXEC, 0)
	} else {
		directoryFD, openDirectoryErr := unix.Openat2(unix.AT_FDCWD, filepath.Dir(config.SocketPath), &unix.OpenHow{
			Flags:   uint64(unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC),
			Resolve: uint64(unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS),
		})
		if openDirectoryErr != nil {
			return nil, fmt.Errorf("sandboxrpc: pin Unix socket directory: %w", openDirectoryErr)
		}
		var directoryStatus unix.Stat_t
		if err := unix.Fstat(directoryFD, &directoryStatus); err != nil {
			_ = unix.Close(directoryFD)
			return nil, fmt.Errorf("sandboxrpc: inspect pinned Unix socket directory: %w", err)
		}
		if directoryStatus.Mode&unix.S_IFMT != unix.S_IFDIR || directoryStatus.Mode&0o777 != 0o700 ||
			directoryStatus.Uid != config.ServerUID {
			_ = unix.Close(directoryFD)
			return nil, fmt.Errorf("sandboxrpc: socket directory must be private and owned by the server UID")
		}
		ownedSocketFD, err = unix.Openat(
			directoryFD,
			filepath.Base(config.SocketPath),
			unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW,
			0,
		)
		closeDirectoryErr := unix.Close(directoryFD)
		if err == nil && closeDirectoryErr != nil {
			_ = unix.Close(ownedSocketFD)
			return nil, fmt.Errorf("sandboxrpc: release pinned Unix socket directory: %w", closeDirectoryErr)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("sandboxrpc: pin Unix socket endpoint: %w", err)
	}
	identity, err := inspectSocketFD(ownedSocketFD)
	if err != nil {
		_ = unix.Close(ownedSocketFD)
		return nil, err
	}
	if identity.uid != config.ServerUID {
		_ = unix.Close(ownedSocketFD)
		return nil, fmt.Errorf("sandboxrpc: Unix socket owner does not match the expected server UID")
	}
	client := &Client{
		socketPath:     config.SocketPath,
		socketIdentity: identity,
		serverUID:      config.ServerUID,
		sandboxID:      append([]byte(nil), config.SandboxID...),
		generation:     config.SandboxGeneration,
		dialUnix:       dependencies.dialUnix,
		endpointFD:     ownedSocketFD,
	}
	copy(client.nonce[:], config.OneTimeNonce)
	client.transport = &http.Transport{
		DisableCompression:  true,
		DialContext:         client.dialContext,
		MaxIdleConns:        2,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
	}
	httpClient := &http.Client{Transport: client.transport}
	client.control = v1connect.NewControlServiceClient(
		httpClient,
		"http://sandbox.invalid",
		connect.WithReadMaxBytes(maximumMessageBytes),
		connect.WithSendMaxBytes(maximumMessageBytes),
	)
	client.process = v1connect.NewSandboxProcessServiceClient(
		httpClient,
		"http://sandbox.invalid",
		connect.WithReadMaxBytes(maximumMessageBytes),
		connect.WithSendMaxBytes(maximumMessageBytes),
	)
	return client, nil
}

func (client *Client) Close() error {
	if client == nil || client.closed.Swap(true) {
		return nil
	}
	client.transport.CloseIdleConnections()
	client.endpointMu.Lock()
	endpointFD := client.endpointFD
	client.endpointFD = -1
	client.endpointMu.Unlock()
	var closeErr error
	if endpointFD >= 0 {
		closeErr = unix.Close(endpointFD)
	}
	client.handshakeMu.Lock()
	clear(client.nonce[:])
	client.handshakeSession = ""
	client.handshakeMu.Unlock()
	return closeErr
}

// Ready establishes and authenticates the client's single-use sandbox session.
func (client *Client) Ready(ctx context.Context) error {
	if client == nil {
		return connect.NewError(connect.CodeFailedPrecondition, errors.New("sandbox RPC client is nil"))
	}
	if ctx == nil {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("request context is nil"))
	}
	if err := ctx.Err(); err != nil {
		return contextConnectError(err)
	}
	if client.closed.Load() {
		return connect.NewError(connect.CodeFailedPrecondition, errors.New("sandbox RPC client is closed"))
	}
	_, err := client.ensureHandshake(ctx)
	return err
}

func (client *Client) Spawn(ctx context.Context, message *v1.SpawnProcessRequest) (*v1.SpawnProcessResponse, error) {
	prepared, requestID, err := prepareRequest(ctx, message)
	if err != nil {
		return nil, err
	}
	requestMessage := prepared.(*v1.SpawnProcessRequest)
	response, err := callClient(client, ctx, func(session string) (*connect.Response[v1.SpawnProcessResponse], error) {
		request := connect.NewRequest(requestMessage)
		request.Header().Set(sessionHeader, session)
		return client.process.Spawn(ctx, request)
	})
	if err != nil {
		return nil, err
	}
	if response == nil || response.Msg == nil || validateResponse(response.Msg, response.Msg.GetMeta(), requestID) != nil ||
		response.Msg.GetProcess() == nil || !bytes.Equal(response.Msg.GetProcess().GetSandboxId().GetValue(), client.sandboxID) ||
		response.Msg.GetProcess().GetGeneration() != client.generation ||
		!proto.Equal(response.Msg.GetProcess().GetInvocationId(), requestMessage.GetInvocationId()) ||
		!validOpaqueID(response.Msg.GetProcess().GetProcessId().GetValue(), 64) {
		return nil, connect.NewError(connect.CodeDataLoss, errors.New("spawn response failed protocol validation"))
	}
	return proto.Clone(response.Msg).(*v1.SpawnProcessResponse), nil
}

func (client *Client) Attach(ctx context.Context, message *v1.AttachProcessRequest) (*ProcessEventStream, error) {
	prepared, _, err := prepareRequest(ctx, message)
	if err != nil {
		return nil, err
	}
	requestMessage := prepared.(*v1.AttachProcessRequest)
	if requestMessage.GetProcess() == nil || requestMessage.GetAfterSequence() == ^uint64(0) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("attach request is invalid"))
	}
	if client == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("sandbox RPC client is nil"))
	}
	if client.closed.Load() {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("sandbox RPC client is closed"))
	}
	session, err := client.ensureHandshake(ctx)
	if err != nil {
		return nil, err
	}
	request := connect.NewRequest(requestMessage)
	request.Header().Set(sessionHeader, session)
	stream, err := client.process.Attach(ctx, request)
	if err != nil {
		return nil, err
	}
	return &ProcessEventStream{
		stream:       stream,
		process:      proto.Clone(requestMessage.GetProcess()).(*v1.ProcessHandle),
		nextSequence: requestMessage.GetAfterSequence() + 1,
	}, nil
}

func (stream *ProcessEventStream) Receive() bool {
	if stream == nil {
		return false
	}
	stream.receiveMu.Lock()
	defer stream.receiveMu.Unlock()
	if stream.validationErr != nil || stream.closed.Load() {
		return false
	}
	if !stream.stream.Receive() {
		stream.validationErr = stream.stream.Err()
		return false
	}
	message := stream.stream.Msg()
	valid := message != nil && !hasUnknownFields(message) && proto.Equal(message.GetProcess(), stream.process) &&
		message.GetSequence() == stream.nextSequence && message.GetSequence() != 0 && !stream.terminal
	if valid {
		switch event := message.GetEvent().(type) {
		case *v1.ProcessEvent_Started:
			valid = event.Started != nil && event.Started.GetStartedAtUnixMs() != 0
		case *v1.ProcessEvent_Stdout:
			valid = event.Stdout != nil && len(event.Stdout.GetData()) > 0 &&
				len(event.Stdout.GetData()) <= maximumMessageBytes && !event.Stdout.GetTruncated()
		case *v1.ProcessEvent_Stderr:
			valid = event.Stderr != nil && len(event.Stderr.GetData()) > 0 &&
				len(event.Stderr.GetData()) <= maximumMessageBytes && !event.Stderr.GetTruncated()
		case *v1.ProcessEvent_Resource:
			valid = event.Resource != nil
		case *v1.ProcessEvent_Exit:
			valid = event.Exit != nil && event.Exit.GetFinishedAtUnixMs() != 0
			if valid {
				switch event.Exit.GetTerminatingSignal() {
				case v1.ProcessSignal_PROCESS_SIGNAL_UNSPECIFIED,
					v1.ProcessSignal_PROCESS_SIGNAL_INTERRUPT,
					v1.ProcessSignal_PROCESS_SIGNAL_TERMINATE,
					v1.ProcessSignal_PROCESS_SIGNAL_KILL,
					v1.ProcessSignal_PROCESS_SIGNAL_HANGUP:
				default:
					valid = false
				}
			}
			stream.terminal = valid
		case *v1.ProcessEvent_Error:
			valid = event.Error != nil && event.Error.GetCode() != v1.ErrorCode_ERROR_CODE_UNSPECIFIED &&
				event.Error.GetReason() != "" && event.Error.GetMessage() != ""
		default:
			valid = false
		}
	}
	if !valid {
		stream.validationErr = connect.NewError(connect.CodeDataLoss, errors.New("process event failed protocol validation"))
		_ = stream.stream.Close()
		return false
	}
	stream.current = proto.Clone(message).(*v1.ProcessEvent)
	stream.nextSequence++
	return true
}

func (stream *ProcessEventStream) Msg() *v1.ProcessEvent {
	if stream == nil {
		return nil
	}
	stream.receiveMu.Lock()
	defer stream.receiveMu.Unlock()
	if stream.current == nil {
		return nil
	}
	return proto.Clone(stream.current).(*v1.ProcessEvent)
}

func (stream *ProcessEventStream) Err() error {
	if stream == nil {
		return connect.NewError(connect.CodeFailedPrecondition, errors.New("process event stream is nil"))
	}
	stream.receiveMu.Lock()
	defer stream.receiveMu.Unlock()
	if stream.validationErr != nil {
		return stream.validationErr
	}
	return stream.stream.Err()
}

func (stream *ProcessEventStream) Close() error {
	if stream == nil {
		return nil
	}
	stream.closed.Store(true)
	stream.closeOnce.Do(func() {
		stream.closeErr = stream.stream.Close()
	})
	return stream.closeErr
}

func (client *Client) WriteStdin(ctx context.Context, message *v1.WriteStdinRequest) (*v1.WriteStdinResponse, error) {
	prepared, requestID, err := prepareRequest(ctx, message)
	if err != nil {
		return nil, err
	}
	requestMessage := prepared.(*v1.WriteStdinRequest)
	response, err := callClient(client, ctx, func(session string) (*connect.Response[v1.WriteStdinResponse], error) {
		request := connect.NewRequest(requestMessage)
		request.Header().Set(sessionHeader, session)
		return client.process.WriteStdin(ctx, request)
	})
	if err != nil {
		return nil, err
	}
	if response == nil || response.Msg == nil || validateResponse(response.Msg, response.Msg.GetMeta(), requestID) != nil ||
		response.Msg.GetAcceptedSequence() != requestMessage.GetChunkSequence() ||
		response.Msg.GetAcceptedBytes() != uint64(len(requestMessage.GetData())) {
		return nil, connect.NewError(connect.CodeDataLoss, errors.New("stdin response failed protocol validation"))
	}
	return proto.Clone(response.Msg).(*v1.WriteStdinResponse), nil
}

func (client *Client) CloseStdin(ctx context.Context, message *v1.CloseStdinRequest) (*v1.CloseStdinResponse, error) {
	prepared, requestID, err := prepareRequest(ctx, message)
	if err != nil {
		return nil, err
	}
	requestMessage := prepared.(*v1.CloseStdinRequest)
	response, err := callClient(client, ctx, func(session string) (*connect.Response[v1.CloseStdinResponse], error) {
		request := connect.NewRequest(requestMessage)
		request.Header().Set(sessionHeader, session)
		return client.process.CloseStdin(ctx, request)
	})
	if err != nil {
		return nil, err
	}
	if response == nil || response.Msg == nil || validateResponse(response.Msg, response.Msg.GetMeta(), requestID) != nil || !response.Msg.GetClosed() {
		return nil, connect.NewError(connect.CodeDataLoss, errors.New("close-stdin response failed protocol validation"))
	}
	return proto.Clone(response.Msg).(*v1.CloseStdinResponse), nil
}

func (client *Client) Signal(ctx context.Context, message *v1.SignalProcessRequest) (*v1.SignalProcessResponse, error) {
	prepared, requestID, err := prepareRequest(ctx, message)
	if err != nil {
		return nil, err
	}
	requestMessage := prepared.(*v1.SignalProcessRequest)
	response, err := callClient(client, ctx, func(session string) (*connect.Response[v1.SignalProcessResponse], error) {
		request := connect.NewRequest(requestMessage)
		request.Header().Set(sessionHeader, session)
		return client.process.Signal(ctx, request)
	})
	if err != nil {
		return nil, err
	}
	if response == nil || response.Msg == nil || validateResponse(response.Msg, response.Msg.GetMeta(), requestID) != nil || !response.Msg.GetDelivered() {
		return nil, connect.NewError(connect.CodeDataLoss, errors.New("signal response failed protocol validation"))
	}
	return proto.Clone(response.Msg).(*v1.SignalProcessResponse), nil
}

func (client *Client) Cancel(ctx context.Context, message *v1.CancelProcessRequest) (*v1.CancelProcessResponse, error) {
	prepared, requestID, err := prepareRequest(ctx, message)
	if err != nil {
		return nil, err
	}
	requestMessage := prepared.(*v1.CancelProcessRequest)
	response, err := callClient(client, ctx, func(session string) (*connect.Response[v1.CancelProcessResponse], error) {
		request := connect.NewRequest(requestMessage)
		request.Header().Set(sessionHeader, session)
		return client.process.Cancel(ctx, request)
	})
	if err != nil {
		return nil, err
	}
	if response == nil || response.Msg == nil || validateResponse(response.Msg, response.Msg.GetMeta(), requestID) != nil ||
		!response.Msg.GetProcessGroupTerminationStarted() {
		return nil, connect.NewError(connect.CodeDataLoss, errors.New("cancel response failed protocol validation"))
	}
	return proto.Clone(response.Msg).(*v1.CancelProcessResponse), nil
}

func (client *Client) Wait(ctx context.Context, message *v1.WaitProcessRequest) (*v1.WaitProcessResponse, error) {
	prepared, requestID, err := prepareRequest(ctx, message)
	if err != nil {
		return nil, err
	}
	requestMessage := prepared.(*v1.WaitProcessRequest)
	response, err := callClient(client, ctx, func(session string) (*connect.Response[v1.WaitProcessResponse], error) {
		request := connect.NewRequest(requestMessage)
		request.Header().Set(sessionHeader, session)
		return client.process.Wait(ctx, request)
	})
	if err != nil {
		return nil, err
	}
	if response == nil || response.Msg == nil || validateResponse(response.Msg, response.Msg.GetMeta(), requestID) != nil ||
		(response.Msg.GetState() != v1.ProcessLifecycleState_PROCESS_LIFECYCLE_STATE_EXITED &&
			response.Msg.GetState() != v1.ProcessLifecycleState_PROCESS_LIFECYCLE_STATE_FAILED) || response.Msg.GetResult() == nil {
		return nil, connect.NewError(connect.CodeDataLoss, errors.New("wait response failed protocol validation"))
	}
	return proto.Clone(response.Msg).(*v1.WaitProcessResponse), nil
}

func (client *Client) dialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	client.endpointMu.Lock()
	if client.closed.Load() || client.endpointFD < 0 {
		client.endpointMu.Unlock()
		return nil, fmt.Errorf("sandboxrpc: client is closed")
	}
	endpointFD, err := unix.FcntlInt(uintptr(client.endpointFD), unix.F_DUPFD_CLOEXEC, 0)
	client.endpointMu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("sandboxrpc: duplicate pinned Unix socket endpoint: %w", err)
	}
	defer unix.Close(endpointFD)
	identity, err := inspectSocketFD(endpointFD)
	if err != nil {
		return nil, err
	}
	if identity != client.socketIdentity || identity.uid != client.serverUID {
		return nil, fmt.Errorf("sandboxrpc: Unix socket identity changed")
	}
	dialPath := "/proc/self/fd/" + strconv.Itoa(endpointFD)
	if len(dialPath) > maximumUnixSocketPathBytes {
		return nil, fmt.Errorf("sandboxrpc: pinned Unix socket descriptor path exceeds Linux sockaddr limit")
	}
	connection, err := client.dialUnix(ctx, dialPath)
	if err != nil {
		return nil, err
	}
	credential, err := socketPeerCredential(connection)
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	if credential.uid != client.serverUID {
		_ = connection.Close()
		return nil, fmt.Errorf("sandboxrpc: Unix socket peer identity mismatch")
	}
	return connection, nil
}

func inspectSocketFD(fd int) (socketIdentity, error) {
	if fd < 0 {
		return socketIdentity{}, fmt.Errorf("sandboxrpc: Unix socket descriptor is invalid")
	}
	var status unix.Stat_t
	if err := unix.Fstat(fd, &status); err != nil {
		return socketIdentity{}, fmt.Errorf("sandboxrpc: inspect pinned Unix socket: %w", err)
	}
	if status.Mode&unix.S_IFMT != unix.S_IFSOCK || status.Mode&0o777 != 0o600 {
		return socketIdentity{}, fmt.Errorf("sandboxrpc: endpoint must be a mode 0600 Unix socket")
	}
	return socketIdentity{device: uint64(status.Dev), inode: status.Ino, uid: status.Uid}, nil
}

func callClient[T any](client *Client, ctx context.Context, invoke func(string) (*connect.Response[T], error)) (*connect.Response[T], error) {
	if client == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("sandbox RPC client is nil"))
	}
	if ctx == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("request context is nil"))
	}
	if client.closed.Load() {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("sandbox RPC client is closed"))
	}
	session, err := client.ensureHandshake(ctx)
	if err != nil {
		return nil, err
	}
	return invoke(session)
}

func (client *Client) ensureHandshake(ctx context.Context) (string, error) {
	for {
		if client.closed.Load() {
			return "", connect.NewError(connect.CodeFailedPrecondition, errors.New("sandbox RPC client is closed"))
		}
		client.handshakeMu.Lock()
		if client.closed.Load() {
			client.handshakeMu.Unlock()
			return "", connect.NewError(connect.CodeFailedPrecondition, errors.New("sandbox RPC client is closed"))
		}
		if client.handshakeSession != "" {
			session := client.handshakeSession
			client.handshakeMu.Unlock()
			return session, nil
		}
		if client.handshakeInFlight != nil {
			finished := client.handshakeInFlight
			client.handshakeMu.Unlock()
			select {
			case <-finished:
				continue
			case <-ctx.Done():
				return "", contextConnectError(ctx.Err())
			}
		}
		if client.handshakeAttempted {
			err := client.handshakeError
			client.handshakeMu.Unlock()
			if err == nil {
				err = connect.NewError(connect.CodeUnauthenticated, errors.New("one-time handshake is unavailable"))
			}
			return "", err
		}
		client.handshakeAttempted = true
		finished := make(chan struct{})
		client.handshakeInFlight = finished
		nonce := append([]byte(nil), client.nonce[:]...)
		client.handshakeMu.Unlock()

		session, err := client.performHandshake(ctx, nonce)
		client.handshakeMu.Lock()
		clear(client.nonce[:])
		if err == nil && !client.closed.Load() {
			client.handshakeSession = session
		} else {
			client.handshakeError = err
		}
		client.handshakeInFlight = nil
		close(finished)
		client.handshakeMu.Unlock()
		if err != nil {
			return "", err
		}
		if client.closed.Load() {
			return "", connect.NewError(connect.CodeFailedPrecondition, errors.New("sandbox RPC client is closed"))
		}
		return session, nil
	}
}

func (client *Client) performHandshake(ctx context.Context, nonce []byte) (string, error) {
	request := connect.NewRequest(&v1.HandshakeRequest{
		Peer:              v1.ProtocolPeer_PROTOCOL_PEER_EXECUTORD,
		MinimumVersion:    protocolVersion(),
		MaximumVersion:    protocolVersion(),
		FeatureBitmap:     0,
		MaximumFrameSize:  maximumMessageBytes,
		DescriptorDigest:  descriptorDigest(),
		OneTimeNonce:      nonce,
		SandboxId:         &v1.OpaqueId{Value: append([]byte(nil), client.sandboxID...)},
		SandboxGeneration: client.generation,
	})
	response, err := client.control.Handshake(ctx, request)
	if err != nil {
		return "", err
	}
	if response == nil || response.Msg == nil || hasUnknownFields(response.Msg) ||
		!isProtocolVersion(response.Msg.GetSelectedVersion()) || response.Msg.GetFeatureBitmap() != 0 ||
		response.Msg.GetMaximumFrameSize() != maximumMessageBytes || !isDescriptorDigest(response.Msg.GetDescriptorDigest()) ||
		response.Msg.GetStatus().GetName() != "sandbox.process" ||
		response.Msg.GetStatus().GetAvailability() != v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_AVAILABLE ||
		!bytes.Equal(response.Msg.GetNonceProof(), nonceProof(nonce, client.sandboxID, client.generation)) {
		return "", connect.NewError(connect.CodeDataLoss, errors.New("handshake response failed protocol validation"))
	}
	session := response.Header().Get(sessionHeader)
	if len(session) == 0 || len(session) > 128 {
		return "", connect.NewError(connect.CodeDataLoss, errors.New("handshake session is missing"))
	}
	return session, nil
}

func prepareRequest(ctx context.Context, message proto.Message) (proto.Message, []byte, error) {
	if ctx == nil {
		return nil, nil, connect.NewError(connect.CodeInvalidArgument, errors.New("request context is nil"))
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, contextConnectError(err)
	}
	if message == nil {
		return nil, nil, connect.NewError(connect.CodeInvalidArgument, errors.New("request is nil"))
	}
	cloned := proto.Clone(message)
	if cloned == nil {
		return nil, nil, connect.NewError(connect.CodeInternal, errors.New("cannot clone request"))
	}
	reflection := cloned.ProtoReflect()
	metaField := reflection.Descriptor().Fields().ByName("meta")
	if metaField == nil || !reflection.Has(metaField) {
		return nil, nil, connect.NewError(connect.CodeInvalidArgument, errors.New("request metadata is missing"))
	}
	meta, ok := reflection.Get(metaField).Message().Interface().(*v1.RpcRequestMeta)
	if !ok || meta == nil || len(meta.GetIdempotencyKey()) < 16 || len(meta.GetIdempotencyKey()) > 64 {
		return nil, nil, connect.NewError(connect.CodeInvalidArgument, errors.New("idempotency key is invalid"))
	}
	requestID := make([]byte, 16)
	if _, err := rand.Read(requestID); err != nil {
		return nil, nil, connect.NewError(connect.CodeInternal, errors.New("cannot generate request identity"))
	}
	now := time.Now()
	deadline := now.Add(defaultRequestTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	maximumDeadline := now.Add(maximumRPCDeadline)
	if deadline.After(maximumDeadline) {
		deadline = maximumDeadline
	}
	if !now.Before(deadline) {
		return nil, nil, connect.NewError(connect.CodeDeadlineExceeded, context.DeadlineExceeded)
	}
	meta.RequestId = &v1.OpaqueId{Value: append([]byte(nil), requestID...)}
	meta.RequestDigest = nil
	meta.DeadlineUnixMs = uint64(deadline.UnixMilli())
	meta.IdempotencyKey = append([]byte(nil), meta.GetIdempotencyKey()...)
	meta.ProtocolVersion = protocolVersion()
	digest, err := requestDigest(cloned)
	if err != nil {
		return nil, nil, connect.NewError(connect.CodeInternal, errors.New("cannot compute request digest"))
	}
	meta.RequestDigest = digest
	return cloned, requestID, nil
}

func validateResponse(message proto.Message, meta *v1.RpcResponseMeta, requestID []byte) error {
	if hasUnknownFields(message) || meta == nil || !bytes.Equal(meta.GetRequestId().GetValue(), requestID) ||
		meta.GetServerSequence() == 0 || !isDescriptorDigest(meta.GetDescriptorDigest()) {
		return errors.New("response metadata is invalid")
	}
	return nil
}

func contextConnectError(err error) error {
	if errors.Is(err, context.Canceled) {
		return connect.NewError(connect.CodeCanceled, context.Canceled)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return connect.NewError(connect.CodeDeadlineExceeded, context.DeadlineExceeded)
	}
	return err
}
