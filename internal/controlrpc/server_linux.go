//go:build linux

package controlrpc

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
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
	"google.golang.org/protobuf/proto"
)

const (
	maximumUnixSocketPathBytes = 107
	sessionLifetime            = 5 * time.Minute
	sessionRandomBytes         = 16
	sessionPayloadBytes        = 1 + 4 + 4 + 8 + sessionRandomBytes
	controlHTTPIOTimeout       = 5 * time.Second
	maximumRequestDeadline     = 5 * time.Minute
)

type CapabilityProvider func(context.Context) ([]*v1.CapabilityStatus, error)

// PeerUIDAuthority grants one logical protocol role to one kernel-authenticated
// UDS peer UID. Keeping the pair explicit prevents independent UID and role
// allowlists from accidentally authorizing their Cartesian product.
type PeerUIDAuthority struct {
	UID  uint32
	Peer v1.ProtocolPeer
}

type ServerConfig struct {
	SocketPath         string
	AllowedUIDs        []uint32
	AllowedPeers       []v1.ProtocolPeer
	PeerUIDAuthorities []PeerUIDAuthority
	ServerPeer         v1.ProtocolPeer
	Capabilities       []*v1.CapabilityStatus
	CapabilityProvider CapabilityProvider
}

type Server struct {
	socketPath string
	listener   net.Listener
	httpServer *http.Server
	handler    *controlHandler

	serveMu    sync.Mutex
	served     bool
	close      sync.Once
	closeError error
	closed     atomic.Bool
}

type controlHandler struct {
	v1connect.UnimplementedControlServiceHandler
	allowedPeers map[uint32]map[v1.ProtocolPeer]struct{}
	serverPeer   v1.ProtocolPeer
	capabilities []*v1.CapabilityStatus
	provider     CapabilityProvider
	sessionKey   [sha256.Size]byte
	sequence     atomic.Uint64
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

func ListenServer(config ServerConfig) (*Server, error) {
	if err := validateServerSocketPath(config.SocketPath); err != nil {
		return nil, err
	}
	serverPeer := config.ServerPeer
	if serverPeer == v1.ProtocolPeer_PROTOCOL_PEER_UNSPECIFIED {
		serverPeer = v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD
	}
	if !isKnownPeer(serverPeer) {
		return nil, fmt.Errorf("controlrpc: server peer %d is invalid", serverPeer)
	}

	allowedUIDs := make(map[uint32]struct{})
	allowedPeers := make(map[uint32]map[v1.ProtocolPeer]struct{})
	if len(config.PeerUIDAuthorities) != 0 {
		if len(config.AllowedUIDs) != 0 || len(config.AllowedPeers) != 0 {
			return nil, fmt.Errorf("controlrpc: configure paired peer authorities or compatibility allowlists, not both")
		}
		for _, authority := range config.PeerUIDAuthorities {
			if !isKnownPeer(authority.Peer) {
				return nil, fmt.Errorf("controlrpc: allowed peer %d is invalid", authority.Peer)
			}
			peers := allowedPeers[authority.UID]
			if peers == nil {
				peers = make(map[v1.ProtocolPeer]struct{})
				allowedPeers[authority.UID] = peers
			}
			if _, duplicate := peers[authority.Peer]; duplicate {
				return nil, fmt.Errorf("controlrpc: peer authority is duplicated")
			}
			peers[authority.Peer] = struct{}{}
			allowedUIDs[authority.UID] = struct{}{}
		}
	} else {
		if len(config.AllowedUIDs) == 0 {
			return nil, fmt.Errorf("controlrpc: allowed UID list must not be empty")
		}
		compatibilityPeers := config.AllowedPeers
		if len(compatibilityPeers) == 0 {
			compatibilityPeers = []v1.ProtocolPeer{v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL}
		}
		if len(config.AllowedUIDs) > 1 && len(compatibilityPeers) > 1 {
			return nil, fmt.Errorf("controlrpc: UID and peer allowlists form an ambiguous authority cross-product")
		}
		for _, uid := range config.AllowedUIDs {
			allowedUIDs[uid] = struct{}{}
			peers := allowedPeers[uid]
			if peers == nil {
				peers = make(map[v1.ProtocolPeer]struct{})
				allowedPeers[uid] = peers
			}
			for _, peer := range compatibilityPeers {
				if !isKnownPeer(peer) {
					return nil, fmt.Errorf("controlrpc: allowed peer %d is invalid", peer)
				}
				peers[peer] = struct{}{}
			}
		}
	}
	if len(allowedUIDs) == 0 {
		return nil, fmt.Errorf("controlrpc: peer authority list must not be empty")
	}

	capabilities, err := cloneCapabilities(config.Capabilities)
	if err != nil {
		return nil, err
	}
	if config.CapabilityProvider != nil && len(config.Capabilities) != 0 {
		return nil, fmt.Errorf("controlrpc: configure static capabilities or a provider, not both")
	}

	if _, err := os.Lstat(config.SocketPath); err == nil {
		return nil, fmt.Errorf("controlrpc: socket path already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("controlrpc: inspect socket path: %w", err)
	}

	address := &net.UnixAddr{Name: config.SocketPath, Net: "unix"}
	unixListener, err := net.ListenUnix("unix", address)
	if err != nil {
		return nil, fmt.Errorf("controlrpc: listen on Unix socket: %w", err)
	}
	unixListener.SetUnlinkOnClose(true)
	cleanup := func() { _ = unixListener.Close() }
	if err := os.Chmod(config.SocketPath, 0o600); err != nil {
		cleanup()
		return nil, fmt.Errorf("controlrpc: set socket permissions: %w", err)
	}
	if _, err := inspectSocket(config.SocketPath); err != nil {
		cleanup()
		return nil, err
	}

	handler := &controlHandler{
		allowedPeers: allowedPeers,
		serverPeer:   serverPeer,
		capabilities: capabilities,
		provider:     config.CapabilityProvider,
	}
	if _, err := rand.Read(handler.sessionKey[:]); err != nil {
		cleanup()
		return nil, fmt.Errorf("controlrpc: generate session key: %w", err)
	}
	_, rpcHandler := v1connect.NewControlServiceHandler(
		handler,
		connect.WithReadMaxBytes(maximumMessageBytes),
		connect.WithSendMaxBytes(maximumMessageBytes),
	)
	listener := &credentialListener{Listener: unixListener, allowedUIDs: allowedUIDs}
	server := &Server{
		socketPath: config.SocketPath,
		listener:   listener,
		handler:    handler,
	}
	server.httpServer = &http.Server{
		Handler:                      rpcHandler,
		ReadTimeout:                  controlHTTPIOTimeout,
		ReadHeaderTimeout:            controlHTTPIOTimeout,
		WriteTimeout:                 maximumRequestDeadline + controlHTTPIOTimeout,
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
		return fmt.Errorf("controlrpc: server is nil")
	}
	if ctx == nil {
		return fmt.Errorf("controlrpc: serve context is nil")
	}
	server.serveMu.Lock()
	if server.served {
		server.serveMu.Unlock()
		return fmt.Errorf("controlrpc: server can only be served once")
	}
	server.served = true
	server.serveMu.Unlock()
	if server.closed.Load() {
		return server.Close()
	}

	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = server.Close()
		case <-stop:
		}
	}()
	err := server.httpServer.Serve(server.listener)
	close(stop)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return server.Close()
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
		if httpError != nil && !errors.Is(httpError, net.ErrClosed) {
			server.closeError = httpError
		}
		if listenerError != nil && !errors.Is(listenerError, net.ErrClosed) {
			server.closeError = errors.Join(server.closeError, listenerError)
		}
	})
	return server.closeError
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
		return peerCredential{}, fmt.Errorf("controlrpc: Unix connection has no syscall handle")
	}
	var (
		credential *syscall.Ucred
		optionErr  error
	)
	raw, err := syscallConnection.SyscallConn()
	if err != nil {
		return peerCredential{}, fmt.Errorf("controlrpc: get raw Unix connection: %w", err)
	}
	if err := raw.Control(func(fileDescriptor uintptr) {
		credential, optionErr = syscall.GetsockoptUcred(int(fileDescriptor), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return peerCredential{}, fmt.Errorf("controlrpc: inspect peer credential: %w", err)
	}
	if optionErr != nil {
		return peerCredential{}, fmt.Errorf("controlrpc: inspect peer credential: %w", optionErr)
	}
	if credential == nil {
		return peerCredential{}, fmt.Errorf("controlrpc: peer credential is missing")
	}
	return peerCredential{pid: credential.Pid, uid: credential.Uid, gid: credential.Gid}, nil
}

func (handler *controlHandler) Handshake(ctx context.Context, request *connect.Request[v1.HandshakeRequest]) (*connect.Response[v1.HandshakeResponse], error) {
	credential, ok := ctx.Value(peerCredentialContextKey{}).(peerCredential)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("peer credential is unavailable"))
	}
	if request == nil || request.Msg == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("handshake request is missing"))
	}
	message := request.Msg
	if hasUnknownFields(message) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("handshake request contains unknown protocol fields"))
	}
	peers := handler.allowedPeers[credential.uid]
	if _, allowed := peers[message.GetPeer()]; !allowed {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("protocol peer is not allowed"))
	}
	if !versionRangeIncludesProtocol(message.GetMinimumVersion(), message.GetMaximumVersion()) {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("protocol version 1.0 is unsupported by the peer"))
	}
	if !isDescriptorDigest(message.GetDescriptorDigest()) {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("protocol descriptor digest mismatch"))
	}
	if len(message.GetOneTimeNonce()) != handshakeNonceBytes {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("handshake nonce has invalid length"))
	}
	if message.GetMaximumFrameSize() < maximumMessageBytes {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("peer maximum frame size is below the required 1 MiB limit"))
	}
	session, err := handler.issueSession(credential.uid, message.GetPeer(), time.Now())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("cannot issue protocol session"))
	}
	response := connect.NewResponse(&v1.HandshakeResponse{
		SelectedVersion:  protocolVersion(),
		FeatureBitmap:    0,
		MaximumFrameSize: maximumMessageBytes,
		DescriptorDigest: descriptorDigest(),
		ServerPeer:       handler.serverPeer,
		Status: &v1.CapabilityStatus{
			Name:         "control.protocol",
			Availability: v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_AVAILABLE,
		},
		NonceProof: nonceProof(message.GetOneTimeNonce(), handler.serverPeer),
	})
	response.Header().Set(sessionHeader, session)
	return response, nil
}

func (handler *controlHandler) GetCapabilities(ctx context.Context, request *connect.Request[v1.GetCapabilitiesRequest]) (*connect.Response[v1.GetCapabilitiesResponse], error) {
	credential, ok := ctx.Value(peerCredentialContextKey{}).(peerCredential)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("peer credential is unavailable"))
	}
	if request == nil || request.Msg == nil || request.Msg.GetMeta() == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("request metadata is missing"))
	}
	if hasUnknownFields(request.Msg) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("request contains unknown protocol fields"))
	}
	if err := handler.verifySession(request.Header().Get(sessionHeader), credential.uid, time.Now()); err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("protocol session is invalid"))
	}
	meta := request.Msg.GetMeta()
	if len(meta.GetRequestId().GetValue()) != 16 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("request ID has invalid length"))
	}
	if !isProtocolVersion(meta.GetProtocolVersion()) {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("request protocol version is unsupported"))
	}
	if meta.GetDeadlineUnixMs() == 0 || meta.GetDeadlineUnixMs() > math.MaxInt64 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("request deadline is missing"))
	}
	metadataDeadline := time.UnixMilli(int64(meta.GetDeadlineUnixMs()))
	now := time.Now()
	if !now.Before(metadataDeadline) {
		return nil, connect.NewError(connect.CodeDeadlineExceeded, errors.New("request deadline has expired"))
	}
	if metadataDeadline.Sub(now) > maximumRequestDeadline {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("request deadline exceeds the protocol bound"))
	}
	expectedDigest, err := getCapabilitiesRequestDigest(request.Msg)
	if err != nil || !proto.Equal(expectedDigest, meta.GetRequestDigest()) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("request digest mismatch"))
	}

	providerContext, cancelProvider := context.WithDeadline(ctx, metadataDeadline)
	defer cancelProvider()
	capabilities := handler.capabilities
	if handler.provider != nil {
		capabilities, err = handler.provider(providerContext)
		if err != nil {
			return nil, providerError(err)
		}
	}
	if err := providerContext.Err(); err != nil {
		return nil, providerError(err)
	}
	capabilities, err = cloneCapabilities(capabilities)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("capability provider returned invalid data"))
	}
	requestID, ok := proto.Clone(meta.GetRequestId()).(*v1.OpaqueId)
	if !ok || requestID == nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("cannot clone request ID"))
	}
	response := &v1.GetCapabilitiesResponse{
		Meta: &v1.RpcResponseMeta{
			RequestId:        requestID,
			ServerSequence:   handler.sequence.Add(1),
			DescriptorDigest: descriptorDigest(),
		},
		Capabilities:     capabilities,
		ProtocolVersion:  protocolVersion(),
		DescriptorDigest: descriptorDigest(),
	}
	return connect.NewResponse(response), nil
}

func (handler *controlHandler) issueSession(uid uint32, peer v1.ProtocolPeer, now time.Time) (string, error) {
	payload := make([]byte, sessionPayloadBytes)
	payload[0] = 1
	binary.BigEndian.PutUint32(payload[1:5], uid)
	binary.BigEndian.PutUint32(payload[5:9], uint32(peer))
	binary.BigEndian.PutUint64(payload[9:17], uint64(now.Add(sessionLifetime).UnixMilli()))
	if _, err := rand.Read(payload[17:]); err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, handler.sessionKey[:])
	_, _ = mac.Write(payload)
	token := append(payload, mac.Sum(nil)...)
	return base64.RawURLEncoding.EncodeToString(token), nil
}

func (handler *controlHandler) verifySession(token string, uid uint32, now time.Time) error {
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(decoded) != sessionPayloadBytes+sha256.Size {
		return fmt.Errorf("invalid session encoding")
	}
	payload := decoded[:sessionPayloadBytes]
	receivedMAC := decoded[sessionPayloadBytes:]
	mac := hmac.New(sha256.New, handler.sessionKey[:])
	_, _ = mac.Write(payload)
	if subtle.ConstantTimeCompare(receivedMAC, mac.Sum(nil)) != 1 || payload[0] != 1 {
		return fmt.Errorf("invalid session signature")
	}
	if binary.BigEndian.Uint32(payload[1:5]) != uid {
		return fmt.Errorf("session UID mismatch")
	}
	peer := v1.ProtocolPeer(binary.BigEndian.Uint32(payload[5:9]))
	if _, allowed := handler.allowedPeers[uid][peer]; !allowed {
		return fmt.Errorf("session peer is not allowed")
	}
	expiresAt := binary.BigEndian.Uint64(payload[9:17])
	if uint64(now.UnixMilli()) >= expiresAt {
		return fmt.Errorf("session expired")
	}
	return nil
}

func versionRangeIncludesProtocol(minimum, maximum *v1.ProtocolVersion) bool {
	if minimum == nil || maximum == nil {
		return false
	}
	minimumValue := [2]uint64{minimum.GetMajor(), minimum.GetMinor()}
	maximumValue := [2]uint64{maximum.GetMajor(), maximum.GetMinor()}
	selected := [2]uint64{1, 0}
	return compareVersion(minimumValue, selected) <= 0 && compareVersion(selected, maximumValue) <= 0
}

func compareVersion(left, right [2]uint64) int {
	if left[0] < right[0] || left[0] == right[0] && left[1] < right[1] {
		return -1
	}
	if left == right {
		return 0
	}
	return 1
}

func providerError(err error) error {
	var connectError *connect.Error
	if errors.As(err, &connectError) {
		return connectError
	}
	if errors.Is(err, context.Canceled) {
		return connect.NewError(connect.CodeCanceled, context.Canceled)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return connect.NewError(connect.CodeDeadlineExceeded, context.DeadlineExceeded)
	}
	return connect.NewError(connect.CodeInternal, errors.New("capability provider failed"))
}

func validateCanonicalSocketPath(path string) error {
	if path == "" || strings.IndexByte(path, 0) >= 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return fmt.Errorf("controlrpc: socket path must be canonical and absolute")
	}
	if len(path) > maximumUnixSocketPathBytes {
		return fmt.Errorf("controlrpc: socket path exceeds Linux sockaddr limit")
	}
	parent := filepath.Dir(path)
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return fmt.Errorf("controlrpc: resolve socket directory: %w", err)
	}
	if resolved != parent {
		return fmt.Errorf("controlrpc: socket directory contains a symbolic link")
	}
	return nil
}

func validateServerSocketPath(path string) error {
	if err := validateCanonicalSocketPath(path); err != nil {
		return err
	}
	return validateSocketDirectory(filepath.Dir(path), uint32(os.Geteuid()))
}

func validateClientSocketPath(path string, socketOwnerUID uint32) error {
	if err := validateCanonicalSocketPath(path); err != nil {
		return err
	}
	return validateSocketDirectory(filepath.Dir(path), socketOwnerUID)
}

func validateSocketDirectory(path string, effectiveUID uint32) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("controlrpc: inspect socket directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("controlrpc: socket parent is not a directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return fmt.Errorf("controlrpc: socket directory identity is unavailable")
	}
	if stat.Uid != effectiveUID {
		return fmt.Errorf("controlrpc: socket directory is owned by UID %d, want %d", stat.Uid, effectiveUID)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("controlrpc: socket directory is group or other writable")
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
		return socketIdentity{}, fmt.Errorf("controlrpc: inspect Unix socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return socketIdentity{}, fmt.Errorf("controlrpc: endpoint is not a Unix socket")
	}
	if info.Mode().Perm() != 0o600 {
		return socketIdentity{}, fmt.Errorf("controlrpc: Unix socket mode is %04o, want 0600", info.Mode().Perm())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return socketIdentity{}, fmt.Errorf("controlrpc: Unix socket identity is unavailable")
	}
	return socketIdentity{device: uint64(stat.Dev), inode: stat.Ino, uid: stat.Uid}, nil
}
