//go:build linux

package controlrpc

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	v1connect "github.com/hancomac/circulusd/api/generated/circulus/v1alpha/circulusv1alphaconnect"
	"google.golang.org/protobuf/proto"
)

const defaultRequestTimeout = 30 * time.Second

type ClientConfig struct {
	SocketPath string
	Peer       v1.ProtocolPeer
}

type Client struct {
	socketPath     string
	socketIdentity socketIdentity
	peer           v1.ProtocolPeer
	transport      *http.Transport
	rpc            v1connect.ControlServiceClient
	closed         atomic.Bool

	handshakeMu       sync.Mutex
	handshakeSession  string
	handshakeInFlight chan struct{}
}

func NewClient(config ClientConfig) (*Client, error) {
	if err := validateCanonicalSocketPath(config.SocketPath); err != nil {
		return nil, err
	}
	identity, err := inspectSocket(config.SocketPath)
	if err != nil {
		return nil, err
	}
	if err := validateClientSocketPath(config.SocketPath, identity.uid); err != nil {
		return nil, err
	}
	peer := config.Peer
	if peer == v1.ProtocolPeer_PROTOCOL_PEER_UNSPECIFIED {
		peer = v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL
	}
	if !isKnownPeer(peer) {
		return nil, fmt.Errorf("controlrpc: client peer %d is invalid", peer)
	}

	client := &Client{
		socketPath:     config.SocketPath,
		socketIdentity: identity,
		peer:           peer,
	}
	client.transport = &http.Transport{
		DisableCompression:  true,
		DialContext:         client.dialContext,
		MaxIdleConns:        4,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
	}
	httpClient := &http.Client{Transport: client.transport}
	client.rpc = v1connect.NewControlServiceClient(
		httpClient,
		"http://control.invalid",
		connect.WithReadMaxBytes(maximumMessageBytes),
		connect.WithSendMaxBytes(maximumMessageBytes),
	)
	return client, nil
}

func (client *Client) GetCapabilities(ctx context.Context) (*v1.GetCapabilitiesResponse, error) {
	if client == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("control RPC client is nil"))
	}
	if ctx == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("request context is nil"))
	}
	if client.closed.Load() {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("control RPC client is closed"))
	}
	requestContext := ctx
	cancel := func() {}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		requestContext, cancel = context.WithTimeout(ctx, defaultRequestTimeout)
	}
	defer cancel()

	session, err := client.ensureHandshake(requestContext)
	if err != nil {
		return nil, err
	}
	response, requestID, err := client.callGetCapabilities(requestContext, session)
	if connect.CodeOf(err) == connect.CodeUnauthenticated {
		client.clearHandshake(session)
		session, err = client.ensureHandshake(requestContext)
		if err != nil {
			return nil, err
		}
		response, requestID, err = client.callGetCapabilities(requestContext, session)
	}
	if err != nil {
		return nil, err
	}
	if err := validateCapabilitiesResponse(response, requestID); err != nil {
		return nil, connect.NewError(connect.CodeDataLoss, err)
	}
	cloned, ok := proto.Clone(response).(*v1.GetCapabilitiesResponse)
	if !ok || cloned == nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("cannot clone capabilities response"))
	}
	return cloned, nil
}

func (client *Client) Close() error {
	if client == nil || client.closed.Swap(true) {
		return nil
	}
	client.transport.CloseIdleConnections()
	return nil
}

func (client *Client) dialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	before, err := inspectSocket(client.socketPath)
	if err != nil {
		return nil, err
	}
	if err := validateClientSocketPath(client.socketPath, before.uid); err != nil {
		return nil, err
	}
	if before != client.socketIdentity {
		return nil, fmt.Errorf("controlrpc: Unix socket identity changed")
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", client.socketPath)
	if err != nil {
		return nil, err
	}
	credential, err := socketPeerCredential(connection)
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	after, err := inspectSocket(client.socketPath)
	if err != nil || after != before || credential.uid != before.uid {
		_ = connection.Close()
		return nil, fmt.Errorf("controlrpc: Unix socket peer identity mismatch")
	}
	return connection, nil
}

func (client *Client) ensureHandshake(ctx context.Context) (string, error) {
	for {
		if client.closed.Load() {
			return "", connect.NewError(connect.CodeFailedPrecondition, errors.New("control RPC client is closed"))
		}
		client.handshakeMu.Lock()
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
		finished := make(chan struct{})
		client.handshakeInFlight = finished
		client.handshakeMu.Unlock()

		session, err := client.performHandshake(ctx)
		client.handshakeMu.Lock()
		if err == nil && !client.closed.Load() {
			client.handshakeSession = session
		}
		client.handshakeInFlight = nil
		close(finished)
		client.handshakeMu.Unlock()
		if err != nil {
			return "", err
		}
		if client.closed.Load() {
			return "", connect.NewError(connect.CodeFailedPrecondition, errors.New("control RPC client is closed"))
		}
		return session, nil
	}
}

func (client *Client) performHandshake(ctx context.Context) (string, error) {
	nonce := make([]byte, handshakeNonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return "", connect.NewError(connect.CodeInternal, errors.New("cannot generate handshake nonce"))
	}
	request := connect.NewRequest(&v1.HandshakeRequest{
		Peer:             client.peer,
		MinimumVersion:   protocolVersion(),
		MaximumVersion:   protocolVersion(),
		FeatureBitmap:    0,
		MaximumFrameSize: maximumMessageBytes,
		DescriptorDigest: descriptorDigest(),
		OneTimeNonce:     nonce,
	})
	response, err := client.rpc.Handshake(ctx, request)
	if err != nil {
		return "", err
	}
	if response == nil || response.Msg == nil ||
		hasUnknownFields(response.Msg) ||
		!isProtocolVersion(response.Msg.GetSelectedVersion()) ||
		response.Msg.GetFeatureBitmap() != 0 ||
		response.Msg.GetMaximumFrameSize() != maximumMessageBytes ||
		!isDescriptorDigest(response.Msg.GetDescriptorDigest()) ||
		response.Msg.GetStatus().GetAvailability() != v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_AVAILABLE ||
		!bytes.Equal(response.Msg.GetNonceProof(), nonceProof(nonce)) {
		return "", connect.NewError(connect.CodeDataLoss, errors.New("invalid handshake response"))
	}
	session := response.Header().Get(sessionHeader)
	if session == "" || len(session) > 256 {
		return "", connect.NewError(connect.CodeDataLoss, errors.New("handshake session is missing or invalid"))
	}
	return session, nil
}

func (client *Client) callGetCapabilities(ctx context.Context, session string) (*v1.GetCapabilitiesResponse, []byte, error) {
	requestID := make([]byte, 16)
	if _, err := rand.Read(requestID); err != nil {
		return nil, nil, connect.NewError(connect.CodeInternal, errors.New("cannot generate request ID"))
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, nil, connect.NewError(connect.CodeInvalidArgument, errors.New("request deadline is missing"))
	}
	message := &v1.GetCapabilitiesRequest{Meta: &v1.RpcRequestMeta{
		RequestId:       &v1.OpaqueId{Value: append([]byte(nil), requestID...)},
		DeadlineUnixMs:  uint64(deadline.UnixMilli()),
		ProtocolVersion: protocolVersion(),
	}}
	digest, err := getCapabilitiesRequestDigest(message)
	if err != nil {
		return nil, nil, connect.NewError(connect.CodeInternal, errors.New("cannot digest capabilities request"))
	}
	message.Meta.RequestDigest = digest
	request := connect.NewRequest(message)
	request.Header().Set(sessionHeader, session)
	response, err := client.rpc.GetCapabilities(ctx, request)
	if err != nil {
		return nil, requestID, err
	}
	if response == nil {
		return nil, requestID, connect.NewError(connect.CodeDataLoss, errors.New("capabilities response is missing"))
	}
	return response.Msg, requestID, nil
}

func (client *Client) clearHandshake(session string) {
	client.handshakeMu.Lock()
	if client.handshakeSession == session {
		client.handshakeSession = ""
	}
	client.handshakeMu.Unlock()
}

func validateCapabilitiesResponse(response *v1.GetCapabilitiesResponse, requestID []byte) error {
	if response == nil || response.GetMeta() == nil {
		return errors.New("capabilities response metadata is missing")
	}
	if hasUnknownFields(response) {
		return errors.New("capabilities response contains unknown protocol fields")
	}
	if !bytes.Equal(response.GetMeta().GetRequestId().GetValue(), requestID) {
		return errors.New("capabilities response request ID mismatch")
	}
	if response.GetMeta().GetServerSequence() == 0 {
		return errors.New("capabilities response server sequence is zero")
	}
	if !isProtocolVersion(response.GetProtocolVersion()) {
		return errors.New("capabilities response protocol version mismatch")
	}
	if !isDescriptorDigest(response.GetMeta().GetDescriptorDigest()) ||
		!isDescriptorDigest(response.GetDescriptorDigest()) ||
		!proto.Equal(response.GetMeta().GetDescriptorDigest(), response.GetDescriptorDigest()) {
		return errors.New("capabilities response descriptor digest mismatch")
	}
	for index, capability := range response.GetCapabilities() {
		if capability == nil {
			return fmt.Errorf("capabilities response item %d is nil", index)
		}
	}
	return nil
}

func contextConnectError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return connect.NewError(connect.CodeDeadlineExceeded, context.DeadlineExceeded)
	}
	if errors.Is(err, context.Canceled) {
		return connect.NewError(connect.CodeCanceled, context.Canceled)
	}
	return err
}
