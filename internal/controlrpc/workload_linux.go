//go:build linux

package controlrpc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math"
	"net/http"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	v1connect "github.com/hancomac/circulusd/api/generated/circulus/v1alpha/circulusv1alphaconnect"
	"google.golang.org/protobuf/proto"
)

const maximumReferenceWorkloadBytes = 512 << 10

// ReferenceWorkloadService is an explicitly configured reference-only wire
// receiver. Transport authentication does not establish durable or fresh broker
// authority. Diagnostic servers have no receiver unless one is configured.
type ReferenceWorkloadService struct {
	receive func(context.Context, *v1.ReferenceWorkloadClaim, []byte) (*v1.ReferenceWorkloadResult, error)
}

// NewReferenceWorkloadService installs only the reference workload RPC callback.
// The control server checks peer UID, boot session, PLATFORMD role, deadline,
// request digest, and unknown fields before invoking it. Claim authorization
// and provider execution remain the explicit receiver's responsibility.
func NewReferenceWorkloadService(receive func(context.Context, *v1.ReferenceWorkloadClaim, []byte) (*v1.ReferenceWorkloadResult, error)) (*ReferenceWorkloadService, error) {
	if receive == nil {
		return nil, errors.New("reference workload receiver is required")
	}
	return &ReferenceWorkloadService{receive: receive}, nil
}

// ReferenceWorkloadClient is an explicit reference-only wire transport. It does
// not mint or authenticate durable start authority. Each Start call sends once;
// its owner must consume a sealed claim before calling and never retry it.
type ReferenceWorkloadClient struct{ client *Client }

func NewReferenceWorkloadClient(client *Client) (*ReferenceWorkloadClient, error) {
	if client == nil || client.closed.Load() || client.peer != v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD ||
		(client.serverPeer != v1.ProtocolPeer_PROTOCOL_PEER_AGENTD && client.serverPeer != v1.ProtocolPeer_PROTOCOL_PEER_EXECUTORD) {
		return nil, errors.New("reference workload transport requires platformd to agentd or executord")
	}
	return &ReferenceWorkloadClient{client: client}, nil
}

func workloadRequestDigest(message *v1.StartClaimedWorkloadRequest) (*v1.Digest, error) {
	if message == nil {
		return nil, errors.New("reference workload request is nil")
	}
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

func (transportClient *ReferenceWorkloadClient) Start(ctx context.Context, claim *v1.ReferenceWorkloadClaim, command []byte) (*v1.ReferenceWorkloadResult, error) {
	if transportClient == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("reference workload transport is nil"))
	}
	client := transportClient.client
	if client == nil || ctx == nil || client.closed.Load() {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("reference workload client is unavailable"))
	}
	if claim == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("reference workload claim is missing"))
	}
	claimSnapshot := proto.Clone(claim).(*v1.ReferenceWorkloadClaim)
	commandSnapshot := bytes.Clone(command)
	requestContext := ctx
	cancel := func() {}
	if _, ok := ctx.Deadline(); !ok {
		requestContext, cancel = context.WithTimeout(ctx, defaultRequestTimeout)
	}
	defer cancel()
	session, err := client.ensureHandshake(requestContext)
	if err != nil {
		return nil, err
	}
	requestID := make([]byte, 16)
	if _, err := rand.Read(requestID); err != nil {
		return nil, err
	}
	deadline, _ := requestContext.Deadline()
	message := &v1.StartClaimedWorkloadRequest{Meta: &v1.RpcRequestMeta{RequestId: &v1.OpaqueId{Value: requestID},
		DeadlineUnixMs: uint64(deadline.UnixMilli()), ProtocolVersion: protocolVersion()}, Claim: claimSnapshot, Command: commandSnapshot}
	message.Meta.RequestDigest, err = workloadRequestDigest(message)
	if err != nil {
		return nil, err
	}
	request := connect.NewRequest(message)
	request.Header().Set(sessionHeader, session)
	// A fresh transport has no previously used connection for net/http to retry.
	// Unlike read-only capabilities, this operation never retries authentication,
	// EOF, cancellation, or any other ambiguous response.
	transport := &http.Transport{DisableCompression: true, DisableKeepAlives: true, DialContext: client.dialContext}
	defer transport.CloseIdleConnections()
	rpc := v1connect.NewReferenceWorkloadServiceClient(&http.Client{Transport: transport}, "http://control.invalid",
		connect.WithReadMaxBytes(maximumMessageBytes), connect.WithSendMaxBytes(maximumMessageBytes))
	response, err := rpc.StartClaimedWorkload(requestContext, request)
	if err != nil {
		return nil, err
	}
	if response == nil || response.Msg == nil || hasUnknownFields(response.Msg) || !response.Msg.ReferenceOnly || response.Msg.Meta == nil ||
		!bytes.Equal(response.Msg.Meta.GetRequestId().GetValue(), requestID) || response.Msg.Meta.ServerSequence == 0 ||
		!isDescriptorDigest(response.Msg.Meta.DescriptorDigest) || !proto.Equal(response.Msg.Claim, claimSnapshot) || !proto.Equal(response.Msg.RequestDigest, message.Meta.RequestDigest) {
		return nil, connect.NewError(connect.CodeDataLoss, errors.New("workload response identity mismatch"))
	}
	if response.Msg.Result == nil || len(response.Msg.Result.Result) > maximumReferenceWorkloadBytes ||
		!proto.Equal(response.Msg.Result.ResultDigest, sha256Digest(response.Msg.Result.Result)) {
		return nil, connect.NewError(connect.CodeDataLoss, errors.New("invalid workload result"))
	}
	return proto.Clone(response.Msg.Result).(*v1.ReferenceWorkloadResult), nil
}

func (handler *controlHandler) StartClaimedWorkload(ctx context.Context, request *connect.Request[v1.StartClaimedWorkloadRequest]) (*connect.Response[v1.StartClaimedWorkloadResponse], error) {
	credential, ok := ctx.Value(peerCredentialContextKey{}).(peerCredential)
	if !ok || request == nil || request.Msg == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("workload peer is unavailable"))
	}
	token := request.Header().Get(sessionHeader)
	if err := handler.verifySession(token, credential.uid, time.Now()); err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("protocol session is invalid"))
	}
	decoded, _ := base64.RawURLEncoding.DecodeString(token) // Signature and length already verified.
	if v1.ProtocolPeer(binary.BigEndian.Uint32(decoded[5:9])) != v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD ||
		(handler.serverPeer != v1.ProtocolPeer_PROTOCOL_PEER_AGENTD && handler.serverPeer != v1.ProtocolPeer_PROTOCOL_PEER_EXECUTORD) {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("workload peer role is forbidden"))
	}
	workload := handler.workload
	if workload == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errors.New("reference workload handler is unavailable"))
	}
	message := request.Msg
	meta := message.Meta
	if hasUnknownFields(message) || meta == nil || len(meta.GetRequestId().GetValue()) != 16 || !isProtocolVersion(meta.ProtocolVersion) ||
		len(meta.IdempotencyKey) != 0 || meta.DeadlineUnixMs == 0 || meta.DeadlineUnixMs > math.MaxInt64 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid workload request metadata"))
	}
	now := time.Now()
	deadline := time.UnixMilli(int64(meta.DeadlineUnixMs))
	if !now.Before(deadline) {
		return nil, connect.NewError(connect.CodeDeadlineExceeded, errors.New("workload request expired"))
	}
	if deadline.Sub(now) > maximumRequestDeadline {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("workload deadline exceeds bound"))
	}
	expected, err := workloadRequestDigest(message)
	if err != nil || !proto.Equal(expected, meta.RequestDigest) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("workload request digest mismatch"))
	}
	if message.Claim == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid reference workload body"))
	}
	if len(message.Command) == 0 || len(message.Command) > maximumReferenceWorkloadBytes {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("workload command exceeds bounds"))
	}
	executeContext, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if err := executeContext.Err(); err != nil {
		return nil, contextConnectError(err)
	}
	result, err := workload.receive(executeContext, proto.Clone(message.Claim).(*v1.ReferenceWorkloadClaim), bytes.Clone(message.Command))
	if err != nil {
		var wireError *connect.Error
		if errors.As(err, &wireError) {
			return nil, wireError
		}
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("reference executor outcome is unproven"))
	}
	if err := executeContext.Err(); err != nil {
		return nil, contextConnectError(err)
	}
	if result == nil || hasUnknownFields(result) || len(result.Result) > maximumReferenceWorkloadBytes ||
		!proto.Equal(result.ResultDigest, sha256Digest(result.Result)) {
		return nil, connect.NewError(connect.CodeInternal, errors.New("reference executor returned invalid result"))
	}
	return connect.NewResponse(&v1.StartClaimedWorkloadResponse{Meta: &v1.RpcResponseMeta{
		RequestId: proto.Clone(meta.RequestId).(*v1.OpaqueId), ServerSequence: handler.sequence.Add(1), DescriptorDigest: descriptorDigest()},
		Claim: proto.Clone(message.Claim).(*v1.ReferenceWorkloadClaim), RequestDigest: proto.Clone(meta.RequestDigest).(*v1.Digest),
		Result: proto.Clone(result).(*v1.ReferenceWorkloadResult), ReferenceOnly: true}), nil
}
