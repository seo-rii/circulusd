package stateappadapter

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/identity"
	"github.com/hancomac/circulusd/internal/stateappclient"
)

type dispatchStartClient interface {
	ClaimDispatchStart(
		context.Context,
		stateappclient.ClaimDispatchStartRequest,
	) (stateappclient.ClaimDispatchStartResult, error)
}

// DispatchStartClaimer is the narrow state-app-backed durability boundary
// consumed by broker.DispatchConsumer. It can issue only claim_dispatch_start;
// the authenticated transport does not expose arbitrary Session mutations.
type DispatchStartClaimer struct {
	client dispatchStartClient
}

func NewDispatchStartClaimer(client *stateappclient.Client) (*DispatchStartClaimer, error) {
	if client == nil {
		return nil, broker.ErrInvalidRequest
	}
	return &DispatchStartClaimer{client: client}, nil
}

func (claimer *DispatchStartClaimer) ClaimDispatchStart(
	ctx context.Context,
	request broker.DispatchStartRequest,
) (broker.DispatchStartClaim, error) {
	if ctx == nil {
		return broker.DispatchStartClaim{}, broker.ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return broker.DispatchStartClaim{}, err
	}
	if claimer == nil || claimer.client == nil {
		return broker.DispatchStartClaim{}, broker.ErrInvalidRequest
	}

	permit := request.Dispatch
	now := request.Now
	deadlineUnixMS := permit.Deadline.UnixMilli()
	providerRequestID := ""
	if permit.ProviderRequestID != (identity.ID{}) {
		providerRequestID = permit.ProviderRequestID.String()
	}
	parentOperationID := ""
	if permit.ParentOperationID != (identity.ID{}) {
		parentOperationID = permit.ParentOperationID.String()
	}
	validService := false
	switch permit.Service {
	case broker.ServiceModel, broker.ServiceWorkspace, broker.ServiceExecutor,
		broker.ServiceMCP, broker.ServiceArtifact, broker.ServiceExternalTool:
		validService = true
	}
	validReplay := false
	switch permit.ReplayPolicy {
	case broker.ReplaySafe, broker.ReplayIdempotencyKey, broker.ReplayNever, broker.ReplayConfirm:
		validReplay = true
	}
	if now.IsZero() || permit.Deadline.IsZero() || !now.Before(permit.Deadline) ||
		request.Authority.ExpiresAt.IsZero() || !now.Before(request.Authority.ExpiresAt) ||
		!permit.Durable || permit.Opaque == "" || permit.EventSequence == 0 ||
		permit.EventSequence >= maximumSharedInteger || permit.DispatchAttempt == 0 ||
		permit.DispatchAttempt > maximumSharedInteger || deadlineUnixMS <= 0 ||
		uint64(deadlineUnixMS) > maximumSharedInteger || permit.Deadline.Nanosecond()%int(time.Millisecond) != 0 ||
		permit.TenantID.Kind() != identity.Tenant || permit.WorkspaceID.Kind() != identity.Workspace ||
		permit.UserID.Kind() != identity.Subject || permit.SessionID.Kind() != identity.Session ||
		permit.TurnID.Kind() != identity.Turn || permit.EffectID.Kind() != identity.Effect ||
		permit.InvocationID.Kind() != identity.Invocation ||
		(permit.ProviderRequestID != (identity.ID{}) && permit.ProviderRequestID.Kind() != identity.Request) ||
		(permit.ParentOperationID != (identity.ID{}) && permit.ParentOperationID.Kind() != identity.Operation) ||
		(permit.ParentOperationID == (identity.ID{}) && permit.Ordinal != 0) ||
		permit.RequestDigest == (broker.Digest{}) || permit.ProviderRouteDigest == (broker.Digest{}) ||
		request.CommandDigest == (broker.Digest{}) || !validService || !validReplay || permit.Operation == "" ||
		permit.Generations.TurnLease > maximumSharedInteger ||
		permit.Generations.Placement > maximumSharedInteger ||
		permit.Generations.Sandbox > maximumSharedInteger ||
		permit.Generations.Authorization > maximumSharedInteger {
		return broker.DispatchStartClaim{}, broker.ErrInvalidRequest
	}
	if request.Authority.TenantID != permit.TenantID ||
		request.Authority.WorkspaceID != permit.WorkspaceID ||
		request.Authority.SessionID != permit.SessionID ||
		request.Authority.TurnID != permit.TurnID ||
		request.Authority.Generations != permit.Generations {
		return broker.DispatchStartClaim{}, broker.ErrFenceMismatch
	}

	requestDigest := fmt.Sprintf("sha256:%x", permit.RequestDigest[:])
	providerRouteDigest := fmt.Sprintf("sha256:%x", permit.ProviderRouteDigest[:])
	commandDigest := fmt.Sprintf("sha256:%x", request.CommandDigest[:])
	parts := [][]byte{
		[]byte("circulusd.dispatch-start-command.v1"),
		[]byte(permit.Opaque),
		[]byte(permit.TenantID.String()),
		[]byte(permit.WorkspaceID.String()),
		[]byte(permit.UserID.String()),
		[]byte(permit.SessionID.String()),
		[]byte(permit.TurnID.String()),
		[]byte(permit.EffectID.String()),
		[]byte(permit.InvocationID.String()),
		permit.RequestDigest[:],
		[]byte(permit.Service),
		[]byte(permit.Operation),
		[]byte(parentOperationID),
		[]byte(strconv.FormatUint(permit.Ordinal, 10)),
		[]byte(permit.ReplayPolicy),
		[]byte(strconv.FormatUint(permit.Generations.TurnLease, 10)),
		[]byte(strconv.FormatUint(permit.Generations.Placement, 10)),
		[]byte(strconv.FormatUint(permit.Generations.Sandbox, 10)),
		[]byte(strconv.FormatUint(permit.Generations.Authorization, 10)),
		[]byte(strconv.FormatUint(permit.DispatchAttempt, 10)),
		[]byte(providerRequestID),
		permit.ProviderRouteDigest[:],
		[]byte(strconv.FormatInt(deadlineUnixMS, 10)),
		[]byte(strconv.FormatUint(permit.EventSequence, 10)),
		request.CommandDigest[:],
	}
	hasher := sha256.New()
	var lengthPrefix [8]byte
	for _, part := range parts {
		binary.BigEndian.PutUint64(lengthPrefix[:], uint64(len(part)))
		_, _ = hasher.Write(lengthPrefix[:])
		_, _ = hasher.Write(part)
	}
	commandID := "dispatch-start-" + hex.EncodeToString(hasher.Sum(nil))

	wireClaims := stateappclient.DispatchPermitClaims{
		TenantID: permit.TenantID.String(), UserID: permit.UserID.String(),
		SessionID: permit.SessionID.String(), TurnID: permit.TurnID.String(),
		EffectID: permit.EffectID.String(), InvocationID: permit.InvocationID.String(),
		RequestDigest: requestDigest, Service: string(permit.Service), Operation: permit.Operation,
		ReplayPolicy: string(permit.ReplayPolicy), ParentOperationID: parentOperationID, Ordinal: permit.Ordinal,
		DispatchAttempt:         permit.DispatchAttempt,
		TurnLeaseGeneration:     permit.Generations.TurnLease,
		PlacementGeneration:     permit.Generations.Placement,
		SandboxGeneration:       permit.Generations.Sandbox,
		AuthorizationGeneration: permit.Generations.Authorization,
		ProviderRouteDigest:     providerRouteDigest, DeadlineUnixMS: uint64(deadlineUnixMS),
	}
	wireRequest := stateappclient.ClaimDispatchStartRequest{
		TenantID: permit.TenantID.String(), WorkspaceID: permit.WorkspaceID.String(),
		SessionID: permit.SessionID.String(),
		CommandID: commandID, ExpectedEventSequence: permit.EventSequence,
		TurnID: permit.TurnID.String(), EffectID: permit.EffectID.String(),
		InvocationID: permit.InvocationID.String(), RequestDigest: requestDigest,
		Fence: stateappclient.DispatchStartFence{
			TurnLeaseGeneration:     permit.Generations.TurnLease,
			PlacementGeneration:     permit.Generations.Placement,
			SandboxGeneration:       permit.Generations.Sandbox,
			AuthorizationGeneration: permit.Generations.Authorization,
		},
		DispatchAttempt: permit.DispatchAttempt, ProviderRequestID: providerRequestID,
		ProviderRouteDigest: providerRouteDigest, DispatchPermitClaims: wireClaims,
		CommandDigest: commandDigest,
	}
	result, err := claimer.client.ClaimDispatchStart(ctx, wireRequest)
	if err != nil {
		var remote *stateappclient.RemoteError
		if !errors.As(err, &remote) {
			return broker.DispatchStartClaim{}, fmt.Errorf("state-app claim dispatch start: %w", err)
		}
		var mapped error
		switch remote.Code {
		case "INVALID_ARGUMENT":
			mapped = broker.ErrInvalidRequest
		case "NOT_FOUND", "FAILED_PRECONDITION", "ABORTED":
			mapped = broker.ErrInvalidEffectState
		case "STALE_GENERATION":
			mapped = broker.ErrStaleGeneration
		case "STALE_DISPATCH_ATTEMPT", "DIGEST_MISMATCH", "PERMISSION_DENIED":
			mapped = broker.ErrFenceMismatch
		case "IDEMPOTENCY_CONFLICT", "ALREADY_EXISTS", "CONFLICT":
			mapped = broker.ErrIdempotencyConflict
		case "LEASE_EXPIRED":
			mapped = broker.ErrLeaseExpired
		case "STORAGE_CONTRACT", "CORRUPT_STATE":
			mapped = broker.ErrDurabilityBarrier
		}
		if mapped == nil {
			return broker.DispatchStartClaim{}, fmt.Errorf("state-app claim dispatch start: %w", err)
		}
		return broker.DispatchStartClaim{}, fmt.Errorf("%w: state-app claim dispatch start: %w", mapped, err)
	}

	if result.OutcomeFresh == result.HostReplayed || result.EffectID != permit.EffectID.String() ||
		result.Permit.DispatchPermitClaims != wireClaims ||
		result.Permit.ProviderRequestID != providerRequestID ||
		result.Permit.CommandDigest != commandDigest ||
		result.Permit.ClaimedEventSequence <= permit.EventSequence ||
		result.Version < result.Permit.ClaimedEventSequence || result.Version > maximumSharedInteger {
		return broker.DispatchStartClaim{}, fmt.Errorf("%w: state-app returned a mismatched dispatch start claim", broker.ErrFenceMismatch)
	}
	receiptDigest := sha256.Sum256([]byte(
		"circulusd.dispatch-start-receipt.v1\x00" + commandID + "\x00" +
			strconv.FormatUint(result.Permit.ClaimedEventSequence, 10),
	))
	return broker.DispatchStartClaim{
		Permit: broker.DispatchStartPermit{
			Dispatch: permit,
			Opaque: broker.OpaquePermit(
				"dispatch-start-receipt-" + hex.EncodeToString(receiptDigest[:]),
			),
			CommandDigest: request.CommandDigest,
			EventSequence: result.Permit.ClaimedEventSequence,
			Durable:       true,
		},
		Fresh: result.OutcomeFresh,
	}, nil
}
