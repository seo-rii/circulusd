//go:build linux

package referenceworkload

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"math"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/identity"
	"google.golang.org/protobuf/proto"
)

const (
	maximumWorkloadBytes   = 512 << 10
	maximumWorkloadInteger = uint64(1)<<53 - 1
)

func ReferenceWorkloadCommandDigest(command []byte) (broker.Digest, error) {
	if len(command) == 0 || len(command) > maximumWorkloadBytes {
		return broker.Digest{}, broker.ErrInvalidRequest
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("circulusd.controlrpc.reference-workload-command.v1\x00"))
	_, _ = hash.Write(command)
	var digest broker.Digest
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

func workloadBodyDigest(claim *v1.ReferenceWorkloadClaim, command []byte) (broker.Digest, error) {
	wire, err := (proto.MarshalOptions{Deterministic: true}).Marshal(&v1.StartClaimedWorkloadRequest{Claim: claim, Command: command})
	if err != nil {
		return broker.Digest{}, err
	}
	return broker.Digest(sha256.Sum256(wire)), nil
}

func workloadProtoID(id identity.ID) *v1.OpaqueId {
	if id == (identity.ID{}) {
		return nil
	}
	return &v1.OpaqueId{Value: []byte(id.String())}
}
func workloadProtoDigest(digest broker.Digest) *v1.Digest {
	return &v1.Digest{Algorithm: v1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: append([]byte(nil), digest[:]...)}
}
func workloadDigest(value *v1.Digest) (broker.Digest, error) {
	if value == nil || value.Algorithm != v1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256 || len(value.Value) != sha256.Size {
		return broker.Digest{}, broker.ErrInvalidRequest
	}
	var result broker.Digest
	copy(result[:], value.Value)
	if result == (broker.Digest{}) {
		return broker.Digest{}, broker.ErrInvalidRequest
	}
	return result, nil
}

func workloadService(service broker.EffectService) v1.EffectService {
	switch service {
	case broker.ServiceExecutor:
		return v1.EffectService_EFFECT_SERVICE_EXECUTOR
	case broker.ServiceModel:
		return v1.EffectService_EFFECT_SERVICE_MODEL
	case broker.ServiceWorkspace:
		return v1.EffectService_EFFECT_SERVICE_WORKSPACE
	case broker.ServiceMCP:
		return v1.EffectService_EFFECT_SERVICE_MCP
	case broker.ServiceArtifact:
		return v1.EffectService_EFFECT_SERVICE_ARTIFACT
	case broker.ServiceExternalTool:
		return v1.EffectService_EFFECT_SERVICE_EXTERNAL_TOOL
	default:
		return v1.EffectService_EFFECT_SERVICE_UNSPECIFIED
	}
}
func workloadReplay(policy broker.ReplayPolicy) v1.ReplayPolicy {
	switch policy {
	case broker.ReplaySafe:
		return v1.ReplayPolicy_REPLAY_POLICY_SAFE
	case broker.ReplayIdempotencyKey:
		return v1.ReplayPolicy_REPLAY_POLICY_IDEMPOTENCY_KEY
	case broker.ReplayNever:
		return v1.ReplayPolicy_REPLAY_POLICY_NEVER
	case broker.ReplayConfirm:
		return v1.ReplayPolicy_REPLAY_POLICY_CONFIRM
	default:
		return v1.ReplayPolicy_REPLAY_POLICY_UNSPECIFIED
	}
}

func encodeWorkloadClaim(permit broker.DispatchStartPermit) (*v1.ReferenceWorkloadClaim, error) {
	d := permit.Dispatch
	if !permit.Durable || !d.Durable || len(permit.Opaque) == 0 || len(permit.Opaque) > 16<<10 || len(d.Opaque) == 0 || len(d.Opaque) > 16<<10 ||
		permit.EventSequence <= d.EventSequence || d.EventSequence == 0 || permit.CommandDigest == (broker.Digest{}) || d.RequestDigest == (broker.Digest{}) ||
		d.ProviderRouteDigest == (broker.Digest{}) || d.DispatchAttempt == 0 || d.Generations.TurnLease == 0 || d.Generations.Placement == 0 ||
		d.Generations.Sandbox == 0 || d.Generations.Authorization == 0 || d.Deadline.IsZero() || d.Deadline.UnixMilli() <= 0 ||
		(d.ParentOperationID == (identity.ID{}) && d.Ordinal != 0) ||
		d.Generations.TurnLease > maximumWorkloadInteger || d.Generations.Placement > maximumWorkloadInteger ||
		d.Generations.Sandbox > maximumWorkloadInteger || d.Generations.Authorization > maximumWorkloadInteger ||
		d.Ordinal > maximumWorkloadInteger || d.DispatchAttempt > maximumWorkloadInteger ||
		d.EventSequence > maximumWorkloadInteger || permit.EventSequence > maximumWorkloadInteger || uint64(d.Deadline.UnixMilli()) > maximumWorkloadInteger ||
		!d.Deadline.Equal(time.UnixMilli(d.Deadline.UnixMilli())) || workloadService(d.Service) == 0 || workloadReplay(d.ReplayPolicy) == 0 ||
		d.Operation == "" || len(d.Operation) > 256 || !utf8.ValidString(d.Operation) || strings.TrimSpace(d.Operation) != d.Operation || strings.IndexFunc(d.Operation, unicode.IsControl) >= 0 {
		return nil, broker.ErrInvalidRequest
	}
	for _, item := range []struct {
		id       identity.ID
		kind     identity.Kind
		optional bool
	}{
		{d.TenantID, identity.Tenant, false}, {d.WorkspaceID, identity.Workspace, false}, {d.UserID, identity.Subject, false},
		{d.SessionID, identity.Session, false}, {d.TurnID, identity.Turn, false}, {d.EffectID, identity.Effect, false},
		{d.InvocationID, identity.Invocation, false}, {d.ParentOperationID, identity.Operation, true}, {d.ProviderRequestID, identity.Request, true},
	} {
		if item.optional && item.id == (identity.ID{}) {
			continue
		}
		if item.id.Kind() != item.kind {
			return nil, broker.ErrInvalidRequest
		}
	}
	return &v1.ReferenceWorkloadClaim{
		Dispatch: &v1.DispatchPermit{Value: []byte(d.Opaque), TenantId: workloadProtoID(d.TenantID), UserId: workloadProtoID(d.UserID),
			SessionId: workloadProtoID(d.SessionID), TurnId: workloadProtoID(d.TurnID), EffectId: workloadProtoID(d.EffectID), InvocationId: workloadProtoID(d.InvocationID),
			RequestDigest: workloadProtoDigest(d.RequestDigest), Service: workloadService(d.Service), Operation: d.Operation, ReplayPolicy: workloadReplay(d.ReplayPolicy),
			ParentOperationId: workloadProtoID(d.ParentOperationID), Ordinal: d.Ordinal, DispatchAttempt: d.DispatchAttempt,
			TurnLeaseGeneration: d.Generations.TurnLease, PlacementGeneration: d.Generations.Placement, SandboxGeneration: d.Generations.Sandbox,
			AuthorizationGeneration: d.Generations.Authorization, DeadlineUnixMs: uint64(d.Deadline.UnixMilli())},
		WorkspaceId: workloadProtoID(d.WorkspaceID), StartProof: []byte(permit.Opaque), CommandDigest: workloadProtoDigest(permit.CommandDigest),
		ClaimedEventSequence: permit.EventSequence, DispatchEventSequence: d.EventSequence, ProviderRequestId: workloadProtoID(d.ProviderRequestID),
		ProviderRouteDigest: workloadProtoDigest(d.ProviderRouteDigest),
	}, nil
}

func decodeWorkloadClaim(message *v1.ReferenceWorkloadClaim) (broker.DispatchStartPermit, error) {
	if message == nil || message.Dispatch == nil {
		return broker.DispatchStartPermit{}, broker.ErrInvalidRequest
	}
	p := message.Dispatch
	var permit broker.DispatchStartPermit
	d := &permit.Dispatch
	for _, item := range []struct {
		value    *v1.OpaqueId
		kind     identity.Kind
		target   *identity.ID
		optional bool
	}{
		{p.TenantId, identity.Tenant, &d.TenantID, false}, {message.WorkspaceId, identity.Workspace, &d.WorkspaceID, false}, {p.UserId, identity.Subject, &d.UserID, false},
		{p.SessionId, identity.Session, &d.SessionID, false}, {p.TurnId, identity.Turn, &d.TurnID, false}, {p.EffectId, identity.Effect, &d.EffectID, false},
		{p.InvocationId, identity.Invocation, &d.InvocationID, false}, {p.ParentOperationId, identity.Operation, &d.ParentOperationID, true},
		{message.ProviderRequestId, identity.Request, &d.ProviderRequestID, true},
	} {
		if item.optional && item.value == nil {
			continue
		}
		id, err := identity.Parse(item.kind, string(item.value.GetValue()))
		if err != nil {
			return broker.DispatchStartPermit{}, broker.ErrInvalidRequest
		}
		*item.target = id
	}
	var err error
	if d.RequestDigest, err = workloadDigest(p.RequestDigest); err != nil {
		return broker.DispatchStartPermit{}, err
	}
	if d.ProviderRouteDigest, err = workloadDigest(message.ProviderRouteDigest); err != nil {
		return broker.DispatchStartPermit{}, err
	}
	if permit.CommandDigest, err = workloadDigest(message.CommandDigest); err != nil {
		return broker.DispatchStartPermit{}, err
	}
	for _, service := range []broker.EffectService{broker.ServiceExecutor, broker.ServiceModel, broker.ServiceWorkspace, broker.ServiceMCP, broker.ServiceArtifact, broker.ServiceExternalTool} {
		if workloadService(service) == p.Service {
			d.Service = service
		}
	}
	for _, policy := range []broker.ReplayPolicy{broker.ReplaySafe, broker.ReplayIdempotencyKey, broker.ReplayNever, broker.ReplayConfirm} {
		if workloadReplay(policy) == p.ReplayPolicy {
			d.ReplayPolicy = policy
		}
	}
	if p.DeadlineUnixMs > math.MaxInt64 {
		return broker.DispatchStartPermit{}, broker.ErrInvalidRequest
	}
	d.Opaque, d.Operation, d.Ordinal, d.DispatchAttempt = broker.OpaquePermit(p.Value), p.Operation, p.Ordinal, p.DispatchAttempt
	d.Generations = broker.Generations{TurnLease: p.TurnLeaseGeneration, Placement: p.PlacementGeneration, Sandbox: p.SandboxGeneration, Authorization: p.AuthorizationGeneration}
	d.Deadline, d.EventSequence, d.Durable = time.UnixMilli(int64(p.DeadlineUnixMs)).UTC(), message.DispatchEventSequence, true
	permit.Opaque, permit.EventSequence, permit.Durable = broker.OpaquePermit(message.StartProof), message.ClaimedEventSequence, true
	encoded, err := encodeWorkloadClaim(permit)
	if err != nil || !proto.Equal(encoded, message) {
		return broker.DispatchStartPermit{}, broker.ErrInvalidRequest
	}
	return permit, nil
}

func encodeWorkloadResult(result ReferenceWorkloadResult) (*v1.ReferenceWorkloadResult, error) {
	if result.ExternalCommitID.Kind() != identity.Commit || result.ResultRef.Kind() != identity.Artifact || len(result.Result) > maximumWorkloadBytes {
		return nil, broker.ErrInvalidRequest
	}
	return &v1.ReferenceWorkloadResult{ExternalCommitId: workloadProtoID(result.ExternalCommitID), ResultRef: workloadProtoID(result.ResultRef),
		Result: append([]byte(nil), result.Result...), ResultDigest: sha256Digest(result.Result)}, nil
}
func decodeWorkloadResult(message *v1.ReferenceWorkloadResult) (ReferenceWorkloadResult, error) {
	if message == nil || len(message.Result) > maximumWorkloadBytes || !proto.Equal(message.ResultDigest, sha256Digest(message.Result)) {
		return ReferenceWorkloadResult{}, errors.New("invalid reference workload result")
	}
	commit, err := identity.Parse(identity.Commit, string(message.ExternalCommitId.GetValue()))
	if err != nil {
		return ReferenceWorkloadResult{}, broker.ErrInvalidRequest
	}
	ref, err := identity.Parse(identity.Artifact, string(message.ResultRef.GetValue()))
	if err != nil {
		return ReferenceWorkloadResult{}, broker.ErrInvalidRequest
	}
	result := ReferenceWorkloadResult{ExternalCommitID: commit, ResultRef: ref, Result: bytes.Clone(message.Result)}
	encoded, err := encodeWorkloadResult(result)
	if err != nil || !proto.Equal(encoded, message) {
		return ReferenceWorkloadResult{}, broker.ErrInvalidRequest
	}
	return result, nil
}

func sha256Digest(value []byte) *v1.Digest {
	digest := sha256.Sum256(value)
	return &v1.Digest{Algorithm: v1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: append([]byte(nil), digest[:]...)}
}
