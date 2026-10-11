package stateappcodec

import (
	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/canonical"
)

var services = map[v1.EffectService]string{v1.EffectService_EFFECT_SERVICE_MODEL: "model", v1.EffectService_EFFECT_SERVICE_WORKSPACE: "workspace", v1.EffectService_EFFECT_SERVICE_EXECUTOR: "executor", v1.EffectService_EFFECT_SERVICE_MCP: "mcp", v1.EffectService_EFFECT_SERVICE_ARTIFACT: "artifact", v1.EffectService_EFFECT_SERVICE_EXTERNAL_TOOL: "external-tool"}
var policies = map[v1.ReplayPolicy]string{v1.ReplayPolicy_REPLAY_POLICY_SAFE: "safe", v1.ReplayPolicy_REPLAY_POLICY_IDEMPOTENCY_KEY: "idempotency-key", v1.ReplayPolicy_REPLAY_POLICY_NEVER: "never", v1.ReplayPolicy_REPLAY_POLICY_CONFIRM: "confirm"}
var phases = map[v1.EffectState]string{v1.EffectState_EFFECT_STATE_PREPARED: "prepared", v1.EffectState_EFFECT_STATE_DISPATCHED: "dispatched", v1.EffectState_EFFECT_STATE_EXTERNALLY_COMMITTED: "externally_committed", v1.EffectState_EFFECT_STATE_SETTLED: "settled", v1.EffectState_EFFECT_STATE_BLOCKED: "blocked"}

// EffectClaimsToValue projects only protocol EffectClaim fields. A protobuf
// EffectRecord cannot reconstruct a SessionEffect: it has no request payload,
// outcome, route digest, start claim or consumption metadata. In particular,
// ResultRef is metadata and is never fabricated into an outcome body here.
func EffectClaimsToValue(record *v1.EffectRecord) (canonical.Map, error) {
	if record == nil || len(record.ProtoReflect().GetUnknown()) != 0 {
		return nil, ErrInvalidEffect
	}
	m := canonical.Map{}
	for key, id := range map[string]*v1.OpaqueId{"tenantId": record.TenantId, "userId": record.UserId, "sessionId": record.SessionId, "turnId": record.TurnId, "effectId": record.EffectId, "invocationId": record.InvocationId} {
		s, ok := idText(id)
		if !ok {
			return nil, ErrInvalidEffect
		}
		m[key] = s
	}
	digest, ok := digestText(record.RequestDigest)
	if !ok {
		return nil, ErrInvalidEffect
	}
	m["requestDigest"] = digest
	service, ok := services[record.Service]
	if !ok {
		return nil, ErrInvalidEffect
	}
	m["service"] = service
	policy, ok := policies[record.ReplayPolicy]
	if !ok {
		return nil, ErrInvalidEffect
	}
	m["replayPolicy"] = policy
	operation, ok := identifier(record.Operation)
	if !ok {
		return nil, ErrInvalidEffect
	}
	m["operation"] = operation
	if record.ParentOperationId != nil {
		parent, ok := idText(record.ParentOperationId)
		if !ok || record.Ordinal > MaximumSafeInteger {
			return nil, ErrInvalidEffect
		}
		m["parentOperationId"] = parent
		m["ordinal"] = record.Ordinal
	} else if record.Ordinal != 0 {
		return nil, ErrInvalidEffect
	}
	return m, nil
}

// EffectRecordFromValue projects authenticated SessionEffect metadata for the
// broker. It does not validate the entire Session aggregate or replace its
// immutable settlement sidecar. The supplied current fence is used only before
// dispatch; an existing dispatch's original generations are preserved.
func EffectRecordFromValue(value canonical.Value, fence broker.Generations) (*v1.EffectRecord, error) {
	m, ok := value.(canonical.Map)
	if !ok {
		return nil, ErrInvalidEffect
	}
	r := &v1.EffectRecord{}
	for key, target := range map[string]**v1.OpaqueId{"tenantId": &r.TenantId, "userId": &r.UserId, "sessionId": &r.SessionId, "turnId": &r.TurnId, "effectId": &r.EffectId, "invocationId": &r.InvocationId} {
		id, ok := protoID(m[key])
		if !ok {
			return nil, ErrInvalidEffect
		}
		*target = id
	}
	if r.RequestDigest, ok = protoDigest(m["requestDigest"]); !ok {
		return nil, ErrInvalidEffect
	}
	if r.Operation, ok = identifier(m["operation"]); !ok {
		return nil, ErrInvalidEffect
	}
	for key, text := range services {
		if m["service"] == text {
			r.Service = key
		}
	}
	for key, text := range policies {
		if m["replayPolicy"] == text {
			r.ReplayPolicy = key
		}
	}
	for key, text := range phases {
		if m["phase"] == text {
			r.State = key
		}
	}
	if r.Service == 0 || r.ReplayPolicy == 0 || r.State == 0 {
		return nil, ErrInvalidEffect
	}
	parent, hasParent := m["parentOperationId"]
	ordinal, hasOrdinal := m["ordinal"]
	if hasParent != hasOrdinal {
		return nil, ErrInvalidEffect
	}
	if hasParent {
		if r.ParentOperationId, ok = protoID(parent); !ok {
			return nil, ErrInvalidEffect
		}
		if r.Ordinal, ok = safeUint(ordinal, 0); !ok {
			return nil, ErrInvalidEffect
		}
	}
	if r.DispatchAttempt, ok = safeUint(m["dispatchAttempt"], 0); !ok {
		return nil, ErrInvalidEffect
	}
	last, exists := m["lastDispatch"]
	if !exists {
		return nil, ErrInvalidEffect
	}
	if last == nil {
		if r.DispatchAttempt != 0 {
			return nil, ErrInvalidEffect
		}
		r.TurnLeaseGeneration = fence.TurnLease
		r.PlacementGeneration = fence.Placement
		r.SandboxGeneration = fence.Sandbox
		r.AuthorizationGeneration = fence.Authorization
	} else {
		d, ok := last.(canonical.Map)
		if !ok {
			return nil, ErrInvalidEffect
		}
		attempt, ok := safeUint(d["dispatchAttempt"], 1)
		if !ok || attempt != r.DispatchAttempt {
			return nil, ErrInvalidEffect
		}
		for key, target := range map[string]*uint64{"turnLeaseGeneration": &r.TurnLeaseGeneration, "placementGeneration": &r.PlacementGeneration, "sandboxGeneration": &r.SandboxGeneration, "authorizationGeneration": &r.AuthorizationGeneration, "deadline": &r.DeadlineUnixMs} {
			minimum := uint64(0)
			if key == "deadline" || key == "turnLeaseGeneration" {
				minimum = 1
			}
			n, ok := safeUint(d[key], minimum)
			if !ok {
				return nil, ErrInvalidEffect
			}
			*target = n
		}
		provider, present := d["providerRequestId"]
		if !present {
			return nil, ErrInvalidEffect
		}
		if provider != nil {
			if r.ProviderRequestId, ok = protoID(provider); !ok {
				return nil, ErrInvalidEffect
			}
		}
	}
	for _, n := range []uint64{r.TurnLeaseGeneration, r.PlacementGeneration, r.SandboxGeneration, r.AuthorizationGeneration} {
		if n > MaximumSafeInteger {
			return nil, ErrInvalidEffect
		}
	}
	for key, target := range map[string]**v1.OpaqueId{"resultRef": &r.ResultRef, "externalCommitId": &r.ExternalCommitId} {
		item, present := m[key]
		if !present {
			return nil, ErrInvalidEffect
		}
		if item != nil {
			id, ok := protoID(item)
			if !ok {
				return nil, ErrInvalidEffect
			}
			*target = id
		}
	}
	return r, nil
}
