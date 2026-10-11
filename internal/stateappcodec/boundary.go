package stateappcodec

import (
	"crypto/sha256"
	"errors"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/canonical"
)

var ErrInvalidBoundary = errors.New("stateappcodec: invalid engine boundary")

// BoundaryToValue requires a real checkpoint and exactly one protobuf arm. All
// bodies are decoded from their canonical-CBOR bytes; no artifact metadata or
// generic JSON is substituted for a Pi engine result.
func BoundaryToValue(boundary *v1.EngineStepBoundary) (canonical.Map, error) {
	if boundary == nil || len(boundary.ProtoReflect().GetUnknown()) != 0 {
		return nil, ErrInvalidBoundary
	}
	checkpoint, err := CheckpointToValue(boundary.Checkpoint)
	if err != nil {
		return nil, ErrInvalidBoundary
	}
	result := canonical.Map{"checkpoint": checkpoint}
	switch arm := boundary.Boundary.(type) {
	case *v1.EngineStepBoundary_CheckpointOnly:
		if arm == nil || arm.CheckpointOnly == nil || len(arm.CheckpointOnly.ProtoReflect().GetUnknown()) != 0 {
			return nil, ErrInvalidBoundary
		}
		result["kind"] = "checkpoint"
	case *v1.EngineStepBoundary_EffectRequest:
		if arm == nil || arm.EffectRequest == nil {
			return nil, ErrInvalidBoundary
		}
		request, err := intentToValue(arm.EffectRequest)
		if err != nil {
			return nil, err
		}
		result["kind"] = "effect_request"
		result["request"] = request
	case *v1.EngineStepBoundary_TurnComplete:
		if arm == nil || arm.TurnComplete == nil || len(arm.TurnComplete.ProtoReflect().GetUnknown()) != 0 {
			return nil, ErrInvalidBoundary
		}
		value, err := verifiedValue(arm.TurnComplete.Value, arm.TurnComplete.ValueDigest)
		if err != nil {
			return nil, err
		}
		result["kind"] = "turn_complete"
		result["result"] = value
	case *v1.EngineStepBoundary_TurnError:
		if arm == nil || arm.TurnError == nil || len(arm.TurnError.ProtoReflect().GetUnknown()) != 0 {
			return nil, ErrInvalidBoundary
		}
		agentError := arm.TurnError
		code, ok := identifier(agentError.Code)
		if !ok {
			return nil, ErrInvalidBoundary
		}
		message, ok := boundedString(agentError.Message, 4096)
		if !ok {
			return nil, ErrInvalidBoundary
		}
		errorValue := canonical.Map{"code": code, "message": message, "retryable": agentError.Retryable}
		if len(agentError.Details) > 0 {
			details, err := verifiedValue(agentError.Details, agentError.DetailsDigest)
			if err != nil {
				return nil, err
			}
			errorValue["details"] = details
		} else if agentError.DetailsDigest != nil {
			return nil, ErrInvalidBoundary
		}
		result["kind"] = "turn_error"
		result["error"] = errorValue
	default:
		return nil, ErrInvalidBoundary
	}
	return result, nil
}

func intentToValue(intent *v1.EffectIntent) (canonical.Map, error) {
	if len(intent.ProtoReflect().GetUnknown()) != 0 {
		return nil, ErrInvalidBoundary
	}
	service, ok := services[intent.Service]
	if !ok {
		return nil, ErrInvalidBoundary
	}
	policy, ok := policies[intent.ReplayPolicy]
	if !ok {
		return nil, ErrInvalidBoundary
	}
	operation, ok := identifier(intent.Operation)
	if !ok {
		return nil, ErrInvalidBoundary
	}
	digest, ok := digestText(intent.RequestDigest)
	if !ok {
		return nil, ErrInvalidBoundary
	}
	payload, err := canonical.Decode(append([]byte(nil), intent.Payload...), canonical.Options{MaxBytes: maximumValueBytes, MaxDepth: 64, MaxItems: 1_000_000})
	if err != nil {
		return nil, ErrInvalidBoundary
	}
	draft := canonical.Map{"service": service, "operation": operation, "replayPolicy": policy, "payload": payload}
	if intent.ParentOperationId != nil {
		parent, ok := idText(intent.ParentOperationId)
		if !ok || intent.Ordinal > MaximumSafeInteger {
			return nil, ErrInvalidBoundary
		}
		draft["parentOperationId"] = parent
		draft["ordinal"] = intent.Ordinal
	} else if intent.Ordinal != 0 {
		return nil, ErrInvalidBoundary
	}
	actual, err := canonical.StructuredDigest("circulusd.session.effect-request", 1, draft)
	if err != nil || actual != digest {
		return nil, ErrInvalidBoundary
	}
	draft["requestDigest"] = digest
	return draft, nil
}

// Value and details digests bind the exact canonical bytes (not a JSON value or
// a domain-separated checkpoint/request digest).
func verifiedValue(body []byte, digest *v1.Digest) (canonical.Value, error) {
	if _, ok := digestText(digest); !ok {
		return nil, ErrInvalidBoundary
	}
	copy := append([]byte(nil), body...)
	sum := sha256.Sum256(copy)
	if string(sum[:]) != string(digest.Value) {
		return nil, ErrInvalidBoundary
	}
	value, err := canonical.Decode(copy, canonical.Options{MaxBytes: maximumValueBytes, MaxDepth: 64, MaxItems: 1_000_000})
	if err != nil {
		return nil, ErrInvalidBoundary
	}
	return value, nil
}
