// Package stateappcodec translates the existing Session/Pi canonical contract.
// It owns no ledger, admission authority, program counter or provider result.
package stateappcodec

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"unicode"
	"unicode/utf8"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/canonical"
	"golang.org/x/text/unicode/norm"
)

const (
	MaximumSafeInteger     = uint64(9_007_199_254_740_991)
	maximumCheckpointBytes = 4 << 20
	maximumValueBytes      = 1 << 20
)

var (
	ErrInvalidCheckpoint = errors.New("stateappcodec: invalid checkpoint")
	ErrInvalidSettlement = errors.New("stateappcodec: invalid settlement")
	ErrInvalidEffect     = errors.New("stateappcodec: invalid effect metadata")
	ErrInvalidScope      = errors.New("stateappcodec: invalid blob scope")
	ErrInvalidBlob       = errors.New("stateappcodec: missing or invalid blob")
)

// CheckpointToValue preserves payload bytes, including an empty protocol-level
// genesis. It does not claim that a particular engine can execute those bytes.
func CheckpointToValue(checkpoint *v1.AgentCheckpoint) (canonical.Map, error) {
	if checkpoint == nil || len(checkpoint.ProtoReflect().GetUnknown()) != 0 {
		return nil, ErrInvalidCheckpoint
	}
	kind := map[v1.CheckpointKind]string{v1.CheckpointKind_CHECKPOINT_KIND_GENESIS: "genesis", v1.CheckpointKind_CHECKPOINT_KIND_ENGINE: "engine"}[checkpoint.Kind]
	engine := map[v1.EngineKind]string{v1.EngineKind_ENGINE_KIND_LOW_LEVEL: "low-level", v1.EngineKind_ENGINE_KIND_AGENT_HARNESS: "agent-harness"}[checkpoint.EngineKind]
	encoding := map[v1.CheckpointPayloadEncoding]string{v1.CheckpointPayloadEncoding_CHECKPOINT_PAYLOAD_ENCODING_PROTOBUF: "protobuf", v1.CheckpointPayloadEncoding_CHECKPOINT_PAYLOAD_ENCODING_CANONICAL_CBOR: "canonical-cbor", v1.CheckpointPayloadEncoding_CHECKPOINT_PAYLOAD_ENCODING_OPAQUE_V1: "opaque-v1"}[checkpoint.PayloadEncoding]
	runtime, ok := digestText(checkpoint.RuntimeRevisionDigest)
	if !ok {
		return nil, ErrInvalidCheckpoint
	}
	payload, ok := digestText(checkpoint.PayloadDigest)
	if !ok {
		return nil, ErrInvalidCheckpoint
	}
	session, ok := idText(checkpoint.SessionId)
	if !ok {
		return nil, ErrInvalidCheckpoint
	}
	turn, ok := idText(checkpoint.TurnId)
	if !ok {
		return nil, ErrInvalidCheckpoint
	}
	var predecessor canonical.Value
	if checkpoint.PredecessorDigest != nil {
		var valid bool
		predecessor, valid = digestText(checkpoint.PredecessorDigest)
		if !valid {
			return nil, ErrInvalidCheckpoint
		}
	}
	value := canonical.Map{"kind": kind, "engineKind": engine, "adapterAbiVersion": checkpoint.AdapterAbiVersion, "checkpointSchemaVersion": checkpoint.CheckpointSchemaVersion, "runtimeRevisionDigest": runtime, "sessionId": session, "turnId": turn, "checkpointSequence": checkpoint.CheckpointSequence, "predecessorDigest": predecessor, "payloadEncoding": encoding, "payloadBytes": canonical.Bytes(append([]byte{}, checkpoint.PayloadBytes...)), "payloadDigest": payload}
	if _, err := parseCheckpoint(value, false); err != nil {
		return nil, err
	}
	return value, nil
}

func CheckpointFromValue(value canonical.Value) (*v1.AgentCheckpoint, error) {
	return parseCheckpoint(value, false)
}

// CheckpointDigest hashes the complete inline wire value using the Session
// chain domain. This is deliberately different from SHA-256(payloadBytes).
func CheckpointDigest(checkpoint *v1.AgentCheckpoint) (broker.Digest, error) {
	value, err := CheckpointToValue(checkpoint)
	if err != nil {
		return broker.Digest{}, err
	}
	text, err := canonical.StructuredDigest("circulusd.session.agent-checkpoint", 1, value)
	if err != nil {
		return broker.Digest{}, ErrInvalidCheckpoint
	}
	result, _ := parseDigest(text)
	return broker.Digest(result), nil
}

func parseCheckpoint(value canonical.Value, external bool) (*v1.AgentCheckpoint, error) {
	m, ok := value.(canonical.Map)
	if !ok || len(m) != 12 {
		return nil, ErrInvalidCheckpoint
	}
	bodyField := "payloadBytes"
	if external {
		bodyField = "payloadSize"
	}
	for _, key := range []string{"kind", "engineKind", "adapterAbiVersion", "checkpointSchemaVersion", "runtimeRevisionDigest", "sessionId", "turnId", "checkpointSequence", "predecessorDigest", "payloadEncoding", bodyField, "payloadDigest"} {
		if _, ok := m[key]; !ok {
			return nil, ErrInvalidCheckpoint
		}
	}
	c := &v1.AgentCheckpoint{}
	switch m["kind"] {
	case "genesis":
		c.Kind = v1.CheckpointKind_CHECKPOINT_KIND_GENESIS
	case "engine":
		c.Kind = v1.CheckpointKind_CHECKPOINT_KIND_ENGINE
	default:
		return nil, ErrInvalidCheckpoint
	}
	switch m["engineKind"] {
	case "low-level":
		c.EngineKind = v1.EngineKind_ENGINE_KIND_LOW_LEVEL
	case "agent-harness":
		c.EngineKind = v1.EngineKind_ENGINE_KIND_AGENT_HARNESS
	default:
		return nil, ErrInvalidCheckpoint
	}
	switch m["payloadEncoding"] {
	case "protobuf":
		c.PayloadEncoding = v1.CheckpointPayloadEncoding_CHECKPOINT_PAYLOAD_ENCODING_PROTOBUF
	case "canonical-cbor":
		c.PayloadEncoding = v1.CheckpointPayloadEncoding_CHECKPOINT_PAYLOAD_ENCODING_CANONICAL_CBOR
	case "opaque-v1":
		c.PayloadEncoding = v1.CheckpointPayloadEncoding_CHECKPOINT_PAYLOAD_ENCODING_OPAQUE_V1
	default:
		return nil, ErrInvalidCheckpoint
	}
	if c.AdapterAbiVersion, ok = safeUint(m["adapterAbiVersion"], 1); !ok {
		return nil, ErrInvalidCheckpoint
	}
	if c.CheckpointSchemaVersion, ok = safeUint(m["checkpointSchemaVersion"], 1); !ok {
		return nil, ErrInvalidCheckpoint
	}
	if c.CheckpointSequence, ok = safeUint(m["checkpointSequence"], 0); !ok {
		return nil, ErrInvalidCheckpoint
	}
	if c.RuntimeRevisionDigest, ok = protoDigest(m["runtimeRevisionDigest"]); !ok {
		return nil, ErrInvalidCheckpoint
	}
	if c.PayloadDigest, ok = protoDigest(m["payloadDigest"]); !ok {
		return nil, ErrInvalidCheckpoint
	}
	if c.SessionId, ok = protoID(m["sessionId"]); !ok {
		return nil, ErrInvalidCheckpoint
	}
	if c.TurnId, ok = protoID(m["turnId"]); !ok {
		return nil, ErrInvalidCheckpoint
	}
	if c.Kind == v1.CheckpointKind_CHECKPOINT_KIND_GENESIS {
		if c.CheckpointSequence != 0 || m["predecessorDigest"] != nil {
			return nil, ErrInvalidCheckpoint
		}
	} else {
		if c.CheckpointSequence == 0 {
			return nil, ErrInvalidCheckpoint
		}
		if c.PredecessorDigest, ok = protoDigest(m["predecessorDigest"]); !ok {
			return nil, ErrInvalidCheckpoint
		}
	}
	if external {
		size, ok := safeUint(m["payloadSize"], 1)
		if !ok || size > maximumCheckpointBytes {
			return nil, ErrInvalidCheckpoint
		}
		return c, nil
	}
	body, ok := m["payloadBytes"].(canonical.Bytes)
	if !ok || len(body) > maximumCheckpointBytes {
		return nil, ErrInvalidCheckpoint
	}
	c.PayloadBytes = append([]byte{}, body...)
	if sum := sha256.Sum256(c.PayloadBytes); string(sum[:]) != string(c.PayloadDigest.Value) {
		return nil, ErrInvalidCheckpoint
	}
	return c, nil
}

func safeUint(value canonical.Value, minimum uint64) (uint64, bool) {
	var n uint64
	switch v := value.(type) {
	case uint64:
		n = v
	case int64:
		if v < 0 {
			return 0, false
		}
		n = uint64(v)
	case int:
		if v < 0 {
			return 0, false
		}
		n = uint64(v)
	default:
		return 0, false
	}
	return n, n >= minimum && n <= MaximumSafeInteger
}
func identifier(value canonical.Value) (string, bool) {
	return boundedString(value, 256)
}
func boundedString(value canonical.Value, maximum int) (string, bool) {
	s, ok := value.(string)
	if !ok || len(s) == 0 || len(s) > maximum || !utf8.ValidString(s) || !norm.NFC.IsNormalString(s) {
		return "", false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return "", false
		}
	}
	return s, true
}
func parseDigest(value canonical.Value) ([32]byte, bool) {
	var result [32]byte
	s, ok := value.(string)
	if !ok || len(s) != 71 || s[:7] != "sha256:" {
		return result, false
	}
	for _, c := range s[7:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return result, false
		}
	}
	decoded, err := hex.DecodeString(s[7:])
	if err != nil {
		return result, false
	}
	copy(result[:], decoded)
	return result, true
}
func protoDigest(value canonical.Value) (*v1.Digest, bool) {
	d, ok := parseDigest(value)
	if !ok {
		return nil, false
	}
	return &v1.Digest{Algorithm: v1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: append([]byte(nil), d[:]...)}, true
}
func digestText(d *v1.Digest) (string, bool) {
	if d == nil || len(d.ProtoReflect().GetUnknown()) != 0 || d.Algorithm != v1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256 || len(d.Value) != 32 {
		return "", false
	}
	return "sha256:" + hex.EncodeToString(d.Value), true
}
func protoID(value canonical.Value) (*v1.OpaqueId, bool) {
	s, ok := identifier(value)
	if !ok {
		return nil, false
	}
	return &v1.OpaqueId{Value: []byte(s)}, true
}
func idText(id *v1.OpaqueId) (string, bool) {
	if id == nil || len(id.ProtoReflect().GetUnknown()) != 0 {
		return "", false
	}
	return identifier(string(id.Value))
}
