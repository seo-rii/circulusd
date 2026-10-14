package stateappcodec

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/canonical"
	"google.golang.org/protobuf/proto"
)

type fixture struct {
	Checkpoints []struct{ Name, WireHex, ExternalHex, PayloadHex, ChainDigest string }
	Settlements []struct{ Name, WireHex, StoredHex, PayloadHex, Digest string }
	Boundaries  []struct{ Name, WireHex string }
}

func golden(t *testing.T) fixture {
	t.Helper()
	body, err := os.ReadFile("../../packages/protocol-types/fixtures/stateapp-pi-codec-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var value fixture
	if err := json.Unmarshal(body, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func fromHex(t *testing.T, text string) []byte {
	t.Helper()
	value, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func value(t *testing.T, text string) canonical.Map {
	t.Helper()
	result, err := canonical.Decode(fromHex(t, text), canonical.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	return result.(canonical.Map)
}
func encoded(t *testing.T, value canonical.Value) []byte {
	t.Helper()
	result, err := canonical.Encode(value, canonical.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func testScope() Scope {
	return Scope{TenantID: "tenant_AAAAAAAAAAAAAAAAAAAAAAAAAA", ActorSubjectID: "subject_AAAAAAAAAAAAAAAAAAAAAAAAAA", SessionID: "sess_AAAAAAAAAAAAAAAAAAAAAAAAAA", AuthorizationGeneration: 1}
}

func TestActualPiCheckpointsRoundTripAndHydrate(t *testing.T) {
	for _, vector := range golden(t).Checkpoints {
		t.Run(vector.Name, func(t *testing.T) {
			wire := value(t, vector.WireHex)
			checkpoint, err := CheckpointFromValue(wire)
			if err != nil {
				t.Fatal(err)
			}
			roundtrip, err := CheckpointToValue(checkpoint)
			if err != nil || !bytes.Equal(encoded(t, roundtrip), fromHex(t, vector.WireHex)) {
				t.Fatalf("checkpoint changed: %v", err)
			}
			digest, err := CheckpointDigest(checkpoint)
			if err != nil || "sha256:"+hex.EncodeToString(digest[:]) != vector.ChainDigest {
				t.Fatalf("chain mismatch: %v", err)
			}
			payload := fromHex(t, vector.PayloadHex)
			calls := 0
			codec, err := New(testScope(), func(_ context.Context, request BlobRequest) (*Blob, error) {
				calls++
				if request.Scope != testScope() || request.Digest != wire["payloadDigest"] {
					t.Fatal("read was not scoped to exact authority and digest")
				}
				return &Blob{Digest: request.Digest, EncodedBytes: len(payload), Bytes: payload}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			hydrated, err := codec.HydrateCheckpoint(context.Background(), value(t, vector.ExternalHex), vector.ChainDigest)
			if err != nil || calls != 1 || !proto.Equal(hydrated, checkpoint) {
				t.Fatalf("hydrate: %v", err)
			}
			payload[0] ^= 1
			if !proto.Equal(hydrated, checkpoint) {
				t.Fatal("reader retained mutable checkpoint bytes")
			}
		})
	}
}

func TestActualPiSettlementsKeepBodiesAndDecimalWrappers(t *testing.T) {
	for _, vector := range golden(t).Settlements {
		t.Run(vector.Name, func(t *testing.T) {
			wire := value(t, vector.WireHex)
			payload := fromHex(t, vector.PayloadHex)
			codec, _ := New(testScope(), func(_ context.Context, request BlobRequest) (*Blob, error) {
				if request.Scope != testScope() || request.Digest != vector.Digest {
					t.Fatal("incorrect blob scope")
				}
				return &Blob{Digest: request.Digest, EncodedBytes: len(payload), Bytes: payload}, nil
			})
			result, err := codec.HydrateSettlement(context.Background(), wire["requestDigest"].(string), value(t, vector.StoredHex))
			if err != nil || !bytes.Equal(encoded(t, result), fromHex(t, vector.WireHex)) {
				t.Fatalf("result body changed: %v", err)
			}
		})
	}
}

func TestCheckpointRejectsInvalidMetadataAndPreservesEmptyGenesis(t *testing.T) {
	base, err := CheckpointFromValue(value(t, golden(t).Checkpoints[0].WireHex))
	if err != nil {
		t.Fatal(err)
	}
	base.PayloadBytes = []byte{}
	sum := sha256.Sum256(nil)
	base.PayloadDigest.Value = sum[:]
	wire, err := CheckpointToValue(base)
	if err != nil {
		t.Fatal(err)
	}
	roundtrip, err := CheckpointFromValue(wire)
	if err != nil || roundtrip.CheckpointSequence != 0 || roundtrip.PredecessorDigest != nil || len(roundtrip.PayloadBytes) != 0 {
		t.Fatalf("empty genesis: %v", err)
	}
	for _, mutate := range []func(*v1.AgentCheckpoint){
		func(c *v1.AgentCheckpoint) { c.CheckpointSequence = 1 },
		func(c *v1.AgentCheckpoint) { c.AdapterAbiVersion = 1 << 53 },
		func(c *v1.AgentCheckpoint) { c.Kind = v1.CheckpointKind_CHECKPOINT_KIND_ENGINE },
		func(c *v1.AgentCheckpoint) { c.PayloadDigest.Value[0] ^= 1 },
		func(c *v1.AgentCheckpoint) { c.PayloadEncoding = v1.CheckpointPayloadEncoding(99) },
		func(c *v1.AgentCheckpoint) { c.SessionId.Value = []byte("bad\n") },
	} {
		copy := proto.Clone(base).(*v1.AgentCheckpoint)
		mutate(copy)
		if _, err := CheckpointToValue(copy); !errors.Is(err, ErrInvalidCheckpoint) {
			t.Fatalf("invalid metadata accepted: %v", err)
		}
	}
}

func TestCheckpointMaximumPayloadAndSafeSequenceAreIndependent(t *testing.T) {
	base, err := CheckpointFromValue(value(t, golden(t).Checkpoints[1].WireHex))
	if err != nil {
		t.Fatal(err)
	}
	base.CheckpointSequence = MaximumSafeInteger
	base.PayloadEncoding = v1.CheckpointPayloadEncoding_CHECKPOINT_PAYLOAD_ENCODING_OPAQUE_V1
	base.PayloadBytes = bytes.Repeat([]byte{0x41}, maximumCheckpointBytes)
	sum := sha256.Sum256(base.PayloadBytes)
	base.PayloadDigest.Value = sum[:]
	wire, err := CheckpointToValue(base)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := CheckpointDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	delete(wire, "payloadBytes")
	wire["payloadSize"] = uint64(maximumCheckpointBytes)
	calls := 0
	codec, _ := New(testScope(), func(_ context.Context, request BlobRequest) (*Blob, error) {
		calls++
		return &Blob{Digest: request.Digest, EncodedBytes: len(base.PayloadBytes), Bytes: base.PayloadBytes}, nil
	})
	hydrated, err := codec.HydrateCheckpoint(context.Background(), wire, "sha256:"+hex.EncodeToString(chain[:]))
	if err != nil || !proto.Equal(base, hydrated) {
		t.Fatalf("4 MiB payload plus metadata rejected: %v", err)
	}
	wire["payloadSize"] = uint64(maximumCheckpointBytes + 1)
	if _, err := codec.HydrateCheckpoint(context.Background(), wire, "sha256:"+hex.EncodeToString(chain[:])); err == nil || calls != 1 {
		t.Fatal("oversized checkpoint reached reader")
	}
	base.CheckpointSequence++
	if _, err := CheckpointToValue(base); err == nil {
		t.Fatal("unsafe checkpoint sequence accepted")
	}
}

func TestHydrationRejectsMissingCorruptAndForeignBeforeRead(t *testing.T) {
	v := golden(t).Checkpoints[1]
	for _, mode := range []string{"missing", "digest", "length", "bytes", "reader", "chain", "scope", "both", "zero"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			codec, _ := New(testScope(), func(_ context.Context, request BlobRequest) (*Blob, error) {
				calls++
				body := fromHex(t, v.PayloadHex)
				blob := &Blob{Digest: request.Digest, EncodedBytes: len(body), Bytes: body}
				switch mode {
				case "missing":
					return nil, nil
				case "digest":
					blob.Digest = "sha256:" + string(bytes.Repeat([]byte{'0'}, 64))
				case "length":
					blob.EncodedBytes++
				case "bytes":
					blob.Bytes[0] ^= 1
				case "reader":
					return nil, errors.New("read failed")
				}
				return blob, nil
			})
			stored := value(t, v.ExternalHex)
			chain := v.ChainDigest
			switch mode {
			case "chain":
				chain = stored["payloadDigest"].(string)
			case "scope":
				stored["sessionId"] = "sess_AAAAAAAAAAAAAAAAAAAAAAAAAM"
			case "both":
				stored["payloadBytes"] = canonical.Bytes{}
			case "zero":
				stored["payloadSize"] = int64(0)
			}
			result, err := codec.HydrateCheckpoint(context.Background(), stored, chain)
			if err == nil || result != nil {
				t.Fatal("failed hydration returned usable checkpoint")
			}
			if (mode == "scope" || mode == "both" || mode == "zero") && calls != 0 {
				t.Fatal("invalid metadata reached reader")
			}
		})
	}
}

func TestSettlementReferenceValidationAndNonSuccessNeedNoReader(t *testing.T) {
	v := golden(t).Settlements[0]
	wire := value(t, v.WireHex)
	request := wire["requestDigest"].(string)
	calls := 0
	codec, _ := New(testScope(), func(context.Context, BlobRequest) (*Blob, error) { calls++; return nil, errors.New("unexpected I/O") })
	for _, outcome := range []canonical.Map{
		{"kind": "error", "code": "FAILED", "message": "request failed", "retryable": false},
		{"kind": "interrupted_unknown", "reason": "provider outcome unknown"},
		{"kind": "abandoned", "reason": "operator decision"},
	} {
		result, err := codec.HydrateSettlement(context.Background(), request, outcome)
		if err != nil || result["outcome"] == nil {
			t.Fatal(err)
		}
	}
	for _, mutate := range []func(canonical.Map){
		func(m canonical.Map) { m["result"] = "artifact_AAAAAAAAAAAAAAAAAAAAAAAAAA" },
		func(m canonical.Map) { m["resultPayloadRef"].(canonical.Map)["encodedBytes"] = int64(0) },
		func(m canonical.Map) { m["resultPayloadRef"].(canonical.Map)["encoding"] = "json" },
	} {
		stored := value(t, v.StoredHex)
		mutate(stored)
		if _, err := codec.HydrateSettlement(context.Background(), request, stored); err == nil {
			t.Fatal("invalid stored outcome accepted")
		}
	}
	if calls != 0 {
		t.Fatal("invalid or non-success outcome read blob")
	}
}

// The state app accepts error settlement messages of up to 4,096 UTF-8 bytes
// (parseAgentError), so hydration must accept the same bound.
func TestSettlementErrorMessageMatchesStateAppBound(t *testing.T) {
	request := value(t, golden(t).Settlements[0].WireHex)["requestDigest"].(string)
	codec, _ := New(testScope(), func(context.Context, BlobRequest) (*Blob, error) { return nil, errors.New("unexpected I/O") })
	for _, test := range []struct {
		message string
		ok      bool
	}{
		{strings.Repeat("a", 256), true},
		{strings.Repeat("a", 257), true},
		{strings.Repeat("a", 4094) + "é", true},
		{strings.Repeat("a", 4096), true},
		{strings.Repeat("a", 4097), false},
		{strings.Repeat("a", 4095) + "é", false},
		{"", false},
		{strings.Repeat("a", 300) + "\xff", false},
		{strings.Repeat("a", 300) + "\n", false},
		{strings.Repeat("a", 300) + "é", false},
	} {
		outcome := canonical.Map{"kind": "error", "code": "FAILED", "message": test.message, "retryable": true}
		result, err := codec.HydrateSettlement(context.Background(), request, outcome)
		if test.ok && (err != nil || result["outcome"].(canonical.Map)["message"] != test.message) {
			t.Fatalf("valid %d-byte message rejected: %v", len(test.message), err)
		}
		if !test.ok && !errors.Is(err, ErrInvalidSettlement) {
			t.Fatalf("invalid %d-byte message accepted: %v", len(test.message), err)
		}
	}
}

func TestHydrationOwnsMetadataBeforeCallingReader(t *testing.T) {
	v := golden(t).Checkpoints[1]
	stored := value(t, v.ExternalHex)
	scope := testScope()
	codec, _ := New(scope, func(_ context.Context, request BlobRequest) (*Blob, error) {
		stored["payloadSize"] = int64(0)
		stored["turnId"] = "changed"
		stored["payloadDigest"] = "changed"
		body := fromHex(t, v.PayloadHex)
		return &Blob{Digest: request.Digest, EncodedBytes: len(body), Bytes: body}, nil
	})
	scope.AuthorizationGeneration = 99
	checkpoint, err := codec.HydrateCheckpoint(context.Background(), stored, v.ChainDigest)
	if err != nil || string(checkpoint.TurnId.Value) != "turn_AAAAAAAAAAAAAAAAAAAAAAAAAA" {
		t.Fatalf("caller mutation crossed read boundary: %v", err)
	}
}

func TestSettlementRejectsCanonicalHashAndItemCountMismatch(t *testing.T) {
	v := golden(t).Settlements[0]
	wire := value(t, v.WireHex)
	for _, mode := range []string{"items", "trailing", "noncanonical", "missing"} {
		t.Run(mode, func(t *testing.T) {
			stored := value(t, v.StoredHex)
			ref := stored["resultPayloadRef"].(canonical.Map)
			body := fromHex(t, v.PayloadHex)
			switch mode {
			case "items":
				ref["encodedItems"] = ref["encodedItems"].(int64) + 1
			case "trailing":
				body = append(body, 0)
			case "noncanonical":
				body = []byte{0x18, 0x00}
			}
			if mode == "trailing" || mode == "noncanonical" {
				sum := sha256.Sum256(body)
				ref["digest"] = "sha256:" + hex.EncodeToString(sum[:])
				ref["encodedBytes"] = int64(len(body))
				ref["encodedItems"] = int64(1)
			}
			codec, _ := New(testScope(), func(_ context.Context, request BlobRequest) (*Blob, error) {
				if mode == "missing" {
					return nil, nil
				}
				return &Blob{Digest: request.Digest, EncodedBytes: len(body), Bytes: body}, nil
			})
			if result, err := codec.HydrateSettlement(context.Background(), wire["requestDigest"].(string), stored); err == nil || result != nil {
				t.Fatal("invalid result body accepted")
			}
		})
	}
}

func TestEffectProjectionPreservesZeroFenceOrdinalAndResultMetadata(t *testing.T) {
	sum := sha256.Sum256([]byte("request"))
	digest := "sha256:" + hex.EncodeToString(sum[:])
	stored := canonical.Map{"tenantId": "tenant", "userId": "user", "sessionId": "session", "turnId": "turn", "effectId": "effect", "invocationId": "invocation", "requestDigest": digest, "service": "external-tool", "operation": "call", "replayPolicy": "safe", "parentOperationId": "parent", "ordinal": int64(0), "phase": "settled", "dispatchAttempt": int64(0), "lastDispatch": nil, "resultRef": "artifact_AAAAAAAAAAAAAAAAAAAAAAAAAA", "externalCommitId": nil, "settlement": canonical.Map{"kind": "abandoned", "reason": "cancelled"}}
	r, err := EffectRecordFromValue(stored, broker.Generations{})
	if err != nil || r.Ordinal != 0 || r.ParentOperationId == nil || r.PlacementGeneration != 0 || string(r.ResultRef.Value) != "artifact_AAAAAAAAAAAAAAAAAAAAAAAAAA" {
		t.Fatalf("effect projection: %v", err)
	}
	claims, err := EffectClaimsToValue(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(claims) != 12 || claims["ordinal"] != uint64(0) || claims["result"] != nil || claims["resultRef"] != nil {
		t.Fatal("metadata fabricated a result or lost ordinal zero")
	}
	stored["dispatchAttempt"] = int64(1)
	stored["lastDispatch"] = canonical.Map{"dispatchAttempt": int64(1), "turnLeaseGeneration": int64(2), "placementGeneration": int64(0), "sandboxGeneration": int64(0), "authorizationGeneration": int64(0), "deadline": int64(10), "providerRequestId": nil}
	r, err = EffectRecordFromValue(stored, broker.Generations{TurnLease: 9, Placement: 9, Sandbox: 9, Authorization: 9})
	if err != nil || r.TurnLeaseGeneration != 2 || r.PlacementGeneration != 0 || r.AuthorizationGeneration != 0 {
		t.Fatal("projection replaced original dispatch fence")
	}
	stored["ordinal"] = uint64(1 << 53)
	if _, err := EffectRecordFromValue(stored, broker.Generations{}); err == nil {
		t.Fatal("unsafe ordinal accepted")
	}
}

func boundaryFixture(t *testing.T, m canonical.Map) *v1.EngineStepBoundary {
	t.Helper()
	checkpoint, err := CheckpointFromValue(m["checkpoint"])
	if err != nil {
		t.Fatal(err)
	}
	b := &v1.EngineStepBoundary{Checkpoint: checkpoint}
	switch m["kind"] {
	case "effect_request":
		r := m["request"].(canonical.Map)
		intent := &v1.EffectIntent{Operation: r["operation"].(string), Payload: encoded(t, r["payload"])}
		intent.RequestDigest, _ = protoDigest(r["requestDigest"])
		for key, text := range services {
			if r["service"] == text {
				intent.Service = key
			}
		}
		for key, text := range policies {
			if r["replayPolicy"] == text {
				intent.ReplayPolicy = key
			}
		}
		if parent, exists := r["parentOperationId"]; exists {
			intent.ParentOperationId, _ = protoID(parent)
			intent.Ordinal, _ = safeUint(r["ordinal"], 0)
		}
		b.Boundary = &v1.EngineStepBoundary_EffectRequest{EffectRequest: intent}
	case "turn_complete":
		body := encoded(t, m["result"])
		sum := sha256.Sum256(body)
		b.Boundary = &v1.EngineStepBoundary_TurnComplete{TurnComplete: &v1.TurnResult{Value: body, ValueDigest: &v1.Digest{Algorithm: v1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: sum[:]}}}
	default:
		t.Fatal("unexpected fixture boundary")
	}
	return b
}

func TestActualPiBoundariesMatchSharedCanonicalValues(t *testing.T) {
	for _, v := range golden(t).Boundaries {
		t.Run(v.Name, func(t *testing.T) {
			message := boundaryFixture(t, value(t, v.WireHex))
			result, err := BoundaryToValue(message)
			if err != nil || !bytes.Equal(encoded(t, result), fromHex(t, v.WireHex)) {
				t.Fatalf("boundary changed: %v", err)
			}
		})
	}
}

func TestBoundaryRejectsMissingUnknownAndMismatchedPayloads(t *testing.T) {
	vectors := golden(t).Boundaries
	model := boundaryFixture(t, value(t, vectors[0].WireHex))
	complete := boundaryFixture(t, value(t, vectors[len(vectors)-1].WireHex))
	for _, mutate := range []func(*v1.EngineStepBoundary){
		func(b *v1.EngineStepBoundary) { b.Checkpoint = nil },
		func(b *v1.EngineStepBoundary) { b.Boundary = nil },
		func(b *v1.EngineStepBoundary) { b.ProtoReflect().SetUnknown([]byte{0x78, 0x01}) },
		func(b *v1.EngineStepBoundary) { b.GetEffectRequest().RequestDigest.Value[0] ^= 1 },
		func(b *v1.EngineStepBoundary) { b.GetEffectRequest().Payload = []byte{0x18, 0x00} },
		func(b *v1.EngineStepBoundary) { b.GetEffectRequest().Ordinal = 1 },
		func(b *v1.EngineStepBoundary) { b.GetEffectRequest().ProtoReflect().SetUnknown([]byte{0x78, 0x01}) },
		func(b *v1.EngineStepBoundary) { b.Boundary = &v1.EngineStepBoundary_CheckpointOnly{} },
	} {
		copy := proto.Clone(model).(*v1.EngineStepBoundary)
		mutate(copy)
		if _, err := BoundaryToValue(copy); !errors.Is(err, ErrInvalidBoundary) {
			t.Fatalf("invalid boundary accepted: %v", err)
		}
	}
	complete.GetTurnComplete().ValueDigest.Value[0] ^= 1
	if _, err := BoundaryToValue(complete); !errors.Is(err, ErrInvalidBoundary) {
		t.Fatal("turn result digest mismatch accepted")
	}
	checkpointOnly := &v1.EngineStepBoundary{Checkpoint: model.Checkpoint, Boundary: &v1.EngineStepBoundary_CheckpointOnly{CheckpointOnly: &v1.Empty{}}}
	if result, err := BoundaryToValue(checkpointOnly); err != nil || result["kind"] != "checkpoint" {
		t.Fatalf("checkpoint-only: %v", err)
	}
	body := encoded(t, canonical.Map{"fraction": canonical.Map{"$pi.number.v1": "1.25"}})
	sum := sha256.Sum256(body)
	agentError := &v1.AgentError{Code: "TEST_FAILURE", Message: string(bytes.Repeat([]byte{'m'}, 4096)), Retryable: true, Details: body, DetailsDigest: &v1.Digest{Algorithm: v1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: sum[:]}}
	errBoundary := &v1.EngineStepBoundary{Checkpoint: model.Checkpoint, Boundary: &v1.EngineStepBoundary_TurnError{TurnError: agentError}}
	if result, err := BoundaryToValue(errBoundary); err != nil || result["error"].(canonical.Map)["details"] == nil {
		t.Fatalf("agent error details: %v", err)
	}
	agentError.Details = nil
	if _, err := BoundaryToValue(errBoundary); err == nil {
		t.Fatal("digest without details accepted")
	}
}
