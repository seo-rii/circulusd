package main

import (
	"bytes"
	"encoding/hex"
	"testing"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
)

// Vectors previously generated with circulusd's generated package
// (formerly sandbox/vectors/main.go); they pin the mirrored digest rules.
func TestNonceProofVector(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x5a}, 32)
	sandboxID := []byte("sandbox_ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	proof := hex.EncodeToString(nonceProof(nonce, sandboxID, 1, v1.ProtocolPeer_PROTOCOL_PEER_SANDBOXD))
	if proof != "c43972172b649256240bd7e8a87461d97e967b5beb6a2585ec72b8f72ddcf8b4" {
		t.Fatalf("nonce proof = %s", proof)
	}
}

func TestRequestDigestVector(t *testing.T) {
	fill := func(n int, b byte) []byte { return bytes.Repeat([]byte{b}, n) }
	opaque := func(text string) *v1.OpaqueId { return &v1.OpaqueId{Value: []byte(text)} }
	effectDigest, _ := hex.DecodeString("581f996626db21ceebfd2250360da42934b75f338c2beacf576863e90997f85d")
	environmentDigest, _ := hex.DecodeString("ba5285161ba6eed0085fb13784ce5c92f70ebc268b94fd66aa1d68a32884204d")
	digest := func(value []byte) *v1.Digest {
		return &v1.Digest{Algorithm: v1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: value}
	}
	sandboxID := []byte("sandbox_ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	request := &v1.SpawnProcessRequest{
		Meta: &v1.RpcRequestMeta{
			RequestId:       &v1.OpaqueId{Value: fill(16, 0x11)},
			DeadlineUnixMs:  1_800_000_000_000,
			IdempotencyKey:  fill(24, 0x22),
			ProtocolVersion: protocolVersion(),
			// Any request digest must be ignored by requestDigest.
			RequestDigest: digest(fill(32, 0x99)),
		},
		DispatchPermit: &v1.DispatchPermit{
			Value: fill(32, 0x33), TenantId: opaque("tenant_local"), UserId: opaque("subject_local"),
			SessionId: opaque("sess_1"), TurnId: opaque("turn_1"), EffectId: opaque("effect_1"), InvocationId: opaque("inv_1"),
			RequestDigest: digest(effectDigest), Service: v1.EffectService_EFFECT_SERVICE_EXECUTOR, Operation: "executor.run",
			ReplayPolicy: v1.ReplayPolicy_REPLAY_POLICY_NEVER, DispatchAttempt: 1, TurnLeaseGeneration: 1, PlacementGeneration: 1,
			SandboxGeneration: 1, AuthorizationGeneration: 1, DeadlineUnixMs: 1_800_000_000_000,
		},
		Sandbox: &v1.SandboxHandle{
			SandboxId: &v1.OpaqueId{Value: sandboxID}, Generation: 1,
			Backend: v1.ExecutionBackend_EXECUTION_BACKEND_NSJAIL, ExecutionEnvironmentDigest: digest(environmentDigest),
		},
		WorkspaceProtection: &v1.WorkspaceProtectionPermit{
			Value: fill(32, 0x44), TenantId: opaque("tenant_local"), UserId: opaque("subject_local"), WorkspaceId: opaque("ws_1"),
			LeaseId: opaque("lease_1"), InvocationId: opaque("inv_1"), RequestDigest: digest(effectDigest), EffectId: opaque("effect_1"),
			SessionId: opaque("sess_1"), SandboxId: &v1.OpaqueId{Value: sandboxID}, Backend: v1.ExecutionBackend_EXECUTION_BACKEND_NSJAIL,
			AccessMode: v1.WorkspaceAccessMode_WORKSPACE_ACCESS_MODE_READ_WRITE, LeaseGeneration: 1, DispatchAttempt: 1,
			TurnLeaseGeneration: 1, PlacementGeneration: 1, SandboxGeneration: 1, ProjectionGeneration: 1, AuthorizationGeneration: 1,
			IssuedAtUnixMs: 1_700_000_000_000, ExpiresAtUnixMs: 1_800_000_000_000, MaximumHoldDeadlineUnixMs: 1_800_000_000_000, EnqueueSequence: 1,
		},
		InvocationId: opaque("inv_1"), RequestDigest: digest(effectDigest),
		Executable: "python3", Arguments: []string{"-I", "-c", "print('hi')"}, WorkingDirectory: "sess_1",
		TimeoutMs: 30000, OutputLimitBytes: 1048576, StdinMode: v1.StdinMode_STDIN_MODE_CLOSED,
	}
	computed, err := requestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(computed.GetValue()); got != "efba7a64b5087707e00caac60fdfd014ad3d25779194b2b3cdddaaaafc2a2c11" {
		t.Fatalf("request digest = %s", got)
	}
	if request.GetMeta().GetRequestDigest() == nil {
		t.Fatal("requestDigest must not mutate the caller's message")
	}
}
