package enginegenesis

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/dependency"
	"github.com/hancomac/circulusd/internal/identity"
	"github.com/hancomac/circulusd/internal/stateappadmission"
	"github.com/hancomac/circulusd/internal/stateappcodec"
	"golang.org/x/text/unicode/norm"
)

const (
	genesisPath          = "/circulusd/engine/v1/genesis:create"
	probePath            = "/circulusd/engine/v1/production:probe"
	genesisType          = "application/vnd.circulusd.engine-genesis+cbor"
	probeType            = "application/vnd.circulusd.engine-genesis-probe+cbor"
	genesisProtocol      = "circulus.engine-genesis.v1alpha1"
	probeProtocol        = "circulus.engine-genesis-probe.v1alpha1"
	requestDomain        = "circulusd.engine-genesis.request.v1"
	responseDomain       = "circulusd.engine-genesis.response.v1"
	keyHeader            = "x-circulus-engine-key-id"
	signatureHeader      = "x-circulus-engine-signature"
	maximumRequestBytes  = 2 << 20
	maximumResponseBytes = (4 << 20) + (64 << 10)
	maximumProbeBytes    = 32 << 10
	maximumSharedInteger = uint64(9_007_199_254_740_991)
)

var (
	genesisSchema = fmt.Sprintf("sha256:%x", sha256.Sum256([]byte("circulus.engine-genesis.v1alpha1|major=1|minor=0|operation=create-genesis|scope=tenant,workspace,actor,session,turn,runtime,inputDigest|input=full-public-user-messages|checkpoint=actual-pi-inline|requestMax=2097152|responseMax=4259840|depth=72|items=100000")))
	probeSchema   = fmt.Sprintf("sha256:%x", sha256.Sum256([]byte("circulus.engine-genesis-probe.v1alpha1|major=1|minor=0|native-ed25519|nonce=32|capability=engine-genesis|descriptor=production-dependency-v1|maxBytes=32768")))
	keyPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

func wireOptions(limit int) canonical.Options {
	return canonical.Options{MaxBytes: limit, MaxDepth: 72, MaxItems: 100_000}
}
func digestBytes(value []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(value)) }
func directionalKey(root []byte, direction string) [32]byte {
	hash := hmac.New(sha256.New, root)
	hash.Write([]byte("circulusd.engine-genesis.key." + direction + ".v1\x00"))
	var key [32]byte
	copy(key[:], hash.Sum(nil))
	return key
}
func mac(key [32]byte, parts ...[]byte) string {
	hash := hmac.New(sha256.New, key[:])
	for _, part := range parts {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(part)))
		hash.Write(size[:])
		hash.Write(part)
	}
	return hex.EncodeToString(hash.Sum(nil))
}
func requestMAC(key [32]byte, keyID string, body []byte) string {
	sum := sha256.Sum256(body)
	return mac(key, []byte(requestDomain), []byte(keyID), []byte("POST"), []byte(genesisPath), sum[:])
}
func responseMAC(key [32]byte, keyID, id string, request []byte, status int, body []byte) string {
	req := sha256.Sum256(request)
	resp := sha256.Sum256(body)
	return mac(key, []byte(responseDomain), []byte(keyID), []byte(id), req[:], []byte(fmt.Sprint(status)), []byte(genesisType), resp[:])
}
func validMAC(left, right string) bool {
	a, err := hex.DecodeString(left)
	if err != nil || len(a) != 32 {
		return false
	}
	b, err := hex.DecodeString(right)
	return err == nil && hmac.Equal(a, b) && left == hex.EncodeToString(a)
}

func snapshotRequest(request stateappadmission.GenesisRequest) (stateappadmission.GenesisRequest, canonical.Map, error) {
	for kind, text := range map[identity.Kind]string{identity.Tenant: request.TenantID, identity.Workspace: request.WorkspaceID, identity.Subject: request.ActorSubjectID, identity.Session: request.SessionID, identity.Turn: request.TurnID} {
		if _, err := identity.Parse(kind, text); err != nil {
			return request, nil, ErrInvalidRequest
		}
	}
	if request.Runtime.EngineKind != "low-level" || request.Runtime.AdapterABIVersion != 2 || request.Runtime.CheckpointSchemaVersion != 2 || !digestPattern.MatchString(request.Runtime.RuntimeRevisionDigest) || !digestPattern.MatchString(request.InputDigest) {
		return request, nil, ErrInvalidRequest
	}
	input, ok := request.Input.(canonical.Map)
	if !ok || len(input) != 1 {
		return request, nil, ErrInvalidRequest
	}
	messages, ok := input["messages"].(canonical.Array)
	if !ok || len(messages) < 1 || len(messages) > 1024 {
		return request, nil, ErrInvalidRequest
	}
	for _, candidate := range messages {
		message, ok := candidate.(canonical.Map)
		if !ok || len(message) != 2 || message["role"] != "user" {
			return request, nil, ErrInvalidRequest
		}
		content, ok := message["content"].(string)
		if !ok || content == "" || !norm.NFC.IsNormalString(content) {
			return request, nil, ErrInvalidRequest
		}
	}
	encoded, err := canonical.Encode(input, canonical.Options{MaxBytes: 1 << 20, MaxDepth: 64, MaxItems: 100_000})
	if err != nil {
		return request, nil, ErrInvalidRequest
	}
	request.Input, err = canonical.Decode(encoded, canonical.Options{MaxBytes: 1 << 20, MaxDepth: 64, MaxItems: 100_000})
	if err != nil {
		return request, nil, ErrInvalidRequest
	}
	digest, err := canonical.StructuredDigest("circulusd.session.turn-input", 1, request.Input)
	if err != nil || digest != request.InputDigest {
		return request, nil, ErrInvalidRequest
	}
	body := requestIdentity(request)
	body["input"] = request.Input
	return request, body, nil
}
func requestIdentity(request stateappadmission.GenesisRequest) canonical.Map {
	return canonical.Map{"tenantId": request.TenantID, "workspaceId": request.WorkspaceID, "actorSubjectId": request.ActorSubjectID, "sessionId": request.SessionID, "turnId": request.TurnID, "inputDigest": request.InputDigest,
		"runtime": canonical.Map{"runtimeRevisionDigest": request.Runtime.RuntimeRevisionDigest, "engineKind": request.Runtime.EngineKind, "adapterAbiVersion": request.Runtime.AdapterABIVersion, "checkpointSchemaVersion": request.Runtime.CheckpointSchemaVersion}}
}

func requestFromValue(value canonical.Value) (stateappadmission.GenesisRequest, error) {
	var request stateappadmission.GenesisRequest
	m, ok := value.(canonical.Map)
	if !ok || len(m) != 8 {
		return request, ErrInvalidRequest
	}
	strings := map[string]*string{"tenantId": &request.TenantID, "workspaceId": &request.WorkspaceID, "actorSubjectId": &request.ActorSubjectID, "sessionId": &request.SessionID, "turnId": &request.TurnID, "inputDigest": &request.InputDigest}
	for key, target := range strings {
		text, ok := m[key].(string)
		if !ok {
			return request, ErrInvalidRequest
		}
		*target = text
	}
	r, ok := m["runtime"].(canonical.Map)
	if !ok || len(r) != 4 {
		return request, ErrInvalidRequest
	}
	request.Runtime.EngineKind, ok = r["engineKind"].(string)
	if !ok {
		return request, ErrInvalidRequest
	}
	request.Runtime.RuntimeRevisionDigest, ok = r["runtimeRevisionDigest"].(string)
	if !ok {
		return request, ErrInvalidRequest
	}
	if request.Runtime.AdapterABIVersion, ok = safeInteger(r["adapterAbiVersion"], 1); !ok {
		return request, ErrInvalidRequest
	}
	if request.Runtime.CheckpointSchemaVersion, ok = safeInteger(r["checkpointSchemaVersion"], 1); !ok {
		return request, ErrInvalidRequest
	}
	request.Input = m["input"]
	owned, _, err := snapshotRequest(request)
	return owned, err
}
func safeInteger(value canonical.Value, min uint64) (uint64, bool) {
	number, ok := value.(int64)
	return uint64(number), ok && number >= 0 && uint64(number) >= min && uint64(number) <= maximumSharedInteger
}

func snapshotCheckpoint(checkpoint *v1.AgentCheckpoint, request stateappadmission.GenesisRequest) (*v1.AgentCheckpoint, error) {
	if checkpoint == nil || len(checkpoint.PayloadBytes) < 1 || len(checkpoint.PayloadBytes) > 4<<20 {
		return nil, ErrInvalidResponse
	}
	value, err := stateappcodec.CheckpointToValue(checkpoint)
	if err != nil || value["kind"] != "genesis" || value["sessionId"] != request.SessionID || value["turnId"] != request.TurnID || value["runtimeRevisionDigest"] != request.Runtime.RuntimeRevisionDigest || value["engineKind"] != request.Runtime.EngineKind || checkpoint.AdapterAbiVersion != request.Runtime.AdapterABIVersion || checkpoint.CheckpointSchemaVersion != request.Runtime.CheckpointSchemaVersion || checkpoint.PayloadEncoding != v1.CheckpointPayloadEncoding_CHECKPOINT_PAYLOAD_ENCODING_CANONICAL_CBOR {
		return nil, ErrInvalidResponse
	}
	payload, err := canonical.Decode(checkpoint.PayloadBytes, wireOptions(4<<20))
	if err != nil {
		return nil, ErrInvalidResponse
	}
	state, ok := payload.(canonical.Map)
	if !ok {
		return nil, ErrInvalidResponse
	}
	digest, err := canonical.StructuredDigest("circulusd.session.turn-input", 1, state["turnInput"])
	if err != nil || digest != request.InputDigest {
		return nil, ErrInvalidResponse
	}
	if len(state) != 9 || state["version"] != int64(1) || state["status"] != "ready" || state["beforeTurnCompleted"] != false || state["awaiting"] != nil || state["terminalCode"] != nil {
		return nil, ErrInvalidResponse
	}
	for _, key := range []string{"pendingTools", "completedTools"} {
		array, ok := state[key].(canonical.Array)
		if !ok || len(array) != 0 {
			return nil, ErrInvalidResponse
		}
	}
	core, ok := state["coreState"].(canonical.Map)
	if !ok || len(core) != 4 || core["version"] != int64(2) || core["phase"] != "ready" {
		return nil, ErrInvalidResponse
	}
	for _, key := range []string{"messages", "pendingToolCalls"} {
		array, ok := core[key].(canonical.Array)
		if !ok || len(array) != 0 {
			return nil, ErrInvalidResponse
		}
	}
	owned, err := stateappcodec.CheckpointFromValue(value)
	if err != nil {
		return nil, ErrInvalidResponse
	}
	return owned, nil
}

func descriptorValue(descriptor dependency.Descriptor) canonical.Map {
	groups := make(canonical.Array, len(descriptor.AtomicGroups))
	for i, group := range descriptor.AtomicGroups {
		groups[i] = string(group)
	}
	return canonical.Map{"schemaVersion": descriptor.SchemaVersion, "backendKind": descriptor.BackendKind, "buildDigest": descriptor.BuildDigest, "applicationDigest": descriptor.ApplicationDigest, "instanceId": descriptor.InstanceID, "transactionDomainId": descriptor.TransactionDomainID, "durabilityClass": descriptor.DurabilityClass, "conformanceRunId": descriptor.ConformanceRunID, "conformanceDigest": descriptor.ConformanceDigest, "runtimeKeyId": descriptor.RuntimeKeyID, "probeEpoch": descriptor.ProbeEpoch, "productionEligible": descriptor.ProductionEligible, "atomicGroups": groups}
}
func proofValue(proof dependency.ProbeResponse, nonce []byte) (canonical.Map, error) {
	if len(nonce) != dependency.ChallengeBytes || proof.KeyID != proof.Descriptor.RuntimeKeyID || len(proof.Signature) != ed25519.SignatureSize || !slices.Contains(proof.Descriptor.AtomicGroups, dependency.AtomicEngineGenesis) {
		return nil, ErrInvalidResponse
	}
	if _, err := dependency.ProbeSigningDigest(proof.Descriptor, nonce); err != nil {
		return nil, ErrInvalidResponse
	}
	return canonical.Map{"protocol": probeProtocol, "major": int64(1), "minor": int64(0), "schemaDigest": probeSchema, "nonce": canonical.Bytes(append([]byte(nil), nonce...)), "descriptor": descriptorValue(proof.Descriptor), "keyId": proof.KeyID, "signature": canonical.Bytes(append([]byte(nil), proof.Signature...))}, nil
}
func proofFromValue(value canonical.Value, nonce []byte) (dependency.ProbeResponse, error) {
	var proof dependency.ProbeResponse
	m, ok := value.(canonical.Map)
	if !ok || len(m) != 8 || m["protocol"] != probeProtocol || m["major"] != int64(1) || m["minor"] != int64(0) || m["schemaDigest"] != probeSchema {
		return proof, ErrInvalidResponse
	}
	echo, ok := m["nonce"].(canonical.Bytes)
	if !ok || !bytes.Equal(echo, nonce) {
		return proof, ErrInvalidResponse
	}
	d, ok := m["descriptor"].(canonical.Map)
	if !ok || len(d) != 13 {
		return proof, ErrInvalidResponse
	}
	strings := map[string]*string{"backendKind": &proof.Descriptor.BackendKind, "buildDigest": &proof.Descriptor.BuildDigest, "applicationDigest": &proof.Descriptor.ApplicationDigest, "instanceId": &proof.Descriptor.InstanceID, "transactionDomainId": &proof.Descriptor.TransactionDomainID, "durabilityClass": &proof.Descriptor.DurabilityClass, "conformanceRunId": &proof.Descriptor.ConformanceRunID, "conformanceDigest": &proof.Descriptor.ConformanceDigest, "runtimeKeyId": &proof.Descriptor.RuntimeKeyID}
	for key, target := range strings {
		text, ok := d[key].(string)
		if !ok {
			return proof, ErrInvalidResponse
		}
		*target = text
	}
	version, ok := safeInteger(d["schemaVersion"], 1)
	if !ok || version != 1 {
		return proof, ErrInvalidResponse
	}
	proof.Descriptor.SchemaVersion = 1
	if proof.Descriptor.ProbeEpoch, ok = safeInteger(d["probeEpoch"], 1); !ok {
		return proof, ErrInvalidResponse
	}
	proof.Descriptor.ProductionEligible, ok = d["productionEligible"].(bool)
	if !ok {
		return proof, ErrInvalidResponse
	}
	groups, ok := d["atomicGroups"].(canonical.Array)
	if !ok || len(groups) > 64 {
		return proof, ErrInvalidResponse
	}
	for _, value := range groups {
		text, ok := value.(string)
		if !ok {
			return proof, ErrInvalidResponse
		}
		proof.Descriptor.AtomicGroups = append(proof.Descriptor.AtomicGroups, dependency.AtomicGroup(text))
	}
	proof.KeyID, ok = m["keyId"].(string)
	if !ok {
		return proof, ErrInvalidResponse
	}
	sig, ok := m["signature"].(canonical.Bytes)
	if !ok {
		return proof, ErrInvalidResponse
	}
	proof.Signature = append([]byte(nil), sig...)
	if _, err := proofValue(proof, nonce); err != nil {
		return proof, err
	}
	return proof, nil
}
