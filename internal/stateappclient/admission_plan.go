package stateappclient

import (
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/identity"
	"golang.org/x/text/unicode/norm"
)

const admissionPlanIngressPath = "/circulusd/state/v1/session-turn:plan"
const admissionPlanIngressContentType = "application/vnd.circulusd.state-turn-plan-ingress+cbor"
const admissionPlanIngressProtocol = "circulus.state-turn-plan-ingress.v1alpha1"
const admissionPlanIngressDescriptor = "circulus.state-turn-plan-ingress.v1alpha1|major=1|minor=0|scoped-session-admission-plan|fields=protocol,major,minor,schemaDigest,requestId,sentAtUnixMs,tenantId,actorSubjectId,sessionId,expectedAuthorizationGeneration,proposedTurnId,input,inputDigest,idempotencyKeyDigest,requestDigest|maxBytes=2097152|maxDepth=72|maxItems=100000"

var admissionPlanIngressSchemaDigest = fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(admissionPlanIngressDescriptor)))

// AdmissionConfigured is only a lifecycle/configuration guard, never evidence.
func (client *Client) AdmissionConfigured() bool {
	if client == nil {
		return false
	}
	client.lifecycleMu.Lock()
	defer client.lifecycleMu.Unlock()
	return !client.closed && client.admissionKeyID != "" && len(client.admissionRequestKey) == 32 && len(client.admissionResponseKey) == 32
}

type PlanSessionTurnAdmissionRequest struct {
	TenantID                        string
	ActorSubjectID                  string
	SessionID                       string
	ExpectedAuthorizationGeneration uint64
	ProposedTurnID                  string
	Input                           canonical.Value
	InputDigest                     string
	IdempotencyKeyDigest            string
	RequestDigest                   string
}

type AdmissionRuntime struct {
	RuntimeRevisionDigest   string
	EngineKind              string
	AdapterABIVersion       uint64
	CheckpointSchemaVersion uint64
}

type PlanSessionTurnAdmissionResult struct {
	WorkspaceID           string
	CommandID             string
	ExpectedEventSequence uint64
	Runtime               AdmissionRuntime
	TurnLeaseGeneration   uint64
	PlannedAt             uint64
	LeaseExpiresAt        uint64
	ReplayedAdmission     *AdmitSessionTurnResult
}

// SnapshotAdmissionPlanningRequest owns the complete normalized input and
// validates both independent semantic digests before any remote operation.
func SnapshotAdmissionPlanningRequest(request PlanSessionTurnAdmissionRequest) (PlanSessionTurnAdmissionRequest, error) {
	for kind, value := range map[identity.Kind]string{identity.Tenant: request.TenantID, identity.Subject: request.ActorSubjectID, identity.Session: request.SessionID, identity.Turn: request.ProposedTurnID} {
		if _, err := identity.Parse(kind, value); err != nil {
			return request, ErrInvalidRequest
		}
	}
	if request.ExpectedAuthorizationGeneration < 1 || request.ExpectedAuthorizationGeneration > maximumSharedInteger ||
		!digestPattern.MatchString(request.InputDigest) || !digestPattern.MatchString(request.RequestDigest) || !digestPattern.MatchString(request.IdempotencyKeyDigest) {
		return request, ErrInvalidRequest
	}
	input, ok := request.Input.(canonical.Map)
	if !ok || len(input) != 1 {
		return request, ErrInvalidRequest
	}
	messages, ok := input["messages"].(canonical.Array)
	if !ok || len(messages) < 1 || len(messages) > 1024 {
		return request, ErrInvalidRequest
	}
	semantic := make(canonical.Array, len(messages))
	for i, value := range messages {
		message, ok := value.(canonical.Map)
		if !ok || len(message) != 2 || message["role"] != "user" {
			return request, ErrInvalidRequest
		}
		content, ok := message["content"].(string)
		if !ok || content == "" || !norm.NFC.IsNormalString(content) {
			return request, ErrInvalidRequest
		}
		semantic[i] = canonical.Array{"user", content}
	}
	bytes, err := canonical.Encode(request.Input, canonical.Options{MaxBytes: 1 << 20, MaxDepth: 64, MaxItems: 100_000})
	if err != nil {
		return request, ErrInvalidRequest
	}
	owned, err := canonical.Decode(bytes, canonical.Options{MaxBytes: 1 << 20, MaxDepth: 64, MaxItems: 100_000})
	if err != nil {
		return request, ErrInvalidRequest
	}
	digest, err := canonical.StructuredDigest("circulusd.session.turn-input", 1, owned)
	if err != nil || digest != request.InputDigest {
		return request, ErrInvalidRequest
	}
	digest, err = canonical.StructuredDigest("circulusd.public.turn.create", 1, canonical.Map{"sessionId": request.SessionID, "messages": semantic})
	if err != nil || digest != request.RequestDigest {
		return request, ErrInvalidRequest
	}
	request.Input = owned
	return request, nil
}

func AdmissionPlanningCommandID(request PlanSessionTurnAdmissionRequest) (string, error) {
	request, err := SnapshotAdmissionPlanningRequest(request)
	if err != nil {
		return "", err
	}
	digest, err := canonical.StructuredDigest("circulusd.session.admission-plan-command", 1, admissionPlanningBody(request))
	if err != nil {
		return "", ErrInvalidRequest
	}
	return "admission:" + digest, nil
}

func admissionPlanningBody(request PlanSessionTurnAdmissionRequest) canonical.Map {
	return canonical.Map{"tenantId": request.TenantID, "actorSubjectId": request.ActorSubjectID, "sessionId": request.SessionID,
		"expectedAuthorizationGeneration": request.ExpectedAuthorizationGeneration, "proposedTurnId": request.ProposedTurnID, "input": request.Input,
		"inputDigest": request.InputDigest, "idempotencyKeyDigest": request.IdempotencyKeyDigest, "requestDigest": request.RequestDigest}
}

func (client *Client) PlanSessionTurnAdmission(ctx context.Context, request PlanSessionTurnAdmissionRequest) (PlanSessionTurnAdmissionResult, error) {
	var fail PlanSessionTurnAdmissionResult
	if ctx == nil {
		return fail, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return fail, err
	}
	if !client.AdmissionConfigured() {
		return fail, ErrInvalidConfig
	}
	request, err := SnapshotAdmissionPlanningRequest(request)
	if err != nil {
		return fail, err
	}
	result, err := client.invokeAuthenticatedIngress(ctx, authenticatedIngressContract{
		path: admissionPlanIngressPath, contentType: admissionPlanIngressContentType,
		requestMACDomain: "circulusd.state-turn-plan-ingress.request.v1", responseMACDomain: "circulusd.state-turn-plan-ingress.response.v1",
		hostSchemaDigest: dispatchStartHostSchemaDigest, requestOptions: canonical.Options{MaxBytes: 2 << 20, MaxDepth: 72, MaxItems: 100_000}, admissionCredentials: true,
	}, func(requestID string, sentAt int64) canonical.Map {
		body := admissionPlanningBody(request)
		body["protocol"] = admissionPlanIngressProtocol
		body["major"] = int64(1)
		body["minor"] = int64(0)
		body["schemaDigest"] = admissionPlanIngressSchemaDigest
		body["requestId"] = requestID
		body["sentAtUnixMs"] = sentAt
		return body
	})
	if err != nil {
		return fail, err
	}
	return decodeAdmissionPlanningResult(result, request)
}

// DecodeAdmissionPlanningResult revalidates strict shape, scope and the
// deterministic command identity for independently qualified client seams.
func DecodeAdmissionPlanningResult(value canonical.Value, request PlanSessionTurnAdmissionRequest) (PlanSessionTurnAdmissionResult, error) {
	return decodeAdmissionPlanningResult(value, request)
}

func decodeAdmissionPlanningResult(value canonical.Value, request PlanSessionTurnAdmissionRequest) (PlanSessionTurnAdmissionResult, error) {
	var fail PlanSessionTurnAdmissionResult
	validated, err := SnapshotAdmissionPlanningRequest(request)
	if err != nil {
		return fail, ErrInvalidRequest
	}
	request = validated
	record, ok := value.(canonical.Map)
	if !ok {
		return fail, ErrInvalidResponse
	}
	kind, ok := record["kind"].(string)
	if !ok || (kind != "new" && kind != "replay") {
		return fail, ErrInvalidResponse
	}
	expected := 11
	if kind == "new" {
		expected = 16
	}
	if len(record) != expected {
		return fail, ErrInvalidResponse
	}
	scope := canonical.Map{"tenantId": request.TenantID, "actorSubjectId": request.ActorSubjectID, "sessionId": request.SessionID,
		"expectedAuthorizationGeneration": int64(request.ExpectedAuthorizationGeneration), "proposedTurnId": request.ProposedTurnID,
		"inputDigest": request.InputDigest, "idempotencyKeyDigest": request.IdempotencyKeyDigest, "requestDigest": request.RequestDigest}
	for key, want := range scope {
		if record[key] != want {
			return fail, ErrInvalidResponse
		}
	}
	workspace, ok := record["workspaceId"].(string)
	if !ok {
		return fail, ErrInvalidResponse
	}
	if _, err := identity.Parse(identity.Workspace, workspace); err != nil {
		return fail, ErrInvalidResponse
	}
	result := PlanSessionTurnAdmissionResult{WorkspaceID: workspace}
	if kind == "replay" {
		receipt, ok := record["admission"].(canonical.Map)
		if !ok || len(receipt) != 4 {
			return fail, ErrInvalidResponse
		}
		turn, ok := receipt["turnId"].(string)
		if !ok {
			return fail, ErrInvalidResponse
		}
		if _, err := identity.Parse(identity.Turn, turn); err != nil {
			return fail, ErrInvalidResponse
		}
		sequence, ok := admissionPlanInteger(receipt["turnSequence"], 0)
		if !ok {
			return fail, ErrInvalidResponse
		}
		version, ok := admissionPlanInteger(receipt["version"], 1)
		if !ok || version <= sequence {
			return fail, ErrInvalidResponse
		}
		active, ok := receipt["activated"].(bool)
		if !ok {
			return fail, ErrInvalidResponse
		}
		result.ReplayedAdmission = &AdmitSessionTurnResult{TurnID: turn, TurnSequence: sequence, Version: version, Activated: active, Replayed: true}
		return result, nil
	}
	command, err := AdmissionPlanningCommandID(request)
	if err != nil || record["commandId"] != command {
		return fail, ErrInvalidResponse
	}
	result.CommandID = command
	if result.ExpectedEventSequence, ok = admissionPlanInteger(record["expectedEventSequence"], 0); !ok || result.ExpectedEventSequence >= maximumSharedInteger {
		return fail, ErrInvalidResponse
	}
	if result.TurnLeaseGeneration, ok = admissionPlanInteger(record["turnLeaseGeneration"], 1); !ok {
		return fail, ErrInvalidResponse
	}
	if result.PlannedAt, ok = admissionPlanInteger(record["plannedAt"], 0); !ok {
		return fail, ErrInvalidResponse
	}
	if result.LeaseExpiresAt, ok = admissionPlanInteger(record["leaseExpiresAt"], 1); !ok || result.LeaseExpiresAt <= result.PlannedAt || result.LeaseExpiresAt-result.PlannedAt > 300_000 {
		return fail, ErrInvalidResponse
	}
	runtime, ok := record["runtime"].(canonical.Map)
	if !ok || len(runtime) != 4 {
		return fail, ErrInvalidResponse
	}
	digest, ok := runtime["runtimeRevisionDigest"].(string)
	if !ok || !digestPattern.MatchString(digest) {
		return fail, ErrInvalidResponse
	}
	result.Runtime.RuntimeRevisionDigest = digest
	engine, ok := runtime["engineKind"].(string)
	if !ok || (engine != "low-level" && engine != "agent-harness") {
		return fail, ErrInvalidResponse
	}
	result.Runtime.EngineKind = engine
	if result.Runtime.AdapterABIVersion, ok = admissionPlanInteger(runtime["adapterAbiVersion"], 1); !ok {
		return fail, ErrInvalidResponse
	}
	if result.Runtime.CheckpointSchemaVersion, ok = admissionPlanInteger(runtime["checkpointSchemaVersion"], 1); !ok {
		return fail, ErrInvalidResponse
	}
	return result, nil
}

func admissionPlanInteger(value canonical.Value, min uint64) (uint64, bool) {
	number, ok := value.(int64)
	return uint64(number), ok && number >= 0 && uint64(number) >= min && uint64(number) <= maximumSharedInteger
}
