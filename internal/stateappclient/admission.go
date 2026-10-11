package stateappclient

import (
	"context"
	"unicode"
	"unicode/utf8"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/identity"
	"golang.org/x/text/unicode/norm"
)

const (
	admissionIngressPath         = "/circulusd/state/v1/session-turn:admit"
	admissionIngressContentType  = "application/vnd.circulusd.state-turn-ingress+cbor"
	admissionIngressProtocol     = "circulus.state-turn-ingress.v1alpha1"
	admissionIngressSchemaDigest = "sha256:eb2c41bda12d84937ea40811c3ae0d367653fcbf8e44aeebb9fc3a7363bcb228"
	admissionRequestMACDomain    = "circulusd.state-turn-ingress.request.v1"
	admissionResponseMACDomain   = "circulusd.state-turn-ingress.response.v1"
)

// AdmitSessionTurnRequest is a complete plan from an independently qualified
// authority. This transport never invents checkpoints, CAS versions or leases.
type AdmitSessionTurnRequest struct {
	TenantID                        string
	ActorSubjectID                  string
	SessionID                       string
	ExpectedAuthorizationGeneration uint64
	CommandID                       string
	ExpectedEventSequence           uint64
	TurnID                          string
	Input                           canonical.Value
	InputDigest                     string
	GenesisCheckpoint               canonical.Value
	TurnLeaseGeneration             uint64
	LeaseExpiresAt                  uint64
	IdempotencyKeyDigest            string
	RequestDigest                   string
}

type AdmitSessionTurnResult struct {
	TurnID       string
	TurnSequence uint64
	Activated    bool
	Replayed     bool
	Version      uint64
}

func (client *Client) AdmitSessionTurn(ctx context.Context, request AdmitSessionTurnRequest) (AdmitSessionTurnResult, error) {
	fail := AdmitSessionTurnResult{}
	if ctx == nil {
		return fail, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return fail, err
	}
	if client == nil || client.httpClient == nil {
		return fail, ErrInvalidConfig
	}
	for kind, value := range map[identity.Kind]string{
		identity.Tenant: request.TenantID, identity.Subject: request.ActorSubjectID, identity.Session: request.SessionID, identity.Turn: request.TurnID,
	} {
		if _, err := identity.Parse(kind, value); err != nil {
			return fail, ErrInvalidRequest
		}
	}
	if request.ExpectedAuthorizationGeneration < 1 || request.ExpectedAuthorizationGeneration > maximumSharedInteger ||
		request.ExpectedEventSequence >= maximumSharedInteger || request.TurnLeaseGeneration < 1 || request.TurnLeaseGeneration > maximumSharedInteger ||
		request.LeaseExpiresAt < 1 || request.LeaseExpiresAt > maximumSharedInteger ||
		request.CommandID == "" || len(request.CommandID) > 256 || !utf8.ValidString(request.CommandID) || !norm.NFC.IsNormalString(request.CommandID) ||
		!digestPattern.MatchString(request.InputDigest) || !digestPattern.MatchString(request.RequestDigest) || !digestPattern.MatchString(request.IdempotencyKeyDigest) {
		return fail, ErrInvalidRequest
	}
	for _, char := range request.CommandID {
		if unicode.IsControl(char) {
			return fail, ErrInvalidRequest
		}
	}
	// Encode and decode before the first asynchronous boundary to own all nested
	// input/checkpoint bytes and reject normalization collisions and unbounded data.
	options := canonical.Options{MaxBytes: 8 << 20, MaxDepth: 72, MaxItems: 1_000_000}
	encoded, err := canonical.Encode(canonical.Map{"input": request.Input, "checkpoint": request.GenesisCheckpoint}, options)
	if err != nil {
		return fail, ErrInvalidRequest
	}
	snapshot, err := canonical.Decode(encoded, options)
	if err != nil {
		return fail, ErrInvalidRequest
	}
	values := snapshot.(canonical.Map)
	input, ok := values["input"].(canonical.Map)
	if !ok || len(input) != 1 {
		return fail, ErrInvalidRequest
	}
	messages, ok := input["messages"].(canonical.Array)
	if !ok || len(messages) < 1 || len(messages) > 1024 {
		return fail, ErrInvalidRequest
	}
	semanticMessages := make(canonical.Array, len(messages))
	for i, value := range messages {
		message, ok := value.(canonical.Map)
		if !ok || len(message) != 2 || message["role"] != "user" {
			return fail, ErrInvalidRequest
		}
		content, ok := message["content"].(string)
		if !ok || content == "" {
			return fail, ErrInvalidRequest
		}
		semanticMessages[i] = canonical.Array{"user", content}
	}
	if _, err := canonical.Encode(input, canonical.Options{MaxBytes: 1 << 20, MaxDepth: 64, MaxItems: 100_000}); err != nil {
		return fail, ErrInvalidRequest
	}
	inputDigest, err := canonical.StructuredDigest("circulusd.session.turn-input", 1, input)
	if err != nil || inputDigest != request.InputDigest {
		return fail, ErrInvalidRequest
	}
	requestDigest, err := canonical.StructuredDigest("circulusd.public.turn.create", 1, canonical.Map{"sessionId": request.SessionID, "messages": semanticMessages})
	if err != nil || requestDigest != request.RequestDigest {
		return fail, ErrInvalidRequest
	}
	checkpoint, ok := values["checkpoint"].(canonical.Map)
	if !ok || checkpoint["sessionId"] != request.SessionID || checkpoint["turnId"] != request.TurnID {
		return fail, ErrInvalidRequest
	}
	result, err := client.invokeAuthenticatedIngress(ctx, authenticatedIngressContract{
		path: admissionIngressPath, contentType: admissionIngressContentType, requestMACDomain: admissionRequestMACDomain, responseMACDomain: admissionResponseMACDomain,
		hostSchemaDigest: dispatchStartHostSchemaDigest, requestOptions: options, admissionCredentials: true,
	}, func(requestID string, sentAt int64) canonical.Map {
		return canonical.Map{"protocol": admissionIngressProtocol, "major": int64(1), "minor": int64(0), "schemaDigest": admissionIngressSchemaDigest,
			"requestId": requestID, "sentAtUnixMs": sentAt, "tenantId": request.TenantID, "actorSubjectId": request.ActorSubjectID, "sessionId": request.SessionID,
			"expectedAuthorizationGeneration": request.ExpectedAuthorizationGeneration, "commandId": request.CommandID, "expectedEventSequence": request.ExpectedEventSequence,
			"turnId": request.TurnID, "input": input, "inputDigest": request.InputDigest, "genesisCheckpoint": checkpoint,
			"turnLeaseGeneration": request.TurnLeaseGeneration, "leaseExpiresAt": request.LeaseExpiresAt, "idempotencyKeyDigest": request.IdempotencyKeyDigest, "requestDigest": request.RequestDigest}
	})
	if err != nil {
		return fail, err
	}
	record, ok := result.(canonical.Map)
	if !ok || len(record) != 3 {
		return fail, ErrInvalidResponse
	}
	outcome, ok := record["outcome"].(canonical.Map)
	if !ok || len(outcome) != 4 || outcome["kind"] != "turn_enqueued" {
		return fail, ErrInvalidResponse
	}
	turnID, idOK := outcome["turnId"].(string)
	sequence, seqOK := outcome["turnSequence"].(int64)
	activated, activeOK := outcome["activated"].(bool)
	replayed, replayOK := record["replayed"].(bool)
	version, versionOK := record["version"].(int64)
	if !idOK || !seqOK || !activeOK || !replayOK || !versionOK || sequence < 0 || version <= sequence || uint64(version) > maximumSharedInteger || (!replayed && turnID != request.TurnID) {
		return fail, ErrInvalidResponse
	}
	if _, err := identity.Parse(identity.Turn, turnID); err != nil {
		return fail, ErrInvalidResponse
	}
	return AdmitSessionTurnResult{TurnID: turnID, TurnSequence: uint64(sequence), Activated: activated, Replayed: replayed, Version: uint64(version)}, nil
}
