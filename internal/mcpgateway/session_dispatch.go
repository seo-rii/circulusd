package mcpgateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"time"

	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/effectledger"
	"github.com/hancomac/circulusd/internal/identity"
)

const (
	sessionDispatchPayloadVersion int64 = 1
	sessionDispatchResultVersion  int64 = 1
	sessionDispatchEnvelopeBytes        = 2048
)

// SessionDispatchStarter adapts one Session-owned single-start claim to one
// MCP provider attempt. The subordinate ledger stores immutable command bytes
// and observations, never the Session bearer or a second retry authority.
type SessionDispatchStarter struct {
	gateway     *Gateway
	ledger      effectledger.Ledger
	routeDigest broker.Digest
}

// NewReferenceSessionDispatchStarter deliberately names the process-local
// durability status of the currently available subordinate ledger.
func NewReferenceSessionDispatchStarter(
	gateway *Gateway,
	ledger effectledger.Ledger,
	routeDigest broker.Digest,
) (*SessionDispatchStarter, error) {
	if gateway == nil || isNilInterface(ledger) || routeDigest == (broker.Digest{}) {
		return nil, ErrInvalidConfiguration
	}
	limits := ledger.Limits()
	minimumPayloadBytes := int(gateway.bounds.MaxInputBytes) + sessionDispatchEnvelopeBytes
	minimumResultBytes := int(gateway.bounds.MaxOutputBytes+gateway.bounds.MaxExternalCommitIDBytes) + sessionDispatchEnvelopeBytes
	if limits.MaximumPayloadBytes < minimumPayloadBytes || limits.MaximumResultBytes < minimumResultBytes {
		return nil, fmt.Errorf("%w: subordinate ledger limits cannot retain the configured MCP envelopes", ErrInvalidConfiguration)
	}
	return &SessionDispatchStarter{gateway: gateway, ledger: ledger, routeDigest: routeDigest}, nil
}

func (starter *SessionDispatchStarter) RouteDigest() broker.Digest {
	if starter == nil {
		return broker.Digest{}
	}
	return starter.routeDigest
}

// Prepare canonicalizes and copies the complete service payload before it is
// entered in the subordinate ledger. It performs no authorization, credential,
// provider, or gateway-repository operation.
func (starter *SessionDispatchStarter) Prepare(
	ctx context.Context,
	dispatch broker.DispatchPermit,
	runtimeRevision identity.ID,
	call CallRequest,
) (broker.Digest, error) {
	if starter == nil || starter.gateway == nil || ctx == nil {
		return broker.Digest{}, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return broker.Digest{}, err
	}
	if runtimeRevision.Kind() != identity.RuntimeRevision || dispatch.Service != broker.ServiceMCP ||
		dispatch.ProviderRouteDigest != starter.routeDigest || dispatch.Operation != call.ToolName {
		return broker.Digest{}, ErrAuthorityMismatch
	}
	input, requestDigest, err := canonicalizeCall(call, starter.gateway.bounds)
	if err != nil {
		return broker.Digest{}, err
	}
	if dispatch.RequestDigest != broker.Digest(requestDigest) {
		return broker.Digest{}, ErrAuthorityMismatch
	}
	payload, commandDigest, err := encodeSessionDispatchPayload(
		runtimeRevision, call.ServerID, call.ToolName, input, starter.gateway.bounds,
	)
	if err != nil {
		return broker.Digest{}, fmt.Errorf("%w: encode Session MCP command", ErrInvalidRequest)
	}
	if err := starter.ledger.Prepare(ctx, effectledger.Command{
		Dispatch: dispatch, CommandDigest: commandDigest, Payload: payload,
	}); err != nil {
		return broker.Digest{}, err
	}
	return commandDigest, nil
}

func (starter *SessionDispatchStarter) Start(ctx context.Context, claim broker.ClaimedDispatchStart) error {
	if starter == nil || starter.gateway == nil || ctx == nil {
		return ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	claimed, err := starter.ledger.ClaimStart(ctx, claim)
	if err != nil {
		return err
	}
	command, opened := claimed.Open()
	observation, observed := claimed.Observation()
	start, claimOpened := claim.Open()
	if !opened || !observed || !claimOpened {
		return ErrDispatchNotDurable
	}
	payload, err := decodeSessionDispatchPayload(command.Payload, starter.gateway.bounds)
	if err != nil {
		return err
	}
	if err := starter.validateClaimedCommand(start, command, payload); err != nil {
		return err
	}
	sessionPermit, sessionOpened := deriveSessionProviderPermit(claim)
	if !sessionOpened {
		return ErrDispatchNotDurable
	}
	claim = broker.ClaimedDispatchStart{}
	start.Opaque = ""
	start.Dispatch.Opaque = ""
	return starter.startProviderOnce(ctx, start, sessionPermit, observation, payload)
}

type sessionDispatchPayload struct {
	runtimeRevision identity.ID
	serverID        string
	toolName        string
	inputCanonical  []byte
}

// SessionDispatchResult is the bounded provider terminal observation retained
// by the subordinate ledger. It is not Session settlement authority.
type SessionDispatchResult struct {
	Output           []byte
	ExternalCommitID string
}

func (SessionDispatchResult) String() string   { return "mcp-session-result<redacted>" }
func (SessionDispatchResult) GoString() string { return "mcp-session-result<redacted>" }

func DecodeSessionDispatchResult(encoded []byte, bounds Bounds) (SessionDispatchResult, error) {
	if len(encoded) == 0 || validateBounds(bounds) != nil {
		return SessionDispatchResult{}, ErrInvalidRequest
	}
	decoded, err := canonical.Decode(encoded, canonical.Options{
		MaxDepth: 4,
		MaxBytes: int(bounds.MaxOutputBytes + bounds.MaxExternalCommitIDBytes + sessionDispatchEnvelopeBytes),
		MaxItems: 8,
	})
	if err != nil {
		return SessionDispatchResult{}, ErrInvalidRequest
	}
	object, ok := decoded.(canonical.Map)
	if !ok || len(object) != 3 || object["version"] != sessionDispatchResultVersion {
		return SessionDispatchResult{}, ErrInvalidRequest
	}
	output, outputOK := object["output"].(canonical.Bytes)
	if !outputOK {
		if raw, bytesOK := object["output"].([]byte); bytesOK {
			output, outputOK = canonical.Bytes(raw), true
		}
	}
	externalCommitID, commitOK := object["externalCommitId"].(string)
	if !outputOK || !commitOK || len(output) == 0 || uint64(len(output)) > bounds.MaxOutputBytes ||
		(externalCommitID != "" && !validBoundedText(externalCommitID, bounds.MaxExternalCommitIDBytes)) {
		return SessionDispatchResult{}, ErrInvalidRequest
	}
	result := SessionDispatchResult{
		Output: append([]byte(nil), output...), ExternalCommitID: externalCommitID,
	}
	canonicalResult, err := encodeSessionDispatchResult(result, bounds)
	if err != nil || !bytes.Equal(canonicalResult, encoded) {
		return SessionDispatchResult{}, ErrInvalidRequest
	}
	return result, nil
}

func encodeSessionDispatchResult(result SessionDispatchResult, bounds Bounds) ([]byte, error) {
	return canonical.Encode(canonical.Map{
		"version": sessionDispatchResultVersion, "output": canonical.Bytes(result.Output),
		"externalCommitId": result.ExternalCommitID,
	}, canonical.Options{
		MaxDepth: 4,
		MaxBytes: int(bounds.MaxOutputBytes + bounds.MaxExternalCommitIDBytes + sessionDispatchEnvelopeBytes),
		MaxItems: 8,
	})
}

func encodeSessionDispatchPayload(
	runtimeRevision identity.ID,
	serverID string,
	toolName string,
	inputCanonical []byte,
	bounds Bounds,
) ([]byte, broker.Digest, error) {
	options := canonical.Options{
		MaxDepth: bounds.MaxInputDepth + 3,
		MaxBytes: int(bounds.MaxInputBytes) + sessionDispatchEnvelopeBytes,
		MaxItems: canonical.DefaultOptions().MaxItems,
	}
	payload := canonical.Map{
		"version": sessionDispatchPayloadVersion, "runtimeRevision": runtimeRevision.String(),
		"server": serverID, "tool": toolName, "input": canonical.Bytes(inputCanonical),
	}
	encoded, err := canonical.Encode(payload, options)
	if err != nil {
		return nil, broker.Digest{}, err
	}
	digestInput, err := canonical.Encode(canonical.Array{
		"circulusd.hash", int64(1), "mcp.session.dispatch", int64(1), payload,
	}, options)
	if err != nil {
		return nil, broker.Digest{}, err
	}
	return encoded, broker.Digest(sha256.Sum256(digestInput)), nil
}

func decodeSessionDispatchPayload(encoded []byte, bounds Bounds) (sessionDispatchPayload, error) {
	decoded, err := canonical.Decode(encoded, canonical.Options{
		MaxDepth: bounds.MaxInputDepth + 2,
		MaxBytes: int(bounds.MaxInputBytes) + sessionDispatchEnvelopeBytes,
		MaxItems: canonical.DefaultOptions().MaxItems,
	})
	if err != nil {
		return sessionDispatchPayload{}, ErrInvalidRequest
	}
	object, ok := decoded.(canonical.Map)
	if !ok || len(object) != 5 || object["version"] != sessionDispatchPayloadVersion {
		return sessionDispatchPayload{}, ErrInvalidRequest
	}
	runtimeText, runtimeOK := object["runtimeRevision"].(string)
	serverID, serverOK := object["server"].(string)
	toolName, toolOK := object["tool"].(string)
	input, inputOK := object["input"].(canonical.Bytes)
	if !inputOK {
		if raw, bytesOK := object["input"].([]byte); bytesOK {
			input, inputOK = canonical.Bytes(raw), true
		}
	}
	runtimeRevision, parseErr := identity.Parse(identity.RuntimeRevision, runtimeText)
	if !runtimeOK || !serverOK || !toolOK || !inputOK || parseErr != nil ||
		!validIdentifier(serverID, bounds.MaxServerIDBytes) || !validIdentifier(toolName, bounds.MaxToolNameBytes) ||
		len(input) == 0 || uint64(len(input)) > bounds.MaxInputBytes {
		return sessionDispatchPayload{}, ErrInvalidRequest
	}
	return sessionDispatchPayload{
		runtimeRevision: runtimeRevision, serverID: serverID, toolName: toolName,
		inputCanonical: append([]byte(nil), input...),
	}, nil
}

func (starter *SessionDispatchStarter) validateClaimedCommand(
	start broker.DispatchStartPermit,
	command effectledger.Command,
	payload sessionDispatchPayload,
) error {
	dispatch := start.Dispatch
	dispatchBinding := dispatch
	dispatchBinding.Opaque = ""
	reencoded, digest, err := encodeSessionDispatchPayload(
		payload.runtimeRevision, payload.serverID, payload.toolName, payload.inputCanonical, starter.gateway.bounds,
	)
	if err != nil || !bytes.Equal(reencoded, command.Payload) || digest != command.CommandDigest ||
		start.CommandDigest != digest || command.Dispatch != dispatchBinding {
		return ErrAuthorityMismatch
	}
	if dispatch.Service != broker.ServiceMCP || dispatch.Operation != payload.toolName ||
		dispatch.ProviderRouteDigest != starter.routeDigest || dispatch.DispatchAttempt == 0 ||
		dispatch.DispatchAttempt > math.MaxUint32 || dispatch.TenantID.Kind() != identity.Tenant ||
		dispatch.WorkspaceID.Kind() != identity.Workspace || dispatch.UserID.Kind() != identity.Subject ||
		dispatch.SessionID.Kind() != identity.Session || dispatch.TurnID.Kind() != identity.Turn ||
		dispatch.EffectID.Kind() != identity.Effect || dispatch.InvocationID.Kind() != identity.Invocation ||
		dispatch.RequestDigest == (broker.Digest{}) || dispatch.Generations.TurnLease == 0 ||
		dispatch.Generations.Placement == 0 || dispatch.Generations.Sandbox == 0 ||
		dispatch.Generations.Authorization == 0 {
		return ErrAuthorityMismatch
	}
	requestDigest, err := digestCanonicalCall(payload.serverID, payload.toolName, payload.inputCanonical)
	if err != nil || broker.Digest(requestDigest) != dispatch.RequestDigest {
		return ErrAuthorityMismatch
	}
	return nil
}

func (starter *SessionDispatchStarter) startProviderOnce(
	ctx context.Context,
	start broker.DispatchStartPermit,
	sessionPermit SessionProviderPermit,
	observation effectledger.Observation,
	payload sessionDispatchPayload,
) error {
	dispatch := start.Dispatch
	scope := ValidatedAuthority{
		TenantID: dispatch.TenantID, UserID: dispatch.UserID, SessionID: dispatch.SessionID,
		WorkspaceID: dispatch.WorkspaceID, TurnID: dispatch.TurnID, EffectID: dispatch.EffectID,
		InvocationID: dispatch.InvocationID, RuntimeRevision: payload.runtimeRevision,
		Generations: Generations{
			TurnLease: dispatch.Generations.TurnLease, Placement: dispatch.Generations.Placement,
			Sandbox: dispatch.Generations.Sandbox, Policy: dispatch.Generations.Authorization,
		},
	}
	if !validScope(scope) {
		return ErrAuthorityMismatch
	}
	server, found := starter.gateway.servers[serverKey{tenant: scope.TenantID, user: scope.UserID, server: payload.serverID}]
	if !found {
		return starter.recordPreStartFailure(ctx, observation, ErrServerNotAllowed)
	}
	server, err := resolveServerRegistration(server, scope)
	if err != nil {
		return starter.recordPreStartFailure(ctx, observation, err)
	}
	tool, found := starter.gateway.tools[toolKey{serverKey: serverKey{
		tenant: scope.TenantID, user: scope.UserID, server: payload.serverID,
	}, tool: payload.toolName}]
	if !found || broker.ReplayPolicy(tool.ReplayPolicy) != dispatch.ReplayPolicy {
		return starter.recordPreStartFailure(ctx, observation, ErrToolNotAllowed)
	}
	requestDigest := Digest(dispatch.RequestDigest)
	authorization, err := starter.gateway.authorizer.Authorize(ctx, ToolAuthorizationRequest{
		Scope: scope, ServerID: server.ServerID, ToolName: tool.ToolName,
		RequestDigest: requestDigest, Permission: "mcp.tools.call",
	})
	if err != nil || !validAuthorizationPermit(authorization, scope, server.ServerID, tool.ToolName, requestDigest) {
		if err == nil {
			err = ErrAuthorizationMismatch
		}
		return starter.recordPreStartFailure(ctx, observation, err)
	}
	availability, err := starter.gateway.checkAvailability(ctx, server, tool)
	if err != nil {
		return starter.recordPreStartFailure(ctx, observation, err)
	}
	credential, err := starter.gateway.authorizeCredential(ctx, scope, server)
	if err != nil {
		return starter.recordPreStartFailure(ctx, observation, err)
	}
	if (tool.ReplayPolicy == ReplayIdempotencyKey &&
		(!availability.SupportsInvocationLedger || !availability.SupportsIdempotencyKey)) ||
		!availability.DurableNegotiation {
		return starter.recordPreStartFailure(ctx, observation, ErrProviderUnavailable)
	}
	dispatchPermit := DispatchPermit{
		Proof: OpaqueDispatchPermit(sessionPermit.Proof), Durable: true, Scope: scope,
		InvocationID: scope.InvocationID, RequestDigest: requestDigest, ProviderID: server.ProviderID,
		Attempt: uint32(dispatch.DispatchAttempt), EffectRevision: start.EventSequence,
		Authorization: authorization,
	}
	provider := starter.gateway.providers[server.ProviderID]
	negotiationCommand := NegotiationCommand{
		Scope: scope, Server: descriptorFor(server), ToolName: tool.ToolName,
		InvocationID: scope.InvocationID, RequestDigest: requestDigest, Attempt: uint32(dispatch.DispatchAttempt),
		Authorization: authorization, Credential: credential, Dispatch: dispatchPermit, Session: sessionPermit,
	}
	receipt, err := provider.Negotiate(ctx, negotiationCommand)
	if err != nil || !validSessionNegotiation(receipt, negotiationCommand, availability) {
		if err == nil {
			err = ErrProtocolMismatch
		}
		return starter.recordPreStartFailure(ctx, observation, err)
	}
	providerStart := ProviderStartPermit{
		Proof: OpaqueProviderStartPermit(sessionPermit.Proof), Durable: true, Scope: scope,
		InvocationID: scope.InvocationID, RequestDigest: requestDigest, ProviderID: server.ProviderID,
		Attempt: uint32(dispatch.DispatchAttempt), EffectRevision: start.EventSequence, ClaimGeneration: 1,
		LeaseExpiresAtUnixNano: sessionStartDeadline(ctx, starter.gateway.bounds.CancelTimeout),
		Dispatch:               dispatchPermit, Negotiation: receipt,
	}
	providerCommand := ProviderCommand{
		Scope: scope, Server: descriptorFor(server), ToolName: tool.ToolName,
		InputCanonical: append([]byte(nil), payload.inputCanonical...), InvocationID: scope.InvocationID,
		RequestDigest: requestDigest, ReplayPolicy: tool.ReplayPolicy, Attempt: uint32(dispatch.DispatchAttempt),
		Authorization: authorization, Credential: credential, Dispatch: dispatchPermit,
		Negotiation: receipt, Start: providerStart, Session: sessionPermit,
	}
	if tool.ReplayPolicy == ReplayIdempotencyKey {
		providerCommand.IdempotencyKey = scope.InvocationID.String()
	}
	result, startErr := provider.Start(ctx, providerCommand)
	providerRequestID := strings.TrimSpace(result.ProviderRequestID)
	validProviderID := providerRequestID != "" && providerRequestID == result.ProviderRequestID &&
		validBoundedText(providerRequestID, starter.gateway.bounds.MaxProviderRequestIDBytes)
	if validProviderID {
		factContext, cancelFacts := starter.gateway.cleanupContext(ctx)
		err := starter.ledger.RecordAccepted(factContext, observation, providerRequestID)
		cancelFacts()
		if err != nil {
			unknownErr := starter.recordUnknown(ctx, observation, "provider acceptance was not durable")
			starter.gateway.closeProviderCall(ctx, result.Call)
			return errors.Join(err, unknownErr)
		}
	}
	if startErr != nil || isNilInterface(result.Call) || !validProviderID {
		var classified *ProviderDispatchError
		if errors.As(startErr, &classified) && classified.Classification() == DispatchDefinitelyNotSent && !validProviderID {
			terminalErr := starter.recordTerminal(ctx, observation, effectledger.TerminalFailed,
				boundedFailureReason(startErr, "provider rejected dispatch", starter.gateway.bounds.MaxFailureBytes))
			starter.gateway.closeProviderCall(ctx, result.Call)
			return terminalErr
		}
		unknownErr := starter.recordUnknown(ctx, observation,
			boundedFailureReason(startErr, "provider dispatch outcome is unknown", starter.gateway.bounds.MaxFailureBytes))
		starter.gateway.closeProviderCall(ctx, result.Call)
		if validProviderID {
			return unknownErr
		}
		if unknownErr != nil {
			return errors.Join(ErrProviderUnavailable, unknownErr)
		}
		return ErrProviderUnavailable
	}
	return starter.consumeProviderCall(ctx, observation, result.Call)
}

func (starter *SessionDispatchStarter) consumeProviderCall(
	ctx context.Context,
	observation effectledger.Observation,
	call ProviderCall,
) error {
	defer starter.gateway.closeProviderCall(ctx, call)
	var chunkCount uint32
	var streamBytes uint64
	for {
		if err := ctx.Err(); err != nil {
			return errors.Join(err, starter.recordUnknown(ctx, observation, "provider stream was interrupted"))
		}
		event, err := call.Next(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return starter.recordUnknown(ctx, observation, "provider stream ended before completion")
			}
			return starter.recordUnknown(ctx, observation,
				boundedFailureReason(err, "provider stream failed", starter.gateway.bounds.MaxFailureBytes))
		}
		switch event.Kind {
		case ProviderOutputChunk:
			if len(event.Output) != 0 || event.ExternalCommitID != "" ||
				uint64(len(event.Chunk)) > starter.gateway.bounds.MaxChunkBytes ||
				chunkCount >= starter.gateway.bounds.MaxChunks ||
				uint64(len(event.Chunk)) > starter.gateway.bounds.MaxOutputBytes-streamBytes {
				return starter.recordUnknown(ctx, observation, "provider output exceeded the Session MCP boundary")
			}
			chunkCount++
			streamBytes += uint64(len(event.Chunk))
		case ProviderCompleted:
			if len(event.Chunk) != 0 || len(event.Output) == 0 ||
				uint64(len(event.Output)) > starter.gateway.bounds.MaxOutputBytes ||
				(event.ExternalCommitID != "" && !validBoundedText(event.ExternalCommitID, starter.gateway.bounds.MaxExternalCommitIDBytes)) {
				return starter.recordUnknown(ctx, observation, "provider returned an invalid terminal result")
			}
			result, encodeErr := encodeSessionDispatchResult(SessionDispatchResult{
				Output: append([]byte(nil), event.Output...), ExternalCommitID: event.ExternalCommitID,
			}, starter.gateway.bounds)
			if encodeErr != nil {
				return starter.recordUnknown(ctx, observation, "provider terminal result could not be encoded")
			}
			factContext, cancelFacts := starter.gateway.cleanupContext(ctx)
			_, err := starter.ledger.RecordTerminal(factContext, observation, effectledger.Terminal{
				Status: effectledger.TerminalCommitted, Result: result,
			})
			cancelFacts()
			return err
		default:
			return starter.recordUnknown(ctx, observation, "provider returned an invalid event")
		}
	}
}

func (starter *SessionDispatchStarter) recordPreStartFailure(
	ctx context.Context,
	observation effectledger.Observation,
	cause error,
) error {
	reason := boundedFailureReason(cause, "MCP dispatch rejected before provider start", starter.gateway.bounds.MaxFailureBytes)
	if err := starter.recordTerminal(ctx, observation, effectledger.TerminalFailed, reason); err != nil {
		return errors.Join(cause, err)
	}
	return nil
}

func (starter *SessionDispatchStarter) recordUnknown(
	ctx context.Context,
	observation effectledger.Observation,
	reason string,
) error {
	return starter.recordTerminal(ctx, observation, effectledger.TerminalUnknown, reason)
}

func (starter *SessionDispatchStarter) recordTerminal(
	ctx context.Context,
	observation effectledger.Observation,
	status effectledger.TerminalStatus,
	reason string,
) error {
	factContext, cancelFacts := starter.gateway.cleanupContext(ctx)
	defer cancelFacts()
	_, err := starter.ledger.RecordTerminal(factContext, observation, effectledger.Terminal{
		Status: status, Result: []byte(reason),
	})
	return err
}

func deriveSessionProviderPermit(claim broker.ClaimedDispatchStart) (SessionProviderPermit, bool) {
	start, opened := claim.Open()
	if !opened {
		return SessionProviderPermit{}, false
	}
	start.Opaque = ""
	start.Dispatch.Opaque = ""
	proof, err := sessionProviderProof(start)
	if err != nil {
		return SessionProviderPermit{}, false
	}
	return SessionProviderPermit{
		Proof: proof, Durable: true, CommandDigest: Digest(start.CommandDigest),
		RouteDigest: Digest(start.Dispatch.ProviderRouteDigest), DispatchAttempt: start.Dispatch.DispatchAttempt,
		start: start, seal: sessionProviderPermitSeal,
	}, true
}

func sessionProviderProof(start broker.DispatchStartPermit) (Digest, error) {
	dispatch := start.Dispatch
	proofInput := canonical.Array{
		"circulusd.hash", int64(1), "mcp.session.provider-start", int64(1),
		canonical.Map{
			"commandDigest":      canonical.Bytes(start.CommandDigest[:]),
			"startEventSequence": start.EventSequence, "startDurable": start.Durable,
			"dispatch": canonical.Map{
				"tenant": dispatch.TenantID.String(), "workspace": dispatch.WorkspaceID.String(),
				"user": dispatch.UserID.String(), "session": dispatch.SessionID.String(),
				"turn": dispatch.TurnID.String(), "effect": dispatch.EffectID.String(),
				"invocation":    dispatch.InvocationID.String(),
				"requestDigest": canonical.Bytes(dispatch.RequestDigest[:]),
				"service":       string(dispatch.Service), "operation": dispatch.Operation,
				"parentOperation": dispatch.ParentOperationID.String(), "ordinal": dispatch.Ordinal,
				"replayPolicy": string(dispatch.ReplayPolicy),
				"generations": canonical.Map{
					"turnLease": dispatch.Generations.TurnLease, "placement": dispatch.Generations.Placement,
					"sandbox": dispatch.Generations.Sandbox, "authorization": dispatch.Generations.Authorization,
				},
				"attempt":         dispatch.DispatchAttempt,
				"platformRequest": dispatch.ProviderRequestID.String(),
				"routeDigest":     canonical.Bytes(dispatch.ProviderRouteDigest[:]),
				"deadline":        dispatch.Deadline.UTC().Format(time.RFC3339Nano),
				"eventSequence":   dispatch.EventSequence, "durable": dispatch.Durable,
			},
		},
	}
	encoded, err := canonical.Encode(proofInput, canonical.DefaultOptions())
	if err != nil {
		return Digest{}, err
	}
	return Digest(sha256.Sum256(encoded)), nil
}

func validSessionNegotiation(
	receipt StartNegotiationReceipt,
	command NegotiationCommand,
	availability ServerAvailability,
) bool {
	return receipt.Durable && receipt.ConnectionGeneration != 0 && receipt.Scope == command.Scope &&
		receipt.Server == command.Server && receipt.InvocationID == command.InvocationID &&
		receipt.RequestDigest == command.RequestDigest && receipt.Attempt == command.Attempt &&
		receipt.NegotiatedProtocolVersion == command.Server.ProtocolVersion &&
		receipt.Affinity == command.Server.Affinity &&
		receipt.SupportsInvocationLedger == availability.SupportsInvocationLedger &&
		receipt.SupportsIdempotencyKey == availability.SupportsIdempotencyKey
}

func sessionStartDeadline(ctx context.Context, fallback time.Duration) int64 {
	if deadline, ok := ctx.Deadline(); ok {
		return deadline.UnixNano()
	}
	return time.Now().Add(fallback).UnixNano()
}
