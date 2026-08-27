package mcpgateway

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/url"
	"path"
	"strings"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/identity"
)

const (
	jsonRPCMethodNotFound = -32601
	jsonRPCInvalidParams  = -32602
	jsonRPCInternalError  = -32603
)

// HandleServerRequest applies the default-deny server-to-client policy. The
// only dispatch paths are narrow central brokers: sampling implementations
// must create a separate model effect through Model Gateway, and RootsProvider
// results are restricted again to the workspace projection here.
func (gateway *Gateway) HandleServerRequest(ctx context.Context, request ServerRequest) (ServerResponse, error) {
	response := ServerResponse{RequestID: request.RequestID}
	if err := ctx.Err(); err != nil {
		return response, err
	}
	if len(request.Authority) == 0 || uint64(len(request.Authority)) > gateway.bounds.MaxAuthorityBytes ||
		!validBoundedText(request.RequestID, gateway.bounds.MaxProviderRequestIDBytes) ||
		!validBoundedText(request.ProviderRequestID, gateway.bounds.MaxProviderRequestIDBytes) ||
		request.ConnectionGeneration == 0 || !validBoundedText(request.Method, gateway.bounds.MaxToolNameBytes) {
		return response, ErrInvalidRequest
	}
	if err := gateway.validateEffect(request.Effect); err != nil {
		return response, err
	}
	switch request.Effect.State {
	case StateDispatched, StateStreaming:
	default:
		return response, ErrInvalidTransition
	}
	attempt, ok := request.Effect.CurrentAttempt()
	if !ok || attempt.ProviderRequestID != request.ProviderRequestID ||
		attempt.Negotiation.ConnectionGeneration != request.ConnectionGeneration {
		return response, ErrAuthorityMismatch
	}
	currentScope, err := gateway.validateCurrentAuthority(ctx, request.Authority, CurrentAuthorityRequest{
		Scope: request.Effect.Scope, RequestDigest: request.Effect.RequestDigest,
		ProviderRequestID: request.ProviderRequestID, Attempt: attempt.Attempt,
		ConnectionGeneration: request.ConnectionGeneration,
		Permission:           "mcp.server_request",
	})
	if err != nil {
		return response, err
	}
	server, _, err := gateway.registrationForEffect(request.Effect)
	if err != nil {
		return response, err
	}
	method := ServerRequestMethod(request.Method)
	methodAllowed := serverMethodAllowed(server.AllowedServerRequests, method)
	paramsInvalid := preflightCanonical(request.Params, 0, gateway.bounds.MaxInputDepth, gateway.bounds.MaxInputBytes) != nil
	var params []byte
	if !paramsInvalid {
		params, err = canonical.Encode(request.Params, canonical.Options{
			MaxDepth: gateway.bounds.MaxInputDepth, MaxBytes: int(gateway.bounds.MaxInputBytes),
			MaxItems: canonical.DefaultOptions().MaxItems,
		})
		paramsInvalid = err != nil
	}
	if paramsInvalid {
		// Do not retain or re-encode attacker-controlled oversized values. The
		// bounded marker still gives this request ID a stable denial receipt.
		params = []byte("invalid-or-oversized-params")
	}
	digestInput, err := canonical.Encode(canonical.Array{
		"circulusd.hash", int64(1), "mcp.server.request", int64(1),
		canonical.Map{
			"parentInvocation":     request.Effect.Scope.InvocationID.String(),
			"parentDigest":         canonical.Bytes(request.Effect.RequestDigest[:]),
			"providerRequest":      request.ProviderRequestID,
			"connectionGeneration": int64(request.ConnectionGeneration),
			"requestId":            request.RequestID,
			"method":               request.Method,
			"params":               canonical.Bytes(params),
		},
	}, canonical.DefaultOptions())
	if err != nil {
		return response, ErrInvalidRequest
	}
	requestDigest := sha256.Sum256(digestInput)
	var childEffectID identity.ID
	var childInvocationID identity.ID
	brokerCancellationRequired := !paramsInvalid && methodAllowed &&
		(method == ServerRequestSampling || method == ServerRequestElicitation)
	if method == ServerRequestSampling && brokerCancellationRequired {
		childEffectID, err = identity.New(identity.Effect)
		if err == nil {
			childInvocationID, err = identity.New(identity.Invocation)
		}
		if err != nil {
			return response, ErrStoreUnavailable
		}
	}
	claimed, err := gateway.repository.ClaimServerRequest(ctx, ServerRequestClaimRequest{
		CurrentScope: currentScope, Parent: cloneEffect(request.Effect), ProviderRequestID: request.ProviderRequestID,
		ConnectionGeneration: request.ConnectionGeneration, RequestID: request.RequestID, Method: request.Method, RequestDigest: requestDigest,
		ChildEffectID: childEffectID, ChildInvocationID: childInvocationID,
		BrokerCancellationRequired: brokerCancellationRequired,
		MaxRequests:                gateway.bounds.MaxEvents, Lease: gateway.bounds.CancelTimeout,
	})
	if err != nil {
		return response, redactedDependencyError(ctx, err, ErrStoreUnavailable,
			ErrInvocationConflict, ErrEffectInFlight, ErrStaleAuthority, ErrInvalidTransition,
			ErrAuthorityMismatch, ErrInvocationNotFound, ErrEventLimit)
	}
	if !claimed.Durable || claimed.Record.ParentInvocationID != request.Effect.Scope.InvocationID ||
		claimed.Record.ProviderRequestID != request.ProviderRequestID || claimed.Record.RequestID != request.RequestID ||
		claimed.Record.ConnectionGeneration != request.ConnectionGeneration ||
		claimed.Record.Method != request.Method || claimed.Record.RequestDigest != requestDigest {
		return response, ErrStoreUnavailable
	}
	if claimed.Record.State == ServerRequestCompleted {
		return cloneServerResponse(claimed.Record.Response), nil
	}
	if !claimed.Fresh || claimed.Record.State != ServerRequestClaimed || !claimed.Record.Permit.Durable ||
		claimed.Record.Permit.Proof == (OpaqueServerRequestPermit{}) || claimed.Record.Permit.Scope != currentScope ||
		claimed.Record.Permit.ParentInvocationID != request.Effect.Scope.InvocationID ||
		claimed.Record.Permit.ProviderRequestID != request.ProviderRequestID ||
		claimed.Record.Permit.ConnectionGeneration != request.ConnectionGeneration ||
		claimed.Record.Permit.RequestID != request.RequestID || claimed.Record.Permit.RequestDigest != requestDigest ||
		claimed.Record.Permit.ClaimGeneration == 0 || claimed.Record.Permit.LeaseExpiresAtUnixNano == 0 {
		return response, ErrEffectInFlight
	}

	var result canonical.Value
	var samplingCancellation SamplingCancellationReceipt
	var elicitationCancellation ElicitationCancellationReceipt
	decision := "allowed"
	reason := "explicit server request policy"
	if paramsInvalid {
		response.Error = &JSONRPCError{Code: jsonRPCInvalidParams, Message: "Invalid params"}
		decision = "denied"
		reason = "invalid or oversized parameters"
	} else if !methodAllowed {
		response.Error = &JSONRPCError{Code: jsonRPCMethodNotFound, Message: "Method not found"}
		decision = "denied"
		reason = "server-initiated method is not allowed"
	} else {
		switch method {
		case ServerRequestSampling:
			var sampling SamplingResult
			samplingRequest := SamplingRequest{
				Scope: currentScope, ParentEffectID: request.Effect.Scope.EffectID,
				ParentInvocationID: request.Effect.Scope.InvocationID, RequestDigest: requestDigest,
				RequestID: request.RequestID, ParamsCanonical: append([]byte(nil), params...), Claim: claimed.Record.Permit,
				ChildEffectID: claimed.Record.Permit.ChildEffectID, ChildInvocationID: claimed.Record.Permit.ChildInvocationID,
			}
			if claimed.Record.Permit.ClaimGeneration == 1 {
				sampling, err = gateway.sampling.Sample(ctx, samplingRequest)
			} else {
				sampling, err = gateway.sampling.Resume(ctx, samplingRequest)
			}
			if err == nil && (!sampling.Durable || sampling.EffectID.Kind() != identity.Effect ||
				sampling.InvocationID.Kind() != identity.Invocation || sampling.EffectID == request.Effect.Scope.EffectID ||
				sampling.InvocationID == request.Effect.Scope.InvocationID || sampling.Scope != currentScope ||
				sampling.ParentEffectID != request.Effect.Scope.EffectID ||
				sampling.ParentInvocationID != request.Effect.Scope.InvocationID || sampling.RequestDigest != requestDigest ||
				sampling.EffectID != samplingRequest.ChildEffectID || sampling.InvocationID != samplingRequest.ChildInvocationID ||
				!sampling.ParentLifecycle.Durable ||
				sampling.ParentLifecycle.Proof == (OpaqueSamplingParentLifecycleReceipt{}) ||
				sampling.ParentLifecycle.Scope != currentScope ||
				sampling.ParentLifecycle.ParentEffectID != samplingRequest.ParentEffectID ||
				sampling.ParentLifecycle.ParentInvocationID != samplingRequest.ParentInvocationID ||
				sampling.ParentLifecycle.ChildEffectID != samplingRequest.ChildEffectID ||
				sampling.ParentLifecycle.ChildInvocationID != samplingRequest.ChildInvocationID ||
				sampling.ParentLifecycle.RequestDigest != requestDigest ||
				sampling.ParentLifecycle.ClaimProof != claimed.Record.Permit.Proof ||
				!sampling.ParentLifecycle.Suspended || !sampling.ParentLifecycle.Resumed) {
				err = ErrServerRequestDenied
			}
			if err != nil {
				cancellationRequest := SamplingCancellationRequest{
					Scope: currentScope, ParentEffectID: request.Effect.Scope.EffectID,
					ParentInvocationID: request.Effect.Scope.InvocationID, RequestDigest: requestDigest,
					Claim: claimed.Record.Permit,
				}
				durableCtx, cancel := gateway.cleanupContext(ctx)
				var cancelErr error
				samplingCancellation, cancelErr = gateway.sampling.Cancel(durableCtx, cancellationRequest)
				if cancelErr != nil {
					mapped := redactedDependencyError(durableCtx, cancelErr, ErrServerRequestDenied,
						ErrServerRequestDenied, ErrInvocationNotFound, ErrEffectInFlight, ErrStaleAuthority)
					cancel()
					return response, mapped
				}
				cancel()
				if !validSamplingCancellationReceipt(samplingCancellation, cancellationRequest) {
					return response, ErrServerRequestDenied
				}
			}
			result = sampling.Value
		case ServerRequestElicitation:
			if claimed.Record.Permit.ClaimGeneration > 1 {
				cancellationRequest := ElicitationCancellationRequest{
					Scope: currentScope, ParentEffectID: request.Effect.Scope.EffectID,
					ParentInvocationID: request.Effect.Scope.InvocationID, RequestDigest: requestDigest,
					Claim: claimed.Record.Permit,
				}
				elicitationCancellation, err = gateway.elicitation.Cancel(ctx, cancellationRequest)
				if err == nil && !validElicitationCancellationReceipt(elicitationCancellation, cancellationRequest) {
					err = ErrServerRequestDenied
				}
				if err == nil {
					err = ErrServerRequestDenied
				}
			} else {
				result, err = gateway.elicitation.Elicit(ctx, ElicitationRequest{
					Scope: currentScope, ParentEffectID: request.Effect.Scope.EffectID,
					ParentInvocationID: request.Effect.Scope.InvocationID, RequestDigest: requestDigest,
					RequestID: request.RequestID, ParamsCanonical: append([]byte(nil), params...), Claim: claimed.Record.Permit,
				})
			}
			if err != nil && elicitationCancellation == (ElicitationCancellationReceipt{}) {
				cancellationRequest := ElicitationCancellationRequest{
					Scope: currentScope, ParentEffectID: request.Effect.Scope.EffectID,
					ParentInvocationID: request.Effect.Scope.InvocationID, RequestDigest: requestDigest,
					Claim: claimed.Record.Permit,
				}
				durableCtx, cancel := gateway.cleanupContext(ctx)
				var cancelErr error
				elicitationCancellation, cancelErr = gateway.elicitation.Cancel(durableCtx, cancellationRequest)
				if cancelErr != nil {
					mapped := redactedDependencyError(durableCtx, cancelErr, ErrServerRequestDenied,
						ErrServerRequestDenied, ErrInvocationNotFound, ErrEffectInFlight, ErrStaleAuthority)
					cancel()
					return response, mapped
				}
				cancel()
				if !validElicitationCancellationReceipt(elicitationCancellation, cancellationRequest) {
					return response, ErrServerRequestDenied
				}
			}
		case ServerRequestRoots:
			var roots []string
			roots, err = gateway.roots.Roots(ctx, currentScope)
			if err == nil {
				result, err = gateway.workspaceRootsValue(roots)
			}
		default:
			// Configuration validation currently makes this unreachable. Keep the
			// runtime fail-closed if a restored registration is ever malformed.
			err = ErrServerRequestDenied
		}
		if err != nil {
			response.Error = &JSONRPCError{Code: jsonRPCInternalError, Message: "Internal error"}
			decision = "failed"
			reason = "allowed server request failed safely"
		}
	}
	if response.Error == nil {
		if err := preflightCanonical(result, 0, gateway.bounds.MaxInputDepth, gateway.bounds.MaxOutputBytes); err != nil {
			response.Error = &JSONRPCError{Code: jsonRPCInternalError, Message: "Internal error"}
			decision = "failed"
			reason = "server request result exceeded bounds"
		}
	}
	if response.Error == nil {
		encoded, encodeErr := canonical.Encode(result, canonical.Options{
			MaxDepth: gateway.bounds.MaxInputDepth, MaxBytes: int(gateway.bounds.MaxOutputBytes),
			MaxItems: canonical.DefaultOptions().MaxItems,
		})
		if encodeErr != nil {
			response.Error = &JSONRPCError{Code: jsonRPCInternalError, Message: "Internal error"}
			decision = "failed"
			reason = "server request result exceeded bounds"
		} else {
			response.ResultCanonical = append([]byte(nil), encoded...)
		}
	}
	audit := gateway.serverRequestAuditEvent(request.Effect, request.Method, decision, reason)
	durableCtx, cancel := gateway.cleanupContext(ctx)
	defer cancel()
	completed, err := gateway.repository.CompleteServerRequest(durableCtx, ServerRequestCommitRequest{
		CurrentScope: currentScope, Permit: claimed.Record.Permit, Response: cloneServerResponse(response), Audit: &audit,
		SamplingCancellation: samplingCancellation, ElicitationCancellation: elicitationCancellation,
	})
	if err != nil {
		return response, redactedDependencyError(durableCtx, err, ErrStoreUnavailable,
			ErrInvocationConflict, ErrEffectInFlight, ErrStaleAuthority, ErrInvalidTransition,
			ErrAuthorityMismatch, ErrInvocationNotFound)
	}
	if !completed.Durable || completed.Record.State != ServerRequestCompleted ||
		completed.Record.RequestDigest != requestDigest || completed.Audit == nil ||
		completed.Record.AuditSequence != completed.Audit.Sequence {
		return response, ErrStoreUnavailable
	}
	if auditErr := gateway.deliverAuditEnvelope(durableCtx, *completed.Audit); auditErr != nil {
		return response, auditErr
	}
	return cloneServerResponse(completed.Record.Response), nil
}

// FilterAdvertisedTools is intentionally stateless. Call it after every
// tools/list and tools/list_changed notification; unregistered tools never
// become visible, and central authorization is reevaluated on each refresh.
// Execute independently repeats authorization at the actual tools/call.
func (gateway *Gateway) FilterAdvertisedTools(ctx context.Context, request ToolListRequest) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(request.Authority) == 0 || uint64(len(request.Authority)) > gateway.bounds.MaxAuthorityBytes ||
		request.EffectID.Kind() != identity.Effect || request.InvocationID.Kind() != identity.Invocation ||
		request.RequestDigest == (Digest{}) || !validIdentifier(request.ServerID, gateway.bounds.MaxServerIDBytes) ||
		uint32(len(request.Advertised)) > gateway.bounds.MaxChunks {
		return nil, ErrInvalidRequest
	}
	scope, err := gateway.authority.ValidateAdmission(ctx, append(OpaqueAuthority(nil), request.Authority...), AuthorityRequest{
		EffectID: request.EffectID, InvocationID: request.InvocationID,
		RequestDigest: request.RequestDigest, Permission: "mcp.tools.list",
	})
	if err != nil {
		return nil, redactedDependencyError(ctx, err, ErrStaleAuthority,
			ErrInvalidRequest, ErrStaleAuthority, ErrAuthorityMismatch)
	}
	if !validScope(scope) || scope.EffectID != request.EffectID || scope.InvocationID != request.InvocationID {
		return nil, ErrAuthorityMismatch
	}
	server := serverKey{tenant: scope.TenantID, user: scope.UserID, server: request.ServerID}
	if _, found := gateway.servers[server]; !found {
		return nil, ErrServerNotAllowed
	}
	seen := make(map[string]struct{}, len(request.Advertised))
	visible := make([]string, 0, len(request.Advertised))
	for _, toolName := range request.Advertised {
		if !validIdentifier(toolName, gateway.bounds.MaxToolNameBytes) {
			return nil, ErrInvalidRequest
		}
		if _, duplicate := seen[toolName]; duplicate {
			return nil, ErrInvalidRequest
		}
		seen[toolName] = struct{}{}
		if _, registered := gateway.tools[toolKey{serverKey: server, tool: toolName}]; !registered {
			continue
		}
		permit, err := gateway.authorizer.Authorize(ctx, ToolAuthorizationRequest{
			Scope: scope, ServerID: request.ServerID, ToolName: toolName,
			RequestDigest: request.RequestDigest, Permission: "mcp.tools.list",
		})
		if errors.Is(err, ErrToolNotAllowed) || errors.Is(err, ErrServerNotAllowed) {
			continue
		}
		if err != nil {
			return nil, redactedDependencyError(ctx, err, ErrToolNotAllowed,
				ErrInvalidRequest, ErrServerNotAllowed, ErrToolNotAllowed, ErrAuthorizationMismatch)
		}
		if !validAuthorizationPermit(permit, scope, request.ServerID, toolName, request.RequestDigest) {
			return nil, ErrAuthorizationMismatch
		}
		visible = append(visible, toolName)
	}
	return visible, nil
}

func (gateway *Gateway) workspaceRootsValue(roots []string) (canonical.Value, error) {
	if uint32(len(roots)) > gateway.bounds.MaxChunks {
		return nil, ErrOutputLimit
	}
	seen := make(map[string]struct{}, len(roots))
	values := make(canonical.Array, 0, len(roots))
	for _, root := range roots {
		if !validBoundedText(root, gateway.bounds.MaxTargetRefBytes) || path.Clean(root) != root ||
			(root != "/workspace" && !strings.HasPrefix(root, "/workspace/")) || strings.Contains(root, "\\") {
			return nil, ErrServerRequestDenied
		}
		if _, duplicate := seen[root]; duplicate {
			return nil, ErrServerRequestDenied
		}
		seen[root] = struct{}{}
		uri := (&url.URL{Scheme: "file", Path: root}).String()
		parsed, err := url.Parse(uri)
		if err != nil || parsed.Scheme != "file" || parsed.Host != "" || parsed.Opaque != "" ||
			parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != root {
			return nil, ErrServerRequestDenied
		}
		decoded, err := url.PathUnescape(parsed.EscapedPath())
		if err != nil || decoded != root || path.Clean(decoded) != decoded ||
			(decoded != "/workspace" && !strings.HasPrefix(decoded, "/workspace/")) {
			return nil, ErrServerRequestDenied
		}
		values = append(values, canonical.Map{"uri": uri})
	}
	return canonical.Map{"roots": values}, nil
}

func validSamplingCancellationReceipt(
	receipt SamplingCancellationReceipt,
	request SamplingCancellationRequest,
) bool {
	return receipt.Durable && receipt.Proof != (OpaqueSamplingCancellationReceipt{}) &&
		receipt.Scope == request.Scope && receipt.ParentEffectID == request.ParentEffectID &&
		receipt.ParentInvocationID == request.ParentInvocationID &&
		receipt.ChildEffectID == request.Claim.ChildEffectID &&
		receipt.ChildInvocationID == request.Claim.ChildInvocationID &&
		receipt.RequestDigest == request.RequestDigest && receipt.RequestDigest == request.Claim.RequestDigest &&
		receipt.ClaimProof == request.Claim.Proof && request.Claim.Durable &&
		request.Claim.Proof != (OpaqueServerRequestPermit{}) &&
		request.Claim.ParentInvocationID == request.ParentInvocationID &&
		request.Claim.ChildEffectID.Kind() == identity.Effect && request.Claim.ChildInvocationID.Kind() == identity.Invocation
}

func validElicitationCancellationReceipt(
	receipt ElicitationCancellationReceipt,
	request ElicitationCancellationRequest,
) bool {
	return receipt.Durable && receipt.Proof != (OpaqueElicitationCancellationReceipt{}) &&
		receipt.Scope == request.Scope && receipt.ParentEffectID == request.ParentEffectID &&
		receipt.ParentInvocationID == request.ParentInvocationID &&
		receipt.RequestDigest == request.RequestDigest && receipt.RequestDigest == request.Claim.RequestDigest &&
		receipt.ClaimProof == request.Claim.Proof && request.Claim.Durable &&
		request.Claim.Proof != (OpaqueServerRequestPermit{}) &&
		request.Claim.ParentInvocationID == request.ParentInvocationID
}

func (gateway *Gateway) serverRequestAuditEvent(effect Effect, method, decision, reason string) AuditEvent {
	return AuditEvent{
		TenantID: effect.Scope.TenantID, UserID: effect.Scope.UserID, SessionID: effect.Scope.SessionID,
		TurnID: effect.Scope.TurnID, InvocationID: effect.Scope.InvocationID,
		ServerID: effect.ServerID, Method: normalizedServerRequestAuditMethod(method), Decision: decision, Reason: reason,
	}
}

func normalizedServerRequestAuditMethod(method string) string {
	switch ServerRequestMethod(method) {
	case ServerRequestSampling, ServerRequestElicitation, ServerRequestRoots:
		return method
	default:
		return "unsupported"
	}
}

func serverMethodAllowed(allowed []ServerRequestMethod, method ServerRequestMethod) bool {
	for _, candidate := range allowed {
		if candidate == method {
			return true
		}
	}
	return false
}
