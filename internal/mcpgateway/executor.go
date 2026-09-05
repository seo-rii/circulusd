package mcpgateway

import (
	"bytes"
	"context"
	"errors"
	"strings"

	"github.com/hancomac/circulusd/internal/identity"
)

// Execute performs exactly one provider attempt. Automatic replay decisions
// end in StateRetryPending; a supervising durable loop must call Execute again
// with fresh authority. This prevents an in-memory retry loop from outliving
// policy or placement generation changes.
func (gateway *Gateway) Execute(ctx context.Context, authority OpaqueAuthority, effect Effect, sink OutputSink) (Effect, error) {
	if err := ctx.Err(); err != nil {
		return Effect{}, err
	}
	if isNilInterface(sink) || len(authority) == 0 || uint64(len(authority)) > gateway.bounds.MaxAuthorityBytes {
		return Effect{}, ErrInvalidRequest
	}
	if err := gateway.validateEffect(effect); err != nil {
		return Effect{}, err
	}
	if effect.State != StateAdmitted && effect.State != StateRetryPending {
		return Effect{}, ErrInvalidTransition
	}

	currentScope, authorization, credential, err := gateway.authorizeNewDispatch(ctx, authority, effect)
	if err != nil {
		return Effect{}, err
	}
	begin, err := gateway.Apply(effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch})
	if err != nil {
		return Effect{}, err
	}
	permit, err := gateway.repository.CommitAndClaimDispatch(ctx, DispatchClaimRequest{
		ExpectedRevision: effect.Revision, CurrentScope: currentScope,
		Previous: cloneEffect(effect), Next: cloneEffect(begin.Effect), Authorization: authorization,
	})
	if err != nil {
		return Effect{}, redactedDependencyError(ctx, err, ErrStoreUnavailable,
			ErrConcurrentTransition, ErrEffectInFlight, ErrStaleAuthority, ErrInvalidTransition, ErrInvocationNotFound)
	}
	attempt, _ := begin.Effect.CurrentAttempt()
	if !validDispatchPermit(permit, begin.Effect, authorization, attempt.Attempt) {
		return Effect{}, ErrDispatchNotDurable
	}

	command := *begin.Dispatch
	command.Scope = currentScope
	command.InputCanonical = append([]byte(nil), begin.Dispatch.InputCanonical...)
	command.Authorization = authorization
	command.Credential = credential
	command.Dispatch = permit
	current := begin.Effect
	provider := gateway.providers[current.ProviderID]
	negotiationCommand := NegotiationCommand{
		Scope: currentScope, Server: command.Server, ToolName: command.ToolName,
		InvocationID: command.InvocationID, RequestDigest: command.RequestDigest, Attempt: command.Attempt,
		Authorization: authorization, Credential: credential, Dispatch: permit,
	}
	receipt, negotiationCallErr := provider.Negotiate(ctx, negotiationCommand)
	if contextErr := ctx.Err(); contextErr != nil {
		cancelled, cancelErr := gateway.Cancel(ctx, authority, current)
		return cancelled, errors.Join(contextErr, cancelErr)
	}
	negotiationErr := negotiationCallErr
	if negotiationCallErr == nil {
		switch {
		case receipt.NegotiatedProtocolVersion != command.Server.ProtocolVersion ||
			receipt.Server.ProtocolVersion != command.Server.ProtocolVersion:
			negotiationErr = ErrProtocolMismatch
		case receipt.Affinity != command.Server.Affinity || receipt.Server.Affinity != command.Server.Affinity:
			negotiationErr = ErrAffinityMismatch
		case receipt.Scope != currentScope || !validNegotiationReceiptForEffect(receipt, current, command.Attempt):
			negotiationErr = ErrProtocolMismatch
		}
	}
	if negotiationErr != nil {
		failed, applyErr := gateway.Apply(current, Event{
			ExpectedRevision: current.Revision, Kind: EventDispatchFailed, Failure: FailureDefinitelyNotSent,
			Reason: boundedFailureReason(negotiationCallErr, "provider negotiation failed before tool dispatch", gateway.bounds.MaxFailureBytes),
		})
		if applyErr != nil {
			return current, applyErr
		}
		current, err = gateway.persistAfterExternal(ctx, currentScope, current, failed.Effect)
		if err != nil {
			return failed.Effect, err
		}
		if errors.Is(negotiationErr, ErrProtocolMismatch) || errors.Is(negotiationErr, ErrAffinityMismatch) {
			return current, negotiationErr
		}
		return current, nil
	}
	negotiated, applyErr := gateway.Apply(current, Event{
		ExpectedRevision: current.Revision, Kind: EventNegotiationRecorded, Negotiation: receipt,
	})
	if applyErr != nil {
		return current, applyErr
	}
	current, err = gateway.persistAfterExternal(ctx, currentScope, current, negotiated.Effect)
	if err != nil {
		return negotiated.Effect, err
	}
	command.Negotiation = receipt
	startPermit, err := gateway.repository.ClaimProviderStart(ctx, ProviderStartClaimRequest{
		CurrentScope: currentScope, Effect: cloneEffect(current), Dispatch: permit, Lease: gateway.bounds.CancelTimeout,
	})
	if err != nil {
		mapped := redactedDependencyError(ctx, err, ErrStoreUnavailable,
			ErrConcurrentTransition, ErrEffectInFlight, ErrStaleAuthority, ErrInvalidTransition,
			ErrInvocationNotFound, ErrDispatchNotDurable)
		if errors.Is(mapped, ErrConcurrentTransition) || errors.Is(mapped, ErrEffectInFlight) || errors.Is(mapped, ErrStaleAuthority) {
			loaded, loadErr := gateway.loadDurableEffect(ctx, current.Scope.InvocationID)
			if loadErr == nil && !sameEffect(loaded, current) {
				return loaded, nil
			}
		}
		return current, mapped
	}
	if !validProviderStartPermit(startPermit, current, currentScope, permit) {
		return current, ErrDispatchNotDurable
	}
	command.Start = startPermit
	startClaimActive := true
	start, startErr := provider.Start(ctx, command)
	providerRequestID := strings.TrimSpace(start.ProviderRequestID)
	validProviderID := providerRequestID != "" && providerRequestID == start.ProviderRequestID &&
		validBoundedText(providerRequestID, gateway.bounds.MaxProviderRequestIDBytes)
	if start.ProviderRequestID != "" && !validProviderID {
		startErr = errors.New("provider returned an invalid request identity after dispatch")
	}
	if validProviderID {
		// Acceptance is an external fact even when the caller was cancelled
		// during Start. Persist it with the bounded independent context before
		// cleanup or cancellation needs to address the accepted request.
		accepted, applyErr := gateway.Apply(current, Event{
			ExpectedRevision: current.Revision, Kind: EventProviderAccepted, ProviderRequestID: providerRequestID,
		})
		if applyErr != nil {
			gateway.closeProviderCall(ctx, start.Call)
			return current, applyErr
		}
		current, err = gateway.persistAfterProviderStart(ctx, currentScope, current, accepted.Effect, startPermit)
		if err != nil {
			gateway.closeProviderCall(ctx, start.Call)
			return accepted.Effect, err
		}
		startClaimActive = false
	}
	if contextErr := ctx.Err(); contextErr != nil {
		gateway.closeProviderCall(ctx, start.Call)
		cancelled, cancelErr := gateway.Cancel(ctx, authority, current)
		return cancelled, errors.Join(contextErr, cancelErr)
	}
	if startErr != nil || isNilInterface(start.Call) || !validProviderID {
		gateway.closeProviderCall(ctx, start.Call)
		class := FailureUnknown
		var classified *ProviderDispatchError
		if errors.As(startErr, &classified) && classified.Classification() == DispatchDefinitelyNotSent && !validProviderID {
			class = FailureDefinitelyNotSent
		}
		reason := boundedFailureReason(startErr, "provider dispatch outcome is unknown", gateway.bounds.MaxFailureBytes)
		failed, applyErr := gateway.Apply(current, Event{
			ExpectedRevision: current.Revision, Kind: EventDispatchFailed, Failure: class, Reason: reason,
		})
		if applyErr != nil {
			return current, applyErr
		}
		if startClaimActive {
			current, err = gateway.persistAfterProviderStart(ctx, currentScope, current, failed.Effect, startPermit)
		} else {
			current, err = gateway.persistAfterExternal(ctx, currentScope, current, failed.Effect)
		}
		if err != nil {
			return failed.Effect, err
		}
		return current, nil
	}

	call := start.Call
	defer gateway.closeProviderCall(ctx, call)
	for {
		if ctx.Err() != nil {
			cancelled, cancelErr := gateway.Cancel(ctx, authority, current)
			if cancelErr != nil {
				return cancelled, errors.Join(ctx.Err(), cancelErr)
			}
			return cancelled, ctx.Err()
		}
		providerEvent, nextErr := call.Next(ctx)
		if nextErr != nil {
			if ctx.Err() != nil {
				cancelled, cancelErr := gateway.Cancel(ctx, authority, current)
				if cancelErr != nil {
					return cancelled, errors.Join(ctx.Err(), cancelErr)
				}
				return cancelled, ctx.Err()
			}
			reason := boundedFailureReason(nextErr, "provider stream ended before completion", gateway.bounds.MaxFailureBytes)
			failed, applyErr := gateway.Apply(current, Event{
				ExpectedRevision: current.Revision, Kind: EventDispatchFailed, Failure: FailureUnknown, Reason: reason,
			})
			if applyErr != nil {
				return current, applyErr
			}
			current, err = gateway.persistAfterExternal(ctx, currentScope, current, failed.Effect)
			if err != nil {
				return failed.Effect, err
			}
			return current, nil
		}

		switch providerEvent.Kind {
		case ProviderOutputChunk:
			if len(providerEvent.Output) != 0 || providerEvent.ExternalCommitID != "" {
				return gateway.cancelProtocolViolation(ctx, authority, current, ErrInvalidRequest)
			}
			chunkTransition, applyErr := gateway.Apply(current, Event{
				ExpectedRevision: current.Revision, Kind: EventOutputChunk, Chunk: providerEvent.Chunk,
			})
			if applyErr != nil {
				if errors.Is(applyErr, ErrOutputLimit) || errors.Is(applyErr, ErrEventLimit) {
					cancelled, cancelErr := gateway.Cancel(ctx, authority, current)
					return cancelled, errors.Join(applyErr, cancelErr)
				}
				return gateway.cancelProtocolViolation(ctx, authority, current, applyErr)
			}
			current, err = gateway.persistAfterExternal(ctx, currentScope, current, chunkTransition.Effect)
			if err != nil {
				return chunkTransition.Effect, err
			}
			if sinkErr := sink.Accept(ctx, append([]byte(nil), providerEvent.Chunk...)); sinkErr != nil {
				cancelled, cancelErr := gateway.Cancel(ctx, authority, current)
				return cancelled, errors.Join(ErrBackpressure, cancelErr)
			}

		case ProviderCompleted:
			if len(providerEvent.Chunk) != 0 {
				return gateway.cancelProtocolViolation(ctx, authority, current, ErrInvalidRequest)
			}
			committed, applyErr := gateway.Apply(current, Event{
				ExpectedRevision: current.Revision, Kind: EventCallCommitted,
				Output: providerEvent.Output, ExternalCommitID: providerEvent.ExternalCommitID,
			})
			if applyErr != nil {
				if errors.Is(applyErr, ErrOutputLimit) || errors.Is(applyErr, ErrEventLimit) {
					cancelled, cancelErr := gateway.Cancel(ctx, authority, current)
					return cancelled, errors.Join(applyErr, cancelErr)
				}
				return gateway.cancelProtocolViolation(ctx, authority, current, applyErr)
			}
			completionBase := current
			persisted, persistErr := gateway.persistAfterExternal(ctx, currentScope, completionBase, committed.Effect)
			current, err = persisted, persistErr
			if errors.Is(err, ErrConcurrentTransition) {
				loaded, loadErr := gateway.loadDurableEffect(ctx, completionBase.Scope.InvocationID)
				if loadErr != nil {
					return committed.Effect, loadErr
				}
				switch loaded.State {
				case StateCancellationPending, StateUncertain, StateNeedsConfirmation, StateFailed:
					merged, mergeErr := gateway.Apply(loaded, Event{
						ExpectedRevision: loaded.Revision, Kind: EventCallCommitted,
						Output: providerEvent.Output, ExternalCommitID: providerEvent.ExternalCommitID,
					})
					if mergeErr != nil {
						return loaded, mergeErr
					}
					current, err = gateway.persistAfterExternal(ctx, currentScope, loaded, merged.Effect)
				case StateExternallyCommitted, StateCompleted:
					if !bytes.Equal(loaded.Output, providerEvent.Output) || loaded.ExternalCommitID != providerEvent.ExternalCommitID {
						return loaded, ErrLedgerMismatch
					}
					current, err = loaded, nil
				default:
					return loaded, ErrConcurrentTransition
				}
			}
			if err != nil {
				return committed.Effect, err
			}
			if current.State == StateCompleted {
				return current, nil
			}
			settled, applyErr := gateway.Apply(current, Event{ExpectedRevision: current.Revision, Kind: EventSettlementCompleted})
			if applyErr != nil {
				return current, applyErr
			}
			current, err = gateway.persistAfterExternal(ctx, currentScope, current, settled.Effect)
			if err != nil {
				return settled.Effect, err
			}
			return current, nil

		default:
			return gateway.cancelProtocolViolation(ctx, authority, current, ErrInvalidRequest)
		}
	}
}

func (gateway *Gateway) authorizeNewDispatch(ctx context.Context, authority OpaqueAuthority, effect Effect) (ValidatedAuthority, ToolAuthorizationPermit, CredentialPermit, error) {
	currentScope, err := gateway.authority.ValidateAdmission(ctx, append(OpaqueAuthority(nil), authority...), AuthorityRequest{
		EffectID: effect.Scope.EffectID, InvocationID: effect.Scope.InvocationID,
		RequestDigest: effect.RequestDigest, Permission: "mcp.tools.call",
	})
	if err != nil {
		return ValidatedAuthority{}, ToolAuthorizationPermit{}, CredentialPermit{}, redactedDependencyError(
			ctx, err, ErrStaleAuthority, ErrInvalidRequest, ErrStaleAuthority, ErrAuthorityMismatch)
	}
	if !sameOperationScope(currentScope, effect.Scope) {
		return ValidatedAuthority{}, ToolAuthorizationPermit{}, CredentialPermit{}, ErrAuthorityMismatch
	}
	server, tool, err := gateway.registrationForEffect(effect)
	if err != nil {
		return ValidatedAuthority{}, ToolAuthorizationPermit{}, CredentialPermit{}, redactedDependencyError(
			ctx, err, ErrToolNotAllowed, ErrInvalidRequest, ErrServerNotAllowed, ErrToolNotAllowed, ErrAuthorizationMismatch)
	}
	authorization, err := gateway.authorizer.Authorize(ctx, ToolAuthorizationRequest{
		Scope: currentScope, ServerID: effect.ServerID, ToolName: effect.ToolName,
		RequestDigest: effect.RequestDigest, Permission: "mcp.tools.call",
	})
	if err != nil {
		return ValidatedAuthority{}, ToolAuthorizationPermit{}, CredentialPermit{}, redactedDependencyError(
			ctx, err, ErrToolNotAllowed, ErrInvalidRequest, ErrServerNotAllowed, ErrToolNotAllowed,
			ErrAuthorizationMismatch, ErrStaleAuthority)
	}
	if !validAuthorizationPermit(authorization, currentScope, effect.ServerID, effect.ToolName, effect.RequestDigest) {
		return ValidatedAuthority{}, ToolAuthorizationPermit{}, CredentialPermit{}, ErrAuthorizationMismatch
	}
	availability, err := gateway.checkAvailability(ctx, server, tool)
	if err != nil {
		return ValidatedAuthority{}, ToolAuthorizationPermit{}, CredentialPermit{}, err
	}
	if (effect.SupportsInvocationLedger && !availability.SupportsInvocationLedger) ||
		(effect.SupportsIdempotencyKey && !availability.SupportsIdempotencyKey) {
		return ValidatedAuthority{}, ToolAuthorizationPermit{}, CredentialPermit{}, ErrProviderUnavailable
	}
	credential, err := gateway.authorizeCredential(ctx, currentScope, server)
	if err != nil {
		return ValidatedAuthority{}, ToolAuthorizationPermit{}, CredentialPermit{}, err
	}
	return currentScope, authorization, credential, nil
}

func (gateway *Gateway) registrationForEffect(effect Effect) (ServerRegistration, ToolRegistration, error) {
	server, found := gateway.servers[serverKey{tenant: effect.Scope.TenantID, user: effect.Scope.UserID, server: effect.ServerID}]
	if !found {
		return ServerRegistration{}, ToolRegistration{}, ErrServerNotAllowed
	}
	server, err := resolveServerRegistration(server, effect.Scope)
	if err != nil {
		return ServerRegistration{}, ToolRegistration{}, err
	}
	tool, found := gateway.tools[toolKey{serverKey: serverKey{tenant: effect.Scope.TenantID, user: effect.Scope.UserID, server: effect.ServerID}, tool: effect.ToolName}]
	if !found {
		return ServerRegistration{}, ToolRegistration{}, ErrToolNotAllowed
	}
	return server, tool, nil
}

func validDispatchPermit(permit DispatchPermit, effect Effect, authorization ToolAuthorizationPermit, attempt uint32) bool {
	return permit.Durable && permit.Proof != (OpaqueDispatchPermit{}) && permit.Scope == authorization.Scope &&
		permit.InvocationID == effect.Scope.InvocationID && permit.RequestDigest == effect.RequestDigest &&
		permit.ProviderID == effect.ProviderID && permit.Attempt == attempt && permit.EffectRevision == effect.Revision &&
		permit.Authorization == authorization
}

func validProviderStartPermit(
	permit ProviderStartPermit,
	effect Effect,
	scope ValidatedAuthority,
	dispatch DispatchPermit,
) bool {
	attempt, ok := effect.CurrentAttempt()
	return ok && permit.Durable && permit.Proof != (OpaqueProviderStartPermit{}) && permit.Scope == scope &&
		permit.InvocationID == effect.Scope.InvocationID && permit.RequestDigest == effect.RequestDigest &&
		permit.ProviderID == effect.ProviderID && permit.Attempt == attempt.Attempt &&
		permit.EffectRevision == effect.Revision && permit.ClaimGeneration != 0 &&
		permit.LeaseExpiresAtUnixNano != 0 && permit.Dispatch == dispatch && permit.Negotiation == attempt.Negotiation
}

func (gateway *Gateway) persistAfterExternal(ctx context.Context, currentScope ValidatedAuthority, previous, next Effect) (Effect, error) {
	return gateway.persistAfterExternalWithClaims(ctx, currentScope, previous, next, nil, nil)
}

func (gateway *Gateway) persistAfterExternalWithCancellation(
	ctx context.Context,
	currentScope ValidatedAuthority,
	previous, next Effect,
	cancellation *CancellationPermit,
) (Effect, error) {
	return gateway.persistAfterExternalWithClaims(ctx, currentScope, previous, next, cancellation, nil)
}

func (gateway *Gateway) persistAfterProviderStart(
	ctx context.Context,
	currentScope ValidatedAuthority,
	previous, next Effect,
	start ProviderStartPermit,
) (Effect, error) {
	return gateway.persistAfterExternalWithClaims(ctx, currentScope, previous, next, nil, &start)
}

func (gateway *Gateway) persistAfterExternalWithClaims(
	ctx context.Context,
	currentScope ValidatedAuthority,
	previous, next Effect,
	cancellation *CancellationPermit,
	start *ProviderStartPermit,
) (Effect, error) {
	durableCtx, cancel := gateway.cleanupContext(ctx)
	defer cancel()
	stored, err := gateway.repository.Commit(durableCtx, TransitionCommitRequest{
		ExpectedRevision: previous.Revision, CurrentScope: currentScope, Previous: cloneEffect(previous),
		Next: cloneEffect(next), Cancellation: cancellation, ProviderStart: start,
	})
	if err != nil {
		return Effect{}, redactedDependencyError(durableCtx, err, ErrStoreUnavailable,
			ErrConcurrentTransition, ErrEffectInFlight, ErrStaleAuthority, ErrInvalidTransition, ErrInvocationNotFound)
	}
	if !stored.Durable || !sameEffect(stored.Effect, next) {
		return Effect{}, ErrStoreUnavailable
	}
	return cloneEffect(stored.Effect), nil
}

func (gateway *Gateway) loadDurableEffect(ctx context.Context, invocationID identity.ID) (Effect, error) {
	stored, err := gateway.repository.Load(ctx, invocationID)
	if err != nil {
		return Effect{}, redactedDependencyError(ctx, err, ErrStoreUnavailable,
			ErrInvocationNotFound, ErrStaleAuthority, ErrConcurrentTransition)
	}
	if !stored.Durable || gateway.validateEffect(stored.Effect) != nil {
		return Effect{}, ErrStoreUnavailable
	}
	return cloneEffect(stored.Effect), nil
}

func (gateway *Gateway) loadAuthoritativeEffect(ctx context.Context, supplied Effect) (Effect, error) {
	stored, err := gateway.loadDurableEffect(ctx, supplied.Scope.InvocationID)
	if err != nil {
		return Effect{}, err
	}
	if sameEffect(stored, supplied) {
		return stored, nil
	}
	if !sameImmutableEffect(stored, supplied) || stored.Revision <= supplied.Revision {
		return Effect{}, ErrConcurrentTransition
	}
	return stored, nil
}

func (gateway *Gateway) validateCurrentAuthority(
	ctx context.Context,
	authority OpaqueAuthority,
	request CurrentAuthorityRequest,
) (ValidatedAuthority, error) {
	currentScope, err := gateway.authority.ValidateCurrent(ctx, append(OpaqueAuthority(nil), authority...), request)
	if err != nil {
		return ValidatedAuthority{}, redactedDependencyError(ctx, err, ErrStaleAuthority,
			ErrInvalidRequest, ErrStaleAuthority, ErrAuthorityMismatch)
	}
	if !validScope(currentScope) || !sameOperationScope(currentScope, request.Scope) {
		return ValidatedAuthority{}, ErrAuthorityMismatch
	}
	return currentScope, nil
}

// Cancel durably records cancellation intent before contacting the provider.
// Its internal cleanup context is bounded and survives cancellation of the
// caller context so accepted effects are never left classified by RAM state.
func (gateway *Gateway) Cancel(ctx context.Context, authority OpaqueAuthority, effect Effect) (Effect, error) {
	if len(authority) == 0 || uint64(len(authority)) > gateway.bounds.MaxAuthorityBytes {
		return Effect{}, ErrInvalidRequest
	}
	if err := gateway.validateEffect(effect); err != nil {
		return Effect{}, err
	}
	durableCtx, cancel := gateway.cleanupContext(ctx)
	defer cancel()
	effect, err := gateway.loadAuthoritativeEffect(durableCtx, effect)
	if err != nil {
		return Effect{}, err
	}
	attempt, _ := effect.CurrentAttempt()
	currentScope, err := gateway.validateCurrentAuthority(durableCtx, authority, CurrentAuthorityRequest{
		Scope: effect.Scope, RequestDigest: effect.RequestDigest, ProviderRequestID: attempt.ProviderRequestID,
		ConnectionGeneration: attempt.Negotiation.ConnectionGeneration, Attempt: attempt.Attempt, Permission: "mcp.cancel",
	})
	if err != nil {
		return Effect{}, err
	}
	reconciled, reconcileErr := gateway.repository.ReconcileServerRequests(durableCtx, ServerRequestReconcileRequest{
		CurrentScope: currentScope, Parent: cloneEffect(effect),
	})
	if reconcileErr != nil {
		return Effect{}, redactedDependencyError(durableCtx, reconcileErr, ErrStoreUnavailable,
			ErrConcurrentTransition, ErrEffectInFlight, ErrStaleAuthority, ErrInvocationNotFound)
	}
	if !reconciled.Durable {
		return Effect{}, ErrStoreUnavailable
	}
	if reconciled.PendingCancellation {
		if err := gateway.cancelReconciledServerRequest(
			durableCtx, currentScope, effect, reconciled.CancellationClaim, reconciled.Record.Method,
		); err != nil {
			return cloneEffect(effect), err
		}
	}
	switch effect.State {
	case StateCompleted, StateCancelled:
		return cloneEffect(effect), nil
	case StateFailed:
		attempt, ok := effect.CurrentAttempt()
		if !ok || attempt.Failure != FailureUnknown {
			return cloneEffect(effect), nil
		}
	case StateExternallyCommitted:
		settled, applyErr := gateway.Apply(effect, Event{ExpectedRevision: effect.Revision, Kind: EventSettlementCompleted})
		if applyErr != nil {
			return effect, applyErr
		}
		return gateway.persistAfterExternal(durableCtx, currentScope, effect, settled.Effect)
	}
	if effect.State == StateCancellationPending {
		current, _, resumeErr := gateway.dispatchCancellation(durableCtx, currentScope, effect)
		return current, resumeErr
	}
	requested, err := gateway.Apply(effect, Event{ExpectedRevision: effect.Revision, Kind: EventCancelRequested})
	if err != nil {
		return Effect{}, err
	}
	current, err := gateway.persistAfterExternal(durableCtx, currentScope, effect, requested.Effect)
	if errors.Is(err, ErrConcurrentTransition) {
		loaded, loadErr := gateway.loadDurableEffect(durableCtx, effect.Scope.InvocationID)
		if loadErr != nil {
			return requested.Effect, loadErr
		}
		switch loaded.State {
		case StateCompleted, StateCancelled:
			return loaded, nil
		case StateFailed:
			loadedAttempt, ok := loaded.CurrentAttempt()
			if !ok || loadedAttempt.Failure != FailureUnknown {
				return loaded, nil
			}
			fallthrough
		case StateAdmitted, StateRetryPending, StateDispatching, StateDispatched, StateStreaming,
			StateUncertain, StateNeedsConfirmation:
			loadedAttempt, _ := loaded.CurrentAttempt()
			retryScope, scopeErr := gateway.validateCurrentAuthority(durableCtx, authority, CurrentAuthorityRequest{
				Scope: loaded.Scope, RequestDigest: loaded.RequestDigest,
				ProviderRequestID:    loadedAttempt.ProviderRequestID,
				ConnectionGeneration: loadedAttempt.Negotiation.ConnectionGeneration,
				Attempt:              loadedAttempt.Attempt, Permission: "mcp.cancel",
			})
			if scopeErr != nil {
				return loaded, scopeErr
			}
			retryRequested, applyErr := gateway.Apply(loaded, Event{
				ExpectedRevision: loaded.Revision, Kind: EventCancelRequested,
			})
			if applyErr != nil {
				return loaded, applyErr
			}
			retryCurrent, retryErr := gateway.persistAfterExternal(
				durableCtx, retryScope, loaded, retryRequested.Effect,
			)
			if retryErr != nil {
				return retryRequested.Effect, retryErr
			}
			if retryCurrent.State == StateCancelled {
				return retryCurrent, nil
			}
			retryCurrent, _, retryErr = gateway.dispatchCancellation(durableCtx, retryScope, retryCurrent)
			return retryCurrent, retryErr
		case StateCancellationPending:
			current, _, resumeErr := gateway.dispatchCancellation(durableCtx, currentScope, loaded)
			return current, resumeErr
		case StateExternallyCommitted:
			settled, applyErr := gateway.Apply(loaded, Event{ExpectedRevision: loaded.Revision, Kind: EventSettlementCompleted})
			if applyErr != nil {
				return loaded, applyErr
			}
			return gateway.persistAfterExternal(durableCtx, currentScope, loaded, settled.Effect)
		default:
			return loaded, ErrConcurrentTransition
		}
	}
	if err != nil {
		return requested.Effect, err
	}
	if current.State == StateCancelled {
		return current, nil
	}
	current, _, err = gateway.dispatchCancellation(durableCtx, currentScope, current)
	return current, err
}

func (gateway *Gateway) dispatchCancellation(
	ctx context.Context,
	currentScope ValidatedAuthority,
	current Effect,
) (Effect, bool, error) {
	claim, err := gateway.repository.ClaimCancellation(ctx, CancellationClaimRequest{
		CurrentScope: currentScope, Effect: cloneEffect(current), Lease: gateway.bounds.CancelTimeout,
	})
	if err != nil {
		return current, false, redactedDependencyError(ctx, err, ErrStoreUnavailable,
			ErrConcurrentTransition, ErrEffectInFlight, ErrStaleAuthority, ErrInvalidTransition, ErrInvocationNotFound)
	}
	if !validCancellationPermit(claim.Permit, current, currentScope) {
		return current, false, ErrDispatchNotDurable
	}
	if !claim.Fresh {
		return current, false, nil
	}
	if claim.Permit.ServerRequest != (ServerRequestPermit{}) {
		if err := gateway.cancelReconciledServerRequest(
			ctx, currentScope, current, claim.Permit.ServerRequest, claim.Permit.ServerRequestMethod,
		); err != nil {
			return current, true, err
		}
	}
	attempt, _ := current.CurrentAttempt()
	if claim.Permit.Start == (ProviderStartPermit{}) {
		resolved, applyErr := gateway.Apply(current, Event{
			ExpectedRevision: current.Revision, Kind: EventCancellationResolved, Cancellation: CancellationPrevented,
		})
		if applyErr != nil {
			return current, true, applyErr
		}
		next, commitErr := gateway.persistAfterExternalWithCancellation(
			ctx, currentScope, current, resolved.Effect, &claim.Permit,
		)
		return next, true, commitErr
	}
	server, _, registrationErr := gateway.registrationForEffect(current)
	if registrationErr != nil {
		next, failureErr := gateway.resolveCancellationFailure(ctx, currentScope, current, claim.Permit, registrationErr)
		return next, true, failureErr
	}
	credential, credentialErr := gateway.authorizeCredential(ctx, currentScope, server)
	if credentialErr != nil {
		next, failureErr := gateway.resolveCancellationFailure(ctx, currentScope, current, claim.Permit, credentialErr)
		return next, true, failureErr
	}
	command := CancelCommand{
		Scope: currentScope, Server: serverForEffect(current), ToolName: current.ToolName,
		InvocationID: current.Scope.InvocationID, RequestDigest: current.RequestDigest,
		ProviderRequestID: attempt.ProviderRequestID, Attempt: attempt.Attempt, Credential: credential,
		Cancellation: claim.Permit, Negotiation: attempt.Negotiation, Start: claim.Permit.Start,
	}
	result, cancelErr := gateway.providers[current.ProviderID].Cancel(ctx, command)
	if cancelErr != nil {
		// An error means no returned classification is authoritative. In
		// particular, a truncated response cannot prove durable absence.
		result = CancellationResult{Status: CancellationUnknown}
		cancelErr = redactedDependencyError(ctx, cancelErr, ErrProviderUnavailable,
			ErrProviderUnavailable, ErrProtocolMismatch, ErrAffinityMismatch)
	}
	if result.Status != CancellationPrevented && result.Status != CancellationAbsent &&
		result.Status != CancellationCommitted && result.Status != CancellationUnknown {
		result.Status = CancellationUnknown
		cancelErr = errors.Join(cancelErr, ErrInvalidRequest)
	}
	event := Event{
		ExpectedRevision: current.Revision, Kind: EventCancellationResolved,
		Cancellation: result.Status,
	}
	if result.Status == CancellationCommitted {
		if gateway.validateLedgerRecord(result.Record, false) != nil {
			result.Status = CancellationUnknown
			event.Cancellation = CancellationUnknown
			cancelErr = errors.Join(cancelErr, ErrLedgerMismatch)
		} else {
			event.Ledger = cloneLedgerRecord(result.Record)
		}
	}
	resolved, applyErr := gateway.Apply(current, event)
	if applyErr != nil {
		return current, true, errors.Join(cancelErr, applyErr)
	}
	resolutionBase := current
	persisted, persistErr := gateway.persistAfterExternalWithCancellation(
		ctx, currentScope, resolutionBase, resolved.Effect, &claim.Permit,
	)
	current, err = persisted, persistErr
	if errors.Is(err, ErrConcurrentTransition) {
		loaded, loadErr := gateway.loadDurableEffect(ctx, resolutionBase.Scope.InvocationID)
		if loadErr != nil {
			return resolved.Effect, true, errors.Join(cancelErr, loadErr)
		}
		switch loaded.State {
		case StateExternallyCommitted, StateCompleted:
			current, err = loaded, nil
		case StateCancelled, StateUncertain, StateNeedsConfirmation, StateFailed:
			return loaded, true, cancelErr
		default:
			return loaded, true, errors.Join(cancelErr, ErrConcurrentTransition)
		}
	}
	if err != nil {
		return resolved.Effect, true, errors.Join(cancelErr, err)
	}
	if current.State == StateExternallyCommitted {
		settled, applyErr := gateway.Apply(current, Event{ExpectedRevision: current.Revision, Kind: EventSettlementCompleted})
		if applyErr != nil {
			return current, true, errors.Join(cancelErr, applyErr)
		}
		settlementBase := current
		persisted, persistErr := gateway.persistAfterExternal(ctx, currentScope, settlementBase, settled.Effect)
		current, err = persisted, persistErr
		if errors.Is(err, ErrConcurrentTransition) {
			loaded, loadErr := gateway.loadDurableEffect(ctx, settlementBase.Scope.InvocationID)
			if loadErr != nil {
				return settled.Effect, true, errors.Join(cancelErr, loadErr)
			}
			if loaded.State == StateCompleted {
				return loaded, true, cancelErr
			}
		}
		if err != nil {
			return settled.Effect, true, errors.Join(cancelErr, err)
		}
	}
	return current, true, cancelErr
}

func validCancellationPermit(permit CancellationPermit, effect Effect, scope ValidatedAuthority) bool {
	attempt, ok := effect.CurrentAttempt()
	if !ok || !permit.Durable || permit.Proof == (OpaqueCancellationPermit{}) || permit.Scope != scope ||
		permit.InvocationID != effect.Scope.InvocationID || permit.RequestDigest != effect.RequestDigest ||
		permit.ProviderID != effect.ProviderID || permit.ProviderRequestID != attempt.ProviderRequestID ||
		permit.Attempt != attempt.Attempt || permit.EffectRevision != effect.Revision ||
		permit.ClaimGeneration == 0 || permit.LeaseExpiresAtUnixNano == 0 {
		return false
	}
	if permit.Start == (ProviderStartPermit{}) {
		return validCancellationServerRequest(permit, effect, scope)
	}
	return validHistoricalProviderStartPermit(permit.Start, effect, scope) &&
		validCancellationServerRequest(permit, effect, scope)
}

func validCancellationServerRequest(permit CancellationPermit, effect Effect, scope ValidatedAuthority) bool {
	if permit.ServerRequest == (ServerRequestPermit{}) {
		return permit.ServerRequestMethod == ""
	}
	child := permit.ServerRequest
	valid := child.Durable &&
		child.Proof != (OpaqueServerRequestPermit{}) && sameOperationScope(child.Scope, scope) &&
		child.ParentInvocationID == effect.Scope.InvocationID && child.RequestDigest != (Digest{}) &&
		child.ClaimGeneration != 0 && child.LeaseExpiresAtUnixNano != 0
	if !valid {
		return false
	}
	switch ServerRequestMethod(permit.ServerRequestMethod) {
	case ServerRequestSampling:
		return child.ChildEffectID.Kind() == identity.Effect && child.ChildInvocationID.Kind() == identity.Invocation
	case ServerRequestElicitation:
		return child.ChildEffectID == (identity.ID{}) && child.ChildInvocationID == (identity.ID{})
	default:
		return false
	}
}

func validHistoricalProviderStartPermit(permit ProviderStartPermit, effect Effect, scope ValidatedAuthority) bool {
	attempt, ok := effect.CurrentAttempt()
	return ok && permit.Durable && permit.Proof != (OpaqueProviderStartPermit{}) &&
		sameOperationScope(permit.Scope, scope) && sameOperationScope(permit.Scope, effect.Scope) &&
		permit.InvocationID == effect.Scope.InvocationID && permit.RequestDigest == effect.RequestDigest &&
		permit.ProviderID == effect.ProviderID && permit.Attempt == attempt.Attempt && permit.ClaimGeneration != 0 &&
		permit.EffectRevision > permit.Dispatch.EffectRevision && permit.EffectRevision <= effect.Revision &&
		permit.LeaseExpiresAtUnixNano != 0 && permit.Negotiation == attempt.Negotiation &&
		permit.Dispatch.InvocationID == effect.Scope.InvocationID && permit.Dispatch.RequestDigest == effect.RequestDigest &&
		permit.Dispatch.ProviderID == effect.ProviderID && permit.Dispatch.Attempt == attempt.Attempt
}

func (gateway *Gateway) cancelReconciledServerRequest(
	ctx context.Context,
	currentScope ValidatedAuthority,
	parent Effect,
	permit ServerRequestPermit,
	method string,
) error {
	commit := ServerRequestReconcileCommitRequest{CurrentScope: currentScope, Permit: permit}
	switch ServerRequestMethod(method) {
	case ServerRequestSampling:
		if isNilInterface(gateway.sampling) {
			return ErrServerRequestDenied
		}
		request := SamplingCancellationRequest{
			Scope: currentScope, ParentEffectID: parent.Scope.EffectID,
			ParentInvocationID: parent.Scope.InvocationID, RequestDigest: permit.RequestDigest, Claim: permit,
		}
		receipt, err := gateway.sampling.Cancel(ctx, request)
		if err != nil {
			return redactedDependencyError(ctx, err, ErrServerRequestDenied,
				ErrServerRequestDenied, ErrInvocationNotFound, ErrEffectInFlight, ErrStaleAuthority)
		}
		if !validSamplingCancellationReceipt(receipt, request) {
			return ErrServerRequestDenied
		}
		commit.Cancellation = receipt
	case ServerRequestElicitation:
		if isNilInterface(gateway.elicitation) {
			return ErrServerRequestDenied
		}
		request := ElicitationCancellationRequest{
			Scope: currentScope, ParentEffectID: parent.Scope.EffectID,
			ParentInvocationID: parent.Scope.InvocationID, RequestDigest: permit.RequestDigest, Claim: permit,
		}
		receipt, err := gateway.elicitation.Cancel(ctx, request)
		if err != nil {
			return redactedDependencyError(ctx, err, ErrServerRequestDenied,
				ErrServerRequestDenied, ErrInvocationNotFound, ErrEffectInFlight, ErrStaleAuthority)
		}
		if !validElicitationCancellationReceipt(receipt, request) {
			return ErrServerRequestDenied
		}
		commit.ElicitationCancellation = receipt
	default:
		return ErrServerRequestDenied
	}
	stored, err := gateway.repository.CompleteServerRequestReconciliation(ctx, commit)
	if errors.Is(err, ErrInvocationConflict) {
		reconciled, reconcileErr := gateway.repository.ReconcileServerRequests(ctx, ServerRequestReconcileRequest{
			CurrentScope: currentScope, Parent: cloneEffect(parent),
		})
		if reconcileErr == nil && reconciled.Durable && !reconciled.PendingCancellation {
			return nil
		}
	}
	if err != nil {
		return redactedDependencyError(ctx, err, ErrStoreUnavailable,
			ErrInvocationConflict, ErrStaleAuthority, ErrInvocationNotFound, ErrServerRequestDenied)
	}
	if !stored.Durable || stored.Record.State != ServerRequestAbandoned ||
		(method == string(ServerRequestSampling) && stored.Record.ChildCancellation != commit.Cancellation) ||
		(method == string(ServerRequestElicitation) && stored.Record.ElicitationCancellation != commit.ElicitationCancellation) {
		return ErrStoreUnavailable
	}
	return nil
}

func (gateway *Gateway) resolveCancellationFailure(
	ctx context.Context,
	currentScope ValidatedAuthority,
	current Effect,
	permit CancellationPermit,
	cause error,
) (Effect, error) {
	resolved, applyErr := gateway.Apply(current, Event{
		ExpectedRevision: current.Revision, Kind: EventCancellationResolved, Cancellation: CancellationUnknown,
	})
	if applyErr != nil {
		return current, errors.Join(cause, applyErr)
	}
	next, commitErr := gateway.persistAfterExternalWithCancellation(ctx, currentScope, current, resolved.Effect, &permit)
	return next, errors.Join(cause, commitErr)
}

// Recover resolves a crash window by consulting the provider ledger. A
// committed record advances only through external-commit settlement; it never
// calls Provider.Start. Inflight and already-classified unknown records do not
// consume the bounded event budget on repeated polling.
func (gateway *Gateway) Recover(ctx context.Context, authority OpaqueAuthority, effect Effect) (RecoveryResult, error) {
	if err := ctx.Err(); err != nil {
		return RecoveryResult{}, err
	}
	if len(authority) == 0 || uint64(len(authority)) > gateway.bounds.MaxAuthorityBytes {
		return RecoveryResult{}, ErrInvalidRequest
	}
	if err := gateway.validateEffect(effect); err != nil {
		return RecoveryResult{}, err
	}
	effect, err := gateway.loadAuthoritativeEffect(ctx, effect)
	if err != nil {
		return RecoveryResult{}, err
	}
	attempt, _ := effect.CurrentAttempt()
	currentScope, err := gateway.validateCurrentAuthority(ctx, authority, CurrentAuthorityRequest{
		Scope: effect.Scope, RequestDigest: effect.RequestDigest, ProviderRequestID: attempt.ProviderRequestID,
		ConnectionGeneration: attempt.Negotiation.ConnectionGeneration, Attempt: attempt.Attempt, Permission: "mcp.recover",
	})
	if err != nil {
		return RecoveryResult{}, err
	}
	reconciled, err := gateway.repository.ReconcileServerRequests(ctx, ServerRequestReconcileRequest{
		CurrentScope: currentScope, Parent: cloneEffect(effect),
	})
	if err != nil {
		return RecoveryResult{}, redactedDependencyError(ctx, err, ErrStoreUnavailable,
			ErrConcurrentTransition, ErrEffectInFlight, ErrStaleAuthority, ErrInvocationNotFound)
	}
	if !reconciled.Durable || reconciled.RetryAfter < 0 {
		return RecoveryResult{}, ErrStoreUnavailable
	}
	if reconciled.Active {
		return RecoveryResult{Effect: cloneEffect(effect), Action: RecoveryWait}, nil
	}
	if reconciled.PendingCancellation {
		if err := gateway.cancelReconciledServerRequest(
			ctx, currentScope, effect, reconciled.CancellationClaim, reconciled.Record.Method,
		); err != nil {
			return RecoveryResult{Effect: cloneEffect(effect), Action: RecoveryWait}, err
		}
	}
	definitiveTerminal := effect.State == StateCompleted || effect.State == StateCancelled
	if effect.State == StateFailed {
		attempt, ok := effect.CurrentAttempt()
		definitiveTerminal = !ok || attempt.Failure != FailureUnknown
	}
	if definitiveTerminal {
		return RecoveryResult{Effect: cloneEffect(effect), Action: recoveryAction(effect)}, nil
	}
	if reconciled.ParentCancelRequired {
		cancelled, cancelErr := gateway.Cancel(ctx, authority, effect)
		return RecoveryResult{Effect: cancelled, Action: recoveryAction(cancelled)}, cancelErr
	}
	if effect.State == StateRetryPending {
		return RecoveryResult{Effect: cloneEffect(effect), Action: RecoveryRetry}, nil
	}
	if effect.State == StateCancellationPending {
		durableCtx, cancel := gateway.cleanupContext(ctx)
		defer cancel()
		next, dispatched, cancelErr := gateway.dispatchCancellation(durableCtx, currentScope, effect)
		if cancelErr != nil {
			return RecoveryResult{Effect: next, Action: recoveryAction(next)}, cancelErr
		}
		if !dispatched {
			return RecoveryResult{Effect: next, Action: RecoveryWait}, nil
		}
		return RecoveryResult{Effect: next, Action: recoveryAction(next)}, nil
	}
	if effect.State == StateExternallyCommitted {
		settled, err := gateway.Apply(effect, Event{ExpectedRevision: effect.Revision, Kind: EventSettlementCompleted})
		if err != nil {
			return RecoveryResult{}, err
		}
		next, err := gateway.persistAfterExternal(ctx, currentScope, effect, settled.Effect)
		if errors.Is(err, ErrConcurrentTransition) {
			loaded, loadErr := gateway.loadDurableEffect(ctx, effect.Scope.InvocationID)
			if loadErr != nil {
				return RecoveryResult{Effect: settled.Effect}, loadErr
			}
			if loaded.State == StateCompleted && bytes.Equal(loaded.Output, effect.Output) &&
				loaded.ExternalCommitID == effect.ExternalCommitID {
				return RecoveryResult{Effect: loaded, Action: RecoverySettled}, nil
			}
			return RecoveryResult{Effect: loaded, Action: recoveryAction(loaded)}, ErrConcurrentTransition
		}
		return RecoveryResult{Effect: next, Action: RecoverySettled}, err
	}
	if effect.State == StateDispatching && attempt.Negotiation == (StartNegotiationReceipt{}) {
		failed, applyErr := gateway.Apply(effect, Event{
			ExpectedRevision: effect.Revision, Kind: EventDispatchFailed, Failure: FailureDefinitelyNotSent,
			Reason: "provider negotiation was not durably recorded",
		})
		if applyErr != nil {
			return RecoveryResult{}, applyErr
		}
		next, commitErr := gateway.persistAfterExternal(ctx, currentScope, effect, failed.Effect)
		if errors.Is(commitErr, ErrConcurrentTransition) {
			loaded, loadErr := gateway.loadDurableEffect(ctx, effect.Scope.InvocationID)
			if loadErr != nil {
				return RecoveryResult{Effect: failed.Effect}, loadErr
			}
			return RecoveryResult{Effect: loaded, Action: recoveryAction(loaded)}, nil
		}
		return RecoveryResult{Effect: next, Action: recoveryAction(next)}, commitErr
	}
	switch effect.State {
	case StateDispatching, StateDispatched, StateStreaming, StateCancellationPending, StateUncertain, StateNeedsConfirmation, StateFailed:
	default:
		return RecoveryResult{}, ErrInvalidTransition
	}
	startResolution, err := gateway.repository.ResolveProviderStart(ctx, ProviderStartResolutionRequest{
		CurrentScope: currentScope, Effect: cloneEffect(effect),
	})
	if err != nil {
		return RecoveryResult{}, redactedDependencyError(ctx, err, ErrStoreUnavailable,
			ErrConcurrentTransition, ErrEffectInFlight, ErrStaleAuthority, ErrInvalidTransition,
			ErrInvocationNotFound, ErrStoreUnavailable)
	}
	if !startResolution.Durable || startResolution.RetryAfter < 0 {
		return RecoveryResult{}, ErrStoreUnavailable
	}
	if startResolution.Active {
		return RecoveryResult{Effect: cloneEffect(effect), Action: RecoveryWait}, nil
	}
	if startResolution.Present {
		if !validHistoricalProviderStartPermit(startResolution.Permit, effect, currentScope) {
			return RecoveryResult{}, ErrDispatchNotDurable
		}
	} else {
		if effect.State != StateDispatching || attempt.ProviderRequestID != "" {
			return RecoveryResult{}, ErrStoreUnavailable
		}
		failed, applyErr := gateway.Apply(effect, Event{
			ExpectedRevision: effect.Revision, Kind: EventDispatchFailed, Failure: FailureDefinitelyNotSent,
			Reason: "provider start was durably prevented",
		})
		if applyErr != nil {
			return RecoveryResult{}, applyErr
		}
		next, commitErr := gateway.persistAfterExternal(ctx, currentScope, effect, failed.Effect)
		return RecoveryResult{Effect: next, Action: recoveryAction(next)}, commitErr
	}
	if effect.State == StateNeedsConfirmation && !effect.SupportsInvocationLedger {
		return RecoveryResult{Effect: cloneEffect(effect), Action: RecoveryConfirmation}, nil
	}
	if effect.State == StateUncertain && effect.ReplayPolicy == ReplayNever && !effect.SupportsInvocationLedger {
		return RecoveryResult{Effect: cloneEffect(effect), Action: RecoveryInterrupted}, nil
	}

	record := LedgerRecord{InvocationID: effect.Scope.InvocationID, RequestDigest: effect.RequestDigest, Status: LedgerUnknown}
	if effect.SupportsInvocationLedger {
		server, _, err := gateway.registrationForEffect(effect)
		if err != nil {
			return RecoveryResult{}, err
		}
		credential, err := gateway.authorizeCredential(ctx, currentScope, server)
		if err != nil {
			return RecoveryResult{}, err
		}
		record, err = gateway.providers[effect.ProviderID].Lookup(ctx, LedgerQuery{
			Scope: currentScope, Server: serverForEffect(effect), ToolName: effect.ToolName,
			InvocationID: effect.Scope.InvocationID, RequestDigest: effect.RequestDigest, Credential: credential,
			Negotiation: attempt.Negotiation, Start: startResolution.Permit,
		})
		if err != nil {
			return RecoveryResult{}, redactedDependencyError(ctx, err, ErrLedgerUnavailable, ErrLedgerUnavailable)
		}
	}
	if gateway.validateLedgerRecord(record, true) != nil || record.InvocationID != effect.Scope.InvocationID || record.RequestDigest != effect.RequestDigest {
		return RecoveryResult{}, ErrLedgerMismatch
	}
	if record.Status == LedgerInflight {
		attempt, ok := effect.CurrentAttempt()
		if !ok || (attempt.ProviderRequestID != "" && attempt.ProviderRequestID != record.ProviderRequestID) {
			return RecoveryResult{}, ErrLedgerMismatch
		}
		if attempt.ProviderRequestID != "" {
			switch effect.State {
			case StateDispatched, StateStreaming, StateCancellationPending,
				StateUncertain, StateNeedsConfirmation, StateFailed:
				// The matching provider identity is already durable. Rewriting an
				// unresolved state for every inflight poll spends a bounded event
				// without learning a new fact and creates a cancellation reserve
				// cycle. Wait revision-neutrally instead.
				return RecoveryResult{Effect: cloneEffect(effect), Action: RecoveryWait}, nil
			}
		}
		recovered, applyErr := gateway.Apply(effect, Event{
			ExpectedRevision: effect.Revision, Kind: EventRecoveryObserved, Ledger: cloneLedgerRecord(record),
		})
		if applyErr != nil {
			return RecoveryResult{}, applyErr
		}
		current, commitErr := gateway.persistAfterExternal(ctx, currentScope, effect, recovered.Effect)
		if errors.Is(commitErr, ErrConcurrentTransition) {
			loaded, loadErr := gateway.loadDurableEffect(ctx, effect.Scope.InvocationID)
			if loadErr != nil {
				return RecoveryResult{Effect: recovered.Effect}, loadErr
			}
			loadedAttempt, ok := loaded.CurrentAttempt()
			if !ok || loadedAttempt.ProviderRequestID != record.ProviderRequestID {
				return RecoveryResult{Effect: loaded}, ErrLedgerMismatch
			}
			return RecoveryResult{Effect: loaded, Action: RecoveryWait}, nil
		}
		return RecoveryResult{Effect: current, Action: RecoveryWait}, commitErr
	}
	if record.Status == LedgerUnknown && effect.State == StateNeedsConfirmation {
		return RecoveryResult{Effect: cloneEffect(effect), Action: RecoveryConfirmation}, nil
	}
	if record.Status == LedgerAbsent && effect.State == StateNeedsConfirmation && attempt.Failure == FailureLedgerAbsent {
		return RecoveryResult{Effect: cloneEffect(effect), Action: RecoveryConfirmation}, nil
	}
	if record.Status == LedgerUnknown && (effect.State == StateUncertain || effect.State == StateFailed) {
		return RecoveryResult{Effect: cloneEffect(effect), Action: RecoveryInterrupted}, nil
	}
	recovered, err := gateway.Apply(effect, Event{
		ExpectedRevision: effect.Revision, Kind: EventRecoveryObserved, Ledger: cloneLedgerRecord(record),
	})
	if err != nil {
		return RecoveryResult{}, err
	}
	persisted, persistErr := gateway.persistAfterExternal(ctx, currentScope, effect, recovered.Effect)
	current, err := persisted, persistErr
	if errors.Is(err, ErrConcurrentTransition) {
		loaded, loadErr := gateway.loadDurableEffect(ctx, effect.Scope.InvocationID)
		if loadErr != nil {
			return RecoveryResult{Effect: recovered.Effect}, loadErr
		}
		if record.Status == LedgerCommitted && (loaded.State == StateExternallyCommitted || loaded.State == StateCompleted) {
			if !bytes.Equal(loaded.Output, record.Output) || loaded.ExternalCommitID != record.ExternalCommitID {
				return RecoveryResult{Effect: loaded}, ErrLedgerMismatch
			}
			current, err = loaded, nil
		} else {
			return RecoveryResult{Effect: loaded, Action: recoveryAction(loaded)}, ErrConcurrentTransition
		}
	}
	if err != nil {
		return RecoveryResult{Effect: recovered.Effect}, err
	}
	if current.State == StateExternallyCommitted {
		settled, applyErr := gateway.Apply(current, Event{ExpectedRevision: current.Revision, Kind: EventSettlementCompleted})
		if applyErr != nil {
			return RecoveryResult{Effect: current}, applyErr
		}
		settlementBase := current
		persisted, persistErr := gateway.persistAfterExternal(ctx, currentScope, settlementBase, settled.Effect)
		current, err = persisted, persistErr
		if errors.Is(err, ErrConcurrentTransition) {
			loaded, loadErr := gateway.loadDurableEffect(ctx, settlementBase.Scope.InvocationID)
			if loadErr != nil {
				return RecoveryResult{Effect: settled.Effect}, loadErr
			}
			if loaded.State == StateCompleted && bytes.Equal(loaded.Output, settlementBase.Output) &&
				loaded.ExternalCommitID == settlementBase.ExternalCommitID {
				return RecoveryResult{Effect: loaded, Action: RecoverySettled}, nil
			}
			return RecoveryResult{Effect: loaded, Action: recoveryAction(loaded)}, ErrConcurrentTransition
		}
		if err != nil {
			return RecoveryResult{Effect: settled.Effect}, err
		}
		return RecoveryResult{Effect: current, Action: RecoverySettled}, nil
	}
	return RecoveryResult{Effect: current, Action: recoveryAction(current)}, nil
}

func (gateway *Gateway) Confirm(ctx context.Context, authority OpaqueAuthority, effect Effect, decision ConfirmationDecision) (Effect, error) {
	if err := ctx.Err(); err != nil {
		return Effect{}, err
	}
	if len(authority) == 0 || uint64(len(authority)) > gateway.bounds.MaxAuthorityBytes ||
		(decision != ConfirmationRetry && decision != ConfirmationAbandon) {
		return Effect{}, ErrInvalidRequest
	}
	if err := gateway.validateEffect(effect); err != nil {
		return Effect{}, err
	}
	attempt, _ := effect.CurrentAttempt()
	currentScope, err := gateway.validateCurrentAuthority(ctx, authority, CurrentAuthorityRequest{
		Scope: effect.Scope, RequestDigest: effect.RequestDigest, ProviderRequestID: attempt.ProviderRequestID,
		ConnectionGeneration: attempt.Negotiation.ConnectionGeneration, Attempt: attempt.Attempt, Permission: "mcp.confirm",
	})
	if err != nil {
		return Effect{}, err
	}
	transition, err := gateway.Apply(effect, Event{
		ExpectedRevision: effect.Revision, Kind: EventConfirmationDecided, Decision: decision,
	})
	if err != nil {
		return Effect{}, err
	}
	audit := AuditEvent{
		TenantID: effect.Scope.TenantID, UserID: effect.Scope.UserID, SessionID: effect.Scope.SessionID,
		TurnID: effect.Scope.TurnID, InvocationID: effect.Scope.InvocationID, ServerID: effect.ServerID,
		Method: "tools/call.confirm", Decision: string(decision), Reason: "uncertain MCP replay decision",
	}
	durableCtx, cancel := gateway.cleanupContext(ctx)
	defer cancel()
	stored, err := gateway.repository.Commit(durableCtx, TransitionCommitRequest{
		ExpectedRevision: effect.Revision, CurrentScope: currentScope,
		Previous: cloneEffect(effect), Next: cloneEffect(transition.Effect), Audit: &audit,
	})
	if err != nil {
		return Effect{}, redactedDependencyError(durableCtx, err, ErrStoreUnavailable,
			ErrConcurrentTransition, ErrEffectInFlight, ErrStaleAuthority, ErrInvalidTransition, ErrInvocationNotFound)
	}
	if !stored.Durable || !sameEffect(stored.Effect, transition.Effect) || stored.Audit == nil {
		return Effect{}, ErrStoreUnavailable
	}
	next := cloneEffect(stored.Effect)
	if auditErr := gateway.deliverAuditEnvelope(durableCtx, *stored.Audit); auditErr != nil {
		return next, auditErr
	}
	return next, nil
}

// FlushAudit delivers durable outbox entries in repository order. Delivery is
// at-least-once across crashes; OutboxSequence is the sink's deduplication key.
func (gateway *Gateway) FlushAudit(ctx context.Context, limit uint32) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if limit == 0 || limit > gateway.bounds.MaxEvents {
		return ErrInvalidRequest
	}
	pending, err := gateway.repository.PendingAudits(ctx, limit)
	if err != nil {
		return redactedDependencyError(ctx, err, ErrStoreUnavailable,
			ErrInvalidRequest, ErrStoreUnavailable)
	}
	if uint32(len(pending)) > limit {
		return ErrStoreUnavailable
	}
	var previous uint64
	for _, envelope := range pending {
		if envelope.Sequence <= previous {
			return ErrStoreUnavailable
		}
		if err := gateway.deliverAuditEnvelope(ctx, envelope); err != nil {
			return err
		}
		previous = envelope.Sequence
	}
	return nil
}

func (gateway *Gateway) deliverAuditEnvelope(ctx context.Context, envelope AuditEnvelope) error {
	if envelope.Sequence == 0 || envelope.Event.OutboxSequence != envelope.Sequence ||
		envelope.Event.TenantID.Kind() != identity.Tenant || envelope.Event.UserID.Kind() != identity.Subject ||
		envelope.Event.SessionID.Kind() != identity.Session || envelope.Event.TurnID.Kind() != identity.Turn ||
		envelope.Event.InvocationID.Kind() != identity.Invocation ||
		!validIdentifier(envelope.Event.ServerID, gateway.bounds.MaxServerIDBytes) ||
		!validBoundedText(envelope.Event.Method, gateway.bounds.MaxToolNameBytes) ||
		!validBoundedText(envelope.Event.Decision, gateway.bounds.MaxToolNameBytes) ||
		!validBoundedText(envelope.Event.Reason, gateway.bounds.MaxFailureBytes) {
		return ErrStoreUnavailable
	}
	if err := gateway.audit.Record(ctx, envelope.Event); err != nil {
		return redactedDependencyError(ctx, err, ErrAuditUnavailable, ErrAuditUnavailable)
	}
	if err := gateway.repository.AcknowledgeAudit(ctx, envelope.Sequence); err != nil {
		return redactedDependencyError(ctx, err, ErrStoreUnavailable,
			ErrInvalidRequest, ErrStoreUnavailable)
	}
	return nil
}

func (gateway *Gateway) cancelProtocolViolation(ctx context.Context, authority OpaqueAuthority, current Effect, cause error) (Effect, error) {
	cancelled, cancelErr := gateway.Cancel(ctx, authority, current)
	return cancelled, errors.Join(cause, cancelErr)
}

func (gateway *Gateway) cleanupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), gateway.bounds.CancelTimeout)
}

func (gateway *Gateway) closeProviderCall(ctx context.Context, call ProviderCall) {
	if !isNilInterface(call) {
		cleanupContext, cancelCleanup := gateway.cleanupContext(ctx)
		defer cancelCleanup()
		_ = call.Close(cleanupContext)
	}
}

func boundedFailureReason(err error, fallback string, maximum uint64) string {
	// Provider errors are not a trusted public-error channel and may contain
	// endpoint credentials or request payload fragments.
	_ = err
	_ = maximum
	return fallback
}

func cloneLedgerRecord(record LedgerRecord) LedgerRecord {
	copy := record
	copy.Output = append([]byte(nil), record.Output...)
	return copy
}

func recoveryAction(effect Effect) RecoveryAction {
	switch effect.State {
	case StateRetryPending:
		return RecoveryRetry
	case StateNeedsConfirmation:
		return RecoveryConfirmation
	case StateCompleted:
		return RecoverySettled
	default:
		return RecoveryInterrupted
	}
}
