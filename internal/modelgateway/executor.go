package modelgateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ExecuteDispatch performs the effect sandwich's external-I/O half. The
// durable coordinator owns both the effect CAS and the exclusive dispatch
// claim, so a competing executor cannot reach Provider.Dispatch.
func (gateway *Gateway) ExecuteDispatch(ctx context.Context, authority OpaqueAuthority, transition Transition) (DispatchExecution, error) {
	if err := ctx.Err(); err != nil {
		return DispatchExecution{}, err
	}
	if len(authority) == 0 || uint64(len(authority)) > gateway.bounds.MaxAuthorityBytes {
		return DispatchExecution{}, ErrInvalidRequest
	}
	effect, command, err := gateway.validateDispatchTransition(transition)
	if err != nil {
		return DispatchExecution{}, err
	}

	currentScope, err := gateway.authority.ValidateAdmission(ctx, append(OpaqueAuthority(nil), authority...), AdmissionAuthorityRequest{
		EffectID: effect.Scope.EffectID, InvocationID: effect.Scope.InvocationID, RequestDigest: effect.RequestDigest, Permission: "model.dispatch",
	})
	if err != nil {
		return DispatchExecution{}, err
	}
	if currentScope != effect.Scope {
		return DispatchExecution{}, ErrAuthorityMismatch
	}

	commitCommand := command
	commitCommand.Request = cloneModelRequest(command.Request)
	commitEffect := effect
	commitEffect.Request = cloneModelRequest(effect.Request)
	commitEffect.Response = cloneResponse(effect.Response)
	permit, err := gateway.dispatches.CommitAndClaimDispatch(ctx, DispatchCommitRequest{
		ExpectedRevision: effect.Revision - 1,
		CurrentScope:     currentScope,
		Effect:           commitEffect,
		Command:          commitCommand,
	})
	if err != nil {
		return DispatchExecution{}, err
	}
	if !permit.Durable || permit.Proof == (OpaqueDispatchPermit{}) || permit.Scope != effect.Scope || permit.EffectID != effect.Scope.EffectID ||
		permit.InvocationID != effect.Scope.InvocationID || permit.RequestDigest != effect.RequestDigest || permit.ProviderID != effect.ProviderID ||
		permit.Attempt != effect.Attempt || permit.EffectRevision != effect.Revision {
		return DispatchExecution{}, ErrDispatchNotDurable
	}
	if err := gateway.dispatches.BeginProviderDispatch(ctx, permit); err != nil {
		return DispatchExecution{Permit: permit, Effect: effect}, err
	}
	return gateway.executeProviderDispatch(ctx, effect, command, permit, gateway.dispatches.CommitProviderAccepted)
}

type providerAcceptedRecorder func(context.Context, ProviderAcceptedCommitRequest) error

func (gateway *Gateway) validateDispatchTransition(transition Transition) (Effect, DispatchCommand, error) {
	if gateway == nil || transition.Dispatch == nil || transition.Cancel != nil {
		return Effect{}, DispatchCommand{}, ErrInvalidRequest
	}
	effect := transition.Effect
	if err := gateway.validateEffect(effect); err != nil {
		return Effect{}, DispatchCommand{}, err
	}
	command := *transition.Dispatch
	if effect.State != StateDispatching || effect.Revision < 2 || command.Permit != (DispatchPermit{}) ||
		command.ProviderID != effect.ProviderID || command.Scope != effect.Scope || command.EffectID != effect.Scope.EffectID ||
		command.InvocationID != effect.Scope.InvocationID || command.RequestDigest != effect.RequestDigest || command.QuotaPermit != effect.QuotaPermit ||
		command.Request.Model != effect.Request.Model || command.Request.MaxOutputTokens != effect.Request.MaxOutputTokens ||
		command.Request.Reasoning != effect.Request.Reasoning ||
		!slices.Equal(command.Request.Messages, effect.Request.Messages) || command.Attempt != effect.Attempt {
		return Effect{}, DispatchCommand{}, ErrInvalidRequest
	}
	return effect, command, nil
}

func (gateway *Gateway) executeProviderDispatch(
	ctx context.Context,
	effect Effect,
	command DispatchCommand,
	permit DispatchPermit,
	recordAccepted providerAcceptedRecorder,
) (DispatchExecution, error) {
	if gateway == nil || ctx == nil || recordAccepted == nil {
		return DispatchExecution{}, ErrInvalidRequest
	}
	providerCommand := command
	providerCommand.Request = cloneModelRequest(command.Request)
	providerCommand.Permit = permit
	providerResult, dispatchErr := gateway.providers[effect.ProviderID].Dispatch(ctx, providerCommand)
	executionEffect := effect
	providerRequestID := strings.TrimSpace(providerResult.ProviderRequestID)
	providerIdentityInvalid := providerRequestID != "" && (providerRequestID != providerResult.ProviderRequestID || !utf8.ValidString(providerRequestID) ||
		strings.IndexFunc(providerRequestID, unicode.IsControl) >= 0 || uint64(len(providerRequestID)) > gateway.bounds.MaxProviderRequestIDBytes ||
		uint64(len(providerRequestID)) > gateway.bounds.MaxEventBytes)
	if providerIdentityInvalid {
		providerRequestID = ""
		dispatchErr = errors.New("provider returned an invalid request identity after dispatch")
	}
	if providerRequestID != "" {
		accepted, applyErr := gateway.Apply(effect, Event{
			ExpectedRevision:  effect.Revision,
			Kind:              EventProviderAccepted,
			ProviderRequestID: providerRequestID,
		})
		if applyErr != nil {
			if providerResult.Stream != nil {
				_ = providerResult.Stream.Close()
			}
			return DispatchExecution{Permit: permit, Effect: effect}, applyErr
		}
		acceptedEffect := accepted.Effect
		acceptedEffect.Request = cloneModelRequest(accepted.Effect.Request)
		acceptedEffect.Response = cloneResponse(accepted.Effect.Response)
		if commitErr := recordAccepted(context.WithoutCancel(ctx), ProviderAcceptedCommitRequest{
			ExpectedRevision: effect.Revision,
			Permit:           permit,
			Effect:           acceptedEffect,
		}); commitErr != nil {
			if providerResult.Stream != nil {
				_ = providerResult.Stream.Close()
			}
			return DispatchExecution{Permit: permit, Effect: accepted.Effect}, fmt.Errorf("%w: persist provider request identity", ErrDispatchNotDurable)
		}
		executionEffect = accepted.Effect
	}
	if dispatchErr == nil && providerResult.Stream != nil && providerRequestID != "" {
		return DispatchExecution{
			Permit: permit,
			Effect: executionEffect,
			Stream: &normalizedProviderStream{gateway: gateway, stream: providerResult.Stream},
		}, nil
	}
	if dispatchErr == nil {
		dispatchErr = errors.New("provider returned no bounded request identity, stream, or error")
	}
	failureClass := FailureTransportUnknown
	reason := gateway.normalizedFailureReason(FailureTransportUnknown)
	var typedFailure *ProviderDispatchError
	if errors.As(dispatchErr, &typedFailure) {
		if typedFailure.Classification() == DispatchFailureDefinitelyNotSent && providerRequestID == "" {
			failureClass = FailurePreDispatch
			reason = gateway.normalizedFailureReason(FailurePreDispatch)
		}
	}
	if providerResult.Stream != nil {
		_ = providerResult.Stream.Close()
	}
	failure := Event{ExpectedRevision: executionEffect.Revision, Kind: EventDispatchFailed, Failure: failureClass, Reason: reason}
	return DispatchExecution{Permit: permit, Effect: executionEffect, Failure: &failure}, nil
}

// ExecuteCancel durably linearizes cancellation against provider dispatch. A
// request is classified as definitely not sent only when the coordinator
// revoked the dispatch claim before BeginProviderDispatch could start I/O.
func (gateway *Gateway) ExecuteCancel(ctx context.Context, authority OpaqueAuthority, transition Transition) (CancellationExecution, error) {
	if err := ctx.Err(); err != nil {
		return CancellationExecution{}, err
	}
	if len(authority) == 0 || uint64(len(authority)) > gateway.bounds.MaxAuthorityBytes || transition.Cancel == nil || transition.Dispatch != nil {
		return CancellationExecution{}, ErrInvalidRequest
	}
	effect := transition.Effect
	if err := gateway.validateEffect(effect); err != nil {
		return CancellationExecution{}, err
	}
	command := *transition.Cancel
	if effect.State != StateCancellationPending || effect.Revision < 2 || command.Permit != (CancellationPermit{}) ||
		command.ProviderID != effect.ProviderID || command.Scope != effect.Scope || command.EffectID != effect.Scope.EffectID ||
		command.InvocationID != effect.Scope.InvocationID || command.RequestDigest != effect.RequestDigest ||
		command.ProviderRequestID != effect.ProviderRequestID || command.Attempt != effect.Attempt {
		return CancellationExecution{}, ErrInvalidRequest
	}
	currentScope, err := gateway.authority.ValidateAdmission(ctx, append(OpaqueAuthority(nil), authority...), AdmissionAuthorityRequest{
		EffectID: effect.Scope.EffectID, InvocationID: effect.Scope.InvocationID, RequestDigest: effect.RequestDigest, Permission: "model.cancel",
	})
	if err != nil {
		return CancellationExecution{}, err
	}
	if !sameAuthorityIdentity(currentScope, effect.Scope) || currentScope.Generations.TurnLease == 0 ||
		currentScope.Generations.Placement == 0 || currentScope.Generations.Policy == 0 {
		return CancellationExecution{}, ErrAuthorityMismatch
	}
	commitCommand := command
	commitEffect := effect
	commitEffect.Request = cloneModelRequest(effect.Request)
	commitEffect.Response = cloneResponse(effect.Response)
	permit, err := gateway.dispatches.CommitAndClaimCancellation(ctx, CancellationCommitRequest{
		ExpectedRevision: effect.Revision - 1, CurrentScope: currentScope, Effect: commitEffect, Command: commitCommand,
	})
	if err != nil {
		return CancellationExecution{}, err
	}
	if !validCancellationPermit(effect, permit) || permit.CurrentScope != currentScope {
		return CancellationExecution{}, ErrDispatchNotDurable
	}
	resolution := Event{
		ExpectedRevision: effect.Revision, Kind: EventCancellationResolved,
		DispatchPrevented: permit.DispatchPrevented, Cancellation: permit,
	}
	if permit.DispatchPrevented {
		return CancellationExecution{Permit: permit, Effect: effect, Resolution: resolution}, nil
	}
	providerCommand := command
	providerCommand.Scope = currentScope
	providerCommand.Permit = permit
	_, _ = gateway.providers[effect.ProviderID].Cancel(ctx, providerCommand)
	resolution.DispatchPrevented = false
	return CancellationExecution{Permit: permit, Effect: effect, Resolution: resolution}, nil
}

// ResumeProviderRequest uses a provider's explicitly advertised durable
// retrieval contract. It never falls back to Dispatch, so absence or ambiguity
// cannot silently create a second provider request.
func (gateway *Gateway) ResumeProviderRequest(ctx context.Context, authority OpaqueAuthority, effect Effect) (EventStream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(authority) == 0 || uint64(len(authority)) > gateway.bounds.MaxAuthorityBytes {
		return nil, ErrInvalidRequest
	}
	if err := gateway.validateEffect(effect); err != nil {
		return nil, err
	}
	if !effect.DurableRequestRetrieval || effect.ProviderRequestID == "" {
		return nil, ErrDurableRetrievalUnavailable
	}
	switch effect.State {
	case StateDispatched, StateStreaming, StateUncertain:
	default:
		return nil, ErrInvalidTransition
	}
	currentScope, err := gateway.authority.ValidateAdmission(ctx, append(OpaqueAuthority(nil), authority...), AdmissionAuthorityRequest{
		EffectID: effect.Scope.EffectID, InvocationID: effect.Scope.InvocationID, RequestDigest: effect.RequestDigest, Permission: "model.resume",
	})
	if err != nil {
		return nil, err
	}
	if !sameAuthorityIdentity(currentScope, effect.Scope) || currentScope.Generations.TurnLease == 0 ||
		currentScope.Generations.Placement == 0 || currentScope.Generations.Policy == 0 {
		return nil, ErrAuthorityMismatch
	}
	commitEffect := effect
	commitEffect.Request = cloneModelRequest(effect.Request)
	commitEffect.Response = cloneResponse(effect.Response)
	permit, err := gateway.dispatches.CommitAndClaimResume(ctx, ResumeCommitRequest{CurrentScope: currentScope, Effect: commitEffect})
	if err != nil {
		return nil, err
	}
	if !validResumePermit(effect, permit) || permit.CurrentScope != currentScope || permit.EffectRevision != effect.Revision {
		return nil, ErrDispatchNotDurable
	}
	retriever, supported := gateway.providers[effect.ProviderID].(ProviderRequestRetriever)
	if !supported {
		return nil, ErrDurableRetrievalUnavailable
	}
	stream, err := retriever.Resume(ctx, ProviderResumeCommand{
		ProviderID: effect.ProviderID, Scope: currentScope, OriginScope: effect.Scope, EffectID: effect.Scope.EffectID,
		InvocationID: effect.Scope.InvocationID, RequestDigest: effect.RequestDigest,
		ProviderRequestID: effect.ProviderRequestID, Attempt: effect.Attempt, Permit: permit,
	})
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return nil, contextErr
		}
		return nil, fmt.Errorf("%w: provider resume failed", ErrProviderUnavailable)
	}
	if stream == nil {
		return nil, ErrDurableRetrievalUnavailable
	}
	return &normalizedProviderStream{gateway: gateway, stream: stream, recovery: permit}, nil
}

type normalizedProviderStream struct {
	gateway  *Gateway
	stream   ProviderStream
	recovery ResumePermit
}

func (stream *normalizedProviderStream) Next(ctx context.Context) (Event, error) {
	providerEvent, err := stream.stream.Next(ctx)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return Event{}, io.EOF
		}
		if contextErr := ctx.Err(); contextErr != nil {
			return Event{}, contextErr
		}
		return Event{}, fmt.Errorf("%w: provider stream failed", ErrProviderUnavailable)
	}
	event := Event{Recovery: stream.recovery}
	switch providerEvent.Kind {
	case ProviderEventDelta:
		if providerEvent.Delta == "" || providerEvent.Response != nil || providerEvent.Failure != "" || providerEvent.Diagnostic != "" {
			return Event{}, ErrInvalidRequest
		}
		event.Kind = EventDelta
		event.Delta = providerEvent.Delta
	case ProviderEventResponseCompleted:
		if providerEvent.Delta != "" || providerEvent.Response == nil || providerEvent.Failure != "" || providerEvent.Diagnostic != "" {
			return Event{}, ErrInvalidRequest
		}
		finishReason := FinishReasonOther
		switch providerEvent.Response.FinishReason {
		case string(FinishReasonStop):
			finishReason = FinishReasonStop
		case string(FinishReasonLength):
			finishReason = FinishReasonLength
		case string(FinishReasonToolCalls):
			finishReason = FinishReasonToolCalls
		case string(FinishReasonContentFilter):
			finishReason = FinishReasonContentFilter
		case string(FinishReasonCancelled):
			finishReason = FinishReasonCancelled
		}
		event.Kind = EventResponseCompleted
		event.Response = cloneResponse(&ModelResponse{
			Text: providerEvent.Response.Text, FinishReason: finishReason,
			Usage: providerEvent.Response.Usage, ToolCalls: providerEvent.Response.ToolCalls,
		})
	case ProviderEventFailed:
		if providerEvent.Delta != "" || providerEvent.Response != nil {
			return Event{}, ErrInvalidRequest
		}
		switch providerEvent.Failure {
		case FailureProviderRejected, FailureTransportUnknown, FailureAfterPartial:
		default:
			return Event{}, ErrInvalidRequest
		}
		event.Kind = EventDispatchFailed
		event.Failure = providerEvent.Failure
		event.Reason = stream.gateway.normalizedFailureReason(providerEvent.Failure)
	default:
		return Event{}, ErrInvalidRequest
	}
	return event, nil
}

func (stream *normalizedProviderStream) Close() error {
	if err := stream.stream.Close(); err != nil {
		return fmt.Errorf("%w: provider stream close failed", ErrProviderUnavailable)
	}
	return nil
}

func validCancellationPermit(effect Effect, permit CancellationPermit) bool {
	revisionBound := permit.EffectRevision == effect.Revision ||
		(effect.CancellationPermit != (CancellationPermit{}) && permit == effect.CancellationPermit &&
			permit.EffectRevision < effect.Revision && permit.EffectRevision+1 == effect.Revision)
	return permit.Durable && permit.Proof != (OpaqueCancellationPermit{}) && permit.EffectID == effect.Scope.EffectID &&
		permit.InvocationID == effect.Scope.InvocationID && permit.RequestDigest == effect.RequestDigest &&
		permit.ProviderID == effect.ProviderID && permit.ProviderRequestID == effect.ProviderRequestID &&
		permit.Attempt == effect.Attempt && revisionBound &&
		sameAuthorityIdentity(permit.CurrentScope, effect.Scope) && permit.CurrentScope.Generations.TurnLease != 0 &&
		permit.CurrentScope.Generations.Placement != 0 && permit.CurrentScope.Generations.Policy != 0
}

func validResumePermit(effect Effect, permit ResumePermit) bool {
	revisionBound := permit.EffectRevision == effect.Revision ||
		(effect.RecoveryPermit != (ResumePermit{}) && permit == effect.RecoveryPermit)
	return permit.Durable && permit.Proof != (OpaqueResumePermit{}) && permit.OriginScope == effect.Scope &&
		permit.EffectID == effect.Scope.EffectID && permit.InvocationID == effect.Scope.InvocationID &&
		permit.RequestDigest == effect.RequestDigest && permit.ProviderID == effect.ProviderID &&
		permit.ProviderRequestID == effect.ProviderRequestID && permit.Attempt == effect.Attempt && revisionBound &&
		sameAuthorityIdentity(permit.CurrentScope, effect.Scope) && permit.CurrentScope.Generations.TurnLease != 0 &&
		permit.CurrentScope.Generations.Placement != 0 && permit.CurrentScope.Generations.Policy != 0
}
