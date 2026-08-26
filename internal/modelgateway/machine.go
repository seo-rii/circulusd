package modelgateway

import (
	"fmt"
	"math"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Apply performs one deterministic transition. It performs no provider I/O
// and mutates neither the input Effect nor Event.
func (gateway *Gateway) Apply(effect Effect, event Event) (Transition, error) {
	if err := gateway.validateEffect(effect); err != nil {
		return Transition{}, err
	}
	if event.ExpectedRevision != effect.Revision {
		return Transition{}, ErrConcurrentTransition
	}
	if effect.Revision == math.MaxUint64 || effect.EventCount >= gateway.bounds.MaxEvents {
		return Transition{}, ErrEventLimit
	}

	var eventBytes uint64
	switch event.Kind {
	case EventBeginDispatch:
		if event.ProviderRequestID != "" || event.Delta != "" || event.Response != nil || event.Failure != "" || event.Reason != "" || event.DispatchPrevented ||
			event.Cancellation != (CancellationPermit{}) || event.Recovery != (ResumePermit{}) {
			return Transition{}, ErrInvalidRequest
		}
	case EventProviderAccepted:
		if event.ProviderRequestID == "" || !utf8.ValidString(event.ProviderRequestID) ||
			strings.IndexFunc(event.ProviderRequestID, unicode.IsControl) >= 0 || uint64(len(event.ProviderRequestID)) > gateway.bounds.MaxProviderRequestIDBytes ||
			event.Delta != "" || event.Response != nil || event.Failure != "" || event.Reason != "" || event.DispatchPrevented ||
			event.Cancellation != (CancellationPermit{}) || event.Recovery != (ResumePermit{}) {
			return Transition{}, ErrInvalidRequest
		}
		eventBytes = uint64(len(event.ProviderRequestID))
	case EventDelta:
		if event.Delta == "" || !utf8.ValidString(event.Delta) || event.ProviderRequestID != "" || event.Response != nil || event.Failure != "" || event.Reason != "" || event.DispatchPrevented ||
			event.Cancellation != (CancellationPermit{}) {
			return Transition{}, ErrInvalidRequest
		}
		eventBytes = uint64(len(event.Delta))
	case EventResponseCompleted:
		if event.Response == nil || event.ProviderRequestID != "" || event.Delta != "" || event.Failure != "" || event.Reason != "" || event.DispatchPrevented ||
			event.Cancellation != (CancellationPermit{}) ||
			!utf8.ValidString(event.Response.Text) || uint64(len(event.Response.Text)) > gateway.bounds.MaxResponseBytes ||
			!validFinishReason(event.Response.FinishReason) || uint64(len(event.Response.FinishReason)) > gateway.bounds.MaxReasonBytes {
			return Transition{}, ErrInvalidRequest
		}
		if uint64(len(event.Response.Text)) > math.MaxUint64-uint64(len(event.Response.FinishReason)) {
			return Transition{}, ErrEventLimit
		}
		responseBytes := uint64(len(event.Response.Text) + len(event.Response.FinishReason))
		normalizedCalls, toolCallBytes, err := normalizeToolCalls(event.Response.ToolCalls)
		if err != nil {
			return Transition{}, err
		}
		if toolCallBytes > math.MaxUint64-responseBytes {
			return Transition{}, ErrEventLimit
		}
		responseBytes += toolCallBytes
		if responseBytes > gateway.bounds.MaxResponseBytes {
			return Transition{}, ErrEventLimit
		}
		event.Response = cloneResponse(event.Response)
		event.Response.ToolCalls = normalizedCalls
		eventBytes = responseBytes
	case EventDispatchFailed:
		switch event.Failure {
		case FailurePreDispatch, FailureProviderRejected, FailureTransportUnknown, FailureAfterPartial:
		default:
			return Transition{}, ErrInvalidRequest
		}
		if event.Reason == "" || !utf8.ValidString(event.Reason) || strings.IndexFunc(event.Reason, unicode.IsControl) >= 0 ||
			uint64(len(event.Reason)) > gateway.bounds.MaxReasonBytes || event.ProviderRequestID != "" || event.Delta != "" || event.Response != nil || event.DispatchPrevented ||
			event.Cancellation != (CancellationPermit{}) {
			return Transition{}, ErrInvalidRequest
		}
		event.Reason = gateway.normalizedFailureReason(event.Failure)
		eventBytes = uint64(len(event.Reason))
	case EventCancelRequested:
		if event.ProviderRequestID != "" || event.Delta != "" || event.Response != nil || event.Failure != "" || event.Reason != "" || event.DispatchPrevented ||
			event.Cancellation != (CancellationPermit{}) || event.Recovery != (ResumePermit{}) {
			return Transition{}, ErrInvalidRequest
		}
	case EventCancellationResolved:
		if event.ProviderRequestID != "" || event.Delta != "" || event.Response != nil || event.Failure != "" || event.Reason != "" || event.Recovery != (ResumePermit{}) {
			return Transition{}, ErrInvalidRequest
		}
	default:
		return Transition{}, ErrInvalidRequest
	}
	if eventBytes > gateway.bounds.MaxEventBytes || eventBytes > math.MaxUint64-effect.EventBytes {
		return Transition{}, ErrEventLimit
	}
	recoveryEvent := event.Recovery != (ResumePermit{})
	if recoveryEvent && !validResumePermit(effect, event.Recovery) {
		return Transition{}, ErrInvalidRequest
	}
	if effect.RecoveryPermit != (ResumePermit{}) &&
		(event.Kind == EventDelta || event.Kind == EventResponseCompleted || event.Kind == EventDispatchFailed) && !recoveryEvent {
		return Transition{}, ErrInvalidRequest
	}

	next := effect
	next.Request = cloneModelRequest(effect.Request)
	next.Response = cloneResponse(effect.Response)
	transition := Transition{}
	switch event.Kind {
	case EventBeginDispatch:
		if next.State != StateAdmitted && next.State != StateRetryPending {
			return Transition{}, ErrInvalidTransition
		}
		if next.Attempt >= next.MaxPreDispatchRetries+1 {
			return Transition{}, ErrInvalidTransition
		}
		next.Attempt++
		next.State = StateDispatching
		next.FailureReason = ""
		transition.Dispatch = &DispatchCommand{
			ProviderID: next.ProviderID, Scope: next.Scope, EffectID: next.Scope.EffectID, InvocationID: next.Scope.InvocationID,
			RequestDigest: next.RequestDigest, QuotaPermit: next.QuotaPermit, Request: cloneModelRequest(next.Request), Attempt: next.Attempt,
		}
	case EventProviderAccepted:
		if next.State != StateDispatching || next.ProviderRequestID != "" || next.PartialOutput {
			return Transition{}, ErrInvalidTransition
		}
		next.ProviderRequestID = event.ProviderRequestID
		next.State = StateDispatched
	case EventDelta:
		if next.State != StateDispatched && next.State != StateStreaming && !(next.State == StateUncertain && recoveryEvent) {
			return Transition{}, ErrInvalidTransition
		}
		if recoveryEvent {
			next.RecoveryPermit = event.Recovery
			next.Outcome = ""
			next.FailureReason = ""
		}
		if eventBytes > gateway.bounds.MaxStreamBytes-next.StreamBytes {
			return Transition{}, ErrEventLimit
		}
		next.StreamBytes += eventBytes
		next.PartialOutput = true
		next.State = StateStreaming
	case EventResponseCompleted:
		if next.State != StateDispatched && next.State != StateStreaming && !(next.State == StateUncertain && recoveryEvent) {
			return Transition{}, ErrInvalidTransition
		}
		if recoveryEvent {
			next.RecoveryPermit = event.Recovery
			next.Outcome = ""
			next.FailureReason = ""
		}
		usage := event.Response.Usage
		if usage.InputTokens > next.ContextTokens {
			return Transition{}, ErrQuotaMismatch
		}
		if usage.InputTokens > next.MaxContextTokens || usage.OutputTokens > next.RequestedOutputTokens ||
			usage.InputTokens > next.MaxTotalTokens || usage.OutputTokens > next.MaxTotalTokens-usage.InputTokens {
			return Transition{}, ErrTokenLimit
		}
		next.Response = cloneResponse(event.Response)
		next.Response.Usage = Usage{InputTokens: next.ContextTokens, OutputTokens: next.RequestedOutputTokens}
		next.State = StateCompleted
		next.Outcome = OutcomeCompleted
	case EventDispatchFailed:
		if recoveryEvent {
			next.RecoveryPermit = event.Recovery
		}
		next.FailureReason = event.Reason
		switch event.Failure {
		case FailurePreDispatch:
			if next.State != StateDispatching || next.ProviderRequestID != "" || next.PartialOutput {
				return Transition{}, ErrInvalidTransition
			}
			if next.Attempt <= next.MaxPreDispatchRetries {
				next.State = StateRetryPending
			} else {
				next.State = StateFailed
				next.Outcome = OutcomeFailed
			}
		case FailureProviderRejected:
			if (next.State != StateDispatching && next.State != StateDispatched && !(next.State == StateUncertain && recoveryEvent)) || next.PartialOutput {
				return Transition{}, ErrInvalidTransition
			}
			next.State = StateFailed
			next.Outcome = OutcomeFailed
		case FailureTransportUnknown:
			if next.State != StateDispatching && next.State != StateDispatched && next.State != StateStreaming && !(next.State == StateUncertain && recoveryEvent) {
				return Transition{}, ErrInvalidTransition
			}
			next.State = StateUncertain
			next.Outcome = OutcomeUncertain
		case FailureAfterPartial:
			if (next.State != StateStreaming && !(next.State == StateUncertain && recoveryEvent)) || !next.PartialOutput {
				return Transition{}, ErrInvalidTransition
			}
			next.State = StateUncertain
			next.Outcome = OutcomeUncertain
		}
	case EventCancelRequested:
		switch next.State {
		case StateAdmitted, StateRetryPending:
			next.State = StateCancelled
			next.Outcome = OutcomeCancelled
			next.FailureReason = ""
		case StateDispatching, StateDispatched, StateStreaming:
			next.State = StateCancellationPending
			transition.Cancel = &CancelCommand{
				ProviderID: next.ProviderID, Scope: next.Scope, EffectID: next.Scope.EffectID, InvocationID: next.Scope.InvocationID,
				RequestDigest: next.RequestDigest, ProviderRequestID: next.ProviderRequestID, Attempt: next.Attempt,
			}
		default:
			return Transition{}, ErrInvalidTransition
		}
	case EventCancellationResolved:
		if next.State != StateCancellationPending {
			return Transition{}, ErrInvalidTransition
		}
		provenPrevented := false
		if event.Cancellation != (CancellationPermit{}) {
			if !validCancellationPermit(next, event.Cancellation) || event.DispatchPrevented != event.Cancellation.DispatchPrevented ||
				(event.Cancellation.DispatchPrevented && (next.ProviderRequestID != "" || next.PartialOutput)) {
				return Transition{}, ErrInvalidRequest
			}
			provenPrevented = event.Cancellation.DispatchPrevented
			next.CancellationPermit = event.Cancellation
		}
		if provenPrevented {
			next.State = StateCancelled
			next.Outcome = OutcomeCancelled
		} else {
			next.State = StateUncertain
			next.Outcome = OutcomeUncertain
		}
	}

	projectedEventCount := next.EventCount + 1
	if next.Outcome == "" && uint64(projectedEventCount)+uint64(minimumTerminalEvents(next)) > uint64(gateway.bounds.MaxEvents) {
		return Transition{}, ErrEventLimit
	}
	next.Revision++
	next.EventCount++
	next.EventBytes += eventBytes
	transition.Effect = next
	return transition, nil
}

func (event Event) String() string {
	return fmt.Sprintf("model-event<kind=%s revision=%d>", event.Kind, event.ExpectedRevision)
}
