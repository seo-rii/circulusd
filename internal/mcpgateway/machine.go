package mcpgateway

import (
	"fmt"
	"math"

	"github.com/hancomac/circulusd/internal/identity"
)

const confirmationAbandonUnknownReason = "user abandoned unknown cancellation"

// Apply performs one deterministic transition without provider I/O or durable
// writes. It never aliases mutable input, event, or output buffers.
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
	eventBytes, err := gateway.validateEvent(effect, event)
	if err != nil {
		return Transition{}, err
	}
	if eventBytes > math.MaxUint64-effect.EventBytes {
		return Transition{}, ErrEventLimit
	}

	next := cloneEffect(effect)
	transition := Transition{}
	switch event.Kind {
	case EventBeginDispatch:
		if (next.State != StateAdmitted && next.State != StateRetryPending) || next.CancellationRequested {
			return Transition{}, ErrInvalidTransition
		}
		allowedAttempts := uint64(1) + uint64(next.AutomaticRetriesUsed) + uint64(next.ConfirmationRetriesUsed)
		if uint64(len(next.Attempts)) >= allowedAttempts {
			return Transition{}, ErrInvalidTransition
		}
		attempt := uint32(len(next.Attempts) + 1)
		next.Attempts = append(next.Attempts, AttemptRecord{Attempt: attempt})
		next.State = StateDispatching
		next.FailureReason = ""
		idempotencyKey := ""
		if next.ReplayPolicy == ReplayIdempotencyKey {
			idempotencyKey = next.Scope.InvocationID.String()
		}
		transition.Dispatch = &DispatchCommand{
			Scope: next.Scope, Server: serverForEffect(next), ToolName: next.ToolName,
			InputCanonical: append([]byte(nil), next.InputCanonical...), InvocationID: next.Scope.InvocationID,
			RequestDigest: next.RequestDigest, ReplayPolicy: next.ReplayPolicy,
			IdempotencyKey: idempotencyKey, Attempt: attempt,
		}

	case EventNegotiationRecorded:
		attempt, ok := next.CurrentAttempt()
		if next.State != StateDispatching || !ok || attempt.ProviderRequestID != "" ||
			attempt.HadOutput || attempt.Failure != "" || attempt.Negotiation != (StartNegotiationReceipt{}) ||
			!validNegotiationReceiptForEffect(event.Negotiation, next, attempt.Attempt) {
			return Transition{}, ErrInvalidTransition
		}
		next.Attempts[len(next.Attempts)-1].Negotiation = event.Negotiation

	case EventProviderAccepted:
		attempt, ok := next.CurrentAttempt()
		if next.State != StateDispatching || !ok || attempt.ProviderRequestID != "" || attempt.HadOutput ||
			attempt.Failure != "" || !validNegotiationReceiptForEffect(attempt.Negotiation, next, attempt.Attempt) {
			return Transition{}, ErrInvalidTransition
		}
		next.Attempts[len(next.Attempts)-1].ProviderRequestID = event.ProviderRequestID
		next.State = StateDispatched

	case EventOutputChunk:
		attempt, ok := next.CurrentAttempt()
		if (next.State != StateDispatched && next.State != StateStreaming) || !ok || attempt.ProviderRequestID == "" {
			return Transition{}, ErrInvalidTransition
		}
		if uint64(len(event.Chunk)) > gateway.bounds.MaxOutputBytes-next.StreamBytes || next.ChunkCount >= gateway.bounds.MaxChunks {
			return Transition{}, ErrOutputLimit
		}
		next.Attempts[len(next.Attempts)-1].HadOutput = true
		next.ChunkCount++
		next.StreamBytes += uint64(len(event.Chunk))
		next.State = StateStreaming

	case EventCallCommitted:
		if next.State != StateDispatched && next.State != StateStreaming && next.State != StateCancellationPending &&
			next.State != StateUncertain && next.State != StateNeedsConfirmation && next.State != StateFailed {
			return Transition{}, ErrInvalidTransition
		}
		attempt, ok := next.CurrentAttempt()
		if next.State == StateFailed && (!ok || attempt.Failure != FailureUnknown) {
			return Transition{}, ErrInvalidTransition
		}
		if !ok || (attempt.ProviderRequestID == "" && event.ExternalCommitID == "") {
			return Transition{}, ErrInvalidTransition
		}
		next.Output = append([]byte(nil), event.Output...)
		next.ExternalCommitID = event.ExternalCommitID
		next.FailureReason = ""
		next.State = StateExternallyCommitted

	case EventSettlementCompleted:
		if next.State != StateExternallyCommitted || len(next.Output) == 0 {
			return Transition{}, ErrInvalidTransition
		}
		next.State = StateCompleted

	case EventDispatchFailed:
		if err := gateway.applyFailure(&next, event.Failure, event.Reason); err != nil {
			return Transition{}, err
		}

	case EventCancelRequested:
		next.CancellationRequested = true
		switch next.State {
		case StateAdmitted:
			next.State = StateCancelled
			next.FailureReason = ""
		case StateRetryPending:
			attempt, ok := next.CurrentAttempt()
			if !ok {
				return Transition{}, ErrInvalidTransition
			}
			if attempt.Failure == FailureDefinitelyNotSent || attempt.Failure == FailureLedgerAbsent {
				next.State = StateCancelled
				next.FailureReason = ""
				break
			}
			next.State = StateCancellationPending
			transition.Cancel = &CancelCommand{
				Scope: next.Scope, Server: serverForEffect(next), ToolName: next.ToolName,
				InvocationID: next.Scope.InvocationID, RequestDigest: next.RequestDigest,
				ProviderRequestID: attempt.ProviderRequestID, Attempt: attempt.Attempt, Negotiation: attempt.Negotiation,
			}
		case StateDispatching, StateDispatched, StateStreaming, StateUncertain, StateNeedsConfirmation:
			next.State = StateCancellationPending
			attempt, _ := next.CurrentAttempt()
			transition.Cancel = &CancelCommand{
				Scope: next.Scope, Server: serverForEffect(next), ToolName: next.ToolName,
				InvocationID: next.Scope.InvocationID, RequestDigest: next.RequestDigest,
				ProviderRequestID: attempt.ProviderRequestID, Attempt: attempt.Attempt, Negotiation: attempt.Negotiation,
			}
		case StateFailed:
			attempt, ok := next.CurrentAttempt()
			if !ok || attempt.Failure != FailureUnknown {
				return Transition{}, ErrInvalidTransition
			}
			next.State = StateCancellationPending
			transition.Cancel = &CancelCommand{
				Scope: next.Scope, Server: serverForEffect(next), ToolName: next.ToolName,
				InvocationID: next.Scope.InvocationID, RequestDigest: next.RequestDigest,
				ProviderRequestID: attempt.ProviderRequestID, Attempt: attempt.Attempt, Negotiation: attempt.Negotiation,
			}
		default:
			return Transition{}, ErrInvalidTransition
		}

	case EventCancellationResolved:
		if next.State != StateCancellationPending {
			return Transition{}, ErrInvalidTransition
		}
		attempt, ok := next.CurrentAttempt()
		if !ok {
			return Transition{}, ErrInvalidTransition
		}
		switch event.Cancellation {
		case CancellationPrevented:
			if attempt.ProviderRequestID != "" || attempt.HadOutput {
				return Transition{}, ErrInvalidTransition
			}
			next.State = StateCancelled
			next.FailureReason = ""
		case CancellationAbsent:
			next.State = StateCancelled
			next.FailureReason = ""
		case CancellationCommitted:
			if err := gateway.applyCommittedRecord(&next, event.Ledger); err != nil {
				return Transition{}, err
			}
		case CancellationUnknown:
			next.Attempts[len(next.Attempts)-1].Failure = FailureUnknown
			next.FailureReason = "cancellation outcome is unknown"
			if next.ReplayPolicy == ReplayConfirm {
				next.State = StateNeedsConfirmation
			} else {
				next.State = StateUncertain
			}
		}

	case EventRecoveryObserved:
		switch next.State {
		case StateDispatching, StateDispatched, StateStreaming, StateCancellationPending, StateUncertain, StateNeedsConfirmation:
		case StateFailed:
			attempt, ok := next.CurrentAttempt()
			if !ok || attempt.Failure != FailureUnknown {
				return Transition{}, ErrInvalidTransition
			}
		default:
			return Transition{}, ErrInvalidTransition
		}
		if event.Ledger.InvocationID != next.Scope.InvocationID || event.Ledger.RequestDigest != next.RequestDigest {
			return Transition{}, ErrLedgerMismatch
		}
		switch event.Ledger.Status {
		case LedgerInflight:
			attempt, ok := next.CurrentAttempt()
			if !ok || event.Ledger.ProviderRequestID == "" ||
				(attempt.ProviderRequestID != "" && attempt.ProviderRequestID != event.Ledger.ProviderRequestID) {
				return Transition{}, ErrLedgerMismatch
			}
			next.Attempts[len(next.Attempts)-1].ProviderRequestID = event.Ledger.ProviderRequestID
			switch next.State {
			case StateDispatching, StateUncertain, StateNeedsConfirmation, StateFailed:
				if next.CancellationRequested {
					next.State = StateCancellationPending
				} else if attempt.HadOutput {
					next.State = StateStreaming
				} else {
					next.State = StateDispatched
				}
				next.Attempts[len(next.Attempts)-1].Failure = ""
				next.FailureReason = ""
			}
		case LedgerCommitted:
			if err := gateway.applyCommittedRecord(&next, event.Ledger); err != nil {
				return Transition{}, err
			}
		case LedgerFailed:
			attempt, ok := next.CurrentAttempt()
			if !ok || (event.Ledger.ProviderRequestID != "" && attempt.ProviderRequestID != "" &&
				attempt.ProviderRequestID != event.Ledger.ProviderRequestID) {
				return Transition{}, ErrLedgerMismatch
			}
			if attempt.ProviderRequestID == "" {
				next.Attempts[len(next.Attempts)-1].ProviderRequestID = event.Ledger.ProviderRequestID
			}
			next.Attempts[len(next.Attempts)-1].Failure = FailureExternalFailed
			next.State = StateFailed
			next.FailureReason = "external invocation failed"
		case LedgerAbsent:
			if err := gateway.applyFailure(&next, FailureLedgerAbsent, "external ledger has no invocation"); err != nil {
				return Transition{}, err
			}
		case LedgerUnknown:
			if err := gateway.applyFailure(&next, FailureUnknown, "external invocation outcome is unknown"); err != nil {
				return Transition{}, err
			}
		default:
			return Transition{}, ErrInvalidTransition
		}

	case EventConfirmationDecided:
		if next.State != StateNeedsConfirmation || next.ReplayPolicy != ReplayConfirm {
			return Transition{}, ErrInvalidTransition
		}
		switch event.Decision {
		case ConfirmationRetry:
			if next.ConfirmationRetriesUsed >= next.MaxConfirmationRetries {
				return Transition{}, ErrInvalidTransition
			}
			next.ConfirmationRetriesUsed++
			next.CancellationRequested = false
			next.State = StateRetryPending
			next.FailureReason = "explicit retry confirmed"
		case ConfirmationAbandon:
			if next.CancellationRequested {
				// Abandoning a retry is not evidence that the provider-side
				// invocation was absent. Preserve the unknown outcome so a late
				// committed result can still be merged and settled.
				next.State = StateUncertain
				next.FailureReason = confirmationAbandonUnknownReason
			} else {
				next.State = StateFailed
				next.FailureReason = "user declined uncertain replay"
			}
		}
	}

	projectedEvents := uint64(next.EventCount) + 1
	if projectedEvents+uint64(minimumRemainingEvents(next)) > uint64(gateway.bounds.MaxEvents) {
		return Transition{}, ErrEventLimit
	}
	next.EventCount++
	next.EventBytes += eventBytes
	next.Revision++
	transition.Effect = next
	return transition, nil
}

func (gateway *Gateway) applyFailure(effect *Effect, class FailureClass, reason string) error {
	attempt, hasAttempt := effect.CurrentAttempt()
	if !hasAttempt {
		return ErrInvalidTransition
	}
	switch class {
	case FailureDefinitelyNotSent:
		if effect.State != StateDispatching || attempt.ProviderRequestID != "" || attempt.HadOutput {
			return ErrInvalidTransition
		}
		effect.Attempts[len(effect.Attempts)-1].Failure = class
		effect.FailureReason = reason
		if effect.AutomaticRetriesUsed < effect.MaxAutomaticRetries {
			effect.AutomaticRetriesUsed++
			effect.State = StateRetryPending
		} else {
			effect.State = StateFailed
		}
		return nil

	case FailureRejected:
		if (effect.State != StateDispatching && effect.State != StateDispatched) || attempt.HadOutput {
			return ErrInvalidTransition
		}
		effect.Attempts[len(effect.Attempts)-1].Failure = class
		effect.FailureReason = reason
		effect.State = StateFailed
		return nil

	case FailureLedgerAbsent, FailureUnknown:
		wasFailedUnknown := effect.State == StateFailed && attempt.Failure == FailureUnknown
		switch effect.State {
		case StateDispatching, StateDispatched, StateStreaming, StateCancellationPending, StateUncertain, StateNeedsConfirmation, StateFailed:
		default:
			return ErrInvalidTransition
		}
		effect.Attempts[len(effect.Attempts)-1].Failure = class
		effect.FailureReason = reason
		if effect.CancellationRequested {
			if class == FailureLedgerAbsent {
				effect.State = StateCancelled
				effect.FailureReason = ""
			} else if effect.ReplayPolicy == ReplayConfirm {
				effect.State = StateNeedsConfirmation
			} else {
				effect.State = StateUncertain
			}
			return nil
		}
		if class == FailureLedgerAbsent && wasFailedUnknown {
			// A prior user-abandon or exhausted retry left the effect Failed
			// only because the external outcome was unknown. Authoritative
			// ledger absence makes that Failed classification definitive; it
			// must not reopen confirmation and strand the retained active slot.
			effect.State = StateFailed
			return nil
		}
		if class == FailureUnknown && attempt.HadOutput && !effect.SupportsInvocationLedger {
			// The caller may already have observed these bytes. Without a
			// durable invocation ledger there is no authoritative way to prove
			// that a replacement attempt will not duplicate the partial stream
			// or its side effect, even for an otherwise replay-safe tool.
			if effect.ReplayPolicy == ReplayConfirm {
				effect.State = StateNeedsConfirmation
			} else {
				effect.State = StateUncertain
			}
			return nil
		}
		switch effect.ReplayPolicy {
		case ReplaySafe, ReplayIdempotencyKey:
			if effect.ReplayPolicy == ReplayIdempotencyKey && !effect.SupportsIdempotencyKey {
				return ErrInvalidTransition
			}
			if effect.AutomaticRetriesUsed < effect.MaxAutomaticRetries {
				effect.AutomaticRetriesUsed++
				effect.State = StateRetryPending
			} else if class == FailureLedgerAbsent || effect.ReplayPolicy == ReplaySafe {
				effect.State = StateFailed
			} else {
				effect.State = StateUncertain
			}
		case ReplayNever:
			if class == FailureLedgerAbsent {
				effect.State = StateFailed
			} else {
				effect.State = StateUncertain
			}
		case ReplayConfirm:
			effect.State = StateNeedsConfirmation
		default:
			return ErrInvalidTransition
		}
		return nil
	default:
		return ErrInvalidTransition
	}
}

func (gateway *Gateway) applyCommittedRecord(effect *Effect, record LedgerRecord) error {
	if gateway.validateLedgerRecord(record, false) != nil || record.InvocationID != effect.Scope.InvocationID ||
		record.RequestDigest != effect.RequestDigest || record.Status != LedgerCommitted {
		return ErrLedgerMismatch
	}
	attempt, ok := effect.CurrentAttempt()
	if !ok {
		return ErrLedgerMismatch
	}
	if record.ProviderRequestID != "" {
		if attempt.ProviderRequestID != "" && attempt.ProviderRequestID != record.ProviderRequestID {
			return ErrLedgerMismatch
		}
		if attempt.ProviderRequestID == "" {
			effect.Attempts[len(effect.Attempts)-1].ProviderRequestID = record.ProviderRequestID
		}
	}
	effect.Output = append([]byte(nil), record.Output...)
	effect.ExternalCommitID = record.ExternalCommitID
	effect.FailureReason = ""
	effect.State = StateExternallyCommitted
	return nil
}

func (gateway *Gateway) validateEvent(effect Effect, event Event) (uint64, error) {
	noLedger := zeroLedgerRecord(event.Ledger)
	noBytes := len(event.Chunk) == 0 && len(event.Output) == 0
	noNegotiation := event.Negotiation == (StartNegotiationReceipt{})
	switch event.Kind {
	case EventBeginDispatch, EventSettlementCompleted, EventCancelRequested:
		if event.ProviderRequestID != "" || !noBytes || event.ExternalCommitID != "" || event.Failure != "" ||
			event.Reason != "" || event.Cancellation != "" || !noLedger || event.Decision != "" || !noNegotiation {
			return 0, ErrInvalidRequest
		}
		return 0, nil

	case EventNegotiationRecorded:
		attempt, ok := effect.CurrentAttempt()
		if !ok || event.ProviderRequestID != "" || !noBytes || event.ExternalCommitID != "" || event.Failure != "" ||
			event.Reason != "" || event.Cancellation != "" || !noLedger || event.Decision != "" || noNegotiation ||
			!validNegotiationReceiptForEffect(event.Negotiation, effect, attempt.Attempt) {
			return 0, ErrInvalidRequest
		}
		return negotiationEventBytes(event.Negotiation), nil

	case EventProviderAccepted:
		if !validBoundedText(event.ProviderRequestID, gateway.bounds.MaxProviderRequestIDBytes) || !noBytes ||
			event.ExternalCommitID != "" || event.Failure != "" || event.Reason != "" || event.Cancellation != "" || !noLedger || event.Decision != "" || !noNegotiation {
			return 0, ErrInvalidRequest
		}
		return uint64(len(event.ProviderRequestID)), nil

	case EventOutputChunk:
		if len(event.Chunk) == 0 || uint64(len(event.Chunk)) > gateway.bounds.MaxChunkBytes || len(event.Output) != 0 ||
			event.ProviderRequestID != "" || event.ExternalCommitID != "" || event.Failure != "" || event.Reason != "" ||
			event.Cancellation != "" || !noLedger || event.Decision != "" || !noNegotiation {
			if uint64(len(event.Chunk)) > gateway.bounds.MaxChunkBytes {
				return 0, ErrOutputLimit
			}
			return 0, ErrInvalidRequest
		}
		return uint64(len(event.Chunk)), nil

	case EventCallCommitted:
		if len(event.Output) == 0 || uint64(len(event.Output)) > gateway.bounds.MaxOutputBytes || len(event.Chunk) != 0 ||
			event.ProviderRequestID != "" || event.Failure != "" || event.Reason != "" || event.Cancellation != "" || !noLedger || event.Decision != "" ||
			!noNegotiation || (event.ExternalCommitID != "" && !validBoundedText(event.ExternalCommitID, gateway.bounds.MaxExternalCommitIDBytes)) {
			if uint64(len(event.Output)) > gateway.bounds.MaxOutputBytes {
				return 0, ErrOutputLimit
			}
			return 0, ErrInvalidRequest
		}
		return uint64(len(event.Output) + len(event.ExternalCommitID)), nil

	case EventDispatchFailed:
		switch event.Failure {
		case FailureDefinitelyNotSent, FailureRejected, FailureLedgerAbsent, FailureUnknown:
		default:
			return 0, ErrInvalidRequest
		}
		if !validBoundedText(event.Reason, gateway.bounds.MaxFailureBytes) || event.ProviderRequestID != "" || !noBytes ||
			event.ExternalCommitID != "" || event.Cancellation != "" || !noLedger || event.Decision != "" || !noNegotiation {
			return 0, ErrInvalidRequest
		}
		return uint64(len(event.Reason)), nil

	case EventCancellationResolved:
		switch event.Cancellation {
		case CancellationPrevented, CancellationAbsent, CancellationUnknown:
			if !noLedger {
				return 0, ErrInvalidRequest
			}
		case CancellationCommitted:
			if event.Ledger.Status != LedgerCommitted || gateway.validateLedgerRecord(event.Ledger, false) != nil {
				return 0, ErrInvalidRequest
			}
		default:
			return 0, ErrInvalidRequest
		}
		if event.ProviderRequestID != "" || !noBytes || event.ExternalCommitID != "" || event.Failure != "" || event.Reason != "" || event.Decision != "" || !noNegotiation {
			return 0, ErrInvalidRequest
		}
		bytes := ledgerEventBytes(event.Ledger)
		if event.Cancellation == CancellationUnknown {
			bytes += uint64(len("cancellation outcome is unknown"))
		}
		return bytes, nil

	case EventRecoveryObserved:
		if zeroLedgerRecord(event.Ledger) || event.ProviderRequestID != "" || !noBytes ||
			event.ExternalCommitID != "" || event.Failure != "" || event.Reason != "" || event.Cancellation != "" || event.Decision != "" || !noNegotiation {
			return 0, ErrInvalidRequest
		}
		if gateway.validateLedgerRecord(event.Ledger, true) != nil {
			return 0, ErrLedgerMismatch
		}
		bytes := ledgerEventBytes(event.Ledger)
		switch event.Ledger.Status {
		case LedgerFailed:
			bytes += uint64(len("external invocation failed"))
		case LedgerAbsent:
			bytes += uint64(len("external ledger has no invocation"))
		case LedgerUnknown:
			bytes += uint64(len("external invocation outcome is unknown"))
		}
		return bytes, nil

	case EventConfirmationDecided:
		if event.Decision != ConfirmationRetry && event.Decision != ConfirmationAbandon {
			return 0, ErrInvalidRequest
		}
		if event.ProviderRequestID != "" || !noBytes || event.ExternalCommitID != "" || event.Failure != "" ||
			event.Reason != "" || event.Cancellation != "" || !noLedger || !noNegotiation {
			return 0, ErrInvalidRequest
		}
		if event.Decision == ConfirmationRetry {
			return uint64(len("explicit retry confirmed")), nil
		}
		if effect.CancellationRequested {
			return uint64(len(confirmationAbandonUnknownReason)), nil
		}
		return uint64(len("user declined uncertain replay")), nil
	default:
		return 0, ErrInvalidRequest
	}
}

func (gateway *Gateway) validateEffect(effect Effect) error {
	if !validScope(effect.Scope) || effect.RequestDigest == (Digest{}) || effect.Revision == 0 ||
		effect.Revision != uint64(effect.EventCount)+1 || effect.EventCount > gateway.bounds.MaxEvents ||
		!validIdentifier(effect.ServerID, gateway.bounds.MaxServerIDBytes) ||
		!validIdentifier(effect.ToolName, gateway.bounds.MaxToolNameBytes) ||
		!validIdentifier(effect.ProviderID, gateway.bounds.MaxServerIDBytes) ||
		!validRegistryRef(effect.TargetRef, gateway.bounds.MaxTargetRefBytes) ||
		!validBoundedText(effect.ProtocolVersion, gateway.bounds.MaxProtocolVersionBytes) ||
		len(effect.InputCanonical) == 0 || uint64(len(effect.InputCanonical)) > gateway.bounds.MaxInputBytes ||
		effect.AutomaticRetriesUsed > effect.MaxAutomaticRetries || effect.ConfirmationRetriesUsed > effect.MaxConfirmationRetries ||
		effect.MaxAutomaticRetries > hardMaxRetries || effect.MaxConfirmationRetries > hardMaxRetries ||
		uint64(len(effect.Attempts)) > 1+uint64(effect.AutomaticRetriesUsed)+uint64(effect.ConfirmationRetriesUsed) ||
		effect.ChunkCount > gateway.bounds.MaxChunks || effect.StreamBytes > gateway.bounds.MaxOutputBytes ||
		effect.EventBytes > gateway.maximumEventBytes() ||
		uint64(len(effect.Output)) > gateway.bounds.MaxOutputBytes ||
		(effect.ExternalCommitID != "" && !validBoundedText(effect.ExternalCommitID, gateway.bounds.MaxExternalCommitIDBytes)) ||
		(effect.FailureReason != "" && !validBoundedText(effect.FailureReason, gateway.bounds.MaxFailureBytes)) {
		return ErrInvalidRequest
	}
	digest, err := digestCanonicalCall(effect.ServerID, effect.ToolName, effect.InputCanonical)
	if err != nil || digest != effect.RequestDigest {
		return fmt.Errorf("%w: restored canonical request digest mismatch", ErrInvalidRequest)
	}
	server, found := gateway.servers[serverKey{tenant: effect.Scope.TenantID, user: effect.Scope.UserID, server: effect.ServerID}]
	if !found {
		return ErrInvalidRequest
	}
	server, err = resolveServerRegistration(server, effect.Scope)
	if err != nil || server.ProviderID != effect.ProviderID || server.Transport != effect.Transport || server.TargetRef != effect.TargetRef ||
		server.ProtocolVersion != effect.ProtocolVersion || server.Affinity != effect.Affinity || server.Credential != effect.Credential {
		return ErrInvalidRequest
	}
	tool, found := gateway.tools[toolKey{serverKey: serverKey{tenant: effect.Scope.TenantID, user: effect.Scope.UserID, server: effect.ServerID}, tool: effect.ToolName}]
	if !found || tool.SideEffecting != effect.SideEffecting || tool.ReplayPolicy != effect.ReplayPolicy ||
		tool.MaxAutomaticRetries != effect.MaxAutomaticRetries || tool.MaxConfirmationRetries != effect.MaxConfirmationRetries {
		return ErrInvalidRequest
	}
	if effect.ReplayPolicy == ReplayIdempotencyKey && (!effect.SupportsIdempotencyKey || !effect.SupportsInvocationLedger) {
		return ErrInvalidRequest
	}
	var accounted uint64 = effect.StreamBytes + uint64(len(effect.Output)) + uint64(len(effect.ExternalCommitID)) + uint64(len(effect.FailureReason))
	for index, attempt := range effect.Attempts {
		if attempt.Attempt != uint32(index+1) || (attempt.ProviderRequestID != "" && !validBoundedText(attempt.ProviderRequestID, gateway.bounds.MaxProviderRequestIDBytes)) ||
			(attempt.HadOutput && attempt.ProviderRequestID == "") ||
			(attempt.Negotiation != (StartNegotiationReceipt{}) && !validNegotiationReceiptForEffect(attempt.Negotiation, effect, attempt.Attempt)) {
			return ErrInvalidRequest
		}
		switch attempt.Failure {
		case "", FailureDefinitelyNotSent, FailureRejected, FailureLedgerAbsent, FailureExternalFailed, FailureUnknown:
		default:
			return ErrInvalidRequest
		}
		if uint64(len(attempt.ProviderRequestID)) > math.MaxUint64-accounted {
			return ErrInvalidRequest
		}
		accounted += uint64(len(attempt.ProviderRequestID))
		negotiationBytes := negotiationEventBytes(attempt.Negotiation)
		if negotiationBytes > math.MaxUint64-accounted {
			return ErrInvalidRequest
		}
		accounted += negotiationBytes
	}
	if accounted > effect.EventBytes {
		return ErrInvalidRequest
	}
	attempt, hasAttempt := effect.CurrentAttempt()
	switch effect.State {
	case StateAdmitted:
		if len(effect.Attempts) != 0 || effect.EventCount != 0 || effect.ChunkCount != 0 || effect.StreamBytes != 0 ||
			len(effect.Output) != 0 || effect.ExternalCommitID != "" || effect.FailureReason != "" || effect.CancellationRequested {
			return ErrInvalidRequest
		}
	case StateDispatching:
		if !hasAttempt || attempt.ProviderRequestID != "" || attempt.HadOutput || attempt.Failure != "" || effect.FailureReason != "" || len(effect.Output) != 0 || effect.CancellationRequested {
			return ErrInvalidRequest
		}
	case StateDispatched:
		if !hasAttempt || attempt.ProviderRequestID == "" || attempt.HadOutput || attempt.Failure != "" ||
			attempt.Negotiation == (StartNegotiationReceipt{}) || len(effect.Output) != 0 || effect.CancellationRequested {
			return ErrInvalidRequest
		}
	case StateStreaming:
		if !hasAttempt || attempt.ProviderRequestID == "" || !attempt.HadOutput || attempt.Failure != "" ||
			attempt.Negotiation == (StartNegotiationReceipt{}) || effect.ChunkCount == 0 || effect.StreamBytes == 0 || len(effect.Output) != 0 || effect.CancellationRequested {
			return ErrInvalidRequest
		}
	case StateRetryPending:
		if !hasAttempt || attempt.Failure == "" || effect.FailureReason == "" || len(effect.Output) != 0 || effect.CancellationRequested {
			return ErrInvalidRequest
		}
	case StateCancellationPending:
		if !hasAttempt || len(effect.Output) != 0 || !effect.CancellationRequested {
			return ErrInvalidRequest
		}
	case StateExternallyCommitted, StateCompleted:
		if len(effect.Output) == 0 || effect.FailureReason != "" || !hasAttempt ||
			attempt.Negotiation == (StartNegotiationReceipt{}) || (attempt.ProviderRequestID == "" && effect.ExternalCommitID == "") {
			return ErrInvalidRequest
		}
	case StateNeedsConfirmation, StateFailed, StateUncertain:
		if effect.FailureReason == "" || len(effect.Output) != 0 {
			return ErrInvalidRequest
		}
	case StateCancelled:
		if len(effect.Output) != 0 || effect.ExternalCommitID != "" || effect.FailureReason != "" || !effect.CancellationRequested {
			return ErrInvalidRequest
		}
	default:
		return ErrInvalidRequest
	}
	return nil
}

func minimumRemainingEvents(effect Effect) uint32 {
	automatic := effect.MaxAutomaticRetries - effect.AutomaticRetriesUsed
	confirmation := effect.MaxConfirmationRetries - effect.ConfirmationRetriesUsed
	attempt, _ := effect.CurrentAttempt()
	hasProviderIdentity := attempt.ProviderRequestID != ""
	preNegotiation := attempt.Negotiation == (StartNegotiationReceipt{})
	confirmationBase := 3*automatic + 10*confirmation

	// Once cancellation was durably requested, reserve only the finite late
	// outcome envelope. Reserving another EventCancelRequested here creates a
	// recursive bound: CancellationUnknown would require more events than its
	// CancellationPending predecessor reserved.
	knownRequestedConfirmationEvents := uint32(3)
	if confirmation > 0 {
		knownRequestedConfirmationEvents = confirmationBase + 3
	}
	requestedConfirmationEvents := knownRequestedConfirmationEvents
	if !hasProviderIdentity {
		// Besides learning the provider identity and entering the known-ID
		// cancellation envelope, ConfirmationAbandon must retain the no-ID
		// uncertain late-owner envelope.
		requestedConfirmationEvents += 3
	}
	requestedUnknownEvents := uint32(2)
	if !hasProviderIdentity {
		if effect.ReplayPolicy == ReplayConfirm {
			requestedUnknownEvents = knownRequestedConfirmationEvents + 2
		} else {
			requestedUnknownEvents = 4
		}
	}
	pendingCancellationEvents := requestedUnknownEvents + 1
	if effect.ReplayPolicy == ReplayConfirm {
		pendingCancellationEvents = requestedConfirmationEvents + 1
	}
	explicitCancellationEvents := pendingCancellationEvents + 1

	dispatchedEvents := uint32(6)
	switch effect.ReplayPolicy {
	case ReplaySafe, ReplayIdempotencyKey:
		if automatic > 0 {
			dispatchedEvents = 4*automatic + 7
		}
	case ReplayConfirm:
		dispatchedEvents = knownRequestedConfirmationEvents + 4
	}
	lateUnrequestedEvents := uint32(2)
	if !hasProviderIdentity {
		lateUnrequestedEvents = dispatchedEvents + 1
	}
	if explicitCancellationEvents > lateUnrequestedEvents {
		lateUnrequestedEvents = explicitCancellationEvents
	}

	switch effect.State {
	case StateCompleted, StateCancelled:
		return 0
	case StateExternallyCommitted:
		return 1
	case StateFailed:
		if attempt.Failure != FailureUnknown {
			return 0
		}
		if effect.CancellationRequested {
			return requestedUnknownEvents
		}
		return lateUnrequestedEvents
	case StateUncertain:
		if effect.CancellationRequested {
			return requestedUnknownEvents
		}
		return lateUnrequestedEvents
	case StateCancellationPending:
		return pendingCancellationEvents
	case StateNeedsConfirmation:
		if effect.CancellationRequested {
			return requestedConfirmationEvents
		}
		remaining := lateUnrequestedEvents
		// The first authoritative absence classification remains in
		// NeedsConfirmation but makes a later abandon definitive. Unknown
		// classification still needs one event to enter unresolved Failed.
		if attempt.Failure != FailureLedgerAbsent {
			remaining++
		}
		if knownRequestedConfirmationEvents > remaining {
			return knownRequestedConfirmationEvents
		}
		return remaining
	case StateAdmitted, StateRetryPending:
		switch effect.ReplayPolicy {
		case ReplaySafe, ReplayIdempotencyKey:
			return 4*automatic + 10
		case ReplayNever:
			return 3*automatic + 10
		case ReplayConfirm:
			return confirmationBase + 12
		}
	case StateDispatching:
		phase := uint32(8)
		if preNegotiation {
			phase++
		}
		switch effect.ReplayPolicy {
		case ReplaySafe, ReplayIdempotencyKey:
			return 4*automatic + phase
		case ReplayNever:
			return 3*automatic + phase
		case ReplayConfirm:
			confirmPhase := uint32(10)
			if preNegotiation {
				confirmPhase++
			}
			return confirmationBase + confirmPhase
		}
	case StateDispatched, StateStreaming:
		return dispatchedEvents
	}
	return hardMaxEvents
}

func validNegotiationReceiptForEffect(receipt StartNegotiationReceipt, effect Effect, attempt uint32) bool {
	return receipt.Durable && receipt.ConnectionGeneration != 0 && receipt.ConnectionGeneration <= math.MaxInt64 && validScope(receipt.Scope) &&
		sameOperationScope(receipt.Scope, effect.Scope) && receipt.Server == serverForEffect(effect) &&
		receipt.InvocationID == effect.Scope.InvocationID && receipt.RequestDigest == effect.RequestDigest &&
		receipt.Attempt == attempt && receipt.NegotiatedProtocolVersion == effect.ProtocolVersion &&
		receipt.Affinity == effect.Affinity &&
		receipt.SupportsInvocationLedger == effect.SupportsInvocationLedger &&
		receipt.SupportsIdempotencyKey == effect.SupportsIdempotencyKey
}

func negotiationEventBytes(receipt StartNegotiationReceipt) uint64 {
	if receipt == (StartNegotiationReceipt{}) {
		return 0
	}
	return 256 + uint64(len(receipt.Server.ServerID)+len(receipt.Server.TargetRef)+
		len(receipt.Server.ProtocolVersion)+len(receipt.NegotiatedProtocolVersion)+
		len(receipt.Affinity.Backend)+len(receipt.Affinity.Scope)+len(receipt.Affinity.SecretExposureClass)+
		len(receipt.Affinity.SandboxProtocolVersion))
}

func (gateway *Gateway) maximumEventBytes() uint64 {
	perEvent := gateway.bounds.MaxOutputBytes + gateway.bounds.MaxProviderRequestIDBytes +
		gateway.bounds.MaxExternalCommitIDBytes + gateway.bounds.MaxFailureBytes +
		gateway.bounds.MaxTargetRefBytes + 2*gateway.bounds.MaxProtocolVersionBytes +
		6*gateway.bounds.MaxServerIDBytes + 256
	return uint64(gateway.bounds.MaxEvents) * perEvent
}

func ledgerEventBytes(record LedgerRecord) uint64 {
	return uint64(len(record.ProviderRequestID)) + uint64(len(record.ExternalCommitID)) + uint64(len(record.Output)) + uint64(len(record.FailureReason))
}

func (gateway *Gateway) validateLedgerRecord(record LedgerRecord, allowInflight bool) error {
	if record.InvocationID.Kind() != identity.Invocation || record.RequestDigest == (Digest{}) ||
		(record.ProviderRequestID != "" && !validBoundedText(record.ProviderRequestID, gateway.bounds.MaxProviderRequestIDBytes)) ||
		(record.ExternalCommitID != "" && !validBoundedText(record.ExternalCommitID, gateway.bounds.MaxExternalCommitIDBytes)) ||
		uint64(len(record.Output)) > gateway.bounds.MaxOutputBytes ||
		(record.FailureReason != "" && !validBoundedText(record.FailureReason, gateway.bounds.MaxFailureBytes)) {
		return ErrLedgerMismatch
	}
	switch record.Status {
	case LedgerAbsent, LedgerUnknown:
		if record.ProviderRequestID != "" || record.ExternalCommitID != "" || len(record.Output) != 0 || record.FailureReason != "" {
			return ErrLedgerMismatch
		}
	case LedgerInflight:
		if !allowInflight || record.ProviderRequestID == "" || record.ExternalCommitID != "" || len(record.Output) != 0 || record.FailureReason != "" {
			return ErrLedgerMismatch
		}
	case LedgerCommitted:
		if len(record.Output) == 0 || record.FailureReason != "" ||
			(record.ProviderRequestID == "" && record.ExternalCommitID == "") {
			return ErrLedgerMismatch
		}
	case LedgerFailed:
		if record.FailureReason == "" || record.ExternalCommitID != "" || len(record.Output) != 0 {
			return ErrLedgerMismatch
		}
	default:
		return ErrLedgerMismatch
	}
	return nil
}

func zeroLedgerRecord(record LedgerRecord) bool {
	return record.InvocationID == (identity.ID{}) && record.RequestDigest == (Digest{}) && record.Status == "" &&
		record.ProviderRequestID == "" && record.ExternalCommitID == "" && len(record.Output) == 0 && record.FailureReason == ""
}

func (event Event) String() string {
	return fmt.Sprintf("mcp-event<kind=%s revision=%d>", event.Kind, event.ExpectedRevision)
}
