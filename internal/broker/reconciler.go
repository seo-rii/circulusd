package broker

import (
	"context"
	"fmt"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/identity"
)

// EffectReconcileRequest carries the subordinate terminal observation needed
// to finish, or exactly replay, Session settlement after recovery. Recovery
// remains the sole source of the authoritative effect decision.
type EffectReconcileRequest struct {
	Recovery RecoveryRequest

	DispatchAttempt        uint64
	ExternalCommitID       identity.ID
	ResultRef              identity.ID
	TerminalError          *v1.PublicError
	SettlementOperationKey string
	SettlementDigest       Digest
}

// EffectReconciler joins an existing recovery decision to its settlement-only
// Session transition. It owns no provider and cannot start or retry one.
type EffectReconciler struct {
	coordinator *Coordinator
}

func NewEffectReconciler(coordinator *Coordinator) (*EffectReconciler, error) {
	if coordinator == nil {
		return nil, fmt.Errorf("%w: coordinator is required", ErrInvalidRequest)
	}
	return &EffectReconciler{coordinator: coordinator}, nil
}

// Reconcile asks the Coordinator for one recovery decision. A settle-only
// decision must exactly match the subordinate terminal observation before it
// can be settled. RecoveryNone is allowed through SettleEffect only to recover
// the original durable receipt for an exact replay.
func (reconciler *EffectReconciler) Reconcile(ctx context.Context, request EffectReconcileRequest) (RecoveryDecision, error) {
	if ctx == nil {
		return RecoveryDecision{}, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return RecoveryDecision{}, err
	}
	if reconciler == nil || reconciler.coordinator == nil ||
		request.DispatchAttempt == 0 ||
		request.ExternalCommitID.Kind() != identity.Commit ||
		request.ResultRef != (identity.ID{}) && request.ResultRef.Kind() != identity.Artifact ||
		(request.ResultRef == (identity.ID{})) == (request.TerminalError == nil) ||
		request.SettlementOperationKey == "" || request.SettlementDigest == (Digest{}) {
		return RecoveryDecision{}, ErrInvalidRequest
	}

	decision, err := reconciler.coordinator.RecoverEffect(ctx, request.Recovery)
	if err != nil {
		return RecoveryDecision{}, err
	}
	switch decision.Action {
	case RecoverySettleOnly:
		if decision.DispatchAttempt != request.DispatchAttempt ||
			decision.ExternalCommitID != request.ExternalCommitID ||
			decision.ResultRef != request.ResultRef {
			return RecoveryDecision{}, fmt.Errorf("%w: terminal observation differs from recovery decision", ErrLedgerMismatch)
		}
	case RecoveryNone:
		// SettleEffect's operation lookup returns the original durable receipt.
		// A missing or conflicting settlement remains fail-closed.
	case RecoverySettleFailed:
		return decision, nil
	default:
		return decision, nil
	}

	receipt, err := reconciler.coordinator.SettleEffect(ctx, SettlementRequest{
		Authority:        request.Recovery.Authority,
		Now:              request.Recovery.Now,
		EffectID:         request.Recovery.EffectID,
		InvocationID:     request.Recovery.InvocationID,
		RequestDigest:    request.Recovery.RequestDigest,
		DispatchAttempt:  request.DispatchAttempt,
		ExternalCommitID: request.ExternalCommitID,
		ResultRef:        request.ResultRef,
		Error:            request.TerminalError,
		OperationKey:     request.SettlementOperationKey,
		SettlementDigest: request.SettlementDigest,
	})
	if err != nil {
		return RecoveryDecision{}, fmt.Errorf("settle recovered effect: %w", err)
	}
	decision.SettlementReceipt = &receipt
	return decision, nil
}
