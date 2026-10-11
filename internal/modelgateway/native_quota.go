package modelgateway

import (
	"context"
	"math"

	"github.com/hancomac/circulusd/internal/dependency"
	"github.com/hancomac/circulusd/internal/identity"
)

func nativeQuotaKey(tenant, user identity.ID) string { return tenant.String() + "/" + user.String() }

func quotaRequestScope(request QuotaRequest) ValidatedAuthority {
	return ValidatedAuthority{TenantID: request.TenantID, UserID: request.UserID, SessionID: request.SessionID, TurnID: request.TurnID,
		EffectID: request.EffectID, InvocationID: request.InvocationID, RuntimeRevision: request.RuntimeRevision, Generations: request.Generations}
}

func validNativeQuotaRequest(request QuotaRequest) bool {
	return validNativeScope(quotaRequestScope(request)) && request.RequestDigest != (Digest{}) && request.OutputTokens != 0 &&
		request.OutputTokens <= math.MaxUint64-request.ContextTokens
}

func (factory *NativeFactory) quotaLimit(tenant, user identity.ID) uint64 {
	for _, limit := range factory.quotaLimits {
		if limit.TenantID == tenant && limit.UserID == user {
			return limit.MaximumTokens
		}
	}
	return 0
}

func nativeQuotaPermit(request QuotaRequest) QuotaPermit {
	// The exact invocation is the immutable reservation identity. Native state
	// rejects its reuse with any different complete authority or token budget.
	return QuotaPermit{ReservationID: request.InvocationID.String(), Durable: true,
		TenantID: request.TenantID, UserID: request.UserID, EffectID: request.EffectID, InvocationID: request.InvocationID,
		SessionID: request.SessionID, TurnID: request.TurnID, RuntimeRevision: request.RuntimeRevision, Generations: request.Generations,
		RequestDigest: request.RequestDigest, ContextTokens: request.ContextTokens, OutputTokens: request.OutputTokens}
}

type nativeQuota struct{ factory *NativeFactory }

func nativeReservationCharge(state *nativeModelState, reservation nativeQuotaReservation) uint64 {
	if projection, found := state.Projections[reservation.Request.InvocationID.String()]; found {
		switch projection.Receipt.Disposition {
		case QuotaDispositionRelease:
			return 0
		case QuotaDispositionConsume:
			return projection.Receipt.Usage.InputTokens + projection.Receipt.Usage.OutputTokens
		}
	}
	return reservation.Request.ContextTokens + reservation.Request.OutputTokens
}

func (quota *nativeQuota) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	return quota.factory.probe(ctx, challenge)
}

func (quota *nativeQuota) Durability() QuotaDurability {
	if quota == nil || quota.factory == nil || quota.factory.check() != nil {
		return QuotaDurability{}
	}
	// Reservation and Session accounting projections are crash durable, but
	// separate Session/quota objects do not provide an atomic settlement.
	return QuotaDurability{CrashDurable: true}
}

func (quota *nativeQuota) Admit(ctx context.Context, request QuotaRequest) (QuotaPermit, error) {
	if quota == nil || quota.factory == nil || !validNativeQuotaRequest(request) {
		return QuotaPermit{}, ErrInvalidRequest
	}
	return nativeModelOperation(ctx, quota.factory, func(state *nativeModelState) (QuotaPermit, error) {
		previous, found := state.Reservations[request.InvocationID.String()]
		if found && previous.Request != request {
			return QuotaPermit{}, ErrQuotaConflict
		}
		if !quota.factory.currentGrant(state, quotaRequestScope(request), request.RequestDigest, "model.dispatch", true) {
			return QuotaPermit{}, ErrStaleAuthority
		}
		if found {
			return previous.Permit, nil
		}
		limit := quota.factory.quotaLimit(request.TenantID, request.UserID)
		if limit == 0 {
			return QuotaPermit{}, ErrQuotaExceeded
		}
		var reserved uint64
		for _, reservation := range state.Reservations {
			if reservation.Request.TenantID != request.TenantID || reservation.Request.UserID != request.UserID {
				continue
			}
			amount := nativeReservationCharge(state, reservation)
			if amount > limit || reserved > limit-amount {
				return QuotaPermit{}, ErrQuotaExceeded
			}
			reserved += amount
		}
		amount := request.ContextTokens + request.OutputTokens
		if amount > limit || reserved > limit-amount {
			return QuotaPermit{}, ErrQuotaExceeded
		}
		permit := nativeQuotaPermit(request)
		state.Reservations[request.InvocationID.String()] = nativeQuotaReservation{request, permit}
		return permit, nil
	})
}

// InspectReservation returns exact persisted admission facts after a fresh
// native barrier. It never validates current authority or allows settlement.
func (factory *NativeFactory) InspectReservation(ctx context.Context, request QuotaRequest) (QuotaPermit, bool, error) {
	if !validNativeQuotaRequest(request) {
		return QuotaPermit{}, false, ErrInvalidRequest
	}
	type inspection struct {
		Permit QuotaPermit
		Found  bool
	}
	result, err := nativeModelOperation(ctx, factory, func(state *nativeModelState) (inspection, error) {
		reservation, found := state.Reservations[request.InvocationID.String()]
		if !found {
			return inspection{}, nil
		}
		if reservation.Request != request {
			return inspection{}, ErrQuotaConflict
		}
		return inspection{reservation.Permit, true}, nil
	})
	return result.Permit, result.Found, err
}

// Exported SettlementPermit fields are data, not an unforgeable Session
// receipt. Even with the authenticated bridge, no caller-supplied permit
// can release, consume, refresh or replay a quota settlement.
func (*nativeQuota) Settle(context.Context, QuotaSettlementRequest) (QuotaSettlementReceipt, error) {
	return QuotaSettlementReceipt{}, ErrSettlementNotReady
}
