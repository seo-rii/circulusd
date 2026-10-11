package publicsession

import (
	"context"
	"errors"

	"github.com/hancomac/circulusd/internal/identity"
)

const (
	maximumConfiguredBytes = 64 << 20
	maximumMessages        = 256
	maximumSharedInteger   = uint64(9_007_199_254_740_991)
)

// ValidateAuthorizationPermit checks that a fresh permit binds the exact request.
func ValidateAuthorizationPermit(permit AuthorizationPermit, request AuthorizationRequest) error {
	if permit.Operation != request.Operation || permit.Principal != request.Principal ||
		permit.SessionID != request.SessionID || permit.AuthorizationGeneration == 0 ||
		permit.AuthorizationGeneration > maximumSharedInteger || permit.Proof == (OpaqueAuthorizationProof{}) {
		return ErrAccessDenied
	}
	return nil
}

// RepositoryError preserves public sentinels and cancellation without leaking
// arbitrary dependency errors.
func RepositoryError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	for _, known := range []error{
		ErrAccessDenied, ErrSessionNotFound, ErrTurnNotFound, ErrIdempotencyConflict,
		ErrSequenceConflict, ErrInvalidCursor, ErrStaleAuthority, ErrInvalidTransition,
	} {
		if errors.Is(err, known) {
			return known
		}
	}
	return ErrRepositoryFailure
}

// ValidatePrincipal requires correctly typed tenant and subject identifiers.
func ValidatePrincipal(principal Principal) error {
	if _, err := identity.Parse(identity.Tenant, principal.TenantID); err != nil {
		return ErrInvalidRequest
	}
	if _, err := identity.Parse(identity.Subject, principal.SubjectID); err != nil {
		return ErrInvalidRequest
	}
	return nil
}
