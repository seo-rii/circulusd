package modelgateway

import (
	"context"
	"crypto/sha256"
	"fmt"
	"reflect"
	"slices"
	"time"

	"github.com/hancomac/circulusd/internal/dependency"
	"github.com/hancomac/circulusd/internal/identity"
)

// NativeAuthorityGrant retains a hash of an operator-provisioned bearer, never
// its bytes. TTL gates admission; cleanup follows the current persisted fence
// and exact admitted reservation instead of the admission deadline.
type NativeAuthorityGrant struct {
	BearerDigest      Digest
	Scope             ValidatedAuthority
	RequestDigest     Digest
	ExpiresAtUnixNano int64
	Permissions       []string
}

func (NativeAuthorityGrant) String() string   { return "native-model-authority-grant<redacted>" }
func (NativeAuthorityGrant) GoString() string { return "native-model-authority-grant<redacted>" }

func NativeBearerDigest(authority OpaqueAuthority) (Digest, error) {
	if len(authority) == 0 || len(authority) > hardMaxAuthorityBytes {
		return Digest{}, ErrInvalidRequest
	}
	return sha256.Sum256(authority), nil
}

func nativeDigestKey(digest Digest) string { return fmt.Sprintf("%x", digest[:]) }
func nativeFenceKey(scope ValidatedAuthority) string {
	return scope.TenantID.String() + "/" + scope.UserID.String() + "/" + scope.SessionID.String() + "/" + scope.TurnID.String()
}

func validNativeScope(scope ValidatedAuthority) bool {
	return scope.TenantID.Kind() == identity.Tenant && scope.UserID.Kind() == identity.Subject &&
		scope.SessionID.Kind() == identity.Session && scope.TurnID.Kind() == identity.Turn &&
		scope.EffectID.Kind() == identity.Effect && scope.InvocationID.Kind() == identity.Invocation &&
		scope.RuntimeRevision.Kind() == identity.RuntimeRevision && scope.Generations.TurnLease != 0 &&
		scope.Generations.Placement != 0 && scope.Generations.Policy != 0
}

func sameNativeFence(left, right ValidatedAuthority) bool {
	return nativeFenceKey(left) == nativeFenceKey(right) && left.RuntimeRevision == right.RuntimeRevision && left.Generations == right.Generations
}

func validNativeGrant(grant NativeAuthorityGrant) bool {
	if grant.BearerDigest == (Digest{}) || !validNativeScope(grant.Scope) || grant.RequestDigest == (Digest{}) ||
		grant.ExpiresAtUnixNano <= 0 || len(grant.Permissions) == 0 || len(grant.Permissions) > 5 || !slices.IsSorted(grant.Permissions) {
		return false
	}
	for i, permission := range grant.Permissions {
		if i != 0 && permission == grant.Permissions[i-1] {
			return false
		}
		switch permission {
		case "model.dispatch", "model.cancel", "model.resume", "model.resolve-uncertain.consume", "model.resolve-uncertain.release":
		default:
			return false
		}
	}
	return true
}

// SetCurrentAuthority and ProvisionGrant are trusted provisioning operations;
// neither is exposed through Gateway. Fence changes cannot roll back any
// generation. Grant provisioning cannot implicitly replace an existing fence.
func (factory *NativeFactory) SetCurrentAuthority(ctx context.Context, scope ValidatedAuthority) error {
	if !validNativeScope(scope) {
		return ErrInvalidRequest
	}
	_, err := nativeModelOperation(ctx, factory, func(state *nativeModelState) (struct{}, error) {
		key := nativeFenceKey(scope)
		if current, found := state.Fences[key]; found && !sameNativeFence(current, scope) {
			old, next := current.Generations, scope.Generations
			if next.TurnLease < old.TurnLease || next.Placement < old.Placement || next.Policy < old.Policy || next == old {
				return struct{}{}, ErrStaleAuthority
			}
		}
		state.Fences[key] = scope
		return struct{}{}, nil
	})
	return err
}

func (factory *NativeFactory) ProvisionGrant(ctx context.Context, grant NativeAuthorityGrant) error {
	if !validNativeGrant(grant) {
		return ErrInvalidRequest
	}
	grant.Permissions = slices.Clone(grant.Permissions)
	_, err := nativeModelOperation(ctx, factory, func(state *nativeModelState) (struct{}, error) {
		key := nativeDigestKey(grant.BearerDigest)
		if previous, found := state.Grants[key]; found {
			if !reflect.DeepEqual(previous, grant) {
				return struct{}{}, ErrAuthorityMismatch
			}
			// Exact provisioning replay never extends TTL or rolls back fencing.
			return struct{}{}, nil
		}
		now := factory.now()
		expires := time.Unix(0, grant.ExpiresAtUnixNano)
		if !expires.After(now) || expires.After(now.Add(24*time.Hour)) {
			return struct{}{}, ErrStaleAuthority
		}
		fence, found := state.Fences[nativeFenceKey(grant.Scope)]
		if found && !sameNativeFence(fence, grant.Scope) {
			return struct{}{}, ErrStaleAuthority
		}
		state.Fences[nativeFenceKey(grant.Scope)] = grant.Scope
		state.Grants[key] = grant
		return struct{}{}, nil
	})
	return err
}

func (factory *NativeFactory) currentGrant(state *nativeModelState, scope ValidatedAuthority, digest Digest, permission string, admission bool) bool {
	if !sameNativeFence(state.Fences[nativeFenceKey(scope)], scope) {
		return false
	}
	for _, grant := range state.Grants {
		if grant.Scope == scope && grant.RequestDigest == digest && slices.Contains(grant.Permissions, permission) &&
			(!admission || factory.now().UnixNano() < grant.ExpiresAtUnixNano) {
			return true
		}
	}
	return false
}

type nativeAuthority struct{ factory *NativeFactory }

func (authority *nativeAuthority) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	return authority.factory.probe(ctx, challenge)
}
func (authority *nativeAuthority) Durability() AuthorityDurability {
	if authority == nil || authority.factory == nil || authority.factory.check() != nil {
		return AuthorityDurability{}
	}
	return AuthorityDurability{CrashDurable: true, CurrentGenerationFencing: true}
}

func (authority *nativeAuthority) ValidateAdmission(ctx context.Context, bearer OpaqueAuthority, request AdmissionAuthorityRequest) (ValidatedAuthority, error) {
	if authority == nil || authority.factory == nil || len(bearer) == 0 || uint64(len(bearer)) > authority.factory.configuration.Bounds.MaxAuthorityBytes ||
		request.EffectID.Kind() != identity.Effect || request.InvocationID.Kind() != identity.Invocation || request.RequestDigest == (Digest{}) {
		return ValidatedAuthority{}, ErrInvalidRequest
	}
	digest, err := NativeBearerDigest(bearer)
	if err != nil {
		return ValidatedAuthority{}, err
	}
	return nativeModelOperation(ctx, authority.factory, func(state *nativeModelState) (ValidatedAuthority, error) {
		grant, found := state.Grants[nativeDigestKey(digest)]
		if !found || grant.Scope.EffectID != request.EffectID || grant.Scope.InvocationID != request.InvocationID ||
			grant.RequestDigest != request.RequestDigest || !slices.Contains(grant.Permissions, request.Permission) ||
			!sameNativeFence(state.Fences[nativeFenceKey(grant.Scope)], grant.Scope) || authority.factory.now().UnixNano() >= grant.ExpiresAtUnixNano {
			return ValidatedAuthority{}, ErrStaleAuthority
		}
		return grant.Scope, nil
	})
}

func (authority *nativeAuthority) ValidateSettlement(ctx context.Context, bearer OpaqueAuthority, request SettlementAuthorityRequest) (ValidatedAuthority, error) {
	if authority == nil || authority.factory == nil || len(bearer) == 0 || uint64(len(bearer)) > authority.factory.configuration.Bounds.MaxAuthorityBytes || request.TerminalDigest == (Digest{}) || request.EffectRevision == 0 {
		return ValidatedAuthority{}, ErrInvalidRequest
	}
	digest, err := NativeBearerDigest(bearer)
	if err != nil {
		return ValidatedAuthority{}, err
	}
	origin := ValidatedAuthority{TenantID: request.TenantID, UserID: request.UserID, SessionID: request.SessionID, TurnID: request.TurnID,
		EffectID: request.EffectID, InvocationID: request.InvocationID, RuntimeRevision: request.RuntimeRevision, Generations: request.Generations}
	if !validNativeScope(origin) || request.RequestDigest == (Digest{}) || (request.Attempt == 0 && request.State != StateCancelled) {
		return ValidatedAuthority{}, ErrInvalidRequest
	}
	switch request.State {
	case StateCompleted:
		if request.Outcome != OutcomeCompleted {
			return ValidatedAuthority{}, ErrInvalidRequest
		}
	case StateFailed:
		if request.Outcome != OutcomeFailed {
			return ValidatedAuthority{}, ErrInvalidRequest
		}
	case StateCancelled:
		if request.Outcome != OutcomeCancelled {
			return ValidatedAuthority{}, ErrInvalidRequest
		}
	case StateUncertain:
		if request.Outcome != OutcomeUncertain {
			return ValidatedAuthority{}, ErrInvalidRequest
		}
	default:
		return ValidatedAuthority{}, ErrSettlementNotReady
	}
	return nativeModelOperation(ctx, authority.factory, func(state *nativeModelState) (ValidatedAuthority, error) {
		grant, found := state.Grants[nativeDigestKey(digest)]
		reservation, reserved := state.Reservations[origin.InvocationID.String()]
		if !found || !reserved || !sameAuthorityIdentity(grant.Scope, origin) || grant.RequestDigest != request.RequestDigest ||
			!slices.Contains(grant.Permissions, "model.dispatch") || !sameNativeFence(state.Fences[nativeFenceKey(grant.Scope)], grant.Scope) ||
			quotaRequestScope(reservation.Request) != origin || reservation.Request.RequestDigest != request.RequestDigest {
			return ValidatedAuthority{}, ErrStaleAuthority
		}
		// This validates current scope only. It neither attests the caller's
		// terminal body nor mints a settlement/start/retry authority.
		return grant.Scope, nil
	})
}
