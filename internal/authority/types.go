// Package authority implements broker-side, snapshot-backed TurnAuthority
// validation without duplicating Session DO state.
package authority

import (
	"context"
	"errors"
	"time"
)

var (
	ErrInvalidConfig           = errors.New("invalid authority validator config")
	ErrInvalidRequest          = errors.New("invalid authority request")
	ErrInvalidSnapshot         = errors.New("invalid authoritative snapshot")
	ErrSnapshotUnavailable     = errors.New("authoritative snapshot unavailable")
	ErrInvalidAuthority        = errors.New("invalid turn authority")
	ErrServiceBindingMismatch  = errors.New("turn authority service binding mismatch")
	ErrScopeMismatch           = errors.New("turn authority scope mismatch")
	ErrPermissionDenied        = errors.New("turn authority permission denied")
	ErrAuthorityExpired        = errors.New("turn authority admission deadline expired")
	ErrInactiveSession         = errors.New("session is not active")
	ErrInactiveTurn            = errors.New("turn is not active")
	ErrLeaseInvalid            = errors.New("turn lease is invalid")
	ErrStaleTurnLease          = errors.New("turn lease generation is stale")
	ErrStalePlacement          = errors.New("placement generation is stale")
	ErrStaleAuthorization      = errors.New("authorization generation is stale")
	ErrRuntimeChanged          = errors.New("runtime revision changed")
	ErrPolicySnapshotChanged   = errors.New("immutable policy snapshot changed")
	ErrEmergencyOverlayChanged = errors.New("emergency policy overlay changed")
	ErrEffectMismatch          = errors.New("settlement effect identity mismatch")
	ErrEffectNotDispatched     = errors.New("effect is not dispatched for settlement")
)

// ServiceBinding identifies one stable broker RPC binding. An authority is
// signed for exactly one binding.
type ServiceBinding string

const (
	BindingState     ServiceBinding = "state"
	BindingWorkspace ServiceBinding = "workspace"
	BindingModel     ServiceBinding = "model"
	BindingMCP       ServiceBinding = "mcp"
	BindingExecutor  ServiceBinding = "executor"
	BindingArtifacts ServiceBinding = "artifacts"
	BindingEvents    ServiceBinding = "events"
)

// Permission is an effective-policy operation name.
type Permission string

// Scope is supplied to broker operations only as a comparison target. The
// authoritative values captured by a handle always originate in Snapshot.
type Scope struct {
	TenantID        string
	UserID          string
	SessionID       string
	TurnID          string
	RuntimeRevision string
	WorkspaceID     string
}

type SessionStatus string

const (
	SessionActive SessionStatus = "active"
	SessionClosed SessionStatus = "closed"
)

type TurnStatus string

const (
	TurnActive    TurnStatus = "active"
	TurnSettling  TurnStatus = "settling"
	TurnAborting  TurnStatus = "aborting"
	TurnCompleted TurnStatus = "completed"
)

type EffectStatus string

const (
	EffectDispatched          EffectStatus = "dispatched"
	EffectExternallyCommitted EffectStatus = "externally_committed"
)

// EffectSnapshot is the Session DO's current durable effect identity.
type EffectSnapshot struct {
	EffectID     string
	InvocationID string
	Status       EffectStatus
}

// Snapshot is one authoritative, internally consistent Session DO view.
// EffectivePermissions is already the intersection of the immutable policy
// snapshot and the live emergency overlay.
type Snapshot struct {
	Scope Scope

	SessionStatus SessionStatus
	TurnStatus    TurnStatus

	LeaseActive    bool
	LeaseExpiresAt time.Time

	TurnLeaseGeneration     uint64
	PlacementGeneration     uint64
	AuthorizationGeneration uint64

	PolicySnapshotDigest   string
	EmergencyOverlayDigest string
	EffectivePermissions   []Permission

	ActiveEffect *EffectSnapshot
}

// SnapshotReader must return a fresh authoritative view on every call. The
// session ID is a lookup key captured from a verified handle, not authority.
type SnapshotReader interface {
	ReadSnapshot(context.Context, string) (Snapshot, error)
}

type Config struct {
	SnapshotReader SnapshotReader
	HMACSecret     []byte
	AuthorityTTL   time.Duration
	Now            func() time.Time
}

type IssueRequest struct {
	Scope       Scope
	Permissions []Permission
}

type AdmissionRequest struct {
	Scope      Scope
	Permission Permission
}

type SettlementRequest struct {
	Scope        Scope
	Permission   Permission
	EffectID     string
	InvocationID string
}

type authorityPurpose uint8

const (
	purposeAdmission authorityPurpose = iota + 1
	purposeSettlement
)

type authorityClaims struct {
	purpose     authorityPurpose
	binding     ServiceBinding
	scope       Scope
	permissions []Permission

	turnLeaseGeneration     uint64
	placementGeneration     uint64
	authorizationGeneration uint64
	policySnapshotDigest    string
	emergencyOverlayDigest  string

	issuedAtUnixNano  int64
	expiresAtUnixNano int64
	effectID          string
	invocationID      string
}

type signedAuthority struct {
	claims authorityClaims
	mac    [32]byte
}

// TurnAuthority is an opaque admission/renewal capability. Its private claims
// are intentionally unavailable to broker clients.
type TurnAuthority struct {
	signed signedAuthority
}

func (TurnAuthority) String() string {
	return "turn-authority<redacted>"
}

func (TurnAuthority) GoString() string {
	return "turn-authority<redacted>"
}

// SettlementAuthority is an ADR-008 recovery capability bound to one already
// dispatched effect. Its distinct type cannot be used for admission.
type SettlementAuthority struct {
	signed signedAuthority
}

func (SettlementAuthority) String() string {
	return "settlement-authority<redacted>"
}

func (SettlementAuthority) GoString() string {
	return "settlement-authority<redacted>"
}

func (SettlementAuthority) isSettlementCredential() {}

// SettlementCredential is sealed to the exact-effect authority type above.
type SettlementCredential interface {
	isSettlementCredential()
}
