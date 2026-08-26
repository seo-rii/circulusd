// Package tenant implements tenant membership, workspace ACL, and quota
// admission. Resource identifiers are never treated as capabilities: every
// decision is evaluated against the resource's tenant and workspace scope.
package tenant

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/hancomac/circulusd/internal/identity"
)

var (
	ErrInvalidConfiguration = errors.New("tenant: invalid configuration")
	ErrInvalidRequest       = errors.New("tenant: invalid request")
	ErrAccessDenied         = errors.New("tenant: access denied")
	ErrQuotaExceeded        = errors.New("tenant: quota exceeded")
	ErrVersionConflict      = errors.New("tenant: expected version conflict")
	ErrVersionExhausted     = errors.New("tenant: version exhausted")
	ErrOperationConflict    = errors.New("tenant: operation ID reused with another request")
	ErrReceiptNotFound      = errors.New("tenant: operation receipt not found")
	ErrReservationNotFound  = errors.New("tenant: reservation not found")
	ErrReservationState     = errors.New("tenant: invalid reservation state")
	ErrInvalidPolicy        = errors.New("tenant: invalid policy")
	ErrPolicyConflict       = errors.New("tenant: policy intersection is empty")
	ErrPolicyRelaxation     = errors.New("tenant: policy update would relax a limit")
	ErrPolicyViolation      = errors.New("tenant: requested resource profile violates policy")
	ErrTeardownUnproven     = errors.New("tenant: durable resource teardown is not proven")
	ErrRepositoryNotDurable = errors.New("tenant: repository does not satisfy the durability contract")
)

// MaximumAmount keeps quota arithmetic within the signed 64-bit range used by
// durable SQL and protobuf providers. Values outside this range fail closed.
const MaximumAmount = uint64(math.MaxInt64)

type Role string

const (
	RolePlatformAdmin   Role = "platform-admin"
	RoleTenantAdmin     Role = "tenant-admin"
	RoleWorkspaceOwner  Role = "workspace-owner"
	RoleWorkspaceMember Role = "workspace-member"
	RoleUser            Role = "user"
)

type Action string

const (
	ActionTenantRead      Action = "tenant.read"
	ActionTenantManage    Action = "tenant.manage"
	ActionWorkspaceRead   Action = "workspace.read"
	ActionWorkspaceWrite  Action = "workspace.write"
	ActionWorkspaceManage Action = "workspace.manage"
	ActionSessionCreate   Action = "session.create"
	ActionBlobStore       Action = "blob.store"
	ActionArtifactCreate  Action = "artifact.create"
	ActionSandboxStart    Action = "sandbox.start"
	ActionModelUse        Action = "model.use"
)

type Principal struct {
	SubjectID identity.ID
}

// Resource carries the authoritative tenant/workspace scope obtained from a
// resource lookup. WorkspaceID must be absent for tenant-level actions.
type Resource struct {
	TenantID    identity.ID
	WorkspaceID identity.ID
}

type AuthorizationRequest struct {
	Principal Principal
	Resource  Resource
	Action    Action
}

type AuthorizationDecision struct {
	Role    Role
	Version uint64
}

// Quota separates independently enforceable tenant budget dimensions. Cost is
// represented in integer micro-units; floating-point values are never admitted.
type Quota struct {
	Sessions        uint64
	WorkspaceBytes  uint64
	BlobBytes       uint64
	ArtifactBytes   uint64
	ActiveSandboxes uint64
	ModelTokens     uint64
	ModelCostMicros uint64
}

type ResourceProfile struct {
	CPUUnits    uint64
	MemoryBytes uint64
}

// ResourceInstance is the exact lifecycle identity charged to a reservation.
// ID is an opaque canonical identifier supplied by the owning subsystem;
// Generation fences deletion receipts from an older incarnation of the same
// logical resource.
type ResourceInstance struct {
	ID         string
	Generation uint64
}

// Policy is already-resolved trusted policy. IntersectPolicies combines
// independent inputs without allowing a later input to weaken an earlier one.
type Policy struct {
	Limits         Quota
	MinimumProfile ResourceProfile
	MaximumProfile ResourceProfile
}

type Membership struct {
	SubjectID identity.ID
	Role      Role
}

type WorkspaceGrant struct {
	SubjectID identity.ID
	Role      Role
}

type WorkspaceACL struct {
	WorkspaceID identity.ID
	Grants      []WorkspaceGrant
}

type TenantConfiguration struct {
	TenantID   identity.ID
	Members    []Membership
	Workspaces []WorkspaceACL
	Policy     Policy
}

type Configuration struct {
	PlatformAdmins []identity.ID
	Tenants        []TenantConfiguration
}

type ReserveRequest struct {
	OperationID      identity.ID
	ExpectedVersion  uint64
	Principal        Principal
	Resource         Resource
	Action           Action
	Amount           Quota
	RequestedProfile ResourceProfile
	Instance         ResourceInstance
}

type TransitionRequest struct {
	OperationID     identity.ID
	ExpectedVersion uint64
	ReservationID   identity.ID
	Principal       Principal
	Resource        Resource
	Action          Action

	// releaseBinding and teardownPermit are deliberately private. Only Service
	// can attach the result of a trusted lifecycle verification, so callers
	// cannot manufacture permission to refund a live resource.
	releaseBinding *releaseBinding
	teardownPermit *teardownPermit
}

type RecoveryRequest struct {
	OperationID identity.ID
	Principal   Principal
	Resource    Resource
	Action      Action
}

type TightenPolicyRequest struct {
	OperationID     identity.ID
	ExpectedVersion uint64
	Principal       Principal
	TenantID        identity.ID
	Policy          Policy
}

type SnapshotRequest struct {
	Principal Principal
	TenantID  identity.ID
}

type OperationKind string

const (
	OperationReserve       OperationKind = "reserve"
	OperationConsume       OperationKind = "consume"
	OperationRelease       OperationKind = "release"
	OperationPolicyTighten OperationKind = "policy-tighten"
)

type ReservationState string

const (
	ReservationReserved ReservationState = "reserved"
	ReservationConsumed ReservationState = "consumed"
	ReservationReleased ReservationState = "released"
)

type LifecycleState string

const (
	LifecycleDestroyed LifecycleState = "destroyed"
)

// TeardownVerificationRequest binds lifecycle verification to one prospective
// quota-release operation. A proof for another reservation, resource
// incarnation, tenant, or operation is not transferable.
type TeardownVerificationRequest struct {
	ReleaseOperationID identity.ID
	ReservationID      identity.ID
	ReservationVersion uint64
	TenantID           identity.ID
	WorkspaceID        identity.ID
	Action             Action
	Instance           ResourceInstance
}

// TeardownReceipt is returned by the trusted resource owner after its durable
// lifecycle journal records destruction. ProofDigest identifies that journal
// receipt; Sequence is its positive durable ordering position.
type TeardownReceipt struct {
	ReleaseOperationID  identity.ID
	ReservationID       identity.ID
	ReservationVersion  uint64
	TenantID            identity.ID
	WorkspaceID         identity.ID
	Action              Action
	Instance            ResourceInstance
	State               LifecycleState
	LifecycleGeneration uint64
	Durable             bool
	Sequence            uint64
	ProofDigest         string
}

type TeardownVerifier interface {
	VerifyTeardown(context.Context, TeardownVerificationRequest) (TeardownReceipt, error)
}

type releaseBinding struct {
	reservationVersion uint64
	instance           ResourceInstance
}

type teardownPermit struct {
	receipt TeardownReceipt
}

// ReleaseBinding exposes an immutable copy of Service's private binding to
// repository adapters. It cannot be set by callers outside this package.
func (request TransitionRequest) ReleaseBinding() (uint64, ResourceInstance, bool) {
	if request.releaseBinding == nil {
		return 0, ResourceInstance{}, false
	}
	return request.releaseBinding.reservationVersion, request.releaseBinding.instance, true
}

// VerifiedTeardown exposes the trusted proof to durable repository adapters.
// Presence means Service checked every binding field before dispatching the
// atomic release mutation; adapters must still compare it with stored state.
func (request TransitionRequest) VerifiedTeardown() (TeardownReceipt, bool) {
	if request.teardownPermit == nil {
		return TeardownReceipt{}, false
	}
	return request.teardownPermit.receipt, true
}

// Receipt is the immutable result of one atomic mutation. Durable providers
// must commit the state transition, tenant version, and receipt together before
// returning Durable=true. OperationID is globally unique within a repository.
type Receipt struct {
	OperationID         identity.ID
	Kind                OperationKind
	Fingerprint         string
	SubjectID           identity.ID
	TenantID            identity.ID
	WorkspaceID         identity.ID
	Action              Action
	ReservationID       identity.ID
	ReservationVersion  uint64
	Amount              Quota
	Instance            ResourceInstance
	State               ReservationState
	Version             uint64
	Durable             bool
	TeardownProofDigest string
}

type Recovery struct {
	Receipt        Receipt
	CurrentState   ReservationState
	CurrentVersion uint64
}

type Snapshot struct {
	Version  uint64
	Policy   Policy
	Used     Quota
	Reserved Quota
}

// RepositoryDurability declares persistence semantics that construction code
// can validate before admitting a repository into production wiring.
type RepositoryDurability struct {
	CrashDurable             bool
	AtomicExpectedVersionCAS bool
	AtomicMutationReceipt    bool
}

// Repository is the atomic persistence contract. A production implementation
// must make each mutation and its receipt one durable expected-version CAS.
// Exact operation replays return the committed receipt even when the supplied
// expected version is now stale; changed reuse returns ErrOperationConflict.
type Repository interface {
	Durability() RepositoryDurability
	Authorize(context.Context, AuthorizationRequest) (AuthorizationDecision, error)
	AuthorizeAndReserve(context.Context, ReserveRequest) (Receipt, error)
	Consume(context.Context, TransitionRequest) (Receipt, error)
	Release(context.Context, TransitionRequest) (Receipt, error)
	Recover(context.Context, RecoveryRequest) (Recovery, error)
	TightenPolicy(context.Context, TightenPolicyRequest) (Receipt, error)
	Snapshot(context.Context, SnapshotRequest) (Snapshot, error)
}

type ReleaseRequest struct {
	OperationID        identity.ID
	ExpectedVersion    uint64
	ReservationID      identity.ID
	ReservationVersion uint64
	Principal          Principal
	Resource           Resource
	Action             Action
	Instance           ResourceInstance
}

type ServiceConfig struct {
	Repository Repository
	Lifecycle  TeardownVerifier

	// AllowReferenceMemory is only for explicitly selected in-process reference
	// deployments and tests. Production construction remains fail-closed.
	AllowReferenceMemory bool
}

type Service struct {
	repository Repository
	lifecycle  TeardownVerifier
	reference  bool
}

// IntersectPolicies resolves policy inputs by selecting the smallest quota and
// maximum profile and the largest minimum profile on every dimension.
func IntersectPolicies(policies ...Policy) (Policy, error) {
	if len(policies) == 0 {
		return Policy{}, fmt.Errorf("%w: at least one policy is required", ErrInvalidPolicy)
	}
	for index, policy := range policies {
		if err := validatePolicy(policy); err != nil {
			return Policy{}, fmt.Errorf("policy %d: %w", index, err)
		}
	}

	resolved := policies[0]
	for _, policy := range policies[1:] {
		if policy.Limits.Sessions < resolved.Limits.Sessions {
			resolved.Limits.Sessions = policy.Limits.Sessions
		}
		if policy.Limits.WorkspaceBytes < resolved.Limits.WorkspaceBytes {
			resolved.Limits.WorkspaceBytes = policy.Limits.WorkspaceBytes
		}
		if policy.Limits.BlobBytes < resolved.Limits.BlobBytes {
			resolved.Limits.BlobBytes = policy.Limits.BlobBytes
		}
		if policy.Limits.ArtifactBytes < resolved.Limits.ArtifactBytes {
			resolved.Limits.ArtifactBytes = policy.Limits.ArtifactBytes
		}
		if policy.Limits.ActiveSandboxes < resolved.Limits.ActiveSandboxes {
			resolved.Limits.ActiveSandboxes = policy.Limits.ActiveSandboxes
		}
		if policy.Limits.ModelTokens < resolved.Limits.ModelTokens {
			resolved.Limits.ModelTokens = policy.Limits.ModelTokens
		}
		if policy.Limits.ModelCostMicros < resolved.Limits.ModelCostMicros {
			resolved.Limits.ModelCostMicros = policy.Limits.ModelCostMicros
		}
		if policy.MinimumProfile.CPUUnits > resolved.MinimumProfile.CPUUnits {
			resolved.MinimumProfile.CPUUnits = policy.MinimumProfile.CPUUnits
		}
		if policy.MinimumProfile.MemoryBytes > resolved.MinimumProfile.MemoryBytes {
			resolved.MinimumProfile.MemoryBytes = policy.MinimumProfile.MemoryBytes
		}
		if policy.MaximumProfile.CPUUnits < resolved.MaximumProfile.CPUUnits {
			resolved.MaximumProfile.CPUUnits = policy.MaximumProfile.CPUUnits
		}
		if policy.MaximumProfile.MemoryBytes < resolved.MaximumProfile.MemoryBytes {
			resolved.MaximumProfile.MemoryBytes = policy.MaximumProfile.MemoryBytes
		}
	}
	if resolved.MinimumProfile.CPUUnits > resolved.MaximumProfile.CPUUnits ||
		resolved.MinimumProfile.MemoryBytes > resolved.MaximumProfile.MemoryBytes {
		return Policy{}, ErrPolicyConflict
	}
	return resolved, nil
}

func validatePolicy(policy Policy) error {
	quotaValues := [...]uint64{
		policy.Limits.Sessions,
		policy.Limits.WorkspaceBytes,
		policy.Limits.BlobBytes,
		policy.Limits.ArtifactBytes,
		policy.Limits.ActiveSandboxes,
		policy.Limits.ModelTokens,
		policy.Limits.ModelCostMicros,
	}
	for _, value := range quotaValues {
		if value > MaximumAmount {
			return fmt.Errorf("%w: quota exceeds maximum durable amount", ErrInvalidPolicy)
		}
	}
	if policy.MinimumProfile.CPUUnits == 0 || policy.MinimumProfile.MemoryBytes == 0 ||
		policy.MaximumProfile.CPUUnits == 0 || policy.MaximumProfile.MemoryBytes == 0 ||
		policy.MinimumProfile.CPUUnits > MaximumAmount || policy.MinimumProfile.MemoryBytes > MaximumAmount ||
		policy.MaximumProfile.CPUUnits > MaximumAmount || policy.MaximumProfile.MemoryBytes > MaximumAmount ||
		policy.MinimumProfile.CPUUnits > policy.MaximumProfile.CPUUnits ||
		policy.MinimumProfile.MemoryBytes > policy.MaximumProfile.MemoryBytes {
		return fmt.Errorf("%w: resource profile range is invalid", ErrInvalidPolicy)
	}
	return nil
}
