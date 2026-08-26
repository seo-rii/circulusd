package tenant

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"sync"

	"github.com/hancomac/circulusd/internal/identity"
)

type workspaceState struct {
	grants map[identity.ID]Role
}

type tenantState struct {
	version      uint64
	policy       Policy
	members      map[identity.ID]Role
	workspaces   map[identity.ID]workspaceState
	used         Quota
	reserved     Quota
	reservations map[identity.ID]reservationRecord
}

type reservationRecord struct {
	tenantID    identity.ID
	workspaceID identity.ID
	subjectID   identity.ID
	action      Action
	amount      Quota
	profile     ResourceProfile
	instance    ResourceInstance
	version     uint64
	state       ReservationState
}

type operationIdentity struct {
	kind               OperationKind
	subjectID          identity.ID
	tenantID           identity.ID
	workspaceID        identity.ID
	action             Action
	reservationID      identity.ID
	amount             Quota
	profile            ResourceProfile
	instance           ResourceInstance
	reservationVersion uint64
	policy             Policy
}

type operationRecord struct {
	identity operationIdentity
	receipt  Receipt
}

// MemoryRepository is a race-safe reference implementation of Repository. It
// models the required transaction boundary with one mutex. Production stores
// must provide the same boundary using durable compare-and-swap transactions.
type MemoryRepository struct {
	mu             sync.RWMutex
	platformAdmins map[identity.ID]struct{}
	tenants        map[identity.ID]*tenantState
	operations     map[identity.ID]operationRecord
}

var _ Repository = (*MemoryRepository)(nil)

func (*MemoryRepository) Durability() RepositoryDurability {
	return RepositoryDurability{
		CrashDurable:             false,
		AtomicExpectedVersionCAS: true,
		AtomicMutationReceipt:    true,
	}
}

func NewMemoryRepository(configuration Configuration) (*MemoryRepository, error) {
	if len(configuration.Tenants) == 0 {
		return nil, fmt.Errorf("%w: at least one tenant is required", ErrInvalidConfiguration)
	}
	repository := &MemoryRepository{
		platformAdmins: make(map[identity.ID]struct{}, len(configuration.PlatformAdmins)),
		tenants:        make(map[identity.ID]*tenantState, len(configuration.Tenants)),
		operations:     make(map[identity.ID]operationRecord),
	}
	for index, subjectID := range configuration.PlatformAdmins {
		if !validID(subjectID, identity.Subject) {
			return nil, fmt.Errorf("%w: platform administrator %d has invalid subject ID", ErrInvalidConfiguration, index)
		}
		if _, duplicate := repository.platformAdmins[subjectID]; duplicate {
			return nil, fmt.Errorf("%w: duplicate platform administrator", ErrInvalidConfiguration)
		}
		repository.platformAdmins[subjectID] = struct{}{}
	}

	workspaceTenants := make(map[identity.ID]identity.ID)
	for tenantIndex, configuration := range configuration.Tenants {
		if !validID(configuration.TenantID, identity.Tenant) {
			return nil, fmt.Errorf("%w: tenant %d has invalid tenant ID", ErrInvalidConfiguration, tenantIndex)
		}
		if _, duplicate := repository.tenants[configuration.TenantID]; duplicate {
			return nil, fmt.Errorf("%w: duplicate tenant ID", ErrInvalidConfiguration)
		}
		if err := validatePolicy(configuration.Policy); err != nil {
			return nil, fmt.Errorf("%w: tenant %s policy: %v", ErrInvalidConfiguration, configuration.TenantID, err)
		}

		state := &tenantState{
			version:      1,
			policy:       configuration.Policy,
			members:      make(map[identity.ID]Role, len(configuration.Members)),
			workspaces:   make(map[identity.ID]workspaceState, len(configuration.Workspaces)),
			reservations: make(map[identity.ID]reservationRecord),
		}
		for memberIndex, member := range configuration.Members {
			if !validID(member.SubjectID, identity.Subject) ||
				(member.Role != RoleTenantAdmin && member.Role != RoleUser) {
				return nil, fmt.Errorf("%w: tenant %d member %d is invalid", ErrInvalidConfiguration, tenantIndex, memberIndex)
			}
			if _, duplicate := state.members[member.SubjectID]; duplicate {
				return nil, fmt.Errorf("%w: duplicate tenant membership", ErrInvalidConfiguration)
			}
			state.members[member.SubjectID] = member.Role
		}
		for workspaceIndex, workspace := range configuration.Workspaces {
			if !validID(workspace.WorkspaceID, identity.Workspace) {
				return nil, fmt.Errorf("%w: tenant %d workspace %d has invalid ID", ErrInvalidConfiguration, tenantIndex, workspaceIndex)
			}
			if _, duplicate := state.workspaces[workspace.WorkspaceID]; duplicate {
				return nil, fmt.Errorf("%w: duplicate workspace in tenant", ErrInvalidConfiguration)
			}
			if owningTenant, duplicate := workspaceTenants[workspace.WorkspaceID]; duplicate {
				return nil, fmt.Errorf("%w: workspace is assigned to tenants %s and %s", ErrInvalidConfiguration, owningTenant, configuration.TenantID)
			}
			workspaceTenants[workspace.WorkspaceID] = configuration.TenantID
			grants := make(map[identity.ID]Role, len(workspace.Grants))
			for grantIndex, grant := range workspace.Grants {
				if !validID(grant.SubjectID, identity.Subject) ||
					(grant.Role != RoleWorkspaceOwner && grant.Role != RoleWorkspaceMember) {
					return nil, fmt.Errorf("%w: tenant %d workspace %d grant %d is invalid", ErrInvalidConfiguration, tenantIndex, workspaceIndex, grantIndex)
				}
				if _, member := state.members[grant.SubjectID]; !member {
					return nil, fmt.Errorf("%w: workspace grant subject is not a tenant member", ErrInvalidConfiguration)
				}
				if _, duplicate := grants[grant.SubjectID]; duplicate {
					return nil, fmt.Errorf("%w: duplicate workspace grant", ErrInvalidConfiguration)
				}
				grants[grant.SubjectID] = grant.Role
			}
			state.workspaces[workspace.WorkspaceID] = workspaceState{grants: grants}
		}
		repository.tenants[configuration.TenantID] = state
	}
	return repository, nil
}

func (repository *MemoryRepository) Authorize(ctx context.Context, request AuthorizationRequest) (AuthorizationDecision, error) {
	if err := validateAuthorizationRequest(request); err != nil {
		return AuthorizationDecision{}, err
	}
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return AuthorizationDecision{}, err
	}
	decision, _, err := repository.authorizeLocked(request)
	return decision, err
}

func (repository *MemoryRepository) AuthorizeAndReserve(ctx context.Context, request ReserveRequest) (Receipt, error) {
	if err := validateMutationHeader(request.OperationID, request.ExpectedVersion); err != nil {
		return Receipt{}, err
	}
	authorization := AuthorizationRequest{Principal: request.Principal, Resource: request.Resource, Action: request.Action}
	if err := validateAuthorizationRequest(authorization); err != nil {
		return Receipt{}, err
	}

	repository.mu.Lock()
	defer repository.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	_, state, err := repository.authorizeLocked(authorization)
	if err != nil {
		return Receipt{}, err
	}
	operation := operationIdentity{
		kind: OperationReserve, subjectID: request.Principal.SubjectID,
		tenantID: request.Resource.TenantID, workspaceID: request.Resource.WorkspaceID,
		action: request.Action, reservationID: request.OperationID,
		amount: request.Amount, profile: request.RequestedProfile, instance: request.Instance,
	}
	if receipt, found, err := repository.replayLocked(request.OperationID, operation); found || err != nil {
		return receipt, err
	}
	if err := validateReserveSemantics(request, state.policy); err != nil {
		return Receipt{}, err
	}
	if request.ExpectedVersion != state.version {
		return Receipt{}, ErrVersionConflict
	}
	if !quotaAdmissible(state.policy.Limits, state.used, state.reserved, request.Amount) {
		return Receipt{}, ErrQuotaExceeded
	}
	version, err := incrementVersion(state.version)
	if err != nil {
		return Receipt{}, err
	}

	reserved := addQuota(state.reserved, request.Amount)
	record := reservationRecord{
		tenantID: request.Resource.TenantID, workspaceID: request.Resource.WorkspaceID,
		subjectID: request.Principal.SubjectID, action: request.Action,
		amount: request.Amount, profile: request.RequestedProfile, instance: request.Instance,
		version: version, state: ReservationReserved,
	}
	receipt := Receipt{
		OperationID: request.OperationID, Kind: OperationReserve,
		Fingerprint: fingerprintOperation(request.OperationID, operation),
		SubjectID:   request.Principal.SubjectID, TenantID: request.Resource.TenantID,
		WorkspaceID: request.Resource.WorkspaceID, Action: request.Action,
		ReservationID: request.OperationID, ReservationVersion: version,
		Amount: request.Amount, Instance: request.Instance,
		State: ReservationReserved, Version: version, Durable: false,
	}
	state.reserved = reserved
	state.version = version
	state.reservations[request.OperationID] = record
	repository.operations[request.OperationID] = operationRecord{identity: operation, receipt: receipt}
	return receipt, nil
}

func (repository *MemoryRepository) Consume(ctx context.Context, request TransitionRequest) (Receipt, error) {
	return repository.transition(ctx, request, OperationConsume)
}

func (repository *MemoryRepository) Release(ctx context.Context, request TransitionRequest) (Receipt, error) {
	return repository.transition(ctx, request, OperationRelease)
}

func (repository *MemoryRepository) transition(ctx context.Context, request TransitionRequest, kind OperationKind) (Receipt, error) {
	if err := validateMutationHeader(request.OperationID, request.ExpectedVersion); err != nil ||
		!validID(request.ReservationID, identity.Operation) {
		if err != nil {
			return Receipt{}, err
		}
		return Receipt{}, fmt.Errorf("%w: reservation ID is invalid", ErrInvalidRequest)
	}
	authorization := AuthorizationRequest{Principal: request.Principal, Resource: request.Resource, Action: request.Action}
	if err := validateAuthorizationRequest(authorization); err != nil {
		return Receipt{}, err
	}

	repository.mu.Lock()
	defer repository.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	decision, state, err := repository.authorizeLocked(authorization)
	if err != nil {
		return Receipt{}, err
	}
	operation := operationIdentity{
		kind: kind, subjectID: request.Principal.SubjectID,
		tenantID: request.Resource.TenantID, workspaceID: request.Resource.WorkspaceID,
		action: request.Action, reservationID: request.ReservationID,
	}
	if request.releaseBinding != nil {
		operation.instance = request.releaseBinding.instance
		operation.reservationVersion = request.releaseBinding.reservationVersion
	}
	if receipt, found, err := repository.replayLocked(request.OperationID, operation); found || err != nil {
		return receipt, err
	}
	if request.ExpectedVersion != state.version {
		return Receipt{}, ErrVersionConflict
	}
	reservation, found := state.reservations[request.ReservationID]
	if !found || reservation.tenantID != request.Resource.TenantID ||
		reservation.workspaceID != request.Resource.WorkspaceID || reservation.action != request.Action {
		return Receipt{}, ErrReservationNotFound
	}
	if reservation.subjectID != request.Principal.SubjectID &&
		decision.Role != RolePlatformAdmin && decision.Role != RoleTenantAdmin && decision.Role != RoleWorkspaceOwner {
		return Receipt{}, ErrAccessDenied
	}

	used := state.used
	reserved := state.reserved
	switch kind {
	case OperationConsume:
		if reservation.state != ReservationReserved || !quotaContains(reserved, reservation.amount) {
			return Receipt{}, ErrReservationState
		}
		if err := validateReserveSemantics(ReserveRequest{
			Action: request.Action, Amount: reservation.amount,
			RequestedProfile: reservation.profile, Instance: reservation.instance,
		}, state.policy); err != nil {
			return Receipt{}, err
		}
		remainingReserved := subtractQuota(reserved, reservation.amount)
		if !quotaAdmissible(state.policy.Limits, used, remainingReserved, reservation.amount) {
			return Receipt{}, ErrQuotaExceeded
		}
		reserved = subtractQuota(reserved, reservation.amount)
		used = addQuota(used, reservation.amount)
		reservation.state = ReservationConsumed
	case OperationRelease:
		switch reservation.state {
		case ReservationReserved:
			if !quotaContains(reserved, reservation.amount) {
				return Receipt{}, ErrReservationState
			}
			reserved = subtractQuota(reserved, reservation.amount)
		case ReservationConsumed:
			// Token and monetary budgets account for irreversible external
			// consumption. They may be cancelled while merely reserved, but a
			// caller must never refund them after successful consumption.
			if reservation.amount.ModelTokens != 0 || reservation.amount.ModelCostMicros != 0 {
				return Receipt{}, ErrReservationState
			}
			if !actionRequiresTeardown(reservation.action) || request.releaseBinding == nil || request.teardownPermit == nil ||
				request.releaseBinding.reservationVersion != reservation.version ||
				request.releaseBinding.instance != reservation.instance {
				return Receipt{}, ErrTeardownUnproven
			}
			proof := request.teardownPermit.receipt
			if proof.ReleaseOperationID != request.OperationID || proof.ReservationID != request.ReservationID ||
				proof.ReservationVersion != reservation.version || proof.TenantID != reservation.tenantID ||
				proof.WorkspaceID != reservation.workspaceID || proof.Action != reservation.action ||
				proof.Instance != reservation.instance || proof.State != LifecycleDestroyed ||
				proof.LifecycleGeneration != reservation.instance.Generation || !proof.Durable ||
				proof.Sequence == 0 || proof.ProofDigest == "" {
				return Receipt{}, ErrTeardownUnproven
			}
			if !quotaContains(used, reservation.amount) {
				return Receipt{}, ErrReservationState
			}
			used = subtractQuota(used, reservation.amount)
		default:
			return Receipt{}, ErrReservationState
		}
		reservation.state = ReservationReleased
	default:
		return Receipt{}, ErrInvalidRequest
	}
	version, err := incrementVersion(state.version)
	if err != nil {
		return Receipt{}, err
	}
	receipt := Receipt{
		OperationID: request.OperationID, Kind: kind,
		Fingerprint: fingerprintOperation(request.OperationID, operation),
		SubjectID:   request.Principal.SubjectID, TenantID: request.Resource.TenantID,
		WorkspaceID: request.Resource.WorkspaceID, Action: request.Action,
		ReservationID: request.ReservationID, ReservationVersion: reservation.version,
		Amount: reservation.amount, Instance: reservation.instance,
		State: reservation.state, Version: version, Durable: false,
	}
	if kind == OperationRelease && request.teardownPermit != nil {
		receipt.TeardownProofDigest = request.teardownPermit.receipt.ProofDigest
	}
	state.used = used
	state.reserved = reserved
	state.version = version
	state.reservations[request.ReservationID] = reservation
	repository.operations[request.OperationID] = operationRecord{identity: operation, receipt: receipt}
	return receipt, nil
}

func (repository *MemoryRepository) Recover(ctx context.Context, request RecoveryRequest) (Recovery, error) {
	if !validID(request.OperationID, identity.Operation) {
		return Recovery{}, fmt.Errorf("%w: operation ID is invalid", ErrInvalidRequest)
	}
	authorization := AuthorizationRequest{Principal: request.Principal, Resource: request.Resource, Action: request.Action}
	if err := validateAuthorizationRequest(authorization); err != nil {
		return Recovery{}, err
	}
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return Recovery{}, err
	}
	decision, state, err := repository.authorizeLocked(authorization)
	if err != nil {
		return Recovery{}, err
	}
	operation, found := repository.operations[request.OperationID]
	if !found || operation.receipt.TenantID != request.Resource.TenantID ||
		operation.receipt.WorkspaceID != request.Resource.WorkspaceID || operation.receipt.Action != request.Action {
		return Recovery{}, ErrReceiptNotFound
	}
	if operation.receipt.SubjectID != request.Principal.SubjectID &&
		decision.Role != RolePlatformAdmin && decision.Role != RoleTenantAdmin && decision.Role != RoleWorkspaceOwner {
		return Recovery{}, ErrAccessDenied
	}
	currentState := operation.receipt.State
	if validID(operation.receipt.ReservationID, identity.Operation) {
		reservation, exists := state.reservations[operation.receipt.ReservationID]
		if !exists {
			return Recovery{}, ErrReservationNotFound
		}
		currentState = reservation.state
	}
	return Recovery{Receipt: operation.receipt, CurrentState: currentState, CurrentVersion: state.version}, nil
}

func (repository *MemoryRepository) TightenPolicy(ctx context.Context, request TightenPolicyRequest) (Receipt, error) {
	if err := validateMutationHeader(request.OperationID, request.ExpectedVersion); err != nil {
		return Receipt{}, err
	}
	if !validID(request.TenantID, identity.Tenant) {
		return Receipt{}, fmt.Errorf("%w: tenant ID is invalid", ErrInvalidRequest)
	}
	if err := validatePolicy(request.Policy); err != nil {
		return Receipt{}, err
	}
	authorization := AuthorizationRequest{
		Principal: request.Principal,
		Resource:  Resource{TenantID: request.TenantID},
		Action:    ActionTenantManage,
	}
	if err := validateAuthorizationRequest(authorization); err != nil {
		return Receipt{}, err
	}

	repository.mu.Lock()
	defer repository.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	_, state, err := repository.authorizeLocked(authorization)
	if err != nil {
		return Receipt{}, err
	}
	operation := operationIdentity{
		kind: OperationPolicyTighten, subjectID: request.Principal.SubjectID,
		tenantID: request.TenantID, action: ActionTenantManage, policy: request.Policy,
	}
	if receipt, found, err := repository.replayLocked(request.OperationID, operation); found || err != nil {
		return receipt, err
	}
	if request.ExpectedVersion != state.version {
		return Receipt{}, ErrVersionConflict
	}
	if policyRelaxes(state.policy, request.Policy) {
		return Receipt{}, ErrPolicyRelaxation
	}
	version, err := incrementVersion(state.version)
	if err != nil {
		return Receipt{}, err
	}
	receipt := Receipt{
		OperationID: request.OperationID, Kind: OperationPolicyTighten,
		Fingerprint: fingerprintOperation(request.OperationID, operation),
		SubjectID:   request.Principal.SubjectID, TenantID: request.TenantID,
		Action: ActionTenantManage, Version: version, Durable: false,
	}
	state.policy = request.Policy
	state.version = version
	repository.operations[request.OperationID] = operationRecord{identity: operation, receipt: receipt}
	return receipt, nil
}

func (repository *MemoryRepository) Snapshot(ctx context.Context, request SnapshotRequest) (Snapshot, error) {
	authorization := AuthorizationRequest{
		Principal: request.Principal,
		Resource:  Resource{TenantID: request.TenantID},
		Action:    ActionTenantManage,
	}
	if err := validateAuthorizationRequest(authorization); err != nil {
		return Snapshot{}, err
	}
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	_, state, err := repository.authorizeLocked(authorization)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Version: state.version, Policy: state.policy, Used: state.used, Reserved: state.reserved}, nil
}

func (repository *MemoryRepository) authorizeLocked(request AuthorizationRequest) (AuthorizationDecision, *tenantState, error) {
	state, found := repository.tenants[request.Resource.TenantID]
	if !found {
		return AuthorizationDecision{}, nil, ErrAccessDenied
	}
	if actionUsesWorkspace(request.Action) {
		if _, found := state.workspaces[request.Resource.WorkspaceID]; !found {
			return AuthorizationDecision{}, nil, ErrAccessDenied
		}
	}
	if _, platformAdministrator := repository.platformAdmins[request.Principal.SubjectID]; platformAdministrator {
		return AuthorizationDecision{Role: RolePlatformAdmin, Version: state.version}, state, nil
	}
	tenantRole, member := state.members[request.Principal.SubjectID]
	if !member {
		return AuthorizationDecision{}, nil, ErrAccessDenied
	}
	if !actionUsesWorkspace(request.Action) {
		if request.Action == ActionTenantRead || tenantRole == RoleTenantAdmin {
			return AuthorizationDecision{Role: tenantRole, Version: state.version}, state, nil
		}
		return AuthorizationDecision{}, nil, ErrAccessDenied
	}
	if tenantRole == RoleTenantAdmin {
		return AuthorizationDecision{Role: RoleTenantAdmin, Version: state.version}, state, nil
	}
	workspaceRole, granted := state.workspaces[request.Resource.WorkspaceID].grants[request.Principal.SubjectID]
	if !granted {
		return AuthorizationDecision{}, nil, ErrAccessDenied
	}
	if request.Action == ActionWorkspaceManage && workspaceRole != RoleWorkspaceOwner {
		return AuthorizationDecision{}, nil, ErrAccessDenied
	}
	return AuthorizationDecision{Role: workspaceRole, Version: state.version}, state, nil
}

func (repository *MemoryRepository) replayLocked(operationID identity.ID, requested operationIdentity) (Receipt, bool, error) {
	existing, found := repository.operations[operationID]
	if !found {
		return Receipt{}, false, nil
	}
	if existing.identity != requested {
		return Receipt{}, true, ErrOperationConflict
	}
	return existing.receipt, true, nil
}

func validateAuthorizationRequest(request AuthorizationRequest) error {
	if !validID(request.Principal.SubjectID, identity.Subject) || !validID(request.Resource.TenantID, identity.Tenant) {
		return fmt.Errorf("%w: principal or tenant ID is invalid", ErrInvalidRequest)
	}
	if !knownAction(request.Action) {
		return fmt.Errorf("%w: action %q is unknown", ErrInvalidRequest, request.Action)
	}
	if actionUsesWorkspace(request.Action) {
		if !validID(request.Resource.WorkspaceID, identity.Workspace) {
			return fmt.Errorf("%w: workspace action requires a workspace ID", ErrInvalidRequest)
		}
	} else if request.Resource.WorkspaceID.String() != "" {
		return fmt.Errorf("%w: tenant action cannot carry a workspace ID", ErrInvalidRequest)
	}
	return nil
}

func validateMutationHeader(operationID identity.ID, expectedVersion uint64) error {
	if !validID(operationID, identity.Operation) || expectedVersion == 0 {
		return fmt.Errorf("%w: operation ID or expected version is invalid", ErrInvalidRequest)
	}
	return nil
}

func validateReserveSemantics(request ReserveRequest, policy Policy) error {
	values := [...]uint64{
		request.Amount.Sessions,
		request.Amount.WorkspaceBytes,
		request.Amount.BlobBytes,
		request.Amount.ArtifactBytes,
		request.Amount.ActiveSandboxes,
		request.Amount.ModelTokens,
		request.Amount.ModelCostMicros,
		request.RequestedProfile.CPUUnits,
		request.RequestedProfile.MemoryBytes,
	}
	for _, value := range values {
		if value > MaximumAmount {
			return fmt.Errorf("%w: amount exceeds maximum durable value", ErrInvalidRequest)
		}
	}

	validAmount := false
	switch request.Action {
	case ActionSessionCreate:
		validAmount = request.Amount == (Quota{Sessions: 1})
	case ActionWorkspaceWrite:
		validAmount = request.Amount.WorkspaceBytes > 0 && request.Amount == (Quota{WorkspaceBytes: request.Amount.WorkspaceBytes})
	case ActionBlobStore:
		validAmount = request.Amount.WorkspaceBytes > 0 && request.Amount.BlobBytes > 0 &&
			request.Amount.WorkspaceBytes == request.Amount.BlobBytes && request.Amount == (Quota{
			WorkspaceBytes: request.Amount.WorkspaceBytes,
			BlobBytes:      request.Amount.BlobBytes,
		})
	case ActionArtifactCreate:
		validAmount = request.Amount.ArtifactBytes > 0 && request.Amount == (Quota{ArtifactBytes: request.Amount.ArtifactBytes})
	case ActionSandboxStart:
		validAmount = request.Amount == (Quota{ActiveSandboxes: 1})
	case ActionModelUse:
		validAmount = (request.Amount.ModelTokens > 0 || request.Amount.ModelCostMicros > 0) && request.Amount == (Quota{
			ModelTokens: request.Amount.ModelTokens, ModelCostMicros: request.Amount.ModelCostMicros,
		})
	default:
		return fmt.Errorf("%w: action does not reserve quota", ErrInvalidRequest)
	}
	if !validAmount {
		return fmt.Errorf("%w: quota amount is not valid for action %q", ErrInvalidRequest, request.Action)
	}
	if actionRequiresTeardown(request.Action) {
		if !validResourceInstance(request.Instance) {
			return fmt.Errorf("%w: live quota requires a resource instance", ErrInvalidRequest)
		}
	} else if request.Instance != (ResourceInstance{}) {
		return fmt.Errorf("%w: model budget cannot carry a resource instance", ErrInvalidRequest)
	}
	if request.Action != ActionSandboxStart {
		if request.RequestedProfile != (ResourceProfile{}) {
			return fmt.Errorf("%w: resource profile is only valid for sandbox admission", ErrInvalidRequest)
		}
		return nil
	}
	profile := request.RequestedProfile
	if profile.CPUUnits < policy.MinimumProfile.CPUUnits || profile.CPUUnits > policy.MaximumProfile.CPUUnits ||
		profile.MemoryBytes < policy.MinimumProfile.MemoryBytes || profile.MemoryBytes > policy.MaximumProfile.MemoryBytes {
		return ErrPolicyViolation
	}
	return nil
}

func knownAction(action Action) bool {
	switch action {
	case ActionTenantRead, ActionTenantManage,
		ActionWorkspaceRead, ActionWorkspaceWrite, ActionWorkspaceManage,
		ActionSessionCreate, ActionBlobStore, ActionArtifactCreate,
		ActionSandboxStart, ActionModelUse:
		return true
	default:
		return false
	}
}

func actionUsesWorkspace(action Action) bool {
	switch action {
	case ActionWorkspaceRead, ActionWorkspaceWrite, ActionWorkspaceManage,
		ActionSessionCreate, ActionBlobStore, ActionArtifactCreate,
		ActionSandboxStart, ActionModelUse:
		return true
	default:
		return false
	}
}

func actionRequiresTeardown(action Action) bool {
	switch action {
	case ActionWorkspaceWrite, ActionSessionCreate, ActionBlobStore, ActionArtifactCreate, ActionSandboxStart:
		return true
	default:
		return false
	}
}

func validResourceInstance(instance ResourceInstance) bool {
	if instance.Generation == 0 || instance.ID == "" || len(instance.ID) > 512 ||
		strings.TrimSpace(instance.ID) != instance.ID {
		return false
	}
	for _, character := range instance.ID {
		if character < 0x21 || character == 0x7f {
			return false
		}
	}
	return true
}

func validID(value identity.ID, kind identity.Kind) bool {
	return value.Kind() == kind && value.String() != ""
}

func quotaAdmissible(limit Quota, used Quota, reserved Quota, requested Quota) bool {
	limits := [...]uint64{limit.Sessions, limit.WorkspaceBytes, limit.BlobBytes, limit.ArtifactBytes, limit.ActiveSandboxes, limit.ModelTokens, limit.ModelCostMicros}
	usedValues := [...]uint64{used.Sessions, used.WorkspaceBytes, used.BlobBytes, used.ArtifactBytes, used.ActiveSandboxes, used.ModelTokens, used.ModelCostMicros}
	reservedValues := [...]uint64{reserved.Sessions, reserved.WorkspaceBytes, reserved.BlobBytes, reserved.ArtifactBytes, reserved.ActiveSandboxes, reserved.ModelTokens, reserved.ModelCostMicros}
	requestedValues := [...]uint64{requested.Sessions, requested.WorkspaceBytes, requested.BlobBytes, requested.ArtifactBytes, requested.ActiveSandboxes, requested.ModelTokens, requested.ModelCostMicros}
	for index, maximum := range limits {
		if usedValues[index] > maximum || reservedValues[index] > maximum-usedValues[index] ||
			requestedValues[index] > maximum-usedValues[index]-reservedValues[index] {
			return false
		}
	}
	return true
}

func quotaContains(total Quota, amount Quota) bool {
	return total.Sessions >= amount.Sessions &&
		total.WorkspaceBytes >= amount.WorkspaceBytes &&
		total.BlobBytes >= amount.BlobBytes &&
		total.ArtifactBytes >= amount.ArtifactBytes &&
		total.ActiveSandboxes >= amount.ActiveSandboxes &&
		total.ModelTokens >= amount.ModelTokens &&
		total.ModelCostMicros >= amount.ModelCostMicros
}

func addQuota(left Quota, right Quota) Quota {
	return Quota{
		Sessions:        left.Sessions + right.Sessions,
		WorkspaceBytes:  left.WorkspaceBytes + right.WorkspaceBytes,
		BlobBytes:       left.BlobBytes + right.BlobBytes,
		ArtifactBytes:   left.ArtifactBytes + right.ArtifactBytes,
		ActiveSandboxes: left.ActiveSandboxes + right.ActiveSandboxes,
		ModelTokens:     left.ModelTokens + right.ModelTokens,
		ModelCostMicros: left.ModelCostMicros + right.ModelCostMicros,
	}
}

func subtractQuota(left Quota, right Quota) Quota {
	return Quota{
		Sessions:        left.Sessions - right.Sessions,
		WorkspaceBytes:  left.WorkspaceBytes - right.WorkspaceBytes,
		BlobBytes:       left.BlobBytes - right.BlobBytes,
		ArtifactBytes:   left.ArtifactBytes - right.ArtifactBytes,
		ActiveSandboxes: left.ActiveSandboxes - right.ActiveSandboxes,
		ModelTokens:     left.ModelTokens - right.ModelTokens,
		ModelCostMicros: left.ModelCostMicros - right.ModelCostMicros,
	}
}

func incrementVersion(current uint64) (uint64, error) {
	if current == math.MaxUint64 {
		return 0, ErrVersionExhausted
	}
	return current + 1, nil
}

func policyRelaxes(current Policy, next Policy) bool {
	return next.Limits.Sessions > current.Limits.Sessions ||
		next.Limits.WorkspaceBytes > current.Limits.WorkspaceBytes ||
		next.Limits.BlobBytes > current.Limits.BlobBytes ||
		next.Limits.ArtifactBytes > current.Limits.ArtifactBytes ||
		next.Limits.ActiveSandboxes > current.Limits.ActiveSandboxes ||
		next.Limits.ModelTokens > current.Limits.ModelTokens ||
		next.Limits.ModelCostMicros > current.Limits.ModelCostMicros ||
		next.MinimumProfile.CPUUnits < current.MinimumProfile.CPUUnits ||
		next.MinimumProfile.MemoryBytes < current.MinimumProfile.MemoryBytes ||
		next.MaximumProfile.CPUUnits > current.MaximumProfile.CPUUnits ||
		next.MaximumProfile.MemoryBytes > current.MaximumProfile.MemoryBytes
}

func fingerprintOperation(operationID identity.ID, operation operationIdentity) string {
	hasher := sha256.New()
	writeString := func(value string) {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(value)))
		_, _ = hasher.Write(length[:])
		_, _ = hasher.Write([]byte(value))
	}
	writeUint64 := func(value uint64) {
		var encoded [8]byte
		binary.BigEndian.PutUint64(encoded[:], value)
		_, _ = hasher.Write(encoded[:])
	}
	writeQuota := func(value Quota) {
		writeUint64(value.Sessions)
		writeUint64(value.WorkspaceBytes)
		writeUint64(value.BlobBytes)
		writeUint64(value.ArtifactBytes)
		writeUint64(value.ActiveSandboxes)
		writeUint64(value.ModelTokens)
		writeUint64(value.ModelCostMicros)
	}
	writeProfile := func(value ResourceProfile) {
		writeUint64(value.CPUUnits)
		writeUint64(value.MemoryBytes)
	}

	writeString("circulusd.tenant-operation.v1")
	writeString(operationID.String())
	writeString(string(operation.kind))
	writeString(operation.subjectID.String())
	writeString(operation.tenantID.String())
	writeString(operation.workspaceID.String())
	writeString(string(operation.action))
	writeString(operation.reservationID.String())
	writeQuota(operation.amount)
	writeProfile(operation.profile)
	writeString(operation.instance.ID)
	writeUint64(operation.instance.Generation)
	writeUint64(operation.reservationVersion)
	writeQuota(operation.policy.Limits)
	writeProfile(operation.policy.MinimumProfile)
	writeProfile(operation.policy.MaximumProfile)
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil))
}
