package secret

import (
	"context"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/hancomac/circulusd/internal/identity"
)

// MemoryStore is a race-safe, volatile contract reference. Capabilities reports
// Durable=false, so NewService rejects it unless a test-only wrapper explicitly
// supplies the durability claim. Production adapters must persist the same
// expected-version, admission, recovery, and tombstone transactions.
type MemoryStore struct {
	mu                  sync.RWMutex
	records             map[string]Record
	leases              map[string]UseLease
	activeByKey         map[string]uint64
	recoveryByLease     map[string]UseRecoveryBinding
	leaseByRecoveryID   map[string]string
	completedRecoveries map[string]UseRecoveryBinding
	acquiredByLease     map[string]bool
	now                 func() time.Time
	cloneRecordForWrite func(Record) Record
}

func NewMemoryStore() *MemoryStore {
	return NewMemoryStoreWithClock(time.Now)
}

func NewMemoryStoreWithClock(now func() time.Time) *MemoryStore {
	if now == nil {
		now = time.Now
	}
	return &MemoryStore{
		records: make(map[string]Record), leases: make(map[string]UseLease),
		activeByKey:         make(map[string]uint64),
		recoveryByLease:     make(map[string]UseRecoveryBinding),
		leaseByRecoveryID:   make(map[string]string),
		completedRecoveries: make(map[string]UseRecoveryBinding),
		acquiredByLease:     make(map[string]bool),
		now:                 now,
		cloneRecordForWrite: cloneRecord,
	}
}

func (*MemoryStore) Capabilities() StoreCapabilities {
	return StoreCapabilities{
		AtomicUseRecovery: true, AtomicPreparedUse: true, BoundedRecoveryEnumeration: true,
	}
}

func (store *MemoryStore) Get(ctx context.Context, tenantID string, secretID string) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	store.mu.RLock()
	if err := ctx.Err(); err != nil {
		store.mu.RUnlock()
		return Record{}, err
	}
	record, found := store.records[tenantID+"\x00"+secretID]
	if !found {
		store.mu.RUnlock()
		return Record{}, ErrSecretNotFound
	}
	copy := cloneRecord(record)
	store.mu.RUnlock()
	return copy, nil
}

func (store *MemoryStore) CompareAndSwap(ctx context.Context, expectedVersion uint64, next Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateRecord(next, maximumDefaultSecretBytes); err != nil {
		return err
	}
	cloneForWrite := store.cloneRecordForWrite
	if cloneForWrite == nil {
		cloneForWrite = cloneRecord
	}
	nextCopy := cloneForWrite(next)
	storeOwnsCopy := false
	defer func() {
		if !storeOwnsCopy {
			clear(nextCopy.Value)
		}
	}()
	if !nextCopy.Active {
		clear(nextCopy.Value)
		nextCopy.Value = nil
	}
	key := next.TenantID + "\x00" + next.SecretID
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	current, found := store.records[key]
	if !found {
		if expectedVersion != 0 || next.Version != 1 {
			return ErrStoreConflict
		}
	} else if current.Version != expectedVersion || expectedVersion == math.MaxUint64 || next.Version != expectedVersion+1 {
		return ErrStoreConflict
	}
	if store.activeByKey[key] != 0 {
		return ErrStoreInUse
	}
	if found {
		clear(current.Value)
	}
	store.records[key] = nextCopy
	storeOwnsCopy = true
	return nil
}

func (store *MemoryStore) BeginUse(
	ctx context.Context,
	request BeginUseRequest,
) (Record, UseLease, error) {
	return store.beginUse(ctx, request, true)
}

func (store *MemoryStore) ReserveUse(ctx context.Context, request ReserveUseRequest) (UseLease, error) {
	_, lease, err := store.beginUse(ctx, request, false)
	return lease, err
}

func (store *MemoryStore) beginUse(
	ctx context.Context,
	request BeginUseRequest,
	acquire bool,
) (Record, UseLease, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, UseLease{}, err
	}
	if request.Recovery.TenantID != request.TenantID ||
		request.Recovery.SecretID != request.SecretID ||
		request.Recovery.SecretVersion != request.ExpectedVersion ||
		validateRecoveryBinding(request.Recovery) != nil {
		return Record{}, UseLease{}, ErrUseLeaseInvalid
	}
	leaseID, err := identity.New(identity.Lease)
	if err != nil {
		return Record{}, UseLease{}, ErrStoreConflict
	}
	key := request.TenantID + "\x00" + request.SecretID
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Record{}, UseLease{}, err
	}
	now := store.now().Round(0).UTC()
	if !admissionMatchesRecovery(
		request.Admission, request.Recovery, request.TenantID, request.SecretID, now,
	) {
		return Record{}, UseLease{}, ErrAccessDenied
	}
	if leaseID, active := store.leaseByRecoveryID[request.Recovery.RecoveryID]; active {
		if bound := store.recoveryByLease[leaseID]; bound == request.Recovery {
			return Record{}, UseLease{}, ErrStoreInUse
		}
		return Record{}, UseLease{}, ErrUseLeaseInvalid
	}
	if _, completed := store.completedRecoveries[request.Recovery.RecoveryID]; completed {
		return Record{}, UseLease{}, ErrUseLeaseInvalid
	}
	record, found := store.records[key]
	if !found || !record.Active || record.Version != request.ExpectedVersion {
		return Record{}, UseLease{}, ErrSecretNotFound
	}
	if request.Admission.Authorization.Exposure != record.Exposure ||
		request.Admission.Authorization.Endpoint != record.Endpoint ||
		request.Admission.Authorization.Audience != record.Audience ||
		request.Recovery.DestroySandboxAfterUse != record.DestroySandboxAfterUse {
		return Record{}, UseLease{}, ErrAccessDenied
	}
	if store.activeByKey[key] != 0 {
		return Record{}, UseLease{}, ErrStoreInUse
	}
	lease := UseLease{
		LeaseID: leaseID.String(), TenantID: request.TenantID, SecretID: request.SecretID,
		Version: request.ExpectedVersion,
	}
	if _, collision := store.leases[lease.LeaseID]; collision {
		return Record{}, UseLease{}, ErrStoreConflict
	}
	store.leases[lease.LeaseID] = lease
	store.activeByKey[key]++
	recovery := request.Recovery
	store.recoveryByLease[lease.LeaseID] = recovery
	store.leaseByRecoveryID[recovery.RecoveryID] = lease.LeaseID
	store.acquiredByLease[lease.LeaseID] = acquire
	if !acquire {
		return Record{}, lease, nil
	}
	return cloneRecord(record), lease, nil
}

func (store *MemoryStore) AcquireReservedUse(
	ctx context.Context,
	request AcquireReservedUseRequest,
) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	if request.Recovery.TenantID != request.TenantID ||
		request.Recovery.SecretID != request.SecretID ||
		request.Recovery.SecretVersion != request.ExpectedVersion ||
		validateRecoveryBinding(request.Recovery) != nil {
		return Record{}, ErrUseLeaseInvalid
	}
	key := request.TenantID + "\x00" + request.SecretID
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	now := store.now().Round(0).UTC()
	if !admissionMatchesRecovery(
		request.Admission, request.Recovery, request.TenantID, request.SecretID, now,
	) {
		return Record{}, ErrAccessDenied
	}
	current, found := store.leases[request.Lease.LeaseID]
	if !found || current != request.Lease || current.TenantID != request.TenantID ||
		current.SecretID != request.SecretID || current.Version != request.ExpectedVersion {
		return Record{}, ErrUseLeaseInvalid
	}
	if bound, found := store.recoveryByLease[request.Lease.LeaseID]; !found || bound != request.Recovery ||
		store.leaseByRecoveryID[request.Recovery.RecoveryID] != request.Lease.LeaseID {
		return Record{}, ErrUseLeaseInvalid
	}
	if store.acquiredByLease[request.Lease.LeaseID] {
		return Record{}, ErrStoreInUse
	}
	record, found := store.records[key]
	if !found || !record.Active || record.Version != request.ExpectedVersion {
		return Record{}, ErrSecretNotFound
	}
	if request.Admission.Authorization.Exposure != record.Exposure ||
		request.Admission.Authorization.Endpoint != record.Endpoint ||
		request.Admission.Authorization.Audience != record.Audience ||
		request.Recovery.DestroySandboxAfterUse != record.DestroySandboxAfterUse {
		return Record{}, ErrAccessDenied
	}
	store.acquiredByLease[request.Lease.LeaseID] = true
	return cloneRecord(record), nil
}

func admissionMatchesRecovery(
	admission UseAdmissionPermit,
	recovery UseRecoveryBinding,
	tenantID string,
	secretID string,
	now time.Time,
) bool {
	access := admission.Authorization.Access
	return validateUseAdmission(admission, now) == nil && access.TenantID == tenantID &&
		admission.Authorization.SecretID == secretID && access.TenantID == recovery.TenantID &&
		access.SubjectID == recovery.SubjectID && access.SessionID == recovery.SessionID &&
		access.WorkspaceID == recovery.WorkspaceID && access.TurnID == recovery.TurnID &&
		access.RuntimeRevision == recovery.RuntimeRevision &&
		access.TurnLeaseGeneration == recovery.TurnLeaseGeneration &&
		access.PlacementGeneration == recovery.PlacementGeneration &&
		access.SandboxGeneration == recovery.SandboxGeneration &&
		access.AuthorizationGeneration == recovery.AuthorizationGeneration &&
		access.Permission == recovery.Permission && access.ServiceBinding == recovery.ServiceBinding &&
		access.AuthorityExpiresAt.Equal(recovery.AuthorityExpiresAt) &&
		admission.Authorization.SecretID == recovery.SecretID &&
		admission.Authorization.Exposure == recovery.Exposure &&
		admission.Authorization.Endpoint == recovery.Endpoint &&
		admission.Authorization.Audience == recovery.Audience &&
		admission.Authorization.InvocationID == recovery.InvocationID
}

func (store *MemoryStore) EndUse(ctx context.Context, lease UseLease) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	current, found := store.leases[lease.LeaseID]
	if !found || current != lease {
		return ErrUseLeaseInvalid
	}
	key := lease.TenantID + "\x00" + lease.SecretID
	delete(store.leases, lease.LeaseID)
	delete(store.acquiredByLease, lease.LeaseID)
	if recovery, found := store.recoveryByLease[lease.LeaseID]; found {
		delete(store.recoveryByLease, lease.LeaseID)
		delete(store.leaseByRecoveryID, recovery.RecoveryID)
		store.completedRecoveries[recovery.RecoveryID] = recovery
	}
	if store.activeByKey[key] <= 1 {
		delete(store.activeByKey, key)
	} else {
		store.activeByKey[key]--
	}
	return nil
}

func (store *MemoryStore) ValidateUseRecovery(ctx context.Context, recovery UseRecoveryBinding) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if validateRecoveryBinding(recovery) != nil {
		return ErrUseLeaseInvalid
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if completed, found := store.completedRecoveries[recovery.RecoveryID]; found {
		if completed == recovery {
			return nil
		}
		return ErrUseLeaseInvalid
	}
	leaseID, found := store.leaseByRecoveryID[recovery.RecoveryID]
	if !found {
		return ErrUseLeaseInvalid
	}
	if bound, active := store.recoveryByLease[leaseID]; !active || bound != recovery {
		return ErrUseLeaseInvalid
	}
	if _, active := store.leases[leaseID]; !active {
		return ErrUseLeaseInvalid
	}
	return nil
}

func (store *MemoryStore) CompleteUseRecovery(ctx context.Context, recovery UseRecoveryBinding) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if validateRecoveryBinding(recovery) != nil {
		return ErrUseLeaseInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if completed, found := store.completedRecoveries[recovery.RecoveryID]; found {
		if completed == recovery {
			return nil
		}
		return ErrUseLeaseInvalid
	}
	leaseID, found := store.leaseByRecoveryID[recovery.RecoveryID]
	if !found {
		return ErrUseLeaseInvalid
	}
	if bound, active := store.recoveryByLease[leaseID]; !active || bound != recovery {
		return ErrUseLeaseInvalid
	}
	lease, active := store.leases[leaseID]
	if !active || lease.TenantID != recovery.TenantID || lease.SecretID != recovery.SecretID ||
		lease.Version != recovery.SecretVersion {
		return ErrUseLeaseInvalid
	}
	key := lease.TenantID + "\x00" + lease.SecretID
	delete(store.leases, leaseID)
	delete(store.acquiredByLease, leaseID)
	delete(store.recoveryByLease, leaseID)
	delete(store.leaseByRecoveryID, recovery.RecoveryID)
	if store.activeByKey[key] <= 1 {
		delete(store.activeByKey, key)
	} else {
		store.activeByKey[key]--
	}
	store.completedRecoveries[recovery.RecoveryID] = recovery
	return nil
}

func (store *MemoryStore) ListPendingUseRecoveries(
	ctx context.Context,
	query PendingUseRecoveryQuery,
) (PendingUseRecoveryPage, error) {
	if err := ctx.Err(); err != nil {
		return PendingUseRecoveryPage{}, err
	}
	if _, err := identity.Parse(identity.Tenant, query.TenantID); err != nil || query.Limit < 1 || query.Limit > 1000 {
		return PendingUseRecoveryPage{}, ErrInvalidRequest
	}
	if query.AfterRecoveryID != "" {
		if _, err := identity.Parse(identity.Operation, query.AfterRecoveryID); err != nil {
			return PendingUseRecoveryPage{}, ErrInvalidRequest
		}
	}
	store.mu.RLock()
	if err := ctx.Err(); err != nil {
		store.mu.RUnlock()
		return PendingUseRecoveryPage{}, err
	}
	recoveries := make([]UseRecoveryBinding, 0, query.Limit+1)
	for _, recovery := range store.recoveryByLease {
		if recovery.TenantID == query.TenantID && recovery.RecoveryID > query.AfterRecoveryID {
			recoveries = append(recoveries, recovery)
			sort.Slice(recoveries, func(left int, right int) bool {
				return recoveries[left].RecoveryID < recoveries[right].RecoveryID
			})
			if len(recoveries) > query.Limit+1 {
				recoveries = recoveries[:query.Limit+1]
			}
		}
	}
	store.mu.RUnlock()
	page := PendingUseRecoveryPage{}
	if len(recoveries) > query.Limit {
		page.Recoveries = append([]UseRecoveryBinding(nil), recoveries[:query.Limit]...)
		page.NextAfterRecoveryID = page.Recoveries[len(page.Recoveries)-1].RecoveryID
		return page, nil
	}
	page.Recoveries = append([]UseRecoveryBinding(nil), recoveries...)
	return page, nil
}

func validateRecoveryBinding(recovery UseRecoveryBinding) error {
	if _, err := identity.Parse(identity.Tenant, recovery.TenantID); err != nil ||
		validateSecretID(recovery.SecretID) != nil || recovery.SecretVersion == 0 ||
		!validExposure(recovery.Exposure) {
		return ErrUseLeaseInvalid
	}
	if _, err := identity.Parse(identity.Subject, recovery.SubjectID); err != nil {
		return ErrUseLeaseInvalid
	}
	if _, err := identity.Parse(identity.Session, recovery.SessionID); err != nil {
		return ErrUseLeaseInvalid
	}
	if _, err := identity.Parse(identity.Workspace, recovery.WorkspaceID); err != nil {
		return ErrUseLeaseInvalid
	}
	if _, err := identity.Parse(identity.Turn, recovery.TurnID); err != nil {
		return ErrUseLeaseInvalid
	}
	if _, err := identity.Parse(identity.RuntimeRevision, recovery.RuntimeRevision); err != nil {
		return ErrUseLeaseInvalid
	}
	for _, generation := range []uint64{
		recovery.TurnLeaseGeneration, recovery.PlacementGeneration, recovery.SandboxGeneration,
		recovery.AuthorizationGeneration,
	} {
		if generation == 0 || generation > maximumSharedGeneration {
			return ErrUseLeaseInvalid
		}
	}
	if validateBoundedText(recovery.Permission, false) != nil ||
		validateBoundedText(recovery.ServiceBinding, false) != nil || recovery.AuthorityExpiresAt.IsZero() ||
		!recovery.AuthorityExpiresAt.Equal(recovery.AuthorityExpiresAt.Round(0).UTC()) {
		return ErrUseLeaseInvalid
	}
	if _, err := identity.Parse(identity.Operation, recovery.RecoveryID); err != nil {
		return ErrUseLeaseInvalid
	}
	switch recovery.Exposure {
	case ExposureSandboxEnv, ExposureSandboxFile:
		if _, err := identity.Parse(identity.Invocation, recovery.InvocationID); err != nil ||
			!digestPattern.MatchString(recovery.ResolvedCacheKey) || recovery.Endpoint != "" || recovery.Audience != "" {
			return ErrUseLeaseInvalid
		}
	case ExposureProxyOnly, ExposureGatewayHeader, ExposureShortLivedToken:
		if recovery.DestroySandboxAfterUse || recovery.InvocationID != "" || recovery.ResolvedCacheKey != "" ||
			validateEndpoint(recovery.Endpoint) != nil || validateBoundedText(recovery.Audience, false) != nil {
			return ErrUseLeaseInvalid
		}
	default:
		return ErrUseLeaseInvalid
	}
	return nil
}

func cloneRecord(record Record) Record {
	copy := record
	copy.Value = append([]byte(nil), record.Value...)
	return copy
}
