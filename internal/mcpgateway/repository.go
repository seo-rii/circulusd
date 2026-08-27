package mcpgateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"time"

	"github.com/hancomac/circulusd/internal/identity"
)

type scopeKey struct {
	tenant  identity.ID
	session identity.ID
	turn    identity.ID
}

type serverRequestKey struct {
	invocation           identity.ID
	providerRequestID    string
	connectionGeneration uint64
	requestID            string
}

type providerStartStatus uint8

const (
	providerStartActive providerStartStatus = iota + 1
	providerStartCompleted
	providerStartRevoked
)

type providerStartRecord struct {
	Permit ProviderStartPermit
	Status providerStartStatus
}

// MemoryRepository is a race-safe, process-local reference implementation of
// the durable repository contract. Production deployments replace it with a
// transactional adapter; it deliberately reports Durable=true only for the
// lifetime of this repository instance.
type MemoryRepository struct {
	mu                               sync.RWMutex
	effects                          map[string]Effect
	scopes                           map[scopeKey]ValidatedAuthority
	active                           map[scopeKey]string
	claims                           map[string]DispatchPermit
	providerStarts                   map[string]providerStartRecord
	cancellationClaims               map[string]CancellationPermit
	serverRequests                   map[serverRequestKey]ServerRequestRecord
	serverRequestCounts              map[string]uint32
	serverRequestLimits              map[string]uint32
	activeServerRequests             map[string]serverRequestKey
	serverRequestReconciliations     map[string]serverRequestKey
	serverRequestCancellationPermits map[serverRequestKey]ServerRequestPermit
	parentCancellationRequired       map[string]serverRequestKey
	pendingAudits                    map[uint64]AuditEnvelope
	auditSequence                    uint64
	nonce                            uint64
	now                              func() time.Time
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{
		effects: make(map[string]Effect), scopes: make(map[scopeKey]ValidatedAuthority),
		active: make(map[scopeKey]string), claims: make(map[string]DispatchPermit),
		providerStarts:                   make(map[string]providerStartRecord),
		cancellationClaims:               make(map[string]CancellationPermit),
		serverRequests:                   make(map[serverRequestKey]ServerRequestRecord),
		serverRequestCounts:              make(map[string]uint32),
		serverRequestLimits:              make(map[string]uint32),
		activeServerRequests:             make(map[string]serverRequestKey),
		serverRequestReconciliations:     make(map[string]serverRequestKey),
		serverRequestCancellationPermits: make(map[serverRequestKey]ServerRequestPermit),
		parentCancellationRequired:       make(map[string]serverRequestKey),
		pendingAudits:                    make(map[uint64]AuditEnvelope), now: time.Now,
	}
}

func (*MemoryRepository) Durability() RepositoryDurability {
	return RepositoryDurability{
		AtomicAdmissionCAS: true, AtomicAdmissionReplay: true, AtomicTransitionCAS: true, ExclusiveDispatchClaim: true,
		ExclusiveProviderStartClaim: true, AtomicProviderStartResolution: true, ExclusiveCancellationClaim: true,
		AtomicExpiredRequestReconciliation: true,
		AtomicCurrentFence:                 true, AtomicActiveEffect: true, AtomicAuditOutbox: true, ReferenceMemory: true,
	}
}

func (repository *MemoryRepository) ClaimCancellation(ctx context.Context, request CancellationClaimRequest) (CancellationClaim, error) {
	if err := ctx.Err(); err != nil {
		return CancellationClaim{}, err
	}
	if request.Lease <= 0 || request.Lease > 30*time.Second {
		return CancellationClaim{}, ErrInvalidRequest
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	key := request.Effect.Scope.InvocationID.String()
	current, found := repository.effects[key]
	if !found {
		return CancellationClaim{}, ErrInvocationNotFound
	}
	if !sameEffect(current, request.Effect) || current.State != StateCancellationPending {
		return CancellationClaim{}, ErrConcurrentTransition
	}
	if !sameOperationScope(request.CurrentScope, current.Scope) ||
		!sameFence(repository.scopes[keyForScope(current.Scope)], request.CurrentScope) {
		return CancellationClaim{}, ErrStaleAuthority
	}
	attempt, ok := current.CurrentAttempt()
	if !ok {
		return CancellationClaim{}, ErrInvalidTransition
	}
	claimKey := dispatchClaimKey(key, attempt.Attempt)
	var providerStart ProviderStartPermit
	if start, exists := repository.providerStarts[claimKey]; exists {
		switch start.Status {
		case providerStartActive, providerStartCompleted, providerStartRevoked:
			providerStart = start.Permit
		default:
			return CancellationClaim{}, ErrInvalidTransition
		}
	}
	now := repository.now()
	existing, exists := repository.cancellationClaims[claimKey]
	if exists && sameFence(existing.Scope, request.CurrentScope) && now.UnixNano() < existing.LeaseExpiresAtUnixNano {
		return CancellationClaim{
			Permit: existing, RetryAfter: time.Duration(existing.LeaseExpiresAtUnixNano - now.UnixNano()),
		}, nil
	}
	proof := existing.Proof
	generation := existing.ClaimGeneration + 1
	if !exists {
		repository.nonce++
		proofInput := append([]byte("mcp.cancel\x00"), []byte(claimKey)...)
		var nonce [8]byte
		binary.BigEndian.PutUint64(nonce[:], repository.nonce)
		proofInput = append(proofInput, nonce[:]...)
		proof = OpaqueCancellationPermit(sha256.Sum256(proofInput))
		generation = 1
	}
	permit := CancellationPermit{
		Proof: proof, Durable: true, Scope: request.CurrentScope,
		InvocationID: current.Scope.InvocationID, RequestDigest: current.RequestDigest,
		ProviderID: current.ProviderID, ProviderRequestID: attempt.ProviderRequestID,
		Attempt: attempt.Attempt, EffectRevision: current.Revision,
		ClaimGeneration: generation, LeaseExpiresAtUnixNano: now.Add(request.Lease).UnixNano(),
		Start: providerStart,
	}
	if childKey, pending := repository.serverRequestReconciliations[key]; pending {
		record, found := repository.serverRequests[childKey]
		childPermit, permitFound := repository.serverRequestCancellationPermits[childKey]
		if !found || !permitFound || record.State != ServerRequestAbandoned ||
			(record.Method != string(ServerRequestSampling) && record.Method != string(ServerRequestElicitation)) {
			return CancellationClaim{}, ErrStoreUnavailable
		}
		permit.ServerRequest = childPermit
		permit.ServerRequestMethod = record.Method
	}
	repository.cancellationClaims[claimKey] = permit
	return CancellationClaim{Permit: permit, Fresh: true}, nil
}

func (repository *MemoryRepository) ReplayAdmission(ctx context.Context, request AdmissionReplayRequest) (StoredEffect, error) {
	if err := ctx.Err(); err != nil {
		return StoredEffect{}, err
	}
	if request.EffectID.Kind() != identity.Effect || request.InvocationID.Kind() != identity.Invocation ||
		request.RequestDigest == (Digest{}) || len(request.InputCanonical) == 0 {
		return StoredEffect{}, ErrInvalidRequest
	}
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	effect, found := repository.effects[request.InvocationID.String()]
	if !found {
		return StoredEffect{}, ErrInvocationNotFound
	}
	if !sameOperationScope(request.CurrentScope, effect.Scope) ||
		!sameFence(repository.scopes[keyForScope(effect.Scope)], request.CurrentScope) {
		return StoredEffect{}, ErrStaleAuthority
	}
	if effect.Scope.EffectID != request.EffectID || effect.RequestDigest != request.RequestDigest ||
		effect.ServerID != request.ServerID || effect.ToolName != request.ToolName ||
		!bytes.Equal(effect.InputCanonical, request.InputCanonical) {
		return StoredEffect{}, ErrInvocationConflict
	}
	return StoredEffect{Effect: cloneEffect(effect), Durable: true}, nil
}

func (repository *MemoryRepository) Admit(ctx context.Context, effect Effect) (StoredEffect, error) {
	if err := ctx.Err(); err != nil {
		return StoredEffect{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	key := effect.Scope.InvocationID.String()
	if existing, found := repository.effects[key]; found {
		if !sameImmutableEffect(existing, effect) {
			return StoredEffect{}, ErrInvocationConflict
		}
		if current := repository.scopes[keyForScope(effect.Scope)]; !sameFence(current, effect.Scope) {
			return StoredEffect{}, ErrStaleAuthority
		}
		return StoredEffect{Effect: cloneEffect(existing), Durable: true}, nil
	}
	scopeKey := keyForScope(effect.Scope)
	if current, found := repository.scopes[scopeKey]; found && !sameFence(current, effect.Scope) {
		return StoredEffect{}, ErrStaleAuthority
	}
	if activeInvocation, active := repository.active[scopeKey]; active && activeInvocation != key {
		return StoredEffect{}, ErrEffectInFlight
	}
	repository.scopes[scopeKey] = effect.Scope
	repository.effects[key] = cloneEffect(effect)
	repository.active[scopeKey] = key
	return StoredEffect{Effect: cloneEffect(effect), Durable: true}, nil
}

func (repository *MemoryRepository) Load(ctx context.Context, invocationID identity.ID) (StoredEffect, error) {
	if err := ctx.Err(); err != nil {
		return StoredEffect{}, err
	}
	if invocationID.Kind() != identity.Invocation {
		return StoredEffect{}, ErrInvalidRequest
	}
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	effect, found := repository.effects[invocationID.String()]
	if !found {
		return StoredEffect{}, ErrInvocationNotFound
	}
	return StoredEffect{Effect: cloneEffect(effect), Durable: true}, nil
}

func (repository *MemoryRepository) CommitAndClaimDispatch(ctx context.Context, request DispatchClaimRequest) (DispatchPermit, error) {
	if err := ctx.Err(); err != nil {
		return DispatchPermit{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	key := request.Previous.Scope.InvocationID.String()
	current, found := repository.effects[key]
	if !found {
		return DispatchPermit{}, ErrInvocationNotFound
	}
	if current.Revision != request.ExpectedRevision || !sameEffect(current, request.Previous) {
		return DispatchPermit{}, ErrConcurrentTransition
	}
	if durableScope := repository.scopes[keyForScope(current.Scope)]; !sameFence(durableScope, request.CurrentScope) ||
		!sameOperationScope(request.CurrentScope, current.Scope) {
		return DispatchPermit{}, ErrStaleAuthority
	}
	if repository.active[keyForScope(current.Scope)] != key {
		return DispatchPermit{}, ErrEffectInFlight
	}
	if request.Next.Revision != request.ExpectedRevision+1 || request.Next.State != StateDispatching ||
		!sameImmutableEffect(current, request.Next) || !validAuthorizationPermit(request.Authorization, request.CurrentScope, current.ServerID, current.ToolName, current.RequestDigest) {
		return DispatchPermit{}, ErrInvalidTransition
	}
	attempt, ok := request.Next.CurrentAttempt()
	if !ok || attempt.Attempt == 0 || attempt.Attempt != uint32(len(request.Next.Attempts)) {
		return DispatchPermit{}, ErrInvalidTransition
	}
	claimKey := dispatchClaimKey(key, attempt.Attempt)
	if _, claimed := repository.claims[claimKey]; claimed {
		return DispatchPermit{}, ErrConcurrentTransition
	}
	repository.nonce++
	proofInput := make([]byte, 0, len(key)+16)
	proofInput = append(proofInput, key...)
	var numbers [16]byte
	binary.BigEndian.PutUint64(numbers[:8], uint64(attempt.Attempt))
	binary.BigEndian.PutUint64(numbers[8:], repository.nonce)
	proofInput = append(proofInput, numbers[:]...)
	proof := sha256.Sum256(proofInput)
	permit := DispatchPermit{
		Proof: OpaqueDispatchPermit(proof), Durable: true, Scope: request.CurrentScope,
		InvocationID: current.Scope.InvocationID, RequestDigest: current.RequestDigest,
		ProviderID: current.ProviderID, Attempt: attempt.Attempt, EffectRevision: request.Next.Revision,
		Authorization: request.Authorization,
	}
	repository.effects[key] = cloneEffect(request.Next)
	repository.claims[claimKey] = permit
	return permit, nil
}

func (repository *MemoryRepository) ClaimProviderStart(
	ctx context.Context,
	request ProviderStartClaimRequest,
) (ProviderStartPermit, error) {
	if err := ctx.Err(); err != nil {
		return ProviderStartPermit{}, err
	}
	if request.Lease <= 0 || request.Lease > 30*time.Second {
		return ProviderStartPermit{}, ErrInvalidRequest
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	invocationKey := request.Effect.Scope.InvocationID.String()
	current, found := repository.effects[invocationKey]
	if !found {
		return ProviderStartPermit{}, ErrInvocationNotFound
	}
	if !sameEffect(current, request.Effect) || current.State != StateDispatching || current.CancellationRequested {
		return ProviderStartPermit{}, ErrConcurrentTransition
	}
	if !sameOperationScope(request.CurrentScope, current.Scope) ||
		!sameFence(repository.scopes[keyForScope(current.Scope)], request.CurrentScope) {
		return ProviderStartPermit{}, ErrStaleAuthority
	}
	if repository.active[keyForScope(current.Scope)] != invocationKey {
		return ProviderStartPermit{}, ErrEffectInFlight
	}
	attempt, ok := current.CurrentAttempt()
	if !ok || attempt.Negotiation == (StartNegotiationReceipt{}) {
		return ProviderStartPermit{}, ErrInvalidTransition
	}
	claimKey := dispatchClaimKey(invocationKey, attempt.Attempt)
	if request.Dispatch == (DispatchPermit{}) || repository.claims[claimKey] != request.Dispatch ||
		request.Dispatch.Scope != request.CurrentScope || request.Dispatch.InvocationID != current.Scope.InvocationID ||
		request.Dispatch.RequestDigest != current.RequestDigest || request.Dispatch.ProviderID != current.ProviderID ||
		request.Dispatch.Attempt != attempt.Attempt {
		return ProviderStartPermit{}, ErrDispatchNotDurable
	}
	now := repository.now()
	if existing, exists := repository.providerStarts[claimKey]; exists {
		if existing.Status == providerStartActive && existing.Permit.Scope == request.CurrentScope &&
			existing.Permit.EffectRevision == current.Revision && existing.Permit.Dispatch == request.Dispatch &&
			existing.Permit.Negotiation == attempt.Negotiation && now.UnixNano() < existing.Permit.LeaseExpiresAtUnixNano {
			return existing.Permit, nil
		}
		return ProviderStartPermit{}, ErrConcurrentTransition
	}
	repository.nonce++
	proofInput := append([]byte("mcp.provider.start\x00"), []byte(claimKey)...)
	var nonce [8]byte
	binary.BigEndian.PutUint64(nonce[:], repository.nonce)
	proofInput = append(proofInput, nonce[:]...)
	permit := ProviderStartPermit{
		Proof: OpaqueProviderStartPermit(sha256.Sum256(proofInput)), Durable: true, Scope: request.CurrentScope,
		InvocationID: current.Scope.InvocationID, RequestDigest: current.RequestDigest, ProviderID: current.ProviderID,
		Attempt: attempt.Attempt, EffectRevision: current.Revision, ClaimGeneration: 1,
		LeaseExpiresAtUnixNano: now.Add(request.Lease).UnixNano(), Dispatch: request.Dispatch,
		Negotiation: attempt.Negotiation,
	}
	repository.providerStarts[claimKey] = providerStartRecord{Permit: permit, Status: providerStartActive}
	return permit, nil
}

func (repository *MemoryRepository) ResolveProviderStart(
	ctx context.Context,
	request ProviderStartResolutionRequest,
) (StoredProviderStartResolution, error) {
	if err := ctx.Err(); err != nil {
		return StoredProviderStartResolution{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	invocationKey := request.Effect.Scope.InvocationID.String()
	current, found := repository.effects[invocationKey]
	if !found {
		return StoredProviderStartResolution{}, ErrInvocationNotFound
	}
	if !sameEffect(current, request.Effect) {
		return StoredProviderStartResolution{}, ErrConcurrentTransition
	}
	if !sameOperationScope(request.CurrentScope, current.Scope) ||
		!sameFence(repository.scopes[keyForScope(current.Scope)], request.CurrentScope) {
		return StoredProviderStartResolution{}, ErrStaleAuthority
	}
	attempt, ok := current.CurrentAttempt()
	if !ok {
		return StoredProviderStartResolution{}, ErrInvalidTransition
	}
	claimKey := dispatchClaimKey(invocationKey, attempt.Attempt)
	start, exists := repository.providerStarts[claimKey]
	if !exists {
		if current.State != StateDispatching || attempt.ProviderRequestID != "" {
			return StoredProviderStartResolution{}, ErrStoreUnavailable
		}
		repository.providerStarts[claimKey] = providerStartRecord{Status: providerStartRevoked}
		return StoredProviderStartResolution{Durable: true}, nil
	}
	if start.Status == providerStartRevoked && start.Permit == (ProviderStartPermit{}) {
		return StoredProviderStartResolution{Durable: true}, nil
	}
	if start.Status == providerStartActive {
		now := repository.now()
		if sameFence(start.Permit.Scope, request.CurrentScope) && now.UnixNano() < start.Permit.LeaseExpiresAtUnixNano {
			return StoredProviderStartResolution{
				Permit: start.Permit, Present: true, Durable: true, Active: true,
				RetryAfter: time.Duration(start.Permit.LeaseExpiresAtUnixNano - now.UnixNano()),
			}, nil
		}
		start.Status = providerStartRevoked
		repository.providerStarts[claimKey] = start
	}
	return StoredProviderStartResolution{Permit: start.Permit, Present: true, Durable: true}, nil
}

func (repository *MemoryRepository) Commit(ctx context.Context, request TransitionCommitRequest) (StoredEffect, error) {
	if err := ctx.Err(); err != nil {
		return StoredEffect{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	key := request.Previous.Scope.InvocationID.String()
	current, found := repository.effects[key]
	if !found {
		return StoredEffect{}, ErrInvocationNotFound
	}
	if current.Revision != request.ExpectedRevision || !sameEffect(current, request.Previous) {
		return StoredEffect{}, ErrConcurrentTransition
	}
	if !sameOperationScope(request.CurrentScope, current.Scope) ||
		!sameFence(repository.scopes[keyForScope(current.Scope)], request.CurrentScope) {
		return StoredEffect{}, ErrStaleAuthority
	}
	if request.Next.Revision != request.ExpectedRevision+1 || !sameImmutableEffect(current, request.Next) {
		return StoredEffect{}, ErrInvalidTransition
	}
	cancellationIntent := !current.CancellationRequested && request.Next.CancellationRequested &&
		request.Next.State == StateCancellationPending &&
		(current.State == StateDispatching || current.State == StateDispatched || current.State == StateStreaming ||
			current.State == StateUncertain || current.State == StateNeedsConfirmation || current.State == StateFailed)
	if _, required := repository.parentCancellationRequired[key]; required && !cancellationIntent {
		return StoredEffect{}, ErrEffectInFlight
	}
	var startKey string
	var nextStart providerStartRecord
	writeStart := false
	if attempt, ok := current.CurrentAttempt(); ok {
		startKey = dispatchClaimKey(key, attempt.Attempt)
		start, exists := repository.providerStarts[startKey]
		switch {
		case request.ProviderStart != nil:
			if current.State != StateDispatching || !exists || start.Status != providerStartActive ||
				start.Permit != *request.ProviderStart {
				return StoredEffect{}, ErrConcurrentTransition
			}
			nextStart = start
			nextStart.Status = providerStartCompleted
			writeStart = true
		case exists && start.Status == providerStartActive:
			now := repository.now()
			if !cancellationIntent && sameFence(start.Permit.Scope, request.CurrentScope) &&
				now.UnixNano() < start.Permit.LeaseExpiresAtUnixNano {
				return StoredEffect{}, ErrEffectInFlight
			}
			nextStart = start
			nextStart.Status = providerStartRevoked
			writeStart = true
		}
	} else if request.ProviderStart != nil {
		return StoredEffect{}, ErrInvalidTransition
	}
	if request.Cancellation != nil {
		attempt, ok := current.CurrentAttempt()
		if !ok || current.State != StateCancellationPending ||
			repository.cancellationClaims[dispatchClaimKey(key, attempt.Attempt)] != *request.Cancellation {
			return StoredEffect{}, ErrConcurrentTransition
		}
	}
	var abandonedKey serverRequestKey
	var abandonedRecord ServerRequestRecord
	var abandonedPermit ServerRequestPermit
	createChildReconciliation := false
	abandonServerRequest := false
	if _, pending := repository.serverRequestReconciliations[key]; pending {
		return StoredEffect{}, ErrEffectInFlight
	}
	if childKey, active := repository.activeServerRequests[key]; active {
		record, found := repository.serverRequests[childKey]
		now := repository.now()
		if !found || record.State != ServerRequestClaimed ||
			(!cancellationIntent && now.UnixNano() < record.Permit.LeaseExpiresAtUnixNano) {
			return StoredEffect{}, ErrEffectInFlight
		}
		originalPermit := record.Permit
		record.State = ServerRequestAbandoned
		record.Permit.Scope = request.CurrentScope
		record.Permit.ClaimGeneration++
		record.Permit.LeaseExpiresAtUnixNano = now.UnixNano()
		abandonedKey = childKey
		abandonedRecord = record
		abandonServerRequest = true
		if record.BrokerCancellationRequired &&
			(record.Method == string(ServerRequestSampling) || record.Method == string(ServerRequestElicitation)) {
			abandonedPermit = originalPermit
			createChildReconciliation = true
		}
	}
	scope := keyForScope(current.Scope)
	activeInvocation, active := repository.active[scope]
	if active && activeInvocation != key {
		return StoredEffect{}, ErrEffectInFlight
	}
	if !active && !current.Terminal() {
		return StoredEffect{}, ErrEffectInFlight
	}
	auditCount := uint64(0)
	if request.Audit != nil {
		auditCount++
	}
	if abandonServerRequest {
		auditCount++
	}
	if auditCount > ^uint64(0)-repository.auditSequence {
		return StoredEffect{}, ErrStoreUnavailable
	}
	audit, err := repository.enqueueAuditLocked(request.Audit)
	if err != nil {
		return StoredEffect{}, err
	}
	if abandonServerRequest {
		abandonAudit := serverRequestAbandonAudit(current, abandonedRecord)
		abandonEnvelope, enqueueErr := repository.enqueueAuditLocked(&abandonAudit)
		if enqueueErr != nil {
			return StoredEffect{}, enqueueErr
		}
		abandonedRecord.AuditSequence = abandonEnvelope.Sequence
	}
	if !active && !request.Next.Terminal() {
		repository.active[scope] = key
	}
	if writeStart {
		repository.providerStarts[startKey] = nextStart
	}
	if abandonServerRequest {
		repository.serverRequests[abandonedKey] = abandonedRecord
		delete(repository.activeServerRequests, key)
		if createChildReconciliation {
			repository.serverRequestReconciliations[key] = abandonedKey
			repository.serverRequestCancellationPermits[abandonedKey] = abandonedPermit
		}
	}
	repository.effects[key] = cloneEffect(request.Next)
	if cancellationIntent {
		delete(repository.parentCancellationRequired, key)
	}
	// A terminal parent cannot release its turn while a nested broker side
	// effect still needs a durable cancellation receipt. The completion method
	// consumes that obligation and releases the slot in the same lock domain.
	if request.Next.Terminal() && !retainsLateProviderOwner(request.Next) &&
		!createChildReconciliation && repository.active[scope] == key {
		delete(repository.active, scope)
		if attempt, ok := request.Next.CurrentAttempt(); ok {
			delete(repository.cancellationClaims, dispatchClaimKey(key, attempt.Attempt))
		}
	}
	return StoredEffect{Effect: cloneEffect(request.Next), Durable: true, Audit: audit}, nil
}

func (repository *MemoryRepository) ReconcileServerRequests(
	ctx context.Context,
	request ServerRequestReconcileRequest,
) (ServerRequestReconcileResult, error) {
	if err := ctx.Err(); err != nil {
		return ServerRequestReconcileResult{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	invocationKey := request.Parent.Scope.InvocationID.String()
	current, found := repository.effects[invocationKey]
	if !found {
		return ServerRequestReconcileResult{}, ErrInvocationNotFound
	}
	if !sameOperationScope(request.CurrentScope, current.Scope) ||
		!sameFence(repository.scopes[keyForScope(current.Scope)], request.CurrentScope) {
		return ServerRequestReconcileResult{}, ErrStaleAuthority
	}
	if pendingKey, pending := repository.serverRequestReconciliations[invocationKey]; pending {
		if !sameEffect(current, request.Parent) {
			return ServerRequestReconcileResult{}, ErrConcurrentTransition
		}
		record, found := repository.serverRequests[pendingKey]
		permit, permitFound := repository.serverRequestCancellationPermits[pendingKey]
		if !found || !permitFound || record.State != ServerRequestAbandoned || !record.BrokerCancellationRequired ||
			(record.Method != string(ServerRequestSampling) && record.Method != string(ServerRequestElicitation)) {
			return ServerRequestReconcileResult{}, ErrStoreUnavailable
		}
		_, parentCancelRequired := repository.parentCancellationRequired[invocationKey]
		return ServerRequestReconcileResult{
			Durable: true, PendingCancellation: true, ParentCancelRequired: parentCancelRequired,
			Record:            cloneServerRequestRecord(record),
			CancellationClaim: permit,
		}, nil
	}
	key, active := repository.activeServerRequests[invocationKey]
	if !active {
		_, required := repository.parentCancellationRequired[invocationKey]
		return ServerRequestReconcileResult{Durable: true, ParentCancelRequired: required}, nil
	}
	if !sameEffect(current, request.Parent) {
		return ServerRequestReconcileResult{}, ErrConcurrentTransition
	}
	record, found := repository.serverRequests[key]
	if !found || record.State != ServerRequestClaimed {
		return ServerRequestReconcileResult{}, ErrStoreUnavailable
	}
	now := repository.now()
	if now.UnixNano() < record.Permit.LeaseExpiresAtUnixNano {
		return ServerRequestReconcileResult{
			Durable: true, Active: true,
			RetryAfter: time.Duration(record.Permit.LeaseExpiresAtUnixNano - now.UnixNano()),
		}, nil
	}
	originalPermit := record.Permit
	record.State = ServerRequestAbandoned
	record.Permit.Scope = request.CurrentScope
	record.Permit.ClaimGeneration++
	record.Permit.LeaseExpiresAtUnixNano = now.UnixNano()
	abandonAudit := serverRequestAbandonAudit(current, record)
	audit, err := repository.enqueueAuditLocked(&abandonAudit)
	if err != nil {
		return ServerRequestReconcileResult{}, err
	}
	record.AuditSequence = audit.Sequence
	repository.serverRequests[key] = record
	delete(repository.activeServerRequests, invocationKey)
	repository.parentCancellationRequired[invocationKey] = key
	result := ServerRequestReconcileResult{
		Durable: true, Reconciled: true, ParentCancelRequired: true, Record: cloneServerRequestRecord(record),
	}
	if record.BrokerCancellationRequired &&
		(record.Method == string(ServerRequestSampling) || record.Method == string(ServerRequestElicitation)) {
		repository.serverRequestReconciliations[invocationKey] = key
		repository.serverRequestCancellationPermits[key] = originalPermit
		result.PendingCancellation = true
		result.CancellationClaim = originalPermit
	}
	return result, nil
}

func serverRequestAbandonAudit(effect Effect, record ServerRequestRecord) AuditEvent {
	return AuditEvent{
		TenantID: effect.Scope.TenantID, UserID: effect.Scope.UserID, SessionID: effect.Scope.SessionID,
		TurnID: effect.Scope.TurnID, InvocationID: effect.Scope.InvocationID, ServerID: effect.ServerID,
		Method: normalizedServerRequestAuditMethod(record.Method), Decision: "failed",
		Reason: "server request abandoned before completion",
	}
}

func (repository *MemoryRepository) CompleteServerRequestReconciliation(
	ctx context.Context,
	request ServerRequestReconcileCommitRequest,
) (StoredServerRequest, error) {
	if err := ctx.Err(); err != nil {
		return StoredServerRequest{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	invocationKey := request.Permit.ParentInvocationID.String()
	current, found := repository.effects[invocationKey]
	if !found {
		return StoredServerRequest{}, ErrInvocationNotFound
	}
	if !sameOperationScope(request.CurrentScope, current.Scope) ||
		!sameFence(repository.scopes[keyForScope(current.Scope)], request.CurrentScope) {
		return StoredServerRequest{}, ErrStaleAuthority
	}
	key, pending := repository.serverRequestReconciliations[invocationKey]
	if !pending || repository.serverRequestCancellationPermits[key] != request.Permit {
		return StoredServerRequest{}, ErrInvocationConflict
	}
	record, found := repository.serverRequests[key]
	if !found || record.State != ServerRequestAbandoned || !record.BrokerCancellationRequired ||
		(record.Method != string(ServerRequestSampling) && record.Method != string(ServerRequestElicitation)) {
		return StoredServerRequest{}, ErrStoreUnavailable
	}
	switch record.Method {
	case string(ServerRequestSampling):
		cancellationRequest := SamplingCancellationRequest{
			Scope: request.CurrentScope, ParentEffectID: current.Scope.EffectID,
			ParentInvocationID: current.Scope.InvocationID, RequestDigest: request.Permit.RequestDigest,
			Claim: request.Permit,
		}
		if request.ElicitationCancellation != (ElicitationCancellationReceipt{}) ||
			!validSamplingCancellationReceipt(request.Cancellation, cancellationRequest) {
			return StoredServerRequest{}, ErrServerRequestDenied
		}
		record.ChildCancellation = request.Cancellation
	case string(ServerRequestElicitation):
		cancellationRequest := ElicitationCancellationRequest{
			Scope: request.CurrentScope, ParentEffectID: current.Scope.EffectID,
			ParentInvocationID: current.Scope.InvocationID, RequestDigest: request.Permit.RequestDigest,
			Claim: request.Permit,
		}
		if request.Cancellation != (SamplingCancellationReceipt{}) ||
			!validElicitationCancellationReceipt(request.ElicitationCancellation, cancellationRequest) {
			return StoredServerRequest{}, ErrServerRequestDenied
		}
		record.ElicitationCancellation = request.ElicitationCancellation
	}
	repository.serverRequests[key] = record
	delete(repository.serverRequestReconciliations, invocationKey)
	delete(repository.serverRequestCancellationPermits, key)
	if current.Terminal() && !retainsLateProviderOwner(current) {
		scope := keyForScope(current.Scope)
		if repository.active[scope] == invocationKey {
			delete(repository.active, scope)
			if attempt, ok := current.CurrentAttempt(); ok {
				delete(repository.cancellationClaims, dispatchClaimKey(invocationKey, attempt.Attempt))
			}
		}
	}
	return StoredServerRequest{Record: cloneServerRequestRecord(record), Durable: true, Fresh: true}, nil
}

// Unknown outcomes may still have a late provider owner or committed external
// work. Definitely-not-sent/rejected/absent failures do not retain the slot.
func retainsLateProviderOwner(effect Effect) bool {
	if effect.State == StateUncertain {
		return true
	}
	if effect.State != StateFailed {
		return false
	}
	attempt, ok := effect.CurrentAttempt()
	return ok && attempt.Failure == FailureUnknown
}

func (repository *MemoryRepository) ClaimServerRequest(
	ctx context.Context,
	request ServerRequestClaimRequest,
) (StoredServerRequest, error) {
	if err := ctx.Err(); err != nil {
		return StoredServerRequest{}, err
	}
	if request.Lease <= 0 || request.Lease > 30*time.Second || request.ConnectionGeneration == 0 ||
		request.MaxRequests == 0 || request.MaxRequests > hardMaxEvents {
		return StoredServerRequest{}, ErrInvalidRequest
	}
	if request.BrokerCancellationRequired && request.Method == string(ServerRequestSampling) {
		if request.ChildEffectID.Kind() != identity.Effect || request.ChildInvocationID.Kind() != identity.Invocation {
			return StoredServerRequest{}, ErrInvalidRequest
		}
	} else if request.ChildEffectID != (identity.ID{}) || request.ChildInvocationID != (identity.ID{}) {
		return StoredServerRequest{}, ErrInvalidRequest
	}
	if request.BrokerCancellationRequired && request.Method != string(ServerRequestSampling) &&
		request.Method != string(ServerRequestElicitation) {
		return StoredServerRequest{}, ErrInvalidRequest
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	invocationKey := request.Parent.Scope.InvocationID.String()
	current, found := repository.effects[invocationKey]
	if !found {
		return StoredServerRequest{}, ErrInvocationNotFound
	}
	if !sameOperationScope(request.CurrentScope, current.Scope) ||
		!sameFence(repository.scopes[keyForScope(current.Scope)], request.CurrentScope) {
		return StoredServerRequest{}, ErrStaleAuthority
	}
	if limit, exists := repository.serverRequestLimits[invocationKey]; exists {
		if limit != request.MaxRequests {
			return StoredServerRequest{}, ErrInvalidRequest
		}
	} else if repository.serverRequestCounts[invocationKey] != 0 {
		return StoredServerRequest{}, ErrStoreUnavailable
	}
	if _, required := repository.parentCancellationRequired[invocationKey]; required {
		return StoredServerRequest{}, ErrInvalidTransition
	}
	if _, pending := repository.serverRequestReconciliations[invocationKey]; pending {
		return StoredServerRequest{}, ErrEffectInFlight
	}
	key := serverRequestKey{
		invocation: request.Parent.Scope.InvocationID, providerRequestID: request.ProviderRequestID,
		connectionGeneration: request.ConnectionGeneration, requestID: request.RequestID,
	}
	if existing, exists := repository.serverRequests[key]; exists {
		if existing.ParentInvocationID != request.Parent.Scope.InvocationID || existing.ProviderRequestID != request.ProviderRequestID ||
			existing.ConnectionGeneration != request.ConnectionGeneration || existing.RequestID != request.RequestID ||
			existing.Method != request.Method || existing.RequestDigest != request.RequestDigest ||
			existing.BrokerCancellationRequired != request.BrokerCancellationRequired {
			return StoredServerRequest{}, ErrInvocationConflict
		}
		if existing.State == ServerRequestCompleted {
			return StoredServerRequest{Record: cloneServerRequestRecord(existing), Durable: true}, nil
		}
		if existing.State != ServerRequestClaimed {
			return StoredServerRequest{}, ErrInvalidTransition
		}
		switch current.State {
		case StateDispatched, StateStreaming:
		default:
			return StoredServerRequest{}, ErrInvalidTransition
		}
		attempt, ok := current.CurrentAttempt()
		if !ok || attempt.ProviderRequestID != request.ProviderRequestID ||
			attempt.Negotiation.ConnectionGeneration != request.ConnectionGeneration {
			return StoredServerRequest{}, ErrAuthorityMismatch
		}
		now := repository.now()
		if sameFence(existing.Permit.Scope, request.CurrentScope) && now.UnixNano() < existing.Permit.LeaseExpiresAtUnixNano {
			return StoredServerRequest{
				Record: cloneServerRequestRecord(existing), Durable: true,
				RetryAfter: time.Duration(existing.Permit.LeaseExpiresAtUnixNano - now.UnixNano()),
			}, nil
		}
		existing.Permit.Scope = request.CurrentScope
		existing.Permit.ClaimGeneration++
		existing.Permit.LeaseExpiresAtUnixNano = now.Add(request.Lease).UnixNano()
		repository.serverRequests[key] = existing
		repository.activeServerRequests[invocationKey] = key
		return StoredServerRequest{Record: cloneServerRequestRecord(existing), Durable: true, Fresh: true}, nil
	}
	if !sameEffect(current, request.Parent) {
		return StoredServerRequest{}, ErrInvalidTransition
	}
	switch current.State {
	case StateDispatched, StateStreaming:
	default:
		return StoredServerRequest{}, ErrInvalidTransition
	}
	attempt, ok := current.CurrentAttempt()
	if !ok || attempt.ProviderRequestID != request.ProviderRequestID ||
		attempt.Negotiation.ConnectionGeneration != request.ConnectionGeneration {
		return StoredServerRequest{}, ErrAuthorityMismatch
	}
	if repository.serverRequestCounts[invocationKey] >= request.MaxRequests {
		limitAudit := AuditEvent{
			TenantID: current.Scope.TenantID, UserID: current.Scope.UserID, SessionID: current.Scope.SessionID,
			TurnID: current.Scope.TurnID, InvocationID: current.Scope.InvocationID, ServerID: current.ServerID,
			Method: normalizedServerRequestAuditMethod(request.Method), Decision: "denied",
			Reason: "server request limit exceeded",
		}
		if _, err := repository.enqueueAuditLocked(&limitAudit); err != nil {
			return StoredServerRequest{}, err
		}
		repository.parentCancellationRequired[invocationKey] = key
		return StoredServerRequest{}, ErrEventLimit
	}
	if _, active := repository.activeServerRequests[invocationKey]; active {
		return StoredServerRequest{}, ErrEffectInFlight
	}
	repository.nonce++
	proofInput := make([]byte, 0, len(invocationKey)+len(request.ProviderRequestID)+len(request.RequestID)+8)
	proofInput = append(proofInput, invocationKey...)
	proofInput = append(proofInput, request.ProviderRequestID...)
	var connection [8]byte
	binary.BigEndian.PutUint64(connection[:], request.ConnectionGeneration)
	proofInput = append(proofInput, connection[:]...)
	proofInput = append(proofInput, request.RequestID...)
	var nonce [8]byte
	binary.BigEndian.PutUint64(nonce[:], repository.nonce)
	proofInput = append(proofInput, nonce[:]...)
	proof := sha256.Sum256(proofInput)
	now := repository.now()
	permit := ServerRequestPermit{
		Proof: OpaqueServerRequestPermit(proof), Durable: true, Scope: request.CurrentScope,
		ParentInvocationID: request.Parent.Scope.InvocationID, ProviderRequestID: request.ProviderRequestID,
		ConnectionGeneration: request.ConnectionGeneration, RequestID: request.RequestID, RequestDigest: request.RequestDigest,
		ChildEffectID: request.ChildEffectID, ChildInvocationID: request.ChildInvocationID,
		ClaimGeneration: 1, LeaseExpiresAtUnixNano: now.Add(request.Lease).UnixNano(),
	}
	record := ServerRequestRecord{
		State: ServerRequestClaimed, ParentInvocationID: request.Parent.Scope.InvocationID,
		ProviderRequestID: request.ProviderRequestID, ConnectionGeneration: request.ConnectionGeneration, RequestID: request.RequestID,
		Method: request.Method, RequestDigest: request.RequestDigest,
		BrokerCancellationRequired: request.BrokerCancellationRequired, Permit: permit,
	}
	repository.serverRequests[key] = record
	repository.serverRequestLimits[invocationKey] = request.MaxRequests
	repository.serverRequestCounts[invocationKey]++
	repository.activeServerRequests[invocationKey] = key
	return StoredServerRequest{Record: cloneServerRequestRecord(record), Durable: true, Fresh: true}, nil
}

func (repository *MemoryRepository) CompleteServerRequest(
	ctx context.Context,
	request ServerRequestCommitRequest,
) (StoredServerRequest, error) {
	if err := ctx.Err(); err != nil {
		return StoredServerRequest{}, err
	}
	if request.Audit == nil {
		return StoredServerRequest{}, ErrInvalidRequest
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	key := serverRequestKey{
		invocation:           request.Permit.ParentInvocationID,
		providerRequestID:    request.Permit.ProviderRequestID,
		connectionGeneration: request.Permit.ConnectionGeneration,
		requestID:            request.Permit.RequestID,
	}
	record, found := repository.serverRequests[key]
	if !found {
		return StoredServerRequest{}, ErrInvocationNotFound
	}
	current, found := repository.effects[request.Permit.ParentInvocationID.String()]
	if !found {
		return StoredServerRequest{}, ErrInvocationNotFound
	}
	if !sameOperationScope(request.CurrentScope, current.Scope) ||
		!sameFence(repository.scopes[keyForScope(current.Scope)], request.CurrentScope) {
		return StoredServerRequest{}, ErrStaleAuthority
	}
	if record.Permit != request.Permit {
		return StoredServerRequest{}, ErrInvocationConflict
	}
	if record.State == ServerRequestCompleted {
		if record.Response.RequestID != request.Response.RequestID ||
			!bytes.Equal(record.Response.ResultCanonical, request.Response.ResultCanonical) ||
			(record.Response.Error == nil) != (request.Response.Error == nil) ||
			(record.Response.Error != nil && *record.Response.Error != *request.Response.Error) {
			return StoredServerRequest{}, ErrInvocationConflict
		}
		return StoredServerRequest{Record: cloneServerRequestRecord(record), Durable: true}, nil
	}
	if repository.activeServerRequests[request.Permit.ParentInvocationID.String()] != key {
		return StoredServerRequest{}, ErrEffectInFlight
	}
	if request.SamplingCancellation != (SamplingCancellationReceipt{}) {
		if record.Method != string(ServerRequestSampling) || !validSamplingCancellationReceipt(
			request.SamplingCancellation,
			SamplingCancellationRequest{
				Scope: request.CurrentScope, ParentEffectID: current.Scope.EffectID,
				ParentInvocationID: current.Scope.InvocationID, RequestDigest: request.Permit.RequestDigest,
				Claim: request.Permit,
			},
		) {
			return StoredServerRequest{}, ErrServerRequestDenied
		}
		record.ChildCancellation = request.SamplingCancellation
	}
	if request.ElicitationCancellation != (ElicitationCancellationReceipt{}) {
		if record.Method != string(ServerRequestElicitation) || !validElicitationCancellationReceipt(
			request.ElicitationCancellation,
			ElicitationCancellationRequest{
				Scope: request.CurrentScope, ParentEffectID: current.Scope.EffectID,
				ParentInvocationID: current.Scope.InvocationID, RequestDigest: request.Permit.RequestDigest,
				Claim: request.Permit,
			},
		) {
			return StoredServerRequest{}, ErrServerRequestDenied
		}
		record.ElicitationCancellation = request.ElicitationCancellation
	}
	record.State = ServerRequestCompleted
	record.Response = cloneServerResponse(request.Response)
	audit, err := repository.enqueueAuditLocked(request.Audit)
	if err != nil {
		return StoredServerRequest{}, err
	}
	if audit != nil {
		record.AuditSequence = audit.Sequence
	}
	repository.serverRequests[key] = record
	delete(repository.activeServerRequests, request.Permit.ParentInvocationID.String())
	return StoredServerRequest{Record: cloneServerRequestRecord(record), Durable: true, Fresh: true, Audit: audit}, nil
}

func (repository *MemoryRepository) PendingAudits(ctx context.Context, limit uint32) ([]AuditEnvelope, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limit == 0 || limit > hardMaxEvents {
		return nil, ErrInvalidRequest
	}
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	result := make([]AuditEnvelope, 0, limit)
	for sequence := uint64(1); sequence <= repository.auditSequence && uint32(len(result)) < limit; sequence++ {
		if envelope, found := repository.pendingAudits[sequence]; found {
			result = append(result, envelope)
		}
	}
	return result, nil
}

func (repository *MemoryRepository) AppendAudit(ctx context.Context, event AuditEvent) (AuditEnvelope, error) {
	if err := ctx.Err(); err != nil {
		return AuditEnvelope{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	envelope, err := repository.enqueueAuditLocked(&event)
	if err != nil {
		return AuditEnvelope{}, err
	}
	return *envelope, nil
}

func (repository *MemoryRepository) AcknowledgeAudit(ctx context.Context, sequence uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if sequence == 0 {
		return ErrInvalidRequest
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	delete(repository.pendingAudits, sequence)
	return nil
}

func (repository *MemoryRepository) enqueueAuditLocked(event *AuditEvent) (*AuditEnvelope, error) {
	if event == nil {
		return nil, nil
	}
	if repository.auditSequence == ^uint64(0) {
		return nil, ErrStoreUnavailable
	}
	repository.auditSequence++
	copy := *event
	copy.OutboxSequence = repository.auditSequence
	envelope := AuditEnvelope{Sequence: repository.auditSequence, Event: copy}
	repository.pendingAudits[envelope.Sequence] = envelope
	return &envelope, nil
}

// SetCurrentAuthority models a durable generation rotation for tests and
// single-process development. It never rewrites already persisted effects.
func (repository *MemoryRepository) SetCurrentAuthority(scope ValidatedAuthority) error {
	if !validScope(scope) {
		return ErrInvalidRequest
	}
	repository.mu.Lock()
	repository.scopes[keyForScope(scope)] = scope
	repository.mu.Unlock()
	return nil
}

func keyForScope(scope ValidatedAuthority) scopeKey {
	return scopeKey{tenant: scope.TenantID, session: scope.SessionID, turn: scope.TurnID}
}

func sameFence(left, right ValidatedAuthority) bool {
	return left.TenantID == right.TenantID && left.UserID == right.UserID && left.SessionID == right.SessionID &&
		left.WorkspaceID == right.WorkspaceID && left.TurnID == right.TurnID &&
		left.RuntimeRevision == right.RuntimeRevision && left.Generations == right.Generations
}

func sameOperationScope(left, right ValidatedAuthority) bool {
	return left.TenantID == right.TenantID && left.UserID == right.UserID && left.SessionID == right.SessionID &&
		left.WorkspaceID == right.WorkspaceID && left.TurnID == right.TurnID &&
		left.EffectID == right.EffectID && left.InvocationID == right.InvocationID &&
		left.RuntimeRevision == right.RuntimeRevision
}

func dispatchClaimKey(invocation string, attempt uint32) string {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], attempt)
	return invocation + string(encoded[:])
}
