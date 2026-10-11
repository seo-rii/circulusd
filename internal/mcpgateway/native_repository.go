package mcpgateway

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"time"

	"github.com/hancomac/circulusd/internal/celld"
	"github.com/hancomac/circulusd/internal/celldbridge"
	"github.com/hancomac/circulusd/internal/dependency"
	"github.com/hancomac/circulusd/internal/identity"
)

// NativeRepositoryConfig selects one concrete native adapter and one bounded
// aggregate. A probe-only wrapper cannot supply the operational source.
type NativeRepositoryConfig struct {
	Source            dependency.Verified[*celldbridge.Storage]
	ObjectID          string
	MaximumRecords    int
	MaximumStateBytes int
}

func (NativeRepositoryConfig) String() string   { return "native-mcp-repository-config<redacted>" }
func (NativeRepositoryConfig) GoString() string { return "native-mcp-repository-config<redacted>" }

type nativeRepositorySource interface {
	celld.Storage
	dependency.ProductionProbe
}

// NativeRepository retains no authoritative state between calls. The existing
// transition machine is reconstructed inside each native transaction callback;
// its mutex protects only that callback's temporary working set. Every returned
// permit, effect and outbox row requires the exact native commit's barrier.
type NativeRepository struct {
	source         nativeRepositorySource
	binding        dependency.Binding
	descriptor     dependency.Descriptor
	check          func() error
	objectID       string
	maximumRecords int
	maximumBytes   int
	now            func() time.Time
	factory        *NativeFactory
}

func (*NativeRepository) String() string   { return "native-mcp-repository<redacted>" }
func (*NativeRepository) GoString() string { return "native-mcp-repository<redacted>" }

func nativeRepositoryGroups() []dependency.AtomicGroup {
	return []dependency.AtomicGroup{dependency.AtomicCommandReceipt, AtomicMCPAuditOutbox,
		AtomicMCPAuthorityFence, AtomicMCPEffectLifecycle, AtomicMCPAuthorization, AtomicMCPProviderDispatch}
}

func NewNativeRepository(config NativeRepositoryConfig) (*NativeRepository, error) {
	source, _, err := config.Source.Open()
	if err != nil || source == nil {
		return nil, dependency.ErrUnverifiedDependency
	}
	return newNativeRepository(source, config.Source, func() error {
		_, _, err := config.Source.Open()
		return err
	}, config.ObjectID, config.MaximumRecords, config.MaximumStateBytes, time.Now)
}

func newNativeRepository(source nativeRepositorySource, binding dependency.Binding, check func() error,
	objectID string, records, maximumBytes int, now func() time.Time) (*NativeRepository, error) {
	if isNilInterface(source) || check == nil || now == nil || !validIdentifier(objectID, 256) ||
		records < 1 || records > 16_384 || maximumBytes < 1024 || maximumBytes > celldbridge.MaximumStateBytes {
		return nil, ErrInvalidConfiguration
	}
	descriptor, err := dependency.RequireAtomicDomain(nativeRepositoryGroups(), binding)
	if err != nil {
		return nil, err
	}
	return &NativeRepository{source: source, binding: binding, descriptor: descriptor, check: check, objectID: objectID,
		maximumRecords: records, maximumBytes: maximumBytes, now: now}, nil
}

func (repository *NativeRepository) ready(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if repository == nil || isNilInterface(repository.source) || repository.check == nil {
		return ErrStoreUnavailable
	}
	if err := repository.check(); err != nil {
		return ErrStoreUnavailable
	}
	return nil
}

func (repository *NativeRepository) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	if err := repository.ready(ctx); err != nil {
		return dependency.ProbeResponse{}, err
	}
	return repository.source.ProbeProduction(ctx, challenge)
}

func (repository *NativeRepository) Durability() RepositoryDurability {
	if repository == nil || repository.check == nil || repository.check() != nil {
		return RepositoryDurability{}
	}
	return RepositoryDurability{CrashDurable: true, AtomicAdmissionCAS: true, AtomicAdmissionReplay: true,
		AtomicTransitionCAS: true, ExclusiveDispatchClaim: true, ExclusiveProviderStartClaim: true,
		AtomicProviderStartResolution: true, ExclusiveCancellationClaim: true,
		AtomicExpiredRequestReconciliation: true, AtomicCurrentFence: true, AtomicActiveEffect: true, AtomicAuditOutbox: true}
}

func nativeRepositoryError(ctx context.Context, err error) error {
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	for _, allowed := range []error{ErrInvalidRequest, ErrInvocationNotFound, ErrInvocationConflict, ErrConcurrentTransition,
		ErrStaleAuthority, ErrAuthorityMismatch, ErrAuthorizationMismatch, ErrToolNotAllowed, ErrAuditUnavailable,
		ErrEffectInFlight, ErrInvalidTransition, ErrDispatchNotDurable, ErrServerRequestDenied} {
		if errors.Is(err, allowed) {
			return allowed
		}
	}
	return ErrStoreUnavailable
}

func nativeRepositoryOperation[T any](ctx context.Context, repository *NativeRepository, operation func(*MemoryRepository) (T, error)) (T, error) {
	return nativeStateOperation(ctx, repository, func(state *nativeRepositoryState) (T, error) { return operation(state.Repository) })
}

func nativeStateOperation[T any](ctx context.Context, repository *NativeRepository, operation func(*nativeRepositoryState) (T, error)) (T, error) {
	var zero, result T
	if err := repository.ready(ctx); err != nil {
		return zero, err
	}
	var invoked, complete bool
	commit, err := repository.source.Transaction(ctx, repository.objectID, func(transaction celld.Transaction) error {
		invoked, complete, result = true, false, zero
		if isNilInterface(transaction) {
			return ErrStoreUnavailable
		}
		encoded, err := transaction.ReadState()
		if err != nil || len(encoded) > repository.maximumBytes {
			return ErrStoreUnavailable
		}
		working, err := decodeNativeState(encoded, repository.objectID, repository.maximumRecords, repository.maximumBytes)
		if err != nil {
			return ErrStoreUnavailable
		}
		working.Repository.now = repository.now
		result, err = operation(working)
		if err != nil {
			return err
		}
		next, err := encodeNativeState(working, repository.objectID, repository.maximumRecords, repository.maximumBytes)
		if err != nil {
			return ErrStoreUnavailable
		}
		if !bytes.Equal(encoded, next) {
			if err := transaction.WriteState(next); err != nil {
				return ErrStoreUnavailable
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		complete = true
		return nil
	})
	if err != nil {
		return zero, nativeRepositoryError(ctx, err)
	}
	if !invoked || !complete || commit.ObjectID != repository.objectID || commit.Revision == 0 {
		return zero, ErrStoreUnavailable
	}
	if err := repository.source.DurabilityBarrier(ctx, commit); err != nil {
		return zero, nativeRepositoryError(ctx, err)
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	return result, nil
}

// SetCurrentAuthority is a trusted operator operation. It writes the actual
// current fence into the same aggregate used by replay and dispatch claims;
// callers cannot rotate an in-process cache to obtain production authority.
func (repository *NativeRepository) SetCurrentAuthority(ctx context.Context, scope ValidatedAuthority) error {
	_, err := nativeRepositoryOperation(ctx, repository, func(working *MemoryRepository) (struct{}, error) {
		if current, found := working.scopes[keyForScope(scope)]; found &&
			(current.Generations.TurnLease > scope.Generations.TurnLease || current.Generations.Placement > scope.Generations.Placement ||
				current.Generations.Sandbox > scope.Generations.Sandbox || current.Generations.Policy > scope.Generations.Policy ||
				(current.Generations == scope.Generations && !sameFence(current, scope))) {
			return struct{}{}, ErrStaleAuthority
		}
		return struct{}{}, working.SetCurrentAuthority(scope)
	})
	return err
}

func (repository *NativeRepository) Admit(ctx context.Context, effect Effect) (StoredEffect, error) {
	return nativeStateOperation(ctx, repository, func(state *nativeRepositoryState) (StoredEffect, error) {
		working := state.Repository
		if repository.factory != nil && !repository.factory.authorizedEffect(state, effect) {
			return StoredEffect{}, ErrStaleAuthority
		}
		if current, found := working.scopes[keyForScope(effect.Scope)]; !found || !sameFence(current, effect.Scope) {
			return StoredEffect{}, ErrStaleAuthority
		}
		return working.Admit(ctx, effect)
	})
}
func (repository *NativeRepository) ReplayAdmission(ctx context.Context, request AdmissionReplayRequest) (StoredEffect, error) {
	return nativeRepositoryOperation(ctx, repository, func(working *MemoryRepository) (StoredEffect, error) { return working.ReplayAdmission(ctx, request) })
}
func (repository *NativeRepository) Load(ctx context.Context, invocation identity.ID) (StoredEffect, error) {
	return nativeRepositoryOperation(ctx, repository, func(working *MemoryRepository) (StoredEffect, error) { return working.Load(ctx, invocation) })
}
func (repository *NativeRepository) CommitAndClaimDispatch(ctx context.Context, request DispatchClaimRequest) (DispatchPermit, error) {
	return nativeStateOperation(ctx, repository, func(state *nativeRepositoryState) (DispatchPermit, error) {
		working := state.Repository
		if repository.factory != nil && (state.PolicyDigest != repository.factory.policyDigest ||
			state.ToolPermits[permitKey(request.Authorization.Proof)] != request.Authorization ||
			!repository.factory.currentGrant(state, request.CurrentScope, request.Previous.RequestDigest, "mcp.tools.call", true)) {
			return DispatchPermit{}, ErrAuthorizationMismatch
		}
		return working.CommitAndClaimDispatch(ctx, request)
	})
}
func (repository *NativeRepository) ClaimProviderStart(ctx context.Context, request ProviderStartClaimRequest) (ProviderStartPermit, error) {
	return nativeStateOperation(ctx, repository, func(state *nativeRepositoryState) (ProviderStartPermit, error) {
		if repository.factory != nil && !repository.factory.currentGrant(state, request.CurrentScope, request.Effect.RequestDigest, "mcp.tools.call", true) {
			return ProviderStartPermit{}, ErrStaleAuthority
		}
		return state.Repository.ClaimProviderStart(ctx, request)
	})
}
func (repository *NativeRepository) ResolveProviderStart(ctx context.Context, request ProviderStartResolutionRequest) (StoredProviderStartResolution, error) {
	return nativeRepositoryOperation(ctx, repository, func(working *MemoryRepository) (StoredProviderStartResolution, error) {
		return working.ResolveProviderStart(ctx, request)
	})
}
func (repository *NativeRepository) ClaimCancellation(ctx context.Context, request CancellationClaimRequest) (CancellationClaim, error) {
	return nativeRepositoryOperation(ctx, repository, func(working *MemoryRepository) (CancellationClaim, error) {
		return working.ClaimCancellation(ctx, request)
	})
}
func (repository *NativeRepository) Commit(ctx context.Context, request TransitionCommitRequest) (StoredEffect, error) {
	return nativeRepositoryOperation(ctx, repository, func(working *MemoryRepository) (StoredEffect, error) { return working.Commit(ctx, request) })
}
func (repository *NativeRepository) ClaimServerRequest(ctx context.Context, request ServerRequestClaimRequest) (StoredServerRequest, error) {
	return nativeRepositoryOperation(ctx, repository, func(working *MemoryRepository) (StoredServerRequest, error) {
		return working.ClaimServerRequest(ctx, request)
	})
}
func (repository *NativeRepository) ReconcileServerRequests(ctx context.Context, request ServerRequestReconcileRequest) (ServerRequestReconcileResult, error) {
	return nativeRepositoryOperation(ctx, repository, func(working *MemoryRepository) (ServerRequestReconcileResult, error) {
		return working.ReconcileServerRequests(ctx, request)
	})
}
func (repository *NativeRepository) CompleteServerRequestReconciliation(ctx context.Context, request ServerRequestReconcileCommitRequest) (StoredServerRequest, error) {
	return nativeRepositoryOperation(ctx, repository, func(working *MemoryRepository) (StoredServerRequest, error) {
		return working.CompleteServerRequestReconciliation(ctx, request)
	})
}
func (repository *NativeRepository) CompleteServerRequest(ctx context.Context, request ServerRequestCommitRequest) (StoredServerRequest, error) {
	return nativeRepositoryOperation(ctx, repository, func(working *MemoryRepository) (StoredServerRequest, error) {
		return working.CompleteServerRequest(ctx, request)
	})
}
func (repository *NativeRepository) AppendAudit(ctx context.Context, event AuditEvent) (AuditEnvelope, error) {
	return nativeRepositoryOperation(ctx, repository, func(working *MemoryRepository) (AuditEnvelope, error) { return working.AppendAudit(ctx, event) })
}
func (repository *NativeRepository) PendingAudits(ctx context.Context, limit uint32) ([]AuditEnvelope, error) {
	return nativeRepositoryOperation(ctx, repository, func(working *MemoryRepository) ([]AuditEnvelope, error) {
		if limit == 0 || limit > 1024 {
			return nil, ErrInvalidRequest
		}
		sequences := make([]uint64, 0, len(working.pendingAudits))
		for sequence := range working.pendingAudits {
			sequences = append(sequences, sequence)
		}
		sort.Slice(sequences, func(i, j int) bool { return sequences[i] < sequences[j] })
		result := make([]AuditEnvelope, 0, limit)
		for _, sequence := range sequences {
			if uint32(len(result)) == limit {
				break
			}
			result = append(result, working.pendingAudits[sequence])
		}
		return result, nil
	})
}
func (repository *NativeRepository) AcknowledgeAudit(ctx context.Context, sequence uint64) error {
	_, err := nativeRepositoryOperation(ctx, repository, func(working *MemoryRepository) (struct{}, error) {
		return struct{}{}, working.AcknowledgeAudit(ctx, sequence)
	})
	return err
}

var _ ProductionEffectRepository = (*NativeRepository)(nil)
