package agent

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/identity"
)

type requestIdentity struct {
	tenantID             identity.ID
	workerID             string
	profile              PlacementProfile
	estimatedMemoryBytes uint64
}

type shard struct {
	spec                   ShardSpec
	process                ShardProcess
	sessions               map[identity.ID]Placement
	estimatedResidentBytes uint64
	rssBytes               uint64
	draining               bool
}

type launchPending struct {
	done chan struct{}
}

type stopPending struct {
	process ShardProcess
	done    chan struct{}
	err     error
}

type trackedStop struct {
	shardID string
	pending *stopPending
	reason  string
}

// Manager serializes placement metadata while performing process launches
// outside its mutex. A per-scope pending barrier coalesces concurrent cold
// starts without making a launcher callback part of the critical section.
type Manager struct {
	mu                  sync.Mutex
	shutdownGate        chan struct{}
	launcher            Launcher
	limits              Limits
	shards              map[string]*shard
	placements          map[identity.ID]Placement
	latestGenerations   map[identity.ID]uint64
	releasedGenerations map[identity.ID]uint64
	requestIdentities   map[identity.ID]requestIdentity
	pendingSessions     map[identity.ID]*launchPending
	pendingScopes       map[string]*launchPending
	pendingStops        map[string]*stopPending
	nextShardSequence   uint64
	closed              bool
}

func NewManager(launcher Launcher, limits Limits) (*Manager, error) {
	if launcher == nil || limits.MaximumSessions <= 0 || limits.MemoryLimitBytes == 0 || limits.AdmissionMemoryWatermarkBytes == 0 || limits.AdmissionMemoryWatermarkBytes > limits.MemoryLimitBytes || limits.MaximumLifetime <= 0 {
		return nil, ErrInvalidConfig
	}
	shutdownGate := make(chan struct{}, 1)
	shutdownGate <- struct{}{}
	return &Manager{
		shutdownGate:        shutdownGate,
		launcher:            launcher,
		limits:              limits,
		shards:              make(map[string]*shard),
		placements:          make(map[identity.ID]Placement),
		latestGenerations:   make(map[identity.ID]uint64),
		releasedGenerations: make(map[identity.ID]uint64),
		requestIdentities:   make(map[identity.ID]requestIdentity),
		pendingSessions:     make(map[identity.ID]*launchPending),
		pendingScopes:       make(map[string]*launchPending),
		pendingStops:        make(map[string]*stopPending),
		nextShardSequence:   1,
	}, nil
}

func ValidateProfile(trust TrustClass, profile PlacementProfile) error {
	scopeStrength := -1
	switch profile.ProcessScope {
	case ScopeShared:
		scopeStrength = 0
	case ScopeTenant:
		scopeStrength = 1
	case ScopeSession:
		scopeStrength = 2
	default:
		return ErrInvalidRequest
	}
	isolationStrength := -1
	switch profile.OuterIsolation {
	case IsolationNone:
		isolationStrength = 0
	case IsolationNSJail, IsolationDocker:
		isolationStrength = 1
	case IsolationFirecracker:
		isolationStrength = 2
	default:
		return ErrInvalidRequest
	}
	minimumScope, minimumIsolation := 0, 0
	switch trust {
	case TrustPlatformReviewed:
	case TrustTenantReviewed:
		minimumScope = 1
	case TrustSignedThirdParty:
		minimumScope, minimumIsolation = 1, 1
	case TrustUnreviewed:
		minimumScope, minimumIsolation = 2, 2
	default:
		return ErrInvalidRequest
	}
	if scopeStrength < minimumScope || isolationStrength < minimumIsolation {
		return ErrIsolationDowngrade
	}
	return nil
}

func WorkerIdentity(sessionID identity.ID, runtime RuntimeIdentity) (string, error) {
	if sessionID.Kind() != identity.Session || !validDigest(runtime.RuntimeRevisionDigest) || runtime.PiAdapterABI == 0 {
		return "", ErrInvalidRequest
	}
	if _, err := time.Parse("2006-01-02", runtime.CompatibilityDate); err != nil {
		return "", fmt.Errorf("%w: compatibility date: %v", ErrInvalidRequest, err)
	}
	flags, err := canonical.NormalizeStringSet(runtime.CompatibilityFlags)
	if err != nil {
		return "", fmt.Errorf("%w: compatibility flags: %v", ErrInvalidRequest, err)
	}
	flagPayload := make(canonical.Array, len(flags))
	for index, flag := range flags {
		if flag == "" {
			return "", fmt.Errorf("%w: compatibility flag is empty", ErrInvalidRequest)
		}
		flagPayload[index] = flag
	}
	digest, err := canonical.StructuredDigest(
		"agent.worker-identity",
		1,
		canonical.Array{sessionID.String(), runtime.RuntimeRevisionDigest, runtime.PiAdapterABI, runtime.CompatibilityDate, flagPayload},
	)
	if err != nil {
		return "", fmt.Errorf("compute worker identity: %w", err)
	}
	return "pi/" + sessionID.String() + "/" + strings.Replace(digest, "sha256:", "sha256-", 1), nil
}

func (manager *Manager) Acquire(ctx context.Context, request PlacementRequest) (Placement, error) {
	if err := ctx.Err(); err != nil {
		return Placement{}, err
	}
	if manager == nil || manager.launcher == nil || request.TenantID.Kind() != identity.Tenant || request.SessionID.Kind() != identity.Session || request.PlacementGeneration == 0 || request.EstimatedMemoryBytes == 0 || request.Now.IsZero() || !validDigest(request.Runtime.RuntimeRevisionDigest) {
		return Placement{}, ErrInvalidRequest
	}
	if err := ValidateProfile(request.TrustClass, request.Profile); err != nil {
		return Placement{}, err
	}
	if request.EstimatedMemoryBytes > manager.limits.AdmissionMemoryWatermarkBytes || request.EstimatedMemoryBytes > manager.limits.MemoryLimitBytes {
		return Placement{}, ErrCapacity
	}
	workerID, err := WorkerIdentity(request.SessionID, request.Runtime)
	if err != nil {
		return Placement{}, err
	}
	fingerprint := requestIdentity{tenantID: request.TenantID, workerID: workerID, profile: request.Profile, estimatedMemoryBytes: request.EstimatedMemoryBytes}

	for {
		if err := ctx.Err(); err != nil {
			return Placement{}, err
		}
		var stopBeforePlacement *trackedStop
		manager.mu.Lock()
		if manager.closed {
			manager.mu.Unlock()
			return Placement{}, ErrManagerClosed
		}
		if pending := manager.pendingSessions[request.SessionID]; pending != nil {
			done := pending.done
			manager.mu.Unlock()
			select {
			case <-ctx.Done():
				return Placement{}, ctx.Err()
			case <-done:
				continue
			}
		}
		latest := manager.latestGenerations[request.SessionID]
		if request.PlacementGeneration < latest {
			manager.mu.Unlock()
			return Placement{}, ErrStalePlacement
		}
		if manager.releasedGenerations[request.SessionID] == request.PlacementGeneration {
			manager.mu.Unlock()
			return Placement{}, ErrStalePlacement
		}
		if request.PlacementGeneration == latest && latest != 0 {
			if existingIdentity := manager.requestIdentities[request.SessionID]; existingIdentity != fingerprint {
				manager.mu.Unlock()
				return Placement{}, ErrPlacementConflict
			}
			if existing, found := manager.placements[request.SessionID]; found {
				existing.Replayed = true
				manager.mu.Unlock()
				return existing, nil
			}
		}
		if request.PlacementGeneration > latest {
			oldIdentity := manager.requestIdentities[request.SessionID]
			manager.latestGenerations[request.SessionID] = request.PlacementGeneration
			manager.requestIdentities[request.SessionID] = fingerprint
			if existing, found := manager.placements[request.SessionID]; found {
				delete(manager.placements, request.SessionID)
				if oldShard := manager.shards[existing.ShardID]; oldShard != nil {
					delete(oldShard.sessions, request.SessionID)
					if oldShard.estimatedResidentBytes < oldIdentity.estimatedMemoryBytes {
						manager.mu.Unlock()
						return Placement{}, ErrInvalidConfig
					}
					oldShard.estimatedResidentBytes -= oldIdentity.estimatedMemoryBytes
					if existing.Profile.ProcessScope == ScopeSession {
						oldShard.draining = true
					}
					if oldShard.draining && len(oldShard.sessions) == 0 {
						delete(manager.shards, oldShard.spec.ShardID)
						pendingStop := manager.trackStopLocked(oldShard.spec.ShardID, oldShard.process)
						stopBeforePlacement = &trackedStop{
							shardID: oldShard.spec.ShardID, pending: pendingStop,
							reason: "stop replaced session shard",
						}
					}
				}
			}
		} else if latest == 0 {
			manager.latestGenerations[request.SessionID] = request.PlacementGeneration
			manager.requestIdentities[request.SessionID] = fingerprint
		}
		if stopBeforePlacement != nil {
			manager.mu.Unlock()
			if err := manager.executeTrackedStop(ctx, *stopBeforePlacement); err != nil {
				return Placement{}, err
			}
			continue
		}

		scopeKey := string(request.Profile.ProcessScope) + "/" + string(request.Profile.OuterIsolation)
		switch request.Profile.ProcessScope {
		case ScopeTenant:
			scopeKey += "/" + request.TenantID.String()
		case ScopeSession:
			scopeKey += "/" + request.SessionID.String()
		}
		candidates := make([]*shard, 0)
		expiredStops := make([]trackedStop, 0)
		for shardID, candidate := range manager.shards {
			if !request.Now.Before(candidate.spec.CreatedAt.Add(manager.limits.MaximumLifetime)) {
				candidate.draining = true
				if len(candidate.sessions) == 0 {
					delete(manager.shards, shardID)
					expiredStops = append(expiredStops, trackedStop{
						shardID: shardID,
						pending: manager.trackStopLocked(shardID, candidate.process),
						reason:  "stop expired workerd shard",
					})
				}
				continue
			}
			if candidate.spec.ScopeKey != scopeKey || candidate.spec.Profile != request.Profile || candidate.draining || len(candidate.sessions) >= manager.limits.MaximumSessions {
				continue
			}
			usedBytes := candidate.estimatedResidentBytes
			if candidate.rssBytes > usedBytes {
				usedBytes = candidate.rssBytes
			}
			if request.EstimatedMemoryBytes > manager.limits.AdmissionMemoryWatermarkBytes-usedBytes || request.EstimatedMemoryBytes > manager.limits.MemoryLimitBytes-usedBytes {
				continue
			}
			candidates = append(candidates, candidate)
		}
		if len(expiredStops) > 0 {
			manager.mu.Unlock()
			var stopErr error
			for _, stop := range expiredStops {
				if err := manager.executeTrackedStop(ctx, stop); err != nil {
					stopErr = errors.Join(stopErr, err)
				}
			}
			if stopErr != nil {
				return Placement{}, stopErr
			}
			continue
		}
		sort.Slice(candidates, func(left, right int) bool {
			if len(candidates[left].sessions) != len(candidates[right].sessions) {
				return len(candidates[left].sessions) < len(candidates[right].sessions)
			}
			return candidates[left].spec.ShardID < candidates[right].spec.ShardID
		})
		if len(candidates) > 0 {
			selected := candidates[0]
			placement := Placement{
				TenantID: request.TenantID, SessionID: request.SessionID,
				PlacementGeneration: request.PlacementGeneration,
				ShardID:             selected.spec.ShardID, WorkerID: workerID,
				Profile: request.Profile, AdmittedAt: request.Now,
			}
			selected.sessions[request.SessionID] = placement
			selected.estimatedResidentBytes += request.EstimatedMemoryBytes
			manager.placements[request.SessionID] = placement
			manager.mu.Unlock()
			return placement, nil
		}

		if pending := manager.pendingScopes[scopeKey]; pending != nil {
			done := pending.done
			manager.mu.Unlock()
			select {
			case <-ctx.Done():
				return Placement{}, ctx.Err()
			case <-done:
				continue
			}
		}
		pending := &launchPending{done: make(chan struct{})}
		manager.pendingScopes[scopeKey] = pending
		manager.pendingSessions[request.SessionID] = pending
		shardID := fmt.Sprintf("agent-shard-%020d", manager.nextShardSequence)
		manager.nextShardSequence++
		spec := ShardSpec{ShardID: shardID, ScopeKey: scopeKey, Profile: request.Profile, Limits: manager.limits, CreatedAt: request.Now}
		manager.mu.Unlock()

		process, launchErr := manager.launcher.Start(ctx, spec)
		var rejectedProcess ShardProcess
		manager.mu.Lock()
		delete(manager.pendingScopes, scopeKey)
		delete(manager.pendingSessions, request.SessionID)
		if launchErr == nil {
			if process == nil || process.ID() != shardID {
				launchErr = ErrInvalidConfig
				rejectedProcess = process
			} else {
				manager.shards[shardID] = &shard{spec: spec, process: process, sessions: make(map[identity.ID]Placement)}
				if manager.closed {
					manager.shards[shardID].draining = true
					launchErr = ErrManagerClosed
				}
			}
		}
		close(pending.done)
		manager.mu.Unlock()
		if rejectedProcess != nil {
			if stopErr := rejectedProcess.Stop(ctx); stopErr != nil {
				launchErr = errors.Join(launchErr, fmt.Errorf("stop rejected workerd process: %w", stopErr))
			}
		}
		if launchErr != nil {
			return Placement{}, fmt.Errorf("launch workerd shard: %w", launchErr)
		}
	}
}

func (manager *Manager) Release(ctx context.Context, request ReleaseRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if manager == nil || request.SessionID.Kind() != identity.Session || request.PlacementGeneration == 0 {
		return ErrInvalidRequest
	}
	manager.mu.Lock()
	if manager.closed {
		manager.mu.Unlock()
		return ErrManagerClosed
	}
	latest := manager.latestGenerations[request.SessionID]
	if request.PlacementGeneration < latest {
		manager.mu.Unlock()
		return ErrStalePlacement
	}
	if request.PlacementGeneration > latest || latest == 0 {
		manager.mu.Unlock()
		return ErrPlacementNotFound
	}
	placement, found := manager.placements[request.SessionID]
	if !found {
		manager.releasedGenerations[request.SessionID] = request.PlacementGeneration
		manager.mu.Unlock()
		return nil
	}
	delete(manager.placements, request.SessionID)
	manager.releasedGenerations[request.SessionID] = request.PlacementGeneration
	currentIdentity := manager.requestIdentities[request.SessionID]
	currentShard := manager.shards[placement.ShardID]
	var stop *trackedStop
	if currentShard != nil {
		delete(currentShard.sessions, request.SessionID)
		currentShard.estimatedResidentBytes -= currentIdentity.estimatedMemoryBytes
		if placement.Profile.ProcessScope == ScopeSession {
			currentShard.draining = true
		}
		if currentShard.draining && len(currentShard.sessions) == 0 {
			delete(manager.shards, currentShard.spec.ShardID)
			stop = &trackedStop{
				shardID: currentShard.spec.ShardID,
				pending: manager.trackStopLocked(currentShard.spec.ShardID, currentShard.process),
				reason:  "stop empty workerd shard",
			}
		}
	}
	manager.mu.Unlock()
	if stop != nil {
		return manager.executeTrackedStop(ctx, *stop)
	}
	return nil
}

func (manager *Manager) Observe(observation ShardObservation) error {
	if manager == nil || observation.ShardID == "" || observation.ObservedAt.IsZero() {
		return ErrInvalidRequest
	}
	manager.mu.Lock()
	if manager.closed {
		manager.mu.Unlock()
		return ErrManagerClosed
	}
	current := manager.shards[observation.ShardID]
	if current == nil {
		manager.mu.Unlock()
		return ErrShardNotFound
	}
	current.rssBytes = observation.RSSBytes
	if observation.OOMObserved || observation.HeapPressure || observation.RSSBytes >= manager.limits.AdmissionMemoryWatermarkBytes || observation.ObservedAt.Sub(current.spec.CreatedAt) >= manager.limits.MaximumLifetime {
		current.draining = true
	}
	var stop *trackedStop
	if current.draining && len(current.sessions) == 0 {
		delete(manager.shards, observation.ShardID)
		stop = &trackedStop{
			shardID: observation.ShardID,
			pending: manager.trackStopLocked(observation.ShardID, current.process),
			reason:  "stop drained workerd shard",
		}
	}
	manager.mu.Unlock()
	if stop != nil {
		return manager.executeTrackedStop(context.Background(), *stop)
	}
	return nil
}

// Shutdown permanently fences admission, waits for launches and previously
// initiated stops to leave their critical windows, and then drains every shard.
// A canceled or failed call may be retried; uncertain Stop failures remain
// tracked until a later call confirms process termination.
func (manager *Manager) Shutdown(ctx context.Context) error {
	if manager == nil || ctx == nil || manager.shutdownGate == nil {
		return ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-manager.shutdownGate:
	}
	defer func() { manager.shutdownGate <- struct{}{} }()

	for {
		manager.mu.Lock()
		manager.closed = true
		launches := make([]<-chan struct{}, 0, len(manager.pendingScopes))
		for _, pending := range manager.pendingScopes {
			launches = append(launches, pending.done)
		}
		manager.mu.Unlock()
		if len(launches) == 0 {
			break
		}
		for _, done := range launches {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-done:
			}
		}
	}

	manager.mu.Lock()
	shardIDs := make([]string, 0, len(manager.shards))
	for shardID := range manager.shards {
		shardIDs = append(shardIDs, shardID)
	}
	sort.Strings(shardIDs)
	stops := make([]trackedStop, 0, len(shardIDs)+len(manager.pendingStops))
	newStops := make(map[string]struct{}, len(shardIDs))
	for _, shardID := range shardIDs {
		current := manager.shards[shardID]
		delete(manager.shards, shardID)
		for sessionID := range current.sessions {
			delete(manager.placements, sessionID)
		}
		pending := manager.trackStopLocked(shardID, current.process)
		stops = append(stops, trackedStop{
			shardID: shardID, pending: pending, reason: "stop workerd shard during shutdown",
		})
		newStops[shardID] = struct{}{}
	}
	pendingIDs := make([]string, 0, len(manager.pendingStops))
	for shardID := range manager.pendingStops {
		if _, newlyTracked := newStops[shardID]; !newlyTracked {
			pendingIDs = append(pendingIDs, shardID)
		}
	}
	sort.Strings(pendingIDs)
	waiting := make([]<-chan struct{}, 0, len(pendingIDs))
	for _, shardID := range pendingIDs {
		pending := manager.pendingStops[shardID]
		select {
		case <-pending.done:
			if pending.err != nil {
				retry := &stopPending{process: pending.process, done: make(chan struct{})}
				manager.pendingStops[shardID] = retry
				stops = append(stops, trackedStop{
					shardID: shardID, pending: retry, reason: "retry uncertain workerd shard stop during shutdown",
				})
			}
		default:
			waiting = append(waiting, pending.done)
		}
	}
	manager.placements = make(map[identity.ID]Placement)
	manager.mu.Unlock()

	var stopErr error
	for _, stop := range stops {
		if err := manager.executeTrackedStop(ctx, stop); err != nil {
			stopErr = errors.Join(stopErr, err)
		}
	}
	for _, done := range waiting {
		select {
		case <-ctx.Done():
			stopErr = errors.Join(stopErr, ctx.Err())
		case <-done:
		}
	}
	manager.mu.Lock()
	for _, pending := range manager.pendingStops {
		select {
		case <-pending.done:
			if pending.err != nil {
				stopErr = errors.Join(stopErr, pending.err)
			}
		default:
			stopErr = errors.Join(stopErr, context.Canceled)
		}
	}
	manager.mu.Unlock()
	return stopErr
}

// trackStopLocked transfers process ownership from the live shard map to a
// retryable termination record. manager.mu must be held by the caller.
func (manager *Manager) trackStopLocked(shardID string, process ShardProcess) *stopPending {
	if pending := manager.pendingStops[shardID]; pending != nil {
		return pending
	}
	pending := &stopPending{process: process, done: make(chan struct{})}
	manager.pendingStops[shardID] = pending
	return pending
}

func (manager *Manager) executeTrackedStop(ctx context.Context, stop trackedStop) error {
	err := stop.pending.process.Stop(ctx)
	manager.mu.Lock()
	if current := manager.pendingStops[stop.shardID]; current == stop.pending {
		stop.pending.err = err
		close(stop.pending.done)
		if err == nil {
			delete(manager.pendingStops, stop.shardID)
		}
	}
	manager.mu.Unlock()
	if err != nil {
		return fmt.Errorf("%s: %w", stop.reason, err)
	}
	return nil
}

func (manager *Manager) Snapshot() ManagerSnapshot {
	if manager == nil {
		return ManagerSnapshot{}
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	snapshot := ManagerSnapshot{Shards: len(manager.shards), ResidentSessions: len(manager.placements)}
	for _, current := range manager.shards {
		snapshot.ResidentMemoryReservationBytes += current.estimatedResidentBytes
		if current.draining {
			snapshot.DrainingShards++
		}
	}
	return snapshot
}

func validDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == 32
}
