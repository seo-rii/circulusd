package artifact

import (
	"bytes"
	"container/heap"
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type memorySweepEntry struct {
	claim SweepClaim
	order uint64
	index int
}

type memorySweepHeap []*memorySweepEntry

func (entries memorySweepHeap) Len() int { return len(entries) }

func (entries memorySweepHeap) Less(left int, right int) bool {
	if entries[left].order != entries[right].order {
		return entries[left].order < entries[right].order
	}
	return entries[left].claim.ObjectKey < entries[right].claim.ObjectKey
}

func (entries memorySweepHeap) Swap(left int, right int) {
	entries[left], entries[right] = entries[right], entries[left]
	entries[left].index = left
	entries[right].index = right
}

func (entries *memorySweepHeap) Push(value any) {
	entry := value.(*memorySweepEntry)
	entry.index = len(*entries)
	*entries = append(*entries, entry)
}

func (entries *memorySweepHeap) Pop() any {
	old := *entries
	last := len(old) - 1
	entry := old[last]
	old[last] = nil
	entry.index = -1
	*entries = old[:last]
	return entry
}

// MemoryRepository is a race-safe reference test double for the durable
// Repository contract. Tenant quota is logical artifact bytes: deleting one
// of two metadata references releases only that artifact's logical usage.
type MemoryRepository struct {
	mu                      sync.RWMutex
	quotas                  map[string]int64
	used                    map[string]int64
	reserved                map[string]int64
	invocations             map[string]InvocationRecord
	invocationOrder         []string
	artifactReservations    map[string]string
	inflightByObject        map[string]int
	artifacts               map[string]ArtifactRecord
	artifactOrder           []string
	activeByObject          map[string]int
	latestTombstoneByObject map[string]time.Time
	artifactIDsByObject     map[string][]string
	lastInvocationScanCount int
	lastArtifactScanCount   int
	sweeps                  map[string]*memorySweepEntry
	sweepQueue              memorySweepHeap
	nextSweepToken          uint64
	nextSweepOrder          uint64
	gcCheckpoint            GCCheckpoint
	gcLease                 GCLease
	gcLeaseHeld             bool
	nextGCLeaseToken        uint64
}

func NewMemoryRepository(tenantQuotaBytes map[string]int64) *MemoryRepository {
	quotas := make(map[string]int64, len(tenantQuotaBytes))
	for tenantID, quota := range tenantQuotaBytes {
		quotas[tenantID] = quota
	}
	return &MemoryRepository{
		quotas: quotas, used: map[string]int64{}, reserved: map[string]int64{},
		invocations: map[string]InvocationRecord{}, artifacts: map[string]ArtifactRecord{},
		artifactReservations: map[string]string{}, inflightByObject: map[string]int{},
		activeByObject: map[string]int{}, latestTombstoneByObject: map[string]time.Time{},
		artifactIDsByObject: map[string][]string{},
		sweeps:              map[string]*memorySweepEntry{},
	}
}

func (repository *MemoryRepository) LookupInvocation(ctx context.Context, invocationID string) (InvocationRecord, bool, error) {
	if err := ctx.Err(); err != nil {
		return InvocationRecord{}, false, err
	}
	repository.mu.RLock()
	record, found := repository.invocations[invocationID]
	repository.mu.RUnlock()
	return cloneInvocationRecord(record), found, nil
}

func (repository *MemoryRepository) BeginCreate(ctx context.Context, request CreateReservation) (InvocationRecord, bool, error) {
	if err := ctx.Err(); err != nil {
		return InvocationRecord{}, false, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if existing, found := repository.invocations[request.InvocationID]; found {
		if existing.TenantID != request.TenantID || existing.RequestDigest != request.RequestDigest {
			return InvocationRecord{}, false, ErrInvocationConflict
		}
		return cloneInvocationRecord(existing), true, nil
	}
	if _, sweeping := repository.sweeps[request.ObjectKey]; sweeping {
		return InvocationRecord{}, false, ErrGCInProgress
	}
	quota, configured := repository.quotas[request.TenantID]
	if !configured || quota < 0 || request.Size < 0 || request.Size > quota-repository.used[request.TenantID]-repository.reserved[request.TenantID] {
		return InvocationRecord{}, false, ErrQuotaExceeded
	}
	if _, exists := repository.artifacts[request.ArtifactID]; exists {
		return InvocationRecord{}, false, ErrRepositoryConflict
	}
	if _, reserved := repository.artifactReservations[request.ArtifactID]; reserved {
		return InvocationRecord{}, false, ErrRepositoryConflict
	}
	record := InvocationRecord{
		TenantID: request.TenantID, SessionID: request.SessionID, WorkspaceID: request.WorkspaceID,
		InvocationID:  request.InvocationID,
		RequestDigest: request.RequestDigest, ArtifactID: request.ArtifactID,
		ObjectKey: request.ObjectKey, Size: request.Size, StartedAt: request.StartedAt,
		HeartbeatAt: request.StartedAt, Generation: 1, State: InvocationInflight,
		SourceRevisionID: request.SourceRevisionID, SourcePath: request.SourcePath,
		ContentDigest: request.ContentDigest, MetadataDigest: request.MetadataDigest,
		Metadata: cloneMetadata(request.Metadata),
	}
	repository.invocations[request.InvocationID] = record
	repository.invocationOrder = append(repository.invocationOrder, request.InvocationID)
	repository.artifactReservations[request.ArtifactID] = request.InvocationID
	repository.inflightByObject[request.ObjectKey]++
	repository.reserved[request.TenantID] += request.Size
	return cloneInvocationRecord(record), false, nil
}

func (repository *MemoryRepository) HeartbeatCreate(ctx context.Context, invocationID string, requestDigest string, generation uint64, now time.Time) (InvocationRecord, error) {
	if err := ctx.Err(); err != nil {
		return InvocationRecord{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	record, found := repository.invocations[invocationID]
	if !found {
		return InvocationRecord{}, ErrRepositoryConflict
	}
	if record.RequestDigest != requestDigest {
		return InvocationRecord{}, ErrInvocationConflict
	}
	if record.State == InvocationAbandoned {
		return InvocationRecord{}, ErrInvocationAbandoned
	}
	if record.Generation != generation {
		return InvocationRecord{}, ErrRepositoryConflict
	}
	if record.State == InvocationCommitted {
		return cloneInvocationRecord(record), nil
	}
	if record.State != InvocationInflight {
		return InvocationRecord{}, ErrRepositoryConflict
	}
	instant := now.UTC()
	if instant.After(record.HeartbeatAt) {
		record.HeartbeatAt = instant
		repository.invocations[invocationID] = record
	}
	return cloneInvocationRecord(record), nil
}

func (repository *MemoryRepository) CommitCreate(ctx context.Context, request CommitCreateRequest) (ArtifactRecord, bool, error) {
	if err := ctx.Err(); err != nil {
		return ArtifactRecord{}, false, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	invocation, found := repository.invocations[request.InvocationID]
	if !found {
		return ArtifactRecord{}, false, ErrRepositoryConflict
	}
	if invocation.RequestDigest != request.RequestDigest {
		return ArtifactRecord{}, false, ErrInvocationConflict
	}
	if invocation.State == InvocationAbandoned {
		return ArtifactRecord{}, false, ErrInvocationAbandoned
	}
	if invocation.State == InvocationCommitted {
		existing, exists := repository.artifacts[invocation.ArtifactID]
		if !exists {
			return ArtifactRecord{}, false, ErrStorageCorruption
		}
		return cloneArtifactRecord(existing), true, nil
	}
	if invocation.Generation != request.Generation {
		return ArtifactRecord{}, false, ErrRepositoryConflict
	}
	artifact := request.Artifact
	if artifact.ArtifactID != invocation.ArtifactID || artifact.TenantID != invocation.TenantID ||
		artifact.InvocationID != invocation.InvocationID || artifact.RequestDigest != invocation.RequestDigest ||
		artifact.ObjectKey != invocation.ObjectKey || artifact.Size != invocation.Size || artifact.State != ArtifactActive {
		return ArtifactRecord{}, false, ErrRepositoryConflict
	}
	if _, exists := repository.artifacts[artifact.ArtifactID]; exists {
		return ArtifactRecord{}, false, ErrRepositoryConflict
	}
	repository.artifacts[artifact.ArtifactID] = cloneArtifactRecord(artifact)
	repository.artifactOrder = append(repository.artifactOrder, artifact.ArtifactID)
	repository.artifactIDsByObject[artifact.ObjectKey] = append(repository.artifactIDsByObject[artifact.ObjectKey], artifact.ArtifactID)
	repository.inflightByObject[artifact.ObjectKey]--
	repository.activeByObject[artifact.ObjectKey]++
	repository.reserved[artifact.TenantID] -= artifact.Size
	repository.used[artifact.TenantID] += artifact.Size
	invocation.State = InvocationCommitted
	repository.invocations[request.InvocationID] = invocation
	return cloneArtifactRecord(artifact), false, nil
}

func (repository *MemoryRepository) GetArtifact(ctx context.Context, artifactID string) (ArtifactRecord, error) {
	if err := ctx.Err(); err != nil {
		return ArtifactRecord{}, err
	}
	repository.mu.RLock()
	record, found := repository.artifacts[artifactID]
	repository.mu.RUnlock()
	if !found {
		return ArtifactRecord{}, ErrArtifactNotFound
	}
	return cloneArtifactRecord(record), nil
}

func (repository *MemoryRepository) TombstoneArtifact(ctx context.Context, artifactID string, tenantID string, now time.Time) (ArtifactRecord, bool, error) {
	if err := ctx.Err(); err != nil {
		return ArtifactRecord{}, false, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	record, found := repository.artifacts[artifactID]
	if !found {
		return ArtifactRecord{}, false, ErrArtifactNotFound
	}
	if record.TenantID != tenantID {
		return ArtifactRecord{}, false, ErrAccessDenied
	}
	if record.State != ArtifactActive {
		return cloneArtifactRecord(record), false, nil
	}
	instant := now.UTC()
	record.State = ArtifactTombstoned
	record.TombstonedAt = &instant
	repository.artifacts[artifactID] = record
	repository.used[tenantID] -= record.Size
	repository.activeByObject[record.ObjectKey]--
	repository.recordTombstoneLocked(record.ObjectKey, instant)
	return cloneArtifactRecord(record), true, nil
}

func (repository *MemoryRepository) TombstoneExpired(ctx context.Context, now time.Time) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	count := 0
	instant := now.UTC()
	for artifactID, record := range repository.artifacts {
		if record.State != ArtifactActive || instant.Before(record.RetainUntil) {
			continue
		}
		record.State = ArtifactTombstoned
		record.TombstonedAt = &instant
		repository.artifacts[artifactID] = record
		repository.used[record.TenantID] -= record.Size
		repository.activeByObject[record.ObjectKey]--
		repository.recordTombstoneLocked(record.ObjectKey, instant)
		count++
	}
	return count, nil
}

func (repository *MemoryRepository) TombstoneExpiredPage(ctx context.Context, lease GCLease, now time.Time, after string, limit int) (int, string, bool, error) {
	if err := ctx.Err(); err != nil {
		return 0, "", false, err
	}
	if limit <= 0 || limit > maximumGCBatchSize {
		return 0, "", false, ErrInvalidRequest
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if !repository.gcLeaseHeld || repository.gcLease.Token != lease.Token {
		return 0, "", false, ErrRepositoryConflict
	}
	start, end, next, done, cursorErr := memoryPageBounds(after, len(repository.artifactOrder), limit)
	if cursorErr != nil {
		return 0, "", false, cursorErr
	}
	repository.lastArtifactScanCount = end - start
	count := 0
	instant := now.UTC()
	for _, artifactID := range repository.artifactOrder[start:end] {
		record := repository.artifacts[artifactID]
		if record.State != ArtifactActive || instant.Before(record.RetainUntil) {
			continue
		}
		record.State = ArtifactTombstoned
		record.TombstonedAt = &instant
		repository.artifacts[artifactID] = record
		repository.used[record.TenantID] -= record.Size
		repository.activeByObject[record.ObjectKey]--
		repository.recordTombstoneLocked(record.ObjectKey, instant)
		count++
	}
	return count, next, done, nil
}

func (repository *MemoryRepository) recordTombstoneLocked(objectKey string, instant time.Time) {
	if latest, found := repository.latestTombstoneByObject[objectKey]; !found || instant.After(latest) {
		repository.latestTombstoneByObject[objectKey] = instant
	}
}

func (repository *MemoryRepository) AbandonInflight(ctx context.Context, startedBefore time.Time) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	count := 0
	for invocationID, record := range repository.invocations {
		if record.State != InvocationInflight || record.StartedAt.After(startedBefore) {
			continue
		}
		record.State = InvocationAbandoned
		record.Generation++
		repository.invocations[invocationID] = record
		repository.reserved[record.TenantID] -= record.Size
		repository.inflightByObject[record.ObjectKey]--
		count++
	}
	return count, nil
}

func (repository *MemoryRepository) AbandonInflightPage(ctx context.Context, lease GCLease, heartbeatBefore time.Time, after string, limit int) (int, string, bool, error) {
	if err := ctx.Err(); err != nil {
		return 0, "", false, err
	}
	if limit <= 0 || limit > maximumGCBatchSize {
		return 0, "", false, ErrInvalidRequest
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if !repository.gcLeaseHeld || repository.gcLease.Token != lease.Token {
		return 0, "", false, ErrRepositoryConflict
	}
	start, end, next, done, cursorErr := memoryPageBounds(after, len(repository.invocationOrder), limit)
	if cursorErr != nil {
		return 0, "", false, cursorErr
	}
	repository.lastInvocationScanCount = end - start
	count := 0
	for _, invocationID := range repository.invocationOrder[start:end] {
		record := repository.invocations[invocationID]
		if record.State != InvocationInflight || record.HeartbeatAt.After(heartbeatBefore) {
			continue
		}
		record.State = InvocationAbandoned
		record.Generation++
		repository.invocations[invocationID] = record
		repository.reserved[record.TenantID] -= record.Size
		repository.inflightByObject[record.ObjectKey]--
		count++
	}
	return count, next, done, nil
}

func memoryPageBounds(cursor string, total int, limit int) (int, int, string, bool, error) {
	start, highwater := 0, total
	if cursor != "" {
		separator := strings.IndexByte(cursor, ':')
		if separator <= 0 || separator == len(cursor)-1 {
			return 0, 0, "", false, ErrRepositoryConflict
		}
		parsedStart, startErr := strconv.Atoi(cursor[:separator])
		parsedHighwater, highwaterErr := strconv.Atoi(cursor[separator+1:])
		if startErr != nil || highwaterErr != nil || parsedStart < 0 || parsedHighwater < parsedStart || parsedHighwater > total {
			return 0, 0, "", false, ErrRepositoryConflict
		}
		start, highwater = parsedStart, parsedHighwater
	}
	end := start + limit
	if end > highwater {
		end = highwater
	}
	done := end == highwater
	next := ""
	if !done {
		next = fmt.Sprintf("%d:%d", end, highwater)
	}
	return start, end, next, done, nil
}

func (repository *MemoryRepository) AcquireGC(ctx context.Context, now time.Time, duration time.Duration) (GCLease, bool, error) {
	if err := ctx.Err(); err != nil {
		return GCLease{}, false, err
	}
	if duration <= 0 {
		return GCLease{}, false, ErrInvalidRequest
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	instant := now.UTC()
	if repository.gcLeaseHeld && instant.Before(repository.gcLease.ExpiresAt) {
		return GCLease{}, false, nil
	}
	repository.nextGCLeaseToken++
	repository.gcLease = GCLease{
		Token: repository.nextGCLeaseToken, ExpiresAt: instant.Add(duration),
		Checkpoint: repository.gcCheckpoint,
	}
	repository.gcLeaseHeld = true
	return repository.gcLease, true, nil
}

func (repository *MemoryRepository) RenewGC(ctx context.Context, lease GCLease, now time.Time, duration time.Duration) (GCLease, error) {
	if err := ctx.Err(); err != nil {
		return GCLease{}, err
	}
	if duration <= 0 {
		return GCLease{}, ErrInvalidRequest
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	instant := now.UTC()
	if !repository.gcLeaseHeld || repository.gcLease.Token != lease.Token || !instant.Before(repository.gcLease.ExpiresAt) {
		return GCLease{}, ErrRepositoryConflict
	}
	repository.gcLease.ExpiresAt = instant.Add(duration)
	return repository.gcLease, nil
}

func (repository *MemoryRepository) ReleaseGC(ctx context.Context, lease GCLease, checkpoint GCCheckpoint) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if !repository.gcLeaseHeld || repository.gcLease.Token != lease.Token {
		return ErrRepositoryConflict
	}
	repository.gcCheckpoint = checkpoint
	repository.gcLeaseHeld = false
	repository.gcLease = GCLease{}
	return nil
}

func (repository *MemoryRepository) PendingSweeps(ctx context.Context) ([]SweepClaim, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	repository.mu.RLock()
	claims := make([]SweepClaim, 0, len(repository.sweeps))
	for _, entry := range repository.sweeps {
		claims = append(claims, entry.claim)
	}
	repository.mu.RUnlock()
	sort.Slice(claims, func(left, right int) bool { return claims[left].ObjectKey < claims[right].ObjectKey })
	return claims, nil
}

func (repository *MemoryRepository) PendingSweepsPage(ctx context.Context, lease GCLease, _ string, limit int) ([]SweepClaim, string, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", false, err
	}
	if limit <= 0 || limit > maximumGCBatchSize {
		return nil, "", false, ErrInvalidRequest
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if !repository.gcLeaseHeld || repository.gcLease.Token != lease.Token {
		return nil, "", false, ErrRepositoryConflict
	}
	count := limit
	if count > repository.sweepQueue.Len() {
		count = repository.sweepQueue.Len()
	}
	selected := make([]*memorySweepEntry, 0, count)
	for range count {
		selected = append(selected, heap.Pop(&repository.sweepQueue).(*memorySweepEntry))
	}
	claims := make([]SweepClaim, 0, count)
	for _, entry := range selected {
		repository.nextSweepOrder++
		entry.order = repository.nextSweepOrder
		entry.claim.LeaseToken = lease.Token
		heap.Push(&repository.sweepQueue, entry)
		claims = append(claims, entry.claim)
	}
	return claims, "", true, nil
}

func (repository *MemoryRepository) ClaimSweep(ctx context.Context, objectKey string, tombstonedBefore time.Time) (SweepClaim, bool, error) {
	if err := ctx.Err(); err != nil {
		return SweepClaim{}, false, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if _, claimed := repository.sweeps[objectKey]; claimed {
		return SweepClaim{}, false, nil
	}
	if repository.inflightByObject[objectKey] != 0 || repository.activeByObject[objectKey] != 0 {
		return SweepClaim{}, false, nil
	}
	if latest, found := repository.latestTombstoneByObject[objectKey]; found && latest.After(tombstonedBefore) {
		return SweepClaim{}, false, nil
	}
	repository.nextSweepToken++
	claim := SweepClaim{ObjectKey: objectKey, Token: repository.nextSweepToken}
	repository.nextSweepOrder++
	entry := &memorySweepEntry{claim: claim, order: repository.nextSweepOrder, index: -1}
	repository.sweeps[objectKey] = entry
	heap.Push(&repository.sweepQueue, entry)
	return claim, true, nil
}

func (repository *MemoryRepository) ClaimSweepLeased(ctx context.Context, lease GCLease, objectKey string, objectVersion string, tombstonedBefore time.Time) (SweepClaim, bool, error) {
	if err := ctx.Err(); err != nil {
		return SweepClaim{}, false, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if !repository.gcLeaseHeld || repository.gcLease.Token != lease.Token || objectKey == "" || objectVersion == "" {
		return SweepClaim{}, false, ErrRepositoryConflict
	}
	if _, claimed := repository.sweeps[objectKey]; claimed {
		return SweepClaim{}, false, nil
	}
	if repository.inflightByObject[objectKey] != 0 || repository.activeByObject[objectKey] != 0 {
		return SweepClaim{}, false, nil
	}
	if latest, found := repository.latestTombstoneByObject[objectKey]; found && latest.After(tombstonedBefore) {
		return SweepClaim{}, false, nil
	}
	repository.nextSweepToken++
	claim := SweepClaim{
		ObjectKey: objectKey, ObjectVersion: objectVersion,
		Token: repository.nextSweepToken, LeaseToken: lease.Token,
	}
	repository.nextSweepOrder++
	entry := &memorySweepEntry{claim: claim, order: repository.nextSweepOrder, index: -1}
	repository.sweeps[objectKey] = entry
	heap.Push(&repository.sweepQueue, entry)
	return claim, true, nil
}

func (repository *MemoryRepository) FinishSweep(ctx context.Context, claim SweepClaim, deleted bool, now time.Time) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	current, found := repository.sweeps[claim.ObjectKey]
	if !found || current.claim != claim {
		return 0, ErrRepositoryConflict
	}
	if !deleted {
		return 0, nil
	}
	repository.removeSweepLocked(current)
	count := 0
	instant := now.UTC()
	for _, artifactID := range repository.artifactIDsByObject[claim.ObjectKey] {
		record := repository.artifacts[artifactID]
		if record.State != ArtifactTombstoned {
			continue
		}
		record.State = ArtifactPurged
		record.PurgedAt = &instant
		repository.artifacts[artifactID] = record
		count++
	}
	delete(repository.latestTombstoneByObject, claim.ObjectKey)
	return count, nil
}

func (repository *MemoryRepository) RetireSweepLeased(ctx context.Context, lease GCLease, claim SweepClaim) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if !repository.gcLeaseHeld || repository.gcLease.Token != lease.Token || claim.LeaseToken != lease.Token {
		return ErrRepositoryConflict
	}
	current, found := repository.sweeps[claim.ObjectKey]
	if !found || current.claim != claim {
		return ErrRepositoryConflict
	}
	repository.removeSweepLocked(current)
	return nil
}

func (repository *MemoryRepository) FinishSweepLeased(ctx context.Context, lease GCLease, claim SweepClaim, deleted bool, now time.Time) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if !repository.gcLeaseHeld || repository.gcLease.Token != lease.Token || claim.LeaseToken != lease.Token {
		return 0, ErrRepositoryConflict
	}
	current, found := repository.sweeps[claim.ObjectKey]
	if !found || current.claim != claim {
		return 0, ErrRepositoryConflict
	}
	if !deleted {
		return 0, nil
	}
	repository.removeSweepLocked(current)
	count := 0
	instant := now.UTC()
	for _, artifactID := range repository.artifactIDsByObject[claim.ObjectKey] {
		record := repository.artifacts[artifactID]
		if record.State != ArtifactTombstoned {
			continue
		}
		record.State = ArtifactPurged
		record.PurgedAt = &instant
		repository.artifacts[artifactID] = record
		count++
	}
	delete(repository.latestTombstoneByObject, claim.ObjectKey)
	return count, nil
}

func (repository *MemoryRepository) removeSweepLocked(entry *memorySweepEntry) {
	heap.Remove(&repository.sweepQueue, entry.index)
	delete(repository.sweeps, entry.claim.ObjectKey)
}

func (repository *MemoryRepository) Stats(tenantID string) RepositoryStats {
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	stats := RepositoryStats{UsedBytes: repository.used[tenantID], ReservedBytes: repository.reserved[tenantID]}
	for _, artifact := range repository.artifacts {
		if artifact.TenantID == tenantID {
			stats.Artifacts++
		}
	}
	for _, invocation := range repository.invocations {
		if invocation.TenantID == tenantID {
			stats.Invocations++
		}
	}
	return stats
}

func (repository *MemoryRepository) LastInvocationScanCount() int {
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	return repository.lastInvocationScanCount
}

func cloneArtifactRecord(record ArtifactRecord) ArtifactRecord {
	copy := record
	copy.Metadata = cloneMetadata(record.Metadata)
	if record.TombstonedAt != nil {
		instant := *record.TombstonedAt
		copy.TombstonedAt = &instant
	}
	if record.PurgedAt != nil {
		instant := *record.PurgedAt
		copy.PurgedAt = &instant
	}
	return copy
}

func cloneInvocationRecord(record InvocationRecord) InvocationRecord {
	copy := record
	copy.Metadata = cloneMetadata(record.Metadata)
	return copy
}

type MemoryBlobStore struct {
	mu                sync.RWMutex
	objects           map[string]BlobObject
	activeHistory     map[string]int
	history           []memoryBlobHistory
	mutation          uint64
	lastListScanCount int
	failAfterPut      error
	failAfterDelete   error
	nextObjectVersion uint64
}

type memoryBlobHistory struct {
	info            BlobInfo
	createdMutation uint64
	deletedMutation uint64
}

func NewMemoryBlobStore() *MemoryBlobStore {
	return &MemoryBlobStore{objects: map[string]BlobObject{}, activeHistory: map[string]int{}}
}

func (store *MemoryBlobStore) PutIfAbsent(ctx context.Context, request BlobPut) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if request.Key == "" || !validDigest(request.Digest) || request.Digest != digestBytes(request.Data) || request.CreatedAt.IsZero() {
		return fmt.Errorf("%w: invalid immutable blob write", ErrStorageCorruption)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, found := store.objects[request.Key]; found {
		if existing.Digest != request.Digest || !bytes.Equal(existing.Data, request.Data) {
			return ErrStorageCorruption
		}
	} else {
		store.nextObjectVersion++
		store.mutation++
		object := BlobObject{
			Key: request.Key, Version: fmt.Sprintf("memory-object-%d", store.nextObjectVersion), Digest: request.Digest,
			Data: append([]byte(nil), request.Data...), CreatedAt: request.CreatedAt.UTC(),
		}
		store.objects[request.Key] = object
		store.history = append(store.history, memoryBlobHistory{
			info: BlobInfo{
				Key: object.Key, Version: object.Version, Digest: object.Digest,
				Size: int64(len(object.Data)), CreatedAt: object.CreatedAt,
			},
			createdMutation: store.mutation,
		})
		store.activeHistory[request.Key] = len(store.history) - 1
	}
	if store.failAfterPut != nil {
		return store.failAfterPut
	}
	return nil
}

func (store *MemoryBlobStore) Get(ctx context.Context, key string) (BlobObject, error) {
	if err := ctx.Err(); err != nil {
		return BlobObject{}, err
	}
	store.mu.RLock()
	object, found := store.objects[key]
	store.mu.RUnlock()
	if !found {
		return BlobObject{}, ErrBlobNotFound
	}
	object.Data = append([]byte(nil), object.Data...)
	return object, nil
}

func (store *MemoryBlobStore) Head(ctx context.Context, key string) (BlobInfo, error) {
	if err := ctx.Err(); err != nil {
		return BlobInfo{}, err
	}
	store.mu.RLock()
	object, found := store.objects[key]
	store.mu.RUnlock()
	if !found {
		return BlobInfo{}, ErrBlobNotFound
	}
	return BlobInfo{
		Key: object.Key, Version: object.Version, Digest: object.Digest,
		Size: int64(len(object.Data)), CreatedAt: object.CreatedAt,
	}, nil
}

func (store *MemoryBlobStore) List(ctx context.Context) ([]BlobInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	store.mu.RLock()
	objects := make([]BlobInfo, 0, len(store.objects))
	for _, object := range store.objects {
		objects = append(objects, BlobInfo{
			Key: object.Key, Version: object.Version, Digest: object.Digest,
			Size: int64(len(object.Data)), CreatedAt: object.CreatedAt,
		})
	}
	store.mu.RUnlock()
	sort.Slice(objects, func(left, right int) bool { return objects[left].Key < objects[right].Key })
	return objects, nil
}

func (store *MemoryBlobStore) ListPage(ctx context.Context, request BlobListRequest) (BlobListPage, error) {
	if err := ctx.Err(); err != nil {
		return BlobListPage{}, err
	}
	if request.Limit <= 0 || request.Limit > maximumGCBatchSize || (request.Epoch == "" && request.Cursor != "") {
		return BlobListPage{}, ErrInvalidRequest
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	epoch := request.Epoch
	var snapshotMutation uint64
	var highwater int
	if epoch == "" {
		snapshotMutation = store.mutation
		highwater = len(store.history)
		epoch = fmt.Sprintf("%d:%d", snapshotMutation, highwater)
	} else {
		separator := strings.IndexByte(epoch, ':')
		if separator <= 0 || separator == len(epoch)-1 {
			return BlobListPage{}, ErrInvalidRequest
		}
		parsedMutation, mutationErr := strconv.ParseUint(epoch[:separator], 10, 64)
		parsedHighwater, highwaterErr := strconv.Atoi(epoch[separator+1:])
		if mutationErr != nil || highwaterErr != nil || parsedMutation > store.mutation ||
			parsedHighwater < 0 || parsedHighwater > len(store.history) {
			return BlobListPage{}, ErrInvalidRequest
		}
		snapshotMutation, highwater = parsedMutation, parsedHighwater
	}
	offset := 0
	if request.Cursor != "" {
		parsed, err := strconv.Atoi(request.Cursor)
		if err != nil || parsed < 0 || parsed > highwater {
			return BlobListPage{}, ErrInvalidRequest
		}
		offset = parsed
	}
	end := offset + request.Limit
	if end > highwater {
		end = highwater
	}
	store.lastListScanCount = end - offset
	pageObjects := make([]BlobInfo, 0, end-offset)
	for _, entry := range store.history[offset:end] {
		if entry.createdMutation <= snapshotMutation &&
			(entry.deletedMutation == 0 || entry.deletedMutation > snapshotMutation) {
			pageObjects = append(pageObjects, entry.info)
		}
	}
	done := end == highwater
	next := ""
	if !done {
		next = strconv.Itoa(end)
	}
	return BlobListPage{Epoch: epoch, NextCursor: next, Objects: pageObjects, Done: done}, nil
}

func (store *MemoryBlobStore) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, found := store.objects[key]; !found {
		return ErrBlobNotFound
	}
	store.mutation++
	historyIndex := store.activeHistory[key]
	store.history[historyIndex].deletedMutation = store.mutation
	delete(store.activeHistory, key)
	delete(store.objects, key)
	if store.failAfterDelete != nil {
		return store.failAfterDelete
	}
	return nil
}

func (store *MemoryBlobStore) DeleteIfVersion(ctx context.Context, key string, version string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	object, found := store.objects[key]
	if !found {
		return ErrBlobNotFound
	}
	if version == "" || object.Version != version {
		return ErrBlobVersionConflict
	}
	store.mutation++
	historyIndex := store.activeHistory[key]
	store.history[historyIndex].deletedMutation = store.mutation
	delete(store.activeHistory, key)
	delete(store.objects, key)
	if store.failAfterDelete != nil {
		return store.failAfterDelete
	}
	return nil
}

func (store *MemoryBlobStore) ObjectCount() int {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return len(store.objects)
}

func (store *MemoryBlobStore) LastListScanCount() int {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return store.lastListScanCount
}

func (store *MemoryBlobStore) EnumerationStateSize() int {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return len(store.history)
}

func (store *MemoryBlobStore) FailAfterPut(err error) {
	store.mu.Lock()
	store.failAfterPut = err
	store.mu.Unlock()
}

func (store *MemoryBlobStore) FailAfterDelete(err error) {
	store.mu.Lock()
	store.failAfterDelete = err
	store.mu.Unlock()
}

func (store *MemoryBlobStore) Corrupt(key string, data []byte) {
	store.mu.Lock()
	defer store.mu.Unlock()
	object, found := store.objects[key]
	if !found {
		return
	}
	object.Data = append([]byte(nil), data...)
	store.objects[key] = object
}
