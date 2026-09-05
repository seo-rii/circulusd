package blob

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ErrIncompleteRoots     = errors.New("root export is incomplete")
	ErrObjectMissing       = errors.New("object guard is missing")
	ErrObjectDeleting      = errors.New("object is being deleted")
	ErrPermitMissing       = errors.New("protection permit is missing")
	ErrPermitReused        = errors.New("protection permit ID was reused")
	ErrStalePermit         = errors.New("protection permit is stale")
	ErrStaleDeletion       = errors.New("deletion claim is stale")
	ErrEpochOrder          = errors.New("GC epoch is not monotonic")
	ErrMarkedObjectMissing = errors.New("marked object is unavailable")
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type State string

const (
	Live      State = "live"
	Candidate State = "candidate"
	Deleting  State = "deleting"
	Deleted   State = "deleted"
)

type Key struct {
	TenantID string
	Digest   string
}

type Permit struct {
	ID                string
	Key               Key
	GuardGeneration   uint64
	ObjectIncarnation uint64
}

type Deletion struct {
	Key             Key
	GuardGeneration uint64
	Epoch           uint64
}

type GuardSnapshot struct {
	Found          bool
	State          State
	Generation     uint64
	Incarnation    uint64
	CreatedAt      time.Time
	CandidateEpoch uint64
	CandidateSince time.Time
	PendingPermits int
}

type GuardTable struct {
	mu        sync.RWMutex
	grace     time.Duration
	lastEpoch uint64
	guards    map[Key]*guardRecord
	permits   map[string]*permitRecord

	storageMu    sync.Mutex
	storageGates map[Key]*storageGate
}

type guardRecord struct {
	state          State
	generation     uint64
	incarnation    uint64
	createdAt      time.Time
	candidateEpoch uint64
	candidateSince time.Time
	deletionEpoch  uint64
	pending        map[string]struct{}
}

type permitRecord struct {
	permit Permit
	state  permitState
}

type permitState string

const (
	permitPending   permitState = "pending"
	permitFinalized permitState = "finalized"
	permitAbandoned permitState = "abandoned"
)

func NewGuardTable(grace time.Duration) *GuardTable {
	if grace < 0 {
		panic("blob guard grace must not be negative")
	}
	return &GuardTable{
		grace:        grace,
		guards:       make(map[Key]*guardRecord),
		permits:      make(map[string]*permitRecord),
		storageGates: make(map[Key]*storageGate),
	}
}

func (table *GuardTable) Register(key Key, createdAt time.Time) error {
	release, err := table.acquireStorage(context.Background(), key)
	if err != nil {
		return err
	}
	defer release()
	return table.register(key, createdAt)
}

// register requires the caller to hold the key's storage gate.
func (table *GuardTable) register(key Key, createdAt time.Time) error {
	if err := validateKey(key); err != nil {
		return err
	}
	if createdAt.IsZero() {
		return fmt.Errorf("register %s: creation time is required", key.Digest)
	}

	table.mu.Lock()
	defer table.mu.Unlock()

	record, found := table.guards[key]
	if !found {
		table.guards[key] = &guardRecord{
			state:       Live,
			generation:  1,
			incarnation: 1,
			createdAt:   createdAt,
			pending:     make(map[string]struct{}),
		}
		return nil
	}
	switch record.state {
	case Live, Candidate:
		return nil
	case Deleting:
		return fmt.Errorf("register %s: %w", key.Digest, ErrObjectDeleting)
	case Deleted:
		record.state = Live
		record.generation++
		record.incarnation++
		record.createdAt = createdAt
		record.candidateEpoch = 0
		record.candidateSince = time.Time{}
		record.deletionEpoch = 0
		record.pending = make(map[string]struct{})
		return nil
	default:
		return fmt.Errorf("register %s: unknown guard state %q", key.Digest, record.state)
	}
}

func (table *GuardTable) Protect(key Key, permitID string) (Permit, error) {
	if err := validateKey(key); err != nil {
		return Permit{}, err
	}
	if strings.TrimSpace(permitID) == "" {
		return Permit{}, fmt.Errorf("protection permit ID is required")
	}

	table.mu.Lock()
	defer table.mu.Unlock()

	if existing, found := table.permits[permitID]; found {
		if existing.permit.Key != key {
			return Permit{}, fmt.Errorf("protect %s: %w", key.Digest, ErrPermitReused)
		}
		if existing.state == permitAbandoned {
			return Permit{}, fmt.Errorf("protect %s: %w", key.Digest, ErrStalePermit)
		}
		guard := table.guards[key]
		if guard == nil || guard.incarnation != existing.permit.ObjectIncarnation {
			return Permit{}, fmt.Errorf("protect %s: %w", key.Digest, ErrStalePermit)
		}
		if guard.state == Deleting || guard.state == Deleted {
			return Permit{}, fmt.Errorf("protect %s: %w", key.Digest, ErrObjectDeleting)
		}
		return existing.permit, nil
	}

	guard, found := table.guards[key]
	if !found {
		return Permit{}, fmt.Errorf("protect %s: %w", key.Digest, ErrObjectMissing)
	}
	if guard.state == Deleting || guard.state == Deleted {
		return Permit{}, fmt.Errorf("protect %s: %w", key.Digest, ErrObjectDeleting)
	}

	guard.generation++
	guard.state = Live
	guard.candidateEpoch = 0
	guard.candidateSince = time.Time{}
	guard.pending[permitID] = struct{}{}
	permit := Permit{
		ID:                permitID,
		Key:               key,
		GuardGeneration:   guard.generation,
		ObjectIncarnation: guard.incarnation,
	}
	table.permits[permitID] = &permitRecord{permit: permit, state: permitPending}
	return permit, nil
}

func (table *GuardTable) Finalize(permitID string) error {
	table.mu.Lock()
	defer table.mu.Unlock()

	record, found := table.permits[permitID]
	if !found {
		return fmt.Errorf("finalize permit %q: %w", permitID, ErrPermitMissing)
	}
	if record.state == permitFinalized {
		return nil
	}
	if record.state == permitAbandoned {
		return fmt.Errorf("finalize permit %q: %w", permitID, ErrStalePermit)
	}
	guard, found := table.guards[record.permit.Key]
	if !found || guard.state == Deleted {
		return fmt.Errorf("finalize permit %q: %w", permitID, ErrStalePermit)
	}
	delete(guard.pending, permitID)
	record.state = permitFinalized
	return nil
}

func (table *GuardTable) Abandon(permitID string) error {
	table.mu.Lock()
	defer table.mu.Unlock()

	record, found := table.permits[permitID]
	if !found {
		return fmt.Errorf("abandon permit %q: %w", permitID, ErrPermitMissing)
	}
	if record.state == permitAbandoned {
		return nil
	}
	if record.state == permitFinalized {
		return fmt.Errorf("abandon permit %q: %w", permitID, ErrStalePermit)
	}
	if guard := table.guards[record.permit.Key]; guard != nil {
		delete(guard.pending, permitID)
	}
	record.state = permitAbandoned
	return nil
}

func (table *GuardTable) Sweep(epoch uint64, rootsComplete bool, marked map[Key]struct{}, now time.Time) ([]Deletion, error) {
	if !rootsComplete {
		return nil, ErrIncompleteRoots
	}
	if now.IsZero() {
		return nil, fmt.Errorf("sweep time is required")
	}

	table.mu.Lock()
	defer table.mu.Unlock()

	if epoch <= table.lastEpoch {
		return nil, fmt.Errorf("sweep epoch %d after %d: %w", epoch, table.lastEpoch, ErrEpochOrder)
	}
	for key := range marked {
		if err := validateKey(key); err != nil {
			return nil, err
		}
		guard, found := table.guards[key]
		if !found || guard.state == Deleting || guard.state == Deleted {
			return nil, fmt.Errorf("mark %s: %w", key.Digest, ErrMarkedObjectMissing)
		}
	}

	table.lastEpoch = epoch
	deletions := make([]Deletion, 0)
	for key, guard := range table.guards {
		if guard.state == Deleting || guard.state == Deleted {
			continue
		}
		if _, found := marked[key]; found || len(guard.pending) > 0 {
			guard.state = Live
			guard.candidateEpoch = 0
			guard.candidateSince = time.Time{}
			continue
		}
		if guard.state == Live {
			guard.state = Candidate
			guard.candidateEpoch = epoch
			guard.candidateSince = now
			continue
		}
		if epoch > guard.candidateEpoch && !now.Before(guard.candidateSince.Add(table.grace)) {
			guard.state = Deleting
			guard.generation++
			guard.deletionEpoch = epoch
			deletions = append(deletions, Deletion{Key: key, GuardGeneration: guard.generation, Epoch: epoch})
		}
	}
	sort.Slice(deletions, func(left, right int) bool {
		if deletions[left].Key.TenantID != deletions[right].Key.TenantID {
			return deletions[left].Key.TenantID < deletions[right].Key.TenantID
		}
		return deletions[left].Key.Digest < deletions[right].Key.Digest
	})
	return deletions, nil
}

// CompleteDeletion updates metadata after deletion and waits for any physical
// operation already using this authority. Physical deletion itself must use
// ContentStore.Delete, which holds the fence across both operations.
func (table *GuardTable) CompleteDeletion(deletion Deletion) error {
	release, err := table.acquireStorage(context.Background(), deletion.Key)
	if err != nil {
		return err
	}
	defer release()
	return table.completeDeletion(deletion)
}

// completeDeletion requires the caller to hold the key's storage gate.
func (table *GuardTable) completeDeletion(deletion Deletion) error {
	if err := validateKey(deletion.Key); err != nil {
		return err
	}

	table.mu.Lock()
	defer table.mu.Unlock()

	guard, found := table.guards[deletion.Key]
	if found && guard.state == Deleted && deletionMatchesGuard(deletion, guard) {
		return nil
	}
	if !found || guard.state != Deleting || !deletionMatchesGuard(deletion, guard) {
		return fmt.Errorf("complete deletion of %s: %w", deletion.Key.Digest, ErrStaleDeletion)
	}
	guard.state = Deleted
	return nil
}

// ValidateDeletion checks the current metadata only. A successful result is not
// a storage deletion fence; use ContentStore.Delete for the physical operation.
func (table *GuardTable) ValidateDeletion(deletion Deletion) error {
	if err := validateKey(deletion.Key); err != nil {
		return err
	}
	table.mu.RLock()
	defer table.mu.RUnlock()
	guard, found := table.guards[deletion.Key]
	if !found || (guard.state != Deleting && guard.state != Deleted) || !deletionMatchesGuard(deletion, guard) {
		return fmt.Errorf("validate deletion of %s: %w", deletion.Key.Digest, ErrStaleDeletion)
	}
	return nil
}

func (table *GuardTable) Snapshot(key Key) GuardSnapshot {
	table.mu.RLock()
	defer table.mu.RUnlock()

	guard, found := table.guards[key]
	if !found {
		return GuardSnapshot{}
	}
	return GuardSnapshot{
		Found:          true,
		State:          guard.state,
		Generation:     guard.generation,
		Incarnation:    guard.incarnation,
		CreatedAt:      guard.createdAt,
		CandidateEpoch: guard.candidateEpoch,
		CandidateSince: guard.candidateSince,
		PendingPermits: len(guard.pending),
	}
}

func validateKey(key Key) error {
	if strings.TrimSpace(key.TenantID) == "" {
		return fmt.Errorf("blob tenant ID is required")
	}
	if !digestPattern.MatchString(key.Digest) {
		return fmt.Errorf("blob digest %q is not canonical SHA-256", key.Digest)
	}
	return nil
}

func deletionMatchesGuard(deletion Deletion, guard *guardRecord) bool {
	return guard.generation == deletion.GuardGeneration && guard.deletionEpoch == deletion.Epoch
}
