package blob

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestProtectionResurrectsCandidateAndIsIdempotent(t *testing.T) {
	t.Parallel()

	start := time.Unix(1_800_000_000, 0)
	table := NewGuardTable(time.Hour)
	key := validKey("tenant-a", "a")
	if err := table.Register(key, start); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if _, err := table.Sweep(1, true, nil, start); err != nil {
		t.Fatalf("Sweep(candidate) error = %v", err)
	}

	permit, err := table.Protect(key, "permit-1")
	if err != nil {
		t.Fatalf("Protect() error = %v", err)
	}
	replayed, err := table.Protect(key, "permit-1")
	if err != nil {
		t.Fatalf("Protect(replay) error = %v", err)
	}
	if replayed != permit {
		t.Fatalf("Protect(replay) = %#v, want %#v", replayed, permit)
	}
	if snapshot := table.Snapshot(key); snapshot.State != Live || snapshot.PendingPermits != 1 {
		t.Fatalf("Snapshot() = %#v, want live with one pending permit", snapshot)
	}

	if err := table.Finalize("permit-1"); err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}
	if err := table.Finalize("permit-1"); err != nil {
		t.Fatalf("Finalize(replay) error = %v", err)
	}
	if snapshot := table.Snapshot(key); snapshot.PendingPermits != 0 {
		t.Fatalf("Snapshot().PendingPermits = %d, want 0", snapshot.PendingPermits)
	}
}

func TestSweepRequiresTwoCompleteEpochsAndGrace(t *testing.T) {
	t.Parallel()

	start := time.Unix(1_800_000_000, 0)
	table := NewGuardTable(time.Hour)
	key := validKey("tenant-a", "b")
	if err := table.Register(key, start); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	if _, err := table.Sweep(1, false, nil, start.Add(24*time.Hour)); !errors.Is(err, ErrIncompleteRoots) {
		t.Fatalf("Sweep(incomplete) error = %v, want ErrIncompleteRoots", err)
	}
	if snapshot := table.Snapshot(key); snapshot.State != Live {
		t.Fatalf("state after incomplete roots = %q, want %q", snapshot.State, Live)
	}
	if deletions, err := table.Sweep(1, true, nil, start); err != nil || len(deletions) != 0 {
		t.Fatalf("Sweep(first complete) = %#v, %v, want no deletions", deletions, err)
	}
	if snapshot := table.Snapshot(key); snapshot.State != Candidate || snapshot.CandidateEpoch != 1 {
		t.Fatalf("first complete snapshot = %#v, want epoch-1 candidate", snapshot)
	}
	if deletions, err := table.Sweep(2, true, nil, start.Add(59*time.Minute)); err != nil || len(deletions) != 0 {
		t.Fatalf("Sweep(before grace) = %#v, %v, want no deletions", deletions, err)
	}
	if deletions, err := table.Sweep(3, true, nil, start.Add(time.Hour)); err != nil || len(deletions) != 1 {
		t.Fatalf("Sweep(after grace) = %#v, %v, want one deletion", deletions, err)
	}
	if snapshot := table.Snapshot(key); snapshot.State != Deleting {
		t.Fatalf("state after sweep = %q, want %q", snapshot.State, Deleting)
	}
}

func TestMarkResurrectsCandidate(t *testing.T) {
	t.Parallel()

	start := time.Unix(1_800_000_000, 0)
	table := NewGuardTable(time.Minute)
	key := validKey("tenant-a", "c")
	if err := table.Register(key, start); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if _, err := table.Sweep(1, true, nil, start); err != nil {
		t.Fatalf("Sweep(candidate) error = %v", err)
	}
	if _, err := table.Sweep(2, true, map[Key]struct{}{key: {}}, start.Add(time.Hour)); err != nil {
		t.Fatalf("Sweep(marked) error = %v", err)
	}
	if snapshot := table.Snapshot(key); snapshot.State != Live || snapshot.CandidateEpoch != 0 {
		t.Fatalf("marked snapshot = %#v, want resurrected live object", snapshot)
	}
}

func TestPendingProtectionNeverExpiresByWallClock(t *testing.T) {
	t.Parallel()

	start := time.Unix(1_800_000_000, 0)
	table := NewGuardTable(time.Minute)
	key := validKey("tenant-a", "d")
	if err := table.Register(key, start); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if _, err := table.Protect(key, "permit-pending"); err != nil {
		t.Fatalf("Protect() error = %v", err)
	}
	for epoch := uint64(1); epoch <= 3; epoch++ {
		if deletions, err := table.Sweep(epoch, true, nil, start.Add(time.Duration(epoch)*24*time.Hour)); err != nil || len(deletions) != 0 {
			t.Fatalf("Sweep(%d) = %#v, %v, want protected object", epoch, deletions, err)
		}
	}
	if snapshot := table.Snapshot(key); snapshot.State != Live || snapshot.PendingPermits != 1 {
		t.Fatalf("pending snapshot = %#v, want live protected object", snapshot)
	}
}

func TestProtectAndDeleteCASHaveOneWinner(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)

	for iteration := range 100 {
		table := NewGuardTable(time.Minute)
		key := validKey("tenant-race", "e")
		if err := table.Register(key, start); err != nil {
			t.Fatalf("iteration %d Register() error = %v", iteration, err)
		}
		if _, err := table.Sweep(1, true, nil, start); err != nil {
			t.Fatalf("iteration %d Sweep(candidate) error = %v", iteration, err)
		}

		ready := make(chan struct{})
		var wait sync.WaitGroup
		wait.Add(2)
		var protectErr error
		var deletions []Deletion
		var sweepErr error
		go func() {
			defer wait.Done()
			<-ready
			_, protectErr = table.Protect(key, "permit-race")
		}()
		go func() {
			defer wait.Done()
			<-ready
			deletions, sweepErr = table.Sweep(2, true, nil, start.Add(time.Hour))
		}()
		close(ready)
		wait.Wait()

		if sweepErr != nil {
			t.Fatalf("iteration %d Sweep(delete) error = %v", iteration, sweepErr)
		}
		protectWon := protectErr == nil
		deleteWon := len(deletions) == 1
		if protectWon == deleteWon {
			t.Fatalf("iteration %d protectWon=%t deleteWon=%t snapshot=%#v", iteration, protectWon, deleteWon, table.Snapshot(key))
		}
		if deleteWon && !errors.Is(protectErr, ErrObjectDeleting) {
			t.Fatalf("iteration %d Protect() error = %v, want ErrObjectDeleting", iteration, protectErr)
		}
	}
}

func TestDeletionCompletionIsGenerationFenced(t *testing.T) {
	t.Parallel()

	start := time.Unix(1_800_000_000, 0)
	table := NewGuardTable(0)
	key := validKey("tenant-a", "f")
	if err := table.Register(key, start); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if _, err := table.Sweep(1, true, nil, start); err != nil {
		t.Fatalf("Sweep(candidate) error = %v", err)
	}
	deletions, err := table.Sweep(2, true, nil, start)
	if err != nil || len(deletions) != 1 {
		t.Fatalf("Sweep(delete) = %#v, %v", deletions, err)
	}
	deletion := deletions[0]
	tampered := deletion
	tampered.Epoch++
	if err := table.CompleteDeletion(tampered); !errors.Is(err, ErrStaleDeletion) {
		t.Fatalf("CompleteDeletion(tampered epoch) error = %v, want ErrStaleDeletion", err)
	}
	if err := table.CompleteDeletion(deletion); err != nil {
		t.Fatalf("CompleteDeletion() error = %v", err)
	}
	if err := table.Register(key, start.Add(time.Second)); err != nil {
		t.Fatalf("Register(restored) error = %v", err)
	}
	if err := table.CompleteDeletion(deletion); !errors.Is(err, ErrStaleDeletion) {
		t.Fatalf("CompleteDeletion(stale) error = %v, want ErrStaleDeletion", err)
	}
	if snapshot := table.Snapshot(key); snapshot.State != Live || snapshot.Generation <= deletion.GuardGeneration {
		t.Fatalf("restored snapshot = %#v, want newer live generation", snapshot)
	}
}

func TestPermitIDCannotBeReusedForAnotherObject(t *testing.T) {
	t.Parallel()

	start := time.Unix(1_800_000_000, 0)
	table := NewGuardTable(time.Hour)
	first := validKey("tenant-a", "1")
	second := validKey("tenant-a", "2")
	if err := table.Register(first, start); err != nil {
		t.Fatalf("Register(first) error = %v", err)
	}
	if err := table.Register(second, start); err != nil {
		t.Fatalf("Register(second) error = %v", err)
	}
	if _, err := table.Protect(first, "permit-shared"); err != nil {
		t.Fatalf("Protect(first) error = %v", err)
	}
	if _, err := table.Protect(second, "permit-shared"); !errors.Is(err, ErrPermitReused) {
		t.Fatalf("Protect(second) error = %v, want ErrPermitReused", err)
	}
}

func TestFinalizedPermitCannotProtectRestoredIncarnation(t *testing.T) {
	t.Parallel()

	start := time.Unix(1_800_000_000, 0)
	table := NewGuardTable(0)
	key := validKey("tenant-a", "3")
	if err := table.Register(key, start); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if _, err := table.Protect(key, "permit-old-incarnation"); err != nil {
		t.Fatalf("Protect() error = %v", err)
	}
	if err := table.Finalize("permit-old-incarnation"); err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}
	if _, err := table.Sweep(1, true, nil, start); err != nil {
		t.Fatalf("Sweep(candidate) error = %v", err)
	}
	deletions, err := table.Sweep(2, true, nil, start)
	if err != nil || len(deletions) != 1 {
		t.Fatalf("Sweep(delete) = %#v, %v", deletions, err)
	}
	if err := table.CompleteDeletion(deletions[0]); err != nil {
		t.Fatalf("CompleteDeletion() error = %v", err)
	}
	if err := table.Register(key, start.Add(time.Second)); err != nil {
		t.Fatalf("Register(restored) error = %v", err)
	}
	if _, err := table.Protect(key, "permit-old-incarnation"); !errors.Is(err, ErrStalePermit) {
		t.Fatalf("Protect(old permit) error = %v, want ErrStalePermit", err)
	}
}

func TestAbandonedPermitIDRemainsReserved(t *testing.T) {
	t.Parallel()

	start := time.Unix(1_800_000_000, 0)
	table := NewGuardTable(time.Hour)
	first := validKey("tenant-a", "4")
	second := validKey("tenant-a", "5")
	if err := table.Register(first, start); err != nil {
		t.Fatalf("Register(first) error = %v", err)
	}
	if err := table.Register(second, start); err != nil {
		t.Fatalf("Register(second) error = %v", err)
	}
	if _, err := table.Protect(first, "permit-abandoned"); err != nil {
		t.Fatalf("Protect(first) error = %v", err)
	}
	if err := table.Abandon("permit-abandoned"); err != nil {
		t.Fatalf("Abandon() error = %v", err)
	}
	if err := table.Abandon("permit-abandoned"); err != nil {
		t.Fatalf("Abandon(replay) error = %v", err)
	}
	if _, err := table.Protect(second, "permit-abandoned"); !errors.Is(err, ErrPermitReused) {
		t.Fatalf("Protect(second) error = %v, want ErrPermitReused", err)
	}
	if _, err := table.Protect(first, "permit-abandoned"); !errors.Is(err, ErrStalePermit) {
		t.Fatalf("Protect(first replay) error = %v, want ErrStalePermit", err)
	}
}

func validKey(tenant, nibble string) Key {
	return Key{TenantID: tenant, Digest: "sha256:" + strings.Repeat(nibble, 64)}
}
