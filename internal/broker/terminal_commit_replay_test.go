package broker

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/identity"
)

var errTerminalCommitReplyLost = errors.New("terminal commit reply lost after durability barrier")

// Model the owner's receipt-before-CAS contract: an exact retained command can
// replay after its turn ends, but any new command still needs a current snapshot.
type terminalCommitStore struct {
	*fakeStore
	committed      *CommitStepCommand
	receipt        EngineStepReceipt
	commitCalls    int
	transitions    int
	replaySnapshot TurnSnapshot
}

func (store *terminalCommitStore) CommitEngineStep(ctx context.Context, command CommitStepCommand) (EngineStepReceipt, error) {
	store.commitCalls++
	if original := store.committed; original != nil && original.OperationKey == command.OperationKey {
		store.replaySnapshot = command.Snapshot
		if original.RequestDigest != command.RequestDigest || original.Permit.Opaque != command.Permit.Opaque || !reflect.DeepEqual(original.Boundary, command.Boundary) {
			return EngineStepReceipt{}, ErrIdempotencyConflict
		}
		return store.receipt, nil
	}
	current := store.snapshot
	if !current.Active || command.Snapshot.SessionID != current.SessionID || command.Snapshot.TurnID != current.TurnID || command.Snapshot.Generations != current.Generations || command.Snapshot.EventSequence != current.EventSequence || command.Snapshot.CheckpointDigest != current.CheckpointDigest {
		return EngineStepReceipt{}, ErrStaleGeneration
	}
	if !command.Now.Before(command.Permit.Deadline) {
		return EngineStepReceipt{}, ErrInvalidRequest
	}
	receipt, err := store.fakeStore.CommitEngineStep(ctx, command)
	if err != nil {
		return receipt, err
	}
	store.committed, store.receipt = &command, receipt
	store.transitions++
	store.snapshot.Active = false
	store.snapshot.TurnID = identity.ID{}
	store.snapshot.Generations.TurnLease = 0
	store.snapshot.CheckpointDigest = Digest{}
	store.snapshot.Checkpoint = nil
	store.snapshot.EventSequence = receipt.EventSequence
	return EngineStepReceipt{}, errTerminalCommitReplyLost
}

func terminalCommitRequest(t *testing.T, store *terminalCommitStore, now time.Time) EngineStepCommit {
	t.Helper()
	return EngineStepCommit{
		Permit: acquirePermit(t, mustCoordinator(t, store, nil), now, "terminal-grant"),
		Now:    now, OperationKey: "terminal-commit", RequestDigest: digest(83),
		Boundary: EngineBoundary{Kind: BoundaryTurnComplete, CheckpointDigest: digest(84)},
	}
}

func TestTerminalCommitReplaysAfterResponseLoss(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0).UTC()
	boundaries := map[string]EngineBoundary{
		"complete": {Kind: BoundaryTurnComplete, CheckpointDigest: digest(84)},
		"error":    {Kind: BoundaryTurnError, CheckpointDigest: digest(84)},
		"proto complete": {CheckpointDigest: digest(84), Message: &v1.EngineStepBoundary{
			Checkpoint: &v1.AgentCheckpoint{}, Boundary: &v1.EngineStepBoundary_TurnComplete{TurnComplete: &v1.TurnResult{}},
		}},
		"proto error": {CheckpointDigest: digest(84), Message: &v1.EngineStepBoundary{
			Checkpoint: &v1.AgentCheckpoint{}, Boundary: &v1.EngineStepBoundary_TurnError{TurnError: &v1.AgentError{}},
		}},
	}
	for name, boundary := range boundaries {
		for _, nextTurn := range []bool{false, true} {
			t.Run(name+map[bool]string{false: "/idle", true: "/next turn"}[nextTurn], func(t *testing.T) {
				store := &terminalCommitStore{fakeStore: newFakeStore(baseSnapshot(now))}
				request := terminalCommitRequest(t, store, now)
				request.Boundary = boundary
				if _, err := mustCoordinator(t, store, nil).CommitEngineStep(context.Background(), request); !errors.Is(err, errTerminalCommitReplyLost) {
					t.Fatalf("initial commit error = %v", err)
				}
				if nextTurn {
					store.snapshot.Active = true
					store.snapshot.TurnID = mustID(identity.Turn, "next")
					store.snapshot.Generations.TurnLease = request.Permit.Generations.TurnLease + 1
					store.snapshot.CheckpointDigest = digest(85)
				}
				for _, retryTime := range []time.Time{now.Add(time.Millisecond), request.Permit.Deadline.Add(time.Hour)} {
					request.Now = retryTime
					receipt, err := mustCoordinator(t, store, nil).CommitEngineStep(context.Background(), request)
					if err != nil || !reflect.DeepEqual(receipt, store.receipt) || store.transitions != 1 {
						t.Fatalf("terminal receipt replay = %#v, %v; transitions=%d", receipt, err, store.transitions)
					}
					if source := store.replaySnapshot; source.TenantID != request.Permit.TenantID || source.WorkspaceID != request.Permit.WorkspaceID || source.UserID != request.Permit.UserID || source.SessionID != request.Permit.SessionID || source.TurnID != request.Permit.TurnID || source.Generations != request.Permit.Generations || source.EventSequence != request.Permit.ExpectedEventSequence || source.CheckpointDigest != request.Permit.CheckpointDigest {
						t.Fatalf("replay did not preserve the original CAS: %#v", source)
					}
				}
			})
		}
	}
}

func TestTerminalCommitReplayRetainsCurrentAuthorityFencing(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0).UTC()
	tests := []struct {
		name   string
		mutate func(*TurnSnapshot)
		want   error
	}{
		{"tenant", func(s *TurnSnapshot) { s.TenantID = mustID(identity.Tenant, "other") }, ErrFenceMismatch},
		{"workspace", func(s *TurnSnapshot) { s.WorkspaceID = mustID(identity.Workspace, "other") }, ErrFenceMismatch},
		{"user", func(s *TurnSnapshot) { s.UserID = mustID(identity.Subject, "other") }, ErrFenceMismatch},
		{"session", func(s *TurnSnapshot) { s.SessionID = mustID(identity.Session, "other") }, ErrStaleGeneration},
		{"authorization", func(s *TurnSnapshot) { s.Generations.Authorization++ }, ErrStaleGeneration},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &terminalCommitStore{fakeStore: newFakeStore(baseSnapshot(now))}
			request := terminalCommitRequest(t, store, now)
			if _, err := mustCoordinator(t, store, nil).CommitEngineStep(context.Background(), request); !errors.Is(err, errTerminalCommitReplyLost) {
				t.Fatal(err)
			}
			test.mutate(&store.snapshot)
			if _, err := mustCoordinator(t, store, nil).CommitEngineStep(context.Background(), request); !errors.Is(err, test.want) {
				t.Fatalf("replay error = %v, want %v", err, test.want)
			}
			if store.commitCalls != 1 {
				t.Fatal("cross-authority replay reached the durable store")
			}
		})
	}
}

func TestTerminalCommitReplayCannotCommitDifferentCommand(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0).UTC()
	tests := []struct {
		name   string
		mutate func(*EngineStepCommit)
		want   error
	}{
		{"missing receipt", func(r *EngineStepCommit) { r.OperationKey = "new-operation" }, ErrStaleGeneration},
		{"different digest", func(r *EngineStepCommit) { r.RequestDigest = digest(101) }, ErrIdempotencyConflict},
		{"different boundary", func(r *EngineStepCommit) { r.Boundary.Kind = BoundaryTurnError }, ErrIdempotencyConflict},
		{"different proof", func(r *EngineStepCommit) { r.Permit.Opaque = opaque(101) }, ErrIdempotencyConflict},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &terminalCommitStore{fakeStore: newFakeStore(baseSnapshot(now))}
			request := terminalCommitRequest(t, store, now)
			if _, err := mustCoordinator(t, store, nil).CommitEngineStep(context.Background(), request); !errors.Is(err, errTerminalCommitReplyLost) {
				t.Fatal(err)
			}
			test.mutate(&request)
			store.snapshot.Active = true
			store.snapshot.TurnID = mustID(identity.Turn, "next")
			store.snapshot.Generations.TurnLease = request.Permit.Generations.TurnLease + 1
			store.snapshot.CheckpointDigest = digest(85)
			request.Now = request.Permit.Deadline.Add(time.Second)
			if _, err := mustCoordinator(t, store, nil).CommitEngineStep(context.Background(), request); !errors.Is(err, test.want) {
				t.Fatalf("replay error = %v, want %v", err, test.want)
			}
			if store.transitions != 1 {
				t.Fatal("replay performed a fresh mutation")
			}
		})
	}
}

func TestTerminalCommitReplayDoesNotRelaxFreshCommitAdmission(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0).UTC()
	t.Run("expired fresh terminal commit", func(t *testing.T) {
		store := &terminalCommitStore{fakeStore: newFakeStore(baseSnapshot(now))}
		request := terminalCommitRequest(t, store, now)
		request.Now = request.Permit.Deadline
		if _, err := mustCoordinator(t, store, nil).CommitEngineStep(context.Background(), request); !errors.Is(err, ErrInvalidRequest) || store.commitCalls != 0 {
			t.Fatalf("fresh expired commit error = %v, calls=%d", err, store.commitCalls)
		}
	})
	t.Run("stale nonterminal commit", func(t *testing.T) {
		store := &terminalCommitStore{fakeStore: newFakeStore(baseSnapshot(now))}
		request := terminalCommitRequest(t, store, now)
		request.Boundary.Kind = BoundaryCheckpoint
		store.snapshot.Generations.Placement++
		if _, err := mustCoordinator(t, store, nil).CommitEngineStep(context.Background(), request); !errors.Is(err, ErrStaleGeneration) || store.commitCalls != 0 {
			t.Fatalf("stale nonterminal commit error = %v, calls=%d", err, store.commitCalls)
		}
	})
	t.Run("missing receipt after placement moves", func(t *testing.T) {
		store := &terminalCommitStore{fakeStore: newFakeStore(baseSnapshot(now))}
		request := terminalCommitRequest(t, store, now)
		store.snapshot.Generations.Placement++
		if _, err := mustCoordinator(t, store, nil).CommitEngineStep(context.Background(), request); !errors.Is(err, ErrStaleGeneration) || store.transitions != 0 {
			t.Fatalf("stale fresh terminal commit error = %v, transitions=%d", err, store.transitions)
		}
	})
}
