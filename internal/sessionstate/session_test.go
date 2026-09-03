package sessionstate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/celld"
)

func newHost(t *testing.T, storage celld.Storage, faults celld.FaultInjector) *celld.Host {
	t.Helper()
	sealer, err := celld.NewPermitCodec(bytes.Repeat([]byte{0x5c}, 32))
	if err != nil {
		t.Fatalf("NewPermitCodec() error = %v", err)
	}
	host, err := celld.NewHost(celld.Config{
		Storage:       storage,
		Aggregate:     Aggregate{},
		Sealer:        sealer,
		FaultInjector: faults,
	})
	if err != nil {
		t.Fatalf("NewHost() error = %v", err)
	}
	return host
}

func execOpen(t *testing.T, host *celld.Host, objectID, commandID, turnID string, generation int64) (celld.Result, error) {
	t.Helper()
	command, err := EncodeOpenTurn(turnID, generation)
	if err != nil {
		t.Fatalf("EncodeOpenTurn() error = %v", err)
	}
	return host.Execute(context.Background(), celld.Request{ObjectID: objectID, CommandID: commandID, Command: command})
}

func execComplete(t *testing.T, host *celld.Host, objectID, commandID, turnID string, generation int64) (celld.Result, error) {
	t.Helper()
	command, err := EncodeCompleteTurn(turnID, generation)
	if err != nil {
		t.Fatalf("EncodeCompleteTurn() error = %v", err)
	}
	return host.Execute(context.Background(), celld.Request{ObjectID: objectID, CommandID: commandID, Command: command})
}

func finalState(t *testing.T, storage *ReferenceStorage, objectID string) SessionState {
	t.Helper()
	stateBytes, ok := storage.State(objectID)
	if !ok {
		t.Fatalf("no committed state for %q", objectID)
	}
	state, err := DecodeState(stateBytes)
	if err != nil {
		t.Fatalf("DecodeState() error = %v", err)
	}
	return state
}

func TestOpenTurnAdmitsSequentiallyAndIsIdempotent(t *testing.T) {
	t.Parallel()
	storage := NewReferenceStorage()
	host := newHost(t, storage, nil)
	const object = "sess_alpha"

	first, err := execOpen(t, host, object, "c1", "turn-1", 1)
	if err != nil {
		t.Fatalf("open turn-1: %v", err)
	}
	if first.Replayed || !first.Durable {
		t.Fatalf("first result replayed=%v durable=%v, want false/true", first.Replayed, first.Durable)
	}

	replay, err := execOpen(t, host, object, "c1", "turn-1", 1)
	if err != nil {
		t.Fatalf("replay of c1: %v", err)
	}
	if !replay.Replayed || !bytes.Equal(replay.Response, first.Response) {
		t.Fatalf("replay result = %+v, want same response marked replayed", replay)
	}

	if _, err := execOpen(t, host, object, "c2", "turn-2", 1); !errors.Is(err, ErrTurnActive) {
		t.Fatalf("open turn-2 while active = %v, want ErrTurnActive", err)
	}

	if _, err := execComplete(t, host, object, "c3", "turn-1", 1); err != nil {
		t.Fatalf("complete turn-1: %v", err)
	}
	if _, err := execOpen(t, host, object, "c4", "turn-2", 1); err != nil {
		t.Fatalf("open turn-2 after completion: %v", err)
	}

	state := finalState(t, storage, object)
	if state.EventSequence != 3 || state.ActiveTurnID != "turn-2" || state.TurnPhase != phaseAccepted {
		t.Fatalf("final state = %+v, want seq=3 active=turn-2 accepted", state)
	}
}

func TestStaleTurnLeaseGenerationRejected(t *testing.T) {
	t.Parallel()
	storage := NewReferenceStorage()
	host := newHost(t, storage, nil)
	const object = "sess_beta"

	if _, err := execOpen(t, host, object, "c1", "turn-1", 2); err != nil {
		t.Fatalf("open turn-1 gen 2: %v", err)
	}
	// A command minted under an older lease generation is fenced out even though
	// it is otherwise well formed.
	if _, err := execComplete(t, host, object, "c2", "turn-1", 1); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("stale-generation complete = %v, want ErrStaleGeneration", err)
	}
	// The fenced command left no durable effect: the turn is still active at gen 2.
	state := finalState(t, storage, object)
	if state.EventSequence != 1 || state.ActiveTurnID != "turn-1" || state.TurnLeaseGeneration != 2 {
		t.Fatalf("final state = %+v, want the stale command to have no effect", state)
	}
}

func TestKillRestartFaultMatrixPreservesExactlyOneAdmission(t *testing.T) {
	t.Parallel()
	points := []celld.FaultPoint{
		celld.FaultBeforeCommit,
		celld.FaultAfterCommit,
		celld.FaultBeforeBarrier,
		celld.FaultAfterBarrier,
		celld.FaultBeforeResponse,
	}
	for _, point := range points {
		point := point
		t.Run(string(point), func(t *testing.T) {
			t.Parallel()
			storage := NewReferenceStorage()
			const object = "sess_crash"

			crash := errors.New("injected crash")
			injector := celld.FaultInjectorFunc(func(_ context.Context, at celld.FaultPoint) error {
				if at == point {
					return crash
				}
				return nil
			})
			crashed := newHost(t, storage, injector)
			if _, err := execOpen(t, crashed, object, "c1", "turn-1", 1); !errors.Is(err, crash) {
				t.Fatalf("expected injected crash at %s, got %v", point, err)
			}

			// Restart: a fresh Host over the same durable storage re-runs the same
			// command. A crash before commit rolls the transition back and it
			// applies fresh; a crash after commit replays the persisted receipt.
			// Either way the turn is admitted exactly once.
			restarted := newHost(t, storage, nil)
			recovered, err := execOpen(t, restarted, object, "c1", "turn-1", 1)
			if err != nil {
				t.Fatalf("recovery after crash at %s: %v", point, err)
			}
			expectReplay := point != celld.FaultBeforeCommit
			if recovered.Replayed != expectReplay {
				t.Fatalf("crash at %s: recovered replayed=%v, want %v", point, recovered.Replayed, expectReplay)
			}
			state := finalState(t, storage, object)
			if state.EventSequence != 1 || state.ActiveTurnID != "turn-1" {
				t.Fatalf("crash at %s: final state = %+v, want exactly one admission", point, state)
			}
		})
	}
}

func TestConcurrentAdmissionsAreSingleWriter(t *testing.T) {
	t.Parallel()

	t.Run("same command id is idempotent", func(t *testing.T) {
		t.Parallel()
		storage := NewReferenceStorage()
		host := newHost(t, storage, nil)
		const (
			object  = "sess_idem"
			workers = 32
		)
		var waitGroup sync.WaitGroup
		var failure atomic.Value
		for worker := 0; worker < workers; worker++ {
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				result, err := execOpen(t, host, object, "shared", "turn-1", 1)
				if err != nil {
					failure.Store(fmt.Sprintf("Execute: %v", err))
					return
				}
				if sequenceOf(t, result.Response) != 1 {
					failure.Store("admission reported a sequence other than 1")
				}
			}()
		}
		waitGroup.Wait()
		if problem := failure.Load(); problem != nil {
			t.Fatal(problem)
		}
		if state := finalState(t, storage, object); state.EventSequence != 1 || state.ActiveTurnID != "turn-1" {
			t.Fatalf("final state = %+v, want exactly one admission", state)
		}
	})

	t.Run("distinct commands admit exactly one turn", func(t *testing.T) {
		t.Parallel()
		storage := NewReferenceStorage()
		host := newHost(t, storage, nil)
		const (
			object  = "sess_race"
			workers = 32
		)
		var (
			waitGroup sync.WaitGroup
			admitted  atomic.Int64
			active    atomic.Int64
		)
		for worker := 0; worker < workers; worker++ {
			worker := worker
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				_, err := execOpen(t, host, object,
					fmt.Sprintf("c-%d", worker), fmt.Sprintf("turn-%d", worker), 1)
				switch {
				case err == nil:
					admitted.Add(1)
				case errors.Is(err, ErrTurnActive):
					active.Add(1)
				default:
					t.Errorf("unexpected error: %v", err)
				}
			}()
		}
		waitGroup.Wait()
		if admitted.Load() != 1 || active.Load() != workers-1 {
			t.Fatalf("admitted=%d turn-active-rejections=%d, want 1 and %d", admitted.Load(), active.Load(), workers-1)
		}
		if state := finalState(t, storage, object); state.EventSequence != 1 || state.ActiveTurnID == "" {
			t.Fatalf("final state = %+v, want exactly one active turn", state)
		}
	})
}

func sequenceOf(t *testing.T, response []byte) int64 {
	t.Helper()
	value, err := canonical.Decode(response, canonical.DefaultOptions())
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	fields, ok := value.(canonical.Map)
	if !ok {
		t.Fatalf("response is not a map: %T", value)
	}
	sequence, ok := fields["eventSequence"].(int64)
	if !ok {
		t.Fatalf("response eventSequence missing or wrong type")
	}
	return sequence
}
