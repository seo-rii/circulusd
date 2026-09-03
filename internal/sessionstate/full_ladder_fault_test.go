package sessionstate

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/hancomac/circulusd/internal/celld"
)

type ladderStep struct {
	id      string
	command []byte
}

// fullTurnSteps is one complete turn exercising every durable transition in the
// SPEC §15 ladder: open, the model effect ladder, the tool effect ladder, and
// completion — nine durable transitions in all.
func fullTurnSteps() []ladderStep {
	return []ladderStep{
		{"open", enc(EncodeOpenTurn("turn-1", 1))},
		{"model-prepare", enc(EncodePrepareModelEffect("turn-1", "eff-model", "sha256:m", 1))},
		{"model-dispatch", enc(EncodeDispatchModelEffect("turn-1", "eff-model", "prov-m", 1))},
		{"model-settle", enc(EncodeSettleModelEffect("turn-1", "eff-model", "commit-m", 1))},
		{"tool-prepare", enc(EncodePrepareToolEffect("turn-1", "eff-tool", "sha256:t", 1))},
		{"tool-dispatch", enc(EncodeDispatchToolEffect("turn-1", "eff-tool", "prov-t", 1))},
		{"tool-commit", enc(EncodeCommitToolEffect("turn-1", "eff-tool", "ext-commit", 1))},
		{"tool-settle", enc(EncodeSettleToolEffect("turn-1", "eff-tool", 1))},
		{"complete", enc(EncodeCompleteTurn("turn-1", 1))},
	}
}

// TestFullLadderKillRestartMatrix injects a crash before and after every durable
// transition of a complete turn (SPEC §51.2 / §53.5). For each (transition, fault
// point) it runs the clean prefix, crashes the target transition at that point,
// restarts a fresh Host over the same durable storage, and replays to the end.
// The turn must always recover to the same final state — no lost transition, no
// duplicate external mutation — whether the crash rolled the transition back
// (before commit) or left it committed for replay (after commit).
func TestFullLadderKillRestartMatrix(t *testing.T) {
	t.Parallel()
	steps := fullTurnSteps()
	points := []celld.FaultPoint{
		celld.FaultBeforeCommit,
		celld.FaultAfterCommit,
		celld.FaultBeforeBarrier,
		celld.FaultAfterBarrier,
		celld.FaultBeforeResponse,
	}
	for crashIndex := range steps {
		for _, point := range points {
			name := fmt.Sprintf("%s@%s", steps[crashIndex].id, point)
			crashIndex, point := crashIndex, point
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				storage := NewReferenceStorage()
				const object = "sess_full"

				// Clean prefix.
				clean := newHost(t, storage, nil)
				for i := 0; i < crashIndex; i++ {
					if _, err := execute(clean, object, steps[i].id, steps[i].command); err != nil {
						t.Fatalf("prefix step %s: %v", steps[i].id, err)
					}
				}

				// Crash the target transition at the target fault point.
				crash := errors.New("injected crash")
				var fired atomic.Bool
				crashing := newHost(t, storage, celld.FaultInjectorFunc(func(_ context.Context, at celld.FaultPoint) error {
					if at == point && fired.CompareAndSwap(false, true) {
						return crash
					}
					return nil
				}))
				if _, err := execute(crashing, object, steps[crashIndex].id, steps[crashIndex].command); !errors.Is(err, crash) {
					t.Fatalf("expected injected crash for %s, got %v", name, err)
				}

				// Restart and replay from the crashed transition to the end.
				recovered := newHost(t, storage, nil)
				for i := crashIndex; i < len(steps); i++ {
					if _, err := execute(recovered, object, steps[i].id, steps[i].command); err != nil {
						t.Fatalf("recovery step %s after crash %s: %v", steps[i].id, name, err)
					}
				}

				state := finalState(t, storage, object)
				if state.EventSequence != int64(len(steps)) || state.ActiveTurnID != "" ||
					state.TurnPhase != phaseIdle || state.EffectID != "" {
					t.Fatalf("crash %s: final state = %+v, want clean completion at sequence %d", name, state, len(steps))
				}
			})
		}
	}
}
