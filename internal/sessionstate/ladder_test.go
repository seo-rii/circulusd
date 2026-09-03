package sessionstate

import (
	"context"
	"errors"
	"testing"

	"github.com/hancomac/circulusd/internal/celld"
)

// enc drops the always-nil encode error for valid test inputs so a command body
// can be built inline.
func enc(command []byte, _ error) []byte { return command }

func execute(host *celld.Host, object, commandID string, command []byte) (celld.Result, error) {
	return host.Execute(context.Background(), celld.Request{ObjectID: object, CommandID: commandID, Command: command})
}

func TestModelEffectLadderAdvancesInOrder(t *testing.T) {
	t.Parallel()
	storage := NewReferenceStorage()
	host := newHost(t, storage, nil)
	const object = "sess_model"

	steps := []struct {
		commandID string
		command   []byte
		wantPhase string
	}{
		{"c1", enc(EncodeOpenTurn("turn-1", 1)), phaseAccepted},
		{"c2", enc(EncodePrepareModelEffect("turn-1", "eff-1", "sha256:req", 1)), phaseModelPrepared},
		{"c3", enc(EncodeDispatchModelEffect("turn-1", "eff-1", "provider-req-1", 1)), phaseModelDispatched},
		{"c4", enc(EncodeSettleModelEffect("turn-1", "eff-1", "commit-1", 1)), phaseModelSettled},
		{"c5", enc(EncodeCompleteTurn("turn-1", 1)), phaseIdle},
	}
	for index, step := range steps {
		if _, err := execute(host, object, step.commandID, step.command); err != nil {
			t.Fatalf("step %d (%s): %v", index, step.commandID, err)
		}
		if phase := finalState(t, storage, object).TurnPhase; phase != step.wantPhase {
			t.Fatalf("step %d: phase = %q, want %q", index, phase, step.wantPhase)
		}
	}
	state := finalState(t, storage, object)
	if state.EventSequence != 5 || state.ActiveTurnID != "" || state.EffectID != "" {
		t.Fatalf("final state = %+v, want seq=5, no active turn or effect", state)
	}
}

func TestModelEffectRejectsOutOfOrderAndDoubleDispatch(t *testing.T) {
	t.Parallel()
	storage := NewReferenceStorage()
	host := newHost(t, storage, nil)
	const object = "sess_order"

	if _, err := execute(host, object, "c1", enc(EncodeOpenTurn("turn-1", 1))); err != nil {
		t.Fatalf("open: %v", err)
	}
	// Dispatch before prepare: wrong phase.
	if _, err := execute(host, object, "c2", enc(EncodeDispatchModelEffect("turn-1", "eff-1", "p1", 1))); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("dispatch before prepare = %v, want ErrInvalidTransition", err)
	}
	if _, err := execute(host, object, "c3", enc(EncodePrepareModelEffect("turn-1", "eff-1", "d1", 1))); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	// A second effect while one is active violates the serial-effect invariant.
	if _, err := execute(host, object, "c4", enc(EncodePrepareModelEffect("turn-1", "eff-2", "d2", 1))); !errors.Is(err, ErrEffectActive) {
		t.Fatalf("second prepare = %v, want ErrEffectActive", err)
	}
	// Settle before dispatch: wrong phase.
	if _, err := execute(host, object, "c5", enc(EncodeSettleModelEffect("turn-1", "eff-1", "commit-1", 1))); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("settle before dispatch = %v, want ErrInvalidTransition", err)
	}
	if _, err := execute(host, object, "c6", enc(EncodeDispatchModelEffect("turn-1", "eff-1", "p1", 1))); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	// A second dispatch under a fresh command id must not re-dispatch: no
	// duplicate external mutation.
	if _, err := execute(host, object, "c7", enc(EncodeDispatchModelEffect("turn-1", "eff-1", "p2", 1))); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("double dispatch = %v, want ErrInvalidTransition", err)
	}
	if _, err := execute(host, object, "c8", enc(EncodeSettleModelEffect("turn-1", "eff-1", "commit-1", 1))); err != nil {
		t.Fatalf("settle: %v", err)
	}
	if state := finalState(t, storage, object); state.TurnPhase != phaseModelSettled || state.EffectID != "" {
		t.Fatalf("final state = %+v, want model_settled with no active effect", state)
	}
}

func TestModelEffectMismatchedEffectIDRejected(t *testing.T) {
	t.Parallel()
	storage := NewReferenceStorage()
	host := newHost(t, storage, nil)
	const object = "sess_mismatch"

	if _, err := execute(host, object, "c1", enc(EncodeOpenTurn("turn-1", 1))); err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := execute(host, object, "c2", enc(EncodePrepareModelEffect("turn-1", "eff-1", "d1", 1))); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if _, err := execute(host, object, "c3", enc(EncodeDispatchModelEffect("turn-1", "eff-9", "p1", 1))); !errors.Is(err, ErrEffectMismatch) {
		t.Fatalf("dispatch mismatched effect = %v, want ErrEffectMismatch", err)
	}
}
