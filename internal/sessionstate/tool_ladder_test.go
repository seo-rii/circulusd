package sessionstate

import (
	"errors"
	"testing"

	"github.com/hancomac/circulusd/internal/celld"
)

// driveToModelSettled runs a turn through open and the full model effect ladder,
// leaving the session in phase model_settled at event sequence 4.
func driveToModelSettled(t *testing.T, host *celld.Host, object string) {
	t.Helper()
	steps := []struct {
		commandID string
		command   []byte
	}{
		{"o", enc(EncodeOpenTurn("turn-1", 1))},
		{"mp", enc(EncodePrepareModelEffect("turn-1", "eff-model", "sha256:m", 1))},
		{"md", enc(EncodeDispatchModelEffect("turn-1", "eff-model", "prov-m", 1))},
		{"ms", enc(EncodeSettleModelEffect("turn-1", "eff-model", "commit-m", 1))},
	}
	for _, step := range steps {
		if _, err := execute(host, object, step.commandID, step.command); err != nil {
			t.Fatalf("drive step %s: %v", step.commandID, err)
		}
	}
}

func TestToolEffectLadderAdvancesInOrderAndCompletes(t *testing.T) {
	t.Parallel()
	storage := NewReferenceStorage()
	host := newHost(t, storage, nil)
	const object = "sess_tool"
	driveToModelSettled(t, host, object)

	steps := []struct {
		commandID string
		command   []byte
		wantPhase string
	}{
		{"tp", enc(EncodePrepareToolEffect("turn-1", "eff-tool", "sha256:t", 1)), phaseToolPrepared},
		{"td", enc(EncodeDispatchToolEffect("turn-1", "eff-tool", "prov-t", 1)), phaseToolDispatched},
		{"tc", enc(EncodeCommitToolEffect("turn-1", "eff-tool", "ext-commit-1", 1)), phaseToolExternalCommit},
		{"ts", enc(EncodeSettleToolEffect("turn-1", "eff-tool", 1)), phaseToolSettled},
		{"done", enc(EncodeCompleteTurn("turn-1", 1)), phaseIdle},
	}
	for index, step := range steps {
		if _, err := execute(host, object, step.commandID, step.command); err != nil {
			t.Fatalf("tool step %d (%s): %v", index, step.commandID, err)
		}
		if phase := finalState(t, storage, object).TurnPhase; phase != step.wantPhase {
			t.Fatalf("tool step %d: phase = %q, want %q", index, phase, step.wantPhase)
		}
	}
	state := finalState(t, storage, object)
	if state.EventSequence != 9 || state.ActiveTurnID != "" || state.EffectID != "" {
		t.Fatalf("final state = %+v, want seq=9 with no active turn or effect", state)
	}
}

func TestToolEffectRequiresCommitBeforeSettle(t *testing.T) {
	t.Parallel()
	storage := NewReferenceStorage()
	host := newHost(t, storage, nil)
	const object = "sess_commit"
	driveToModelSettled(t, host, object)

	if _, err := execute(host, object, "tp", enc(EncodePrepareToolEffect("turn-1", "eff-tool", "d", 1))); err != nil {
		t.Fatalf("prepare tool: %v", err)
	}
	if _, err := execute(host, object, "td", enc(EncodeDispatchToolEffect("turn-1", "eff-tool", "p", 1))); err != nil {
		t.Fatalf("dispatch tool: %v", err)
	}
	// Settling before the external commit is recorded is rejected.
	if _, err := execute(host, object, "ts", enc(EncodeSettleToolEffect("turn-1", "eff-tool", 1))); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("settle before commit = %v, want ErrInvalidTransition", err)
	}
	if _, err := execute(host, object, "tc", enc(EncodeCommitToolEffect("turn-1", "eff-tool", "ext-1", 1))); err != nil {
		t.Fatalf("commit tool: %v", err)
	}
	if _, err := execute(host, object, "ts", enc(EncodeSettleToolEffect("turn-1", "eff-tool", 1))); err != nil {
		t.Fatalf("settle tool: %v", err)
	}
	if state := finalState(t, storage, object); state.TurnPhase != phaseToolSettled || state.EffectExternalID != "" {
		t.Fatalf("final state = %+v, want tool_settled with cleared effect", state)
	}
}

func TestToolEffectSerialInvariant(t *testing.T) {
	t.Parallel()
	storage := NewReferenceStorage()
	host := newHost(t, storage, nil)
	const object = "sess_toolserial"
	driveToModelSettled(t, host, object)

	if _, err := execute(host, object, "tp", enc(EncodePrepareToolEffect("turn-1", "eff-tool", "d", 1))); err != nil {
		t.Fatalf("prepare tool: %v", err)
	}
	// A second effect while the tool effect is active violates the serial invariant.
	if _, err := execute(host, object, "tp2", enc(EncodePrepareToolEffect("turn-1", "eff-other", "d2", 1))); !errors.Is(err, ErrEffectActive) {
		t.Fatalf("second tool prepare = %v, want ErrEffectActive", err)
	}
	// A turn cannot complete while a tool effect is in flight.
	if _, err := execute(host, object, "done", enc(EncodeCompleteTurn("turn-1", 1))); !errors.Is(err, ErrEffectActive) {
		t.Fatalf("complete with active effect = %v, want ErrEffectActive", err)
	}
}
