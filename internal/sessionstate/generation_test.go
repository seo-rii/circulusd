package sessionstate

import (
	"errors"
	"testing"
)

func TestPlacementGenerationRotationRejectsStaleDispatch(t *testing.T) {
	t.Parallel()
	storage := NewReferenceStorage()
	host := newHost(t, storage, nil)
	const object = "sess_placement"

	if _, err := execute(host, object, "o", enc(EncodeOpenTurn("turn-1", 1))); err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := execute(host, object, "p", enc(EncodePrepareModelEffect("turn-1", "eff-1", "d", 1))); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	// Placement generation rotates to 5 while the effect is prepared.
	if _, err := execute(host, object, "rot", enc(EncodeRotatePlacement("turn-1", 5, 1))); err != nil {
		t.Fatalf("rotate placement: %v", err)
	}
	// A dispatch minted under the pre-rotation placement generation is fenced.
	if _, err := execute(host, object, "d-stale", enc(EncodeDispatchModelEffectAt("turn-1", "eff-1", "p", 3, 1))); !errors.Is(err, ErrStalePlacementGeneration) {
		t.Fatalf("stale-placement dispatch = %v, want ErrStalePlacementGeneration", err)
	}
	// A dispatch under the current placement generation proceeds.
	if _, err := execute(host, object, "d-ok", enc(EncodeDispatchModelEffectAt("turn-1", "eff-1", "p", 5, 1))); err != nil {
		t.Fatalf("current-placement dispatch: %v", err)
	}
	if state := finalState(t, storage, object); state.PlacementGeneration != 5 || state.TurnPhase != phaseModelDispatched {
		t.Fatalf("final state = %+v, want placement gen 5 and model_dispatched", state)
	}
}

func TestPolicyGenerationRotationRejectsStalePrepare(t *testing.T) {
	t.Parallel()
	storage := NewReferenceStorage()
	host := newHost(t, storage, nil)
	const object = "sess_policy"

	if _, err := execute(host, object, "o", enc(EncodeOpenTurn("turn-1", 1))); err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := execute(host, object, "rot", enc(EncodeRotatePolicy("turn-1", 4, 1))); err != nil {
		t.Fatalf("rotate policy: %v", err)
	}
	// A prepare minted under the pre-rotation policy generation is fenced.
	if _, err := execute(host, object, "p-stale", enc(EncodePrepareModelEffectAt("turn-1", "eff-1", "d", 2, 1))); !errors.Is(err, ErrStalePolicyGeneration) {
		t.Fatalf("stale-policy prepare = %v, want ErrStalePolicyGeneration", err)
	}
	// A prepare under the current policy generation proceeds.
	if _, err := execute(host, object, "p-ok", enc(EncodePrepareModelEffectAt("turn-1", "eff-1", "d", 4, 1))); err != nil {
		t.Fatalf("current-policy prepare: %v", err)
	}
	if state := finalState(t, storage, object); state.PolicyGeneration != 4 || state.TurnPhase != phaseModelPrepared {
		t.Fatalf("final state = %+v, want policy gen 4 and model_prepared", state)
	}
}

func TestGenerationRotationMustAdvance(t *testing.T) {
	t.Parallel()
	storage := NewReferenceStorage()
	host := newHost(t, storage, nil)
	const object = "sess_rotate"

	if _, err := execute(host, object, "o", enc(EncodeOpenTurn("turn-1", 1))); err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := execute(host, object, "r1", enc(EncodeRotatePlacement("turn-1", 3, 1))); err != nil {
		t.Fatalf("rotate to 3: %v", err)
	}
	if _, err := execute(host, object, "r2", enc(EncodeRotatePlacement("turn-1", 3, 1))); !errors.Is(err, ErrInvalidRotation) {
		t.Fatalf("rotate to same = %v, want ErrInvalidRotation", err)
	}
	if _, err := execute(host, object, "r3", enc(EncodeRotatePlacement("turn-1", 2, 1))); !errors.Is(err, ErrInvalidRotation) {
		t.Fatalf("rotate backward = %v, want ErrInvalidRotation", err)
	}
	if state := finalState(t, storage, object); state.PlacementGeneration != 3 {
		t.Fatalf("final placement generation = %d, want 3", state.PlacementGeneration)
	}
}
