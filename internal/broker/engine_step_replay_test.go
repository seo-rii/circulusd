package broker

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAcquireEngineStepReplaysOriginalLiveDeadline(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0).UTC()
	store := newFakeStore(baseSnapshot(now))
	request := EngineStepRequest{
		Authority: baseAuthority(now), Now: now, OperationKey: "replayed-step",
		Budget: EngineStepBudget{MaximumEvents: 1, MaximumEphemeralBytes: 4096, MaximumWallClock: time.Second},
	}
	original, err := mustCoordinator(t, store, nil).AcquireEngineStep(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}

	// The first reply may have been lost. A new coordinator must accept the
	// retained grant without moving its deadline forward to the retry time.
	request.Now = now.Add(time.Millisecond)
	replayed, err := mustCoordinator(t, store, nil).AcquireEngineStep(context.Background(), request)
	if err != nil {
		t.Fatalf("replay of a still-live grant: %v", err)
	}
	if replayed.Opaque != original.Opaque || !replayed.Deadline.Equal(original.Deadline) || replayed.Budget != original.Budget || len(store.stepPermits) != 1 {
		t.Fatalf("replay changed the durable grant: original=%#v replayed=%#v", original, replayed)
	}

	request.Now = original.Deadline
	if _, err := mustCoordinator(t, store, nil).AcquireEngineStep(context.Background(), request); !errors.Is(err, ErrFenceMismatch) {
		t.Fatalf("expired retained grant error = %v, want %v", err, ErrFenceMismatch)
	}
}

func TestAcquireEngineStepReplayStillValidatesReceipt(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0).UTC()
	tests := []struct {
		name   string
		mutate func(*EngineStepPermit)
	}{
		{"extended deadline", func(p *EngineStepPermit) { p.Deadline = now.Add(2 * time.Second) }},
		{"changed budget", func(p *EngineStepPermit) { p.Budget.MaximumEphemeralBytes++ }},
		{"changed fence", func(p *EngineStepPermit) { p.Generations.Authorization++ }},
		{"changed checkpoint", func(p *EngineStepPermit) { p.CheckpointDigest = digest(212) }},
		{"changed resume context", func(p *EngineStepPermit) { p.ResumeSettlement = []byte("different settlement") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newFakeStore(baseSnapshot(now))
			coordinator := mustCoordinator(t, store, nil)
			original := acquirePermit(t, coordinator, now, "replayed-step")
			test.mutate(&original)
			store.stepPermits[original.OperationKey] = original
			_, err := coordinator.AcquireEngineStep(context.Background(), EngineStepRequest{
				Authority: baseAuthority(now), Now: now.Add(time.Millisecond), OperationKey: original.OperationKey,
				Budget: EngineStepBudget{MaximumEvents: 1, MaximumEphemeralBytes: 1, MaximumWallClock: time.Second},
			})
			if !errors.Is(err, ErrFenceMismatch) {
				t.Fatalf("AcquireEngineStep() error = %v, want %v", err, ErrFenceMismatch)
			}
		})
	}
}
