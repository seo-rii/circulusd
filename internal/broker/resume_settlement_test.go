package broker

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

type settlementBodyStore struct {
	DurableStore
	tamper bool
}

func (store *settlementBodyStore) AcquireEngineStep(ctx context.Context, command AcquireStepCommand) (EngineStepPermit, error) {
	permit, err := store.DurableStore.AcquireEngineStep(ctx, command)
	permit.ResumeSettlement = bytes.Clone(command.Snapshot.ResumeSettlement)
	if store.tamper {
		permit.ResumeSettlement = append(permit.ResumeSettlement, 0)
	}
	return permit, err
}

func TestEngineGrantBindsActualCanonicalSettlementBody(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	for _, tamper := range []bool{false, true} {
		snapshot := baseSnapshot(now)
		snapshot.ResumeSettlement = []byte{0xa1, 0x61, 'x', 0x01}
		store := &settlementBodyStore{DurableStore: newFakeStore(snapshot), tamper: tamper}
		coordinator, err := NewCoordinator(store, nil)
		if err != nil {
			t.Fatal(err)
		}
		permit, err := coordinator.AcquireEngineStep(context.Background(), EngineStepRequest{Authority: baseAuthority(now), Now: now,
			Budget: EngineStepBudget{MaximumEvents: 1, MaximumEphemeralBytes: 1024, MaximumWallClock: time.Second}, OperationKey: "resume"})
		if tamper {
			if !errors.Is(err, ErrFenceMismatch) {
				t.Fatalf("tampered body got %v", err)
			}
		} else if err != nil || !bytes.Equal(permit.ResumeSettlement, snapshot.ResumeSettlement) {
			t.Fatalf("grant body=%x err=%v", permit.ResumeSettlement, err)
		}
	}
}
