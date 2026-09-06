package broker

import (
	"context"
	"testing"
	"time"
)

// TestWorkloadDispatcherAdmitsThenStartsExactlyOnce proves the Unit 14
// composition: one Dispatch admits the effect through the durable store and
// starts the provider exactly once, and a replayed Dispatch never starts the
// provider a second time.
func TestWorkloadDispatcherAdmitsThenStartsExactlyOnce(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_900_002_000, 0).UTC()
	snapshot := baseSnapshot(now)
	snapshot.ActiveEffect = baseEffect(EffectPrepared)
	store := newFakeStore(snapshot)
	coordinator := mustCoordinator(t, store, nil)
	starter := &recordingDispatchStarter{}
	consumer, err := NewDispatchConsumer(
		verifiedDispatchStartClaimer(t, coordinator),
		map[EffectService]DispatchStarter{ServiceExecutor: starter},
		time.Second,
	)
	if err != nil {
		t.Fatalf("NewDispatchConsumer() error = %v", err)
	}
	dispatcher, err := NewWorkloadDispatcher(coordinator, consumer)
	if err != nil {
		t.Fatalf("NewWorkloadDispatcher() error = %v", err)
	}
	request := WorkloadDispatch{
		Dispatch:      baseDispatchRequest(now),
		Authority:     baseAuthority(now),
		Now:           now,
		CommandDigest: digest(160),
	}

	first, err := dispatcher.Dispatch(context.Background(), request)
	if err != nil || first.Outcome != DispatchStartOutcomeStarted || !first.Claim.Fresh {
		t.Fatalf("first Dispatch() = %#v, %v; want a fresh started attempt", first, err)
	}

	// A replayed Dispatch must not start the provider again: whether admission
	// idempotently returns the same permit (then the start claim is not fresh) or
	// admission rejects the replay, the provider is never started twice.
	second, secondErr := dispatcher.Dispatch(context.Background(), request)
	if secondErr == nil && second.Claim.Fresh {
		t.Fatalf("replayed Dispatch() started a fresh attempt: %#v", second)
	}

	starter.mu.Lock()
	calls := starter.calls
	starter.mu.Unlock()
	store.mu.Lock()
	claimTransitions := store.dispatchStartTransitions
	store.mu.Unlock()
	if calls != 1 || claimTransitions != 1 {
		t.Fatalf("starter calls=%d claim transitions=%d, want 1/1", calls, claimTransitions)
	}
}

// TestNewWorkloadDispatcherRejectsNilDependencies proves the composition refuses
// to construct without both halves, including a typed-nil admitter.
func TestNewWorkloadDispatcherRejectsNilDependencies(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_900_002_100, 0).UTC()
	snapshot := baseSnapshot(now)
	snapshot.ActiveEffect = baseEffect(EffectPrepared)
	store := newFakeStore(snapshot)
	coordinator := mustCoordinator(t, store, nil)
	consumer, err := NewDispatchConsumer(
		verifiedDispatchStartClaimer(t, coordinator),
		map[EffectService]DispatchStarter{ServiceExecutor: &recordingDispatchStarter{}},
		time.Second,
	)
	if err != nil {
		t.Fatalf("NewDispatchConsumer() error = %v", err)
	}

	if dispatcher, err := NewWorkloadDispatcher(nil, consumer); dispatcher != nil || err == nil {
		t.Fatalf("NewWorkloadDispatcher(nil admitter) = %#v, %v; want rejection", dispatcher, err)
	}
	if dispatcher, err := NewWorkloadDispatcher(coordinator, nil); dispatcher != nil || err == nil {
		t.Fatalf("NewWorkloadDispatcher(nil consumer) = %#v, %v; want rejection", dispatcher, err)
	}
	var typedNil *Coordinator
	if dispatcher, err := NewWorkloadDispatcher(typedNil, consumer); dispatcher != nil || err == nil {
		t.Fatalf("NewWorkloadDispatcher(typed-nil admitter) = %#v, %v; want rejection", dispatcher, err)
	}
}
