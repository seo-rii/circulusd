package platformapi_test

import (
	"context"
	"testing"

	"github.com/hancomac/circulusd/internal/identity"
	"github.com/hancomac/circulusd/internal/platformapi"
)

func newOperationID(t *testing.T) string {
	t.Helper()
	value, err := identity.New(identity.Operation)
	if err != nil {
		t.Fatalf("identity.New(Operation) error = %v", err)
	}
	return value.String()
}

// durableStep is one entry in the turn/effect ladder appended to the journal.
type durableStep struct {
	eventType platformapi.EventType
	status    platformapi.TurnStatus
}

// fullDurableLadder is a transition-valid durable event sequence from admission
// to completion. Its length exceeds any single reconnect page below, so the
// reconnect loop must span several pages to cover it.
var fullDurableLadder = []durableStep{
	{platformapi.EventTurnAccepted, platformapi.TurnActive},
	{platformapi.EventModelEffectPrepared, platformapi.TurnActive},
	{platformapi.EventModelSettled, platformapi.TurnActive},
	{platformapi.EventToolEffectPrepared, platformapi.TurnActive},
	{platformapi.EventToolExternallyCommit, platformapi.TurnActive},
	{platformapi.EventToolSettled, platformapi.TurnActive},
	{platformapi.EventTurnCompleted, platformapi.TurnCompleted},
}

func appendLadder(
	t *testing.T,
	service *platformapi.Service,
	auth platformapi.EventAuthority,
	steps []durableStep,
) {
	t.Helper()
	for index, step := range steps {
		event, replayed, err := service.AppendDurableEvent(context.Background(), platformapi.AppendDurableEventRequest{
			Authority: auth, CommandID: newOperationID(t), ExpectedSequence: uint64(index),
			Type: step.eventType, Payload: []byte(`{"step":"durable"}`), TurnStatus: step.status,
		})
		if err != nil || replayed || event.Sequence != uint64(index+1) {
			t.Fatalf("AppendDurableEvent(step %d %s) = %#v, %t, %v", index, step.eventType, event, replayed, err)
		}
	}
}

// TestDurableReplayReconnectCoversJournalExactlyOnce drives the §53.16 durable
// disconnect/reconnect recovery: a client pages the whole journal by repeatedly
// reconnecting from its last durable cursor with a page limit smaller than the
// journal. The union of replayed events across every reconnect is exactly the
// contiguous durable sequence 1..N with no gap and no duplication, every
// reconnect observes the current session snapshot, and only the final page is
// caught up with a live subscription.
func TestDurableReplayReconnectCoversJournalExactlyOnce(t *testing.T) {
	ctx := context.Background()
	store := platformapi.NewMemoryStore()
	registerAPISession(t, store)
	service := newAPIService(t, store, &scopedAuthorizer{})
	created, err := service.CreateTurn(ctx, platformapi.CreateTurnRequest{
		Principal: platformapi.Principal{TenantID: apiTenantID, SubjectID: apiSubjectID},
		SessionID: apiSessionID, IdempotencyKey: "reconnect-journal",
		Messages: []platformapi.Message{{Role: "user", Content: "drive the ladder"}},
	})
	if err != nil {
		t.Fatalf("CreateTurn() error = %v", err)
	}
	auth := eventAuthority(created.Turn.ID)
	appendLadder(t, service, auth, fullDurableLadder)
	total := uint64(len(fullDurableLadder))

	const pageLimit = 2
	collected := make([]uint64, 0, total)
	cursor := uint64(0)
	reconnects := 0
	for {
		reconnects++
		if reconnects > int(total)+2 {
			t.Fatalf("reconnect loop did not converge after %d rounds", reconnects)
		}
		stream, err := service.OpenEventStream(ctx, platformapi.ReplayEventsRequest{
			Principal: platformapi.Principal{TenantID: apiTenantID, SubjectID: apiSubjectID},
			SessionID: apiSessionID, AfterSequence: cursor, Limit: pageLimit,
		})
		if err != nil {
			t.Fatalf("OpenEventStream(after %d) error = %v", cursor, err)
		}
		if stream.Replay.Snapshot.SessionID != apiSessionID ||
			stream.Replay.Snapshot.LastDurableSequence != total {
			t.Fatalf("reconnect %d snapshot = %#v, want session %q last %d",
				reconnects, stream.Replay.Snapshot, apiSessionID, total)
		}
		for _, event := range stream.Replay.Events {
			if !event.Durable {
				t.Fatalf("reconnect %d replayed a non-durable event %#v", reconnects, event)
			}
			collected = append(collected, event.Sequence)
			cursor = event.Sequence
		}
		if stream.CaughtUp {
			if stream.Subscription == nil {
				t.Fatalf("reconnect %d caught up without a live subscription", reconnects)
			}
			stream.Subscription.Close()
			break
		}
		if stream.Subscription != nil {
			t.Fatalf("reconnect %d not caught up but carried a subscription", reconnects)
		}
	}

	if uint64(len(collected)) != total {
		t.Fatalf("collected %d durable events across reconnects, want %d", len(collected), total)
	}
	for index, sequence := range collected {
		if sequence != uint64(index+1) {
			t.Fatalf("collected sequences = %v, want contiguous 1..%d", collected, total)
		}
	}
	if reconnects < 2 {
		t.Fatalf("journal covered in %d reconnect(s); expected several pages", reconnects)
	}

	// A fresh full replay must return the same contiguous durable journal.
	replay, err := service.ReplayEvents(ctx, platformapi.ReplayEventsRequest{
		Principal: platformapi.Principal{TenantID: apiTenantID, SubjectID: apiSubjectID},
		SessionID: apiSessionID, AfterSequence: 0, Limit: int(total) + 8,
	})
	if err != nil || uint64(len(replay.Events)) != total || replay.Snapshot.LastDurableSequence != total {
		t.Fatalf("full replay = %#v, %v", replay, err)
	}
}

// TestEphemeralLossAcrossReconnectLeavesDurableStateUnchanged proves §36.6 /
// §53.16: an ephemeral delta buffered to a subscriber and then dropped by a
// disconnect never enters the durable journal, never advances the durable
// cursor, and never blocks a later durable append from continuing the exact
// contiguous sequence.
func TestEphemeralLossAcrossReconnectLeavesDurableStateUnchanged(t *testing.T) {
	ctx := context.Background()
	store := platformapi.NewMemoryStore()
	registerAPISession(t, store)
	service := newAPIService(t, store, &scopedAuthorizer{})
	created, err := service.CreateTurn(ctx, platformapi.CreateTurnRequest{
		Principal: platformapi.Principal{TenantID: apiTenantID, SubjectID: apiSubjectID},
		SessionID: apiSessionID, IdempotencyKey: "ephemeral-loss",
		Messages: []platformapi.Message{{Role: "user", Content: "keep durable state clean"}},
	})
	if err != nil {
		t.Fatalf("CreateTurn() error = %v", err)
	}
	auth := eventAuthority(created.Turn.ID)
	appendLadder(t, service, auth, []durableStep{
		{platformapi.EventTurnAccepted, platformapi.TurnActive},
	})

	durableBefore, err := service.ReplayEvents(ctx, platformapi.ReplayEventsRequest{
		Principal: platformapi.Principal{TenantID: apiTenantID, SubjectID: apiSubjectID},
		SessionID: apiSessionID, AfterSequence: 0, Limit: 16,
	})
	if err != nil || len(durableBefore.Events) != 1 || durableBefore.Snapshot.LastDurableSequence != 1 {
		t.Fatalf("durable replay before ephemeral = %#v, %v", durableBefore, err)
	}

	// Open a caught-up subscription, publish an ephemeral delta into it, then
	// drop it by closing without reading — modeling a client disconnect that
	// loses the buffered ephemeral frame.
	stream, err := service.OpenEventStream(ctx, platformapi.ReplayEventsRequest{
		Principal: platformapi.Principal{TenantID: apiTenantID, SubjectID: apiSubjectID},
		SessionID: apiSessionID, AfterSequence: 1, Limit: 16,
	})
	if err != nil || !stream.CaughtUp || stream.Subscription == nil {
		t.Fatalf("OpenEventStream() = %#v, %v", stream, err)
	}
	if _, err := service.PublishEphemeralEvent(ctx, platformapi.EphemeralEventRequest{
		Authority: auth, Type: platformapi.EventModelDelta, Payload: []byte("lost partial"),
	}); err != nil {
		t.Fatalf("PublishEphemeralEvent() error = %v", err)
	}
	stream.Subscription.Close()

	// After the loss the durable journal and cursor are byte-for-byte unchanged.
	durableAfter, err := service.ReplayEvents(ctx, platformapi.ReplayEventsRequest{
		Principal: platformapi.Principal{TenantID: apiTenantID, SubjectID: apiSubjectID},
		SessionID: apiSessionID, AfterSequence: 0, Limit: 16,
	})
	if err != nil {
		t.Fatalf("durable replay after ephemeral = %v", err)
	}
	if durableAfter.Snapshot != durableBefore.Snapshot || len(durableAfter.Events) != 1 ||
		durableAfter.Events[0] != durableBefore.Events[0] {
		t.Fatalf("durable state changed after ephemeral loss: before=%#v after=%#v", durableBefore, durableAfter)
	}

	// The next durable append continues the exact contiguous sequence: the lost
	// ephemeral never consumed a durable slot.
	completed, replayed, err := service.AppendDurableEvent(ctx, platformapi.AppendDurableEventRequest{
		Authority: auth, CommandID: newOperationID(t), ExpectedSequence: 1,
		Type: platformapi.EventTurnCompleted, Payload: []byte(`{"state":"completed"}`),
		TurnStatus: platformapi.TurnCompleted,
	})
	if err != nil || replayed || completed.Sequence != 2 {
		t.Fatalf("AppendDurableEvent(after ephemeral loss) = %#v, %t, %v", completed, replayed, err)
	}
}
