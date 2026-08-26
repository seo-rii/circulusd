package platformapi_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/platformapi"
)

type nilEventSubscription struct{}

func (*nilEventSubscription) Events() <-chan platformapi.Event { return nil }
func (*nilEventSubscription) Close()                           {}

type typedNilStreamRepository struct {
	*platformapi.MemoryStore
}

type nilChannelStreamRepository struct {
	*platformapi.MemoryStore
}

func (*typedNilStreamRepository) Durability() platformapi.RepositoryDurability {
	return platformapi.RepositoryDurability{
		CrashDurable: true, AtomicIdempotency: true, AtomicEventSequence: true,
		AtomicReplaySubscribe: true, AtomicAuthorizationFence: true,
	}
}

func (repository *typedNilStreamRepository) OpenEventStream(
	ctx context.Context,
	query platformapi.ReplayQuery,
) (platformapi.EventStream, error) {
	replay, err := repository.ReplayEvents(ctx, query)
	var subscription *nilEventSubscription
	return platformapi.EventStream{Replay: replay, CaughtUp: true, Subscription: subscription}, err
}

func (*nilChannelStreamRepository) Durability() platformapi.RepositoryDurability {
	return platformapi.RepositoryDurability{
		CrashDurable: true, AtomicIdempotency: true, AtomicEventSequence: true,
		AtomicReplaySubscribe: true, AtomicAuthorizationFence: true,
	}
}

func (repository *nilChannelStreamRepository) OpenEventStream(
	ctx context.Context,
	query platformapi.ReplayQuery,
) (platformapi.EventStream, error) {
	replay, err := repository.ReplayEvents(ctx, query)
	return platformapi.EventStream{
		Replay: replay, CaughtUp: true, Subscription: &nilEventSubscription{},
	}, err
}

func TestOpenEventStreamRejectsTypedNilSubscription(t *testing.T) {
	store := platformapi.NewMemoryStore()
	registerAPISession(t, store)
	service, err := platformapi.NewService(platformapi.Config{
		Store: &typedNilStreamRepository{MemoryStore: store}, Authorizer: &scopedAuthorizer{},
		EventAuthorizer: &scopedEventAuthorizer{}, IdempotencySecret: []byte(strings.Repeat("i", 32)),
		MaximumMessageBytes: 1024, MaximumEventBytes: 1024, MaximumReplayEvents: 256,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.OpenEventStream(context.Background(), platformapi.ReplayEventsRequest{
		Principal: platformapi.Principal{TenantID: apiTenantID, SubjectID: apiSubjectID},
		SessionID: apiSessionID,
	})
	if !errors.Is(err, platformapi.ErrRepositoryFailure) {
		t.Fatalf("OpenEventStream(typed nil subscription) error = %v, want ErrRepositoryFailure", err)
	}
}

func TestOpenEventStreamRejectsSubscriptionWithNilEventChannel(t *testing.T) {
	store := platformapi.NewMemoryStore()
	registerAPISession(t, store)
	service, err := platformapi.NewService(platformapi.Config{
		Store: &nilChannelStreamRepository{MemoryStore: store}, Authorizer: &scopedAuthorizer{},
		EventAuthorizer: &scopedEventAuthorizer{}, IdempotencySecret: []byte(strings.Repeat("i", 32)),
		MaximumMessageBytes: 1024, MaximumEventBytes: 1024, MaximumReplayEvents: 256,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.OpenEventStream(context.Background(), platformapi.ReplayEventsRequest{
		Principal: platformapi.Principal{TenantID: apiTenantID, SubjectID: apiSubjectID},
		SessionID: apiSessionID,
	})
	if !errors.Is(err, platformapi.ErrRepositoryFailure) {
		t.Fatalf("OpenEventStream(nil event channel) error = %v, want ErrRepositoryFailure", err)
	}
}

func TestOpenEventStreamHasNoReplayToLiveRaceGap(t *testing.T) {
	for iteration := range 100 {
		ctx := context.Background()
		store := platformapi.NewMemoryStore()
		registerAPISession(t, store)
		service := newAPIService(t, store, &scopedAuthorizer{})
		created, err := service.CreateTurn(ctx, platformapi.CreateTurnRequest{
			Principal: platformapi.Principal{TenantID: apiTenantID, SubjectID: apiSubjectID},
			SessionID: apiSessionID, IdempotencyKey: "stream-turn",
			Messages: []platformapi.Message{{Role: "user", Content: "race"}},
		})
		if err != nil {
			t.Fatalf("iteration %d CreateTurn() error = %v", iteration, err)
		}
		eventAuth := eventAuthority(created.Turn.ID)
		if _, _, err := service.AppendDurableEvent(ctx, platformapi.AppendDurableEventRequest{
			Authority: eventAuth, CommandID: "op_AAAAAAAAAAAAAAAAAAAAAAAAAA",
			ExpectedSequence: 0, Type: platformapi.EventTurnAccepted,
			Payload: []byte(`{"state":"accepted"}`), TurnStatus: platformapi.TurnActive,
		}); err != nil {
			t.Fatalf("iteration %d append accepted: %v", iteration, err)
		}

		type streamResult struct {
			stream platformapi.EventStream
			err    error
		}
		start := make(chan struct{})
		opened := make(chan streamResult, 1)
		appended := make(chan error, 1)
		go func() {
			<-start
			stream, err := service.OpenEventStream(ctx, platformapi.ReplayEventsRequest{
				Principal: platformapi.Principal{TenantID: apiTenantID, SubjectID: apiSubjectID},
				SessionID: apiSessionID, AfterSequence: 0, Limit: 10,
			})
			opened <- streamResult{stream: stream, err: err}
		}()
		go func() {
			<-start
			_, _, err := service.AppendDurableEvent(ctx, platformapi.AppendDurableEventRequest{
				Authority: eventAuth, CommandID: "op_AAAAAAAAAAAAAAAAAAAAAAAAAE",
				ExpectedSequence: 1, Type: platformapi.EventTurnCompleted,
				Payload: []byte(`{"state":"completed"}`), TurnStatus: platformapi.TurnCompleted,
			})
			appended <- err
		}()
		close(start)
		result := <-opened
		if result.err != nil {
			t.Fatalf("iteration %d OpenEventStream() error = %v", iteration, result.err)
		}
		if err := <-appended; err != nil {
			t.Fatalf("iteration %d append completed: %v", iteration, err)
		}
		if !result.stream.CaughtUp || result.stream.Subscription == nil {
			t.Fatalf("iteration %d stream = %#v, want caught-up subscription", iteration, result.stream)
		}
		seenSecond := 0
		for _, event := range result.stream.Replay.Events {
			if event.Sequence == 2 {
				seenSecond++
			}
		}
		if seenSecond == 0 {
			select {
			case event := <-result.stream.Subscription.Events():
				if event.Sequence != 2 || event.Type != platformapi.EventTurnCompleted {
					t.Fatalf("iteration %d live event = %#v", iteration, event)
				}
				seenSecond++
			case <-time.After(time.Second):
				t.Fatalf("iteration %d lost event between replay and subscription", iteration)
			}
		}
		select {
		case duplicate := <-result.stream.Subscription.Events():
			if duplicate.Sequence == 2 {
				t.Fatalf("iteration %d duplicated event 2 across replay/live", iteration)
			}
		default:
		}
		result.stream.Subscription.Close()
		if seenSecond != 1 {
			t.Fatalf("iteration %d event 2 count = %d, want 1", iteration, seenSecond)
		}
	}
}

func TestEphemeralEventIsLiveOnlyAndDoesNotAdvanceDurableCursor(t *testing.T) {
	ctx := context.Background()
	store := platformapi.NewMemoryStore()
	registerAPISession(t, store)
	service := newAPIService(t, store, &scopedAuthorizer{})
	created, err := service.CreateTurn(ctx, platformapi.CreateTurnRequest{
		Principal: platformapi.Principal{TenantID: apiTenantID, SubjectID: apiSubjectID},
		SessionID: apiSessionID, IdempotencyKey: "ephemeral-stream",
		Messages: []platformapi.Message{{Role: "user", Content: "stream"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	eventAuth := eventAuthority(created.Turn.ID)
	if _, _, err := service.AppendDurableEvent(ctx, platformapi.AppendDurableEventRequest{
		Authority: eventAuth, CommandID: "op_AAAAAAAAAAAAAAAAAAAAAAAAAA", ExpectedSequence: 0,
		Type: platformapi.EventTurnAccepted, Payload: []byte(`{"state":"accepted"}`), TurnStatus: platformapi.TurnActive,
	}); err != nil {
		t.Fatal(err)
	}
	stream, err := service.OpenEventStream(ctx, platformapi.ReplayEventsRequest{
		Principal: platformapi.Principal{TenantID: apiTenantID, SubjectID: apiSubjectID},
		SessionID: apiSessionID, AfterSequence: 1, Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Subscription.Close()
	published, err := service.PublishEphemeralEvent(ctx, platformapi.EphemeralEventRequest{
		Authority: eventAuth, Type: platformapi.EventModelDelta, Payload: []byte("partial"),
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case live := <-stream.Subscription.Events():
		if live != published || live.Durable || live.Sequence != 0 {
			t.Fatalf("live ephemeral = %#v, published = %#v", live, published)
		}
	case <-time.After(time.Second):
		t.Fatal("ephemeral event was not delivered to live subscriber")
	}
	replay, err := service.ReplayEvents(ctx, platformapi.ReplayEventsRequest{
		Principal: platformapi.Principal{TenantID: apiTenantID, SubjectID: apiSubjectID},
		SessionID: apiSessionID, AfterSequence: 1, Limit: 10,
	})
	if err != nil || len(replay.Events) != 0 || replay.Snapshot.LastDurableSequence != 1 {
		t.Fatalf("durable replay after ephemeral = %#v, %v", replay, err)
	}
}

func TestAuthorizationRotationDisconnectsExistingEventStream(t *testing.T) {
	ctx := context.Background()
	store := platformapi.NewMemoryStore()
	registerAPISession(t, store)
	service := newAPIService(t, store, &scopedAuthorizer{})
	created, err := service.CreateTurn(ctx, platformapi.CreateTurnRequest{
		Principal: platformapi.Principal{TenantID: apiTenantID, SubjectID: apiSubjectID},
		SessionID: apiSessionID, IdempotencyKey: "stream-revocation",
		Messages: []platformapi.Message{{Role: "user", Content: "revoke stream"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	eventAuth := eventAuthority(created.Turn.ID)
	if _, _, err := service.AppendDurableEvent(ctx, platformapi.AppendDurableEventRequest{
		Authority: eventAuth, CommandID: "op_AAAAAAAAAAAAAAAAAAAAAAAAAA", ExpectedSequence: 0,
		Type: platformapi.EventTurnAccepted, Payload: []byte(`{"state":"accepted"}`), TurnStatus: platformapi.TurnActive,
	}); err != nil {
		t.Fatal(err)
	}
	stream, err := service.OpenEventStream(ctx, platformapi.ReplayEventsRequest{
		Principal: platformapi.Principal{TenantID: apiTenantID, SubjectID: apiSubjectID},
		SessionID: apiSessionID, AfterSequence: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RotateAuthorizationGeneration(ctx, apiTenantID, apiSubjectID, apiSessionID, 7, 8); err != nil {
		t.Fatal(err)
	}
	select {
	case _, open := <-stream.Subscription.Events():
		if open {
			t.Fatal("event subscription remained open after authorization rotation")
		}
	case <-time.After(time.Second):
		t.Fatal("authorization rotation did not disconnect event subscription")
	}
	eventAuth.AuthorizationGeneration = 8
	if _, err := service.PublishEphemeralEvent(ctx, platformapi.EphemeralEventRequest{
		Authority: eventAuth, Type: platformapi.EventModelDelta, Payload: []byte("post-revocation"),
	}); err != nil {
		t.Fatalf("PublishEphemeralEvent(new generation) error = %v", err)
	}
}
