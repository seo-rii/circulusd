package celldrepo_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/celld"
	"github.com/hancomac/circulusd/internal/platformapi"
	"github.com/hancomac/circulusd/internal/platformapi/celldrepo"
	"github.com/hancomac/circulusd/internal/sessionstate"
)

// gatedBarrierStorage holds one object's durability barrier until released.
type gatedBarrierStorage struct {
	*sessionstate.ReferenceStorage
	objectID string
	armed    atomic.Bool
	entered  chan struct{}
	release  chan struct{}
}

func (storage *gatedBarrierStorage) DurabilityBarrier(ctx context.Context, token celld.CommitToken) error {
	if token.ObjectID == storage.objectID && storage.armed.CompareAndSwap(true, false) {
		close(storage.entered)
		<-storage.release
	}
	return storage.ReferenceStorage.DurabilityBarrier(ctx, token)
}

func TestCelldRepositoryBarrierDoesNotBlockOtherSessions(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	const otherSessionID = "sess_BBBBBBBBBBBBBBBBBBBBBBBBBB"
	storage := &gatedBarrierStorage{
		ReferenceStorage: sessionstate.NewReferenceStorage(), objectID: sessionID,
		entered: make(chan struct{}), release: make(chan struct{}),
	}
	repo, err := celldrepo.NewReferenceRepository(newHost(t, storage), storage)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{sessionID, otherSessionID} {
		if err := repo.RegisterSession(ctx, platformapi.SessionRegistration{
			TenantID: tenantID, SubjectID: subjectID, SessionID: id,
			RuntimeRevision: runtimeRevision, WorkspaceID: workspaceID,
			PlacementGeneration: uint64(placementGen), AuthorizationGeneration: uint64(authorizationGen),
		}); err != nil {
			t.Fatalf("RegisterSession(%s) error = %v", id, err)
		}
	}
	createOneTurn(t, repo, "turn-one")

	storage.armed.Store(true)
	appended := make(chan error, 1)
	go func() {
		_, _, err := repo.AppendDurableEvent(ctx, platformapi.AppendEventCommand{
			Authority: repoEventAuthority("turn-one"), CommandID: newOp(t), CommandDigest: "sha256:accepted",
			ExpectedSequence: 0, Type: platformapi.EventTurnAccepted, Payload: `{"state":"x"}`,
			TurnStatus: platformapi.TurnActive,
		})
		appended <- err
	}()
	select {
	case <-storage.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("append did not reach the durability barrier")
	}
	defer func() {
		close(storage.release)
		if err := <-appended; err != nil {
			t.Errorf("gated append error = %v", err)
		}
	}()

	otherPermit := permit(platformapi.OperationReadEvents)
	otherPermit.SessionID = otherSessionID
	opened := make(chan error, 1)
	go func() {
		stream, err := repo.OpenEventStream(ctx, platformapi.ReplayQuery{
			TenantID: tenantID, SubjectID: subjectID, SessionID: otherSessionID,
			Limit: 16, Authorization: otherPermit,
		})
		if err == nil && stream.Subscription == nil {
			err = errors.New("caught-up stream has no subscription")
		}
		if stream.Subscription != nil {
			stream.Subscription.Close()
		}
		opened <- err
	}()
	select {
	case err := <-opened:
		if err != nil {
			t.Fatalf("OpenEventStream(other session) error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("another session's barrier blocked OpenEventStream")
	}
}

func TestCelldRepositoryDefiniteAppendRejectionKeepsSubscribers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := newRegisteredRepository(t)
	createOneTurn(t, repo, "turn-one")
	appendDurable(t, repo, "turn-one", 0, platformapi.EventTurnAccepted, platformapi.TurnActive)
	stream, err := repo.OpenEventStream(ctx, platformapi.ReplayQuery{
		TenantID: tenantID, SubjectID: subjectID, SessionID: sessionID,
		AfterSequence: 1, Limit: 16, Authorization: permit(platformapi.OperationReadEvents),
	})
	if err != nil || !stream.CaughtUp || stream.Subscription == nil {
		t.Fatalf("OpenEventStream() = %#v, %v", stream, err)
	}
	defer stream.Subscription.Close()

	// A stale expected sequence is rejected inside the rolled-back transaction,
	// so nothing was committed and live readers stay connected.
	if _, _, err := repo.AppendDurableEvent(ctx, platformapi.AppendEventCommand{
		Authority: repoEventAuthority("turn-one"), CommandID: newOp(t), CommandDigest: "sha256:stale",
		ExpectedSequence: 0, Type: platformapi.EventTurnCompleted, Payload: `{"state":"x"}`,
		TurnStatus: platformapi.TurnCompleted,
	}); !errors.Is(err, platformapi.ErrSequenceConflict) {
		t.Fatalf("stale append error = %v, want ErrSequenceConflict", err)
	}
	completed := appendDurable(t, repo, "turn-one", 1, platformapi.EventTurnCompleted, platformapi.TurnCompleted)
	select {
	case live, open := <-stream.Subscription.Events():
		if !open {
			t.Fatal("a definite append rejection disconnected the live subscriber")
		}
		if live != completed {
			t.Fatalf("live event = %#v, want %#v", live, completed)
		}
	case <-time.After(time.Second):
		t.Fatal("durable event was not delivered to the live subscriber")
	}
}
