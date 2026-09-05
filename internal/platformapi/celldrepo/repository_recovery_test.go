package celldrepo_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/hancomac/circulusd/internal/celld"
	"github.com/hancomac/circulusd/internal/platformapi"
	"github.com/hancomac/circulusd/internal/platformapi/celldrepo"
	"github.com/hancomac/circulusd/internal/sessionstate"
)

func TestCelldRepositoryRecoversLiveAppendAcrossCommitFailures(t *testing.T) {
	for _, point := range []celld.FaultPoint{
		celld.FaultBeforeCommit, celld.FaultAfterCommit, celld.FaultBeforeBarrier,
		celld.FaultAfterBarrier, celld.FaultBeforeResponse,
	} {
		t.Run(string(point), func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			storage := sessionstate.NewReferenceStorage()
			sealer, err := celld.NewPermitCodec(bytes.Repeat([]byte{0x3d}, 32))
			if err != nil {
				t.Fatal(err)
			}
			inject := false
			host, err := celld.NewHost(celld.Config{
				Storage: storage, Aggregate: celldrepo.Aggregate{}, Sealer: sealer,
				FaultInjector: celld.FaultInjectorFunc(func(_ context.Context, observed celld.FaultPoint) error {
					if inject && observed == point {
						inject = false
						return errors.New("injected append response failure")
					}
					return nil
				}),
			})
			if err != nil {
				t.Fatal(err)
			}
			mustRegister(t, host)
			repo, err := celldrepo.NewReferenceRepository(host, storage)
			if err != nil {
				t.Fatal(err)
			}
			createOneTurn(t, repo, "turn-one")
			appendDurable(t, repo, "turn-one", 0, platformapi.EventTurnAccepted, platformapi.TurnActive)
			query := platformapi.ReplayQuery{
				TenantID: tenantID, SubjectID: subjectID, SessionID: sessionID,
				AfterSequence: 1, Limit: 16, Authorization: permit(platformapi.OperationReadEvents),
			}
			stream, err := repo.OpenEventStream(ctx, query)
			if err != nil || stream.Subscription == nil {
				t.Fatalf("open stream = %+v, %v", stream, err)
			}
			defer stream.Subscription.Close()
			command := platformapi.AppendEventCommand{
				Authority: repoEventAuthority("turn-one"), CommandID: newOp(t), CommandDigest: "sha256:completed",
				ExpectedSequence: 1, Type: platformapi.EventTurnCompleted,
				Payload: `{"state":"completed"}`, TurnStatus: platformapi.TurnCompleted,
			}
			inject = true
			if _, _, err := repo.AppendDurableEvent(ctx, command); !errors.Is(err, platformapi.ErrRepositoryFailure) {
				t.Fatalf("injected append error = %v", err)
			}
			select {
			case event, open := <-stream.Subscription.Events():
				if open {
					t.Fatalf("uncertain append delivered %+v instead of disconnecting", event)
				}
			default:
				t.Fatal("uncertain append left a live subscription silently behind the journal")
			}

			// Reconnect before retrying. A committed event belongs in replay;
			// an uncommitted one must arrive live exactly once after the retry.
			reconnected, err := repo.OpenEventStream(ctx, query)
			if err != nil || !reconnected.CaughtUp || reconnected.Subscription == nil {
				t.Fatalf("reconnect = %+v, %v", reconnected, err)
			}
			defer reconnected.Subscription.Close()
			committed := point != celld.FaultBeforeCommit
			wantReplay := 0
			if committed {
				wantReplay = 1
			}
			if len(reconnected.Replay.Events) != wantReplay {
				t.Fatalf("replayed %d events, want %d", len(reconnected.Replay.Events), wantReplay)
			}
			event, replayed, err := repo.AppendDurableEvent(ctx, command)
			if err != nil || replayed != committed || event.Sequence != 2 {
				t.Fatalf("retry = %+v, replayed=%t, %v", event, replayed, err)
			}
			if !committed {
				select {
				case delivered := <-reconnected.Subscription.Events():
					if delivered != event {
						t.Fatalf("live retry = %+v, want %+v", delivered, event)
					}
				default:
					t.Fatal("new commit was not delivered live")
				}
			}
			if _, replayed, err := repo.AppendDurableEvent(ctx, command); err != nil || !replayed {
				t.Fatalf("second retry replayed=%t, %v", replayed, err)
			}
			select {
			case duplicate, open := <-reconnected.Subscription.Events():
				t.Fatalf("successful receipt replay changed live stream: %+v, open=%t", duplicate, open)
			default:
			}
		})
	}
}
