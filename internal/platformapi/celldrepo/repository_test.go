package celldrepo_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/authority"
	"github.com/hancomac/circulusd/internal/celld"
	"github.com/hancomac/circulusd/internal/conformance"
	"github.com/hancomac/circulusd/internal/conformance/publicrepo"
	"github.com/hancomac/circulusd/internal/identity"
	"github.com/hancomac/circulusd/internal/platformapi"
	"github.com/hancomac/circulusd/internal/platformapi/celldrepo"
	"github.com/hancomac/circulusd/internal/sessionstate"
)

// durableRepository overrides only the reference repository's self-reported
// durability, so a test can drive the gate's PASS path (all atomic behaviors
// hold over celld) while provenance controls whether the evidence is promotable.
type durableRepository struct {
	*celldrepo.Repository
}

func (durableRepository) Durability() platformapi.RepositoryDurability {
	return platformapi.RepositoryDurability{
		CrashDurable: true, AtomicIdempotency: true, AtomicEventSequence: true,
		AtomicReplaySubscribe: true, AtomicAuthorizationFence: true,
	}
}

type celldHarness struct {
	reference bool
	durable   bool
}

func (harness celldHarness) NewSubject(ctx context.Context) (*publicrepo.Subject, error) {
	storage := sessionstate.NewReferenceStorage()
	sealer, err := celld.NewPermitCodec(bytes.Repeat([]byte{0x3d}, 32))
	if err != nil {
		return nil, err
	}
	host, err := celld.NewHost(celld.Config{Storage: storage, Aggregate: celldrepo.Aggregate{}, Sealer: sealer})
	if err != nil {
		return nil, err
	}
	repo, err := celldrepo.NewReferenceRepository(host, storage)
	if err != nil {
		return nil, err
	}
	if err := repo.RegisterSession(ctx, platformapi.SessionRegistration{
		TenantID: tenantID, SubjectID: subjectID, SessionID: sessionID,
		RuntimeRevision: runtimeRevision, WorkspaceID: workspaceID,
		PlacementGeneration: uint64(placementGen), AuthorizationGeneration: uint64(authorizationGen),
	}); err != nil {
		return nil, err
	}
	var repository platformapi.Repository = repo
	if harness.durable {
		repository = durableRepository{Repository: repo}
	}
	return &publicrepo.Subject{
		Repository: repository,
		TenantID:   tenantID, SubjectID: subjectID, SessionID: sessionID,
		WorkspaceID: workspaceID, RuntimeRevision: runtimeRevision,
		PlacementGeneration: uint64(placementGen), AuthorizationGeneration: uint64(authorizationGen),
		Permit: func(op platformapi.Operation) platformapi.AuthorizationPermit {
			return platformapi.AuthorizationPermit{
				Operation: op,
				Principal: platformapi.Principal{TenantID: tenantID, SubjectID: subjectID},
				SessionID: sessionID, AuthorizationGeneration: uint64(authorizationGen),
				Proof: platformapi.OpaqueAuthorizationProof{1},
			}
		},
	}, nil
}

func (harness celldHarness) Provenance() publicrepo.Provenance {
	return publicrepo.Provenance{Version: "0.1.0", Reference: harness.reference}
}

func TestCelldReferenceRepositoryFailsCrashDurableButPassesBehavior(t *testing.T) {
	t.Parallel()
	// Every atomic behavioral check (idempotency, sequence, replay+subscribe,
	// authorization fence) holds over the celld composition; only crash-durable
	// fails, because the reference celld.Storage is not durable.
	result := publicrepo.Qualify(context.Background(), celldHarness{reference: true, durable: false})
	if result.Status != conformance.Fail {
		t.Fatalf("result = %+v, want FAIL", result)
	}
	if !strings.Contains(result.Reason, "crash-durable") {
		t.Fatalf("reason %q should name the crash-durable check", result.Reason)
	}
}

func TestCelldDurableRepositoryPassesGateButNotPromotable(t *testing.T) {
	t.Parallel()
	result := publicrepo.Qualify(context.Background(), celldHarness{reference: true, durable: true})
	if result.Status != conformance.Pass {
		t.Fatalf("durable celld repository result = %+v, want PASS", result)
	}
	if !result.Evidence.Mock || result.Evidence.Class != conformance.EvidenceClassReferenceOnly {
		t.Fatalf("reference PASS evidence = %+v, want mock reference-only", result.Evidence)
	}
	collector := conformance.NewCollector()
	if err := collector.Add(result); err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	profile := conformance.Profile{Name: "production", Production: true, Required: []string{publicrepo.Component}}
	if err := collector.Evaluate(profile); err == nil {
		t.Fatal("production profile accepted a reference celld repository PASS")
	}
}

func newOp(t *testing.T) string {
	t.Helper()
	value, err := identity.New(identity.Operation)
	if err != nil {
		t.Fatalf("identity.New(Operation) error = %v", err)
	}
	return value.String()
}

func permit(operation platformapi.Operation) platformapi.AuthorizationPermit {
	return platformapi.AuthorizationPermit{
		Operation: operation,
		Principal: platformapi.Principal{TenantID: tenantID, SubjectID: subjectID},
		SessionID: sessionID, AuthorizationGeneration: uint64(authorizationGen),
		Proof: platformapi.OpaqueAuthorizationProof{1},
	}
}

func repoEventAuthority(turnID string) platformapi.EventAuthority {
	return platformapi.EventAuthority{
		Scope: authority.Scope{
			TenantID: tenantID, UserID: subjectID, SessionID: sessionID, TurnID: turnID,
			RuntimeRevision: runtimeRevision, WorkspaceID: workspaceID,
		},
		PlacementGeneration: uint64(placementGen), AuthorizationGeneration: uint64(authorizationGen),
	}
}

func newRegisteredRepository(t *testing.T) *celldrepo.Repository {
	t.Helper()
	storage := sessionstate.NewReferenceStorage()
	host := newHost(t, storage)
	repo, err := celldrepo.NewReferenceRepository(host, storage)
	if err != nil {
		t.Fatalf("NewReferenceRepository() error = %v", err)
	}
	if err := repo.RegisterSession(context.Background(), platformapi.SessionRegistration{
		TenantID: tenantID, SubjectID: subjectID, SessionID: sessionID,
		RuntimeRevision: runtimeRevision, WorkspaceID: workspaceID,
		PlacementGeneration: uint64(placementGen), AuthorizationGeneration: uint64(authorizationGen),
	}); err != nil {
		t.Fatalf("RegisterSession() error = %v", err)
	}
	return repo
}

func createOneTurn(t *testing.T, repo *celldrepo.Repository, turnID string) {
	t.Helper()
	_, _, err := repo.CreateTurn(context.Background(), platformapi.CreateTurnCommand{
		TenantID: tenantID, SubjectID: subjectID, SessionID: sessionID,
		KeyDigest: "key-1", RequestDigest: "digest-a",
		ProposedTurn: platformapi.Turn{
			ID: turnID, TenantID: tenantID, SubjectID: subjectID, SessionID: sessionID,
			RequestDigest: "digest-a", Status: platformapi.TurnQueued,
		},
		Authorization: permit(platformapi.OperationCreateTurn),
	})
	if err != nil {
		t.Fatalf("CreateTurn() error = %v", err)
	}
}

func appendDurable(t *testing.T, repo *celldrepo.Repository, turnID string, expected uint64, eventType platformapi.EventType, status platformapi.TurnStatus) platformapi.Event {
	t.Helper()
	event, _, err := repo.AppendDurableEvent(context.Background(), platformapi.AppendEventCommand{
		Authority: repoEventAuthority(turnID), CommandID: newOp(t), CommandDigest: "sha256:x",
		ExpectedSequence: expected, Type: eventType, Payload: `{"state":"x"}`, TurnStatus: status,
	})
	if err != nil {
		t.Fatalf("AppendDurableEvent(%s) error = %v", eventType, err)
	}
	return event
}

func TestCelldRepositoryReplayReconnectAndLiveSubscription(t *testing.T) {
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

	completed := appendDurable(t, repo, "turn-one", 1, platformapi.EventTurnCompleted, platformapi.TurnCompleted)
	if completed.Sequence != 2 {
		t.Fatalf("completed sequence = %d, want 2", completed.Sequence)
	}
	select {
	case live := <-stream.Subscription.Events():
		if live.Sequence != 2 || live.Type != platformapi.EventTurnCompleted || !live.Durable {
			t.Fatalf("live event = %#v", live)
		}
	case <-time.After(time.Second):
		t.Fatal("durable event was not delivered to the live subscriber")
	}
	select {
	case duplicate := <-stream.Subscription.Events():
		t.Fatalf("unexpected duplicate live event %#v", duplicate)
	default:
	}

	replay, err := repo.ReplayEvents(ctx, platformapi.ReplayQuery{
		TenantID: tenantID, SubjectID: subjectID, SessionID: sessionID,
		AfterSequence: 0, Limit: 16, Authorization: permit(platformapi.OperationReadEvents),
	})
	if err != nil || len(replay.Events) != 2 || replay.Snapshot.LastDurableSequence != 2 {
		t.Fatalf("replay = %#v, %v", replay, err)
	}
}

func TestCelldRepositoryEphemeralIsLiveOnly(t *testing.T) {
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

	if err := repo.PublishEphemeralEvent(ctx, repoEventAuthority("turn-one"), platformapi.Event{
		TurnID: "turn-one", Type: platformapi.EventModelDelta, Payload: "partial", Durable: false,
	}); err != nil {
		t.Fatalf("PublishEphemeralEvent() error = %v", err)
	}
	select {
	case live := <-stream.Subscription.Events():
		if live.Durable || live.Sequence != 0 || live.Type != platformapi.EventModelDelta {
			t.Fatalf("live ephemeral = %#v", live)
		}
	case <-time.After(time.Second):
		t.Fatal("ephemeral event was not delivered to the live subscriber")
	}

	replay, err := repo.ReplayEvents(ctx, platformapi.ReplayQuery{
		TenantID: tenantID, SubjectID: subjectID, SessionID: sessionID,
		AfterSequence: 0, Limit: 16, Authorization: permit(platformapi.OperationReadEvents),
	})
	if err != nil || len(replay.Events) != 1 || replay.Snapshot.LastDurableSequence != 1 {
		t.Fatalf("durable replay after ephemeral = %#v, %v", replay, err)
	}
}

func TestCelldRepositoryRejectsUnauthorizedReplay(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := newRegisteredRepository(t)
	createOneTurn(t, repo, "turn-one")

	stale := permit(platformapi.OperationReadEvents)
	stale.AuthorizationGeneration = uint64(authorizationGen) + 1
	if _, err := repo.ReplayEvents(ctx, platformapi.ReplayQuery{
		TenantID: tenantID, SubjectID: subjectID, SessionID: sessionID,
		AfterSequence: 0, Limit: 16, Authorization: stale,
	}); !errors.Is(err, platformapi.ErrAccessDenied) {
		t.Fatalf("stale-generation replay error = %v, want ErrAccessDenied", err)
	}
}
