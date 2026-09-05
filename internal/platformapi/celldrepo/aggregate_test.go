package celldrepo_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/hancomac/circulusd/internal/celld"
	"github.com/hancomac/circulusd/internal/platformapi/celldrepo"
	"github.com/hancomac/circulusd/internal/sessionevent"
	"github.com/hancomac/circulusd/internal/sessionstate"
)

const (
	tenantID         = "tenant_AAAAAAAAAAAAAAAAAAAAAAAAAA"
	subjectID        = "subject_AAAAAAAAAAAAAAAAAAAAAAAAAA"
	sessionID        = "sess_AAAAAAAAAAAAAAAAAAAAAAAAAA"
	runtimeRevision  = "runtime_AAAAAAAAAAAAAAAAAAAAAAAAAA"
	workspaceID      = "ws_AAAAAAAAAAAAAAAAAAAAAAAAAA"
	placementGen     = int64(4)
	authorizationGen = int64(7)
)

var (
	eventAccepted      = string(sessionevent.EventTurnAccepted)
	eventModelPrepared = string(sessionevent.EventModelEffectPrepared)
	eventCompleted     = string(sessionevent.EventTurnCompleted)
	statusActive       = string(sessionevent.TurnActive)
	statusCompleted    = string(sessionevent.TurnCompleted)
)

func newHost(t *testing.T, storage celld.Storage) *celld.Host {
	t.Helper()
	sealer, err := celld.NewPermitCodec(bytes.Repeat([]byte{0x3d}, 32))
	if err != nil {
		t.Fatalf("NewPermitCodec() error = %v", err)
	}
	host, err := celld.NewHost(celld.Config{Storage: storage, Aggregate: celldrepo.Aggregate{}, Sealer: sealer})
	if err != nil {
		t.Fatalf("NewHost() error = %v", err)
	}
	return host
}

func mustRegister(t *testing.T, host *celld.Host) {
	t.Helper()
	command, err := celldrepo.EncodeRegister(celldrepo.RegisterCommand{
		TenantID: tenantID, SubjectID: subjectID, SessionID: sessionID,
		RuntimeRevision: runtimeRevision, WorkspaceID: workspaceID,
		PlacementGeneration: placementGen, AuthorizationGeneration: authorizationGen,
	})
	if err != nil {
		t.Fatalf("EncodeRegister() error = %v", err)
	}
	if _, err := host.Execute(context.Background(), celld.Request{
		ObjectID: sessionID, CommandID: "op_register", Command: command,
	}); err != nil {
		t.Fatalf("register Execute() error = %v", err)
	}
}

func execCreate(t *testing.T, host *celld.Host, commandID string, input celldrepo.CreateTurnCommand) (celld.Result, error) {
	t.Helper()
	command, err := celldrepo.EncodeCreateTurn(input)
	if err != nil {
		t.Fatalf("EncodeCreateTurn() error = %v", err)
	}
	return host.Execute(context.Background(), celld.Request{ObjectID: sessionID, CommandID: commandID, Command: command})
}

func execAppend(t *testing.T, host *celld.Host, commandID string, input celldrepo.AppendEventCommand) (celld.Result, error) {
	t.Helper()
	command, err := celldrepo.EncodeAppendEvent(input)
	if err != nil {
		t.Fatalf("EncodeAppendEvent() error = %v", err)
	}
	return host.Execute(context.Background(), celld.Request{ObjectID: sessionID, CommandID: commandID, Command: command})
}

func createInput(keyDigest, requestDigest, proposedTurnID string) celldrepo.CreateTurnCommand {
	return celldrepo.CreateTurnCommand{
		SubjectID: subjectID, KeyDigest: keyDigest, RequestDigest: requestDigest,
		ProposedTurnID: proposedTurnID, AuthorizationGeneration: authorizationGen,
	}
}

func appendInput(turnID string, expectedSequence int64, eventType, turnStatus string) celldrepo.AppendEventCommand {
	return celldrepo.AppendEventCommand{
		TurnID: turnID, ExpectedSequence: expectedSequence, Type: eventType,
		Payload: `{"state":"` + turnStatus + `"}`, TurnStatus: turnStatus,
		PlacementGeneration: placementGen, AuthorizationGeneration: authorizationGen,
	}
}

func finalState(t *testing.T, storage *sessionstate.ReferenceStorage) celldrepoStateView {
	t.Helper()
	stateBytes, ok := storage.State(sessionID)
	if !ok {
		t.Fatalf("no committed state for %q", sessionID)
	}
	view, err := celldrepo.DecodeState(stateBytes)
	if err != nil {
		t.Fatalf("DecodeState() error = %v", err)
	}
	return view
}

type celldrepoStateView interface {
	Registered() bool
	LastDurableSequence() int64
	ActiveTurnID() string
	TurnStatus() string
	EventCount() int
}

func TestRegisterCreateDedupAndConflict(t *testing.T) {
	t.Parallel()
	storage := sessionstate.NewReferenceStorage()
	host := newHost(t, storage)
	mustRegister(t, host)

	first, err := execCreate(t, host, "op_create_a1", createInput("key-1", "digest-a", "turn-one"))
	if err != nil {
		t.Fatalf("first create error = %v", err)
	}
	turnID, dedup, status, err := celldrepo.DecodeCreateResponse(first.Response)
	if err != nil || dedup || turnID != "turn-one" || status != string(sessionevent.TurnQueued) {
		t.Fatalf("first create = %q dedup=%t status=%q err=%v", turnID, dedup, status, err)
	}

	// Same key + same digest with a different proposed turn deduplicates to the
	// first turn.
	repeat, err := execCreate(t, host, "op_create_a2", createInput("key-1", "digest-a", "turn-two"))
	if err != nil {
		t.Fatalf("duplicate create error = %v", err)
	}
	dupTurn, dedup, _, err := celldrepo.DecodeCreateResponse(repeat.Response)
	if err != nil || !dedup || dupTurn != "turn-one" {
		t.Fatalf("duplicate create = %q dedup=%t err=%v, want turn-one dedup=true", dupTurn, dedup, err)
	}

	// Same key + different digest conflicts.
	if _, err := execCreate(t, host, "op_create_a3", createInput("key-1", "digest-b", "turn-three")); !errors.Is(err, celldrepo.ErrIdempotencyConflict) {
		t.Fatalf("conflicting create error = %v, want ErrIdempotencyConflict", err)
	}

	// A distinct key creates a distinct turn.
	other, err := execCreate(t, host, "op_create_b1", createInput("key-2", "digest-c", "turn-four"))
	if err != nil {
		t.Fatalf("distinct-key create error = %v", err)
	}
	otherTurn, dedup, _, err := celldrepo.DecodeCreateResponse(other.Response)
	if err != nil || dedup || otherTurn != "turn-four" {
		t.Fatalf("distinct-key create = %q dedup=%t err=%v", otherTurn, dedup, err)
	}

	state := finalState(t, storage)
	if !state.Registered() || state.ActiveTurnID() != "turn-one" || state.EventCount() != 0 {
		t.Fatalf("final state active=%q events=%d", state.ActiveTurnID(), state.EventCount())
	}
}

func TestAppendLadderAndSequenceConflict(t *testing.T) {
	t.Parallel()
	storage := sessionstate.NewReferenceStorage()
	host := newHost(t, storage)
	mustRegister(t, host)
	if _, err := execCreate(t, host, "op_create", createInput("key-1", "digest-a", "turn-one")); err != nil {
		t.Fatalf("create error = %v", err)
	}

	accepted, err := execAppend(t, host, "op_append_1", appendInput("turn-one", 0, eventAccepted, statusActive))
	if err != nil {
		t.Fatalf("append accepted error = %v", err)
	}
	sequence, turnID, _, _, err := celldrepo.DecodeAppendResponse(accepted.Response)
	if err != nil || sequence != 1 || turnID != "turn-one" {
		t.Fatalf("append accepted = seq %d turn %q err %v", sequence, turnID, err)
	}

	// A distinct command reusing the consumed expected sequence loses the fence.
	if _, err := execAppend(t, host, "op_append_dup", appendInput("turn-one", 0, eventAccepted, statusActive)); !errors.Is(err, celldrepo.ErrSequenceConflict) {
		t.Fatalf("re-used sequence error = %v, want ErrSequenceConflict", err)
	}

	if _, err := execAppend(t, host, "op_append_2", appendInput("turn-one", 1, eventModelPrepared, statusActive)); err != nil {
		t.Fatalf("append model prepared error = %v", err)
	}
	if _, err := execAppend(t, host, "op_append_3", appendInput("turn-one", 2, eventCompleted, statusCompleted)); err != nil {
		t.Fatalf("append completed error = %v", err)
	}

	state := finalState(t, storage)
	if state.EventCount() != 3 || state.LastDurableSequence() != 3 || state.TurnStatus() != statusCompleted {
		t.Fatalf("final state events=%d last=%d status=%q", state.EventCount(), state.LastDurableSequence(), state.TurnStatus())
	}
}

func TestAppendRejectsStaleGenerations(t *testing.T) {
	t.Parallel()
	storage := sessionstate.NewReferenceStorage()
	host := newHost(t, storage)
	mustRegister(t, host)
	if _, err := execCreate(t, host, "op_create", createInput("key-1", "digest-a", "turn-one")); err != nil {
		t.Fatalf("create error = %v", err)
	}

	stalePlacement := appendInput("turn-one", 0, eventAccepted, statusActive)
	stalePlacement.PlacementGeneration = placementGen - 1
	if _, err := execAppend(t, host, "op_stale_p", stalePlacement); !errors.Is(err, celldrepo.ErrStaleAuthority) {
		t.Fatalf("stale placement error = %v, want ErrStaleAuthority", err)
	}

	staleAuthz := appendInput("turn-one", 0, eventAccepted, statusActive)
	staleAuthz.AuthorizationGeneration = authorizationGen - 1
	if _, err := execAppend(t, host, "op_stale_a", staleAuthz); !errors.Is(err, celldrepo.ErrStaleAuthority) {
		t.Fatalf("stale authorization error = %v, want ErrStaleAuthority", err)
	}
}

func TestCreateRejectsStaleAuthorization(t *testing.T) {
	t.Parallel()
	storage := sessionstate.NewReferenceStorage()
	host := newHost(t, storage)
	mustRegister(t, host)

	stale := createInput("key-1", "digest-a", "turn-one")
	stale.AuthorizationGeneration = authorizationGen - 1
	if _, err := execCreate(t, host, "op_create_stale", stale); !errors.Is(err, celldrepo.ErrStaleAuthority) {
		t.Fatalf("stale-authorization create error = %v, want ErrStaleAuthority", err)
	}
}

func TestCelldReceiptReplaysAppendAndConflictsOnMismatch(t *testing.T) {
	t.Parallel()
	storage := sessionstate.NewReferenceStorage()
	host := newHost(t, storage)
	mustRegister(t, host)
	if _, err := execCreate(t, host, "op_create", createInput("key-1", "digest-a", "turn-one")); err != nil {
		t.Fatalf("create error = %v", err)
	}
	first, err := execAppend(t, host, "op_append", appendInput("turn-one", 0, eventAccepted, statusActive))
	if err != nil || first.Replayed {
		t.Fatalf("first append = %#v, %v", first, err)
	}

	// The same command id and body replays the same durable event.
	replay, err := execAppend(t, host, "op_append", appendInput("turn-one", 0, eventAccepted, statusActive))
	if err != nil || !replay.Replayed {
		t.Fatalf("replay append = replayed:%t, %v", replay.Replayed, err)
	}
	sequence, _, _, _, err := celldrepo.DecodeAppendResponse(replay.Response)
	if err != nil || sequence != 1 {
		t.Fatalf("replay response = seq %d err %v", sequence, err)
	}

	// The same command id with a different body is an idempotency conflict.
	different := appendInput("turn-one", 0, eventAccepted, statusActive)
	different.Payload = `{"state":"tampered"}`
	if _, err := execAppend(t, host, "op_append", different); !errors.Is(err, celld.ErrIdempotencyConflict) {
		t.Fatalf("mismatched replay error = %v, want celld.ErrIdempotencyConflict", err)
	}
}

func TestKillRestartReplaysCommittedRecord(t *testing.T) {
	t.Parallel()
	storage := sessionstate.NewReferenceStorage()
	host := newHost(t, storage)
	mustRegister(t, host)
	if _, err := execCreate(t, host, "op_create", createInput("key-1", "digest-a", "turn-one")); err != nil {
		t.Fatalf("create error = %v", err)
	}
	if _, err := execAppend(t, host, "op_append_1", appendInput("turn-one", 0, eventAccepted, statusActive)); err != nil {
		t.Fatalf("append accepted error = %v", err)
	}

	// Restart: a fresh Host over the same committed storage.
	restarted := newHost(t, storage)

	// The persisted creation receipt still deduplicates the same key.
	repeat, err := execCreate(t, restarted, "op_create_after_restart", createInput("key-1", "digest-a", "turn-two"))
	if err != nil {
		t.Fatalf("post-restart create error = %v", err)
	}
	turnID, dedup, _, err := celldrepo.DecodeCreateResponse(repeat.Response)
	if err != nil || !dedup || turnID != "turn-one" {
		t.Fatalf("post-restart create = %q dedup=%t err=%v, want turn-one dedup=true", turnID, dedup, err)
	}

	// The durable journal continues from the persisted sequence.
	next, err := execAppend(t, restarted, "op_append_2", appendInput("turn-one", 1, eventModelPrepared, statusActive))
	if err != nil {
		t.Fatalf("post-restart append error = %v", err)
	}
	sequence, _, _, _, err := celldrepo.DecodeAppendResponse(next.Response)
	if err != nil || sequence != 2 {
		t.Fatalf("post-restart append = seq %d err %v", sequence, err)
	}

	state := finalState(t, storage)
	if state.EventCount() != 2 || state.LastDurableSequence() != 2 {
		t.Fatalf("final state events=%d last=%d, want 2/2", state.EventCount(), state.LastDurableSequence())
	}
}
