package celldrepo

import (
	"context"
	"errors"

	"github.com/hancomac/circulusd/internal/celld"
	"github.com/hancomac/circulusd/internal/identity"
	"github.com/hancomac/circulusd/internal/platformapi"
	"sync"
)

// StateReader reads the committed state bytes of one celld object. The reference
// celld.Storage (sessionstate.ReferenceStorage) satisfies it; a real celld
// deployment supplies an equivalent authoritative read.
type StateReader interface {
	State(objectID string) ([]byte, bool)
}

// Repository is a platformapi.Repository backed by the public-session Aggregate
// running under a celld.Host. Durable idempotency, sequence fencing, and the
// crash barrier come from celld; live subscription delivery (durable fan-out and
// ephemeral events) is served in process, exactly as the MemoryStore reference.
//
// A single mutex serializes durable append (host Execute plus its live publish)
// against opening a stream (committed read plus subscribe), so no durable event
// is lost or duplicated across the replay-to-live handoff.
//
// The reference constructor reports CrashDurable:false: over the reference
// celld.Storage this proves the atomic contract behaviorally but is not durable.
// A served, promotable Repository requires a real crash-durable celld substrate
// (Unit 11.6) and would report CrashDurable:true.
type Repository struct {
	host         *celld.Host
	reader       StateReader
	newCommandID func() (string, error)
	crashDurable bool

	mu          sync.Mutex
	subscribers map[string]map[uint64]chan platformapi.Event
	nextSubID   uint64
}

var _ platformapi.Repository = (*Repository)(nil)

// NewReferenceRepository builds a reference (non-durable) Repository over a
// celld.Host and a committed-state reader for the same storage.
func NewReferenceRepository(host *celld.Host, reader StateReader) (*Repository, error) {
	if host == nil || reader == nil {
		return nil, errors.New("celldrepo: host and reader are required")
	}
	return &Repository{
		host:   host,
		reader: reader,
		newCommandID: func() (string, error) {
			value, err := identity.New(identity.Operation)
			if err != nil {
				return "", err
			}
			return value.String(), nil
		},
		crashDurable: false,
		subscribers:  make(map[string]map[uint64]chan platformapi.Event),
	}, nil
}

// Durability reports the reference contract: the atomic behaviors are
// implemented, but the reference celld.Storage is not crash durable.
func (repo *Repository) Durability() platformapi.RepositoryDurability {
	return platformapi.RepositoryDurability{
		CrashDurable:             repo.crashDurable,
		AtomicIdempotency:        true,
		AtomicEventSequence:      true,
		AtomicReplaySubscribe:    true,
		AtomicAuthorizationFence: true,
	}
}

// RegisterSession provisions the session object. It is idempotent: an identical
// registration succeeds, a conflicting one is rejected.
func (repo *Repository) RegisterSession(ctx context.Context, registration platformapi.SessionRegistration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	encoded, err := EncodeRegister(RegisterCommand{
		TenantID: registration.TenantID, SubjectID: registration.SubjectID,
		SessionID: registration.SessionID, RuntimeRevision: registration.RuntimeRevision,
		WorkspaceID:             registration.WorkspaceID,
		PlacementGeneration:     int64(registration.PlacementGeneration),
		AuthorizationGeneration: int64(registration.AuthorizationGeneration),
	})
	if err != nil {
		return platformapi.ErrInvalidRequest
	}
	commandID, err := repo.newCommandID()
	if err != nil {
		return platformapi.ErrRepositoryFailure
	}
	if _, err := repo.host.Execute(ctx, celld.Request{
		ObjectID: registration.SessionID, CommandID: commandID, Command: encoded,
	}); err != nil {
		if errors.Is(err, ErrRegistrationConflict) {
			return platformapi.ErrInvalidTransition
		}
		return platformapi.ErrRepositoryFailure
	}
	return nil
}

func (repo *Repository) CreateTurn(
	ctx context.Context,
	command platformapi.CreateTurnCommand,
) (platformapi.Turn, bool, error) {
	if err := ctx.Err(); err != nil {
		return platformapi.Turn{}, false, err
	}
	if command.Authorization.Operation != platformapi.OperationCreateTurn ||
		command.Authorization.Proof == (platformapi.OpaqueAuthorizationProof{}) {
		return platformapi.Turn{}, false, platformapi.ErrAccessDenied
	}
	encoded, err := EncodeCreateTurn(CreateTurnCommand{
		SubjectID: command.SubjectID, KeyDigest: command.KeyDigest,
		RequestDigest: command.RequestDigest, ProposedTurnID: command.ProposedTurn.ID,
		AuthorizationGeneration: int64(command.Authorization.AuthorizationGeneration),
	})
	if err != nil {
		return platformapi.Turn{}, false, platformapi.ErrInvalidRequest
	}
	commandID, err := repo.newCommandID()
	if err != nil {
		return platformapi.Turn{}, false, platformapi.ErrRepositoryFailure
	}
	result, err := repo.host.Execute(ctx, celld.Request{
		ObjectID: command.SessionID, CommandID: commandID, Command: encoded,
	})
	if err != nil {
		return platformapi.Turn{}, false, mapCreateError(err)
	}
	turnID, deduplicated, status, err := DecodeCreateResponse(result.Response)
	if err != nil {
		return platformapi.Turn{}, false, platformapi.ErrRepositoryFailure
	}
	return platformapi.Turn{
		ID: turnID, TenantID: command.TenantID, SubjectID: command.SubjectID,
		SessionID: command.SessionID, RequestDigest: command.RequestDigest,
		Status: platformapi.TurnStatus(status),
	}, deduplicated, nil
}

func (repo *Repository) AppendDurableEvent(
	ctx context.Context,
	command platformapi.AppendEventCommand,
) (platformapi.Event, bool, error) {
	if err := ctx.Err(); err != nil {
		return platformapi.Event{}, false, err
	}
	encoded, err := EncodeAppendEvent(AppendEventCommand{
		TurnID: command.Authority.Scope.TurnID, ExpectedSequence: int64(command.ExpectedSequence),
		Type: string(command.Type), Payload: command.Payload, TurnStatus: string(command.TurnStatus),
		PlacementGeneration:     int64(command.Authority.PlacementGeneration),
		AuthorizationGeneration: int64(command.Authority.AuthorizationGeneration),
	})
	if err != nil {
		return platformapi.Event{}, false, platformapi.ErrInvalidRequest
	}
	repo.mu.Lock()
	defer repo.mu.Unlock()
	result, err := repo.host.Execute(ctx, celld.Request{
		ObjectID: command.Authority.Scope.SessionID, CommandID: command.CommandID, Command: encoded,
	})
	if err != nil {
		return platformapi.Event{}, false, mapAppendError(err)
	}
	sequence, turnID, eventType, payload, err := DecodeAppendResponse(result.Response)
	if err != nil {
		return platformapi.Event{}, false, platformapi.ErrRepositoryFailure
	}
	event := platformapi.Event{
		Sequence: sequence, TurnID: turnID, Type: platformapi.EventType(eventType),
		Payload: payload, Durable: true,
	}
	if !result.Replayed {
		repo.publishLocked(command.Authority.Scope.SessionID, event)
	}
	return event, result.Replayed, nil
}

func (repo *Repository) PublishEphemeralEvent(
	ctx context.Context,
	authority platformapi.EventAuthority,
	event platformapi.Event,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if event.Durable || event.Sequence != 0 || event.TurnID != authority.Scope.TurnID || event.Payload == "" {
		return platformapi.ErrInvalidRequest
	}
	repo.mu.Lock()
	defer repo.mu.Unlock()
	record, found, err := repo.readRecord(authority.Scope.SessionID)
	if err != nil {
		return platformapi.ErrRepositoryFailure
	}
	if !found {
		return platformapi.ErrSessionNotFound
	}
	if record.tenantID != authority.Scope.TenantID || record.subjectID != authority.Scope.UserID ||
		record.runtimeRevision != authority.Scope.RuntimeRevision || record.workspaceID != authority.Scope.WorkspaceID {
		return platformapi.ErrAccessDenied
	}
	if record.placementGeneration != int64(authority.PlacementGeneration) ||
		record.authorizationGeneration != int64(authority.AuthorizationGeneration) {
		return platformapi.ErrStaleAuthority
	}
	if _, ok := record.turns[authority.Scope.TurnID]; !ok {
		return platformapi.ErrTurnNotFound
	}
	repo.publishLocked(authority.Scope.SessionID, event)
	return nil
}

func (repo *Repository) ReplayEvents(
	ctx context.Context,
	query platformapi.ReplayQuery,
) (platformapi.EventReplay, error) {
	if err := ctx.Err(); err != nil {
		return platformapi.EventReplay{}, err
	}
	record, found, err := repo.readRecord(query.SessionID)
	if err != nil {
		return platformapi.EventReplay{}, platformapi.ErrRepositoryFailure
	}
	if !found {
		return platformapi.EventReplay{}, platformapi.ErrSessionNotFound
	}
	if err := authorizeRead(record, query); err != nil {
		return platformapi.EventReplay{}, err
	}
	replay, err := projectReplay(record, query)
	if err != nil {
		return platformapi.EventReplay{}, err
	}
	return replay, nil
}

func (repo *Repository) OpenEventStream(
	ctx context.Context,
	query platformapi.ReplayQuery,
) (platformapi.EventStream, error) {
	if err := ctx.Err(); err != nil {
		return platformapi.EventStream{}, err
	}
	repo.mu.Lock()
	defer repo.mu.Unlock()
	record, found, err := repo.readRecord(query.SessionID)
	if err != nil {
		return platformapi.EventStream{}, platformapi.ErrRepositoryFailure
	}
	if !found {
		return platformapi.EventStream{}, platformapi.ErrSessionNotFound
	}
	if err := authorizeRead(record, query); err != nil {
		return platformapi.EventStream{}, err
	}
	replay, err := projectReplay(record, query)
	if err != nil {
		return platformapi.EventStream{}, err
	}
	lastReplayed := query.AfterSequence
	if count := len(replay.Events); count != 0 {
		lastReplayed = replay.Events[count-1].Sequence
	}
	stream := platformapi.EventStream{
		Replay: replay, CaughtUp: lastReplayed == replay.Snapshot.LastDurableSequence,
	}
	if stream.CaughtUp {
		stream.Subscription = repo.subscribeLocked(query.SessionID)
	}
	return stream, nil
}

func (repo *Repository) readRecord(sessionID string) (sessionRecord, bool, error) {
	stateBytes, ok := repo.reader.State(sessionID)
	if !ok {
		return sessionRecord{}, false, nil
	}
	record, err := decodeState(stateBytes)
	if err != nil {
		return sessionRecord{}, false, err
	}
	if !record.registered() {
		return sessionRecord{}, false, nil
	}
	return record, true, nil
}

func authorizeRead(record sessionRecord, query platformapi.ReplayQuery) error {
	permit := query.Authorization
	if record.tenantID != query.TenantID || record.subjectID != query.SubjectID ||
		permit.Operation != platformapi.OperationReadEvents ||
		permit.Principal.TenantID != record.tenantID || permit.Principal.SubjectID != record.subjectID ||
		permit.SessionID != query.SessionID ||
		permit.AuthorizationGeneration != uint64(record.authorizationGeneration) ||
		permit.Proof == (platformapi.OpaqueAuthorizationProof{}) {
		return platformapi.ErrAccessDenied
	}
	return nil
}

func projectReplay(record sessionRecord, query platformapi.ReplayQuery) (platformapi.EventReplay, error) {
	limit := query.Limit
	if limit < 1 {
		return platformapi.EventReplay{}, platformapi.ErrInvalidRequest
	}
	if query.AfterSequence > uint64(len(record.events)) {
		return platformapi.EventReplay{}, platformapi.ErrInvalidCursor
	}
	snapshot, events, err := project(record, query.AfterSequence, limit)
	if err != nil {
		return platformapi.EventReplay{}, platformapi.ErrRepositoryFailure
	}
	replay := platformapi.EventReplay{
		Snapshot: platformapi.SessionSnapshot{
			SessionID:           snapshot.SessionID,
			ActiveTurnID:        snapshot.ActiveTurnID,
			TurnStatus:          platformapi.TurnStatus(snapshot.TurnStatus),
			LastDurableSequence: snapshot.LastDurableSequence,
		},
		Events: make([]platformapi.Event, 0, len(events)),
	}
	for _, event := range events {
		replay.Events = append(replay.Events, platformapi.Event{
			Sequence: event.Sequence, TurnID: event.TurnID,
			Type: platformapi.EventType(event.Type), Payload: event.Payload, Durable: true,
		})
	}
	return replay, nil
}

// publishLocked fans a live event out to the session's subscribers. A durable
// event that cannot be delivered closes the subscription so the client
// reconnects from its cursor; an ephemeral event that cannot be delivered is
// dropped. Callers must hold repo.mu.
func (repo *Repository) publishLocked(sessionID string, event platformapi.Event) {
	for id, channel := range repo.subscribers[sessionID] {
		select {
		case channel <- event:
		default:
			if event.Durable {
				close(channel)
				delete(repo.subscribers[sessionID], id)
			}
		}
	}
}

func (repo *Repository) subscribeLocked(sessionID string) *subscription {
	if repo.subscribers[sessionID] == nil {
		repo.subscribers[sessionID] = make(map[uint64]chan platformapi.Event)
	}
	repo.nextSubID++
	id := repo.nextSubID
	channel := make(chan platformapi.Event, 64)
	repo.subscribers[sessionID][id] = channel
	return &subscription{repo: repo, sessionID: sessionID, id: id, events: channel}
}

type subscription struct {
	repo      *Repository
	sessionID string
	id        uint64
	events    chan platformapi.Event
}

func (sub *subscription) Events() <-chan platformapi.Event { return sub.events }

func (sub *subscription) Close() {
	if sub == nil || sub.repo == nil {
		return
	}
	sub.repo.mu.Lock()
	defer sub.repo.mu.Unlock()
	channels := sub.repo.subscribers[sub.sessionID]
	if channels == nil {
		return
	}
	if channel, ok := channels[sub.id]; ok {
		delete(channels, sub.id)
		close(channel)
	}
}

func mapCreateError(err error) error {
	switch {
	case errors.Is(err, ErrIdempotencyConflict), errors.Is(err, celld.ErrIdempotencyConflict):
		return platformapi.ErrIdempotencyConflict
	case errors.Is(err, ErrStaleAuthority):
		return platformapi.ErrStaleAuthority
	case errors.Is(err, ErrAccessDenied):
		return platformapi.ErrAccessDenied
	case errors.Is(err, ErrNotRegistered):
		return platformapi.ErrSessionNotFound
	default:
		return platformapi.ErrRepositoryFailure
	}
}

func mapAppendError(err error) error {
	switch {
	case errors.Is(err, ErrSequenceConflict):
		return platformapi.ErrSequenceConflict
	case errors.Is(err, ErrStaleAuthority):
		return platformapi.ErrStaleAuthority
	case errors.Is(err, ErrTurnNotFound):
		return platformapi.ErrTurnNotFound
	case errors.Is(err, ErrInvalidTransition):
		return platformapi.ErrInvalidTransition
	case errors.Is(err, ErrIdempotencyConflict), errors.Is(err, celld.ErrIdempotencyConflict):
		return platformapi.ErrIdempotencyConflict
	case errors.Is(err, ErrNotRegistered):
		return platformapi.ErrSessionNotFound
	default:
		return platformapi.ErrRepositoryFailure
	}
}
