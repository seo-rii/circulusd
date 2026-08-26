package platformapi

import (
	"context"
	"sync"

	"github.com/hancomac/circulusd/internal/identity"
)

type creationReceipt struct {
	requestDigest string
	turn          Turn
}

type eventReceipt struct {
	commandDigest string
	event         Event
}

type memorySession struct {
	registration     SessionRegistration
	turns            map[string]Turn
	creationReceipts map[string]creationReceipt
	eventReceipts    map[string]eventReceipt
	events           []Event
	snapshot         SessionSnapshot
	subscribers      map[uint64]chan Event
	nextSubscriberID uint64
}

// MemoryStore is a race-safe reference implementation of Repository. Its
// mutex is the transaction boundary for idempotent creation, fenced append,
// sequence allocation, receipt persistence, and snapshot publication.
type MemoryStore struct {
	mu       sync.RWMutex
	sessions map[string]*memorySession
	turns    map[string]string
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		sessions: make(map[string]*memorySession),
		turns:    make(map[string]string),
	}
}

func (*MemoryStore) Durability() RepositoryDurability {
	return RepositoryDurability{
		CrashDurable: false, AtomicIdempotency: true, AtomicEventSequence: true,
		AtomicReplaySubscribe: true, AtomicAuthorizationFence: true,
	}
}

func (store *MemoryStore) RegisterSession(ctx context.Context, registration SessionRegistration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := identity.Parse(identity.Tenant, registration.TenantID); err != nil {
		return ErrInvalidRequest
	}
	if _, err := identity.Parse(identity.Subject, registration.SubjectID); err != nil {
		return ErrInvalidRequest
	}
	if _, err := identity.Parse(identity.Session, registration.SessionID); err != nil {
		return ErrInvalidRequest
	}
	if _, err := identity.Parse(identity.RuntimeRevision, registration.RuntimeRevision); err != nil {
		return ErrInvalidRequest
	}
	if _, err := identity.Parse(identity.Workspace, registration.WorkspaceID); err != nil ||
		registration.PlacementGeneration == 0 || registration.AuthorizationGeneration == 0 {
		return ErrInvalidRequest
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, found := store.sessions[registration.SessionID]; found {
		if existing.registration == registration {
			return nil
		}
		return ErrInvalidTransition
	}
	store.sessions[registration.SessionID] = &memorySession{
		registration:     registration,
		turns:            make(map[string]Turn),
		creationReceipts: make(map[string]creationReceipt),
		eventReceipts:    make(map[string]eventReceipt),
		snapshot:         SessionSnapshot{SessionID: registration.SessionID},
		subscribers:      make(map[uint64]chan Event),
	}
	return nil
}

func (store *MemoryStore) CreateTurn(
	ctx context.Context,
	command CreateTurnCommand,
) (Turn, bool, error) {
	if err := ctx.Err(); err != nil {
		return Turn{}, false, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	session, found := store.sessions[command.SessionID]
	if !found {
		return Turn{}, false, ErrSessionNotFound
	}
	if session.registration.TenantID != command.TenantID ||
		session.registration.SubjectID != command.SubjectID {
		return Turn{}, false, ErrAccessDenied
	}
	if !store.authorizedForSession(session, command.Authorization, OperationCreateTurn) {
		return Turn{}, false, ErrAccessDenied
	}
	receiptKey := command.SubjectID + "\x00" + command.KeyDigest
	if receipt, found := session.creationReceipts[receiptKey]; found {
		if receipt.requestDigest != command.RequestDigest {
			return Turn{}, false, ErrIdempotencyConflict
		}
		return receipt.turn, true, nil
	}
	if ownerSession, collision := store.turns[command.ProposedTurn.ID]; collision && ownerSession != command.SessionID {
		return Turn{}, false, ErrIdempotencyConflict
	}
	if _, collision := session.turns[command.ProposedTurn.ID]; collision {
		return Turn{}, false, ErrIdempotencyConflict
	}
	session.turns[command.ProposedTurn.ID] = command.ProposedTurn
	session.creationReceipts[receiptKey] = creationReceipt{
		requestDigest: command.RequestDigest,
		turn:          command.ProposedTurn,
	}
	store.turns[command.ProposedTurn.ID] = command.SessionID
	if session.snapshot.ActiveTurnID == "" {
		session.snapshot.ActiveTurnID = command.ProposedTurn.ID
		session.snapshot.TurnStatus = command.ProposedTurn.Status
	}
	return command.ProposedTurn, false, nil
}

func (store *MemoryStore) AppendDurableEvent(
	ctx context.Context,
	command AppendEventCommand,
) (Event, bool, error) {
	if err := ctx.Err(); err != nil {
		return Event{}, false, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	session, err := store.authorizedSession(command.Authority)
	if err != nil {
		return Event{}, false, err
	}
	if receipt, found := session.eventReceipts[command.CommandID]; found {
		if receipt.commandDigest != command.CommandDigest {
			return Event{}, false, ErrIdempotencyConflict
		}
		return receipt.event, true, nil
	}
	if command.ExpectedSequence != uint64(len(session.events)) {
		return Event{}, false, ErrSequenceConflict
	}
	turn := session.turns[command.Authority.Scope.TurnID]
	if err := validateTurnTransition(turn.Status, command.TurnStatus, command.Type); err != nil {
		return Event{}, false, err
	}
	event := Event{
		Sequence: uint64(len(session.events)) + 1,
		TurnID:   command.Authority.Scope.TurnID,
		Type:     command.Type,
		Payload:  command.Payload,
		Durable:  true,
	}
	turn.Status = command.TurnStatus
	session.turns[turn.ID] = turn
	session.events = append(session.events, event)
	session.eventReceipts[command.CommandID] = eventReceipt{
		commandDigest: command.CommandDigest,
		event:         event,
	}
	session.snapshot.ActiveTurnID = turn.ID
	session.snapshot.TurnStatus = turn.Status
	session.snapshot.LastDurableSequence = event.Sequence
	store.publishLocked(session, event)
	return event, false, nil
}

func (store *MemoryStore) PublishEphemeralEvent(ctx context.Context, authority EventAuthority, event Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	session, err := store.authorizedSession(authority)
	if err != nil {
		return err
	}
	if event.Durable || event.Sequence != 0 || event.TurnID != authority.Scope.TurnID ||
		!validEphemeralEvent(event.Type) || event.Payload == "" {
		return ErrInvalidRequest
	}
	store.publishLocked(session, event)
	return nil
}

func (store *MemoryStore) ReplayEvents(ctx context.Context, query ReplayQuery) (EventReplay, error) {
	if err := ctx.Err(); err != nil {
		return EventReplay{}, err
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	session, found := store.sessions[query.SessionID]
	if !found {
		return EventReplay{}, ErrSessionNotFound
	}
	if session.registration.TenantID != query.TenantID || session.registration.SubjectID != query.SubjectID ||
		!store.authorizedForSession(session, query.Authorization, OperationReadEvents) {
		return EventReplay{}, ErrAccessDenied
	}
	return store.replayLocked(session, query)
}

func (store *MemoryStore) OpenEventStream(ctx context.Context, query ReplayQuery) (EventStream, error) {
	if err := ctx.Err(); err != nil {
		return EventStream{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	session, found := store.sessions[query.SessionID]
	if !found {
		return EventStream{}, ErrSessionNotFound
	}
	if session.registration.TenantID != query.TenantID || session.registration.SubjectID != query.SubjectID ||
		!store.authorizedForSession(session, query.Authorization, OperationReadEvents) {
		return EventStream{}, ErrAccessDenied
	}
	replay, err := store.replayLocked(session, query)
	if err != nil {
		return EventStream{}, err
	}
	lastReplayed := query.AfterSequence
	if len(replay.Events) != 0 {
		lastReplayed = replay.Events[len(replay.Events)-1].Sequence
	}
	stream := EventStream{Replay: replay, CaughtUp: lastReplayed == replay.Snapshot.LastDurableSequence}
	if !stream.CaughtUp {
		return stream, nil
	}
	session.nextSubscriberID++
	channel := make(chan Event, 64)
	session.subscribers[session.nextSubscriberID] = channel
	stream.Subscription = &memorySubscription{
		store: store, sessionID: query.SessionID, subscriberID: session.nextSubscriberID, events: channel,
	}
	return stream, nil
}

func (store *MemoryStore) replayLocked(session *memorySession, query ReplayQuery) (EventReplay, error) {
	if query.Limit < 1 {
		return EventReplay{}, ErrInvalidRequest
	}
	last := uint64(len(session.events))
	if query.AfterSequence > last {
		return EventReplay{}, ErrInvalidCursor
	}
	start := int(query.AfterSequence)
	end := start + query.Limit
	if end > len(session.events) {
		end = len(session.events)
	}
	return EventReplay{
		Snapshot: session.snapshot,
		Events:   append([]Event(nil), session.events[start:end]...),
	}, nil
}

func (store *MemoryStore) publishLocked(session *memorySession, event Event) {
	for subscriberID, events := range session.subscribers {
		select {
		case events <- event:
		default:
			if event.Durable {
				close(events)
				delete(session.subscribers, subscriberID)
			}
		}
	}
}

func (store *MemoryStore) TurnCount(tenantID string, sessionID string) int {
	store.mu.RLock()
	defer store.mu.RUnlock()
	session, found := store.sessions[sessionID]
	if !found || session.registration.TenantID != tenantID {
		return 0
	}
	return len(session.turns)
}

// RotateAuthorizationGeneration models the authoritative ACL revocation fence.
// Existing readers are disconnected while the mutex is held, so an event
// published under the next generation cannot reach an old subscription.
func (store *MemoryStore) RotateAuthorizationGeneration(
	ctx context.Context,
	tenantID string,
	subjectID string,
	sessionID string,
	expected uint64,
	next uint64,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := identity.Parse(identity.Tenant, tenantID); err != nil {
		return ErrInvalidRequest
	}
	if _, err := identity.Parse(identity.Subject, subjectID); err != nil {
		return ErrInvalidRequest
	}
	if _, err := identity.Parse(identity.Session, sessionID); err != nil || expected == 0 ||
		next <= expected || next > maximumSharedInteger {
		return ErrInvalidRequest
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	session, found := store.sessions[sessionID]
	if !found {
		return ErrSessionNotFound
	}
	if session.registration.TenantID != tenantID || session.registration.SubjectID != subjectID {
		return ErrAccessDenied
	}
	if session.registration.AuthorizationGeneration != expected {
		return ErrStaleAuthority
	}
	session.registration.AuthorizationGeneration = next
	for subscriberID, events := range session.subscribers {
		close(events)
		delete(session.subscribers, subscriberID)
	}
	return nil
}

func (*MemoryStore) authorizedForSession(
	session *memorySession,
	permit AuthorizationPermit,
	operation Operation,
) bool {
	return permit.Operation == operation &&
		permit.Principal.TenantID == session.registration.TenantID &&
		permit.Principal.SubjectID == session.registration.SubjectID &&
		permit.SessionID == session.registration.SessionID &&
		permit.AuthorizationGeneration == session.registration.AuthorizationGeneration &&
		permit.Proof != (OpaqueAuthorizationProof{})
}

func (store *MemoryStore) authorizedSession(authority EventAuthority) (*memorySession, error) {
	session, found := store.sessions[authority.Scope.SessionID]
	if !found {
		return nil, ErrSessionNotFound
	}
	if session.registration.TenantID != authority.Scope.TenantID ||
		session.registration.SubjectID != authority.Scope.UserID ||
		session.registration.RuntimeRevision != authority.Scope.RuntimeRevision ||
		session.registration.WorkspaceID != authority.Scope.WorkspaceID {
		return nil, ErrAccessDenied
	}
	if session.registration.PlacementGeneration != authority.PlacementGeneration ||
		session.registration.AuthorizationGeneration != authority.AuthorizationGeneration {
		return nil, ErrStaleAuthority
	}
	turn, found := session.turns[authority.Scope.TurnID]
	if !found {
		return nil, ErrTurnNotFound
	}
	if turn.SubjectID != authority.Scope.UserID || turn.TenantID != authority.Scope.TenantID ||
		turn.SessionID != authority.Scope.SessionID {
		return nil, ErrAccessDenied
	}
	return session, nil
}

type memorySubscription struct {
	store        *MemoryStore
	sessionID    string
	subscriberID uint64
	events       <-chan Event
}

func (subscription *memorySubscription) Events() <-chan Event {
	return subscription.events
}

func (subscription *memorySubscription) Close() {
	if subscription == nil || subscription.store == nil {
		return
	}
	subscription.store.mu.Lock()
	defer subscription.store.mu.Unlock()
	session, found := subscription.store.sessions[subscription.sessionID]
	if !found {
		return
	}
	events, found := session.subscribers[subscription.subscriberID]
	if !found {
		return
	}
	delete(session.subscribers, subscription.subscriberID)
	close(events)
}
