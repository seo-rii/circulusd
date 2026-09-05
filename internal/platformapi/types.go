// Package platformapi implements the authenticated public turn API and its
// durable event replay boundary. Durable repositories must preserve the same
// atomic idempotency, sequence, and generation-fencing contracts as the
// race-safe memory reference adapter.
package platformapi

import (
	"context"
	"errors"

	"github.com/hancomac/circulusd/internal/authority"
	"github.com/hancomac/circulusd/internal/sessionevent"
)

var (
	ErrInvalidConfig        = sessionevent.ErrInvalidConfig
	ErrInvalidRequest       = sessionevent.ErrInvalidRequest
	ErrAccessDenied         = sessionevent.ErrAccessDenied
	ErrSessionNotFound      = sessionevent.ErrSessionNotFound
	ErrTurnNotFound         = errors.New("platform api: turn not found")
	ErrIdempotencyConflict  = errors.New("platform api: idempotency conflict")
	ErrSequenceConflict     = errors.New("platform api: durable event sequence conflict")
	ErrInvalidCursor        = sessionevent.ErrInvalidCursor
	ErrStaleAuthority       = sessionevent.ErrStaleAuthority
	ErrInvalidTransition    = errors.New("platform api: invalid turn transition")
	ErrRepositoryFailure    = sessionevent.ErrRepositoryFailure
	ErrRepositoryNotDurable = errors.New("platform api: repository is not crash durable")
)

type Operation = sessionevent.Operation

const (
	OperationCreateTurn = sessionevent.OperationCreateTurn
	OperationReadEvents = sessionevent.OperationReadEvents
)

type Principal = sessionevent.Principal
type AuthorizationRequest = sessionevent.AuthorizationRequest
type OpaqueAuthorizationProof = sessionevent.OpaqueAuthorizationProof
type AuthorizationPermit = sessionevent.AuthorizationPermit
type Authorizer = sessionevent.Authorizer

// EventAuthorizer verifies fresh Session authority before any repository
// lookup. EventAuthority fields are comparison targets, not credentials.
type EventAuthorizer interface {
	AuthorizeEvent(context.Context, EventAuthority) error
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type TurnStatus = sessionevent.TurnStatus

const (
	TurnQueued            = sessionevent.TurnQueued
	TurnActive            = sessionevent.TurnActive
	TurnNeedsConfirmation = sessionevent.TurnNeedsConfirmation
	TurnCompleted         = sessionevent.TurnCompleted
	TurnFailed            = sessionevent.TurnFailed
	TurnAborted           = sessionevent.TurnAborted
)

type Turn struct {
	ID            string
	TenantID      string
	SubjectID     string
	SessionID     string
	RequestDigest string
	Status        TurnStatus
}

type CreateTurnRequest struct {
	Principal      Principal
	SessionID      string
	IdempotencyKey string
	Messages       []Message
}

type CreateTurnResult struct {
	Turn         Turn
	Deduplicated bool
}

type EventType = sessionevent.EventType

const (
	EventTurnAccepted          = sessionevent.EventTurnAccepted
	EventModelEffectPrepared   = sessionevent.EventModelEffectPrepared
	EventModelSettled          = sessionevent.EventModelSettled
	EventToolEffectPrepared    = sessionevent.EventToolEffectPrepared
	EventToolExternallyCommit  = sessionevent.EventToolExternallyCommit
	EventToolSettled           = sessionevent.EventToolSettled
	EventTurnNeedsConfirmation = sessionevent.EventTurnNeedsConfirmation
	EventTurnCompleted         = sessionevent.EventTurnCompleted
	EventTurnFailed            = sessionevent.EventTurnFailed
	EventTurnAborted           = sessionevent.EventTurnAborted
	EventModelDelta            = sessionevent.EventModelDelta
	EventToolStdout            = sessionevent.EventToolStdout
	EventToolStderr            = sessionevent.EventToolStderr
	EventToolLeaseWaiting      = sessionevent.EventToolLeaseWaiting
)

type EventAuthority struct {
	Scope                   authority.Scope
	Credential              authority.TurnAuthority
	PlacementGeneration     uint64
	AuthorizationGeneration uint64
}

type AppendDurableEventRequest struct {
	Authority        EventAuthority
	CommandID        string
	ExpectedSequence uint64
	Type             EventType
	Payload          []byte
	TurnStatus       TurnStatus
}

type EphemeralEventRequest struct {
	Authority EventAuthority
	Type      EventType
	Payload   []byte
}

type Event struct {
	Sequence uint64
	TurnID   string
	Type     EventType
	Payload  string
	Durable  bool
}

type SessionSnapshot struct {
	SessionID           string
	ActiveTurnID        string
	TurnStatus          TurnStatus
	LastDurableSequence uint64
}

type ReplayEventsRequest struct {
	Principal     Principal
	SessionID     string
	AfterSequence uint64
	Limit         int
}

type EventReplay struct {
	Snapshot SessionSnapshot
	Events   []Event
}

type EventSubscription interface {
	Events() <-chan Event
	Close()
}

// EventStream is opened atomically with its durable replay. When CaughtUp is
// false, Subscription is nil and the caller reconnects from the final replayed
// sequence. When true, every later durable event is either delivered in order
// or the subscription is closed so the cursor can recover it.
type EventStream struct {
	Replay       EventReplay
	CaughtUp     bool
	Subscription EventSubscription
}

type SessionRegistration struct {
	TenantID                string
	SubjectID               string
	SessionID               string
	RuntimeRevision         string
	WorkspaceID             string
	PlacementGeneration     uint64
	AuthorizationGeneration uint64
}

type CreateTurnCommand struct {
	TenantID      string
	SubjectID     string
	SessionID     string
	KeyDigest     string
	RequestDigest string
	ProposedTurn  Turn
	Authorization AuthorizationPermit
}

type AppendEventCommand struct {
	Authority        EventAuthority
	CommandID        string
	CommandDigest    string
	ExpectedSequence uint64
	Type             EventType
	Payload          string
	TurnStatus       TurnStatus
}

type ReplayQuery struct {
	TenantID      string
	SubjectID     string
	SessionID     string
	AfterSequence uint64
	Limit         int
	Authorization AuthorizationPermit
}

type Repository interface {
	Durability() RepositoryDurability
	CreateTurn(context.Context, CreateTurnCommand) (Turn, bool, error)
	AppendDurableEvent(context.Context, AppendEventCommand) (Event, bool, error)
	PublishEphemeralEvent(context.Context, EventAuthority, Event) error
	ReplayEvents(context.Context, ReplayQuery) (EventReplay, error)
	OpenEventStream(context.Context, ReplayQuery) (EventStream, error)
}

type RepositoryDurability struct {
	CrashDurable             bool
	AtomicIdempotency        bool
	AtomicEventSequence      bool
	AtomicReplaySubscribe    bool
	AtomicAuthorizationFence bool
}

type Config struct {
	Store                Repository
	Authorizer           Authorizer
	EventAuthorizer      EventAuthorizer
	IdempotencySecret    []byte
	MaximumMessageBytes  int
	MaximumEventBytes    int
	MaximumReplayEvents  int
	NewTurnID            func() (string, error)
	AllowReferenceMemory bool
}

type TurnAdmissionValidator interface {
	ValidateAdmission(
		context.Context,
		authority.TurnAuthority,
		authority.ServiceBinding,
		authority.AdmissionRequest,
	) error
}
