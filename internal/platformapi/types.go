// Package platformapi implements the authenticated public turn API and its
// durable event replay boundary. Durable repositories must preserve the same
// atomic idempotency, sequence, and generation-fencing contracts as the
// race-safe memory reference adapter.
package platformapi

import (
	"context"
	"errors"

	"github.com/hancomac/circulusd/internal/authority"
)

var (
	ErrInvalidConfig        = errors.New("platform api: invalid configuration")
	ErrInvalidRequest       = errors.New("platform api: invalid request")
	ErrAccessDenied         = errors.New("platform api: access denied")
	ErrSessionNotFound      = errors.New("platform api: session not found")
	ErrTurnNotFound         = errors.New("platform api: turn not found")
	ErrIdempotencyConflict  = errors.New("platform api: idempotency conflict")
	ErrSequenceConflict     = errors.New("platform api: durable event sequence conflict")
	ErrInvalidCursor        = errors.New("platform api: invalid durable event cursor")
	ErrStaleAuthority       = errors.New("platform api: stale event authority")
	ErrInvalidTransition    = errors.New("platform api: invalid turn transition")
	ErrRepositoryFailure    = errors.New("platform api: repository failure")
	ErrRepositoryNotDurable = errors.New("platform api: repository is not crash durable")
)

type Operation string

const (
	OperationCreateTurn Operation = "create-turn"
	OperationReadEvents Operation = "read-events"
)

type Principal struct {
	TenantID  string
	SubjectID string
}

type AuthorizationRequest struct {
	Operation Operation
	Principal Principal
	SessionID string
}

type OpaqueAuthorizationProof [32]byte

func (OpaqueAuthorizationProof) String() string   { return "api-authorization<redacted>" }
func (OpaqueAuthorizationProof) GoString() string { return "api-authorization<redacted>" }

// AuthorizationPermit is trusted output from Authorizer. Repository adapters
// compare its current generation inside the same transaction as the protected
// read or mutation, closing revocation races after the initial policy check.
type AuthorizationPermit struct {
	Operation               Operation
	Principal               Principal
	SessionID               string
	AuthorizationGeneration uint64
	Proof                   OpaqueAuthorizationProof
}

type Authorizer interface {
	Authorize(context.Context, AuthorizationRequest) (AuthorizationPermit, error)
}

// EventAuthorizer verifies fresh Session authority before any repository
// lookup. EventAuthority fields are comparison targets, not credentials.
type EventAuthorizer interface {
	AuthorizeEvent(context.Context, EventAuthority) error
}

type Message struct {
	Role    string
	Content string
}

type TurnStatus string

const (
	TurnQueued            TurnStatus = "queued"
	TurnActive            TurnStatus = "active"
	TurnNeedsConfirmation TurnStatus = "needs_confirmation"
	TurnCompleted         TurnStatus = "completed"
	TurnFailed            TurnStatus = "failed"
	TurnAborted           TurnStatus = "aborted"
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

type EventType string

const (
	EventTurnAccepted          EventType = "turn.accepted"
	EventModelEffectPrepared   EventType = "model.effect.prepared"
	EventModelSettled          EventType = "model.settled"
	EventToolEffectPrepared    EventType = "tool.effect.prepared"
	EventToolExternallyCommit  EventType = "tool.externally_committed"
	EventToolSettled           EventType = "tool.settled"
	EventTurnNeedsConfirmation EventType = "turn.needs_confirmation"
	EventTurnCompleted         EventType = "turn.completed"
	EventTurnFailed            EventType = "turn.failed"
	EventTurnAborted           EventType = "turn.aborted"
	EventModelDelta            EventType = "model.delta"
	EventToolStdout            EventType = "tool.stdout"
	EventToolStderr            EventType = "tool.stderr"
	EventToolLeaseWaiting      EventType = "tool.lease.waiting"
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
