// Package sessionevent defines the narrow read-only Session event contract
// shared by the production state bootstrap and the public API. It deliberately
// contains no repository or reference-memory implementation.
package sessionevent

import (
	"context"
	"errors"

	"github.com/hancomac/circulusd/internal/dependency"
)

var (
	ErrInvalidConfig     = errors.New("platform api: invalid configuration")
	ErrInvalidRequest    = errors.New("platform api: invalid request")
	ErrAccessDenied      = errors.New("platform api: access denied")
	ErrSessionNotFound   = errors.New("platform api: session not found")
	ErrInvalidCursor     = errors.New("platform api: invalid durable event cursor")
	ErrStaleAuthority    = errors.New("platform api: stale event authority")
	ErrRepositoryFailure = errors.New("platform api: repository failure")
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
// compare its current generation inside the protected read or mutation.
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

type TurnStatus string

const (
	TurnQueued            TurnStatus = "queued"
	TurnActive            TurnStatus = "active"
	TurnNeedsConfirmation TurnStatus = "needs_confirmation"
	TurnCompleted         TurnStatus = "completed"
	TurnFailed            TurnStatus = "failed"
	TurnAborted           TurnStatus = "aborted"
)

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

type SessionEffectService string

const (
	SessionEffectModel        SessionEffectService = "model"
	SessionEffectWorkspace    SessionEffectService = "workspace"
	SessionEffectExecutor     SessionEffectService = "executor"
	SessionEffectMCP          SessionEffectService = "mcp"
	SessionEffectArtifact     SessionEffectService = "artifact"
	SessionEffectExternalTool SessionEffectService = "external-tool"
)

type SessionSettlementKind string

const (
	SessionSettlementSuccess            SessionSettlementKind = "success"
	SessionSettlementError              SessionSettlementKind = "error"
	SessionSettlementInterruptedUnknown SessionSettlementKind = "interrupted_unknown"
	SessionSettlementAbandoned          SessionSettlementKind = "abandoned"
)

// SessionEventPageReader is deliberately read-only. Its production challenge
// must be served by the same concrete reader that handles operational reads.
type SessionEventPageReader interface {
	dependency.ProductionProbe
	ReadSessionEventPage(context.Context, AuthorizedSessionEventPageRequest) (SessionPublicEventPage, error)
}

type AuthorizedSessionEventPageRequest struct {
	Authorization AuthorizationPermit
	SessionID     string
	AfterSequence uint64
	Limit         int
}

type SessionPublicEvent struct {
	Sequence         uint64                `json:"sequence"`
	Type             EventType             `json:"type"`
	TurnID           string                `json:"turnId"`
	TurnSequence     uint64                `json:"turnSequence"`
	Status           TurnStatus            `json:"status,omitempty"`
	EffectID         string                `json:"effectId,omitempty"`
	InvocationID     string                `json:"invocationId,omitempty"`
	Service          SessionEffectService  `json:"service,omitempty"`
	Operation        string                `json:"operation,omitempty"`
	ExternalCommitID string                `json:"externalCommitId,omitempty"`
	ResultRef        string                `json:"resultRef,omitempty"`
	SettlementKind   SessionSettlementKind `json:"settlementKind,omitempty"`
}

type SessionPublicEventSnapshot struct {
	SessionID         string      `json:"sessionId"`
	ActiveTurnID      *string     `json:"activeTurnId"`
	TurnStatus        *TurnStatus `json:"turnStatus"`
	LastEventSequence uint64      `json:"lastEventSequence"`
}

type SessionPublicEventPage struct {
	Snapshot SessionPublicEventSnapshot `json:"snapshot"`
	Events   []SessionPublicEvent       `json:"events"`
}
