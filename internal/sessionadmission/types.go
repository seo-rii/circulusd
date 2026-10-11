// Package sessionadmission defines the narrow durable Session admission
// contract shared by production state adapters and the public API. It contains
// no repository or reference-memory implementation.
package sessionadmission

import (
	"context"
	"errors"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/dependency"
	"github.com/hancomac/circulusd/internal/sessionevent"
)

var (
	ErrInvalidConfig        = sessionevent.ErrInvalidConfig
	ErrInvalidRequest       = sessionevent.ErrInvalidRequest
	ErrAccessDenied         = sessionevent.ErrAccessDenied
	ErrSessionNotFound      = sessionevent.ErrSessionNotFound
	ErrTurnNotFound         = errors.New("platform api: turn not found")
	ErrInvalidTransition    = errors.New("platform api: invalid turn transition")
	ErrStaleAuthority       = sessionevent.ErrStaleAuthority
	ErrRepositoryFailure    = sessionevent.ErrRepositoryFailure
	ErrIdempotencyConflict  = errors.New("platform api: idempotency conflict")
	ErrSequenceConflict     = errors.New("platform api: durable event sequence conflict")
	ErrRepositoryNotDurable = errors.New("platform api: repository is not crash durable")
)

type Operation = sessionevent.Operation

const OperationCreateTurn = sessionevent.OperationCreateTurn

type Principal = sessionevent.Principal
type OpaqueAuthorizationProof = sessionevent.OpaqueAuthorizationProof
type AuthorizationPermit = sessionevent.AuthorizationPermit

// Message is a single ordered public user input.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type Turn struct {
	ID            string
	TenantID      string
	SubjectID     string
	SessionID     string
	RequestDigest string
	Status        sessionevent.TurnStatus
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

// SessionTurnAdmission carries the full normalized input to the same Session
// authority that owns admission receipts and public events. Runtime,
// checkpoint and lease fields come from trusted preparation, never public JSON.
type SessionTurnAdmission struct {
	Authorization  AuthorizationPermit
	ProposedTurnID string
	KeyDigest      string
	RequestDigest  string
	Input          canonical.Value
	InputDigest    string
}

type SessionTurnAdmissionResult struct {
	TurnID       string
	TurnSequence uint64
	Activated    bool
	Deduplicated bool
}

type SessionTurnStore interface {
	dependency.ProductionProbe
	AdmitTurn(context.Context, SessionTurnAdmission) (SessionTurnAdmissionResult, error)
}
