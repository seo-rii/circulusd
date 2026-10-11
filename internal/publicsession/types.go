// Package publicsession implements authenticated Session turn admission and
// durable event replay using qualified operational sources. It contains no
// repository or reference-memory implementation.
package publicsession

import (
	"github.com/hancomac/circulusd/internal/sessionadmission"
	"github.com/hancomac/circulusd/internal/sessionevent"
)

var (
	ErrInvalidConfig        = sessionevent.ErrInvalidConfig
	ErrInvalidRequest       = sessionevent.ErrInvalidRequest
	ErrAccessDenied         = sessionevent.ErrAccessDenied
	ErrSessionNotFound      = sessionevent.ErrSessionNotFound
	ErrTurnNotFound         = sessionadmission.ErrTurnNotFound
	ErrIdempotencyConflict  = sessionadmission.ErrIdempotencyConflict
	ErrSequenceConflict     = sessionadmission.ErrSequenceConflict
	ErrInvalidCursor        = sessionevent.ErrInvalidCursor
	ErrStaleAuthority       = sessionevent.ErrStaleAuthority
	ErrInvalidTransition    = sessionadmission.ErrInvalidTransition
	ErrRepositoryFailure    = sessionevent.ErrRepositoryFailure
	ErrRepositoryNotDurable = sessionadmission.ErrRepositoryNotDurable
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

type Message = sessionadmission.Message
type Turn = sessionadmission.Turn
type CreateTurnRequest = sessionadmission.CreateTurnRequest
type CreateTurnResult = sessionadmission.CreateTurnResult

type TurnStatus = sessionevent.TurnStatus

const (
	TurnQueued            = sessionevent.TurnQueued
	TurnActive            = sessionevent.TurnActive
	TurnNeedsConfirmation = sessionevent.TurnNeedsConfirmation
	TurnCompleted         = sessionevent.TurnCompleted
	TurnFailed            = sessionevent.TurnFailed
	TurnAborted           = sessionevent.TurnAborted
)

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
)
