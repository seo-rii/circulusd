// Package broker coordinates bounded engine steps and external effect
// boundaries. Durable session state remains owned by the injected DurableStore;
// this package deliberately does not maintain a second turn state machine.
package broker

import (
	"context"
	"errors"
	"time"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/identity"
)

var (
	ErrInvalidRequest      = errors.New("broker: invalid request")
	ErrAdmissionExpired    = errors.New("broker: new admission authority expired")
	ErrLeaseExpired        = errors.New("broker: turn lease expired")
	ErrStaleGeneration     = errors.New("broker: stale generation")
	ErrFenceMismatch       = errors.New("broker: identity fence mismatch")
	ErrEffectInFlight      = errors.New("broker: effect already in flight")
	ErrInvalidEffectState  = errors.New("broker: invalid effect state")
	ErrIdempotencyConflict = errors.New("broker: idempotency key reused with different input")
	ErrDurabilityBarrier   = errors.New("broker: durability barrier not confirmed")
	ErrLedgerUnavailable   = errors.New("broker: invocation ledger unavailable")
	ErrLedgerMismatch      = errors.New("broker: invocation ledger proof mismatch")
)

type Digest [32]byte

// OpaquePermit preserves the protocol's arbitrary bytes without imposing a
// local token format. String keeps receipts comparable for exact replay checks.
type OpaquePermit string

func (OpaquePermit) String() string { return "opaque-permit<redacted>" }

func (OpaquePermit) GoString() string { return "opaque-permit<redacted>" }

type Generations struct {
	TurnLease     uint64
	Placement     uint64
	Sandbox       uint64
	Authorization uint64
}

// ValidatedTurnFence is a trusted comparison envelope produced after an
// opaque authority validator succeeds. It is not itself a bearer credential;
// DurableStore must still compare it atomically with authoritative state.
type ValidatedTurnFence struct {
	TenantID    identity.ID
	SessionID   identity.ID
	TurnID      identity.ID
	Generations Generations
	ExpiresAt   time.Time
}

func (ValidatedTurnFence) String() string { return "validated-turn-authority<redacted>" }

func (ValidatedTurnFence) GoString() string { return "validated-turn-authority<redacted>" }

type EffectService string

const (
	ServiceModel        EffectService = "model"
	ServiceWorkspace    EffectService = "workspace"
	ServiceExecutor     EffectService = "executor"
	ServiceMCP          EffectService = "mcp"
	ServiceArtifact     EffectService = "artifact"
	ServiceExternalTool EffectService = "external-tool"
)

type ReplayPolicy string

const (
	ReplaySafe           ReplayPolicy = "safe"
	ReplayIdempotencyKey ReplayPolicy = "idempotency-key"
	ReplayNever          ReplayPolicy = "never"
	ReplayConfirm        ReplayPolicy = "confirm"
)

type EffectState string

const (
	EffectPrepared            EffectState = "prepared"
	EffectDispatched          EffectState = "dispatched"
	EffectExternallyCommitted EffectState = "externally_committed"
	EffectSettled             EffectState = "settled"
	EffectBlocked             EffectState = "blocked"
)

type EffectSnapshot struct {
	EffectID          identity.ID
	InvocationID      identity.ID
	RequestDigest     Digest
	Service           EffectService
	Operation         string
	ParentOperationID identity.ID
	Ordinal           uint64
	ReplayPolicy      ReplayPolicy
	State             EffectState
	DispatchAttempt   uint64
	Generations       Generations
	ExternalCommitID  identity.ID
	ResultRef         identity.ID
	PreparationPermit *EffectPreparationPermit
	LastDispatch      *DispatchMetadata
	Settlement        *v1.EffectRecord
}

type DispatchMetadata struct {
	DispatchAttempt   uint64
	Generations       Generations
	ProviderRequestID identity.ID
	Deadline          time.Time
}

type TurnSnapshot struct {
	TenantID             identity.ID
	UserID               identity.ID
	SessionID            identity.ID
	TurnID               identity.ID
	Active               bool
	AbortRequested       bool
	LeaseExpiresAt       time.Time
	Generations          Generations
	CheckpointDigest     Digest
	EventSequence        uint64
	EngineStepLimits     EngineStepBudget
	ActiveEffect         *EffectSnapshot
	Checkpoint           *v1.AgentCheckpoint
	UnconsumedSettlement *v1.EffectRecord
}

type EngineStepBudget struct {
	MaximumEvents         uint64
	MaximumEphemeralBytes uint64
	MaximumWallClock      time.Duration
}

type EngineStepRequest struct {
	Authority    ValidatedTurnFence
	Now          time.Time
	Budget       EngineStepBudget
	OperationKey string
}

type EngineStepPermit struct {
	Opaque                OpaquePermit
	TenantID              identity.ID
	UserID                identity.ID
	OperationKey          string
	SessionID             identity.ID
	TurnID                identity.ID
	Generations           Generations
	ExpectedEventSequence uint64
	CheckpointDigest      Digest
	Budget                EngineStepBudget
	Deadline              time.Time
	Durable               bool
	Checkpoint            *v1.AgentCheckpoint
	UnconsumedSettlement  *v1.EffectRecord
}

type BoundaryKind string

const (
	BoundaryCheckpoint    BoundaryKind = "checkpoint"
	BoundaryEffectRequest BoundaryKind = "effect_request"
	BoundaryTurnComplete  BoundaryKind = "turn_complete"
	BoundaryTurnError     BoundaryKind = "turn_error"
)

type EffectIntent struct {
	Service           EffectService
	Operation         string
	ReplayPolicy      ReplayPolicy
	RequestDigest     Digest
	Payload           []byte
	ParentOperationID identity.ID
	Ordinal           uint64
}

type EngineBoundary struct {
	Kind             BoundaryKind
	CheckpointDigest Digest
	Effect           *EffectIntent
	Message          *v1.EngineStepBoundary
}

type EngineStepCommit struct {
	Permit        EngineStepPermit
	Now           time.Time
	OperationKey  string
	RequestDigest Digest
	Boundary      EngineBoundary
}

type EngineStepReceipt struct {
	OperationKey      string
	EventSequence     uint64
	Durable           bool
	PreparedEffect    *v1.EffectRecord
	PreparationPermit *EffectPreparationPermit
}

// EffectPreparationPermit proves a durable effect preparation but cannot by
// itself authorize external I/O.
type EffectPreparationPermit struct {
	EffectKey
	Opaque            OpaquePermit
	TenantID          identity.ID
	UserID            identity.ID
	Service           EffectService
	Operation         string
	ParentOperationID identity.ID
	Ordinal           uint64
	ReplayPolicy      ReplayPolicy
	Generations       Generations
	DispatchAttempt   uint64
	Deadline          time.Time
	EventSequence     uint64
	Durable           bool
}

type EffectKey struct {
	SessionID     identity.ID
	TurnID        identity.ID
	EffectID      identity.ID
	InvocationID  identity.ID
	RequestDigest Digest
}

type DispatchRequest struct {
	Authority         ValidatedTurnFence
	Now               time.Time
	EffectID          identity.ID
	InvocationID      identity.ID
	RequestDigest     Digest
	Service           EffectService
	Operation         string
	OperationKey      string
	OperationDigest   Digest
	PreparationPermit EffectPreparationPermit
	ProviderRequestID identity.ID
	Deadline          time.Time
}

type DispatchPermit struct {
	EffectKey
	Opaque            OpaquePermit
	TenantID          identity.ID
	UserID            identity.ID
	Service           EffectService
	Operation         string
	ParentOperationID identity.ID
	Ordinal           uint64
	ReplayPolicy      ReplayPolicy
	Generations       Generations
	DispatchAttempt   uint64
	ProviderRequestID identity.ID
	Deadline          time.Time
	EventSequence     uint64
	Durable           bool
}

type SettlementRequest struct {
	Authority        ValidatedTurnFence
	Now              time.Time
	EffectID         identity.ID
	InvocationID     identity.ID
	RequestDigest    Digest
	DispatchAttempt  uint64
	ExternalCommitID identity.ID
	ResultRef        identity.ID
	Error            *v1.PublicError
	OperationKey     string
	SettlementDigest Digest
}

type SettlementReceipt struct {
	EffectKey
	State            EffectState
	DispatchAttempt  uint64
	ExternalCommitID identity.ID
	ResultRef        identity.ID
	Error            *v1.PublicError
	OperationDigest  Digest
	RecoveryKind     RecoverySettlementKind
	Effect           *v1.EffectRecord
	EventSequence    uint64
	Durable          bool
}

type ConfirmationRequest struct {
	Authority       ValidatedTurnFence
	Now             time.Time
	EffectID        identity.ID
	InvocationID    identity.ID
	RequestDigest   Digest
	DispatchAttempt uint64
	OperationKey    string
	OperationDigest Digest
}

type ConfirmationReceipt struct {
	EffectKey
	DispatchAttempt  uint64
	ExternalCommitID identity.ID
	ResultRef        identity.ID
	EventSequence    uint64
	Durable          bool
}

type LedgerStatus string

const (
	LedgerAbsent    LedgerStatus = "absent"
	LedgerInflight  LedgerStatus = "inflight"
	LedgerCommitted LedgerStatus = "committed"
	LedgerFailed    LedgerStatus = "failed"
	LedgerUnknown   LedgerStatus = "unknown"
)

type LedgerRecord struct {
	Status            LedgerStatus
	EffectID          identity.ID
	InvocationID      identity.ID
	RequestDigest     Digest
	Service           EffectService
	Operation         string
	DispatchAttempt   uint64
	ProviderRequestID identity.ID
	ExternalCommitID  identity.ID
	ResultRef         identity.ID
}

type LedgerLookup struct {
	EffectKey
	Service           EffectService
	Operation         string
	DispatchAttempt   uint64
	ProviderRequestID identity.ID
}

type InvocationLedger interface {
	Lookup(context.Context, LedgerLookup) (LedgerRecord, error)
}

type RecoveryAction string

const (
	RecoveryNone              RecoveryAction = "none"
	RecoveryDispatch          RecoveryAction = "dispatch"
	RecoveryReplay            RecoveryAction = "replay_same_invocation"
	RecoveryWaitExternal      RecoveryAction = "wait_external"
	RecoverySettleOnly        RecoveryAction = "settle_only"
	RecoverySettleFailed      RecoveryAction = "settle_failed"
	RecoverySettleInterrupted RecoveryAction = "settle_interrupted_unknown"
	RecoveryNeedsConfirmation RecoveryAction = "needs_confirmation"
	RecoveryAwaitConfirmation RecoveryAction = "await_confirmation"
)

type RecoveryRequest struct {
	Authority         ValidatedTurnFence
	Now               time.Time
	EffectID          identity.ID
	InvocationID      identity.ID
	RequestDigest     Digest
	OperationKey      string
	OperationDigest   Digest
	UserConfirmed     bool
	ProviderRequestID identity.ID
	Deadline          time.Time
	Reason            *v1.PublicError
}

type RecoveryDecision struct {
	Action            RecoveryAction
	EffectKey         EffectKey
	ReplayPolicy      ReplayPolicy
	DispatchAttempt   uint64
	ExternalCommitID  identity.ID
	ResultRef         identity.ID
	PreparationPermit *EffectPreparationPermit
	DispatchPermit    *DispatchPermit
	SettlementReceipt *SettlementReceipt
	BlockReceipt      *BlockReceipt
}

// DurableStore is the authoritative Session-state adapter. Every mutation is
// atomic, compares the supplied snapshot/fences, provides idempotency, and
// returns only after its durability barrier completes. Durable=false is a
// fail-closed signal used by adapters that cannot prove that contract.
type DurableStore interface {
	LookupOperation(context.Context, OperationLookup) (OperationReceipt, error)
	ReadTurn(context.Context, identity.ID) (TurnSnapshot, error)
	AcquireEngineStep(context.Context, AcquireStepCommand) (EngineStepPermit, error)
	CommitEngineStep(context.Context, CommitStepCommand) (EngineStepReceipt, error)
	MarkDispatched(context.Context, MarkDispatchedCommand) (DispatchPermit, error)
	MarkExternallyCommitted(context.Context, MarkExternalCommand) (ConfirmationReceipt, error)
	SettleEffect(context.Context, SettleCommand) (SettlementReceipt, error)
	BlockEffect(context.Context, BlockCommand) (BlockReceipt, error)
	PrepareRetry(context.Context, PrepareRetryCommand) (EffectPreparationPermit, error)
	SettleRecovery(context.Context, SettleRecoveryCommand) (SettlementReceipt, error)
}

type OperationKind string

const (
	OperationDispatch           OperationKind = "dispatch"
	OperationConfirmation       OperationKind = "confirmation"
	OperationSettlement         OperationKind = "settlement"
	OperationRecoverySettlement OperationKind = "recovery_settlement"
	OperationBlock              OperationKind = "block"
)

type OperationLookup struct {
	Kind            OperationKind
	OperationKey    string
	OperationDigest Digest
	SessionID       identity.ID
}

type OperationReceipt struct {
	Found           bool
	Kind            OperationKind
	OperationDigest Digest
	Dispatch        *DispatchPermit
	Confirmation    *ConfirmationReceipt
	Settlement      *SettlementReceipt
	Block           *BlockReceipt
}

type AcquireStepCommand struct {
	Snapshot     TurnSnapshot
	Now          time.Time
	Budget       EngineStepBudget
	OperationKey string
}

type CommitStepCommand struct {
	Snapshot      TurnSnapshot
	Permit        EngineStepPermit
	Now           time.Time
	OperationKey  string
	RequestDigest Digest
	Boundary      EngineBoundary
}

type MarkDispatchedCommand struct {
	Snapshot          TurnSnapshot
	Key               EffectKey
	Service           EffectService
	Operation         string
	OperationKey      string
	OperationDigest   Digest
	PreparationPermit EffectPreparationPermit
	ProviderRequestID identity.ID
	Now               time.Time
	Deadline          time.Time
}

type MarkExternalCommand struct {
	Snapshot        TurnSnapshot
	Key             EffectKey
	Record          LedgerRecord
	DispatchAttempt uint64
	OperationKey    string
	OperationDigest Digest
}

type SettleCommand struct {
	Snapshot         TurnSnapshot
	Key              EffectKey
	ExternalCommitID identity.ID
	ResultRef        identity.ID
	Error            *v1.PublicError
	DispatchAttempt  uint64
	OperationKey     string
	SettlementDigest Digest
}

type BlockCommand struct {
	Snapshot        TurnSnapshot
	Key             EffectKey
	OperationKey    string
	OperationDigest Digest
	Reason          *v1.PublicError
}

type BlockReceipt struct {
	EffectKey
	State           EffectState
	ReplayPolicy    ReplayPolicy
	DispatchAttempt uint64
	OperationDigest Digest
	Reason          *v1.PublicError
	EventSequence   uint64
	Durable         bool
}

type PrepareRetryCommand struct {
	Snapshot        TurnSnapshot
	Key             EffectKey
	OperationKey    string
	OperationDigest Digest
	Now             time.Time
	Deadline        time.Time
	UserConfirmed   bool
}

type RecoverySettlementKind string

const (
	RecoverySettlementFailed      RecoverySettlementKind = "failed"
	RecoverySettlementInterrupted RecoverySettlementKind = "interrupted_unknown"
)

type SettleRecoveryCommand struct {
	Snapshot        TurnSnapshot
	Key             EffectKey
	OperationKey    string
	OperationDigest Digest
	Kind            RecoverySettlementKind
	Error           *v1.PublicError
}
