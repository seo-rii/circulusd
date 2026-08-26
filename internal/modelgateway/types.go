// Package modelgateway defines the provider-neutral admission and effect state
// machine for model calls. Durable ownership and compare-and-swap remain the
// responsibility of the Session state plane; Effect.Revision is the fencing
// value that a durable adapter must compare atomically.
package modelgateway

import (
	"context"
	"errors"

	"github.com/hancomac/circulusd/internal/identity"
)

var (
	ErrInvalidConfiguration        = errors.New("model gateway: invalid configuration")
	ErrInvalidRequest              = errors.New("model gateway: invalid request")
	ErrInputLimit                  = errors.New("model gateway: input limit exceeded")
	ErrModelNotAllowed             = errors.New("model gateway: model is not allowed")
	ErrTokenLimit                  = errors.New("model gateway: token limit exceeded")
	ErrQuotaExceeded               = errors.New("model gateway: quota exceeded")
	ErrQuotaMismatch               = errors.New("model gateway: quota permit mismatch")
	ErrQuotaConflict               = errors.New("model gateway: quota invocation conflict")
	ErrProviderUnavailable         = errors.New("model gateway: provider unavailable")
	ErrStaleAuthority              = errors.New("model gateway: stale authority")
	ErrAuthorityMismatch           = errors.New("model gateway: authority scope mismatch")
	ErrInvalidTransition           = errors.New("model gateway: invalid state transition")
	ErrConcurrentTransition        = errors.New("model gateway: stale effect revision")
	ErrDispatchNotDurable          = errors.New("model gateway: dispatch claim is not durable")
	ErrDurableRetrievalUnavailable = errors.New("model gateway: durable provider retrieval unavailable")
	ErrEventLimit                  = errors.New("model gateway: provider event limit exceeded")
	ErrSettlementNotReady          = errors.New("model gateway: effect is not ready for settlement")
	ErrStateDependenciesNotDurable = errors.New("model gateway: state dependencies do not satisfy the durability contract")
)

type Digest [32]byte

// OpaqueAuthority is only passed to a trusted validator. Its formatting
// methods intentionally never reveal credential bytes.
type OpaqueAuthority []byte

func (OpaqueAuthority) String() string   { return "model-authority<redacted>" }
func (OpaqueAuthority) GoString() string { return "model-authority<redacted>" }

type Generations struct {
	TurnLease uint64
	Placement uint64
	Policy    uint64
}

// ValidatedAuthority is trusted output from AuthorityValidator. Tenant and
// user are never accepted directly in AdmissionRequest.
type ValidatedAuthority struct {
	TenantID        identity.ID
	UserID          identity.ID
	SessionID       identity.ID
	TurnID          identity.ID
	EffectID        identity.ID
	InvocationID    identity.ID
	RuntimeRevision identity.ID
	Generations     Generations
}

type AdmissionAuthorityRequest struct {
	EffectID      identity.ID
	InvocationID  identity.ID
	RequestDigest Digest
	Permission    string
}

type SettlementAuthorityRequest struct {
	TenantID          identity.ID
	UserID            identity.ID
	SessionID         identity.ID
	TurnID            identity.ID
	EffectID          identity.ID
	InvocationID      identity.ID
	RuntimeRevision   identity.ID
	Generations       Generations
	RequestDigest     Digest
	ProviderRequestID string
	Attempt           uint32
	EffectRevision    uint64
	State             State
	Outcome           Outcome
	Usage             Usage
	TerminalDigest    Digest
}

type AuthorityDurability struct {
	CrashDurable             bool
	CurrentGenerationFencing bool
	ReferenceMemory          bool
}

// AuthorityValidator must validate current turn, placement, policy and
// runtime fencing. Admission validation also owns TTL enforcement; settlement
// validation follows current generations and exact effect identity instead of
// the original admission TTL (SPEC.md section 29.7).
type AuthorityValidator interface {
	Durability() AuthorityDurability
	ValidateAdmission(context.Context, OpaqueAuthority, AdmissionAuthorityRequest) (ValidatedAuthority, error)
	ValidateSettlement(context.Context, OpaqueAuthority, SettlementAuthorityRequest) (ValidatedAuthority, error)
}

type Role string

const (
	RoleSystem    Role = "system"
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	RoleTool      Role = "tool"
)

type Message struct {
	Role    Role
	Content string
}

type ModelRequest struct {
	Model           string
	Messages        []Message
	MaxOutputTokens uint64
	Reasoning       ReasoningOptions
}

type ReasoningEffort string

const (
	ReasoningEffortDefault  ReasoningEffort = "default"
	ReasoningEffortDisabled ReasoningEffort = "disabled"
	ReasoningEffortLow      ReasoningEffort = "low"
	ReasoningEffortMedium   ReasoningEffort = "medium"
	ReasoningEffortHigh     ReasoningEffort = "high"
)

// ReasoningOptions is the provider-neutral reasoning vocabulary. Provider
// adapters map this normalized effort to their endpoint-specific parameters.
type ReasoningOptions struct {
	Effort ReasoningEffort
}

type Bounds struct {
	MaxAuthorityBytes         uint64
	MaxMessages               uint32
	MaxMessageBytes           uint64
	MaxInputBytes             uint64
	MaxModelBytes             uint64
	MaxProviderIDBytes        uint64
	MaxProviderRequestIDBytes uint64
	MaxEventBytes             uint64
	MaxEvents                 uint32
	MaxStreamBytes            uint64
	MaxResponseBytes          uint64
	MaxReasonBytes            uint64
}

type ModelGrant struct {
	TenantID              identity.ID
	UserID                identity.ID
	Model                 string
	ProviderID            string
	MaxContextTokens      uint64
	MaxOutputTokens       uint64
	MaxTotalTokens        uint64
	MaxPreDispatchRetries uint32
}

type Configuration struct {
	Bounds Bounds
	Grants []ModelGrant

	// AllowReferenceMemory is restricted to explicitly selected in-process
	// reference deployments and tests. Production construction fails closed.
	AllowReferenceMemory bool
}

type TokenCountRequest struct {
	Model    string
	Messages []Message
}

// TokenCounter is provider/model aware. Admission fails closed when a model's
// context cannot be counted.
type TokenCounter interface {
	Count(context.Context, TokenCountRequest) (uint64, error)
}

type QuotaRequest struct {
	TenantID        identity.ID
	UserID          identity.ID
	SessionID       identity.ID
	TurnID          identity.ID
	EffectID        identity.ID
	InvocationID    identity.ID
	RuntimeRevision identity.ID
	Generations     Generations
	RequestDigest   Digest
	ContextTokens   uint64
	OutputTokens    uint64
}

// QuotaPermit represents an authoritative, atomic quota admission/reservation.
// Implementations must reject without leaving a partial reservation.
type QuotaPermit struct {
	ReservationID   string
	Durable         bool
	TenantID        identity.ID
	UserID          identity.ID
	EffectID        identity.ID
	InvocationID    identity.ID
	SessionID       identity.ID
	TurnID          identity.ID
	RuntimeRevision identity.ID
	Generations     Generations
	RequestDigest   Digest
	ContextTokens   uint64
	OutputTokens    uint64
}

func (QuotaPermit) String() string   { return "model-quota-permit<redacted>" }
func (QuotaPermit) GoString() string { return "model-quota-permit<redacted>" }

type QuotaDurability struct {
	CrashDurable                bool
	AtomicReservationSettlement bool
	ReferenceMemory             bool
}

type QuotaAdmitter interface {
	Durability() QuotaDurability
	// Admit MUST be idempotent for the exact effect/invocation/request digest.
	// Reuse of an invocation with different input must return ErrQuotaConflict
	// without adding another reservation.
	Admit(context.Context, QuotaRequest) (QuotaPermit, error)
	// Settle MUST durably and idempotently consume, release, or hold the exact
	// reservation. Exact terminal replays return the current immutable receipt,
	// including its original Authorization, even when the caller has since renewed
	// its authority generations. Conflicting terminal data returns
	// ErrQuotaConflict. The sole permitted update is Hold to a refreshed
	// Hold, Consume, or Release when Recovery is a fresh durable ResumePermit
	// bound to the same effect and Authorization proves the recovered terminal
	// CAS, or when Resolution is the durable single-winner decision of a freshly
	// authorized user/operator. A refreshed Hold replaces the old
	// recovery/authorization binding so a later recovery cannot settle against a
	// superseded observation.
	Settle(context.Context, QuotaSettlementRequest) (QuotaSettlementReceipt, error)
}

type QuotaDisposition string

const (
	QuotaDispositionConsume QuotaDisposition = "consume"
	QuotaDispositionRelease QuotaDisposition = "release"
	QuotaDispositionHold    QuotaDisposition = "hold"
)

type QuotaSettlementRequest struct {
	Permit            QuotaPermit
	Authorization     SettlementPermit
	Recovery          ResumePermit
	Resolution        UncertainResolutionPermit
	Outcome           Outcome
	Disposition       QuotaDisposition
	Usage             Usage
	ProviderRequestID string
	Attempt           uint32
}

type QuotaSettlementReceipt struct {
	ReservationID     string
	EffectID          identity.ID
	InvocationID      identity.ID
	RequestDigest     Digest
	Outcome           Outcome
	Disposition       QuotaDisposition
	Usage             Usage
	ProviderRequestID string
	Attempt           uint32
	Durable           bool
	Authorization     SettlementPermit
	Recovery          ResumePermit
	Resolution        UncertainResolutionPermit
}

func (QuotaSettlementReceipt) String() string   { return "model-quota-settlement<redacted>" }
func (QuotaSettlementReceipt) GoString() string { return "model-quota-settlement<redacted>" }

type Dependencies struct {
	Authority    AuthorityValidator
	TokenCounter TokenCounter
	Quota        QuotaAdmitter
	Dispatches   DispatchCoordinator
	Providers    map[string]Provider
}

type AdmissionRequest struct {
	Authority     OpaqueAuthority
	EffectID      identity.ID
	InvocationID  identity.ID
	RequestDigest Digest
	Request       ModelRequest
}

type State string

const (
	StateAdmitted            State = "admitted"
	StateDispatching         State = "dispatching"
	StateRetryPending        State = "retry_pending"
	StateDispatched          State = "dispatched"
	StateStreaming           State = "streaming"
	StateCancellationPending State = "cancellation_pending"
	StateCompleted           State = "completed"
	StateFailed              State = "failed"
	StateCancelled           State = "cancelled"
	StateUncertain           State = "uncertain"
)

type Outcome string

const (
	OutcomeCompleted Outcome = "completed"
	OutcomeFailed    Outcome = "failed"
	OutcomeCancelled Outcome = "cancelled"
	OutcomeUncertain Outcome = "uncertain"
)

type Usage struct {
	InputTokens  uint64
	OutputTokens uint64
}

type FinishReason string

const (
	FinishReasonStop          FinishReason = "stop"
	FinishReasonLength        FinishReason = "length"
	FinishReasonToolCalls     FinishReason = "tool_calls"
	FinishReasonContentFilter FinishReason = "content_filter"
	FinishReasonCancelled     FinishReason = "cancelled"
	FinishReasonOther         FinishReason = "other"
)

// ToolCallOrder carries provider-declared order when the provider format has
// one. When Declared is false, Index must be zero and the gateway applies its
// stable provider-neutral fallback ordering.
type ToolCallOrder struct {
	Declared bool
	Index    uint32
}

type ToolCall struct {
	ID        string
	Name      string
	Arguments CanonicalToolArguments
	Order     ToolCallOrder
}

type ModelResponse struct {
	Text         string
	FinishReason FinishReason
	// Usage is authoritative quota accounting after gateway normalization. The
	// provider's untrusted counters may prove an over-limit response, but cannot
	// reduce this value below the admitted reservation.
	Usage     Usage
	ToolCalls []ToolCall
}

// Effect is an immutable-by-contract snapshot. Apply returns a defensive copy
// and never mutates its input. A durable adapter must CAS Revision when storing
// the returned snapshot.
type Effect struct {
	Scope                   ValidatedAuthority
	RequestDigest           Digest
	Request                 ModelRequest
	ProviderID              string
	QuotaPermit             QuotaPermit
	ContextTokens           uint64
	RequestedOutputTokens   uint64
	MaxContextTokens        uint64
	MaxTotalTokens          uint64
	MaxPreDispatchRetries   uint32
	DurableRequestRetrieval bool
	State                   State
	Outcome                 Outcome
	Revision                uint64
	Attempt                 uint32
	EventCount              uint32
	EventBytes              uint64
	StreamBytes             uint64
	ProviderRequestID       string
	PartialOutput           bool
	FailureReason           string
	Response                *ModelResponse
	CancellationPermit      CancellationPermit
	RecoveryPermit          ResumePermit
}

type FailureClass string

const (
	FailurePreDispatch      FailureClass = "pre_dispatch"
	FailureProviderRejected FailureClass = "provider_rejected"
	FailureTransportUnknown FailureClass = "transport_unknown"
	FailureAfterPartial     FailureClass = "after_partial"
)

type EventKind string

const (
	EventBeginDispatch        EventKind = "begin_dispatch"
	EventProviderAccepted     EventKind = "provider_accepted"
	EventDelta                EventKind = "delta"
	EventResponseCompleted    EventKind = "response_completed"
	EventDispatchFailed       EventKind = "dispatch_failed"
	EventCancelRequested      EventKind = "cancel_requested"
	EventCancellationResolved EventKind = "cancellation_resolved"
)

type Event struct {
	ExpectedRevision  uint64
	Kind              EventKind
	ProviderRequestID string
	Delta             string
	Response          *ModelResponse
	Failure           FailureClass
	Reason            string
	DispatchPrevented bool
	Cancellation      CancellationPermit
	Recovery          ResumePermit
}

type DispatchCommand struct {
	ProviderID    string
	Scope         ValidatedAuthority
	EffectID      identity.ID
	InvocationID  identity.ID
	RequestDigest Digest
	QuotaPermit   QuotaPermit
	Request       ModelRequest
	Attempt       uint32
	Permit        DispatchPermit
}

// OpaqueDispatchPermit is a provider-visible proof that the current effect
// revision and dispatch attempt were durably claimed before provider I/O.
// Its formatting methods intentionally never reveal proof bytes.
type OpaqueDispatchPermit [32]byte

func (OpaqueDispatchPermit) String() string   { return "model-dispatch-permit<redacted>" }
func (OpaqueDispatchPermit) GoString() string { return "model-dispatch-permit<redacted>" }

type DispatchPermit struct {
	Proof          OpaqueDispatchPermit
	Durable        bool
	Scope          ValidatedAuthority
	EffectID       identity.ID
	InvocationID   identity.ID
	RequestDigest  Digest
	ProviderID     string
	Attempt        uint32
	EffectRevision uint64
}

func (DispatchPermit) String() string   { return "model-dispatch-permit<redacted>" }
func (DispatchPermit) GoString() string { return "model-dispatch-permit<redacted>" }

type DispatchCommitRequest struct {
	ExpectedRevision uint64
	CurrentScope     ValidatedAuthority
	Effect           Effect
	Command          DispatchCommand
}

type DispatchDurability struct {
	CrashDurable            bool
	AtomicEffectTransitions bool
	ExclusiveDispatchClaim  bool
	ReferenceMemory         bool
}

// DispatchCoordinator is the durable executor boundary. CommitAndClaimDispatch
// MUST atomically compare ExpectedRevision, independently verify CurrentScope
// and its generations against current durable authority, persist Effect, and
// exclusively claim the provider/attempt tuple before returning a permit. A
// replay or competing claimant returns ErrConcurrentTransition and must not
// issue a new permit. CommitProviderAccepted MUST CAS ExpectedRevision and
// bind the provider request ID to the same permit before returning. Since that
// second write follows external I/O, implementations must supply their own
// finite timeout even when the passed context no longer carries cancellation.
// CommitAndClaimSettlement MUST validate every request's fresh CurrentScope.
// When the exact terminal digest was already committed, including before a
// crash and generation takeover, it returns the original immutable permit so
// quota receipt replay remains stable; the permit's CurrentScope therefore may
// carry an older generation than the separately validated request scope.
type DispatchCoordinator interface {
	Durability() DispatchDurability
	CommitAndClaimDispatch(context.Context, DispatchCommitRequest) (DispatchPermit, error)
	BeginProviderDispatch(context.Context, DispatchPermit) error
	CommitProviderAccepted(context.Context, ProviderAcceptedCommitRequest) error
	CommitAndClaimCancellation(context.Context, CancellationCommitRequest) (CancellationPermit, error)
	CommitAndClaimResume(context.Context, ResumeCommitRequest) (ResumePermit, error)
	CommitAndClaimSettlement(context.Context, SettlementCommitRequest) (SettlementPermit, error)
	CommitAndClaimUncertainResolution(context.Context, UncertainResolutionCommitRequest) (UncertainResolutionPermit, error)
}

type DispatchExecution struct {
	Permit  DispatchPermit
	Effect  Effect
	Stream  EventStream
	Failure *Event
}

type ProviderAcceptedCommitRequest struct {
	ExpectedRevision uint64
	Permit           DispatchPermit
	Effect           Effect
}

type CancelCommand struct {
	ProviderID        string
	Scope             ValidatedAuthority
	EffectID          identity.ID
	InvocationID      identity.ID
	RequestDigest     Digest
	ProviderRequestID string
	Attempt           uint32
	Permit            CancellationPermit
}

type OpaqueCancellationPermit [32]byte

func (OpaqueCancellationPermit) String() string   { return "model-cancellation-permit<redacted>" }
func (OpaqueCancellationPermit) GoString() string { return "model-cancellation-permit<redacted>" }

// CancellationPermit is durable proof of the cancellation/dispatch race's
// linearization result. DispatchPrevented may be true only when the coordinator
// atomically revoked an unstarted dispatch claim, causing BeginProviderDispatch
// for that claim to fail before provider I/O.
type CancellationPermit struct {
	Proof             OpaqueCancellationPermit
	Durable           bool
	CurrentScope      ValidatedAuthority
	EffectID          identity.ID
	InvocationID      identity.ID
	RequestDigest     Digest
	ProviderID        string
	ProviderRequestID string
	Attempt           uint32
	EffectRevision    uint64
	DispatchPrevented bool
}

func (CancellationPermit) String() string   { return "model-cancellation-permit<redacted>" }
func (CancellationPermit) GoString() string { return "model-cancellation-permit<redacted>" }

type CancellationCommitRequest struct {
	ExpectedRevision uint64
	CurrentScope     ValidatedAuthority
	Effect           Effect
	Command          CancelCommand
}

type CancellationExecution struct {
	Permit     CancellationPermit
	Effect     Effect
	Resolution Event
}

type OpaqueResumePermit [32]byte

func (OpaqueResumePermit) String() string   { return "model-resume-permit<redacted>" }
func (OpaqueResumePermit) GoString() string { return "model-resume-permit<redacted>" }

// ResumePermit binds one durable provider retrieval to the original effect and
// the fresh owner generations. A coordinator may rotate the proof after a
// takeover, but must never turn retrieval into a new inference.
type ResumePermit struct {
	Proof             OpaqueResumePermit
	Durable           bool
	OriginScope       ValidatedAuthority
	CurrentScope      ValidatedAuthority
	EffectID          identity.ID
	InvocationID      identity.ID
	RequestDigest     Digest
	ProviderID        string
	ProviderRequestID string
	Attempt           uint32
	EffectRevision    uint64
}

func (ResumePermit) String() string   { return "model-resume-permit<redacted>" }
func (ResumePermit) GoString() string { return "model-resume-permit<redacted>" }

type ResumeCommitRequest struct {
	CurrentScope ValidatedAuthority
	Effect       Effect
}

type OpaqueSettlementPermit [32]byte

func (OpaqueSettlementPermit) String() string   { return "model-settlement-permit<redacted>" }
func (OpaqueSettlementPermit) GoString() string { return "model-settlement-permit<redacted>" }

// SettlementPermit proves that the exact terminal snapshot won the durable
// effect CAS before quota is consumed, released, or moved out of hold.
type SettlementPermit struct {
	Proof          OpaqueSettlementPermit
	Durable        bool
	CurrentScope   ValidatedAuthority
	EffectID       identity.ID
	InvocationID   identity.ID
	RequestDigest  Digest
	EffectRevision uint64
	TerminalDigest Digest
	ReservationID  string
}

func (SettlementPermit) String() string   { return "model-settlement-permit<redacted>" }
func (SettlementPermit) GoString() string { return "model-settlement-permit<redacted>" }

type SettlementCommitRequest struct {
	ExpectedRevision uint64
	CurrentScope     ValidatedAuthority
	Effect           Effect
	TerminalDigest   Digest
}

type UncertainResolution string

const (
	UncertainResolutionConsume UncertainResolution = "consume"
	UncertainResolutionRelease UncertainResolution = "release"
)

type OpaqueUncertainResolutionPermit [32]byte

func (OpaqueUncertainResolutionPermit) String() string {
	return "model-uncertain-resolution-permit<redacted>"
}

func (OpaqueUncertainResolutionPermit) GoString() string {
	return "model-uncertain-resolution-permit<redacted>"
}

// UncertainResolutionPermit is the durable, single-winner user/operator
// decision for accounting an uncertain provider request. Exact replays return
// the original permit across generation takeover.
type UncertainResolutionPermit struct {
	Proof          OpaqueUncertainResolutionPermit
	Durable        bool
	CurrentScope   ValidatedAuthority
	EffectID       identity.ID
	InvocationID   identity.ID
	RequestDigest  Digest
	TerminalDigest Digest
	ReservationID  string
	Decision       UncertainResolution
}

func (UncertainResolutionPermit) String() string {
	return "model-uncertain-resolution-permit<redacted>"
}

func (UncertainResolutionPermit) GoString() string {
	return "model-uncertain-resolution-permit<redacted>"
}

type UncertainResolutionCommitRequest struct {
	CurrentScope   ValidatedAuthority
	Effect         Effect
	TerminalDigest Digest
	Decision       UncertainResolution
}

type Transition struct {
	Effect   Effect
	Dispatch *DispatchCommand
	Cancel   *CancelCommand
}

type Settlement struct {
	Scope             ValidatedAuthority
	RequestDigest     Digest
	Outcome           Outcome
	ProviderRequestID string
	Attempt           uint32
	PartialOutput     bool
	NeedsConfirmation bool
	FailureReason     string
	Response          *ModelResponse
	QuotaReceipt      QuotaSettlementReceipt
}
