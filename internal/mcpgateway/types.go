// Package mcpgateway defines the provider-neutral security, admission,
// dispatch, replay, and settlement boundary for MCP tool calls. It does not
// expose process handles, raw transports, or credential material to callers.
package mcpgateway

import (
	"context"
	"errors"
	"time"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/dependency"
	"github.com/hancomac/circulusd/internal/identity"
)

var (
	ErrInvalidConfiguration  = errors.New("mcp gateway: invalid configuration")
	ErrInvalidRequest        = errors.New("mcp gateway: invalid request")
	ErrInputLimit            = errors.New("mcp gateway: input limit exceeded")
	ErrOutputLimit           = errors.New("mcp gateway: output limit exceeded")
	ErrEventLimit            = errors.New("mcp gateway: event limit exceeded")
	ErrServerNotAllowed      = errors.New("mcp gateway: server is not allowed")
	ErrToolNotAllowed        = errors.New("mcp gateway: tool is not allowed")
	ErrReplayPolicyRequired  = errors.New("mcp gateway: side-effecting tool requires a replay policy")
	ErrProtocolMismatch      = errors.New("mcp gateway: protocol negotiation mismatch")
	ErrAffinityMismatch      = errors.New("mcp gateway: backend affinity mismatch")
	ErrCredentialUnavailable = errors.New("mcp gateway: credential broker unavailable")
	ErrCredentialMismatch    = errors.New("mcp gateway: credential binding mismatch")
	ErrProviderUnavailable   = errors.New("mcp gateway: provider unavailable")
	ErrStaleAuthority        = errors.New("mcp gateway: stale authority")
	ErrAuthorityMismatch     = errors.New("mcp gateway: authority scope mismatch")
	ErrAuthorizationMismatch = errors.New("mcp gateway: tool authorization permit mismatch")
	ErrInvocationConflict    = errors.New("mcp gateway: invocation reused with different request")
	ErrInvocationNotFound    = errors.New("mcp gateway: invocation not found")
	ErrEffectInFlight        = errors.New("mcp gateway: another effect is active for the turn")
	ErrInvalidTransition     = errors.New("mcp gateway: invalid state transition")
	ErrConcurrentTransition  = errors.New("mcp gateway: stale effect revision")
	ErrDispatchNotDurable    = errors.New("mcp gateway: dispatch claim is not durable")
	ErrStoreUnavailable      = errors.New("mcp gateway: durable store unavailable")
	ErrLedgerUnavailable     = errors.New("mcp gateway: invocation ledger unavailable")
	ErrLedgerMismatch        = errors.New("mcp gateway: invocation ledger mismatch")
	ErrNeedsConfirmation     = errors.New("mcp gateway: explicit confirmation required")
	ErrBackpressure          = errors.New("mcp gateway: output consumer rejected data")
	ErrAuditUnavailable      = errors.New("mcp gateway: audit sink unavailable")
	ErrServerRequestDenied   = errors.New("mcp gateway: server-initiated request denied")
)

type Digest [32]byte

// OpaqueAuthority is copied before it crosses the trusted validation
// boundary. Formatting never reveals its bearer bytes.
type OpaqueAuthority []byte

func (OpaqueAuthority) String() string   { return "mcp-authority<redacted>" }
func (OpaqueAuthority) GoString() string { return "mcp-authority<redacted>" }

type Generations struct {
	TurnLease uint64
	Placement uint64
	Policy    uint64
}

type ValidatedAuthority struct {
	TenantID        identity.ID
	UserID          identity.ID
	SessionID       identity.ID
	WorkspaceID     identity.ID
	TurnID          identity.ID
	EffectID        identity.ID
	InvocationID    identity.ID
	RuntimeRevision identity.ID
	Generations     Generations
}

func (ValidatedAuthority) String() string   { return "validated-mcp-authority<redacted>" }
func (ValidatedAuthority) GoString() string { return "validated-mcp-authority<redacted>" }

type AuthorityRequest struct {
	EffectID      identity.ID
	InvocationID  identity.ID
	RequestDigest Digest
	Permission    string
}

type CurrentAuthorityRequest struct {
	Scope                ValidatedAuthority
	RequestDigest        Digest
	ProviderRequestID    string
	ConnectionGeneration uint64
	Attempt              uint32
	Permission           string
}

// AuthorityValidator owns admission TTL and current turn/placement/policy
// fencing. ValidateCurrent intentionally validates current generations rather
// than the original admission token's wall-clock expiry.
type AuthorityValidator interface {
	ValidateAdmission(context.Context, OpaqueAuthority, AuthorityRequest) (ValidatedAuthority, error)
	ValidateCurrent(context.Context, OpaqueAuthority, CurrentAuthorityRequest) (ValidatedAuthority, error)
}

type ToolAuthorizationRequest struct {
	Scope         ValidatedAuthority
	ServerID      string
	ToolName      string
	RequestDigest Digest
	Permission    string
}

type ToolAuthorizationProof [32]byte

func (ToolAuthorizationProof) String() string   { return "mcp-tool-proof<redacted>" }
func (ToolAuthorizationProof) GoString() string { return "mcp-tool-proof<redacted>" }

// ToolAuthorizationPermit is a current, exact tenant/user/tool policy proof.
// A durable dispatch adapter must fence on the contained scope and policy
// generation before allowing provider I/O.
type ToolAuthorizationPermit struct {
	Proof         ToolAuthorizationProof
	Durable       bool
	Scope         ValidatedAuthority
	ServerID      string
	ToolName      string
	RequestDigest Digest
}

func (ToolAuthorizationPermit) String() string   { return "mcp-tool-permit<redacted>" }
func (ToolAuthorizationPermit) GoString() string { return "mcp-tool-permit<redacted>" }

type ToolAuthorizer interface {
	Authorize(context.Context, ToolAuthorizationRequest) (ToolAuthorizationPermit, error)
}

type Transport string

const (
	TransportStdio          Transport = "stdio"
	TransportStreamableHTTP Transport = "streamable-http"
)

type ScopeKind string

const (
	ScopeWorkspace  ScopeKind = "workspace"
	ScopeSession    ScopeKind = "session"
	ScopeInvocation ScopeKind = "invocation"
)

// BackendAffinity is the complete cache/placement identity that a long-lived
// stdio server is bound to. It is intentionally comparable so exact reuse
// checks cannot accidentally omit a component.
type BackendAffinity struct {
	Backend                string
	EnvironmentRevision    identity.ID
	Scope                  ScopeKind
	ScopeID                identity.ID
	ResourceProfileDigest  Digest
	NetworkPolicyDigest    Digest
	SecretExposureClass    string
	SandboxProtocolVersion string
}

type CredentialHandle struct{ value string }

func (CredentialHandle) String() string   { return "mcp-credential-handle<redacted>" }
func (CredentialHandle) GoString() string { return "mcp-credential-handle<redacted>" }

func (handle CredentialHandle) IsZero() bool { return handle.value == "" }

type CredentialBinding struct {
	Handle   CredentialHandle
	Audience string
}

type CredentialRequest struct {
	Handle    CredentialHandle
	TenantID  identity.ID
	UserID    identity.ID
	ServerID  string
	Audience  string
	TargetRef string
}

type CredentialProof [32]byte

func (CredentialProof) String() string   { return "mcp-credential-proof<redacted>" }
func (CredentialProof) GoString() string { return "mcp-credential-proof<redacted>" }

// CredentialPermit is an opaque redemption capability. No API in this
// package carries a raw token, password, or endpoint credential.
type CredentialPermit struct {
	Proof     CredentialProof
	Durable   bool
	Handle    CredentialHandle
	TenantID  identity.ID
	UserID    identity.ID
	ServerID  string
	Audience  string
	TargetRef string
}

func (CredentialPermit) String() string   { return "mcp-credential-permit<redacted>" }
func (CredentialPermit) GoString() string { return "mcp-credential-permit<redacted>" }

type CredentialBroker interface {
	Authorize(context.Context, CredentialRequest) (CredentialPermit, error)
}

type ReplayPolicy string

const (
	ReplaySafe           ReplayPolicy = "safe"
	ReplayIdempotencyKey ReplayPolicy = "idempotency-key"
	ReplayNever          ReplayPolicy = "never"
	ReplayConfirm        ReplayPolicy = "confirm"
)

type ServerRegistration struct {
	TenantID              identity.ID
	UserID                identity.ID
	ServerID              string
	ProviderID            string
	Transport             Transport
	TargetRef             string
	ProtocolVersion       string
	Affinity              BackendAffinity
	Credential            CredentialBinding
	AllowedServerRequests []ServerRequestMethod
}

type ToolRegistration struct {
	TenantID               identity.ID
	UserID                 identity.ID
	ServerID               string
	ToolName               string
	SideEffecting          bool
	ReplayPolicy           ReplayPolicy
	MaxAutomaticRetries    uint32
	MaxConfirmationRetries uint32
}

type Bounds struct {
	MaxAuthorityBytes         uint64
	MaxServerIDBytes          uint64
	MaxToolNameBytes          uint64
	MaxTargetRefBytes         uint64
	MaxProtocolVersionBytes   uint64
	MaxCredentialHandleBytes  uint64
	MaxAudienceBytes          uint64
	MaxInputBytes             uint64
	MaxInputDepth             int
	MaxProviderRequestIDBytes uint64
	MaxExternalCommitIDBytes  uint64
	MaxChunkBytes             uint64
	MaxChunks                 uint32
	MaxOutputBytes            uint64
	MaxFailureBytes           uint64
	MaxEvents                 uint32
	CancelTimeout             time.Duration
}

type Configuration struct {
	Bounds               Bounds
	Servers              []ServerRegistration
	Tools                []ToolRegistration
	AllowReferenceMemory bool
}

type Dependencies struct {
	Authority   AuthorityValidator
	Authorizer  ToolAuthorizer
	Credentials CredentialBroker
	Repository  EffectRepository
	Audit       AuditSink
	Providers   map[string]Provider
	Sampling    SamplingBroker
	Elicitation ElicitationBroker
	Roots       RootsProvider
}

const (
	AtomicMCPAuditOutbox       dependency.AtomicGroup = "mcp-audit-outbox"
	AtomicMCPAuthorityFence    dependency.AtomicGroup = "mcp-authority-fence"
	AtomicMCPEffectLifecycle   dependency.AtomicGroup = "mcp-effect-lifecycle"
	AtomicMCPAuthorization     dependency.AtomicGroup = "mcp-authorization-fence"
	AtomicMCPCredentialBinding dependency.AtomicGroup = "mcp-credential-binding"
	AtomicMCPProviderDispatch  dependency.AtomicGroup = "mcp-provider-dispatch"
	AtomicMCPSamplingBridge    dependency.AtomicGroup = "mcp-sampling-parent-child"
	AtomicMCPElicitationBridge dependency.AtomicGroup = "mcp-elicitation-fence"
)

// Production interfaces bind the exact live runtime objects used by Gateway
// to signed conformance evidence and a live dependency probe. Raw interfaces
// are accepted only by the explicitly selected reference-memory constructor.
type ProductionAuthorityValidator interface {
	AuthorityValidator
	dependency.ProductionProbe
}

type ProductionEffectRepository interface {
	EffectRepository
	dependency.ProductionProbe
}

type ProductionAuditSink interface {
	AuditSink
	dependency.ProductionProbe
}

type ProductionToolAuthorizer interface {
	ToolAuthorizer
	dependency.ProductionProbe
}

type ProductionCredentialBroker interface {
	CredentialBroker
	dependency.ProductionProbe
}

type ProductionProvider interface {
	Provider
	dependency.ProductionProbe
}

type ProductionSamplingBroker interface {
	SamplingBroker
	dependency.ProductionProbe
}

type ProductionElicitationBroker interface {
	ElicitationBroker
	dependency.ProductionProbe
}

type ProductionRootsProvider interface {
	RootsProvider
	dependency.ProductionProbe
}

type ProductionDependencies struct {
	Authority   dependency.Verified[ProductionAuthorityValidator]
	Authorizer  dependency.Verified[ProductionToolAuthorizer]
	Credentials dependency.Verified[ProductionCredentialBroker]
	Repository  dependency.Verified[ProductionEffectRepository]
	Audit       dependency.Verified[ProductionAuditSink]
	Providers   map[string]dependency.Verified[ProductionProvider]
	Sampling    dependency.Verified[ProductionSamplingBroker]
	Elicitation dependency.Verified[ProductionElicitationBroker]
	Roots       dependency.Verified[ProductionRootsProvider]
}

type CallRequest struct {
	ServerID string
	ToolName string
	Input    canonical.Value
}

type AdmissionRequest struct {
	Authority     OpaqueAuthority
	EffectID      identity.ID
	InvocationID  identity.ID
	RequestDigest Digest
	Call          CallRequest
}

type State string

const (
	StateAdmitted            State = "admitted"
	StateDispatching         State = "dispatching"
	StateRetryPending        State = "retry_pending"
	StateDispatched          State = "dispatched"
	StateStreaming           State = "streaming"
	StateCancellationPending State = "cancellation_pending"
	StateExternallyCommitted State = "externally_committed"
	StateNeedsConfirmation   State = "needs_confirmation"
	StateCompleted           State = "completed"
	StateFailed              State = "failed"
	StateCancelled           State = "cancelled"
	StateUncertain           State = "uncertain"
)

type AttemptRecord struct {
	Attempt           uint32
	ProviderRequestID string
	HadOutput         bool
	Failure           FailureClass
	Negotiation       StartNegotiationReceipt
}

// Effect is immutable by contract. Gateway methods return defensive copies;
// EffectRepository implementations must CAS Revision.
type Effect struct {
	Scope                    ValidatedAuthority
	RequestDigest            Digest
	ServerID                 string
	ToolName                 string
	ProviderID               string
	Transport                Transport
	TargetRef                string
	ProtocolVersion          string
	Affinity                 BackendAffinity
	Credential               CredentialBinding
	InputCanonical           []byte
	SideEffecting            bool
	ReplayPolicy             ReplayPolicy
	MaxAutomaticRetries      uint32
	MaxConfirmationRetries   uint32
	SupportsInvocationLedger bool
	SupportsIdempotencyKey   bool
	State                    State
	Revision                 uint64
	EventCount               uint32
	EventBytes               uint64
	Attempts                 []AttemptRecord
	AutomaticRetriesUsed     uint32
	ConfirmationRetriesUsed  uint32
	ChunkCount               uint32
	StreamBytes              uint64
	ExternalCommitID         string
	Output                   []byte
	FailureReason            string
	CancellationRequested    bool
}

func (effect Effect) CurrentAttempt() (AttemptRecord, bool) {
	if len(effect.Attempts) == 0 {
		return AttemptRecord{}, false
	}
	return effect.Attempts[len(effect.Attempts)-1], true
}

func (effect Effect) Terminal() bool {
	switch effect.State {
	case StateCompleted, StateFailed, StateCancelled, StateUncertain:
		return true
	default:
		return false
	}
}

type EventKind string

const (
	EventBeginDispatch        EventKind = "begin_dispatch"
	EventNegotiationRecorded  EventKind = "negotiation_recorded"
	EventProviderAccepted     EventKind = "provider_accepted"
	EventOutputChunk          EventKind = "output_chunk"
	EventCallCommitted        EventKind = "call_committed"
	EventSettlementCompleted  EventKind = "settlement_completed"
	EventDispatchFailed       EventKind = "dispatch_failed"
	EventCancelRequested      EventKind = "cancel_requested"
	EventCancellationResolved EventKind = "cancellation_resolved"
	EventRecoveryObserved     EventKind = "recovery_observed"
	EventConfirmationDecided  EventKind = "confirmation_decided"
)

type FailureClass string

const (
	FailureDefinitelyNotSent FailureClass = "definitely_not_sent"
	FailureRejected          FailureClass = "rejected"
	FailureLedgerAbsent      FailureClass = "ledger_absent"
	FailureExternalFailed    FailureClass = "external_failed"
	FailureUnknown           FailureClass = "unknown"
)

type ConfirmationDecision string

const (
	ConfirmationRetry   ConfirmationDecision = "retry"
	ConfirmationAbandon ConfirmationDecision = "abandon"
)

type CancellationStatus string

const (
	CancellationPrevented CancellationStatus = "prevented"
	CancellationAbsent    CancellationStatus = "absent"
	CancellationCommitted CancellationStatus = "committed"
	CancellationUnknown   CancellationStatus = "unknown"
)

type LedgerStatus string

const (
	LedgerAbsent    LedgerStatus = "absent"
	LedgerInflight  LedgerStatus = "inflight"
	LedgerCommitted LedgerStatus = "committed"
	LedgerFailed    LedgerStatus = "failed"
	LedgerUnknown   LedgerStatus = "unknown"
)

type LedgerRecord struct {
	InvocationID      identity.ID
	RequestDigest     Digest
	Status            LedgerStatus
	ProviderRequestID string
	ExternalCommitID  string
	Output            []byte
	FailureReason     string
}

type Event struct {
	ExpectedRevision  uint64
	Kind              EventKind
	ProviderRequestID string
	Chunk             []byte
	Output            []byte
	ExternalCommitID  string
	Failure           FailureClass
	Reason            string
	Cancellation      CancellationStatus
	Ledger            LedgerRecord
	Decision          ConfirmationDecision
	Negotiation       StartNegotiationReceipt
}

type OpaqueDispatchPermit [32]byte

func (OpaqueDispatchPermit) String() string   { return "mcp-dispatch-permit<redacted>" }
func (OpaqueDispatchPermit) GoString() string { return "mcp-dispatch-permit<redacted>" }

type DispatchPermit struct {
	Proof          OpaqueDispatchPermit
	Durable        bool
	Scope          ValidatedAuthority
	InvocationID   identity.ID
	RequestDigest  Digest
	ProviderID     string
	Attempt        uint32
	EffectRevision uint64
	Authorization  ToolAuthorizationPermit
}

func (DispatchPermit) String() string   { return "mcp-dispatch-permit<redacted>" }
func (DispatchPermit) GoString() string { return "mcp-dispatch-permit<redacted>" }

type DispatchCommand struct {
	Scope          ValidatedAuthority
	Server         ServerDescriptor
	ToolName       string
	InputCanonical []byte
	InvocationID   identity.ID
	RequestDigest  Digest
	ReplayPolicy   ReplayPolicy
	IdempotencyKey string
	Attempt        uint32
	Authorization  ToolAuthorizationPermit
	Credential     CredentialPermit
	Dispatch       DispatchPermit
	Negotiation    StartNegotiationReceipt
	Start          ProviderStartPermit
}

func (DispatchCommand) String() string   { return "mcp-provider-command<redacted>" }
func (DispatchCommand) GoString() string { return "mcp-provider-command<redacted>" }

// ProviderCommand names the trusted adapter-facing form explicitly.
type ProviderCommand = DispatchCommand

// NegotiationCommand creates or resolves the exact transport session that a
// later Start may use. It carries the durable dispatch claim but cannot invoke
// the tool. A returned receipt must be committed before Start is called.
type NegotiationCommand struct {
	Scope         ValidatedAuthority
	Server        ServerDescriptor
	ToolName      string
	InvocationID  identity.ID
	RequestDigest Digest
	Attempt       uint32
	Authorization ToolAuthorizationPermit
	Credential    CredentialPermit
	Dispatch      DispatchPermit
}

func (NegotiationCommand) String() string   { return "mcp-negotiation-command<redacted>" }
func (NegotiationCommand) GoString() string { return "mcp-negotiation-command<redacted>" }

type CancelCommand struct {
	Scope             ValidatedAuthority
	Server            ServerDescriptor
	ToolName          string
	InvocationID      identity.ID
	RequestDigest     Digest
	ProviderRequestID string
	Attempt           uint32
	Credential        CredentialPermit
	Cancellation      CancellationPermit
	Negotiation       StartNegotiationReceipt
	Start             ProviderStartPermit
}

func (CancelCommand) String() string   { return "mcp-cancel-command<redacted>" }
func (CancelCommand) GoString() string { return "mcp-cancel-command<redacted>" }

type OpaqueCancellationPermit [32]byte

func (OpaqueCancellationPermit) String() string   { return "mcp-cancellation-permit<redacted>" }
func (OpaqueCancellationPermit) GoString() string { return "mcp-cancellation-permit<redacted>" }

// CancellationPermit is a durable, bounded-lease claim. Proof is stable across
// owner-generation takeover so a transport can deduplicate reissued cancel
// commands, while ClaimGeneration and Scope fence stale completion writes.
type CancellationPermit struct {
	Proof                  OpaqueCancellationPermit
	Durable                bool
	Scope                  ValidatedAuthority
	InvocationID           identity.ID
	RequestDigest          Digest
	ProviderID             string
	ProviderRequestID      string
	Attempt                uint32
	EffectRevision         uint64
	ClaimGeneration        uint64
	LeaseExpiresAtUnixNano int64
	Start                  ProviderStartPermit
	ServerRequest          ServerRequestPermit
	ServerRequestMethod    string
}

func (CancellationPermit) String() string   { return "mcp-cancellation-permit<redacted>" }
func (CancellationPermit) GoString() string { return "mcp-cancellation-permit<redacted>" }

type CancellationClaimRequest struct {
	CurrentScope ValidatedAuthority
	Effect       Effect
	Lease        time.Duration
}

type CancellationClaim struct {
	Permit     CancellationPermit
	Fresh      bool
	RetryAfter time.Duration
}

type OpaqueProviderStartPermit [32]byte

func (OpaqueProviderStartPermit) String() string   { return "mcp-provider-start-permit<redacted>" }
func (OpaqueProviderStartPermit) GoString() string { return "mcp-provider-start-permit<redacted>" }

// ProviderStartPermit is the durable linearization result for the final
// transition from negotiation-only activity to an externally effectful tool
// dispatch. Provider adapters must reject expired permits and deduplicate the
// stable proof. Cancel/recovery commits race with ClaimProviderStart in the
// same transaction domain, so only one side can win.
type ProviderStartPermit struct {
	Proof                  OpaqueProviderStartPermit
	Durable                bool
	Scope                  ValidatedAuthority
	InvocationID           identity.ID
	RequestDigest          Digest
	ProviderID             string
	Attempt                uint32
	EffectRevision         uint64
	ClaimGeneration        uint64
	LeaseExpiresAtUnixNano int64
	Dispatch               DispatchPermit
	Negotiation            StartNegotiationReceipt
}

func (ProviderStartPermit) String() string   { return "mcp-provider-start-permit<redacted>" }
func (ProviderStartPermit) GoString() string { return "mcp-provider-start-permit<redacted>" }

type ProviderStartClaimRequest struct {
	CurrentScope ValidatedAuthority
	Effect       Effect
	Dispatch     DispatchPermit
	Lease        time.Duration
}

// ProviderStartResolutionRequest fences a possibly in-flight Start before
// cancellation or ledger recovery resolves its stable proof. A missing proof
// is authoritative only when the repository atomically proves no start claim
// was ever issued for the current attempt.
type ProviderStartResolutionRequest struct {
	CurrentScope ValidatedAuthority
	Effect       Effect
}

type StoredProviderStartResolution struct {
	Permit     ProviderStartPermit
	Present    bool
	Durable    bool
	Active     bool
	RetryAfter time.Duration
}

type Transition struct {
	Effect   Effect
	Dispatch *DispatchCommand
	Cancel   *CancelCommand
}

type ServerDescriptor struct {
	ServerID        string
	Transport       Transport
	TargetRef       string
	ProtocolVersion string
	Affinity        BackendAffinity
}

type ServerAvailability struct {
	Available                 bool
	Reason                    string
	DurableNegotiation        bool
	NegotiatedProtocolVersion string
	Affinity                  BackendAffinity
	SupportsInvocationLedger  bool
	SupportsIdempotencyKey    bool
}

type ProviderStartResult struct {
	ProviderRequestID string
	Call              ProviderCall
}

// StartNegotiationReceipt binds the actual process/HTTP session selected by
// Negotiate to the current authority, exact invocation, negotiated protocol,
// stdio affinity, and replay capabilities. Availability alone is not proof
// that the subsequently selected transport instance has these properties.
type StartNegotiationReceipt struct {
	Durable                   bool
	Scope                     ValidatedAuthority
	Server                    ServerDescriptor
	InvocationID              identity.ID
	RequestDigest             Digest
	Attempt                   uint32
	NegotiatedProtocolVersion string
	Affinity                  BackendAffinity
	SupportsInvocationLedger  bool
	SupportsIdempotencyKey    bool
	ConnectionGeneration      uint64
}

type ProviderEventKind string

const (
	ProviderOutputChunk ProviderEventKind = "output_chunk"
	ProviderCompleted   ProviderEventKind = "completed"
)

type ProviderEvent struct {
	Kind             ProviderEventKind
	Chunk            []byte
	Output           []byte
	ExternalCommitID string
}

type ProviderCall interface {
	Next(context.Context) (ProviderEvent, error)
	Close() error
}

type LedgerQuery struct {
	Scope         ValidatedAuthority
	Server        ServerDescriptor
	ToolName      string
	InvocationID  identity.ID
	RequestDigest Digest
	Credential    CredentialPermit
	Negotiation   StartNegotiationReceipt
	Start         ProviderStartPermit
}

type CancellationResult struct {
	Status CancellationStatus
	Record LedgerRecord
}

// Provider is a trusted transport adapter. Concrete network/process adapters
// live outside this package. Start receives only registry-resolved targets and
// opaque credential permits, never caller-supplied URLs or raw secrets. At the
// irreversible dispatch boundary an adapter must validate Start against its
// expiry/current authority and atomically deduplicate its proof; Cancel carries
// the same proof so an adapter can install a tombstone before a delayed Start.
type Provider interface {
	Availability(context.Context, ServerDescriptor) (ServerAvailability, error)
	Negotiate(context.Context, NegotiationCommand) (StartNegotiationReceipt, error)
	Start(context.Context, ProviderCommand) (ProviderStartResult, error)
	Cancel(context.Context, CancelCommand) (CancellationResult, error)
	Lookup(context.Context, LedgerQuery) (LedgerRecord, error)
}

type DispatchFailureClassification string

const (
	DispatchDefinitelyNotSent DispatchFailureClassification = "definitely_not_sent"
	DispatchUnknown           DispatchFailureClassification = "unknown"
)

type ProviderDispatchError struct {
	classification DispatchFailureClassification
	reason         string
	cause          error
}

type StoredEffect struct {
	Effect  Effect
	Durable bool
	Audit   *AuditEnvelope
}

type AdmissionReplayRequest struct {
	CurrentScope   ValidatedAuthority
	EffectID       identity.ID
	InvocationID   identity.ID
	RequestDigest  Digest
	ServerID       string
	ToolName       string
	InputCanonical []byte
}

type DispatchClaimRequest struct {
	ExpectedRevision uint64
	CurrentScope     ValidatedAuthority
	Previous         Effect
	Next             Effect
	Authorization    ToolAuthorizationPermit
}

type TransitionCommitRequest struct {
	ExpectedRevision uint64
	CurrentScope     ValidatedAuthority
	Previous         Effect
	Next             Effect
	Audit            *AuditEvent
	Cancellation     *CancellationPermit
	ProviderStart    *ProviderStartPermit
}

type RepositoryDurability struct {
	CrashDurable                       bool
	AtomicAdmissionCAS                 bool
	AtomicAdmissionReplay              bool
	AtomicTransitionCAS                bool
	ExclusiveDispatchClaim             bool
	ExclusiveProviderStartClaim        bool
	AtomicProviderStartResolution      bool
	ExclusiveCancellationClaim         bool
	AtomicExpiredRequestReconciliation bool
	AtomicCurrentFence                 bool
	AtomicActiveEffect                 bool
	AtomicAuditOutbox                  bool
	ReferenceMemory                    bool
}

type ServerRequestReconcileRequest struct {
	CurrentScope ValidatedAuthority
	Parent       Effect
}

type ServerRequestReconcileResult struct {
	Durable              bool
	Reconciled           bool
	Active               bool
	PendingCancellation  bool
	ParentCancelRequired bool
	Record               ServerRequestRecord
	CancellationClaim    ServerRequestPermit
	RetryAfter           time.Duration
}

// EffectRepository is the authoritative invocation ledger for gateway-local
// progress. ReplayAdmission must atomically combine exact immutable-request
// matching with the current authority fence. Dispatch and transition commits
// must CAS that fence, server requests must be durably claimed/deduplicated,
// and non-nil audit records must enter the monotonic outbox in the same
// transaction as their state/response. PendingAudits are returned in strictly
// increasing sequence order and acknowledgement is idempotent.
type EffectRepository interface {
	Durability() RepositoryDurability
	Admit(context.Context, Effect) (StoredEffect, error)
	ReplayAdmission(context.Context, AdmissionReplayRequest) (StoredEffect, error)
	Load(context.Context, identity.ID) (StoredEffect, error)
	CommitAndClaimDispatch(context.Context, DispatchClaimRequest) (DispatchPermit, error)
	ClaimProviderStart(context.Context, ProviderStartClaimRequest) (ProviderStartPermit, error)
	ResolveProviderStart(context.Context, ProviderStartResolutionRequest) (StoredProviderStartResolution, error)
	ClaimCancellation(context.Context, CancellationClaimRequest) (CancellationClaim, error)
	Commit(context.Context, TransitionCommitRequest) (StoredEffect, error)
	ClaimServerRequest(context.Context, ServerRequestClaimRequest) (StoredServerRequest, error)
	ReconcileServerRequests(context.Context, ServerRequestReconcileRequest) (ServerRequestReconcileResult, error)
	CompleteServerRequestReconciliation(context.Context, ServerRequestReconcileCommitRequest) (StoredServerRequest, error)
	CompleteServerRequest(context.Context, ServerRequestCommitRequest) (StoredServerRequest, error)
	AppendAudit(context.Context, AuditEvent) (AuditEnvelope, error)
	PendingAudits(context.Context, uint32) ([]AuditEnvelope, error)
	AcknowledgeAudit(context.Context, uint64) error
}

type OutputSink interface {
	Accept(context.Context, []byte) error
}

type OutputSinkFunc func(context.Context, []byte) error

func (function OutputSinkFunc) Accept(ctx context.Context, chunk []byte) error {
	return function(ctx, chunk)
}

type RecoveryAction string

const (
	RecoveryWait         RecoveryAction = "wait"
	RecoveryRetry        RecoveryAction = "retry"
	RecoverySettled      RecoveryAction = "settled"
	RecoveryConfirmation RecoveryAction = "confirmation"
	RecoveryInterrupted  RecoveryAction = "interrupted"
)

type RecoveryResult struct {
	Effect Effect
	Action RecoveryAction
}

type AuditEvent struct {
	OutboxSequence uint64
	TenantID       identity.ID
	UserID         identity.ID
	SessionID      identity.ID
	TurnID         identity.ID
	InvocationID   identity.ID
	ServerID       string
	Method         string
	Decision       string
	Reason         string
}

// AuditEnvelope is committed atomically with the state transition it
// describes. Audit sinks can use Sequence as an idempotency key because a
// crash after delivery but before acknowledgement may cause redelivery.
type AuditEnvelope struct {
	Sequence uint64
	Event    AuditEvent
}

type AuditSink interface {
	Record(context.Context, AuditEvent) error
}

// The following narrow brokers make explicitly allowed server-initiated
// methods cross their required central authority rather than a generic
// callback that could silently bypass model quota or workspace projection.
type SamplingBroker interface {
	Sample(context.Context, SamplingRequest) (SamplingResult, error)
	Resume(context.Context, SamplingRequest) (SamplingResult, error)
	Cancel(context.Context, SamplingCancellationRequest) (SamplingCancellationReceipt, error)
}

type SamplingRequest struct {
	Scope              ValidatedAuthority
	ParentEffectID     identity.ID
	ParentInvocationID identity.ID
	RequestDigest      Digest
	RequestID          string
	ParamsCanonical    []byte
	Claim              ServerRequestPermit
	ChildEffectID      identity.ID
	ChildInvocationID  identity.ID
}

// SamplingResult proves that an explicitly allowed sampling request traversed
// Model Gateway as its own durable effect instead of recursively invoking a
// model inside the MCP transport adapter.
type SamplingResult struct {
	Value              canonical.Value
	EffectID           identity.ID
	InvocationID       identity.ID
	Scope              ValidatedAuthority
	ParentEffectID     identity.ID
	ParentInvocationID identity.ID
	RequestDigest      Digest
	Durable            bool
	ParentLifecycle    SamplingParentLifecycleReceipt
}

type OpaqueSamplingParentLifecycleReceipt [32]byte

func (OpaqueSamplingParentLifecycleReceipt) String() string {
	return "mcp-sampling-parent-lifecycle-receipt<redacted>"
}
func (OpaqueSamplingParentLifecycleReceipt) GoString() string {
	return "mcp-sampling-parent-lifecycle-receipt<redacted>"
}

// SamplingParentLifecycleReceipt proves that the shared durable coordinator
// suspended the MCP parent, ran the named child model effect, and resumed the
// same parent without ever exposing two active effects for the turn.
type SamplingParentLifecycleReceipt struct {
	Proof              OpaqueSamplingParentLifecycleReceipt
	Durable            bool
	Scope              ValidatedAuthority
	ParentEffectID     identity.ID
	ParentInvocationID identity.ID
	ChildEffectID      identity.ID
	ChildInvocationID  identity.ID
	RequestDigest      Digest
	ClaimProof         OpaqueServerRequestPermit
	Suspended          bool
	Resumed            bool
}

type OpaqueSamplingCancellationReceipt [32]byte

func (OpaqueSamplingCancellationReceipt) String() string {
	return "mcp-sampling-cancellation-receipt<redacted>"
}
func (OpaqueSamplingCancellationReceipt) GoString() string {
	return "mcp-sampling-cancellation-receipt<redacted>"
}

// SamplingCancellationRequest hands the already durable child identity and
// server-request proof back to Model Gateway. Cancel must be idempotent by the
// stable server-request proof and terminalize or recover the child effect.
type SamplingCancellationRequest struct {
	Scope              ValidatedAuthority
	ParentEffectID     identity.ID
	ParentInvocationID identity.ID
	RequestDigest      Digest
	Claim              ServerRequestPermit
}

type SamplingCancellationReceipt struct {
	Proof              OpaqueSamplingCancellationReceipt
	Durable            bool
	Scope              ValidatedAuthority
	ParentEffectID     identity.ID
	ParentInvocationID identity.ID
	ChildEffectID      identity.ID
	ChildInvocationID  identity.ID
	RequestDigest      Digest
	ClaimProof         OpaqueServerRequestPermit
}

func (SamplingCancellationReceipt) String() string {
	return "mcp-sampling-cancellation-receipt<redacted>"
}
func (SamplingCancellationReceipt) GoString() string {
	return "mcp-sampling-cancellation-receipt<redacted>"
}

type ElicitationBroker interface {
	Elicit(context.Context, ElicitationRequest) (canonical.Value, error)
	Cancel(context.Context, ElicitationCancellationRequest) (ElicitationCancellationReceipt, error)
}

type ElicitationRequest struct {
	Scope              ValidatedAuthority
	ParentEffectID     identity.ID
	ParentInvocationID identity.ID
	RequestDigest      Digest
	RequestID          string
	ParamsCanonical    []byte
	Claim              ServerRequestPermit
}

type OpaqueElicitationCancellationReceipt [32]byte

func (OpaqueElicitationCancellationReceipt) String() string {
	return "mcp-elicitation-cancellation-receipt<redacted>"
}
func (OpaqueElicitationCancellationReceipt) GoString() string {
	return "mcp-elicitation-cancellation-receipt<redacted>"
}

type ElicitationCancellationRequest struct {
	Scope              ValidatedAuthority
	ParentEffectID     identity.ID
	ParentInvocationID identity.ID
	RequestDigest      Digest
	Claim              ServerRequestPermit
}

type ElicitationCancellationReceipt struct {
	Proof              OpaqueElicitationCancellationReceipt
	Durable            bool
	Scope              ValidatedAuthority
	ParentEffectID     identity.ID
	ParentInvocationID identity.ID
	RequestDigest      Digest
	ClaimProof         OpaqueServerRequestPermit
}

type RootsProvider interface {
	Roots(context.Context, ValidatedAuthority) ([]string, error)
}

type ServerRequestMethod string

const (
	ServerRequestSampling    ServerRequestMethod = "sampling/createMessage"
	ServerRequestElicitation ServerRequestMethod = "elicitation/create"
	ServerRequestRoots       ServerRequestMethod = "roots/list"
)

type ServerRequest struct {
	Authority            OpaqueAuthority
	Effect               Effect
	RequestID            string
	ProviderRequestID    string
	ConnectionGeneration uint64
	Method               string
	Params               canonical.Value
}

type JSONRPCError struct {
	Code    int
	Message string
}

type ServerResponse struct {
	RequestID       string
	ResultCanonical []byte
	Error           *JSONRPCError
}

type ServerRequestRecordState string

const (
	ServerRequestClaimed   ServerRequestRecordState = "claimed"
	ServerRequestCompleted ServerRequestRecordState = "completed"
	ServerRequestAbandoned ServerRequestRecordState = "abandoned"
)

type OpaqueServerRequestPermit [32]byte

func (OpaqueServerRequestPermit) String() string   { return "mcp-server-request-permit<redacted>" }
func (OpaqueServerRequestPermit) GoString() string { return "mcp-server-request-permit<redacted>" }

type ServerRequestPermit struct {
	Proof                  OpaqueServerRequestPermit
	Durable                bool
	Scope                  ValidatedAuthority
	ParentInvocationID     identity.ID
	ProviderRequestID      string
	ConnectionGeneration   uint64
	RequestID              string
	RequestDigest          Digest
	ChildEffectID          identity.ID
	ChildInvocationID      identity.ID
	ClaimGeneration        uint64
	LeaseExpiresAtUnixNano int64
}

func (ServerRequestPermit) String() string   { return "mcp-server-request-permit<redacted>" }
func (ServerRequestPermit) GoString() string { return "mcp-server-request-permit<redacted>" }

type ServerRequestClaimRequest struct {
	CurrentScope               ValidatedAuthority
	Parent                     Effect
	ProviderRequestID          string
	ConnectionGeneration       uint64
	RequestID                  string
	Method                     string
	RequestDigest              Digest
	ChildEffectID              identity.ID
	ChildInvocationID          identity.ID
	BrokerCancellationRequired bool
	MaxRequests                uint32
	Lease                      time.Duration
}

type ServerRequestRecord struct {
	State                      ServerRequestRecordState
	ParentInvocationID         identity.ID
	ProviderRequestID          string
	ConnectionGeneration       uint64
	RequestID                  string
	Method                     string
	RequestDigest              Digest
	BrokerCancellationRequired bool
	Response                   ServerResponse
	Permit                     ServerRequestPermit
	ChildCancellation          SamplingCancellationReceipt
	ElicitationCancellation    ElicitationCancellationReceipt
	AuditSequence              uint64
}

type StoredServerRequest struct {
	Record     ServerRequestRecord
	Durable    bool
	Fresh      bool
	Audit      *AuditEnvelope
	RetryAfter time.Duration
}

type ServerRequestCommitRequest struct {
	CurrentScope            ValidatedAuthority
	Permit                  ServerRequestPermit
	Response                ServerResponse
	Audit                   *AuditEvent
	SamplingCancellation    SamplingCancellationReceipt
	ElicitationCancellation ElicitationCancellationReceipt
}

type ServerRequestReconcileCommitRequest struct {
	CurrentScope            ValidatedAuthority
	Permit                  ServerRequestPermit
	Cancellation            SamplingCancellationReceipt
	ElicitationCancellation ElicitationCancellationReceipt
}

type ToolListRequest struct {
	Authority     OpaqueAuthority
	EffectID      identity.ID
	InvocationID  identity.ID
	RequestDigest Digest
	ServerID      string
	Advertised    []string
}
