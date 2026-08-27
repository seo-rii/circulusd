// Package secret implements opaque, scope-bound credential handles. Raw
// material crosses only trusted gateway, token-minter, or sandbox-injector
// interfaces and is never returned by Service methods.
package secret

import (
	"context"
	"errors"
	"time"
)

var (
	ErrInvalidConfig              = errors.New("secret: invalid configuration")
	ErrInvalidRequest             = errors.New("secret: invalid request")
	ErrAccessDenied               = errors.New("secret: access denied")
	ErrSecretNotFound             = errors.New("secret: record not found")
	ErrStoreConflict              = errors.New("secret: durable store conflict")
	ErrStoreNotDurable            = errors.New("secret: store lacks required durability capabilities")
	ErrStoreInUse                 = errors.New("secret: record has an active use lease")
	ErrUseLeaseInvalid            = errors.New("secret: use lease is invalid")
	ErrUseReleaseUnconfirmed      = errors.New("secret: use lease release is unconfirmed")
	ErrRecoveryDenied             = errors.New("secret: recovery authority denied")
	ErrRecoveryAuditNotDurable    = errors.New("secret: recovery audit event is not durable")
	ErrStaleHandle                = errors.New("secret: stale handle")
	ErrExposureDenied             = errors.New("secret: exposure class denied")
	ErrAuditNotDurable            = errors.New("secret: audit event is not durable")
	ErrGatewayUnavailable         = errors.New("secret: gateway unavailable")
	ErrGatewayFailed              = errors.New("secret: gateway dispatch failed")
	ErrGatewayRecoveryUnconfirmed = errors.New("secret: gateway recovery is unconfirmed")
	ErrSandboxUnavailable         = errors.New("secret: sandbox injector unavailable")
	ErrSandboxFailed              = errors.New("secret: sandbox injection failed")
	ErrCleanupUnconfirmed         = errors.New("secret: sandbox cleanup is unconfirmed")
	ErrContainmentUnconfirmed     = errors.New("secret: sandbox containment is unconfirmed")
	ErrTokenUnavailable           = errors.New("secret: short-lived token minter unavailable")
	ErrTokenFailed                = errors.New("secret: short-lived token mint failed")
	ErrResponseTooLarge           = errors.New("secret: gateway response exceeds its limit")
	ErrSensitiveSerialization     = errors.New("secret: generic serialization of sensitive material is forbidden")
)

type ExposureClass string

const (
	ExposureProxyOnly       ExposureClass = "proxy-only"
	ExposureGatewayHeader   ExposureClass = "gateway-header"
	ExposureSandboxEnv      ExposureClass = "sandbox-env"
	ExposureSandboxFile     ExposureClass = "sandbox-file"
	ExposureShortLivedToken ExposureClass = "short-lived-token"
)

type Operation string

const (
	OperationIssue      Operation = "issue"
	OperationGatewayUse Operation = "gateway-use"
	OperationSandboxUse Operation = "sandbox-use"
)

type AccessContext struct {
	TenantID                string
	SubjectID               string
	SessionID               string
	WorkspaceID             string
	TurnID                  string
	RuntimeRevision         string
	TurnLeaseGeneration     uint64
	PlacementGeneration     uint64
	SandboxGeneration       uint64
	AuthorizationGeneration uint64
	Permission              string
	ServiceBinding          string
	AuthorityExpiresAt      time.Time
}

type Record struct {
	SecretID               string
	TenantID               string
	Version                uint64
	Exposure               ExposureClass
	Value                  []byte
	InjectionName          string
	Endpoint               string
	Audience               string
	Active                 bool
	DestroySandboxAfterUse bool
}

func (Record) String() string   { return "secret-record<redacted>" }
func (Record) GoString() string { return "secret-record<redacted>" }
func (Record) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// Store is the secret service's durability and linearization boundary.
// Production adapters must authenticate and atomically validate Admission,
// install Recovery before returning raw material, retain completed recovery-ID
// tombstones, and durably enumerate pending recoveries in bounded pages.
// ReserveUse must install the same fence without reading raw material, and
// AcquireReservedUse must revalidate and return material at most once. Get,
// BeginUse, and AcquireReservedUse return caller-owned Value buffers even when
// they also return an error; Service clears every returned buffer.
type Store interface {
	Capabilities() StoreCapabilities
	Get(context.Context, string, string) (Record, error)
	BeginUse(context.Context, BeginUseRequest) (Record, UseLease, error)
	ReserveUse(context.Context, ReserveUseRequest) (UseLease, error)
	AcquireReservedUse(context.Context, AcquireReservedUseRequest) (Record, error)
	EndUse(context.Context, UseLease) error
	ValidateUseRecovery(context.Context, UseRecoveryBinding) error
	CompleteUseRecovery(context.Context, UseRecoveryBinding) error
	ListPendingUseRecoveries(context.Context, PendingUseRecoveryQuery) (PendingUseRecoveryPage, error)
}

type StoreCapabilities struct {
	// Durable means mutations and completion tombstones survive process loss.
	Durable bool
	// AtomicUseRecovery means Recovery and its lease commit before raw material
	// can be returned, and release/tombstone updates share the same transaction.
	AtomicUseRecovery bool
	// AtomicAdmissionValidation means BeginUse, ReserveUse, and
	// AcquireReservedUse authenticate Proof, compare every turn/runtime/generation
	// dimension with authoritative current state, and evaluate both deadlines in
	// the same transaction that installs a fence or returns raw material.
	AtomicAdmissionValidation bool
	// AtomicPreparedUse means sandbox recovery can be reserved without returning
	// raw material, then atomically revalidated exactly once before acquisition.
	AtomicPreparedUse bool
	// BoundedRecoveryEnumeration means Limit bounds both the returned page and
	// adapter working memory; callers restart scans to observe concurrent inserts.
	BoundedRecoveryEnumeration bool
}

type PendingUseRecoveryQuery struct {
	TenantID        string
	AfterRecoveryID string
	Limit           int
}

type PendingUseRecoveryPage struct {
	Recoveries          []UseRecoveryBinding
	NextAfterRecoveryID string
}

type BeginUseRequest struct {
	TenantID        string
	SecretID        string
	ExpectedVersion uint64
	Recovery        UseRecoveryBinding
	Admission       UseAdmissionPermit
}

type ReserveUseRequest = BeginUseRequest

type AcquireReservedUseRequest struct {
	TenantID        string
	SecretID        string
	ExpectedVersion uint64
	Recovery        UseRecoveryBinding
	Lease           UseLease
	Admission       UseAdmissionPermit
}

type UseLease struct {
	LeaseID  string
	TenantID string
	SecretID string
	Version  uint64
}

// UseRecoveryBinding contains durable routing and fencing metadata only. It
// never contains credential material and is safe to persist for reconciliation.
type UseRecoveryBinding struct {
	TenantID                string
	SubjectID               string
	SessionID               string
	WorkspaceID             string
	TurnID                  string
	RuntimeRevision         string
	TurnLeaseGeneration     uint64
	PlacementGeneration     uint64
	SandboxGeneration       uint64
	AuthorizationGeneration uint64
	Permission              string
	ServiceBinding          string
	AuthorityExpiresAt      time.Time
	DestroySandboxAfterUse  bool
	SecretID                string
	SecretVersion           uint64
	Exposure                ExposureClass
	InvocationID            string
	RecoveryID              string
	ResolvedCacheKey        string
	Endpoint                string
	Audience                string
}

func (UseRecoveryBinding) String() string   { return "use-recovery<redacted>" }
func (UseRecoveryBinding) GoString() string { return "use-recovery<redacted>" }

type AuthorizationRequest struct {
	Operation    Operation
	Access       AccessContext
	SecretID     string
	Exposure     ExposureClass
	Endpoint     string
	Audience     string
	InvocationID string
}

type Authorizer interface {
	Authorize(context.Context, AuthorizationRequest) error
}

// UseAdmitter revalidates authoritative policy and issues a short-lived exact
// proof before each Store reservation/acquisition transaction. Store must
// authenticate the opaque Proof and compare all authority dimensions.
type UseAdmitter interface {
	Admit(context.Context, UseAdmissionRequest) (UseAdmissionPermit, error)
}

type UseAdmissionRequest struct {
	Authorization   AuthorizationRequest
	HandleExpiresAt time.Time
	RequestedAt     time.Time
}

type UseAdmissionPermit struct {
	Authorization   AuthorizationRequest
	HandleExpiresAt time.Time
	IssuedAt        time.Time
	ExpiresAt       time.Time
	Proof           string
}

func (UseAdmissionPermit) String() string   { return "use-admission<redacted>" }
func (UseAdmissionPermit) GoString() string { return "use-admission<redacted>" }
func (UseAdmissionPermit) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

type AuditEvent struct {
	Operation               Operation
	TenantID                string
	SubjectID               string
	SessionID               string
	WorkspaceID             string
	TurnID                  string
	RuntimeRevision         string
	InvocationID            string
	SecretID                string
	Version                 uint64
	Exposure                ExposureClass
	Endpoint                string
	Audience                string
	AuthorizationGeneration uint64
	TurnLeaseGeneration     uint64
	PlacementGeneration     uint64
	SandboxGeneration       uint64
	Permission              string
	ServiceBinding          string
	AuthorityExpiresAt      time.Time
}

type AuditReceipt struct {
	Durable  bool
	Sequence uint64
}

type AuditSink interface {
	Append(context.Context, AuditEvent) (AuditReceipt, error)
}

// Handle is intentionally opaque outside this package. It is a short-lived
// in-process capability, not a serializable bearer token.
type Handle struct {
	access                 AccessContext
	secretID               string
	version                uint64
	exposure               ExposureClass
	endpoint               string
	audience               string
	destroySandboxAfterUse bool
	invocationID           string
	expiresAt              time.Time
}

func (Handle) String() string   { return "secret-handle<redacted>" }
func (Handle) GoString() string { return "secret-handle<redacted>" }

type IssueRequest struct {
	Access       AccessContext
	SecretID     string
	Exposure     ExposureClass
	Endpoint     string
	Audience     string
	InvocationID string
}

// CredentialMaterial is passed only to trusted dependencies supplied when the
// Service is constructed. Callers receive only their dependency's public
// response or cleanup receipt.
type CredentialMaterial struct {
	Exposure      ExposureClass
	InjectionName string
	Value         []byte
	ExpiresAt     time.Time
}

func (CredentialMaterial) String() string   { return "credential-material<redacted>" }
func (CredentialMaterial) GoString() string { return "credential-material<redacted>" }
func (CredentialMaterial) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

type GatewayUseRequest struct {
	Access   AccessContext
	Handle   Handle
	Endpoint string
	Audience string
	Payload  []byte
}

type GatewayDispatch struct {
	Authority AccessContext
	Endpoint  string
	Audience  string
	Payload   []byte
	Recovery  GatewayRecoveryReference
}

type GatewayResponse struct {
	Payload         []byte
	Recovery        GatewayRecoveryReference
	RecoveryDurable bool
}

type GatewayRecoveryRequest struct {
	Authority RecoveryAuthority
	Recovery  GatewayRecoveryReference
}

type RecoveryAuthority struct {
	TenantID  string
	SubjectID string
}

type RecoveryOperation string

const (
	RecoveryContainSandbox RecoveryOperation = "contain-sandbox"
	RecoveryReleaseGateway RecoveryOperation = "release-gateway"
	RecoveryListPending    RecoveryOperation = "list-pending"
)

type RecoveryAuthorizationRequest struct {
	Operation               RecoveryOperation
	Authority               RecoveryAuthority
	RecoveryID              string
	OriginalSubjectID       string
	SessionID               string
	WorkspaceID             string
	TurnID                  string
	RuntimeRevision         string
	TurnLeaseGeneration     uint64
	PlacementGeneration     uint64
	SandboxGeneration       uint64
	AuthorizationGeneration uint64
	Permission              string
	ServiceBinding          string
	AuthorityExpiresAt      time.Time
	DestroySandboxAfterUse  bool
	SecretID                string
	SecretVersion           uint64
	Exposure                ExposureClass
	InvocationID            string
	ResolvedCacheKey        string
	Endpoint                string
	Audience                string
}

type RecoveryAuthorizer interface {
	AuthorizeRecovery(context.Context, RecoveryAuthorizationRequest) error
}

type RecoveryAuditEvent struct {
	Operation               RecoveryOperation
	Authority               RecoveryAuthority
	RecoveryID              string
	TenantID                string
	OriginalSubjectID       string
	SessionID               string
	WorkspaceID             string
	TurnID                  string
	RuntimeRevision         string
	TurnLeaseGeneration     uint64
	PlacementGeneration     uint64
	SandboxGeneration       uint64
	AuthorizationGeneration uint64
	Permission              string
	ServiceBinding          string
	AuthorityExpiresAt      time.Time
	DestroySandboxAfterUse  bool
	SecretID                string
	SecretVersion           uint64
	Exposure                ExposureClass
	InvocationID            string
	ResolvedCacheKey        string
	Endpoint                string
	Audience                string
}

type RecoveryAuditSink interface {
	AppendRecovery(context.Context, RecoveryAuditEvent) (AuditReceipt, error)
}

type PendingRecoveryRequest struct {
	Authority       RecoveryAuthority
	AfterRecoveryID string
	Limit           int
}

type GatewayDispatcher interface {
	// Dispatch must durably bind dispatch.Recovery before external dispatch or
	// credential retention. Recover must idempotently reconcile that exact
	// binding; SafeToRelease is valid only after credential use is no longer
	// uncertain. Implementations must not retain CredentialMaterial after return.
	Capabilities() GatewayCapabilities
	Dispatch(context.Context, GatewayDispatch, CredentialMaterial) (GatewayResponse, error)
	Recover(context.Context, GatewayRecoveryDispatch) (GatewayRecoveryReceipt, error)
}

type GatewayCapabilities struct {
	DurableRecovery    bool
	IdempotentRecovery bool
}

type GatewayRecoveryDispatch struct {
	Recovery GatewayRecoveryReference
}

type GatewayRecoveryReceipt struct {
	Recovery      GatewayRecoveryReference
	Durable       bool
	SafeToRelease bool
}

type TokenMintRequest struct {
	TenantID  string
	SecretID  string
	Version   uint64
	Endpoint  string
	Audience  string
	Seed      []byte
	ExpiresBy time.Time
}

func (TokenMintRequest) String() string   { return "token-mint-request<redacted>" }
func (TokenMintRequest) GoString() string { return "token-mint-request<redacted>" }
func (TokenMintRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

type MintedToken struct {
	Value     []byte
	ExpiresAt time.Time
}

func (MintedToken) String() string   { return "minted-token<redacted>" }
func (MintedToken) GoString() string { return "minted-token<redacted>" }
func (MintedToken) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

type TokenMinter interface {
	Mint(context.Context, TokenMintRequest) (MintedToken, error)
}

type SandboxUseRequest struct {
	Access       AccessContext
	Handle       Handle
	InvocationID string
	BaseCacheKey string
}

type SandboxRecoveryRequest struct {
	Authority RecoveryAuthority
	Recovery  SandboxRecoveryReference
}

type SandboxDispatch struct {
	TenantID               string
	SubjectID              string
	SessionID              string
	WorkspaceID            string
	InvocationID           string
	ResolvedCacheKey       string
	DestroySandboxAfterUse bool
}

type SandboxCleanupReceipt struct {
	InvocationID       string
	Recovery           SandboxRecoveryReference
	FileRemoved        bool
	EnvironmentCleared bool
	SandboxDestroyed   bool
}

type SandboxRecoveryReference = UseRecoveryBinding
type GatewayRecoveryReference = SandboxRecoveryReference

type SandboxExposurePermit struct {
	InvocationID     string
	RecoveryID       string
	ResolvedCacheKey string
	Recovery         SandboxRecoveryReference
	Durable          bool
}

type SandboxQuarantineReceipt struct {
	InvocationID     string
	RecoveryID       string
	ResolvedCacheKey string
	Durable          bool
}

type SandboxInjector interface {
	// Prepare is idempotent for the exact recovery ID and must durably bind the
	// complete recovery before returning Durable=true. Cleanup and Quarantine
	// must be idempotent for retries after acknowledgement loss. Implementations
	// must not retain CredentialMaterial after Use returns.
	Prepare(context.Context, SandboxDispatch, SandboxRecoveryReference) (SandboxExposurePermit, error)
	Use(context.Context, SandboxDispatch, SandboxExposurePermit, CredentialMaterial) (SandboxCleanupReceipt, error)
	Cleanup(context.Context, SandboxDispatch, SandboxExposurePermit) (SandboxCleanupReceipt, error)
	Quarantine(context.Context, SandboxDispatch, SandboxExposurePermit) (SandboxQuarantineReceipt, error)
}

type Config struct {
	Store                Store
	Authorizer           Authorizer
	Admitter             UseAdmitter
	Audit                AuditSink
	RecoveryAuthorizer   RecoveryAuthorizer
	RecoveryAudit        RecoveryAuditSink
	Gateway              GatewayDispatcher
	Sandbox              SandboxInjector
	TokenMinter          TokenMinter
	Now                  func() time.Time
	MaximumRequestBytes  int
	MaximumResponseBytes int
	MaximumSecretBytes   int
	MaximumTokenTTL      time.Duration
	HandleTTL            time.Duration
	RecoveryTimeout      time.Duration
	ServiceBinding       string
}
