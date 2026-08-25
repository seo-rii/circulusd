// Package executor defines backend-neutral sandbox lifecycle contracts.
package executor

import (
	"context"
	"errors"
	"fmt"

	"github.com/hancomac/circulusd/internal/identity"
)

var (
	ErrInvalidSpec        = errors.New("invalid sandbox spec")
	ErrUnavailable        = errors.New("execution provider unavailable")
	ErrDevelopmentOnly    = errors.New("development-only execution provider")
	ErrBackendMismatch    = errors.New("execution backend mismatch")
	ErrBackendUnavailable = errors.New("requested execution backend is unavailable")
	ErrSecurityDowngrade  = errors.New("execution backend security downgrade is not permitted")
	ErrUnknownHandle      = errors.New("unknown sandbox handle")
	ErrStaleHandle        = errors.New("stale sandbox handle")
	ErrSandboxDraining    = errors.New("sandbox is draining")
	ErrSandboxStopped     = errors.New("sandbox is stopped")
)

// Backend identifies one native execution implementation. Mock is reserved
// for development and contract testing; it is not a native execution backend.
type Backend string

const (
	BackendNsJail      Backend = "nsjail"
	BackendDocker      Backend = "docker"
	BackendFirecracker Backend = "firecracker"
	BackendMock        Backend = "mock"
)

// DeploymentMode determines whether development-only behavior may be used.
type DeploymentMode string

const (
	DeploymentDevelopment DeploymentMode = "development"
	DeploymentProduction  DeploymentMode = "production"
)

// IsolationClass is the minimum kernel-isolation boundary a tool policy may
// require. NsJail and Docker are both shared-kernel backends; neither is
// treated as universally stronger than the other.
type IsolationClass string

const (
	IsolationSharedKernel IsolationClass = "shared-kernel"
	IsolationMicroVM      IsolationClass = "microvm"
)

// FallbackMode determines whether a failed exact backend choice may consider
// an administrator-declared ordered alternative list.
type FallbackMode string

const (
	FallbackDisabled FallbackMode = "disabled"
	FallbackExplicit FallbackMode = "explicit"
)

// BackendFallbackPolicy is explicit configuration, never an implicit retry
// strategy. Mock cannot be a fallback for a native backend.
type BackendFallbackPolicy struct {
	Mode                   FallbackMode
	Order                  []Backend
	AllowSecurityDowngrade bool
}

// BackendSelection contains every independent availability constraint from
// SPEC.md section 19.2. An empty higher-priority preference falls through to
// the next default, but every constraint set itself must be explicit.
type BackendSelection struct {
	Mode                 DeploymentMode
	ToolOrSession        Backend
	WorkspaceDefault     Backend
	UserDefault          Backend
	ServerDefault        Backend
	ServerAllowed        []Backend
	RegistryAllowed      []Backend
	ExtensionSupported   []Backend
	EnvironmentArtifacts []Backend
	HostCapabilities     []Capability
	MinimumIsolation     IsolationClass
	Fallback             BackendFallbackPolicy
}

// BackendSelectionResult records both sides of a fallback decision for API
// responses and audit. Eligible is canonical and ordered independently of
// caller slice ordering.
type BackendSelectionResult struct {
	Requested         Backend
	Resolved          Backend
	Eligible          []Backend
	FallbackUsed      bool
	SecurityDowngrade bool
}

// WorkspaceAccess is the authority granted to the sandbox projection.
type WorkspaceAccess string

const (
	WorkspaceReadOnly  WorkspaceAccess = "read-only"
	WorkspaceReadWrite WorkspaceAccess = "read-write"
)

// WorkspaceProjection identifies the filesystem projection contract.
type WorkspaceProjection string

const (
	ProjectionMaterializedManifest WorkspaceProjection = "materialized-manifest"
	ProjectionFUSEExperimental     WorkspaceProjection = "fuse-experimental"
)

// ScopeKind determines the process-state reuse boundary.
type ScopeKind string

const (
	ScopeWorkspace  ScopeKind = "workspace"
	ScopeSession    ScopeKind = "session"
	ScopeInvocation ScopeKind = "invocation"
)

// SandboxScope binds a sandbox cache entry to one opaque scope identity.
type SandboxScope struct {
	Kind     ScopeKind
	Identity string
}

// SecretExposureClass partitions sandbox reuse by the strongest form of
// credential material exposed to a process in that sandbox.
type SecretExposureClass string

const (
	SecretProxyOnly       SecretExposureClass = "proxy-only"
	SecretGatewayHeader   SecretExposureClass = "gateway-header"
	SecretSandboxEnv      SecretExposureClass = "sandbox-env"
	SecretSandboxFile     SecretExposureClass = "sandbox-file"
	SecretShortLivedToken SecretExposureClass = "short-lived-token"
)

// LaunchAuthority is an opaque broker-created sandbox admission object. It
// captures the tenant boundary without exposing a caller-selectable tenant ID
// in SandboxSpec. Its generation fences stale launch requests but deliberately
// does not affect the reusable sandbox cache key.
type LaunchAuthority struct {
	tenant     identity.ID
	generation uint64
}

// NewLaunchAuthority is a trusted broker boundary. Untrusted extension input
// must never call it or supply its tenant argument.
func NewLaunchAuthority(tenant identity.ID, generation uint64) (LaunchAuthority, error) {
	if tenant.Kind() != identity.Tenant || tenant.String() == "" {
		return LaunchAuthority{}, fmt.Errorf("%w: launch authority requires a tenant identity", ErrInvalidSpec)
	}
	if generation == 0 {
		return LaunchAuthority{}, fmt.Errorf("%w: launch authority generation must be positive", ErrInvalidSpec)
	}
	return LaunchAuthority{tenant: tenant, generation: generation}, nil
}

func (authority LaunchAuthority) IsZero() bool {
	return authority == LaunchAuthority{}
}

func (authority LaunchAuthority) Generation() uint64 {
	return authority.generation
}

func (authority LaunchAuthority) String() string {
	if authority.IsZero() {
		return "sandbox-launch-authority<zero>"
	}
	return fmt.Sprintf("sandbox-launch-authority<generation=%d>", authority.generation)
}

func (authority LaunchAuthority) GoString() string {
	return authority.String()
}

// LifecycleState is the host-side sandbox resource state. Stop completes at
// LifecycleStopped and intentionally retains the resource record. Destroy
// advances it to LifecycleDestroyed, after which EnsureSandbox may create a
// new fenced generation.
type LifecycleState string

const (
	LifecycleReady     LifecycleState = "ready"
	LifecycleDraining  LifecycleState = "draining"
	LifecycleStopped   LifecycleState = "stopped"
	LifecycleDestroyed LifecycleState = "destroyed"
)

// CacheKey is the comparable, canonical identity of all sandbox reuse inputs.
// Its bytes are intentionally private so callers cannot bypass validation.
type CacheKey struct {
	digest [32]byte
}

func (key CacheKey) String() string {
	return fmt.Sprintf("sha256:%x", key.digest)
}

// SandboxHandle is an opaque provider-scoped authority. Its monotonic
// generation is exposed for logging and fencing diagnostics; callers cannot
// construct a non-zero valid handle because all authority fields are private.
type SandboxHandle struct {
	providerID uint64
	slotID     uint64
	generation uint64
}

func (handle SandboxHandle) Generation() uint64 {
	return handle.generation
}

func (handle SandboxHandle) IsZero() bool {
	return handle == SandboxHandle{}
}

func (handle SandboxHandle) String() string {
	if handle.IsZero() {
		return "sandbox-handle<zero>"
	}
	return fmt.Sprintf("sandbox-handle<generation=%d>", handle.generation)
}

// Capability reports whether a provider can admit work in a deployment mode.
// UnavailableReason must be non-empty whenever Available is false.
type Capability struct {
	Backend           Backend
	Available         bool
	UnavailableReason string
	DevelopmentOnly   bool
}

// EnsureRequest asks a provider to reuse or create the canonical sandbox.
type EnsureRequest struct {
	Mode DeploymentMode
	Spec SandboxSpec
}

// EnsureResult reports whether an existing ready sandbox was reused.
type EnsureResult struct {
	Handle   SandboxHandle
	CacheKey CacheKey
	Reused   bool
}

// SandboxHealth is an immutable point-in-time lifecycle view.
type SandboxHealth struct {
	Handle        SandboxHandle
	State         LifecycleState
	Healthy       bool
	AcceptingWork bool
}

// SandboxSnapshot is a defensive copy of one provider-owned resource record.
type SandboxSnapshot struct {
	Handle   SandboxHandle
	CacheKey CacheKey
	Spec     SandboxSpec
	State    LifecycleState
}

// FaultPoint identifies a deterministic provider boundary available to fault
// injection and crash-recovery contract tests.
type FaultPoint string

const (
	FaultCapabilities FaultPoint = "capabilities"
	FaultEnsure       FaultPoint = "ensure"
	FaultStopDraining FaultPoint = "stop-draining"
	FaultDestroy      FaultPoint = "destroy"
	FaultHealth       FaultPoint = "health"
	FaultSnapshot     FaultPoint = "snapshot"
)

// FaultMetadata carries non-secret correlation information to a fault
// injector. An injector must not call the same lifecycle operation recursively.
type FaultMetadata struct {
	Backend  Backend
	CacheKey CacheKey
	Handle   SandboxHandle
	State    LifecycleState
}

// FaultInjector is supplied to provider constructors by conformance tests.
// Implementations must be safe for every operation they allow concurrently.
type FaultInjector interface {
	Inject(context.Context, FaultPoint, FaultMetadata) error
}

// FaultInjectorFunc adapts a function to FaultInjector.
type FaultInjectorFunc func(context.Context, FaultPoint, FaultMetadata) error

func (function FaultInjectorFunc) Inject(
	ctx context.Context,
	point FaultPoint,
	metadata FaultMetadata,
) error {
	return function(ctx, point, metadata)
}

// Provider is the backend-neutral sandbox control contract. Backend-specific
// process and materialization APIs are intentionally outside this foundational
// lifecycle unit and can be layered through adapters later.
type Provider interface {
	Capabilities(context.Context, DeploymentMode) (Capability, error)
	EnsureSandbox(context.Context, EnsureRequest) (EnsureResult, error)
	Stop(context.Context, SandboxHandle) error
	Destroy(context.Context, SandboxHandle) error
	Health(context.Context, SandboxHandle) (SandboxHealth, error)
	Snapshot(context.Context) ([]SandboxSnapshot, error)
}
