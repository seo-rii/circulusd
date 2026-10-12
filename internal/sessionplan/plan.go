// Package sessionplan composes signed extension compilation and exact NsJail
// selection into one immutable session/sandbox plan. Planning performs no
// session admission, provider calls or filesystem operations. Its output is
// configuration, not an authorization or production-conformance proof; callers
// must retain their admission, workspace-lease and host qualification gates.
package sessionplan

import (
	"context"
	"errors"
	"fmt"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/environment"
	"github.com/hancomac/circulusd/internal/executor"
	"github.com/hancomac/circulusd/internal/extensionregistry"
	"github.com/hancomac/circulusd/internal/identity"
)

var (
	ErrInvalidPolicy  = errors.New("session plan: invalid trusted policy")
	ErrInvalidRequest = errors.New("session plan: invalid request")
	ErrInvalidPlan    = errors.New("session plan: invalid plan")
)

const maximumSharedInteger = uint64(9_007_199_254_740_991)

// Policy is supplied by trusted composition, not public JSON or extension
// configuration. The first single-node profile always selects NsJail with no
// fallback. Capability availability does not attest kernel qualification.
type Policy struct {
	TenantID                identity.ID
	Architecture            environment.Architecture
	Mode                    executor.DeploymentMode
	AllowedBackends         []executor.Backend
	HostCapabilities        []executor.Capability
	MinimumIsolation        extensionregistry.Isolation
	AuthorizationGeneration uint64
	PolicyGeneration        uint64
	Workerd                 extensionregistry.WorkerdRevision
	Pi                      extensionregistry.PiRevision
	ResourceDigest          string
	NetworkDigest           string
	EffectivePolicyDigest   string
	SecretExposure          executor.SecretExposureClass
	SandboxProtocolVersion  uint32
	IdleTimeoutSeconds      uint32
	MaximumLifetimeSeconds  uint32
	WorkspaceAccess         executor.WorkspaceAccess
}

// Request chooses signed extension coordinates and their configuration. It
// cannot select host paths, environment artifacts, runtime binaries, backend,
// tenant or weaker policy. User and workspace authorization remains external.
type Request struct {
	SessionID     identity.ID
	WorkspaceID   identity.ID
	UserID        identity.ID
	Selections    []extensionregistry.Selection
	Configuration canonical.Map
}

type Planner struct {
	registry  *extensionregistry.Registry
	policy    Policy
	authority executor.LaunchAuthority
}

// SessionBinding is the immutable identity/configuration projection for session
// creation. IDs are comparison targets which still require trusted admission
// authorization. It carries no lease, checkpoint or admission authority.
type SessionBinding struct {
	TenantID                identity.ID
	UserID                  identity.ID
	SessionID               identity.ID
	WorkspaceID             identity.ID
	RuntimeRevisionDigest   string
	EnvironmentDigest       string
	EnvironmentRevisionID   identity.ID
	Architecture            environment.Architecture
	Backend                 executor.Backend
	PolicyGeneration        uint64
	AuthorizationGeneration uint64
}

var planSeal = new(struct{})

// Plan has no exported mutable state. Its private seal proves validated,
// immutable configuration only, never authorization or host qualification.
// Copy getters never lend out registry, policy, environment or runtime slices.
// The zero Plan is unusable.
type Plan struct {
	seal    *struct{}
	mode    executor.DeploymentMode
	binding SessionBinding
	runtime extensionregistry.RuntimeRevision
	sandbox executor.SandboxSpec
	cache   executor.CacheKey
}

// New retains the registry's immutable signed records. Registry revalidates its
// resolver's returned environment on every compilation; an injected resolver
// must itself support concurrent Resolve calls. Policy slices are snapshotted.
func New(registry *extensionregistry.Registry, policy Policy) (*Planner, error) {
	if registry == nil || policy.TenantID.Kind() != identity.Tenant ||
		policy.AuthorizationGeneration < 1 || policy.AuthorizationGeneration > maximumSharedInteger ||
		policy.PolicyGeneration < 1 || policy.PolicyGeneration > maximumSharedInteger ||
		(policy.Architecture != environment.ArchitectureX8664 && policy.Architecture != environment.ArchitectureAArch64) {
		return nil, ErrInvalidPolicy
	}
	policy.AllowedBackends = append([]executor.Backend(nil), policy.AllowedBackends...)
	policy.HostCapabilities = append([]executor.Capability(nil), policy.HostCapabilities...)
	policy.Workerd.CompatibilityFlags = append([]string(nil), policy.Workerd.CompatibilityFlags...)
	authority, err := executor.NewLaunchAuthority(policy.TenantID, policy.AuthorizationGeneration)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPolicy, err)
	}
	planner := &Planner{registry: registry, policy: policy, authority: authority}
	// This validates static sandbox-policy fields; the temporary spec is never
	// returned. The real environment and session scope are populated only after
	// signed runtime compilation succeeds.
	if _, err := planner.sandbox(policy.EffectivePolicyDigest, "policy-validation").CanonicalCacheKey(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPolicy, err)
	}
	if _, err := executor.ResolveBackend(planner.selection([]executor.Backend{executor.BackendNsJail})); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPolicy, err)
	}
	return planner, nil
}

func (planner *Planner) Plan(ctx context.Context, request Request) (Plan, error) {
	if ctx == nil || planner == nil || planner.registry == nil {
		return Plan{}, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return Plan{}, err
	}
	if request.SessionID.Kind() != identity.Session || request.WorkspaceID.Kind() != identity.Workspace || request.UserID.Kind() != identity.Subject ||
		len(request.Selections) < 1 || len(request.Selections) > 256 || request.Configuration == nil {
		return Plan{}, ErrInvalidRequest
	}
	// Snapshot selections before compilation. Registry owns and validates a
	// deep extension-JSON configuration snapshot before invoking its resolver,
	// preserving finite numeric options as well as caller-mutation isolation.
	selections := append([]extensionregistry.Selection(nil), request.Selections...)
	policy := planner.policy
	runtime, err := planner.registry.CompileRuntime(extensionregistry.CompileRequest{
		Selections: selections, Configuration: request.Configuration, Workerd: policy.Workerd, Pi: policy.Pi,
		Architecture: policy.Architecture, Backend: environment.BackendNsJail,
		PolicyGeneration: policy.PolicyGeneration, PolicyMinimumIsolation: policy.MinimumIsolation,
	})
	if err != nil {
		return Plan{}, fmt.Errorf("compile session runtime: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Plan{}, err
	}
	// Registry checks each signed extension and assessment against NsJail and
	// revalidates the resolver result. Never accept a caller's artifact list.
	artifacts := make([]executor.Backend, 0, 3)
	if runtime.Environment.Artifacts.NsJail != nil {
		artifacts = append(artifacts, executor.BackendNsJail)
	}
	if runtime.Environment.Artifacts.Docker != nil {
		artifacts = append(artifacts, executor.BackendDocker)
	}
	if runtime.Environment.Artifacts.Firecracker != nil {
		artifacts = append(artifacts, executor.BackendFirecracker)
	}
	selected, err := executor.ResolveBackend(planner.selection(artifacts))
	if err != nil {
		return Plan{}, fmt.Errorf("select session backend: %w", err)
	}
	if selected.Resolved != executor.BackendNsJail || selected.FallbackUsed || selected.SecurityDowngrade || runtime.Backend != environment.BackendNsJail {
		return Plan{}, ErrInvalidPlan
	}
	sandbox := planner.sandbox(runtime.Environment.Digest, request.SessionID.String())
	cache, err := sandbox.CanonicalCacheKey()
	if err != nil {
		return Plan{}, fmt.Errorf("plan session sandbox: %w", err)
	}
	return Plan{
		seal: planSeal, mode: policy.Mode, runtime: cloneRuntime(runtime), sandbox: sandbox, cache: cache,
		binding: SessionBinding{TenantID: policy.TenantID, UserID: request.UserID, SessionID: request.SessionID, WorkspaceID: request.WorkspaceID,
			RuntimeRevisionDigest: runtime.Digest, EnvironmentDigest: runtime.Environment.Digest, EnvironmentRevisionID: runtime.Environment.ID,
			Architecture: policy.Architecture, Backend: executor.BackendNsJail, PolicyGeneration: policy.PolicyGeneration,
			AuthorizationGeneration: policy.AuthorizationGeneration},
	}, nil
}

func (planner *Planner) selection(artifacts []executor.Backend) executor.BackendSelection {
	minimum := executor.IsolationSharedKernel
	if planner.policy.MinimumIsolation.OuterIsolation == extensionregistry.OuterIsolationFirecracker {
		minimum = executor.IsolationMicroVM
	}
	return executor.BackendSelection{Mode: planner.policy.Mode, ToolOrSession: executor.BackendNsJail,
		ServerAllowed: planner.policy.AllowedBackends, RegistryAllowed: []executor.Backend{executor.BackendNsJail},
		ExtensionSupported: []executor.Backend{executor.BackendNsJail}, EnvironmentArtifacts: artifacts,
		HostCapabilities: planner.policy.HostCapabilities, MinimumIsolation: minimum,
		Fallback: executor.BackendFallbackPolicy{Mode: executor.FallbackDisabled}}
}

func (planner *Planner) sandbox(environmentDigest, sessionID string) executor.SandboxSpec {
	p := planner.policy
	return executor.SandboxSpec{LaunchAuthority: planner.authority, Backend: executor.BackendNsJail, EnvironmentDigest: environmentDigest,
		ResourceDigest: p.ResourceDigest, NetworkDigest: p.NetworkDigest, EffectivePolicyDigest: p.EffectivePolicyDigest,
		SecretExposure: p.SecretExposure, SandboxProtocolVersion: p.SandboxProtocolVersion, IdleTimeoutSeconds: p.IdleTimeoutSeconds,
		MaximumLifetimeSeconds: p.MaximumLifetimeSeconds, WorkspaceAccess: p.WorkspaceAccess, Projection: executor.ProjectionMaterializedManifest,
		Scope: executor.SandboxScope{Kind: executor.ScopeSession, Identity: sessionID}}
}

func (plan Plan) Validate() error {
	if plan.seal != planSeal || plan.binding.SessionID.Kind() != identity.Session ||
		plan.binding.RuntimeRevisionDigest != plan.runtime.Digest || plan.binding.EnvironmentDigest != plan.runtime.Environment.Digest ||
		plan.binding.EnvironmentDigest != plan.sandbox.EnvironmentDigest || plan.binding.EnvironmentRevisionID != plan.runtime.Environment.ID ||
		plan.binding.Backend != executor.BackendNsJail || plan.sandbox.Backend != executor.BackendNsJail ||
		plan.sandbox.Scope.Kind != executor.ScopeSession || plan.sandbox.Scope.Identity != plan.binding.SessionID.String() {
		return ErrInvalidPlan
	}
	cache, err := plan.sandbox.CanonicalCacheKey()
	if err != nil || cache != plan.cache {
		return ErrInvalidPlan
	}
	return nil
}

func (plan Plan) SessionBinding() SessionBinding    { return plan.binding }
func (plan Plan) SandboxSpec() executor.SandboxSpec { return plan.sandbox }
func (plan Plan) CacheKey() executor.CacheKey       { return plan.cache }
func (plan Plan) RuntimeRevision() extensionregistry.RuntimeRevision {
	return cloneRuntime(plan.runtime)
}
func (plan Plan) Environment() environment.Revision {
	return cloneEnvironment(plan.runtime.Environment)
}

// EnsureRequest preserves the exact planned backend and deployment mode. It is
// still subject to the real provider's admission and qualification checks.
func (plan Plan) EnsureRequest() (executor.EnsureRequest, error) {
	if err := plan.Validate(); err != nil {
		return executor.EnsureRequest{}, err
	}
	return executor.EnsureRequest{Mode: plan.mode, Spec: plan.sandbox}, nil
}

func cloneRuntime(value extensionregistry.RuntimeRevision) extensionregistry.RuntimeRevision {
	value.Workerd.CompatibilityFlags = append([]string(nil), value.Workerd.CompatibilityFlags...)
	value.Extensions = append([]extensionregistry.ResolvedExtension(nil), value.Extensions...)
	value.HookOrder = append([]string(nil), value.HookOrder...)
	value.Environment = cloneEnvironment(value.Environment)
	return value
}

func cloneEnvironment(value environment.Revision) environment.Revision {
	value.Packages = append([]environment.Package(nil), value.Packages...)
	if value.Artifacts.NsJail != nil {
		artifact := *value.Artifacts.NsJail
		value.Artifacts.NsJail = &artifact
	}
	if value.Artifacts.Docker != nil {
		artifact := *value.Artifacts.Docker
		value.Artifacts.Docker = &artifact
	}
	if value.Artifacts.Firecracker != nil {
		artifact := *value.Artifacts.Firecracker
		value.Artifacts.Firecracker = &artifact
	}
	return value
}
