package sessionplan_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/environment"
	"github.com/hancomac/circulusd/internal/executor"
	"github.com/hancomac/circulusd/internal/executor/nsjail"
	"github.com/hancomac/circulusd/internal/extensionregistry"
	"github.com/hancomac/circulusd/internal/identity"
	"github.com/hancomac/circulusd/internal/sessionplan"
)

func TestSignedEnvironmentBindsSessionSandboxAndDeclarativeLaunch(t *testing.T) {
	f := newFixture(t)
	p, err := sessionplan.New(f.registry(t), f.policy)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := p.Plan(context.Background(), f.request)
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Validate(); err != nil {
		t.Fatal(err)
	}
	runtime, env, spec, binding := plan.RuntimeRevision(), plan.Environment(), plan.SandboxSpec(), plan.SessionBinding()
	if env.Digest != f.environment.Digest || runtime.Environment.Digest != env.Digest || spec.EnvironmentDigest != env.Digest ||
		binding.EnvironmentDigest != env.Digest || binding.RuntimeRevisionDigest != runtime.Digest || binding.EnvironmentRevisionID != env.ID ||
		binding.TenantID != f.policy.TenantID || binding.UserID != f.request.UserID || binding.SessionID != f.request.SessionID || binding.WorkspaceID != f.request.WorkspaceID ||
		binding.Backend != executor.BackendNsJail || spec.Backend != executor.BackendNsJail || binding.Architecture != f.policy.Architecture ||
		spec.Scope.Kind != executor.ScopeSession || spec.Scope.Identity != f.request.SessionID.String() ||
		spec.LaunchAuthority.Generation() != f.policy.AuthorizationGeneration {
		t.Fatal("session and sandbox did not inherit the one compiled environment and trusted identity")
	}
	key, err := spec.CanonicalCacheKey()
	if err != nil || key != plan.CacheKey() {
		t.Fatalf("cache binding: %v", err)
	}
	ensure, err := plan.EnsureRequest()
	if err != nil || ensure.Mode != executor.DeploymentProduction || ensure.Spec != spec {
		t.Fatalf("ensure request: %v", err)
	}
	if len(runtime.Extensions) != 2 || len(env.Packages) != 2 {
		t.Fatal("requirements did not resolve together")
	}

	// Compile the real NsJail declarative launch plan, without starting a native
	// process or claiming that the host enforces this configuration.
	native, err := nsjail.NewPlanner(nsjail.Config{BinaryPath: "/usr/lib/circulusd/nsjail", EnvironmentRoot: "/var/lib/circulusd/environments",
		SandboxRoot: "/run/circulusd/sandboxes", CgroupRoot: "/sys/fs/cgroup/circulusd", SandboxdPath: "/usr/lib/circulusd/sandboxd",
		ProtocolVersion: 1, SandboxdClientUID: 65534, CommandManifestOwnerUID: 65534})
	if err != nil {
		t.Fatal(err)
	}
	launch, err := native.Build(nsjail.Request{SandboxID: id(t, identity.Sandbox, 9), Generation: 1, EnvironmentDigest: env.Digest,
		RootfsDigest: env.Artifacts.NsJail.RootfsDigest, SeccompProfileDigest: env.SeccompProfileDigest, SandboxdDigest: env.SandboxdDigest,
		HostUID: 65536, HostGID: 65537, WorkspaceAccess: spec.WorkspaceAccess, Network: nsjail.NetworkNone,
		Resources: nsjail.ResourceLimits{MemoryBytes: 256 << 20, MaximumProcesses: 64, CPUMillisPerSecond: 500, ScratchBytes: 64 << 20,
			TemporaryBytes: 16 << 20, RunBytes: 8 << 20, MaximumOpenFiles: 256, MaximumFileBytes: 64 << 20, MaximumLifetimeSeconds: 600}})
	if err != nil {
		t.Fatal(err)
	}
	if err := launch.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, encoded := range nsjail.VerifyLaunchPlanIsolation(launch) {
		if !encoded {
			t.Errorf("declarative isolation %s missing", name)
		}
	}
	text := string(launch.Configuration())
	if !strings.Contains(text, env.Digest) || !strings.Contains(text, env.Artifacts.NsJail.RootfsDigest) || strings.Contains(text, "/attacker/rootfs") {
		t.Fatal("launch artifacts did not come from the compiled environment")
	}
}

func TestPlanKeepsAgentAndNativeIsolationIndependent(t *testing.T) {
	for _, source := range []string{"policy", "extension", "assessment"} {
		t.Run(source, func(t *testing.T) {
			f := newFixture(t)
			switch source {
			case "policy":
				f.policy.MinimumIsolation.OuterIsolation = extensionregistry.OuterIsolationFirecracker
			case "extension":
				f.records[0].Revision.RequestedMinimumIsolation.OuterIsolation = extensionregistry.OuterIsolationFirecracker
				f.sign(t, 0)
			case "assessment":
				f.records[0].Assessment.MinimumIsolation.OuterIsolation = extensionregistry.OuterIsolationFirecracker
				f.sign(t, 0)
			}
			planner, err := sessionplan.New(f.registry(t), f.policy)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := planner.Plan(context.Background(), f.request)
			if err != nil {
				t.Fatal(err)
			}
			runtime := plan.RuntimeRevision()
			if runtime.MinimumIsolation.OuterIsolation != extensionregistry.OuterIsolationFirecracker ||
				runtime.MinimumIsolation.ProcessScope != extensionregistry.ProcessScopeSession {
				t.Fatalf("Agent minimum was weakened: %#v", runtime.MinimumIsolation)
			}
			ensure, err := plan.EnsureRequest()
			if err != nil {
				t.Fatal(err)
			}
			if runtime.Backend != environment.BackendNsJail || ensure.Spec.Backend != executor.BackendNsJail ||
				plan.SessionBinding().Backend != executor.BackendNsJail {
				t.Fatal("Agent isolation changed the independently selected native backend")
			}
		})
	}
}

func TestPlanningFailuresCannotProduceAnAdmissionOrProviderRequest(t *testing.T) {
	for _, name := range []string{"version conflict", "missing rootfs", "missing capability", "development capability", "native backend denied", "unknown extension", "foreign identity", "raw rootfs", "canceled", "unsigned revision"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch name {
			case "version conflict":
				f.records[1].Revision.NativeRequirements = []environment.Requirement{{PackageID: "python", Constraint: "2.7.x"}}
				f.sign(t, 1)
			case "missing rootfs":
				f.environment.Artifacts.NsJail = nil
				f.environment.Artifacts.Docker = &environment.DockerArtifact{ImageDigest: digest('9')}
				f.redigest(t)
			case "missing capability":
				f.policy.HostCapabilities[0].Available = false
				f.policy.HostCapabilities[0].UnavailableReason = "not provisioned"
			case "development capability":
				f.policy.HostCapabilities[0].DevelopmentOnly = true
			case "native backend denied":
				f.policy.AllowedBackends = []executor.Backend{executor.BackendFirecracker}
			case "unknown extension":
				f.request.Selections[0].Version = "9.9.9"
			case "foreign identity":
				f.request.SessionID = f.request.WorkspaceID
			case "raw rootfs":
				f.environment.Artifacts.NsJail.RootfsDigest = "/attacker/rootfs"
			case "canceled":
				cancel()
			case "unsigned revision":
				f.records[0].Revision.NativeRequirements[0].Constraint = "2.7.x"
			}
			var plan sessionplan.Plan
			registry, err := f.tryRegistry()
			if err == nil {
				var planner *sessionplan.Planner
				planner, err = sessionplan.New(registry, f.policy)
				if err == nil {
					plan, err = planner.Plan(ctx, f.request)
				}
			}
			if err == nil {
				t.Fatal("invalid composition accepted")
			}
			// These counters are ordering witnesses, not implementations claiming
			// native execution or admission durability.
			admissions, providerCalls := 0, 0
			if plan.Validate() == nil {
				admissions++
			}
			if _, requestErr := plan.EnsureRequest(); requestErr == nil {
				providerCalls++
			}
			if admissions != 0 || providerCalls != 0 {
				t.Fatal("failed planning produced a usable downstream request")
			}
		})
	}
}

func TestPlanSnapshotsPolicyRegistryInputsAndEveryReturnedSlice(t *testing.T) {
	f := newFixture(t)
	registry := f.registry(t)
	planner, err := sessionplan.New(registry, f.policy)
	if err != nil {
		t.Fatal(err)
	}
	f.policy.HostCapabilities[0].Available = false
	f.policy.AllowedBackends[0] = executor.BackendMock
	f.policy.Workerd.CompatibilityFlags[0] = "caller-changed"
	f.records[0].Revision.NativeRequirements[0].Constraint = "2.7.x"
	f.environment.Packages[0].Version = "2.7.0"
	f.environment.Artifacts.NsJail.RootfsDigest = digest('f')
	plan, err := planner.Plan(context.Background(), f.request)
	if err != nil {
		t.Fatal(err)
	}
	wantRuntime, wantEnv, wantBinding, wantSpec := plan.RuntimeRevision(), plan.Environment(), plan.SessionBinding(), plan.SandboxSpec()
	changedRuntime, changedEnv := plan.RuntimeRevision(), plan.Environment()
	changedRuntime.Workerd.CompatibilityFlags[0] = "getter-changed"
	changedRuntime.HookOrder[0] = "getter-changed"
	changedRuntime.Extensions[0].ID = "getter-changed"
	changedRuntime.Environment.Packages[0].Version = "0.0.0"
	changedRuntime.Environment.Artifacts.NsJail.RootfsDigest = digest('a')
	changedEnv.Packages[0].Version = "0.0.0"
	changedEnv.Artifacts.NsJail.RootfsDigest = digest('b')
	f.request.Selections[0].ID = "other/extension"
	f.request.Configuration["official/python"].(canonical.Map)["rootfs"] = "/different/path"
	if !reflect.DeepEqual(plan.RuntimeRevision(), wantRuntime) || !reflect.DeepEqual(plan.Environment(), wantEnv) || plan.SessionBinding() != wantBinding || plan.SandboxSpec() != wantSpec || plan.Validate() != nil {
		t.Fatal("caller mutation changed the sealed plan")
	}
}

func TestResolverCannotMutateTheRequestBeingCompiled(t *testing.T) {
	f := newFixture(t)
	resolver, err := environment.NewResolver([]environment.Revision{f.environment})
	if err != nil {
		t.Fatal(err)
	}
	f.resolver = resolverFunc(func(request environment.Request) (environment.Revision, error) {
		f.request.Selections[0].ID = "caller/mutated"
		f.request.Configuration["official/python"].(canonical.Map)["rootfs"] = "/changed/during/resolve"
		return resolver.Resolve(request)
	})
	planner, err := sessionplan.New(f.registry(t), f.policy)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planner.Plan(context.Background(), f.request)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := canonical.StructuredDigest("circulusd.runtime.extension-configuration", 1, canonical.Map{
		"official/python": canonical.Map{"rootfs": "/attacker/rootfs"}, "official/report": canonical.Map{},
	})
	if err != nil || plan.RuntimeRevision().ConfigurationDigest != expected {
		t.Fatalf("request changed during resolve: %v", err)
	}
}

func TestConcurrentPlansKeepSessionIdentityAndCacheSeparated(t *testing.T) {
	f := newFixture(t)
	planner, err := sessionplan.New(f.registry(t), f.policy)
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	keys := make(chan executor.CacheKey, 12)
	for index := byte(20); index < 32; index++ {
		request := f.request
		request.SessionID = id(t, identity.Session, index)
		group.Add(1)
		go func() {
			defer group.Done()
			plan, err := planner.Plan(context.Background(), request)
			if err != nil {
				t.Error(err)
				return
			}
			if plan.SessionBinding().SessionID != request.SessionID {
				t.Error("cross-session plan")
			}
			keys <- plan.CacheKey()
		}()
	}
	group.Wait()
	close(keys)
	unique := make(map[executor.CacheKey]bool)
	for key := range keys {
		unique[key] = true
	}
	if len(unique) != 12 {
		t.Fatalf("session cache keys = %d", len(unique))
	}
}

func TestPlannerRejectsInvalidConstructionAndZeroPlans(t *testing.T) {
	f := newFixture(t)
	if _, err := sessionplan.New(nil, f.policy); !errors.Is(err, sessionplan.ErrInvalidPolicy) {
		t.Fatalf("nil registry: %v", err)
	}
	for _, mutate := range []func(*sessionplan.Policy){
		func(p *sessionplan.Policy) { p.TenantID = identity.ID{} },
		func(p *sessionplan.Policy) { p.AuthorizationGeneration = 0 },
		func(p *sessionplan.Policy) { p.ResourceDigest = "/raw/path" },
		func(p *sessionplan.Policy) { p.Mode = "" },
	} {
		policy := f.policy
		mutate(&policy)
		if _, err := sessionplan.New(f.registry(t), policy); !errors.Is(err, sessionplan.ErrInvalidPolicy) {
			t.Fatalf("invalid policy: %v", err)
		}
	}
	var plan sessionplan.Plan
	if !errors.Is(plan.Validate(), sessionplan.ErrInvalidPlan) {
		t.Fatal("zero plan accepted")
	}
	if _, err := plan.EnsureRequest(); !errors.Is(err, sessionplan.ErrInvalidPlan) {
		t.Fatal("zero plan produced ensure request")
	}
}

type resolverFunc func(environment.Request) (environment.Revision, error)

func (f resolverFunc) Resolve(request environment.Request) (environment.Revision, error) {
	return f(request)
}

type fixture struct {
	roots       extensionregistry.TrustRoots
	records     []extensionregistry.SignedRevision
	environment environment.Revision
	resolver    extensionregistry.EnvironmentResolver
	policy      sessionplan.Policy
	request     sessionplan.Request
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	bundle := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	assessment := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	f := &fixture{roots: extensionregistry.TrustRoots{Bundle: map[string]ed25519.PublicKey{"bundle": bundle.Public().(ed25519.PublicKey)},
		Assessment: map[string]ed25519.PublicKey{"assessment": assessment.Public().(ed25519.PublicKey)}}}
	f.environment = environment.Revision{ID: id(t, identity.EnvironmentRevision, 1), Architecture: environment.ArchitectureX8664,
		Packages:       []environment.Package{{ID: "python", Version: "3.13.2", Digest: digest('1')}, {ID: "jq", Version: "1.7.0", Digest: digest('2')}},
		SandboxdDigest: digest('3'), SeccompProfileDigest: digest('4'), FilesystemPolicyDigest: digest('5'),
		Artifacts: environment.BackendArtifacts{NsJail: &environment.NsJailArtifact{RootfsDigest: digest('6')}}}
	f.redigest(t)
	for i, name := range []string{"python", "report"} {
		revision := extensionregistry.CompiledRevision{ID: "official/" + name, Version: "1.0.0", Publisher: "platform", ContentDigest: digest(byte('a' + i)),
			RevisionDigest: digest(byte('c' + i)), BundleDigest: digest('1'), BundleSize: 1024, SBOMDigest: digest('2'), ConfigurationSchemaDigest: "sha256:a2c799262a3ce3c19ef5cdd983bf3d12b43ab3c426227091b909dcb7054738c0", ConfigurationSchema: []byte(`{"type":"object"}`),
			Tools: []string{name + ".run"}, NativeRequirements: []environment.Requirement{{PackageID: "python", Constraint: "3.13.x"}},
			SupportedBackends: []environment.Backend{environment.BackendNsJail}, StateSchemaVersion: 1,
			RequestedMinimumIsolation: extensionregistry.Isolation{ProcessScope: extensionregistry.ProcessScopeSession, OuterIsolation: extensionregistry.OuterIsolationNsJail}}
		if i == 1 {
			revision.NativeRequirements = []environment.Requirement{{PackageID: "jq", Constraint: "1.7.x"}}
		}
		f.records = append(f.records, extensionregistry.SignedRevision{Revision: revision, Assessment: extensionregistry.SecurityAssessment{
			ExtensionDigest: revision.ContentDigest, TrustClass: extensionregistry.TrustClassPlatformReviewed, AssessedAt: "2026-10-08T00:00:00Z",
			MinimumIsolation: revision.RequestedMinimumIsolation, AllowedExecutionBackends: []environment.Backend{environment.BackendNsJail}}})
		f.sign(t, i)
	}
	f.policy = sessionplan.Policy{TenantID: id(t, identity.Tenant, 2), Architecture: environment.ArchitectureX8664, Mode: executor.DeploymentProduction,
		AllowedBackends: []executor.Backend{executor.BackendNsJail}, HostCapabilities: []executor.Capability{{Backend: executor.BackendNsJail, Available: true}},
		MinimumIsolation:        extensionregistry.Isolation{ProcessScope: extensionregistry.ProcessScopeSession, OuterIsolation: extensionregistry.OuterIsolationNsJail},
		AuthorizationGeneration: 7, PolicyGeneration: 3, ResourceDigest: digest('7'), NetworkDigest: digest('8'), EffectivePolicyDigest: digest('9'),
		SecretExposure: executor.SecretProxyOnly, SandboxProtocolVersion: 1, IdleTimeoutSeconds: 60, MaximumLifetimeSeconds: 600, WorkspaceAccess: executor.WorkspaceReadWrite,
		Workerd: extensionregistry.WorkerdRevision{BinaryDigest: digest('a'), CompatibilityDate: "2026-08-01", CompatibilityFlags: []string{"nodejs_compat"}, LoaderABIVersion: 1},
		Pi:      extensionregistry.PiRevision{PackageDigest: digest('b'), AdapterABIVersion: 1, AgentEngine: "low-level"}}
	f.request = sessionplan.Request{SessionID: id(t, identity.Session, 3), WorkspaceID: id(t, identity.Workspace, 4), UserID: id(t, identity.Subject, 5),
		Selections:    []extensionregistry.Selection{{ID: "official/python", Version: "1.0.0"}, {ID: "official/report", Version: "1.0.0"}},
		Configuration: canonical.Map{"official/python": canonical.Map{"rootfs": "/attacker/rootfs"}, "official/report": canonical.Map{}}}
	return f
}

func (f *fixture) redigest(t *testing.T) {
	t.Helper()
	var err error
	f.environment.Digest, err = environment.DigestRevision(f.environment)
	if err != nil {
		t.Fatal(err)
	}
}
func (f *fixture) sign(t *testing.T, index int) {
	t.Helper()
	record := &f.records[index]
	d, err := extensionregistry.BundleSignatureDigest(record.Revision, "bundle")
	if err != nil {
		t.Fatal(err)
	}
	record.BundleSignature = extensionregistry.Signature{KeyID: "bundle", Value: ed25519.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)), []byte(d))}
	record.Assessment.Signature.KeyID = "assessment"
	d, err = extensionregistry.AssessmentSignatureDigest(record.Assessment)
	if err != nil {
		t.Fatal(err)
	}
	record.Assessment.Signature.Value = ed25519.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32)), []byte(d))
}
func (f *fixture) tryRegistry() (*extensionregistry.Registry, error) {
	resolver := f.resolver
	if resolver == nil {
		var err error
		resolver, err = environment.NewResolver([]environment.Revision{f.environment})
		if err != nil {
			return nil, err
		}
	}
	return extensionregistry.New(f.roots, f.records, resolver)
}
func (f *fixture) registry(t *testing.T) *extensionregistry.Registry {
	t.Helper()
	registry, err := f.tryRegistry()
	if err != nil {
		t.Fatal(err)
	}
	return registry
}
func digest(fill byte) string { return "sha256:" + strings.Repeat(string(fill), 64) }
func id(t *testing.T, kind identity.Kind, fill byte) identity.ID {
	t.Helper()
	value, err := (identity.Generator{Random: bytes.NewReader(bytes.Repeat([]byte{fill}, 16))}).New(kind)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
