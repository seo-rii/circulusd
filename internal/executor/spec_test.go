package executor_test

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/hancomac/circulusd/internal/executor"
	"github.com/hancomac/circulusd/internal/identity"
)

const (
	digest00 = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	digest11 = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	digest22 = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	digest33 = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
)

func TestSandboxSpecCanonicalCacheKey(t *testing.T) {
	t.Parallel()

	base := validSpec()
	want, err := base.CanonicalCacheKey()
	if err != nil {
		t.Fatalf("CanonicalCacheKey() error = %v", err)
	}
	if got := want.String(); got != "sha256:18aa36d75e74fc8bfd20b1b9971cc7a21c4fd963d85af21085aae6389a24de37" {
		t.Fatalf("CanonicalCacheKey().String() = %q", got)
	}

	tests := []struct {
		name   string
		mutate func(*executor.SandboxSpec)
	}{
		{name: "tenant authority", mutate: func(spec *executor.SandboxSpec) {
			spec.LaunchAuthority = launchAuthority(1, 1)
		}},
		{name: "backend", mutate: func(spec *executor.SandboxSpec) { spec.Backend = executor.BackendDocker }},
		{name: "environment digest", mutate: func(spec *executor.SandboxSpec) { spec.EnvironmentDigest = digest11 }},
		{name: "resource digest", mutate: func(spec *executor.SandboxSpec) { spec.ResourceDigest = digest22 }},
		{name: "network digest", mutate: func(spec *executor.SandboxSpec) { spec.NetworkDigest = digest33 }},
		{name: "effective policy digest", mutate: func(spec *executor.SandboxSpec) { spec.EffectivePolicyDigest = digest00 }},
		{name: "secret exposure", mutate: func(spec *executor.SandboxSpec) { spec.SecretExposure = executor.SecretSandboxEnv }},
		{name: "sandbox protocol version", mutate: func(spec *executor.SandboxSpec) { spec.SandboxProtocolVersion = 2 }},
		{name: "idle timeout", mutate: func(spec *executor.SandboxSpec) { spec.IdleTimeoutSeconds = 61 }},
		{name: "maximum lifetime", mutate: func(spec *executor.SandboxSpec) { spec.MaximumLifetimeSeconds = 3_601 }},
		{name: "workspace access", mutate: func(spec *executor.SandboxSpec) { spec.WorkspaceAccess = executor.WorkspaceReadWrite }},
		{name: "projection", mutate: func(spec *executor.SandboxSpec) { spec.Projection = executor.ProjectionFUSEExperimental }},
		{name: "scope kind", mutate: func(spec *executor.SandboxSpec) { spec.Scope.Kind = executor.ScopeSession }},
		{name: "scope identity", mutate: func(spec *executor.SandboxSpec) { spec.Scope.Identity = "ws_2" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			changed := base
			tt.mutate(&changed)
			got, err := changed.CanonicalCacheKey()
			if err != nil {
				t.Fatalf("CanonicalCacheKey() error = %v", err)
			}
			if got == want {
				t.Fatalf("CanonicalCacheKey() did not include %s", tt.name)
			}
		})
	}

	again, err := base.CanonicalCacheKey()
	if err != nil {
		t.Fatalf("second CanonicalCacheKey() error = %v", err)
	}
	if again != want {
		t.Fatalf("CanonicalCacheKey() is not deterministic: %v != %v", again, want)
	}

	sameTenant := base
	sameTenant.LaunchAuthority = launchAuthority(0, 2)
	sameTenantKey, err := sameTenant.CanonicalCacheKey()
	if err != nil {
		t.Fatalf("CanonicalCacheKey(same tenant authority) error = %v", err)
	}
	if sameTenantKey != want {
		t.Fatal("ephemeral launch authority identity changed the sandbox cache key")
	}
}

func TestSandboxSpecValidationFailsClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*executor.SandboxSpec)
	}{
		{name: "missing launch authority", mutate: func(spec *executor.SandboxSpec) { spec.LaunchAuthority = executor.LaunchAuthority{} }},
		{name: "unknown backend", mutate: func(spec *executor.SandboxSpec) { spec.Backend = executor.Backend("podman") }},
		{name: "missing environment digest", mutate: func(spec *executor.SandboxSpec) { spec.EnvironmentDigest = "" }},
		{name: "uppercase digest", mutate: func(spec *executor.SandboxSpec) { spec.ResourceDigest = "sha256:" + strings.Repeat("A", 64) }},
		{name: "malformed digest", mutate: func(spec *executor.SandboxSpec) { spec.NetworkDigest = "sha256:no" }},
		{name: "unknown secret exposure", mutate: func(spec *executor.SandboxSpec) { spec.SecretExposure = executor.SecretExposureClass("raw") }},
		{name: "zero sandbox protocol version", mutate: func(spec *executor.SandboxSpec) { spec.SandboxProtocolVersion = 0 }},
		{name: "zero idle timeout", mutate: func(spec *executor.SandboxSpec) { spec.IdleTimeoutSeconds = 0 }},
		{name: "zero maximum lifetime", mutate: func(spec *executor.SandboxSpec) { spec.MaximumLifetimeSeconds = 0 }},
		{name: "idle exceeds lifetime", mutate: func(spec *executor.SandboxSpec) { spec.IdleTimeoutSeconds = 3_601 }},
		{name: "unknown workspace access", mutate: func(spec *executor.SandboxSpec) { spec.WorkspaceAccess = executor.WorkspaceAccess("host") }},
		{name: "unknown projection", mutate: func(spec *executor.SandboxSpec) { spec.Projection = executor.WorkspaceProjection("virtiofs") }},
		{name: "unknown scope kind", mutate: func(spec *executor.SandboxSpec) { spec.Scope.Kind = executor.ScopeKind("tenant") }},
		{name: "empty scope identity", mutate: func(spec *executor.SandboxSpec) { spec.Scope.Identity = "" }},
		{name: "scope identity nul", mutate: func(spec *executor.SandboxSpec) { spec.Scope.Identity = "ws\x00bad" }},
		{name: "scope identity invalid utf8", mutate: func(spec *executor.SandboxSpec) { spec.Scope.Identity = string([]byte{'w', 0xff}) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			spec := validSpec()
			tt.mutate(&spec)
			if _, err := spec.CanonicalCacheKey(); !errors.Is(err, executor.ErrInvalidSpec) {
				t.Fatalf("CanonicalCacheKey() error = %v, want ErrInvalidSpec", err)
			}
		})
	}
}

func TestLaunchAuthorityIsOpaqueAndValidated(t *testing.T) {
	t.Parallel()

	authority := launchAuthority(7, 1)
	if authority.IsZero() || authority.Generation() != 1 {
		t.Fatalf("launch authority = %#v", authority)
	}
	for _, formatted := range []string{
		fmt.Sprintf("%s", authority),
		fmt.Sprintf("%v", authority),
		fmt.Sprintf("%#v", authority),
	} {
		if strings.Contains(formatted, "tenant_") {
			t.Fatalf("formatted launch authority leaked tenant identity: %q", formatted)
		}
	}

	subject, err := (identity.Generator{Random: bytes.NewReader(make([]byte, 16))}).New(identity.Subject)
	if err != nil {
		t.Fatalf("identity.New(subject) error = %v", err)
	}
	if _, err := executor.NewLaunchAuthority(subject, 1); !errors.Is(err, executor.ErrInvalidSpec) {
		t.Fatalf("NewLaunchAuthority(subject) error = %v, want ErrInvalidSpec", err)
	}
	tenant, err := (identity.Generator{Random: bytes.NewReader(make([]byte, 16))}).New(identity.Tenant)
	if err != nil {
		t.Fatalf("identity.New(tenant) error = %v", err)
	}
	if _, err := executor.NewLaunchAuthority(tenant, 0); !errors.Is(err, executor.ErrInvalidSpec) {
		t.Fatalf("NewLaunchAuthority(generation 0) error = %v, want ErrInvalidSpec", err)
	}
}

func validSpec() executor.SandboxSpec {
	return executor.SandboxSpec{
		LaunchAuthority:        launchAuthority(0, 1),
		Backend:                executor.BackendMock,
		EnvironmentDigest:      digest00,
		ResourceDigest:         digest11,
		NetworkDigest:          digest22,
		EffectivePolicyDigest:  digest33,
		SecretExposure:         executor.SecretProxyOnly,
		SandboxProtocolVersion: 1,
		IdleTimeoutSeconds:     60,
		MaximumLifetimeSeconds: 3_600,
		WorkspaceAccess:        executor.WorkspaceReadOnly,
		Projection:             executor.ProjectionMaterializedManifest,
		Scope: executor.SandboxScope{
			Kind:     executor.ScopeWorkspace,
			Identity: "ws_1",
		},
	}
}

func launchAuthority(fill byte, generation uint64) executor.LaunchAuthority {
	tenant, err := (identity.Generator{Random: bytes.NewReader(bytes.Repeat([]byte{fill}, 16))}).New(identity.Tenant)
	if err != nil {
		panic(err)
	}
	authority, err := executor.NewLaunchAuthority(tenant, generation)
	if err != nil {
		panic(err)
	}
	return authority
}
