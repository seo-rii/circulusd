package doctor

import (
	"context"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/hancomac/circulusd/internal/config"
	"github.com/hancomac/circulusd/internal/conformance"
	"github.com/hancomac/circulusd/internal/conformance/docker"
	"github.com/hancomac/circulusd/internal/conformance/firecracker"
	"github.com/hancomac/circulusd/internal/conformance/nsjail"
)

// producedComponents is the set of conformance component ids a sandbox gate emits.
// A nil probe yields one UNAVAILABLE result per required component, so the report's
// component set is exactly what the gate can produce on a provisioned host.
func producedComponents(report conformance.Report) []string {
	components := make([]string, 0, len(report.Results))
	for _, result := range report.Results {
		components = append(components, result.Component)
	}
	sort.Strings(components)
	return components
}

// TestSandboxGatesProduceExactlyTheDoctorRequiredBackendComponents ties the
// production ConformanceProfile to the gate producers: for each sandbox backend,
// every component the gate emits must be required by the profile, and every
// profile-required component under that backend prefix must be produced by the
// gate. host.* components (host.nftables-tool, host.kvm-access) come from host
// probes, not the sandbox gates, so they are excluded by prefix. This is the guard
// that keeps internal/doctor and internal/conformance/{nsjail,docker,firecracker}
// from drifting: a renamed or dropped component fails here.
func TestSandboxGatesProduceExactlyTheDoctorRequiredBackendComponents(t *testing.T) {
	t.Parallel()

	profile, err := ConformanceProfile(
		config.InstallProfileFull,
		[]config.Backend{config.BackendNsJail, config.BackendDocker, config.BackendFirecracker},
	)
	if err != nil {
		t.Fatalf("ConformanceProfile() error = %v", err)
	}

	ctx := context.Background()
	backends := []struct {
		name     string
		prefix   string
		produced []string
	}{
		{name: "nsjail", prefix: "nsjail.", produced: producedComponents(nsjail.QualifyReport(ctx, nil))},
		{name: "docker", prefix: "docker.", produced: producedComponents(docker.QualifyReport(ctx, nil))},
		{name: "firecracker", prefix: "firecracker.", produced: producedComponents(firecracker.QualifyReport(ctx, nil))},
	}

	for _, backend := range backends {
		t.Run(backend.name, func(t *testing.T) {
			t.Parallel()
			if len(backend.produced) == 0 {
				t.Fatalf("%s gate produced no components", backend.name)
			}
			// Every produced component is required by the profile.
			for _, component := range backend.produced {
				if !strings.HasPrefix(component, backend.prefix) {
					t.Errorf("%s gate produced %q outside the %q prefix", backend.name, component, backend.prefix)
				}
				if !slices.Contains(profile.Required, component) {
					t.Errorf("profile does not require produced component %q", component)
				}
			}
			// Every profile-required component under this backend prefix is produced.
			for _, required := range profile.Required {
				if !strings.HasPrefix(required, backend.prefix) {
					continue
				}
				if !slices.Contains(backend.produced, required) {
					t.Errorf("profile requires %q but the %s gate does not produce it", required, backend.name)
				}
			}
		})
	}
}
