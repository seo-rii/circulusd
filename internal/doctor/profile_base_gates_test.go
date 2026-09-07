package doctor

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/hancomac/circulusd/internal/config"
	"github.com/hancomac/circulusd/internal/conformance/audit"
	"github.com/hancomac/circulusd/internal/conformance/auth"
	"github.com/hancomac/circulusd/internal/conformance/configuration"
	"github.com/hancomac/circulusd/internal/conformance/state"
)

// TestBaseGatesProduceExactlyTheDoctorRequiredComponents ties the production
// ConformanceProfile to the base (backend-independent) gate producers: for each
// prefix, every component the gate emits must be required by the profile, and every
// profile-required component under that prefix must be produced by the gate. This is
// the guard that keeps internal/doctor and internal/conformance/{state,audit,auth,
// configuration} from drifting: a renamed or dropped component fails here.
//
// Only the prefixes these gates own are checked. The collapsed state.celld
// aggregate (internal/conformance/celld) is intentionally not a profile requirement
// and is produced by a different gate, so it is not part of the state gate's set;
// the host.*, object-store.*, effect-recovery.*, release.*, uds.*, and workerd.*
// families have their own producers and guards.
func TestBaseGatesProduceExactlyTheDoctorRequiredComponents(t *testing.T) {
	t.Parallel()

	profile, err := ConformanceProfile(
		config.InstallProfileFull,
		[]config.Backend{config.BackendNsJail, config.BackendDocker},
	)
	if err != nil {
		t.Fatalf("ConformanceProfile() error = %v", err)
	}

	ctx := context.Background()
	families := []struct {
		name     string
		prefix   string
		produced []string
	}{
		{name: "state", prefix: "state.", produced: producedComponents(state.QualifyReport(ctx, nil))},
		{name: "audit", prefix: "audit.", produced: producedComponents(audit.QualifyReport(ctx, nil))},
		{name: "auth", prefix: "auth.", produced: producedComponents(auth.QualifyReport(ctx, nil))},
		{name: "configuration", prefix: "configuration.", produced: producedComponents(configuration.QualifyReport(ctx, nil))},
	}

	for _, family := range families {
		t.Run(family.name, func(t *testing.T) {
			t.Parallel()
			if len(family.produced) == 0 {
				t.Fatalf("%s gate produced no components", family.name)
			}
			// Every produced component is required by the profile and under the prefix.
			for _, component := range family.produced {
				if !strings.HasPrefix(component, family.prefix) {
					t.Errorf("%s gate produced %q outside the %q prefix", family.name, component, family.prefix)
				}
				if !slices.Contains(profile.Required, component) {
					t.Errorf("profile does not require produced component %q", component)
				}
			}
			// Every profile-required component under this prefix is produced.
			for _, required := range profile.Required {
				if !strings.HasPrefix(required, family.prefix) {
					continue
				}
				if !slices.Contains(family.produced, required) {
					t.Errorf("profile requires %q but the %s gate does not produce it", required, family.name)
				}
			}
		})
	}
}
