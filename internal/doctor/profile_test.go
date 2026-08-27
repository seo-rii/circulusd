package doctor

import (
	"slices"
	"testing"

	"github.com/hancomac/circulusd/internal/config"
)

func TestConformanceProfileSelectsOnlyTheConfiguredBackendGates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		profile    config.InstallProfile
		backends   []config.Backend
		production bool
		included   []string
		excluded   []string
	}{
		{
			name:       "lightweight",
			profile:    config.InstallProfileLightweight,
			backends:   []config.Backend{config.BackendNsJail},
			production: true,
			included:   []string{"nsjail.namespace", "host.nftables-tool"},
			excluded:   []string{"docker.creation", "firecracker.boot", "host.kvm-access"},
		},
		{
			name:       "docker",
			profile:    config.InstallProfileDocker,
			backends:   []config.Backend{config.BackendDocker},
			production: true,
			included:   []string{"docker.creation", "host.nftables-tool"},
			excluded:   []string{"nsjail.namespace", "firecracker.boot", "host.kvm-access"},
		},
		{
			name:       "firecracker",
			profile:    config.InstallProfileFirecracker,
			backends:   []config.Backend{config.BackendFirecracker},
			production: true,
			included:   []string{"firecracker.boot", "host.kvm-access"},
			excluded:   []string{"nsjail.namespace", "docker.creation", "host.nftables-tool"},
		},
		{
			name:       "full",
			profile:    config.InstallProfileFull,
			backends:   []config.Backend{config.BackendNsJail, config.BackendDocker, config.BackendFirecracker},
			production: true,
			included:   []string{"nsjail.namespace", "docker.creation", "firecracker.boot", "host.kvm-access", "host.nftables-tool"},
		},
		{
			name:       "development",
			profile:    config.InstallProfileDevelopment,
			backends:   []config.Backend{config.BackendNsJail, config.BackendDocker},
			production: false,
			included:   []string{"nsjail.namespace", "docker.creation"},
			excluded:   []string{"firecracker.boot", "host.kvm-access"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			profile, err := ConformanceProfile(test.profile, test.backends)
			if err != nil {
				t.Fatalf("ConformanceProfile() error = %v", err)
			}
			if profile.Name != string(test.profile) || profile.Production != test.production {
				t.Fatalf("ConformanceProfile() = %+v", profile)
			}
			if !slices.IsSorted(profile.Required) {
				t.Fatalf("ConformanceProfile().Required is not sorted: %v", profile.Required)
			}
			for _, component := range []string{
				"host.architecture",
				"host.kernel",
				"host.scratch-quota",
				"state.kill-durability",
				"object-store.concurrent-cas",
				"workerd.dynamic-worker",
				"effect-recovery.boundary-matrix",
				"auth.durable-credentials",
				"audit.durable-chain",
				"release.signature",
				"uds.protocol",
			} {
				if !slices.Contains(profile.Required, component) {
					t.Errorf("ConformanceProfile().Required lacks common gate %q", component)
				}
			}
			for _, component := range test.included {
				if !slices.Contains(profile.Required, component) {
					t.Errorf("ConformanceProfile().Required lacks %q", component)
				}
			}
			for _, component := range test.excluded {
				if slices.Contains(profile.Required, component) {
					t.Errorf("ConformanceProfile().Required unexpectedly contains %q", component)
				}
			}
		})
	}
}

func TestConformanceProfileRejectsAmbiguousBackendMatrices(t *testing.T) {
	t.Parallel()

	tests := []struct {
		profile  config.InstallProfile
		backends []config.Backend
	}{
		{profile: config.InstallProfileLightweight},
		{profile: config.InstallProfileLightweight, backends: []config.Backend{config.BackendDocker}},
		{profile: config.InstallProfileDocker, backends: []config.Backend{config.BackendDocker, config.BackendDocker}},
		{profile: config.InstallProfileFirecracker, backends: []config.Backend{config.BackendFirecracker, config.BackendNsJail}},
		{profile: config.InstallProfileDevelopment, backends: []config.Backend{config.BackendFirecracker}},
		{profile: config.InstallProfile("future"), backends: []config.Backend{config.BackendNsJail}},
	}
	for index, test := range tests {
		if _, err := ConformanceProfile(test.profile, test.backends); err == nil {
			t.Fatalf("ConformanceProfile(tests[%d]) error = nil", index)
		}
	}
}
