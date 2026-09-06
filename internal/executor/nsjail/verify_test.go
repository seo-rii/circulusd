package nsjail

import (
	"strings"
	"testing"

	contract "github.com/hancomac/circulusd/internal/conformance/nsjail"
)

func TestVerifyLaunchPlanIsolationAcceptsTheHardenedProductionPlan(t *testing.T) {
	t.Parallel()
	planner, err := NewPlanner(validConfig())
	if err != nil {
		t.Fatalf("NewPlanner() error = %v", err)
	}
	plan, err := planner.Build(validRequest(t))
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	results := VerifyLaunchPlanIsolation(plan)
	for _, check := range contract.RequiredChecks() {
		got, ok := results[check.ID]
		if !ok {
			t.Fatalf("verifier did not cover §53.10 contract check %q", check.ID)
		}
		if !got {
			t.Fatalf("the hardened production plan failed §53.10 check %q", check.ID)
		}
	}
	if len(results) != len(contract.RequiredChecks()) {
		t.Fatalf("verifier returned %d results, want exactly %d", len(results), len(contract.RequiredChecks()))
	}
}

func TestVerifyLaunchPlanIsolationRejectsWeakenedConfigurations(t *testing.T) {
	t.Parallel()
	planner, err := NewPlanner(validConfig())
	if err != nil {
		t.Fatalf("NewPlanner() error = %v", err)
	}
	plan, err := planner.Build(validRequest(t))
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	base := string(plan.Configuration())

	tests := []struct {
		name   string
		check  string
		weaken func(string) string
	}{
		{
			name:  "retained capabilities",
			check: "no-retained-capabilities",
			weaken: func(config string) string {
				return strings.Replace(config, "keep_caps: false", "keep_caps: true", 1)
			},
		},
		{
			name:  "regained privileges",
			check: "no-new-privs",
			weaken: func(config string) string {
				return strings.Replace(config, "disable_no_new_privs: false", "disable_no_new_privs: true", 1)
			},
		},
		{
			name:  "writable rootfs",
			check: "rootfs-read-only",
			weaken: func(config string) string {
				return strings.Replace(
					config,
					"dst: \"/\"\n  is_bind: true\n  rw: false",
					"dst: \"/\"\n  is_bind: true\n  rw: true",
					1,
				)
			},
		},
		{
			name:  "disabled seccomp",
			check: "seccomp-deny",
			weaken: func(config string) string {
				return strings.Replace(config, "seccomp_policy_file:", "seccomp_disabled:", 1)
			},
		},
		{
			name:  "shared network namespace",
			check: "namespace-isolation",
			weaken: func(config string) string {
				return strings.Replace(config, "clone_newnet: true", "clone_newnet: false", 1)
			},
		},
		{
			name:  "unbounded cgroup",
			check: "cgroup-limits",
			weaken: func(config string) string {
				return strings.Replace(config, "cgroup_mem_max:", "cgroup_mem_unbounded:", 1)
			},
		},
		{
			name:  "docker socket exposed",
			check: "host-path-nonexposure",
			weaken: func(config string) string {
				return config + "mount {\n  src: \"/var/run/docker.sock\"\n  dst: \"/var/run/docker.sock\"\n  is_bind: true\n  rw: true\n}\n"
			},
		},
		{
			name:  "persistent jail",
			check: "resource-cleanup",
			weaken: func(config string) string {
				return strings.Replace(config, "mode: ONCE", "mode: LISTEN", 1)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			weakened := test.weaken(base)
			if weakened == base {
				t.Fatalf("weakening %q did not change the configuration", test.name)
			}
			// The hardened plan passes this check.
			if !verifyIsolationConfiguration(base)[test.check] {
				t.Fatalf("hardened base unexpectedly failed §53.10 check %q", test.check)
			}
			// The weakened plan must fail exactly this check.
			if verifyIsolationConfiguration(weakened)[test.check] {
				t.Fatalf("weakened config still passed §53.10 check %q", test.check)
			}
		})
	}
}
