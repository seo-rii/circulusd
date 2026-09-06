package nsjail

import (
	"strings"

	contract "github.com/hancomac/circulusd/internal/conformance/nsjail"
)

// VerifyLaunchPlanIsolation statically checks that a compiled LaunchPlan's
// NsJail configuration declaratively encodes each SPEC §53.10 isolation property
// enumerated by internal/conformance/nsjail. It returns one bool per contract
// check ID (true = the plan text encodes the boundary).
//
// This is a host-independent, reference-first check (Unit 13.1): it proves the
// plan encodes the boundary a real kernel then enforces. It is NOT the external
// NsJail conformance gate — a real kernel/seccomp/cgroup run is still required to
// promote §53.10. A zero LaunchPlan encodes nothing and fails every check.
func VerifyLaunchPlanIsolation(plan LaunchPlan) map[string]bool {
	return verifyIsolationConfiguration(string(plan.configuration))
}

// verifyIsolationConfiguration is the core static check over the protobuf-text
// NsJail configuration, keyed by the conformance contract's check IDs so the
// verifier and the gate cannot drift.
func verifyIsolationConfiguration(config string) map[string]bool {
	results := make(map[string]bool, len(contract.RequiredChecks()))
	for _, check := range contract.RequiredChecks() {
		results[check.ID] = planEncodesIsolation(check.ID, config)
	}
	return results
}

func planEncodesIsolation(id, config string) bool {
	switch id {
	case "namespace-isolation":
		for _, namespace := range []string{
			"clone_newnet: true",
			"clone_newuser: true",
			"clone_newns: true",
			"clone_newpid: true",
			"clone_newipc: true",
			"clone_newuts: true",
		} {
			if !strings.Contains(config, namespace) {
				return false
			}
		}
		return true
	case "uid-gid-mapping":
		return strings.Contains(config, "uidmap {") && strings.Contains(config, "gidmap {")
	case "rootfs-read-only":
		return strings.Contains(config, "dst: \"/\"\n  is_bind: true\n  rw: false")
	case "write-confinement":
		return strings.Contains(config, "dst: \"/\"\n  is_bind: true\n  rw: false") &&
			strings.Contains(config, "dst: \"/workspace\"") &&
			strings.Contains(config, "dst: \"/scratch\"")
	case "host-path-nonexposure":
		for _, forbidden := range []string{
			"dst: \"/home\"",
			"dst: \"/root\"",
			"/dev/kvm",
			"docker.sock",
		} {
			if strings.Contains(config, forbidden) {
				return false
			}
		}
		return true
	case "no-new-privs":
		return strings.Contains(config, "disable_no_new_privs: false")
	case "no-retained-capabilities":
		return strings.Contains(config, "keep_caps: false")
	case "seccomp-deny":
		return strings.Contains(config, "seccomp_policy_file:")
	case "cgroup-limits":
		return strings.Contains(config, "cgroup_mem_max:") &&
			strings.Contains(config, "cgroup_pids_max:") &&
			strings.Contains(config, "cgroup_cpu_ms_per_sec:")
	case "network-default-deny":
		return strings.Contains(config, "clone_newnet: true")
	case "timeout-cancel-teardown":
		return strings.Contains(config, "time_limit:")
	case "sandboxd-private-uds":
		return strings.Contains(config, "dst: \"/run/circulusd/control\"")
	case "resource-cleanup":
		return strings.Contains(config, "mode: ONCE")
	default:
		return false
	}
}
