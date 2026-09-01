package doctor

import (
	"fmt"
	"slices"

	"github.com/hancomac/circulusd/internal/config"
	"github.com/hancomac/circulusd/internal/conformance"
)

func ConformanceProfile(
	installProfile config.InstallProfile,
	enabledBackends []config.Backend,
) (conformance.Profile, error) {
	backendSet := make(map[config.Backend]struct{}, len(enabledBackends))
	for _, backend := range enabledBackends {
		if backend != config.BackendNsJail &&
			backend != config.BackendDocker &&
			backend != config.BackendFirecracker {
			return conformance.Profile{}, fmt.Errorf("doctor: backend %q is unsupported", backend)
		}
		if _, duplicate := backendSet[backend]; duplicate {
			return conformance.Profile{}, fmt.Errorf("doctor: backend %q is duplicated", backend)
		}
		backendSet[backend] = struct{}{}
	}

	_, nsJailEnabled := backendSet[config.BackendNsJail]
	_, dockerEnabled := backendSet[config.BackendDocker]
	_, firecrackerEnabled := backendSet[config.BackendFirecracker]
	validMatrix := false
	switch installProfile {
	case config.InstallProfileLightweight:
		validMatrix = nsJailEnabled && !dockerEnabled && !firecrackerEnabled
	case config.InstallProfileDocker:
		validMatrix = !nsJailEnabled && dockerEnabled && !firecrackerEnabled
	case config.InstallProfileFirecracker:
		validMatrix = !nsJailEnabled && !dockerEnabled && firecrackerEnabled
	case config.InstallProfileFull:
		validMatrix = nsJailEnabled || dockerEnabled
	case config.InstallProfileDevelopment:
		validMatrix = (nsJailEnabled || dockerEnabled) && !firecrackerEnabled
	default:
		return conformance.Profile{}, fmt.Errorf(
			"doctor: install profile %q is unsupported",
			installProfile,
		)
	}
	if !validMatrix {
		return conformance.Profile{}, fmt.Errorf(
			"doctor: install profile %q does not match enabled backends",
			installProfile,
		)
	}

	required := make(map[string]struct{})
	for _, component := range []string{
		"audit.durable-chain",
		"audit.signed-checkpoint",
		"auth.durable-credentials",
		"configuration.fail-closed",
		"effect-recovery.boundary-matrix",
		"host.architecture",
		"host.cgroup-v2",
		"host.disk",
		"host.kernel",
		"host.namespace-handles",
		"host.scratch-quota",
		"object-store.bucket-access",
		"object-store.conditional-write",
		"object-store.concurrent-cas",
		"object-store.read-after-write",
		"object-store.restart-persistence",
		"release.signature",
		"state.kill-durability",
		"state.object-creation",
		"state.ownership-fencing",
		"state.recovery",
		"state.replication-rpo",
		"state.session-turn",
		"state.sqlite-transaction",
		"uds.protocol",
		"workerd.agent-engine",
		"workerd.content-addressed-replacement",
		"workerd.cpu-limit",
		"workerd.dynamic-worker",
		"workerd.dynamic-worker-reconstruction",
		"workerd.extension-order",
		"workerd.isolate-separation",
		"workerd.outbound-denial",
		"workerd.rss-cold-start",
		"workerd.shard-kill-reconstruction",
		"workerd.shard-pressure-recycle",
		"workerd.stable-broker-binding",
	} {
		required[component] = struct{}{}
	}
	if nsJailEnabled {
		for _, component := range []string{
			"host.nftables-tool",
			"nsjail.capability-drop",
			"nsjail.cgroup-limits",
			"nsjail.destroy-cleanup",
			"nsjail.host-path-invisibility",
			"nsjail.namespace",
			"nsjail.network-deny",
			"nsjail.no-new-privileges",
			"nsjail.process-cancel",
			"nsjail.read-only-rootfs",
			"nsjail.sandboxd-uds",
			"nsjail.seccomp",
			"nsjail.unique-uid",
			"nsjail.workspace-roundtrip",
		} {
			required[component] = struct{}{}
		}
	}
	if dockerEnabled {
		for _, component := range []string{
			"docker.creation",
			"docker.hardening",
			"docker.limits",
			"docker.network-deny",
			"docker.non-root",
			"docker.read-only-rootfs",
			"docker.sandboxd-uds",
			"docker.socket-invisibility",
			"docker.workspace-roundtrip",
			"host.nftables-tool",
		} {
			required[component] = struct{}{}
		}
	}
	if firecrackerEnabled {
		for _, component := range []string{
			"firecracker.boot",
			"firecracker.command",
			"firecracker.jailer",
			"firecracker.limits",
			"firecracker.no-nic",
			"firecracker.scratch-cleanup",
			"firecracker.unique-uid",
			"firecracker.vsock-sandboxd",
			"firecracker.workspace-roundtrip",
			"host.kvm-access",
		} {
			required[component] = struct{}{}
		}
	}

	components := make([]string, 0, len(required))
	for component := range required {
		components = append(components, component)
	}
	slices.Sort(components)
	return conformance.Profile{
		Name:       string(installProfile),
		Production: installProfile != config.InstallProfileDevelopment,
		Required:   components,
	}, nil
}
