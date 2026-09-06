// Package nsjail defines the NsJail sandbox conformance gate. It is the sandbox
// analogue of internal/conformance/celld: it enumerates the runtime isolation
// properties a provisioned NsJail launcher and kernel must prove for the single
// execution backend to qualify (SPEC §53.10), and produces a conformance.Result.
//
// The checks themselves require a real NsJail binary running against a live
// kernel with user/mount/pid/ipc/uts/net namespaces, cgroup v2, and seccomp.
// Without a provisioned IsolationProbe this gate returns UNAVAILABLE, never PASS
// — a reference or mock probe can only produce reference-only (non-promotable)
// evidence. §53.10 therefore stays UNAVAILABLE (NsJail is not installed on the
// development host) until this gate returns a fresh external PASS from a
// provisioned host; the executor's launch-plan tests (internal/executor/nsjail)
// verify the declarative config only and never satisfy this gate.
package nsjail

import (
	"context"
	"fmt"
	"strings"

	"github.com/hancomac/circulusd/internal/conformance"
)

// Component is the conformance component id for the NsJail sandbox gate.
const Component = "sandbox.nsjail"

// Check is one required NsJail runtime isolation property.
type Check struct {
	ID          string
	Reference   string // the SPEC clause the check enforces
	Description string
}

// RequiredChecks returns the isolation properties a provisioned NsJail launch
// must satisfy. All must hold for the gate to PASS. The set mirrors SPEC §53.10
// one-to-one so a real run cannot silently drop a boundary.
func RequiredChecks() []Check {
	return []Check{
		{
			ID:          "namespace-isolation",
			Reference:   "SPEC §53.10",
			Description: "USER, MOUNT, PID, IPC, UTS, and NET namespaces are applied to the sandboxed process",
		},
		{
			ID:          "uid-gid-mapping",
			Reference:   "SPEC §53.10",
			Description: "the sandbox host UID/GID are mapped per policy inside the user namespace",
		},
		{
			ID:          "rootfs-read-only",
			Reference:   "SPEC §53.10",
			Description: "the sandbox root filesystem is mounted read-only",
		},
		{
			ID:          "write-confinement",
			Reference:   "SPEC §53.10",
			Description: "writes outside /workspace and scratch are denied",
		},
		{
			ID:          "host-path-nonexposure",
			Reference:   "SPEC §53.10",
			Description: "host /home, /root, platform data, the Docker socket, and /dev/kvm are not exposed",
		},
		{
			ID:          "no-new-privs",
			Reference:   "SPEC §53.10",
			Description: "no_new_privs remains set so a privileged-exec cannot regain privileges",
		},
		{
			ID:          "no-retained-capabilities",
			Reference:   "SPEC §53.10",
			Description: "no ambient or effective capabilities are retained in the sandbox",
		},
		{
			ID:          "seccomp-deny",
			Reference:   "SPEC §53.10",
			Description: "the seccomp policy denies a disallowed syscall",
		},
		{
			ID:          "cgroup-limits",
			Reference:   "SPEC §53.10",
			Description: "cgroup CPU, memory, and PID limits are applied to the sandbox",
		},
		{
			ID:          "network-default-deny",
			Reference:   "SPEC §53.10",
			Description: "the sandbox has no external network connectivity by default",
		},
		{
			ID:          "timeout-cancel-teardown",
			Reference:   "SPEC §53.10",
			Description: "a timeout or cancellation terminates the whole process tree and cgroup",
		},
		{
			ID:          "sandboxd-private-uds",
			Reference:   "SPEC §53.10",
			Description: "only the sandboxd private UDS is reachable from inside the jail",
		},
		{
			ID:          "resource-cleanup",
			Reference:   "SPEC §53.10",
			Description: "after destroy the namespaces, cgroup, veth, and scratch are reclaimed",
		},
	}
}

// Provenance is the release and host identity of the qualified NsJail launcher.
// Reference marks a non-production (reference or mock) probe whose PASS is not
// promotable.
type Provenance struct {
	Version           string
	BinaryDigest      string // canonical sha256:... or empty
	EnvironmentDigest string // canonical sha256:... or empty
	Kernel            string
	Architecture      string
	Reference         bool
}

// CheckOutcome is the result of running one isolation check against a live jail.
type CheckOutcome struct {
	Passed bool
	Detail string
}

// IsolationProbe drives the isolation checks against a provisioned NsJail
// launcher and kernel. The production implementation is external work against a
// real NsJail host; there is no in-process implementation, so callers without a
// host pass nil and receive UNAVAILABLE.
type IsolationProbe interface {
	Provenance() Provenance
	RunCheck(ctx context.Context, check Check) (CheckOutcome, error)
}

// Qualify runs the NsJail sandbox gate. A nil probe (no provisioned NsJail host)
// yields UNAVAILABLE; a check that cannot run yields UNAVAILABLE; a check that
// does not hold yields FAIL; all checks holding yields PASS with evidence whose
// class reflects whether the probe was a real external host or a reference one.
func Qualify(ctx context.Context, probe IsolationProbe) conformance.Result {
	if probe == nil {
		return conformance.Result{
			Component: Component,
			Status:    conformance.Unavailable,
			Reason:    "no provisioned NsJail host: the sandbox gate requires a real NsJail binary and kernel with namespaces, cgroup v2, and seccomp; record UNAVAILABLE and leave §53.10 unqualified",
			Evidence:  conformance.Evidence{Class: conformance.EvidenceClassExternal, ArtifactReferences: []conformance.ArtifactReference{}},
		}
	}

	provenance := probe.Provenance()
	for _, check := range RequiredChecks() {
		outcome, err := probe.RunCheck(ctx, check)
		if err != nil {
			return conformance.Result{
				Component: Component,
				Status:    conformance.Unavailable,
				Reason:    fmt.Sprintf("isolation check %q could not run: %v", check.ID, err),
				Evidence:  evidence(provenance),
			}
		}
		if !outcome.Passed {
			reason := fmt.Sprintf("isolation check %q (%s) failed", check.ID, check.Reference)
			if detail := strings.TrimSpace(outcome.Detail); detail != "" {
				reason += ": " + detail
			}
			return conformance.Result{
				Component: Component,
				Status:    conformance.Fail,
				Reason:    reason,
				Evidence:  evidence(provenance),
			}
		}
	}
	return conformance.Result{
		Component: Component,
		Status:    conformance.Pass,
		Evidence:  evidence(provenance),
	}
}

func evidence(provenance Provenance) conformance.Evidence {
	result := conformance.Evidence{
		Version:            provenance.Version,
		BinaryDigest:       provenance.BinaryDigest,
		EnvironmentDigest:  provenance.EnvironmentDigest,
		Kernel:             provenance.Kernel,
		Architecture:       provenance.Architecture,
		ArtifactReferences: []conformance.ArtifactReference{},
	}
	if provenance.Reference {
		// A reference probe can never carry external evidence: mark it mock and
		// reference-only so the production profile rejects it.
		result.Class = conformance.EvidenceClassReferenceOnly
		result.Mock = true
		result.BinaryDigest = ""
		result.EnvironmentDigest = ""
	} else {
		result.Class = conformance.EvidenceClassExternal
	}
	return result
}
