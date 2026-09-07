// Package nsjail defines the NsJail sandbox conformance gate. It is the sandbox
// analogue of internal/conformance/celld: it enumerates the runtime isolation
// properties a provisioned NsJail launcher and kernel must prove for the single
// execution backend to qualify (SPEC §53.10), and produces one conformance
// Result per property.
//
// The component ids are the per-check ids required by internal/doctor's
// production ConformanceProfile (nsjail.namespace, nsjail.seccomp, …). Each check
// is its own conformance component — the same granularity the wired workerd gate
// (internal/conformance/workerd) already uses — so a real host run feeds the
// doctor profile directly. host.nftables-tool is a host-tool property produced by
// a host probe, not this sandbox gate.
//
// The checks themselves require a real NsJail binary running against a live
// kernel with user/mount/pid/ipc/uts/net namespaces, cgroup v2, and seccomp.
// Without a provisioned IsolationProbe this gate returns every component as
// UNAVAILABLE, never PASS — a reference or mock probe can only produce
// reference-only (non-promotable) evidence. §53.10 therefore stays UNAVAILABLE
// (NsJail is not installed on the development host) until this gate returns a
// fresh external PASS from a provisioned host; the executor's launch-plan tests
// (internal/executor/nsjail) verify the declarative config only and never satisfy
// this gate.
package nsjail

import (
	"context"
	"fmt"
	"strings"

	"github.com/hancomac/circulusd/internal/conformance"
)

// Check is one required NsJail runtime isolation property. Component is the
// conformance component id (matching internal/doctor's required nsjail set); ID
// is the stable semantic key the launch-plan verifier keys its static checks on.
type Check struct {
	ID          string
	Component   string
	Reference   string // the SPEC clause the check enforces
	Description string
}

// RequiredChecks returns the isolation properties a provisioned NsJail launch
// must satisfy. All must hold for §53.10 to qualify. Each check maps one-to-one
// to a doctor-required nsjail.* component, so a run cannot silently drop a
// boundary and the doctor profile cannot require a component nothing produces.
func RequiredChecks() []Check {
	return []Check{
		{
			ID:          "namespace-isolation",
			Component:   "nsjail.namespace",
			Reference:   "SPEC §53.10",
			Description: "USER, MOUNT, PID, IPC, UTS, and NET namespaces are applied to the sandboxed process",
		},
		{
			ID:          "uid-gid-mapping",
			Component:   "nsjail.unique-uid",
			Reference:   "SPEC §53.10",
			Description: "the sandbox host UID/GID are mapped to a unique unprivileged identity inside the user namespace",
		},
		{
			ID:          "rootfs-read-only",
			Component:   "nsjail.read-only-rootfs",
			Reference:   "SPEC §53.10",
			Description: "the sandbox root filesystem is mounted read-only",
		},
		{
			ID:          "write-confinement",
			Component:   "nsjail.workspace-roundtrip",
			Reference:   "SPEC §53.10",
			Description: "a write to the read-write workspace projection is visible on host readback and writes outside /workspace and scratch are denied",
		},
		{
			ID:          "host-path-nonexposure",
			Component:   "nsjail.host-path-invisibility",
			Reference:   "SPEC §53.10",
			Description: "host /home, /root, platform data, the Docker socket, and /dev/kvm are not exposed",
		},
		{
			ID:          "no-new-privs",
			Component:   "nsjail.no-new-privileges",
			Reference:   "SPEC §53.10",
			Description: "no_new_privs remains set so a privileged-exec cannot regain privileges",
		},
		{
			ID:          "no-retained-capabilities",
			Component:   "nsjail.capability-drop",
			Reference:   "SPEC §53.10",
			Description: "no ambient or effective capabilities are retained in the sandbox",
		},
		{
			ID:          "seccomp-deny",
			Component:   "nsjail.seccomp",
			Reference:   "SPEC §53.10",
			Description: "the seccomp policy denies a disallowed syscall",
		},
		{
			ID:          "cgroup-limits",
			Component:   "nsjail.cgroup-limits",
			Reference:   "SPEC §53.10",
			Description: "cgroup CPU, memory, and PID limits are applied to the sandbox",
		},
		{
			ID:          "network-default-deny",
			Component:   "nsjail.network-deny",
			Reference:   "SPEC §53.10",
			Description: "the sandbox has no external network connectivity by default",
		},
		{
			ID:          "timeout-cancel-teardown",
			Component:   "nsjail.process-cancel",
			Reference:   "SPEC §53.10",
			Description: "a timeout or cancellation terminates the whole process tree and cgroup",
		},
		{
			ID:          "sandboxd-private-uds",
			Component:   "nsjail.sandboxd-uds",
			Reference:   "SPEC §53.10",
			Description: "only the sandboxd private UDS is reachable from inside the jail",
		},
		{
			ID:          "resource-cleanup",
			Component:   "nsjail.destroy-cleanup",
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
// host pass nil and receive UNAVAILABLE for every component.
type IsolationProbe interface {
	Provenance() Provenance
	RunCheck(ctx context.Context, check Check) (CheckOutcome, error)
}

// QualifyReport runs the NsJail sandbox gate and returns one conformance Result
// per required component. A nil probe (no provisioned NsJail host) yields
// UNAVAILABLE for every component; a check that cannot run yields UNAVAILABLE for
// that component; a check that does not hold yields FAIL; a check that holds
// yields PASS with evidence whose class reflects whether the probe was a real
// external host or a reference one. Each component is independent, so a single
// failed boundary does not mask the status of the others.
func QualifyReport(ctx context.Context, probe IsolationProbe) conformance.Report {
	collector := conformance.NewCollector()
	if probe == nil {
		for _, check := range RequiredChecks() {
			_ = collector.Add(conformance.Result{
				Component: check.Component,
				Status:    conformance.Unavailable,
				Reason:    fmt.Sprintf("no provisioned NsJail host: %s (%s) requires a real NsJail binary and kernel with namespaces, cgroup v2, and seccomp; record UNAVAILABLE and leave §53.10 unqualified", check.ID, check.Reference),
				Evidence:  conformance.Evidence{Class: conformance.EvidenceClassExternal, ArtifactReferences: []conformance.ArtifactReference{}},
			})
		}
		return collector.Report()
	}

	provenance := probe.Provenance()
	for _, check := range RequiredChecks() {
		result := conformance.Result{Component: check.Component, Evidence: evidence(provenance)}
		outcome, err := probe.RunCheck(ctx, check)
		switch {
		case err != nil:
			result.Status = conformance.Unavailable
			result.Reason = fmt.Sprintf("isolation check %q could not run: %v", check.ID, err)
		case !outcome.Passed:
			result.Status = conformance.Fail
			result.Reason = fmt.Sprintf("isolation check %q (%s) failed", check.ID, check.Reference)
			if detail := strings.TrimSpace(outcome.Detail); detail != "" {
				result.Reason += ": " + detail
			}
		default:
			result.Status = conformance.Pass
		}
		_ = collector.Add(result)
	}
	return collector.Report()
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
