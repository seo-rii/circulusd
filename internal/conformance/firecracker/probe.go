// Package firecracker defines the Firecracker sandbox conformance gate. It is
// the microVM analogue of internal/conformance/nsjail: it enumerates the
// isolation properties a provisioned Firecracker jailer and KVM host must prove
// for the Firecracker execution backend to qualify (SPEC §53.12), and produces
// one conformance Result per property.
//
// The component ids are the per-check ids required by internal/doctor's
// production ConformanceProfile (firecracker.jailer, firecracker.no-nic, …).
// Each check is its own conformance component — the same granularity the wired
// workerd gate already uses — so a real host run feeds the doctor profile
// directly. host.kvm-access is a host-tool property produced by a host probe,
// not this sandbox gate.
//
// The checks require a real Firecracker binary, jailer, and /dev/kvm. Without a
// provisioned IsolationProbe this gate returns every component as UNAVAILABLE,
// never PASS — a reference or mock probe can only produce reference-only
// (non-promotable) evidence. §53.12 therefore stays UNAVAILABLE (Firecracker,
// the jailer, and /dev/kvm are absent on the development host) until this gate
// returns a fresh external PASS from a provisioned host.
package firecracker

import (
	"context"
	"fmt"
	"strings"

	"github.com/hancomac/circulusd/internal/conformance"
)

// Check is one required Firecracker microVM isolation property. Component is the
// conformance component id (matching internal/doctor's required firecracker set);
// ID is the stable semantic key.
type Check struct {
	ID          string
	Component   string
	Reference   string // the SPEC clause the check enforces
	Description string
}

// RequiredChecks returns the isolation properties a provisioned Firecracker
// microVM must satisfy. All must hold for §53.12 to qualify. Each check maps
// one-to-one to a doctor-required firecracker.* component, so a run cannot
// silently drop a boundary and the doctor profile cannot require a component
// nothing produces.
func RequiredChecks() []Check {
	return []Check{
		{
			ID:          "boot",
			Component:   "firecracker.boot",
			Reference:   "SPEC §53.12",
			Description: "the microVM boots the pinned guest kernel and rootfs, and there is no silent fallback when /dev/kvm is unsupported",
		},
		{
			ID:          "command",
			Component:   "firecracker.command",
			Reference:   "SPEC §53.12",
			Description: "the dispatched command runs inside the guest and its result is returned over the control channel",
		},
		{
			ID:          "jailer",
			Component:   "firecracker.jailer",
			Reference:   "SPEC §53.12",
			Description: "the microVM is launched through the Firecracker jailer, which restricts access to the API socket",
		},
		{
			ID:          "resource-limits",
			Component:   "firecracker.limits",
			Reference:   "SPEC §53.12",
			Description: "vCPU, memory, and scratch limits are applied to the microVM",
		},
		{
			ID:          "no-guest-nic",
			Component:   "firecracker.no-nic",
			Reference:   "SPEC §53.12",
			Description: "in network mode none the guest has no NIC",
		},
		{
			ID:          "scratch-discard",
			Component:   "firecracker.scratch-cleanup",
			Reference:   "SPEC §53.12",
			Description: "scratch is discarded after the microVM shuts down",
		},
		{
			ID:          "unique-microvm-uid-gid",
			Component:   "firecracker.unique-uid",
			Reference:   "SPEC §53.12",
			Description: "each microVM runs under a unique UID/GID",
		},
		{
			ID:          "control-channel-vsock",
			Component:   "firecracker.vsock-sandboxd",
			Reference:   "SPEC §53.12",
			Description: "the sandbox control channel is a vsock to sandboxd, not a guest network path",
		},
		{
			ID:          "workspace-roundtrip",
			Component:   "firecracker.workspace-roundtrip",
			Reference:   "SPEC §53.12",
			Description: "a write to the read-write workspace projection is visible on host readback and writes outside it are denied",
		},
	}
}

// Provenance is the release and host identity of the qualified Firecracker host.
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

// CheckOutcome is the result of running one isolation check against a live
// microVM.
type CheckOutcome struct {
	Passed bool
	Detail string
}

// IsolationProbe drives the isolation checks against a provisioned Firecracker
// jailer and KVM host. The production implementation is external work against a
// real host; there is no in-process implementation, so callers without a host
// pass nil and receive UNAVAILABLE for every component.
type IsolationProbe interface {
	Provenance() Provenance
	RunCheck(ctx context.Context, check Check) (CheckOutcome, error)
}

// QualifyReport runs the Firecracker sandbox gate and returns one conformance
// Result per required component. A nil probe (no provisioned host) yields
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
				Reason:    fmt.Sprintf("no provisioned Firecracker host: %s (%s) requires a real Firecracker binary, jailer, and /dev/kvm; record UNAVAILABLE and leave §53.12 unqualified", check.ID, check.Reference),
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
