// Package firecracker defines the Firecracker sandbox conformance gate. It is
// the microVM analogue of internal/conformance/nsjail: it enumerates the
// isolation properties a provisioned Firecracker jailer and KVM host must prove
// for the Firecracker execution backend to qualify (SPEC §53.12), and produces
// a conformance.Result.
//
// The checks require a real Firecracker binary, jailer, and /dev/kvm. Without a
// provisioned IsolationProbe this gate returns UNAVAILABLE, never PASS — a
// reference or mock probe can only produce reference-only (non-promotable)
// evidence. §53.12 therefore stays UNAVAILABLE (Firecracker, the jailer, and
// /dev/kvm are absent on the development host) until this gate returns a fresh
// external PASS from a provisioned host.
package firecracker

import (
	"context"
	"fmt"
	"strings"

	"github.com/hancomac/circulusd/internal/conformance"
)

// Component is the conformance component id for the Firecracker sandbox gate.
const Component = "sandbox.firecracker"

// Check is one required Firecracker microVM isolation property.
type Check struct {
	ID          string
	Reference   string // the SPEC clause the check enforces
	Description string
}

// RequiredChecks returns the isolation properties a provisioned Firecracker
// microVM must satisfy. All must hold for the gate to PASS. The set mirrors SPEC
// §53.12 one-to-one so a real run cannot silently drop a boundary.
func RequiredChecks() []Check {
	return []Check{
		{
			ID:          "jailer",
			Reference:   "SPEC §53.12",
			Description: "the microVM is launched through the Firecracker jailer",
		},
		{
			ID:          "unique-microvm-uid-gid",
			Reference:   "SPEC §53.12",
			Description: "each microVM runs under a unique UID/GID",
		},
		{
			ID:          "api-socket-nonaccess",
			Reference:   "SPEC §53.12",
			Description: "the Firecracker API socket is not accessible to normal users",
		},
		{
			ID:          "control-channel-vsock",
			Reference:   "SPEC §53.12",
			Description: "the sandbox control channel is a vsock, not a guest network path",
		},
		{
			ID:          "no-guest-nic",
			Reference:   "SPEC §53.12",
			Description: "in network mode none the guest has no NIC",
		},
		{
			ID:          "scratch-discard",
			Reference:   "SPEC §53.12",
			Description: "scratch is discarded after the microVM shuts down",
		},
		{
			ID:          "no-silent-kvm-fallback",
			Reference:   "SPEC §53.12",
			Description: "there is no silent fallback when /dev/kvm is unsupported",
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
// pass nil and receive UNAVAILABLE.
type IsolationProbe interface {
	Provenance() Provenance
	RunCheck(ctx context.Context, check Check) (CheckOutcome, error)
}

// Qualify runs the Firecracker sandbox gate. A nil probe (no provisioned host)
// yields UNAVAILABLE; a check that cannot run yields UNAVAILABLE; a check that
// does not hold yields FAIL; all checks holding yields PASS with evidence whose
// class reflects whether the probe was a real external host or a reference one.
func Qualify(ctx context.Context, probe IsolationProbe) conformance.Result {
	if probe == nil {
		return conformance.Result{
			Component: Component,
			Status:    conformance.Unavailable,
			Reason:    "no provisioned Firecracker host: the sandbox gate requires a real Firecracker binary, jailer, and /dev/kvm; record UNAVAILABLE and leave §53.12 unqualified",
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
