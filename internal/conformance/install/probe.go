// Package install defines the install/upgrade conformance gate. It enumerates
// the offline-install, backend-availability, and upgrade-rollback properties a
// provisioned installer must prove (SPEC §53.18), and produces a
// conformance.Result.
//
// The checks require a real clean network-denied Linux host with the pinned
// release artifacts. Without a provisioned Probe this gate returns UNAVAILABLE,
// never PASS — a reference or mock probe can only produce reference-only
// (non-promotable) evidence. §53.18 therefore stays NOT_RUN until this gate
// returns a fresh external PASS from a provisioned host.
package install

import (
	"context"
	"fmt"
	"strings"

	"github.com/hancomac/circulusd/internal/conformance"
)

// Component is the conformance component id for the install/upgrade gate.
const Component = "install.profile"

// Check is one required install/upgrade property.
type Check struct {
	ID          string
	Reference   string // the SPEC clause the check enforces
	Description string
}

// RequiredChecks returns the properties a provisioned installer must satisfy.
// All must hold for the gate to PASS. The set mirrors SPEC §53.18 one-to-one so
// a real run cannot silently drop a boundary.
func RequiredChecks() []Check {
	return []Check{
		{
			ID:          "lightweight-profile-offline-install",
			Reference:   "SPEC §53.18",
			Description: "the lightweight profile installs on an internet-blocked clean Linux host",
		},
		{
			ID:          "docker-profile-without-kvm",
			Reference:   "SPEC §53.18",
			Description: "the Docker profile installs without KVM",
		},
		{
			ID:          "firecracker-profile-without-docker",
			Reference:   "SPEC §53.18",
			Description: "the Firecracker profile installs without Docker",
		},
		{
			ID:          "full-profile-independent-backend-verification",
			Reference:   "SPEC §53.18",
			Description: "the full profile independently verifies all three backends' availability",
		},
		{
			ID:          "cas-failure-blocks-state-plane",
			Reference:   "SPEC §53.18",
			Description: "an object-store CAS failure forbids the state plane from starting",
		},
		{
			ID:          "unsupported-protocol-fail-closed",
			Reference:   "SPEC §53.18",
			Description: "an unsupported internal protocol version fails closed",
		},
		{
			ID:          "upgrade-rollback-window-retains-artifact",
			Reference:   "SPEC §53.18",
			Description: "the previous runtime artifact is retained during the upgrade rollback window",
		},
		{
			ID:          "post-install-doctor-end-to-end-turn",
			Reference:   "SPEC §53.18",
			Description: "a doctor end-to-end turn completes immediately after install",
		},
	}
}

// Provenance is the release and host identity of the qualified install.
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

// CheckOutcome is the result of running one install/upgrade check.
type CheckOutcome struct {
	Passed bool
	Detail string
}

// Probe drives the install/upgrade checks against a provisioned host. The
// production implementation is external work against a real host; there is no
// in-process implementation, so callers without a host pass nil and receive
// UNAVAILABLE.
type Probe interface {
	Provenance() Provenance
	RunCheck(ctx context.Context, check Check) (CheckOutcome, error)
}

// Qualify runs the install/upgrade gate. A nil probe (no provisioned host)
// yields UNAVAILABLE; a check that cannot run yields UNAVAILABLE; a check that
// does not hold yields FAIL; all checks holding yields PASS with evidence whose
// class reflects whether the probe was a real external host or a reference one.
func Qualify(ctx context.Context, probe Probe) conformance.Result {
	if probe == nil {
		return conformance.Result{
			Component: Component,
			Status:    conformance.Unavailable,
			Reason:    "no provisioned install host: the gate requires a real clean network-denied Linux host with the pinned release artifacts; record UNAVAILABLE and leave §53.18 unqualified",
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
				Reason:    fmt.Sprintf("install check %q could not run: %v", check.ID, err),
				Evidence:  evidence(provenance),
			}
		}
		if !outcome.Passed {
			reason := fmt.Sprintf("install check %q (%s) failed", check.ID, check.Reference)
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
		result.Class = conformance.EvidenceClassReferenceOnly
		result.Mock = true
		result.BinaryDigest = ""
		result.EnvironmentDigest = ""
	} else {
		result.Class = conformance.EvidenceClassExternal
	}
	return result
}
