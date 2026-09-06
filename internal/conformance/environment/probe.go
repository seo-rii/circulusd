// Package environment defines the execution-environment-resolution conformance
// gate. It enumerates the requirement-resolution, conflict, artifact, and
// digest properties a provisioned environment resolver must prove (SPEC §53.7),
// and produces a conformance.Result.
//
// The checks require a real curated-environment resolver and backend artifact
// store. Without a provisioned EnvironmentProbe this gate returns UNAVAILABLE,
// never PASS — a reference or mock probe can only produce reference-only
// (non-promotable) evidence. §53.7 therefore stays NOT_RUN until this gate
// returns a fresh external PASS from a provisioned host.
package environment

import (
	"context"
	"fmt"
	"strings"

	"github.com/hancomac/circulusd/internal/conformance"
)

// Component is the conformance component id for the environment-resolution gate.
const Component = "runtime.environment"

// Check is one required environment-resolution property.
type Check struct {
	ID          string
	Reference   string // the SPEC clause the check enforces
	Description string
}

// RequiredChecks returns the properties a provisioned environment resolver must
// satisfy. All must hold for the gate to PASS. The set mirrors SPEC §53.7
// one-to-one so a real run cannot silently drop a boundary.
func RequiredChecks() []Check {
	return []Check{
		{
			ID:          "requirement-union-resolves-one-environment",
			Reference:   "SPEC §53.7",
			Description: "the union of extension package requirements resolves to one curated environment",
		},
		{
			ID:          "version-conflict-fails-session-creation",
			Reference:   "SPEC §53.7",
			Description: "a package version conflict fails session creation",
		},
		{
			ID:          "missing-backend-artifact-blocks-selection",
			Reference:   "SPEC §53.7",
			Description: "a backend cannot be selected in an environment that lacks its artifact",
		},
		{
			ID:          "environment-digest-change-cache-miss",
			Reference:   "SPEC §53.7",
			Description: "an environment digest change causes a sandbox cache miss and a new sandbox",
		},
		{
			ID:          "no-extension-raw-image-path",
			Reference:   "SPEC §53.7",
			Description: "an extension cannot specify a raw Docker image, NsJail rootfs, or Firecracker path",
		},
	}
}

// Provenance is the release and host identity of the qualified resolver.
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

// CheckOutcome is the result of running one environment-resolution check.
type CheckOutcome struct {
	Passed bool
	Detail string
}

// EnvironmentProbe drives the environment-resolution checks against a
// provisioned resolver and artifact store. The production implementation is
// external work against a real host; there is no in-process implementation, so
// callers without a host pass nil and receive UNAVAILABLE.
type EnvironmentProbe interface {
	Provenance() Provenance
	RunCheck(ctx context.Context, check Check) (CheckOutcome, error)
}

// Qualify runs the environment-resolution gate. A nil probe yields UNAVAILABLE;
// a check that cannot run yields UNAVAILABLE; a check that does not hold yields
// FAIL; all checks holding yields PASS with evidence whose class reflects
// whether the probe was a real external host or a reference one.
func Qualify(ctx context.Context, probe EnvironmentProbe) conformance.Result {
	if probe == nil {
		return conformance.Result{
			Component: Component,
			Status:    conformance.Unavailable,
			Reason:    "no provisioned environment resolver: the gate requires a real curated-environment resolver and backend artifact store; record UNAVAILABLE and leave §53.7 unqualified",
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
				Reason:    fmt.Sprintf("environment check %q could not run: %v", check.ID, err),
				Evidence:  evidence(provenance),
			}
		}
		if !outcome.Passed {
			reason := fmt.Sprintf("environment check %q (%s) failed", check.ID, check.Reference)
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
