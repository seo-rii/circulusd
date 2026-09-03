// Package celld defines the celld durability conformance gate (Unit 11.6). It is
// the celld analogue of internal/conformance/workerd: it enumerates the
// durability properties a provisioned, pinned celld process must prove for the
// state plane to start (SPEC §15.8 celld durability contract, §16.1 object-store
// conditional-write/CAS), and produces a conformance.Result.
//
// The checks themselves require a real celld process. Without a provisioned
// DurabilityProbe this gate returns UNAVAILABLE, never PASS — a reference or
// mock probe can only produce reference-only (non-promotable) evidence. §53.2
// and §53.5 therefore stay NOT_RUN and state.celld stays NOT_WIRED until this
// gate returns a fresh external PASS from a provisioned host.
package celld

import (
	"context"
	"fmt"
	"strings"

	"github.com/hancomac/circulusd/internal/conformance"
)

// Component is the conformance component id for the celld durability gate.
const Component = "state.celld"

// Check is one required celld durability property.
type Check struct {
	ID          string
	Reference   string // the SPEC clause the check enforces
	Description string
}

// RequiredChecks returns the durability properties a provisioned celld process
// must satisfy. All must hold for the gate to PASS.
func RequiredChecks() []Check {
	return []Check{
		{
			ID:          "single-writer",
			Reference:   "SPEC §15.8",
			Description: "a single writer owns each object; a late write from a prior owner is rejected",
		},
		{
			ID:          "atomic-durable-commit",
			Reference:   "SPEC §15.8",
			Description: "a committed transaction is atomic and durable (fsync-equivalent) before the commit is acknowledged",
		},
		{
			ID:          "durability-barrier",
			Reference:   "SPEC §15.8",
			Description: "the commit-before-dispatch durability barrier confirms success only after the commit is durable",
		},
		{
			ID:          "object-store-cas",
			Reference:   "SPEC §16.1",
			Description: "object-store conditional-write / ETag compare-and-set is proven end to end",
		},
		{
			ID:          "read-your-writes",
			Reference:   "SPEC §15.8",
			Description: "a committed write is visible to a subsequent read on the same object",
		},
	}
}

// Provenance is the release and host identity of the qualified celld. Reference
// marks a non-production (reference or mock) probe whose PASS is not promotable.
type Provenance struct {
	Version           string
	BinaryDigest      string // canonical sha256:... or empty
	EnvironmentDigest string // canonical sha256:... or empty
	Kernel            string
	Architecture      string
	Reference         bool
}

// CheckOutcome is the result of running one durability check against a live celld.
type CheckOutcome struct {
	Passed bool
	Detail string
}

// DurabilityProbe drives the durability checks against a provisioned celld
// process. The production implementation is external work against a pinned celld
// host; there is no in-process implementation, so callers without a host pass
// nil and receive UNAVAILABLE.
type DurabilityProbe interface {
	Provenance() Provenance
	RunCheck(ctx context.Context, check Check) (CheckOutcome, error)
}

// Qualify runs the celld durability gate. A nil probe (no provisioned celld)
// yields UNAVAILABLE; a check that cannot run yields UNAVAILABLE; a check that
// does not hold yields FAIL; all checks holding yields PASS with evidence whose
// class reflects whether the probe was a real external host or a reference one.
func Qualify(ctx context.Context, probe DurabilityProbe) conformance.Result {
	if probe == nil {
		return conformance.Result{
			Component: Component,
			Status:    conformance.Unavailable,
			Reason:    "no provisioned celld process: the durability gate requires a pinned celld host with a real object store; record UNAVAILABLE and leave Unit 11 incomplete",
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
				Reason:    fmt.Sprintf("durability check %q could not run: %v", check.ID, err),
				Evidence:  evidence(provenance),
			}
		}
		if !outcome.Passed {
			reason := fmt.Sprintf("durability check %q (%s) failed", check.ID, check.Reference)
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
