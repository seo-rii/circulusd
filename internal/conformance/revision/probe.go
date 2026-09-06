// Package revision defines the runtime-revision conformance gate. It enumerates
// the candidate/migration/CAS-activation/rollback properties a provisioned
// runtime-revision control loop must prove (SPEC §53.6), and produces a
// conformance.Result.
//
// The checks require a real Worker Loader activating content-addressed runtime
// revisions across live isolates. Without a provisioned RevisionProbe this gate
// returns UNAVAILABLE, never PASS — a reference or mock probe can only produce
// reference-only (non-promotable) evidence. §53.6 therefore stays NOT_RUN until
// this gate returns a fresh external PASS from a provisioned host. The in-process
// state-app session runtime-revision tests exercise the admission-fence logic but
// never satisfy this gate.
package revision

import (
	"context"
	"fmt"
	"strings"

	"github.com/hancomac/circulusd/internal/conformance"
)

// Component is the conformance component id for the runtime-revision gate.
const Component = "runtime.revision"

// Check is one required runtime-revision property.
type Check struct {
	ID          string
	Reference   string // the SPEC clause the check enforces
	Description string
}

// RequiredChecks returns the properties a provisioned runtime-revision control
// loop must satisfy. All must hold for the gate to PASS. The set mirrors SPEC
// §53.6 one-to-one so a real run cannot silently drop a boundary.
func RequiredChecks() []Check {
	return []Check{
		{
			ID:          "candidate-health-fail-keeps-active",
			Reference:   "SPEC §53.6",
			Description: "a candidate health-check failure keeps the current activeRevision",
		},
		{
			ID:          "migration-fail-keeps-old-state",
			Reference:   "SPEC §53.6",
			Description: "a candidate state-migration failure keeps the old state and revision",
		},
		{
			ID:          "no-admission-before-cas-activation",
			Reference:   "SPEC §53.6",
			Description: "no user turn is admitted to the new revision before CAS activation",
		},
		{
			ID:          "old-worker-admission-rejected",
			Reference:   "SPEC §53.6",
			Description: "after activation, the old Worker's new-turn admission is rejected",
		},
		{
			ID:          "rollback-next-turn-only",
			Reference:   "SPEC §53.6",
			Description: "rollback changes only the next turn's runtime and does not claim to undo emitted side effects",
		},
	}
}

// Provenance is the release and host identity of the qualified runtime-revision
// loop. Reference marks a non-production (reference or mock) probe whose PASS is
// not promotable.
type Provenance struct {
	Version           string
	BinaryDigest      string // canonical sha256:... or empty
	EnvironmentDigest string // canonical sha256:... or empty
	Kernel            string
	Architecture      string
	Reference         bool
}

// CheckOutcome is the result of running one runtime-revision check.
type CheckOutcome struct {
	Passed bool
	Detail string
}

// RevisionProbe drives the runtime-revision checks against a provisioned Worker
// Loader. The production implementation is external work against a real host;
// there is no in-process implementation, so callers without a host pass nil and
// receive UNAVAILABLE.
type RevisionProbe interface {
	Provenance() Provenance
	RunCheck(ctx context.Context, check Check) (CheckOutcome, error)
}

// Qualify runs the runtime-revision gate. A nil probe yields UNAVAILABLE; a
// check that cannot run yields UNAVAILABLE; a check that does not hold yields
// FAIL; all checks holding yields PASS with evidence whose class reflects
// whether the probe was a real external host or a reference one.
func Qualify(ctx context.Context, probe RevisionProbe) conformance.Result {
	if probe == nil {
		return conformance.Result{
			Component: Component,
			Status:    conformance.Unavailable,
			Reason:    "no provisioned runtime-revision loop: the gate requires a real Worker Loader activating content-addressed revisions across live isolates; record UNAVAILABLE and leave §53.6 unqualified",
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
				Reason:    fmt.Sprintf("runtime-revision check %q could not run: %v", check.ID, err),
				Evidence:  evidence(provenance),
			}
		}
		if !outcome.Passed {
			reason := fmt.Sprintf("runtime-revision check %q (%s) failed", check.ID, check.Reference)
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
