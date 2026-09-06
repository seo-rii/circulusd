// Package secret defines the secret-handling conformance gate. It enumerates
// the properties a provisioned secret proxy and sandbox integration must prove
// for secret delivery to qualify (SPEC §53.15), and produces a
// conformance.Result.
//
// The checks require a real secret proxy, a real sandbox, and a real audit
// sink. Without a provisioned SecretProbe this gate returns UNAVAILABLE, never
// PASS — a reference or mock probe can only produce reference-only
// (non-promotable) evidence. §53.15 therefore stays NOT_RUN until this gate
// returns a fresh external PASS from a provisioned host. The in-process
// internal/secret unit tests exercise the resolution/cache logic but never
// satisfy this gate, because they prove nothing about raw-value absence inside
// a real sandbox or Worker.
package secret

import (
	"context"
	"fmt"
	"strings"

	"github.com/hancomac/circulusd/internal/conformance"
)

// Component is the conformance component id for the secret-handling gate.
const Component = "runtime.secret"

// Check is one required secret-handling property.
type Check struct {
	ID          string
	Reference   string // the SPEC clause the check enforces
	Description string
}

// RequiredChecks returns the properties a provisioned secret integration must
// satisfy. All must hold for the gate to PASS. The set mirrors SPEC §53.15
// one-to-one so a real run cannot silently drop a boundary.
func RequiredChecks() []Check {
	return []Check{
		{
			ID:          "proxy-only-raw-absent",
			Reference:   "SPEC §53.15",
			Description: "a proxy-only secret's raw value is never present in the sandbox or Worker",
		},
		{
			ID:          "sandbox-secret-use-audited",
			Reference:   "SPEC §53.15",
			Description: "sandbox-env and sandbox-file secret use is recorded in the audit log",
		},
		{
			ID:          "temp-file-cleanup",
			Reference:   "SPEC §53.15",
			Description: "secret temporary files are cleaned up after use",
		},
		{
			ID:          "exposure-class-reuse-policy",
			Reference:   "SPEC §53.15",
			Description: "a secret exposure-class change applies the sandbox reuse policy",
		},
	}
}

// Provenance is the release and host identity of the qualified secret
// integration. Reference marks a non-production (reference or mock) probe whose
// PASS is not promotable.
type Provenance struct {
	Version           string
	BinaryDigest      string // canonical sha256:... or empty
	EnvironmentDigest string // canonical sha256:... or empty
	Kernel            string
	Architecture      string
	Reference         bool
}

// CheckOutcome is the result of running one secret-handling check.
type CheckOutcome struct {
	Passed bool
	Detail string
}

// SecretProbe drives the secret-handling checks against a provisioned secret
// proxy and sandbox. The production implementation is external work against a
// real host; there is no in-process implementation, so callers without a host
// pass nil and receive UNAVAILABLE.
type SecretProbe interface {
	Provenance() Provenance
	RunCheck(ctx context.Context, check Check) (CheckOutcome, error)
}

// Qualify runs the secret-handling gate. A nil probe (no provisioned
// integration) yields UNAVAILABLE; a check that cannot run yields UNAVAILABLE; a
// check that does not hold yields FAIL; all checks holding yields PASS with
// evidence whose class reflects whether the probe was a real external host or a
// reference one.
func Qualify(ctx context.Context, probe SecretProbe) conformance.Result {
	if probe == nil {
		return conformance.Result{
			Component: Component,
			Status:    conformance.Unavailable,
			Reason:    "no provisioned secret integration: the gate requires a real secret proxy, sandbox, and audit sink; record UNAVAILABLE and leave §53.15 unqualified",
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
				Reason:    fmt.Sprintf("secret check %q could not run: %v", check.ID, err),
				Evidence:  evidence(provenance),
			}
		}
		if !outcome.Passed {
			reason := fmt.Sprintf("secret check %q (%s) failed", check.ID, check.Reference)
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
