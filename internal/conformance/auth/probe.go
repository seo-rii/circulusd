// Package auth defines the durable-credentials conformance gate. It enumerates
// the credential-durability property the platform's authentication material must
// prove (SPEC §27.4: credentials are provisioned from durable, fail-closed key
// material, survive restart, and honor rotation/expiry), and produces one
// conformance Result per property.
//
// The component id is the per-check id required by internal/doctor's production
// ConformanceProfile (auth.durable-credentials). The check is its own conformance
// component — the same granularity the wired workerd and sandbox gates use — so a
// real host run feeds the doctor profile directly.
//
// The check requires the platform's real credential material (state read/dispatch
// signing roots, capability-token keys) loaded from durable storage. Without a
// provisioned CredentialProbe this gate returns the component as UNAVAILABLE, never
// PASS — a reference or mock probe can only produce reference-only (non-promotable)
// evidence — so an unprovisioned host leaves the component unqualified.
package auth

import (
	"context"
	"fmt"
	"strings"

	"github.com/hancomac/circulusd/internal/conformance"
)

// Check is one required credential-durability property. Component is the
// conformance component id (matching internal/doctor's required auth set); ID is
// the stable semantic key a probe keys its checks on.
type Check struct {
	ID          string
	Component   string
	Reference   string // the SPEC clause the check enforces
	Description string
}

// RequiredChecks returns the credential-durability properties the platform's
// authentication material must satisfy. Each check maps one-to-one to a
// doctor-required auth.* component, so a run cannot silently drop a property and
// the doctor profile cannot require a component nothing produces.
func RequiredChecks() []Check {
	return []Check{
		{
			ID:          "durable-credentials",
			Component:   "auth.durable-credentials",
			Reference:   "SPEC §27.4",
			Description: "authentication credentials are loaded from durable key material, survive restart, and honor rotation and expiry rather than an ephemeral in-memory default",
		},
	}
}

// Provenance is the release and host identity that provisioned the credentials.
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

// CheckOutcome is the result of running one credential check against live
// credential material.
type CheckOutcome struct {
	Passed bool
	Detail string
}

// CredentialProbe drives the credential checks against provisioned platform
// authentication material. The production implementation is external work against
// a real deployment; there is no in-process implementation, so callers without a
// host pass nil and receive UNAVAILABLE for every component.
type CredentialProbe interface {
	Provenance() Provenance
	RunCheck(ctx context.Context, check Check) (CheckOutcome, error)
}

// QualifyReport runs the durable-credentials gate and returns one conformance
// Result per required component. A nil probe (no provisioned credentials) yields
// UNAVAILABLE for every component; a check that cannot run yields UNAVAILABLE for
// that component; a check that does not hold yields FAIL; a check that holds yields
// PASS with evidence whose class reflects whether the probe was a real external
// host or a reference one.
func QualifyReport(ctx context.Context, probe CredentialProbe) conformance.Report {
	collector := conformance.NewCollector()
	if probe == nil {
		for _, check := range RequiredChecks() {
			_ = collector.Add(conformance.Result{
				Component: check.Component,
				Status:    conformance.Unavailable,
				Reason:    fmt.Sprintf("no provisioned credentials: %s (%s) requires real platform authentication material loaded from durable storage; record UNAVAILABLE and leave the credential requirement unqualified", check.ID, check.Reference),
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
			result.Reason = fmt.Sprintf("credential check %q could not run: %v", check.ID, err)
		case !outcome.Passed:
			result.Status = conformance.Fail
			result.Reason = fmt.Sprintf("credential check %q (%s) failed", check.ID, check.Reference)
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
