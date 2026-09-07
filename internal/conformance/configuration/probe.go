// Package configuration defines the fail-closed configuration conformance gate.
// It enumerates the fail-closed loading property the platform configuration loader
// must prove (SPEC §43.5: an invalid, incomplete, or unsafe production
// configuration is rejected and startup is refused rather than continuing on a
// permissive default), and produces one conformance Result per property.
//
// The component id is the per-check id required by internal/doctor's production
// ConformanceProfile (configuration.fail-closed). The check is its own conformance
// component — the same granularity the wired workerd and sandbox gates use — so a
// real host run feeds the doctor profile directly.
//
// The check requires the platform's real configuration loader evaluated against a
// deliberately invalid production configuration. Without a provisioned ConfigProbe
// this gate returns the component as UNAVAILABLE, never PASS — a reference or mock
// probe can only produce reference-only (non-promotable) evidence — so an
// unprovisioned host leaves the component unqualified.
package configuration

import (
	"context"
	"fmt"
	"strings"

	"github.com/hancomac/circulusd/internal/conformance"
)

// Check is one required fail-closed configuration property. Component is the
// conformance component id (matching internal/doctor's required configuration set);
// ID is the stable semantic key a probe keys its checks on.
type Check struct {
	ID          string
	Component   string
	Reference   string // the SPEC clause the check enforces
	Description string
}

// RequiredChecks returns the fail-closed loading properties the platform
// configuration loader must satisfy. Each check maps one-to-one to a
// doctor-required configuration.* component, so a run cannot silently drop a
// property and the doctor profile cannot require a component nothing produces.
func RequiredChecks() []Check {
	return []Check{
		{
			ID:          "fail-closed",
			Component:   "configuration.fail-closed",
			Reference:   "SPEC §43.5",
			Description: "an invalid, incomplete, or unsafe production configuration is rejected and startup is refused rather than continuing on a permissive default",
		},
	}
}

// Provenance is the release and host identity of the qualified configuration
// loader. Reference marks a non-production (reference or mock) probe whose PASS is
// not promotable.
type Provenance struct {
	Version           string
	BinaryDigest      string // canonical sha256:... or empty
	EnvironmentDigest string // canonical sha256:... or empty
	Kernel            string
	Architecture      string
	Reference         bool
}

// CheckOutcome is the result of running one fail-closed check against the live
// configuration loader.
type CheckOutcome struct {
	Passed bool
	Detail string
}

// ConfigProbe drives the fail-closed checks against the platform's real
// configuration loader. The production implementation is external work against a
// real deployment; there is no in-process implementation, so callers without a
// host pass nil and receive UNAVAILABLE for every component.
type ConfigProbe interface {
	Provenance() Provenance
	RunCheck(ctx context.Context, check Check) (CheckOutcome, error)
}

// QualifyReport runs the fail-closed configuration gate and returns one
// conformance Result per required component. A nil probe (no provisioned loader)
// yields UNAVAILABLE for every component; a check that cannot run yields
// UNAVAILABLE for that component; a check that does not hold yields FAIL; a check
// that holds yields PASS with evidence whose class reflects whether the probe was a
// real external host or a reference one.
func QualifyReport(ctx context.Context, probe ConfigProbe) conformance.Report {
	collector := conformance.NewCollector()
	if probe == nil {
		for _, check := range RequiredChecks() {
			_ = collector.Add(conformance.Result{
				Component: check.Component,
				Status:    conformance.Unavailable,
				Reason:    fmt.Sprintf("no provisioned configuration loader: %s (%s) requires the real platform loader evaluated against an invalid production configuration; record UNAVAILABLE and leave the fail-closed requirement unqualified", check.ID, check.Reference),
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
			result.Reason = fmt.Sprintf("configuration check %q could not run: %v", check.ID, err)
		case !outcome.Passed:
			result.Status = conformance.Fail
			result.Reason = fmt.Sprintf("configuration check %q (%s) failed", check.ID, check.Reference)
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
