// Package audit defines the durable audit-sink conformance gate. It enumerates
// the audit-record integrity properties a provisioned production audit sink must
// prove (SPEC §48.3: a monotonic sequence is MUST, and a hash chain plus periodic
// signed checkpoint are the production integrity requirement), and produces one
// conformance Result per property.
//
// The component ids are the per-check ids required by internal/doctor's production
// ConformanceProfile (audit.durable-chain, audit.signed-checkpoint). Each check is
// its own conformance component — the same granularity the wired workerd and
// sandbox gates use — so a real host run feeds the doctor profile directly.
//
// The checks require a real audit sink emitting a hash-chained, monotonic,
// durable record stream with periodic signed checkpoints over that chain. Without
// a provisioned AuditProbe this gate returns every component as UNAVAILABLE, never
// PASS — a reference or mock probe can only produce reference-only (non-promotable)
// evidence. A general application log is never an audit authority, so an
// unprovisioned host leaves these components unqualified.
package audit

import (
	"context"
	"fmt"
	"strings"

	"github.com/hancomac/circulusd/internal/conformance"
)

// Check is one required audit-sink integrity property. Component is the
// conformance component id (matching internal/doctor's required audit set); ID is
// the stable semantic key a probe keys its checks on.
type Check struct {
	ID          string
	Component   string
	Reference   string // the SPEC clause the check enforces
	Description string
}

// RequiredChecks returns the audit-sink integrity properties a provisioned
// production audit sink must satisfy. Each check maps one-to-one to a
// doctor-required audit.* component, so a run cannot silently drop a property and
// the doctor profile cannot require a component nothing produces.
func RequiredChecks() []Check {
	return []Check{
		{
			ID:          "durable-chain",
			Component:   "audit.durable-chain",
			Reference:   "SPEC §48.3",
			Description: "audit records form a durable, append-only, monotonic hash chain so a removed or reordered record is detectable",
		},
		{
			ID:          "signed-checkpoint",
			Component:   "audit.signed-checkpoint",
			Reference:   "SPEC §48.3",
			Description: "a periodic signed checkpoint over the audit chain is emitted and verifies against the sink signing identity",
		},
	}
}

// Provenance is the release and host identity of the qualified audit sink.
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

// CheckOutcome is the result of running one integrity check against a live audit
// sink.
type CheckOutcome struct {
	Passed bool
	Detail string
}

// AuditProbe drives the integrity checks against a provisioned audit sink. The
// production implementation is external work against a real durable audit sink;
// there is no in-process implementation, so callers without a host pass nil and
// receive UNAVAILABLE for every component.
type AuditProbe interface {
	Provenance() Provenance
	RunCheck(ctx context.Context, check Check) (CheckOutcome, error)
}

// QualifyReport runs the audit-sink gate and returns one conformance Result per
// required component. A nil probe (no provisioned audit sink) yields UNAVAILABLE
// for every component; a check that cannot run yields UNAVAILABLE for that
// component; a check that does not hold yields FAIL; a check that holds yields PASS
// with evidence whose class reflects whether the probe was a real external host or
// a reference one. Each component is independent, so a single failed property does
// not mask the status of the others.
func QualifyReport(ctx context.Context, probe AuditProbe) conformance.Report {
	collector := conformance.NewCollector()
	if probe == nil {
		for _, check := range RequiredChecks() {
			_ = collector.Add(conformance.Result{
				Component: check.Component,
				Status:    conformance.Unavailable,
				Reason:    fmt.Sprintf("no provisioned audit sink: %s (%s) requires a real durable audit sink with a hash chain and signed checkpoints; record UNAVAILABLE and leave the audit integrity requirement unqualified", check.ID, check.Reference),
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
			result.Reason = fmt.Sprintf("audit check %q could not run: %v", check.ID, err)
		case !outcome.Passed:
			result.Status = conformance.Fail
			result.Reason = fmt.Sprintf("audit check %q (%s) failed", check.ID, check.Reference)
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
