// Package state defines the celld/state-app conformance gate. It is the §44.3
// analogue of the sandbox gates (internal/conformance/{nsjail,docker,firecracker}):
// it enumerates the durable state-plane properties a provisioned celld/state app
// must prove for the single durable state machine to qualify (SPEC §44.3, §53.1–5),
// and produces one conformance Result per property.
//
// The component ids are the per-check ids required by internal/doctor's production
// ConformanceProfile (state.object-creation, state.sqlite-transaction, …). Each
// check is its own conformance component — the same granularity the wired workerd
// and sandbox gates use — so a real host run feeds the doctor profile directly.
// This gate is distinct from internal/conformance/celld, which proves the collapsed
// §15.8/§16.1 durability contract as the single aggregate component state.celld; the
// two coexist and neither produces the other's ids.
//
// The checks themselves require a real celld/state app backed by a durable
// SQLite store and a configured object-store replication target. Without a
// provisioned DurabilityProbe this gate returns every component as UNAVAILABLE,
// never PASS — a reference or mock probe can only produce reference-only
// (non-promotable) evidence. §53.2 and §53.5 therefore stay unqualified until this
// gate returns a fresh external PASS from a provisioned host; the state aggregate's
// launch-plan and property tests verify the model only and never satisfy this gate.
package state

import (
	"context"
	"fmt"
	"strings"

	"github.com/hancomac/circulusd/internal/conformance"
)

// Check is one required celld/state-app durability property. Component is the
// conformance component id (matching internal/doctor's required state set); ID is
// the stable semantic key a probe keys its checks on.
type Check struct {
	ID          string
	Component   string
	Reference   string // the SPEC clause the check enforces
	Description string
}

// RequiredChecks returns the durable state-plane properties a provisioned
// celld/state app must satisfy. All must hold for §53.2/§53.5 to qualify. Each
// check maps one-to-one to a doctor-required state.* component, so a run cannot
// silently drop a property and the doctor profile cannot require a component
// nothing produces.
func RequiredChecks() []Check {
	return []Check{
		{
			ID:          "object-creation",
			Component:   "state.object-creation",
			Reference:   "SPEC §44.3",
			Description: "a new durable state object is created and assigned a stable identity in the celld/state app",
		},
		{
			ID:          "sqlite-transaction",
			Component:   "state.sqlite-transaction",
			Reference:   "SPEC §44.3",
			Description: "a SQLite-backed state transaction commits atomically or rolls back with no partial write",
		},
		{
			ID:          "ownership-fencing",
			Component:   "state.ownership-fencing",
			Reference:   "SPEC §44.3",
			Description: "a write from a fenced stale-generation owner is rejected so a single current owner writes each object",
		},
		{
			ID:          "session-turn",
			Component:   "state.session-turn",
			Reference:   "SPEC §44.3",
			Description: "a Session DO turn transaction serializes concurrent tools into a single durable turn state machine",
		},
		{
			ID:          "recovery",
			Component:   "state.recovery",
			Reference:   "SPEC §44.3",
			Description: "durable state is recovered intact after a clean process restart",
		},
		{
			ID:          "kill-durability",
			Component:   "state.kill-durability",
			Reference:   "SPEC §15.8",
			Description: "content committed immediately before kill -9 is observed after restart (commit-durability barrier)",
		},
		{
			ID:          "replication-rpo",
			Component:   "state.replication-rpo",
			Reference:   "SPEC §44.3",
			Description: "the configured celld to object-store replication meets its recovery-point-objective bound",
		},
	}
}

// Provenance is the release and host identity of the qualified celld/state app.
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

// CheckOutcome is the result of running one durability check against a live
// celld/state app.
type CheckOutcome struct {
	Passed bool
	Detail string
}

// DurabilityProbe drives the durability checks against a provisioned celld/state
// app. The production implementation is external work against a pinned celld host
// with a durable SQLite store and object-store replication; there is no in-process
// implementation, so callers without a host pass nil and receive UNAVAILABLE for
// every component.
type DurabilityProbe interface {
	Provenance() Provenance
	RunCheck(ctx context.Context, check Check) (CheckOutcome, error)
}

// QualifyReport runs the celld/state-app gate and returns one conformance Result
// per required component. A nil probe (no provisioned celld/state host) yields
// UNAVAILABLE for every component; a check that cannot run yields UNAVAILABLE for
// that component; a check that does not hold yields FAIL; a check that holds yields
// PASS with evidence whose class reflects whether the probe was a real external
// host or a reference one. Each component is independent, so a single failed
// property does not mask the status of the others.
func QualifyReport(ctx context.Context, probe DurabilityProbe) conformance.Report {
	collector := conformance.NewCollector()
	if probe == nil {
		for _, check := range RequiredChecks() {
			_ = collector.Add(conformance.Result{
				Component: check.Component,
				Status:    conformance.Unavailable,
				Reason:    fmt.Sprintf("no provisioned celld/state host: %s (%s) requires a real celld/state app with a durable SQLite store and object-store replication; record UNAVAILABLE and leave §53.2/§53.5 unqualified", check.ID, check.Reference),
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
			result.Reason = fmt.Sprintf("durability check %q could not run: %v", check.ID, err)
		case !outcome.Passed:
			result.Status = conformance.Fail
			result.Reason = fmt.Sprintf("durability check %q (%s) failed", check.ID, check.Reference)
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
