// Package aclquota defines the ACL and quota conformance gate. It enumerates
// the cross-tenant access-control and quota-admission properties a provisioned
// control plane must prove (SPEC §53.17), and produces a conformance.Result.
//
// The checks require a real multi-tenant control plane with durable quota
// accounting. Without a provisioned Probe this gate returns UNAVAILABLE, never
// PASS — a reference or mock probe can only produce reference-only
// (non-promotable) evidence. §53.17 therefore stays NOT_RUN until this gate
// returns a fresh external PASS from a provisioned host.
package aclquota

import (
	"context"
	"fmt"
	"strings"

	"github.com/hancomac/circulusd/internal/conformance"
)

// Component is the conformance component id for the ACL/quota gate.
const Component = "control.acl-quota"

// Check is one required ACL/quota property.
type Check struct {
	ID          string
	Reference   string // the SPEC clause the check enforces
	Description string
}

// RequiredChecks returns the ACL/quota properties a provisioned control plane
// must satisfy. All must hold for the gate to PASS. The set mirrors SPEC §53.17
// one-to-one so a real run cannot silently drop a boundary.
func RequiredChecks() []Check {
	return []Check{
		{
			ID:          "cross-tenant-access-denied",
			Reference:   "SPEC §53.17",
			Description: "knowing another tenant's resource ID does not grant access to it",
		},
		{
			ID:          "workspace-role-enforced",
			Reference:   "SPEC §53.17",
			Description: "workspace member and owner roles are enforced",
		},
		{
			ID:          "quota-exceeded-admission-denied",
			Reference:   "SPEC §53.17",
			Description: "exceeding a sandbox, session, or blob quota denies admission",
		},
		{
			ID:          "quota-rejection-no-partial-mutation",
			Reference:   "SPEC §53.17",
			Description: "a quota rejection leaves no partial durable mutation",
		},
	}
}

// Provenance is the release and host identity of the qualified control plane.
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

// CheckOutcome is the result of running one ACL/quota check.
type CheckOutcome struct {
	Passed bool
	Detail string
}

// Probe drives the ACL/quota checks against a provisioned control plane. The
// production implementation is external work against a real host; there is no
// in-process implementation, so callers without a host pass nil and receive
// UNAVAILABLE.
type Probe interface {
	Provenance() Provenance
	RunCheck(ctx context.Context, check Check) (CheckOutcome, error)
}

// Qualify runs the ACL/quota gate. A nil probe (no provisioned control plane)
// yields UNAVAILABLE; a check that cannot run yields UNAVAILABLE; a check that
// does not hold yields FAIL; all checks holding yields PASS with evidence whose
// class reflects whether the probe was a real external host or a reference one.
func Qualify(ctx context.Context, probe Probe) conformance.Result {
	if probe == nil {
		return conformance.Result{
			Component: Component,
			Status:    conformance.Unavailable,
			Reason:    "no provisioned control plane: the gate requires a real multi-tenant control plane with durable quota accounting; record UNAVAILABLE and leave §53.17 unqualified",
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
				Reason:    fmt.Sprintf("acl/quota check %q could not run: %v", check.ID, err),
				Evidence:  evidence(provenance),
			}
		}
		if !outcome.Passed {
			reason := fmt.Sprintf("acl/quota check %q (%s) failed", check.ID, check.Reference)
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
