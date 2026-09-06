// Package docker defines the Docker sandbox conformance gate. It is the Docker
// analogue of internal/conformance/nsjail: it enumerates the container
// hardening properties a provisioned Docker daemon must prove for the Docker
// execution backend to qualify (SPEC §53.11), and produces a conformance.Result.
//
// The checks require a real Docker daemon the harness can drive. Without a
// provisioned IsolationProbe this gate returns UNAVAILABLE, never PASS — a
// reference or mock probe can only produce reference-only (non-promotable)
// evidence. §53.11 therefore stays NOT_RUN (the Docker CLI exists but daemon
// access is unverified on the development host) until this gate returns a fresh
// external PASS from a provisioned daemon.
package docker

import (
	"context"
	"fmt"
	"strings"

	"github.com/hancomac/circulusd/internal/conformance"
)

// Component is the conformance component id for the Docker sandbox gate.
const Component = "sandbox.docker"

// Check is one required Docker container hardening property.
type Check struct {
	ID          string
	Reference   string // the SPEC clause the check enforces
	Description string
}

// RequiredChecks returns the hardening properties a provisioned Docker container
// must satisfy. All must hold for the gate to PASS. The set mirrors SPEC §53.11
// one-to-one so a real run cannot silently drop a boundary.
func RequiredChecks() []Check {
	return []Check{
		{
			ID:          "non-root-uid",
			Reference:   "SPEC §53.11",
			Description: "the container process runs as a non-root UID",
		},
		{
			ID:          "docker-socket-nonexposure",
			Reference:   "SPEC §53.11",
			Description: "the Docker socket is not exposed inside the container",
		},
		{
			ID:          "rootfs-read-only",
			Reference:   "SPEC §53.11",
			Description: "the container root filesystem is read-only",
		},
		{
			ID:          "cap-drop-no-new-privs",
			Reference:   "SPEC §53.11",
			Description: "all capabilities are dropped and no-new-privileges is set",
		},
		{
			ID:          "cgroup-limits",
			Reference:   "SPEC §53.11",
			Description: "cgroup CPU, memory, and PID limits are applied to the container",
		},
		{
			ID:          "network-default-deny",
			Reference:   "SPEC §53.11",
			Description: "the container has no external network connectivity by default",
		},
		{
			ID:          "timeout-teardown",
			Reference:   "SPEC §53.11",
			Description: "a timeout terminates the container process tree",
		},
		{
			ID:          "sandboxd-private-uds",
			Reference:   "SPEC §53.11",
			Description: "only the sandboxd private UDS is reachable from inside the container",
		},
	}
}

// Provenance is the release and host identity of the qualified Docker daemon.
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

// CheckOutcome is the result of running one hardening check against a live
// container.
type CheckOutcome struct {
	Passed bool
	Detail string
}

// IsolationProbe drives the hardening checks against a provisioned Docker
// daemon. The production implementation is external work against a real daemon;
// there is no in-process implementation, so callers without a daemon pass nil
// and receive UNAVAILABLE.
type IsolationProbe interface {
	Provenance() Provenance
	RunCheck(ctx context.Context, check Check) (CheckOutcome, error)
}

// Qualify runs the Docker sandbox gate. A nil probe (no provisioned daemon)
// yields UNAVAILABLE; a check that cannot run yields UNAVAILABLE; a check that
// does not hold yields FAIL; all checks holding yields PASS with evidence whose
// class reflects whether the probe was a real external host or a reference one.
func Qualify(ctx context.Context, probe IsolationProbe) conformance.Result {
	if probe == nil {
		return conformance.Result{
			Component: Component,
			Status:    conformance.Unavailable,
			Reason:    "no provisioned Docker daemon: the sandbox gate requires a real daemon the harness can drive; record UNAVAILABLE and leave §53.11 unqualified",
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
				Reason:    fmt.Sprintf("hardening check %q could not run: %v", check.ID, err),
				Evidence:  evidence(provenance),
			}
		}
		if !outcome.Passed {
			reason := fmt.Sprintf("hardening check %q (%s) failed", check.ID, check.Reference)
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
