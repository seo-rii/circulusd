// Package docker defines the Docker sandbox conformance gate. It is the Docker
// analogue of internal/conformance/nsjail: it enumerates the container
// hardening properties a provisioned Docker daemon must prove for the Docker
// execution backend to qualify (SPEC §53.11), and produces one conformance
// Result per property.
//
// The component ids are the per-check ids required by internal/doctor's
// production ConformanceProfile (docker.non-root, docker.hardening, …). Each
// check is its own conformance component — the same granularity the wired
// workerd gate already uses — so a real daemon run feeds the doctor profile
// directly. host.nftables-tool is a host-tool property produced by a host probe,
// not this sandbox gate.
//
// The checks require a real Docker daemon the harness can drive. Without a
// provisioned IsolationProbe this gate returns every component as UNAVAILABLE,
// never PASS — a reference or mock probe can only produce reference-only
// (non-promotable) evidence. §53.11 therefore stays NOT_RUN (the Docker CLI
// exists but daemon access is unverified on the development host) until this gate
// returns a fresh external PASS from a provisioned daemon.
package docker

import (
	"context"
	"fmt"
	"strings"

	"github.com/hancomac/circulusd/internal/conformance"
)

// Check is one required Docker container hardening property. Component is the
// conformance component id (matching internal/doctor's required docker set); ID
// is the stable semantic key.
type Check struct {
	ID          string
	Component   string
	Reference   string // the SPEC clause the check enforces
	Description string
}

// RequiredChecks returns the hardening properties a provisioned Docker container
// must satisfy. All must hold for §53.11 to qualify. Each check maps one-to-one
// to a doctor-required docker.* component, so a run cannot silently drop a
// boundary and the doctor profile cannot require a component nothing produces.
func RequiredChecks() []Check {
	return []Check{
		{
			ID:          "container-lifecycle",
			Component:   "docker.creation",
			Reference:   "SPEC §53.11",
			Description: "the container is created from the pinned image and a timeout or stop terminates its process tree and removes it",
		},
		{
			ID:          "non-root-uid",
			Component:   "docker.non-root",
			Reference:   "SPEC §53.11",
			Description: "the container process runs as a non-root UID",
		},
		{
			ID:          "docker-socket-nonexposure",
			Component:   "docker.socket-invisibility",
			Reference:   "SPEC §53.11",
			Description: "the Docker socket is not exposed inside the container",
		},
		{
			ID:          "rootfs-read-only",
			Component:   "docker.read-only-rootfs",
			Reference:   "SPEC §53.11",
			Description: "the container root filesystem is read-only",
		},
		{
			ID:          "cap-drop-no-new-privs",
			Component:   "docker.hardening",
			Reference:   "SPEC §53.11",
			Description: "all capabilities are dropped and no-new-privileges is set",
		},
		{
			ID:          "cgroup-limits",
			Component:   "docker.limits",
			Reference:   "SPEC §53.11",
			Description: "cgroup CPU, memory, and PID limits are applied to the container",
		},
		{
			ID:          "network-default-deny",
			Component:   "docker.network-deny",
			Reference:   "SPEC §53.11",
			Description: "the container has no external network connectivity by default",
		},
		{
			ID:          "sandboxd-private-uds",
			Component:   "docker.sandboxd-uds",
			Reference:   "SPEC §53.11",
			Description: "only the sandboxd private UDS is reachable from inside the container",
		},
		{
			ID:          "workspace-roundtrip",
			Component:   "docker.workspace-roundtrip",
			Reference:   "SPEC §53.11",
			Description: "a write to the read-write workspace projection is visible on host readback and writes outside it are denied",
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
// and receive UNAVAILABLE for every component.
type IsolationProbe interface {
	Provenance() Provenance
	RunCheck(ctx context.Context, check Check) (CheckOutcome, error)
}

// QualifyReport runs the Docker sandbox gate and returns one conformance Result
// per required component. A nil probe (no provisioned daemon) yields UNAVAILABLE
// for every component; a check that cannot run yields UNAVAILABLE for that
// component; a check that does not hold yields FAIL; a check that holds yields
// PASS with evidence whose class reflects whether the probe was a real external
// daemon or a reference one. Each component is independent, so a single failed
// boundary does not mask the status of the others.
func QualifyReport(ctx context.Context, probe IsolationProbe) conformance.Report {
	collector := conformance.NewCollector()
	if probe == nil {
		for _, check := range RequiredChecks() {
			_ = collector.Add(conformance.Result{
				Component: check.Component,
				Status:    conformance.Unavailable,
				Reason:    fmt.Sprintf("no provisioned Docker daemon: %s (%s) requires a real daemon the harness can drive; record UNAVAILABLE and leave §53.11 unqualified", check.ID, check.Reference),
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
			result.Reason = fmt.Sprintf("hardening check %q could not run: %v", check.ID, err)
		case !outcome.Passed:
			result.Status = conformance.Fail
			result.Reason = fmt.Sprintf("hardening check %q (%s) failed", check.ID, check.Reference)
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
