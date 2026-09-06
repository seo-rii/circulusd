// Package filesystem defines the workspace-filesystem conformance gate. It
// enumerates the durable-write, manifest-diff, symlink, special-file, blob,
// recovery, lease, and overlay properties a provisioned workspace filesystem
// must prove (SPEC §53.8), and produces a conformance.Result.
//
// The checks require a real sandbox writing through a real overlay/manifest
// pipeline into the durable Workspace DO. Without a provisioned FilesystemProbe
// this gate returns UNAVAILABLE, never PASS — a reference or mock probe can only
// produce reference-only (non-promotable) evidence. §53.8 therefore stays
// NOT_RUN until this gate returns a fresh external PASS from a provisioned host.
// The in-process internal/workspace manifest/blob/aggregate tests exercise the
// diff, symlink, and lease logic but never satisfy this gate.
package filesystem

import (
	"context"
	"fmt"
	"strings"

	"github.com/hancomac/circulusd/internal/conformance"
)

// Component is the conformance component id for the workspace-filesystem gate.
const Component = "workspace.filesystem"

// Check is one required workspace-filesystem property.
type Check struct {
	ID          string
	Reference   string // the SPEC clause the check enforces
	Description string
}

// RequiredChecks returns the properties a provisioned workspace filesystem must
// satisfy. All must hold for the gate to PASS. The set mirrors SPEC §53.8
// one-to-one so a real run cannot silently drop a boundary.
func RequiredChecks() []Check {
	return []Check{
		{
			ID:          "direct-write-durable-revision",
			Reference:   "SPEC §53.8",
			Description: "a direct write is durable as a Workspace DO revision",
		},
		{
			ID:          "manifest-diff-reflects-fs-ops",
			Reference:   "SPEC §53.8",
			Description: "file create/modify/delete/rename/chmod are reflected in the manifest diff",
		},
		{
			ID:          "absolute-symlink-rejected",
			Reference:   "SPEC §53.8",
			Description: "an absolute symlink is rejected",
		},
		{
			ID:          "escaping-symlink-rejected",
			Reference:   "SPEC §53.8",
			Description: "a symlink escaping the workspace is rejected",
		},
		{
			ID:          "special-file-commit-rejected",
			Reference:   "SPEC §53.8",
			Description: "a durable commit of a device, FIFO, or socket is rejected",
		},
		{
			ID:          "large-blob-upload",
			Reference:   "SPEC §53.8",
			Description: "a large file blob upload with metadata commit works",
		},
		{
			ID:          "sandbox-kill-restores-revision",
			Reference:   "SPEC §53.8",
			Description: "after a sandbox kill the last committed revision is restored",
		},
		{
			ID:          "stale-sandbox-commit-rejected",
			Reference:   "SPEC §53.8",
			Description: "a stale sandbox commit is rejected",
		},
		{
			ID:          "single-mutable-writer-lease",
			Reference:   "SPEC §53.8",
			Description: "two mutable writer leases cannot be held concurrently",
		},
		{
			ID:          "no-lease-write-blocked",
			Reference:   "SPEC §53.8",
			Description: "an invocation without write permission runs without a lease and /workspace writes are blocked",
		},
		{
			ID:          "overlay-fullscan-diff-equal",
			Reference:   "SPEC §53.8",
			Description: "where overlayfs diff is supported, the overlay mutation set equals the full-scan diff",
		},
	}
}

// Provenance is the release and host identity of the qualified filesystem.
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

// CheckOutcome is the result of running one workspace-filesystem check.
type CheckOutcome struct {
	Passed bool
	Detail string
}

// FilesystemProbe drives the workspace-filesystem checks against a provisioned
// sandbox and manifest pipeline. The production implementation is external work
// against a real host; there is no in-process implementation, so callers
// without a host pass nil and receive UNAVAILABLE.
type FilesystemProbe interface {
	Provenance() Provenance
	RunCheck(ctx context.Context, check Check) (CheckOutcome, error)
}

// Qualify runs the workspace-filesystem gate. A nil probe yields UNAVAILABLE; a
// check that cannot run yields UNAVAILABLE; a check that does not hold yields
// FAIL; all checks holding yields PASS with evidence whose class reflects
// whether the probe was a real external host or a reference one.
func Qualify(ctx context.Context, probe FilesystemProbe) conformance.Result {
	if probe == nil {
		return conformance.Result{
			Component: Component,
			Status:    conformance.Unavailable,
			Reason:    "no provisioned workspace filesystem: the gate requires a real sandbox writing through a real overlay/manifest pipeline into the durable Workspace DO; record UNAVAILABLE and leave §53.8 unqualified",
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
				Reason:    fmt.Sprintf("filesystem check %q could not run: %v", check.ID, err),
				Evidence:  evidence(provenance),
			}
		}
		if !outcome.Passed {
			reason := fmt.Sprintf("filesystem check %q (%s) failed", check.ID, check.Reference)
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
