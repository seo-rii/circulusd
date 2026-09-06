// Package mcp defines the MCP execution conformance gate. It is the MCP
// analogue of internal/conformance/nsjail: it enumerates the properties a
// provisioned stdio MCP server running inside a selected execution backend must
// prove for MCP tool execution to qualify (SPEC §53.14), and produces a
// conformance.Result.
//
// The checks require a real MCP server process running inside a real NsJail,
// Docker, or Firecracker backend the harness can drive. Without a provisioned
// ExecutionProbe this gate returns UNAVAILABLE, never PASS — a reference or mock
// probe can only produce reference-only (non-promotable) evidence. §53.14
// therefore stays NOT_RUN until this gate returns a fresh external PASS from a
// provisioned host. The in-process internal/mcpgateway unit tests exercise the
// broker, protocol, filter, cancellation, and restart logic but never satisfy
// this gate, because they prove nothing about server-process confinement inside
// a real backend.
package mcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/hancomac/circulusd/internal/conformance"
)

// Component is the conformance component id for the MCP execution gate.
const Component = "runtime.mcp"

// Check is one required MCP execution property.
type Check struct {
	ID          string
	Reference   string // the SPEC clause the check enforces
	Description string
}

// RequiredChecks returns the properties a provisioned MCP-in-backend integration
// must satisfy. All must hold for the gate to PASS. The set mirrors SPEC §53.14
// one-to-one so a real run cannot silently drop a boundary.
func RequiredChecks() []Check {
	return []Check{
		{
			ID:          "stdio-in-selected-backend",
			Reference:   "SPEC §53.14",
			Description: "the stdio MCP server runs inside the selected execution backend",
		},
		{
			ID:          "no-nsjail-escape",
			Reference:   "SPEC §53.14",
			Description: "with NsJail selected, no server process is created outside the NsJail sandbox",
		},
		{
			ID:          "no-docker-escape",
			Reference:   "SPEC §53.14",
			Description: "with Docker selected, no server process is created outside the container",
		},
		{
			ID:          "no-firecracker-escape",
			Reference:   "SPEC §53.14",
			Description: "with Firecracker selected, no server process is created outside the guest",
		},
		{
			ID:          "long-lived-multiplexing",
			Reference:   "SPEC §53.14",
			Description: "multiple JSON-RPC requests are delivered to the same long-lived server process",
		},
		{
			ID:          "cancellation-and-death",
			Reference:   "SPEC §53.14",
			Description: "request cancellation and server death are handled",
		},
		{
			ID:          "denied-tool-rejected-at-call",
			Reference:   "SPEC §53.14",
			Description: "a denied MCP tool is rejected even at the actual call stage",
		},
		{
			ID:          "credential-nonexposure",
			Reference:   "SPEC §53.14",
			Description: "credential raw values are never passed to the Pi Worker",
		},
		{
			ID:          "sampling-elicitation-default-deny",
			Reference:   "SPEC §53.14",
			Description: "server-initiated sampling/elicitation requests are denied by default and audited",
		},
		{
			ID:          "protocol-version-pin-fail-closed",
			Reference:   "SPEC §53.14",
			Description: "an MCP protocol version pin mismatch fails closed",
		},
	}
}

// Provenance is the release and host identity of the qualified MCP integration.
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

// CheckOutcome is the result of running one execution check against a live MCP
// server inside a real backend.
type CheckOutcome struct {
	Passed bool
	Detail string
}

// ExecutionProbe drives the MCP checks against a provisioned stdio MCP server
// running inside a real execution backend. The production implementation is
// external work against a real host; there is no in-process implementation, so
// callers without a host pass nil and receive UNAVAILABLE.
type ExecutionProbe interface {
	Provenance() Provenance
	RunCheck(ctx context.Context, check Check) (CheckOutcome, error)
}

// Qualify runs the MCP execution gate. A nil probe (no provisioned integration)
// yields UNAVAILABLE; a check that cannot run yields UNAVAILABLE; a check that
// does not hold yields FAIL; all checks holding yields PASS with evidence whose
// class reflects whether the probe was a real external host or a reference one.
func Qualify(ctx context.Context, probe ExecutionProbe) conformance.Result {
	if probe == nil {
		return conformance.Result{
			Component: Component,
			Status:    conformance.Unavailable,
			Reason:    "no provisioned MCP-in-backend integration: the gate requires a real stdio MCP server running inside a selected NsJail/Docker/Firecracker backend; record UNAVAILABLE and leave §53.14 unqualified",
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
				Reason:    fmt.Sprintf("MCP check %q could not run: %v", check.ID, err),
				Evidence:  evidence(provenance),
			}
		}
		if !outcome.Passed {
			reason := fmt.Sprintf("MCP check %q (%s) failed", check.ID, check.Reference)
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
