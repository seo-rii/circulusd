package firecracker

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/hancomac/circulusd/internal/conformance"
)

type fakeProbe struct {
	provenance Provenance
	failID     string
	errorID    string
}

func (probe fakeProbe) Provenance() Provenance { return probe.provenance }

func (probe fakeProbe) RunCheck(_ context.Context, check Check) (CheckOutcome, error) {
	switch check.ID {
	case probe.errorID:
		return CheckOutcome{}, errors.New("probe transport error")
	case probe.failID:
		return CheckOutcome{Passed: false, Detail: "observed a guest NIC"}, nil
	default:
		return CheckOutcome{Passed: true}, nil
	}
}

// doctorRequiredFirecrackerComponents is the per-check component set
// internal/doctor's production ConformanceProfile requires for the firecracker
// backend (host.kvm-access is a host-probe property, not this sandbox gate).
// This gate must produce exactly this set so the doctor profile cannot require a
// component nothing emits.
var doctorRequiredFirecrackerComponents = []string{
	"firecracker.boot",
	"firecracker.command",
	"firecracker.jailer",
	"firecracker.limits",
	"firecracker.no-nic",
	"firecracker.scratch-cleanup",
	"firecracker.unique-uid",
	"firecracker.vsock-sandboxd",
	"firecracker.workspace-roundtrip",
}

func index(report conformance.Report) map[string]conformance.Result {
	byComponent := make(map[string]conformance.Result, len(report.Results))
	for _, result := range report.Results {
		byComponent[result.Component] = result
	}
	return byComponent
}

func mustCollect(t *testing.T, report conformance.Report) {
	t.Helper()
	collector := conformance.NewCollector()
	if err := collector.Merge(report); err != nil {
		t.Fatalf("report failed conformance validation: %v", err)
	}
}

func TestQualifyReportWithoutProbeIsUnavailablePerComponent(t *testing.T) {
	t.Parallel()
	report := QualifyReport(context.Background(), nil)
	byComponent := index(report)
	for _, component := range doctorRequiredFirecrackerComponents {
		result, found := byComponent[component]
		if !found {
			t.Fatalf("component %q missing from report", component)
		}
		if result.Status != conformance.Unavailable {
			t.Fatalf("component %q = %s, want UNAVAILABLE", component, result.Status)
		}
		if strings.TrimSpace(result.Reason) == "" {
			t.Fatalf("UNAVAILABLE component %q must carry a reason", component)
		}
	}
	if len(report.Results) != len(doctorRequiredFirecrackerComponents) {
		t.Fatalf("report has %d results, want %d", len(report.Results), len(doctorRequiredFirecrackerComponents))
	}
	mustCollect(t, report)
}

func TestQualifyReportReferenceProbePassesButIsNotPromotable(t *testing.T) {
	t.Parallel()
	report := QualifyReport(context.Background(), fakeProbe{provenance: Provenance{Version: "1.7", Reference: true}})
	for _, result := range report.Results {
		if result.Status != conformance.Pass {
			t.Fatalf("component %q = %s, want PASS", result.Component, result.Status)
		}
		if !result.Evidence.Mock || result.Evidence.Class != conformance.EvidenceClassReferenceOnly {
			t.Fatalf("component %q reference evidence = %+v, want mock reference-only", result.Component, result.Evidence)
		}
	}
	mustCollect(t, report)

	collector := conformance.NewCollector()
	if err := collector.Merge(report); err != nil {
		t.Fatalf("Merge() error = %v", err)
	}
	profile := conformance.Profile{Name: "production", Production: true, Required: doctorRequiredFirecrackerComponents}
	if err := collector.Evaluate(profile); err == nil {
		t.Fatal("production profile accepted a reference/mock Firecracker report")
	}
}

func TestQualifyReportNonReferenceProbeSatisfiesProductionProfile(t *testing.T) {
	t.Parallel()
	report := QualifyReport(context.Background(), fakeProbe{provenance: Provenance{Version: "1.7", Reference: false}})
	for _, result := range report.Results {
		if result.Status != conformance.Pass {
			t.Fatalf("component %q = %s, want PASS", result.Component, result.Status)
		}
		if result.Evidence.Mock || result.Evidence.Class != conformance.EvidenceClassExternal {
			t.Fatalf("component %q evidence = %+v, want external non-mock", result.Component, result.Evidence)
		}
	}

	collector := conformance.NewCollector()
	if err := collector.Merge(report); err != nil {
		t.Fatalf("Merge() error = %v", err)
	}
	profile := conformance.Profile{Name: "production", Production: true, Required: doctorRequiredFirecrackerComponents}
	if err := collector.Evaluate(profile); err != nil {
		t.Fatalf("production profile rejected an external Firecracker report: %v", err)
	}
}

func TestQualifyReportFailsOnlyTheFailedComponent(t *testing.T) {
	t.Parallel()
	report := QualifyReport(context.Background(), fakeProbe{failID: "no-guest-nic"})
	byComponent := index(report)
	failed := byComponent["firecracker.no-nic"]
	if failed.Status != conformance.Fail {
		t.Fatalf("firecracker.no-nic = %s, want FAIL", failed.Status)
	}
	if !strings.Contains(failed.Reason, "no-guest-nic") {
		t.Fatalf("reason %q should name the failed check", failed.Reason)
	}
	for component, result := range byComponent {
		if component == "firecracker.no-nic" {
			continue
		}
		if result.Status != conformance.Pass {
			t.Fatalf("component %q = %s, want PASS (a single failed boundary must not mask the others)", component, result.Status)
		}
	}
	mustCollect(t, report)
}

func TestQualifyReportUnavailableOnlyForTheErroredComponent(t *testing.T) {
	t.Parallel()
	report := QualifyReport(context.Background(), fakeProbe{errorID: "jailer"})
	byComponent := index(report)
	errored := byComponent["firecracker.jailer"]
	if errored.Status != conformance.Unavailable {
		t.Fatalf("firecracker.jailer = %s, want UNAVAILABLE", errored.Status)
	}
	if !strings.Contains(errored.Reason, "jailer") {
		t.Fatalf("reason %q should name the check that could not run", errored.Reason)
	}
	for component, result := range byComponent {
		if component == "firecracker.jailer" {
			continue
		}
		if result.Status != conformance.Pass {
			t.Fatalf("component %q = %s, want PASS", component, result.Status)
		}
	}
	mustCollect(t, report)
}

func TestRequiredChecksMatchDoctorComponentSet(t *testing.T) {
	t.Parallel()
	seenID := make(map[string]struct{})
	components := make([]string, 0, len(RequiredChecks()))
	for _, check := range RequiredChecks() {
		if _, duplicate := seenID[check.ID]; duplicate {
			t.Fatalf("duplicate check id %q", check.ID)
		}
		seenID[check.ID] = struct{}{}
		if check.Reference == "" || check.Description == "" {
			t.Fatalf("check %q is missing its SPEC reference or description", check.ID)
		}
		if check.Component == "" {
			t.Fatalf("check %q is missing its conformance component", check.ID)
		}
		components = append(components, check.Component)
	}
	sort.Strings(components)

	want := append([]string(nil), doctorRequiredFirecrackerComponents...)
	sort.Strings(want)
	if len(components) != len(want) {
		t.Fatalf("RequiredChecks produced %d components, want %d", len(components), len(want))
	}
	for i := range want {
		if components[i] != want[i] {
			t.Fatalf("component set drifted from the doctor profile: got %v, want %v", components, want)
		}
	}
}
