package configuration

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
		return CheckOutcome{Passed: false, Detail: "startup continued on a permissive default"}, nil
	default:
		return CheckOutcome{Passed: true}, nil
	}
}

// doctorRequiredConfigurationComponents is the per-check component set
// internal/doctor's production ConformanceProfile requires for fail-closed
// configuration loading. This gate must produce exactly this set so the doctor
// profile cannot require a component nothing emits.
var doctorRequiredConfigurationComponents = []string{
	"configuration.fail-closed",
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
	for _, component := range doctorRequiredConfigurationComponents {
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
	if len(report.Results) != len(doctorRequiredConfigurationComponents) {
		t.Fatalf("report has %d results, want %d", len(report.Results), len(doctorRequiredConfigurationComponents))
	}
	mustCollect(t, report)
}

func TestQualifyReportReferenceProbePassesButIsNotPromotable(t *testing.T) {
	t.Parallel()
	report := QualifyReport(context.Background(), fakeProbe{provenance: Provenance{Version: "1.0", Reference: true}})
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
	profile := conformance.Profile{Name: "production", Production: true, Required: doctorRequiredConfigurationComponents}
	if err := collector.Evaluate(profile); err == nil {
		t.Fatal("production profile accepted a reference/mock configuration report")
	}
}

func TestQualifyReportNonReferenceProbeSatisfiesProductionProfile(t *testing.T) {
	t.Parallel()
	report := QualifyReport(context.Background(), fakeProbe{provenance: Provenance{Version: "1.0", Reference: false}})
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
	profile := conformance.Profile{Name: "production", Production: true, Required: doctorRequiredConfigurationComponents}
	if err := collector.Evaluate(profile); err != nil {
		t.Fatalf("production profile rejected an external configuration report: %v", err)
	}
}

func TestQualifyReportFailIsFail(t *testing.T) {
	t.Parallel()
	report := QualifyReport(context.Background(), fakeProbe{failID: "fail-closed"})
	failed := index(report)["configuration.fail-closed"]
	if failed.Status != conformance.Fail {
		t.Fatalf("configuration.fail-closed = %s, want FAIL", failed.Status)
	}
	if !strings.Contains(failed.Reason, "fail-closed") {
		t.Fatalf("reason %q should name the failed check", failed.Reason)
	}
	mustCollect(t, report)
}

func TestQualifyReportProbeErrorIsUnavailable(t *testing.T) {
	t.Parallel()
	report := QualifyReport(context.Background(), fakeProbe{errorID: "fail-closed"})
	errored := index(report)["configuration.fail-closed"]
	if errored.Status != conformance.Unavailable {
		t.Fatalf("configuration.fail-closed = %s, want UNAVAILABLE", errored.Status)
	}
	if !strings.Contains(errored.Reason, "fail-closed") {
		t.Fatalf("reason %q should name the check that could not run", errored.Reason)
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

	want := append([]string(nil), doctorRequiredConfigurationComponents...)
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
