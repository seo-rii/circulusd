package doctor

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/conformance"
)

func TestRunBindsSortedProbeEvidenceToTheCurrentInvocation(t *testing.T) {
	t.Parallel()

	observedAt := time.Date(2026, time.August, 27, 1, 2, 3, 0, time.UTC)
	digest := "sha256:" + strings.Repeat("a", 64)
	report, err := Run(context.Background(), Plan{
		RunID:         "doctor-run-1",
		Profile:       conformance.Profile{Name: "lightweight", Production: true, Required: []string{"state", "nsjail"}},
		ConfigDigest:  digest,
		ReleaseDigest: digest,
		HostID:        "host-1",
		Clock:         func() time.Time { return observedAt },
		Probes: []Probe{
			{
				Component: "state",
				Run: func(context.Context) conformance.Result {
					return conformance.Result{Component: "state", Status: conformance.Pass}
				},
			},
			{
				Component: "nsjail",
				Run: func(context.Context) conformance.Result {
					return conformance.Result{
						Component: "nsjail",
						Status:    conformance.Unavailable,
						Reason:    "binary missing",
					}
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if report.SchemaVersion != 1 || report.RunID != "doctor-run-1" ||
		report.Profile != "lightweight" || report.ConfigDigest != digest ||
		report.ReleaseDigest != digest || report.HostID != "host-1" {
		t.Fatalf("Run() identity = %+v", report)
	}
	if !report.StartedAt.Equal(observedAt) || !report.FinishedAt.Equal(observedAt) {
		t.Fatalf("Run() timestamps = %v..%v, want %v", report.StartedAt, report.FinishedAt, observedAt)
	}
	if report.ProductionEligible {
		t.Fatal("Run() ProductionEligible = true with unavailable required backend")
	}
	if len(report.Results) != 2 || report.Results[0].Component != "nsjail" ||
		report.Results[1].Component != "state" {
		t.Fatalf("Run() results = %+v, want sorted components", report.Results)
	}
}

func TestRunFailsClosedForSyntheticAndMissingRequiredEvidence(t *testing.T) {
	t.Parallel()

	digest := "sha256:" + strings.Repeat("b", 64)
	report, err := Run(context.Background(), Plan{
		RunID:         "doctor-run-2",
		Profile:       conformance.Profile{Name: "production", Production: true, Required: []string{"celld", "workerd"}},
		ConfigDigest:  digest,
		ReleaseDigest: digest,
		HostID:        "host-2",
		Clock:         time.Now,
		Probes: []Probe{{
			Component: "celld",
			Run: func(context.Context) conformance.Result {
				return conformance.Result{
					Component: "celld",
					Status:    conformance.Pass,
					Evidence:  conformance.Evidence{Mock: true},
				}
			},
		}},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if report.ProductionEligible {
		t.Fatal("Run() ProductionEligible = true for synthetic production evidence")
	}
	if len(report.Results) != 2 || report.Results[1].Component != "workerd" ||
		report.Results[1].Status != conformance.NotRun {
		t.Fatalf("Run() results = %+v, want missing workerd NOT_RUN", report.Results)
	}
	if report.FailureReason == "" {
		t.Fatal("Run() FailureReason is empty")
	}
}

func TestRunNeverLabelsANonProductionProfileProductionEligible(t *testing.T) {
	t.Parallel()

	digest := "sha256:" + strings.Repeat("e", 64)
	report, err := Run(context.Background(), Plan{
		RunID:         "doctor-run-development",
		Profile:       conformance.Profile{Name: "development", Required: []string{"reference-state"}},
		ConfigDigest:  digest,
		ReleaseDigest: digest,
		HostID:        "host-development",
		Clock:         time.Now,
		Probes: []Probe{{
			Component: "reference-state",
			Run: func(context.Context) conformance.Result {
				return conformance.Result{Component: "reference-state", Status: conformance.Pass}
			},
		}},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !report.ProfileQualified {
		t.Fatal("Run() ProfileQualified = false for a passing development profile")
	}
	if report.ProductionEligible {
		t.Fatal("Run() ProductionEligible = true for a non-production profile")
	}
}

func TestRunRejectsAmbiguousOrUnboundPlansBeforeExecutingProbes(t *testing.T) {
	t.Parallel()

	digest := "sha256:" + strings.Repeat("c", 64)
	executed := false
	probe := Probe{
		Component: "state",
		Run: func(context.Context) conformance.Result {
			executed = true
			return conformance.Result{Component: "state", Status: conformance.Pass}
		},
	}
	invalidPlans := []Plan{
		{
			RunID:         "doctor-run-empty",
			Profile:       conformance.Profile{Name: "production", Production: true},
			ConfigDigest:  digest,
			ReleaseDigest: digest,
			HostID:        "host-3",
			Clock:         time.Now,
		},
		{
			RunID:         "doctor-run-3",
			Profile:       conformance.Profile{Name: "production", Production: true, Required: []string{"state"}},
			ConfigDigest:  "sha256:invalid",
			ReleaseDigest: digest,
			HostID:        "host-3",
			Clock:         time.Now,
			Probes:        []Probe{probe},
		},
		{
			RunID:         "doctor-run-3",
			Profile:       conformance.Profile{Name: "production", Production: true, Required: []string{"state"}},
			ConfigDigest:  digest,
			ReleaseDigest: digest,
			HostID:        "host-3",
			Clock:         time.Now,
			Probes:        []Probe{probe, probe},
		},
	}
	for index, plan := range invalidPlans {
		if _, err := Run(context.Background(), plan); err == nil {
			t.Fatalf("Run(invalidPlans[%d]) error = nil", index)
		}
	}
	if executed {
		t.Fatal("Run() executed a probe before validating the complete plan")
	}
}

func TestRunConvertsProbeContractViolationsAndPanicsToFail(t *testing.T) {
	t.Parallel()

	digest := "sha256:" + strings.Repeat("d", 64)
	report, err := Run(context.Background(), Plan{
		RunID:         "doctor-run-4",
		Profile:       conformance.Profile{Name: "development", Required: []string{"mismatch", "panic"}},
		ConfigDigest:  digest,
		ReleaseDigest: digest,
		HostID:        "host-4",
		Clock:         time.Now,
		Probes: []Probe{
			{
				Component: "mismatch",
				Run: func(context.Context) conformance.Result {
					return conformance.Result{Component: "other", Status: conformance.Pass}
				},
			},
			{
				Component: "panic",
				Run:       func(context.Context) conformance.Result { panic("secret panic detail") },
			},
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	for _, result := range report.Results {
		if result.Status != conformance.Fail {
			t.Fatalf("result %q status = %q, want FAIL", result.Component, result.Status)
		}
		if strings.Contains(result.Reason, "secret panic detail") {
			t.Fatalf("result %q leaked panic detail: %q", result.Component, result.Reason)
		}
	}
}
