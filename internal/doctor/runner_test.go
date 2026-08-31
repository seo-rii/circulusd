package doctor

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
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
		RunID:              "doctor-run-1",
		Profile:            conformance.Profile{Name: "lightweight", Production: true, Required: []string{"state", "nsjail"}},
		ConfigDigest:       digest,
		ReleaseDigest:      digest,
		HostID:             "host-1",
		RunnerBinaryDigest: digest,
		TargetInstanceID:   "single-node-1",
		Clock:              func() time.Time { return observedAt },
		Probes: []Probe{
			{
				Component: "state",
				Run: func(context.Context) conformance.Result {
					return conformance.Result{
						Component: "state",
						Status:    conformance.Pass,
						Evidence: conformance.Evidence{
							Class: conformance.EvidenceClassExternal,
							ArtifactReferences: []conformance.ArtifactReference{{
								Name: "state-app.wasm", Digest: digest,
							}},
						},
					}
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
	if report.SchemaVersion != 1 || report.APIVersion != "v1alpha" || report.RunID != "doctor-run-1" ||
		report.Profile != "lightweight" || report.ConfigDigest != digest ||
		report.ReleaseDigest != digest || report.HostID != "host-1" ||
		report.RunnerBinaryDigest != digest || report.TargetInstanceID != "single-node-1" ||
		!report.ProductionProfile || !reflect.DeepEqual(report.RequiredComponents, []string{"nsjail", "state"}) {
		t.Fatalf("Run() identity = %+v", report)
	}
	if !report.StartedAt.Equal(observedAt) || !report.FinishedAt.Equal(observedAt) || !report.ObservedAt.Equal(observedAt) {
		t.Fatalf("Run() timestamps = %v..%v, want %v", report.StartedAt, report.FinishedAt, observedAt)
	}
	if report.ProductionEligible {
		t.Fatal("Run() ProductionEligible = true with unavailable required backend")
	}
	if len(report.Results) != 2 || report.Results[0].Component != "nsjail" ||
		report.Results[1].Component != "state" {
		t.Fatalf("Run() results = %+v, want sorted components", report.Results)
	}
	if report.Results[1].Evidence.Class != conformance.EvidenceClassExternal ||
		len(report.Results[1].Evidence.ArtifactReferences) != 1 {
		t.Fatalf("Run() state evidence = %+v", report.Results[1].Evidence)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("Marshal(report) error = %v", err)
	}
	if !strings.Contains(string(encoded), `"apiVersion":"v1alpha"`) ||
		!strings.Contains(string(encoded), `"probeRunId":"doctor-run-1"`) ||
		strings.Contains(string(encoded), `"runId"`) ||
		!strings.Contains(string(encoded), `"artifactReferences"`) {
		t.Fatalf("doctor JSON identity = %s", encoded)
	}
}

func TestRunOwnsProbePlanBeforeExecutingCallbacks(t *testing.T) {
	t.Parallel()

	digest := "sha256:" + strings.Repeat("9", 64)
	pass := func(component string) conformance.Result {
		return conformance.Result{
			Component: component,
			Status:    conformance.Pass,
			Evidence:  conformance.Evidence{Class: conformance.EvidenceClassExternal},
		}
	}
	var plan Plan
	plan = Plan{
		RunID:              "doctor-owned-plan",
		Profile:            conformance.Profile{Name: "production", Production: true, Required: []string{"first", "second"}},
		ConfigDigest:       digest,
		ReleaseDigest:      digest,
		HostID:             "host-owned-plan",
		RunnerBinaryDigest: digest,
		TargetInstanceID:   "target-owned-plan",
		Clock:              time.Now,
		Probes: []Probe{
			{
				Component: "first",
				Run: func(context.Context) conformance.Result {
					plan.Probes[1].Run = func(context.Context) conformance.Result {
						return pass("second")
					}
					return pass("first")
				},
			},
			{
				Component: "second",
				Run: func(context.Context) conformance.Result {
					return conformance.Result{
						Component: "second",
						Status:    conformance.Fail,
						Reason:    "original probe failed",
						Evidence:  conformance.Evidence{Class: conformance.EvidenceClassExternal},
					}
				},
			},
		},
	}

	report, err := Run(context.Background(), plan)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if report.ProfileQualified || report.Results[1].Component != "second" ||
		report.Results[1].Status != conformance.Fail {
		t.Fatalf("Run() observed callback-mutated probe plan: %+v", report)
	}
}

func TestRunCanonicalizesAndValidatesArtifactReferenceSets(t *testing.T) {
	t.Parallel()

	observedAt := time.Date(2026, time.August, 27, 2, 3, 4, 0, time.UTC)
	digest := "sha256:" + strings.Repeat("7", 64)
	report, err := Run(context.Background(), Plan{
		RunID:              "doctor-artifact-order",
		Profile:            conformance.Profile{Name: "production", Production: true, Required: []string{"state"}},
		ConfigDigest:       digest,
		ReleaseDigest:      digest,
		HostID:             "host-artifact-order",
		RunnerBinaryDigest: digest,
		TargetInstanceID:   "target-artifact-order",
		Clock:              func() time.Time { return observedAt },
		Probes: []Probe{{
			Component: "state",
			Run: func(context.Context) conformance.Result {
				return conformance.Result{
					Component: "state",
					Status:    conformance.Pass,
					Evidence: conformance.Evidence{
						Class: conformance.EvidenceClassExternal,
						ArtifactReferences: []conformance.ArtifactReference{
							{Name: "zeta", Digest: digest},
							{Name: "alpha", Digest: digest},
						},
					},
				}
			},
		}},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	artifacts := report.Results[0].Evidence.ArtifactReferences
	if len(artifacts) != 2 || artifacts[0].Name != "alpha" || artifacts[1].Name != "zeta" {
		t.Fatalf("Run() artifacts = %+v, want canonical name order", artifacts)
	}

	current := CurrentIdentity{
		Profile:            report.Profile,
		ConfigDigest:       digest,
		ReleaseDigest:      digest,
		HostID:             report.HostID,
		RunnerBinaryDigest: digest,
		TargetInstanceID:   report.TargetInstanceID,
		ProductionProfile:  true,
		RequiredComponents: []string{"state"},
		Now:                observedAt,
		MaximumAge:         time.Minute,
	}
	report.Results[0].Evidence.ArtifactReferences[0], report.Results[0].Evidence.ArtifactReferences[1] =
		report.Results[0].Evidence.ArtifactReferences[1], report.Results[0].Evidence.ArtifactReferences[0]
	if err := ValidateCurrent(report, current); err == nil {
		t.Fatal("ValidateCurrent() accepted noncanonical artifact reference order")
	}
}

func TestRunFailsClosedForSyntheticAndMissingRequiredEvidence(t *testing.T) {
	t.Parallel()

	digest := "sha256:" + strings.Repeat("b", 64)
	report, err := Run(context.Background(), Plan{
		RunID:              "doctor-run-2",
		Profile:            conformance.Profile{Name: "production", Production: true, Required: []string{"celld", "workerd"}},
		ConfigDigest:       digest,
		ReleaseDigest:      digest,
		HostID:             "host-2",
		RunnerBinaryDigest: digest,
		TargetInstanceID:   "single-node-2",
		Clock:              time.Now,
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
		RunID:              "doctor-run-development",
		Profile:            conformance.Profile{Name: "development", Required: []string{"reference-state"}},
		ConfigDigest:       digest,
		ReleaseDigest:      digest,
		HostID:             "host-development",
		RunnerBinaryDigest: digest,
		TargetInstanceID:   "development-node",
		Clock:              time.Now,
		Probes: []Probe{{
			Component: "reference-state",
			Run: func(context.Context) conformance.Result {
				return conformance.Result{
					Component: "reference-state",
					Status:    conformance.Pass,
					Evidence: conformance.Evidence{
						Class: conformance.EvidenceClassReferenceOnly,
						Mock:  true,
					},
				}
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

func TestRunReturnsCancellationObservedAtTheFinalClockBoundary(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	digest := "sha256:" + strings.Repeat("8", 64)
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	clockCalls := 0
	report, err := Run(ctx, Plan{
		RunID:              "doctor-final-cancel",
		Profile:            conformance.Profile{Name: "production", Production: true, Required: []string{"state"}},
		ConfigDigest:       digest,
		ReleaseDigest:      digest,
		HostID:             "host-final-cancel",
		RunnerBinaryDigest: digest,
		TargetInstanceID:   "target-final-cancel",
		Clock: func() time.Time {
			clockCalls++
			if clockCalls == 2 {
				cancel()
			}
			return now
		},
		Probes: []Probe{{
			Component: "state",
			Run: func(context.Context) conformance.Result {
				return conformance.Result{
					Component: "state",
					Status:    conformance.Pass,
					Evidence:  conformance.Evidence{Class: conformance.EvidenceClassExternal},
				}
			},
		}},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
	if !reflect.DeepEqual(report, Report{}) {
		t.Fatalf("Run() report = %+v, want zero report after cancellation", report)
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
			RunID:              "doctor-run-empty",
			Profile:            conformance.Profile{Name: "production", Production: true},
			ConfigDigest:       digest,
			ReleaseDigest:      digest,
			HostID:             "host-3",
			RunnerBinaryDigest: digest,
			TargetInstanceID:   "single-node-3",
			Clock:              time.Now,
		},
		{
			RunID:              "doctor-run-3",
			Profile:            conformance.Profile{Name: "production", Production: true, Required: []string{"state"}},
			ConfigDigest:       "sha256:invalid",
			ReleaseDigest:      digest,
			HostID:             "host-3",
			RunnerBinaryDigest: digest,
			TargetInstanceID:   "single-node-3",
			Clock:              time.Now,
			Probes:             []Probe{probe},
		},
		{
			RunID:              "doctor-run-3",
			Profile:            conformance.Profile{Name: "production", Production: true, Required: []string{"state"}},
			ConfigDigest:       digest,
			ReleaseDigest:      digest,
			HostID:             "host-3",
			RunnerBinaryDigest: digest,
			TargetInstanceID:   "single-node-3",
			Clock:              time.Now,
			Probes:             []Probe{probe, probe},
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
		RunID:              "doctor-run-4",
		Profile:            conformance.Profile{Name: "development", Required: []string{"mismatch", "panic"}},
		ConfigDigest:       digest,
		ReleaseDigest:      digest,
		HostID:             "host-4",
		RunnerBinaryDigest: digest,
		TargetInstanceID:   "single-node-4",
		Clock:              time.Now,
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

func TestRunRejectsUnclassifiedReferenceAndCanceledProductionPasses(t *testing.T) {
	t.Parallel()

	digest := "sha256:" + strings.Repeat("f", 64)
	tests := []struct {
		name       string
		result     conformance.Result
		cancelRun  bool
		wantStatus conformance.Status
		wantClass  conformance.EvidenceClass
	}{
		{
			name: "unclassified",
			result: conformance.Result{
				Component: "state.kill-durability",
				Status:    conformance.Pass,
			},
			wantStatus: conformance.Fail,
			wantClass:  conformance.EvidenceClassExternal,
		},
		{
			name: "reference only",
			result: conformance.Result{
				Component: "state.kill-durability",
				Status:    conformance.Pass,
				Evidence: conformance.Evidence{
					Class: conformance.EvidenceClassReferenceOnly,
				},
			},
			wantStatus: conformance.Pass,
			wantClass:  conformance.EvidenceClassReferenceOnly,
		},
		{
			name: "legacy mock",
			result: conformance.Result{
				Component: "state.kill-durability",
				Status:    conformance.Pass,
				Evidence:  conformance.Evidence{Mock: true},
			},
			wantStatus: conformance.Pass,
			wantClass:  conformance.EvidenceClassReferenceOnly,
		},
		{
			name: "canceled before success",
			result: conformance.Result{
				Component: "state.kill-durability",
				Status:    conformance.Pass,
				Evidence: conformance.Evidence{
					Class: conformance.EvidenceClassExternal,
				},
			},
			cancelRun:  true,
			wantStatus: conformance.NotRun,
			wantClass:  conformance.EvidenceClassExternal,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			report, err := Run(ctx, Plan{
				RunID:              "doctor-classification-1",
				Profile:            conformance.Profile{Name: "production", Production: true, Required: []string{"state.kill-durability"}},
				ConfigDigest:       digest,
				ReleaseDigest:      digest,
				HostID:             "host-classification",
				RunnerBinaryDigest: digest,
				TargetInstanceID:   "state-instance-1",
				Clock:              time.Now,
				Probes: []Probe{{
					Component: "state.kill-durability",
					Run: func(context.Context) conformance.Result {
						if test.cancelRun {
							cancel()
						}
						return test.result
					},
				}},
			})
			if test.cancelRun {
				if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(report, Report{}) {
					t.Fatalf("Run() = %+v, %v, want zero report and context.Canceled", report, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if report.ProfileQualified || report.ProductionEligible || len(report.Results) != 1 {
				t.Fatalf("Run() report = %+v, want rejected production evidence", report)
			}
			result := report.Results[0]
			if result.Status != test.wantStatus || result.Evidence.Class != test.wantClass ||
				result.Evidence.ArtifactReferences == nil {
				t.Fatalf("Run() result = %+v, want status=%s class=%s with artifactReferences", result, test.wantStatus, test.wantClass)
			}
		})
	}
}

func TestValidateCurrentMatchesEveryIdentityAndFreshnessBoundary(t *testing.T) {
	t.Parallel()

	observedAt := time.Date(2026, time.August, 27, 3, 4, 5, 0, time.UTC)
	digest := "sha256:" + strings.Repeat("9", 64)
	report, err := Run(context.Background(), Plan{
		RunID:              "doctor-current-1",
		Profile:            conformance.Profile{Name: "production", Production: true, Required: []string{"state.kill-durability"}},
		ConfigDigest:       digest,
		ReleaseDigest:      digest,
		HostID:             "host-current",
		RunnerBinaryDigest: digest,
		TargetInstanceID:   "state-instance-current",
		Clock:              func() time.Time { return observedAt },
		Probes: []Probe{{
			Component: "state.kill-durability",
			Run: func(context.Context) conformance.Result {
				return conformance.Result{
					Component: "state.kill-durability",
					Status:    conformance.Pass,
					Evidence: conformance.Evidence{
						Class: conformance.EvidenceClassExternal,
					},
				}
			},
		}},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	current := CurrentIdentity{
		Profile:            "production",
		ConfigDigest:       digest,
		ReleaseDigest:      digest,
		HostID:             "host-current",
		RunnerBinaryDigest: digest,
		TargetInstanceID:   "state-instance-current",
		ProductionProfile:  true,
		RequiredComponents: []string{"state.kill-durability"},
		Now:                observedAt.Add(time.Hour),
		MaximumAge:         time.Hour,
	}
	if err := ValidateCurrent(report, current); err != nil {
		t.Fatalf("ValidateCurrent(fresh) error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Report, *CurrentIdentity)
	}{
		{name: "profile", mutate: func(_ *Report, identity *CurrentIdentity) { identity.Profile = "full" }},
		{name: "configuration", mutate: func(_ *Report, identity *CurrentIdentity) {
			identity.ConfigDigest = "sha256:" + strings.Repeat("1", 64)
		}},
		{name: "release", mutate: func(_ *Report, identity *CurrentIdentity) {
			identity.ReleaseDigest = "sha256:" + strings.Repeat("2", 64)
		}},
		{name: "host", mutate: func(_ *Report, identity *CurrentIdentity) { identity.HostID = "host-replaced" }},
		{name: "runner binary", mutate: func(_ *Report, identity *CurrentIdentity) {
			identity.RunnerBinaryDigest = "sha256:" + strings.Repeat("3", 64)
		}},
		{name: "target instance", mutate: func(_ *Report, identity *CurrentIdentity) { identity.TargetInstanceID = "state-instance-replaced" }},
		{name: "expired", mutate: func(_ *Report, identity *CurrentIdentity) { identity.Now = observedAt.Add(time.Hour + time.Nanosecond) }},
		{name: "stale run start", mutate: func(candidate *Report, _ *CurrentIdentity) {
			candidate.StartedAt = observedAt.Add(-time.Nanosecond)
		}},
		{name: "future observation", mutate: func(candidate *Report, identity *CurrentIdentity) {
			candidate.ObservedAt = identity.Now.Add(time.Nanosecond)
		}},
		{name: "future finish", mutate: func(candidate *Report, identity *CurrentIdentity) {
			candidate.FinishedAt = identity.Now.Add(time.Nanosecond)
		}},
		{name: "zero maximum age", mutate: func(_ *Report, identity *CurrentIdentity) { identity.MaximumAge = 0 }},
		{name: "unbounded maximum age", mutate: func(_ *Report, identity *CurrentIdentity) { identity.MaximumAge = 24*time.Hour + time.Nanosecond }},
		{name: "wrong API version", mutate: func(candidate *Report, _ *CurrentIdentity) { candidate.APIVersion = "v1" }},
		{name: "forged qualified flag", mutate: func(candidate *Report, _ *CurrentIdentity) {
			candidate.ProfileQualified = !candidate.ProfileQualified
			candidate.ProductionEligible = false
			candidate.FailureReason = "forged"
		}},
		{name: "forged eligible flag", mutate: func(candidate *Report, _ *CurrentIdentity) {
			candidate.ProductionEligible = false
		}},
		{name: "forged failure reason", mutate: func(candidate *Report, _ *CurrentIdentity) {
			candidate.FailureReason = "forged"
		}},
		{name: "production profile marker", mutate: func(candidate *Report, _ *CurrentIdentity) {
			candidate.ProductionProfile = false
		}},
		{name: "required component set", mutate: func(candidate *Report, _ *CurrentIdentity) {
			candidate.RequiredComponents = []string{"host.kernel"}
		}},
		{name: "unsorted required components", mutate: func(candidate *Report, _ *CurrentIdentity) {
			candidate.RequiredComponents = []string{"state.kill-durability", "host.kernel"}
		}},
		{name: "passing result with failure reason", mutate: func(candidate *Report, _ *CurrentIdentity) {
			candidate.Results[0].Reason = "forged failure"
		}},
		{name: "optional failure without reason", mutate: func(candidate *Report, _ *CurrentIdentity) {
			candidate.Results = append(candidate.Results, conformance.Result{
				Component: "telemetry.optional",
				Status:    conformance.Fail,
				Evidence: conformance.Evidence{
					Class:              conformance.EvidenceClassExternal,
					ArtifactReferences: []conformance.ArtifactReference{},
				},
			})
		}},
		{name: "optional production reference pass", mutate: func(candidate *Report, _ *CurrentIdentity) {
			candidate.Results = append(candidate.Results, conformance.Result{
				Component: "telemetry.optional",
				Status:    conformance.Pass,
				Evidence: conformance.Evidence{
					Class:              conformance.EvidenceClassReferenceOnly,
					ArtifactReferences: []conformance.ArtifactReference{},
				},
			})
		}},
		{name: "host evidence for optional service failure", mutate: func(candidate *Report, _ *CurrentIdentity) {
			candidate.Results = append(candidate.Results, conformance.Result{
				Component: "telemetry.optional",
				Status:    conformance.Fail,
				Reason:    "diagnostic endpoint is disabled",
				Evidence: conformance.Evidence{
					Class:              conformance.EvidenceClassHostObservation,
					ArtifactReferences: []conformance.ArtifactReference{},
				},
			})
		}},
		{name: "oversized evidence version", mutate: func(candidate *Report, _ *CurrentIdentity) {
			candidate.Results[0].Evidence.Version = strings.Repeat("v", 129)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := report
			candidate.RequiredComponents = append([]string(nil), report.RequiredComponents...)
			candidate.Results = append([]conformance.Result(nil), report.Results...)
			for index := range candidate.Results {
				candidate.Results[index].Evidence.ArtifactReferences = make(
					[]conformance.ArtifactReference,
					len(report.Results[index].Evidence.ArtifactReferences),
				)
				copy(
					candidate.Results[index].Evidence.ArtifactReferences,
					report.Results[index].Evidence.ArtifactReferences,
				)
			}
			identity := current
			test.mutate(&candidate, &identity)
			if err := ValidateCurrent(candidate, identity); err == nil {
				t.Fatal("ValidateCurrent() error = nil, want stale or invalid evidence rejection")
			}
		})
	}

	optionalFailure := report
	optionalFailure.Results = append(optionalFailure.Results, conformance.Result{
		Component: "telemetry.optional",
		Status:    conformance.Fail,
		Reason:    "diagnostic endpoint is disabled",
		Evidence: conformance.Evidence{
			Class:              conformance.EvidenceClassExternal,
			ArtifactReferences: []conformance.ArtifactReference{},
		},
	})
	if err := ValidateCurrent(optionalFailure, current); err != nil {
		t.Fatalf("ValidateCurrent(optional failure) error = %v", err)
	}

	requiredSetSubstitution := report
	requiredSetSubstitution.Results = append(requiredSetSubstitution.Results, conformance.Result{
		Component: "telemetry.optional",
		Status:    conformance.Pass,
		Evidence: conformance.Evidence{
			Class:              conformance.EvidenceClassExternal,
			ArtifactReferences: []conformance.ArtifactReference{},
		},
	})
	requiredSetSubstitution.RequiredComponents = []string{"telemetry.optional"}
	if err := ValidateCurrent(requiredSetSubstitution, current); err == nil {
		t.Fatal("ValidateCurrent(required-set substitution) error = nil")
	}
}

func TestRunRejectsEvidenceWindowBeyondMaximumReportAge(t *testing.T) {
	t.Parallel()

	startedAt := time.Date(2026, time.August, 27, 3, 4, 5, 0, time.UTC)
	clockCalls := 0
	digest := "sha256:" + strings.Repeat("8", 64)
	_, err := Run(context.Background(), Plan{
		RunID:              "doctor-overlong-run",
		Profile:            conformance.Profile{Name: "production", Production: true, Required: []string{"state"}},
		ConfigDigest:       digest,
		ReleaseDigest:      digest,
		HostID:             "host-overlong-run",
		RunnerBinaryDigest: digest,
		TargetInstanceID:   "target-overlong-run",
		Clock: func() time.Time {
			clockCalls++
			if clockCalls == 1 {
				return startedAt
			}
			return startedAt.Add(maximumDoctorReportAge + time.Nanosecond)
		},
		Probes: []Probe{{
			Component: "state",
			Run: func(context.Context) conformance.Result {
				return conformance.Result{
					Component: "state",
					Status:    conformance.Pass,
					Evidence:  conformance.Evidence{Class: conformance.EvidenceClassExternal},
				}
			},
		}},
	})
	if err == nil {
		t.Fatal("Run() error = nil, want overlong evidence window rejection")
	}
}
