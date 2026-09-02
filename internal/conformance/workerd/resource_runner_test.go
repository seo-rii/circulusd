package workerd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/agent"
	"github.com/hancomac/circulusd/internal/conformance"
)

// TestStockWorkerdResourceQualification is the explicit external resource gate.
// It runs only when CIRCULUSD_WORKERD_QUALIFICATION_CONFIG points at a private
// operator qualification document on a provisioned host. The gate fails unless
// the four required results PASS and the recorded residual-gap result is an
// honest FAIL from one shared envelope. A skip (no config) is never a PASS.
func TestStockWorkerdResourceQualification(t *testing.T) {
	configPath := os.Getenv("CIRCULUSD_WORKERD_QUALIFICATION_CONFIG")
	if configPath == "" {
		t.Skip("set CIRCULUSD_WORKERD_QUALIFICATION_CONFIG to run the external workerd resource qualification gate")
	}
	report := runResourceQualification(t.Context(), liveResourceRunnerDeps(), configPath)
	for _, result := range report.Results {
		t.Logf("resource result %s = %s (%s)", result.Component, result.Status, result.Reason)
	}
	qualified, err := evaluateResourceQualificationRun(report.Results)
	if err != nil {
		t.Fatalf("resource qualification run is structurally invalid: %v", err)
	}
	if !qualified {
		t.Fatalf("workerd resource qualification did not reach the achievable bar (four required PASS + one recorded FAIL)")
	}
}

// stubResourceProbeRunner returns a canned outcome and records the input it saw.
type stubResourceProbeRunner struct {
	result   resourceProbeRunResult
	err      error
	captured resourceProbeRunInput
	calls    int
}

func (runner *stubResourceProbeRunner) Run(_ context.Context, input resourceProbeRunInput) (resourceProbeRunResult, error) {
	runner.calls++
	runner.captured = input
	return runner.result, runner.err
}

func qualifiedResourceProbeObservations(base time.Time) []resourceProbeObservation {
	observations := make([]resourceProbeObservation, 0, len(resourceQualificationComponents))
	for index, component := range resourceQualificationComponents {
		status := conformance.Pass
		reason := "kernel-enforced boundary observed"
		if isRecordedResourceQualificationComponent(component) {
			status = conformance.Fail
			reason = "stock workerd does not reconstruct a per-isolate fault on this pin"
		}
		start := base.Add(time.Duration(index) * time.Second)
		observations = append(observations, resourceProbeObservation{
			Component:      component,
			Status:         status,
			Reason:         reason,
			StartedAt:      start,
			FinishedAt:     start.Add(time.Second),
			RawSampleCount: 5,
		})
	}
	return observations
}

// privateResourceTempDir returns a 0700 caller-owned directory, matching the
// evidence-retention contract that the operator provisions a private output
// directory. t.TempDir yields 0755, which retention correctly rejects.
func privateResourceTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "cq-evidence")
	if err != nil {
		t.Fatalf("create private temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func writeResourceRunnerConfig(t *testing.T, evidenceDir string) string {
	t.Helper()
	document := fmt.Sprintf(`{
  "schemaVersion":1,
  "releaseManifestPath":"/usr/lib/pi-platform/release-manifest.json",
  "releaseTrustRootsPath":"/etc/pi-platform/release-trust-roots.json",
  "installedWorkerdPath":"/usr/lib/pi-platform/bin/workerd",
  "architecture":"x86_64",
  "cgroupRootPath":"/sys/fs/cgroup/pi-platform/qualification",
  "evidenceOutputDirectory":%q,
  "limits":{
    "cpuMaxQuotaMicros":50000,
    "cpuMaxPeriodMicros":100000,
    "memoryMaxBytes":1073741824,
    "memorySwapMaxBytes":0,
    "pidsMax":128
  },
  "timeoutsMillis":{"readiness":10000,"probe":60000,"drain":30000,"total":600000},
  "coldStartSamples":5
}`, evidenceDir)
	path := filepath.Join(t.TempDir(), "qualification.json")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func fakeResolvedRelease() *resolvedResourceRelease {
	return &resolvedResourceRelease{
		identity: resourceQualificationReleaseIdentity{
			releaseVersion:            "0.3.0",
			releaseStatus:             "development",
			manifestSigningDigest:     "sha256:" + strings.Repeat("1", 64),
			architecture:              "x86_64",
			workerdVersion:            "1.20260825.1",
			artifactName:              "workerd-linux-64.gz",
			archiveSHA256:             strings.Repeat("2", 64),
			extractionRecipe:          "gzip-single-file-v1",
			extractedExecutableSHA256: strings.Repeat("3", 64),
		},
		openExecutable: func() (*os.File, error) { return nil, fmt.Errorf("not opened in fake") },
		close:          func() error { return nil },
	}
}

func fakeResourceRunnerDeps(t *testing.T, runner resourceProbeRunner) resourceRunnerDeps {
	t.Helper()
	tick := time.Unix(1_700_000_000, 0).UTC()
	return resourceRunnerDeps{
		now: func() time.Time {
			tick = tick.Add(time.Second)
			return tick
		},
		hostIdentity: func() (resourceRunnerHostIdentity, error) {
			return resourceRunnerHostIdentity{
				Kernel:     "6.14.0-generic",
				HostBootID: strings.Repeat("a", 32),
				RunID:      strings.Repeat("b", 32),
			}, nil
		},
		resolveRelease: func(resourceQualificationConfig) (*resolvedResourceRelease, error) {
			return fakeResolvedRelease(), nil
		},
		provisionCgroup: func(agent.WorkerdCgroupConfig) agent.WorkerdCgroupProvisioning {
			return agent.WorkerdCgroupProvisioning{
				Satisfied:          true,
				RootDevice:         25,
				RootInode:          39256,
				EnabledControllers: []string{"cpu", "memory", "pids"},
			}
		},
		makeFixtureDir: func() (string, func(), error) {
			dir, err := os.MkdirTemp("", "cq")
			if err != nil {
				return "", nil, err
			}
			return dir, func() { _ = os.RemoveAll(dir) }, nil
		},
		probeRunner: runner,
		binding: resourceRunnerBinding{
			runnerBinaryDigest:   "sha256:" + strings.Repeat("4", 64),
			sourceDigest:         "sha256:" + strings.Repeat("5", 64),
			probeInventoryDigest: "sha256:" + strings.Repeat("6", 64),
		},
	}
}

func TestRunResourceQualificationBindsFourPassPlusRecordedFailAndRetainsEvidence(t *testing.T) {
	evidenceDir := privateResourceTempDir(t)
	configPath := writeResourceRunnerConfig(t, evidenceDir)
	runner := &stubResourceProbeRunner{
		result: resourceProbeRunResult{
			agentInstanceID: strings.Repeat("c", 32),
			probes:          qualifiedResourceProbeObservations(time.Unix(1_700_000_100, 0).UTC()),
			cleanupComplete: true,
		},
	}
	report := runResourceQualification(context.Background(), fakeResourceRunnerDeps(t, runner), configPath)

	if runner.calls != 1 {
		t.Fatalf("probe runner called %d times, want 1", runner.calls)
	}
	if len(report.Results) != len(resourceQualificationComponents) {
		t.Fatalf("report has %d results, want %d", len(report.Results), len(resourceQualificationComponents))
	}
	qualified, err := evaluateResourceQualificationRun(report.Results)
	if err != nil {
		t.Fatalf("evaluateResourceQualificationRun() error = %v", err)
	}
	if !qualified {
		t.Fatalf("run did not reach the achievable bar: %+v", report.Results)
	}

	var observationDigest string
	for _, result := range report.Results {
		if isRecordedResourceQualificationComponent(result.Component) {
			if result.Status != conformance.Fail {
				t.Fatalf("recorded component %s = %s, want FAIL", result.Component, result.Status)
			}
			continue
		}
		if result.Status != conformance.Pass {
			t.Fatalf("required component %s = %s, want PASS", result.Component, result.Status)
		}
		if result.Evidence.Class != conformance.EvidenceClassExternal || result.Evidence.Mock {
			t.Fatalf("required component %s evidence is not external non-mock: %+v", result.Component, result.Evidence)
		}
		if len(result.Evidence.ArtifactReferences) != 1 ||
			result.Evidence.ArtifactReferences[0].Name != resourceObservationArtifactName {
			t.Fatalf("required component %s missing observation reference: %+v", result.Component, result.Evidence.ArtifactReferences)
		}
		observationDigest = result.Evidence.ArtifactReferences[0].Digest
	}
	if !validResourceEvidenceDigest(observationDigest) {
		t.Fatalf("observation digest %q is not canonical", observationDigest)
	}

	artifactPath := filepath.Join(evidenceDir, resourceObservationArtifactName)
	encoded, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatalf("retained evidence artifact is missing: %v", err)
	}
	if got := "sha256:" + hexSHA256(encoded); got != observationDigest {
		t.Fatalf("retained artifact digest %q does not match result reference %q", got, observationDigest)
	}
}

func TestRunResourceQualificationMapsPreflightFailuresToTheStatusTable(t *testing.T) {
	base := func(t *testing.T, runner resourceProbeRunner) resourceRunnerDeps {
		return fakeResourceRunnerDeps(t, runner)
	}
	okRunner := func() *stubResourceProbeRunner {
		return &stubResourceProbeRunner{result: resourceProbeRunResult{
			agentInstanceID: strings.Repeat("c", 32),
			probes:          qualifiedResourceProbeObservations(time.Unix(1_700_000_100, 0).UTC()),
			cleanupComplete: true,
		}}
	}

	for _, test := range []struct {
		name    string
		mutate  func(deps *resourceRunnerDeps)
		want    conformance.Status
		wantSub string
	}{
		{
			name: "release unavailable",
			mutate: func(deps *resourceRunnerDeps) {
				deps.resolveRelease = func(resourceQualificationConfig) (*resolvedResourceRelease, error) {
					return nil, fmt.Errorf("%w: no installed workerd", errResourceQualificationReleaseUnavailable)
				}
			},
			want: conformance.Unavailable,
		},
		{
			name: "release invalid",
			mutate: func(deps *resourceRunnerDeps) {
				deps.resolveRelease = func(resourceQualificationConfig) (*resolvedResourceRelease, error) {
					return nil, fmt.Errorf("%w: digest mismatch", errResourceQualificationReleaseInvalid)
				}
			},
			want: conformance.Fail,
		},
		{
			name: "cgroup host unavailable",
			mutate: func(deps *resourceRunnerDeps) {
				deps.provisionCgroup = func(agent.WorkerdCgroupConfig) agent.WorkerdCgroupProvisioning {
					return agent.WorkerdCgroupProvisioning{HostUnavailable: true, Reason: "cgroup v2 not delegated"}
				}
			},
			want: conformance.Unavailable,
		},
		{
			name: "cgroup contract violation",
			mutate: func(deps *resourceRunnerDeps) {
				deps.provisionCgroup = func(agent.WorkerdCgroupConfig) agent.WorkerdCgroupProvisioning {
					return agent.WorkerdCgroupProvisioning{Reason: "root is not empty"}
				}
			},
			want: conformance.Fail,
		},
		{
			name: "probes not implemented",
			mutate: func(deps *resourceRunnerDeps) {
				deps.probeRunner = notImplementedResourceProbeRunner{}
			},
			want: conformance.NotRun,
		},
		{
			name: "probe framework failure",
			mutate: func(deps *resourceRunnerDeps) {
				deps.probeRunner = &stubResourceProbeRunner{err: fmt.Errorf("launcher exploded")}
			},
			want: conformance.Fail,
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			evidenceDir := t.TempDir()
			configPath := writeResourceRunnerConfig(t, evidenceDir)
			deps := base(t, okRunner())
			test.mutate(&deps)
			report := runResourceQualification(context.Background(), deps, configPath)
			if len(report.Results) != len(resourceQualificationComponents) {
				t.Fatalf("report has %d results, want %d", len(report.Results), len(resourceQualificationComponents))
			}
			for _, result := range report.Results {
				if result.Status != test.want {
					t.Fatalf("component %s = %s, want uniform %s (%q)", result.Component, result.Status, test.want, result.Reason)
				}
			}
		})
	}
}

func TestRunResourceQualificationRejectsRecordedComponentClaimingPass(t *testing.T) {
	evidenceDir := privateResourceTempDir(t)
	configPath := writeResourceRunnerConfig(t, evidenceDir)
	probes := qualifiedResourceProbeObservations(time.Unix(1_700_000_100, 0).UTC())
	for index := range probes {
		if isRecordedResourceQualificationComponent(probes[index].Component) {
			probes[index].Status = conformance.Pass
			probes[index].Reason = "fabricated pass"
		}
	}
	runner := &stubResourceProbeRunner{result: resourceProbeRunResult{
		agentInstanceID: strings.Repeat("c", 32),
		probes:          probes,
		cleanupComplete: true,
	}}
	report := runResourceQualification(context.Background(), fakeResourceRunnerDeps(t, runner), configPath)
	for _, result := range report.Results {
		if result.Status != conformance.Fail {
			t.Fatalf("component %s = %s, want uniform FAIL for a recorded PASS framing error", result.Component, result.Status)
		}
	}
}

// TestResourceGateIsNotSatisfiedByTheWorkerdTestPath is the retained negative
// control: the older workerd-test conformance path (selected by the three binary
// environment variables) and an unconfigured resource gate can never produce a
// resource PASS. Only the fully configured, provisioned gate does.
func TestResourceGateIsNotSatisfiedByTheWorkerdTestPath(t *testing.T) {
	t.Parallel()

	resourceComponents := make(map[string]struct{}, len(resourceQualificationComponents))
	for _, component := range resourceQualificationComponents {
		resourceComponents[component] = struct{}{}
	}
	found := 0
	for _, candidate := range requiredProbes {
		if _, ok := resourceComponents[candidate.component]; !ok {
			continue
		}
		found++
		if candidate.entrypoint != "" {
			t.Fatalf("resource component %q must have no workerd-test entrypoint", candidate.component)
		}
		if candidate.notRunReason == "" {
			t.Fatalf("resource component %q must carry a NOT_RUN reason on the workerd-test path", candidate.component)
		}
	}
	if found != len(resourceQualificationComponents) {
		t.Fatalf("probe inventory has %d resource components, want %d", found, len(resourceQualificationComponents))
	}

	deps := fakeResourceRunnerDeps(t, &stubResourceProbeRunner{})
	report := runResourceQualification(context.Background(), deps, filepath.Join(t.TempDir(), "absent.json"))
	for _, result := range report.Results {
		if result.Status == conformance.Pass {
			t.Fatalf("an unconfigured resource gate produced a PASS for %q", result.Component)
		}
	}
}

func TestRunResourceQualificationRejectsMalformedConfigAndBadConfigPath(t *testing.T) {
	deps := fakeResourceRunnerDeps(t, &stubResourceProbeRunner{})

	if report := runResourceQualification(context.Background(), deps, "relative/path.json"); report.Results[0].Status != conformance.Fail {
		t.Fatalf("non-absolute config path = %s, want FAIL", report.Results[0].Status)
	}

	absent := filepath.Join(t.TempDir(), "missing.json")
	if report := runResourceQualification(context.Background(), deps, absent); report.Results[0].Status != conformance.Unavailable {
		t.Fatalf("absent config = %s, want UNAVAILABLE", report.Results[0].Status)
	}

	malformed := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(malformed, []byte("{ not json"), 0o600); err != nil {
		t.Fatalf("write malformed config: %v", err)
	}
	if report := runResourceQualification(context.Background(), deps, malformed); report.Results[0].Status != conformance.Fail {
		t.Fatalf("malformed config = %s, want FAIL", report.Results[0].Status)
	}
}
