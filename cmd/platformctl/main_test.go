package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/config"
	"github.com/hancomac/circulusd/internal/conformance"
	"github.com/hancomac/circulusd/internal/doctor"
)

func TestDoctorCommandEmitsIdentityBoundJSONAndFailsForMissingGates(t *testing.T) {
	t.Parallel()

	digest := "sha256:" + strings.Repeat("a", 64)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := execute(context.Background(), []string{
		"doctor",
		"--config", "/etc/pi-platform/config.yaml",
		"--release-manifest", "/usr/lib/pi-platform/release-manifest.json",
		"--profile", "lightweight",
	}, commandDependencies{
		stdout: &stdout,
		stderr: &stderr,
		clock:  func() time.Time { return time.Date(2026, time.August, 27, 2, 3, 4, 0, time.UTC) },
		loadConfiguration: func(path string, profile config.InstallProfile) (configurationSnapshot, string, error) {
			if path != "/etc/pi-platform/config.yaml" || profile != config.InstallProfileLightweight {
				t.Fatalf("loadConfiguration(%q, %q)", path, profile)
			}
			return configurationSnapshot{
				dataDirectory: "/var/lib/circulusd",
				backends:      []config.Backend{config.BackendNsJail},
			}, digest, nil
		},
		loadRelease: func(path string, production bool) (doctor.Probe, string, error) {
			if path != "/usr/lib/pi-platform/release-manifest.json" || !production {
				t.Fatalf("loadRelease(%q, %t)", path, production)
			}
			return doctor.Probe{
				Component: "release.signature",
				Run: func(context.Context) conformance.Result {
					return conformance.Result{Component: "release.signature", Status: conformance.Pass}
				},
			}, digest, nil
		},
		hostSources: passingHostSources(),
		runID:       func() (string, error) { return "doctor-cli-run-1", nil },
		hostID:      func() (string, error) { return "host-cli-1", nil },
	})
	if exitCode != 1 {
		t.Fatalf("execute() = %d, want 1 for missing required gates; stderr=%q", exitCode, stderr.String())
	}
	var report doctor.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("doctor JSON: %v; output=%q", err, stdout.String())
	}
	if report.RunID != "doctor-cli-run-1" || report.ConfigDigest != digest ||
		report.ReleaseDigest != digest || report.ProfileQualified || report.ProductionEligible {
		t.Fatalf("doctor report = %+v", report)
	}
	if !strings.Contains(report.FailureReason, "NOT_RUN") {
		t.Fatalf("doctor failure reason = %q, want NOT_RUN", report.FailureReason)
	}
}

func TestDoctorCommandExitsZeroOnlyWhenEverySelectedProductionGatePasses(t *testing.T) {
	t.Parallel()

	digest := "sha256:" + strings.Repeat("b", 64)
	profile, err := doctor.ConformanceProfile(
		config.InstallProfileLightweight,
		[]config.Backend{config.BackendNsJail},
	)
	if err != nil {
		t.Fatalf("ConformanceProfile() error = %v", err)
	}
	hostComponents := map[string]struct{}{
		"host.architecture":      {},
		"host.cgroup-v2":         {},
		"host.disk":              {},
		"host.kernel":            {},
		"host.namespace-handles": {},
		"host.nftables-tool":     {},
		"host.scratch-quota":     {},
		"host.kvm-access":        {},
		"release.signature":      {},
	}
	additional := make([]doctor.Probe, 0, len(profile.Required))
	for _, component := range profile.Required {
		if _, implemented := hostComponents[component]; implemented {
			continue
		}
		additional = append(additional, doctor.Probe{
			Component: component,
			Run: func(context.Context) conformance.Result {
				return conformance.Result{Component: component, Status: conformance.Pass}
			},
		})
	}
	var stdout bytes.Buffer
	exitCode := execute(context.Background(), []string{
		"doctor",
		"--config", "/etc/pi-platform/config.yaml",
		"--release-manifest", "/usr/lib/pi-platform/release-manifest.json",
		"--profile", "lightweight",
	}, commandDependencies{
		stdout: &stdout,
		stderr: &bytes.Buffer{},
		clock:  time.Now,
		loadConfiguration: func(string, config.InstallProfile) (configurationSnapshot, string, error) {
			return configurationSnapshot{dataDirectory: "/var/lib/circulusd", backends: []config.Backend{config.BackendNsJail}}, digest, nil
		},
		loadRelease: func(string, bool) (doctor.Probe, string, error) {
			return doctor.Probe{
				Component: "release.signature",
				Run: func(context.Context) conformance.Result {
					return conformance.Result{Component: "release.signature", Status: conformance.Pass}
				},
			}, digest, nil
		},
		hostSources:      passingHostSources(),
		additionalProbes: additional,
		runID:            func() (string, error) { return "doctor-cli-run-2", nil },
		hostID:           func() (string, error) { return "host-cli-2", nil },
	})
	if exitCode != 0 {
		t.Fatalf("execute() = %d, want 0; output=%q", exitCode, stdout.String())
	}
	var report doctor.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("doctor JSON: %v", err)
	}
	if !report.ProfileQualified || !report.ProductionEligible {
		t.Fatalf("doctor report = %+v", report)
	}
}

func TestDoctorCommandRejectsInvalidInputBeforeRunningHostProbes(t *testing.T) {
	t.Parallel()

	executed := false
	dependencies := commandDependencies{
		stdout: &bytes.Buffer{},
		stderr: &bytes.Buffer{},
		clock:  time.Now,
		loadConfiguration: func(string, config.InstallProfile) (configurationSnapshot, string, error) {
			executed = true
			return configurationSnapshot{}, "", errors.New("must not run")
		},
		loadRelease: func(string, bool) (doctor.Probe, string, error) {
			executed = true
			return doctor.Probe{}, "", errors.New("must not run")
		},
		hostSources: doctor.HostSources{},
		runID: func() (string, error) {
			executed = true
			return "", errors.New("must not run")
		},
		hostID: func() (string, error) {
			executed = true
			return "", errors.New("must not run")
		},
	}
	invalidArguments := [][]string{
		{},
		{"unknown"},
		{"doctor", "--profile", "future"},
		{"doctor", "--config", "relative", "--profile", "lightweight"},
		{"doctor", "unexpected"},
	}
	for index, arguments := range invalidArguments {
		if exitCode := execute(context.Background(), arguments, dependencies); exitCode != 2 {
			t.Fatalf("execute(invalidArguments[%d]) = %d, want 2", index, exitCode)
		}
	}
	if executed {
		t.Fatal("execute() invoked dependencies for invalid CLI input")
	}
}

func TestDefaultReleaseProbeKeepsDevelopmentEvidenceReferenceOnly(t *testing.T) {
	t.Parallel()

	manifestPath, err := filepath.Abs("../../deploy/airgap/release-manifest.json")
	if err != nil {
		t.Fatalf("Abs() error = %v", err)
	}
	dependencies := defaultDependencies()
	referenceProbe, digest, err := dependencies.loadRelease(manifestPath, false)
	if err != nil {
		t.Fatalf("loadRelease(reference) error = %v", err)
	}
	if !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("loadRelease() digest = %q", digest)
	}
	reference := referenceProbe.Run(t.Context())
	if reference.Status != conformance.Pass || !reference.Evidence.Mock {
		t.Fatalf("reference release result = %+v", reference)
	}
	productionProbe, _, err := dependencies.loadRelease(manifestPath, true)
	if err != nil {
		t.Fatalf("loadRelease(production) error = %v", err)
	}
	production := productionProbe.Run(t.Context())
	if production.Status != conformance.Fail || production.Evidence.Mock {
		t.Fatalf("production release result = %+v", production)
	}
}

func passingHostSources() doctor.HostSources {
	files := map[string]string{
		"/proc/sys/kernel/osrelease":        "6.12.4-reference\n",
		"/sys/fs/cgroup/cgroup.controllers": "cpu io memory pids\n",
		"/proc/self/mountinfo": strings.Join([]string{
			"29 23 0:26 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw",
			"30 23 8:1 / /var/lib/circulusd rw,prjquota - ext4 /dev/sda1 rw,prjquota",
		}, "\n"),
	}
	return doctor.HostSources{
		OperatingSystem: "linux",
		Architecture:    "amd64",
		ReadFile: func(path string, _ int64) ([]byte, error) {
			value, found := files[path]
			if !found {
				return nil, fs.ErrNotExist
			}
			return []byte(value), nil
		},
		Stat: func(string) error { return nil },
		StatFS: func(string) (doctor.FileSystemStats, error) {
			return doctor.FileSystemStats{FreeBytes: 20 << 30, FreeInodes: 2_000_000}, nil
		},
		LookPath:      func(string) (string, error) { return "/usr/sbin/nft", nil },
		OpenReadWrite: func(string) error { return nil },
	}
}
