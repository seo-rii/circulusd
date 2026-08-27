package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/config"
	"github.com/hancomac/circulusd/internal/conformance"
	"github.com/hancomac/circulusd/internal/controlrpc"
	"github.com/hancomac/circulusd/internal/doctor"
	"github.com/hancomac/circulusd/internal/release"
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
		"--release-trust-roots", "/etc/pi-platform/release-trust-roots.json",
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
		loadRelease: func(path string, trustRootsPath string, production bool) (doctor.Probe, string, error) {
			if path != "/usr/lib/pi-platform/release-manifest.json" ||
				trustRootsPath != "/etc/pi-platform/release-trust-roots.json" || !production {
				t.Fatalf("loadRelease(%q, %q, %t)", path, trustRootsPath, production)
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
		loadRelease: func(string, string, bool) (doctor.Probe, string, error) {
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
		loadRelease: func(string, string, bool) (doctor.Probe, string, error) {
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
		{"doctor", "--release-trust-roots", "relative", "--profile", "lightweight"},
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
	referenceProbe, digest, err := dependencies.loadRelease(
		manifestPath,
		filepath.Join(t.TempDir(), "missing-roots.json"),
		false,
	)
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
	productionProbe, _, err := dependencies.loadRelease(
		manifestPath,
		filepath.Join(t.TempDir(), "missing-roots.json"),
		true,
	)
	if err != nil {
		t.Fatalf("loadRelease(production) error = %v", err)
	}
	production := productionProbe.Run(t.Context())
	if production.Status != conformance.Fail || production.Evidence.Mock {
		t.Fatalf("production release result = %+v", production)
	}
}

func TestDefaultReleaseProbeVerifiesProductionAgainstOfflineRoots(t *testing.T) {
	t.Parallel()

	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	manifest := release.Manifest{
		SchemaVersion: 1,
		Release: release.Release{
			Version:       "0.3.0",
			Status:        "production",
			Architectures: []string{"x86_64"},
		},
		Toolchains: map[string]string{
			"go":                 "1.25.3",
			"node":               "24.1.0",
			"pnpm":               "10.30.0",
			"protoc":             "3.21.12",
			"protocGenGo":        "1.36.10",
			"protocGenConnectGo": "1.19.1",
		},
	}
	artifactSize := uint64(1)
	for _, componentName := range []string{
		"platformd", "agentd", "executord", "sandboxd", "workerd", "celld",
	} {
		component := release.Component{
			Name:          componentName,
			Version:       "0.3.0",
			Commit:        strings.Repeat("0", 40),
			License:       "Apache-2.0",
			Source:        "https://example.invalid/" + componentName,
			Qualification: "conformance-pass",
			Artifacts: []release.Artifact{{
				Architecture: "any",
				Name:         componentName + ".tar.zst",
				SHA256:       strings.Repeat("1", 64),
				SizeBytes:    &artifactSize,
			}},
		}
		digest, err := release.ArtifactSigningDigest(
			manifest.Release,
			component,
			component.Artifacts[0],
		)
		if err != nil {
			t.Fatalf("ArtifactSigningDigest() error = %v", err)
		}
		component.Artifacts[0].Signature = &release.Signature{
			Algorithm: "ed25519",
			KeyID:     "release-root-1",
			Value: base64.StdEncoding.EncodeToString(
				ed25519.Sign(privateKey, []byte(digest)),
			),
		}
		manifest.Components = append(manifest.Components, component)
	}
	for _, pair := range []string{
		"platformd-agentd",
		"platformd-executord",
		"session-host-dynamic-worker",
		"executord-sandboxd",
		"state-app-schema",
	} {
		manifest.ProtocolCompatibility = append(
			manifest.ProtocolCompatibility,
			release.ProtocolCompatibility{
				Pair:             pair,
				Minimum:          release.ProtocolVersion{Major: 1},
				Maximum:          release.ProtocolVersion{Major: 1},
				DescriptorSHA256: strings.Repeat("2", 64),
			},
		)
	}
	manifestDigest, err := release.ManifestSigningDigest(manifest)
	if err != nil {
		t.Fatalf("ManifestSigningDigest() error = %v", err)
	}
	manifest.Signatures = []release.Signature{{
		Algorithm: "ed25519",
		KeyID:     "release-root-1",
		Value: base64.StdEncoding.EncodeToString(
			ed25519.Sign(privateKey, []byte(manifestDigest)),
		),
	}}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal(manifest) error = %v", err)
	}
	temporaryDirectory := t.TempDir()
	manifestPath := filepath.Join(temporaryDirectory, "release-manifest.json")
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
	}
	rootBytes, err := json.Marshal(map[string]any{
		"schemaVersion": 1,
		"roots": []map[string]string{{
			"keyId":     "release-root-1",
			"algorithm": "ed25519",
			"publicKey": base64.StdEncoding.EncodeToString(
				privateKey.Public().(ed25519.PublicKey),
			),
		}},
	})
	if err != nil {
		t.Fatalf("Marshal(roots) error = %v", err)
	}
	rootsPath := filepath.Join(temporaryDirectory, "release-trust-roots.json")
	if err := os.WriteFile(rootsPath, rootBytes, 0o600); err != nil {
		t.Fatalf("WriteFile(roots) error = %v", err)
	}

	probe, digest, err := defaultDependencies().loadRelease(
		manifestPath,
		rootsPath,
		true,
	)
	if err != nil {
		t.Fatalf("loadRelease() error = %v", err)
	}
	result := probe.Run(t.Context())
	if result.Status != conformance.Pass || result.Evidence.Mock ||
		result.Evidence.BinaryDigest != digest {
		t.Fatalf("production release result = %+v, digest = %q", result, digest)
	}
	missingProbe, _, err := defaultDependencies().loadRelease(
		manifestPath,
		filepath.Join(temporaryDirectory, "missing-roots.json"),
		true,
	)
	if err != nil {
		t.Fatalf("loadRelease(missing roots) error = %v", err)
	}
	if missing := missingProbe.Run(t.Context()); missing.Status != conformance.NotRun {
		t.Fatalf("missing root result = %+v", missing)
	}

	if err := os.WriteFile(rootsPath, []byte(`{"schemaVersion":1,"roots":[]}`), 0o600); err != nil {
		t.Fatalf("WriteFile(invalid roots) error = %v", err)
	}
	invalidProbe, _, err := defaultDependencies().loadRelease(manifestPath, rootsPath, true)
	if err != nil {
		t.Fatalf("loadRelease(invalid roots) error = %v", err)
	}
	if invalid := invalidProbe.Run(t.Context()); invalid.Status != conformance.Fail {
		t.Fatalf("invalid root result = %+v", invalid)
	}
}

func TestCapabilitiesCommandQueriesPlatformdAndEmitsStableJSON(t *testing.T) {
	socketDirectory, err := os.MkdirTemp("/tmp", "cpc-")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(socketDirectory); err != nil {
			t.Errorf("RemoveAll(%q) error = %v", socketDirectory, err)
		}
	})
	socketPath := filepath.Join(socketDirectory, "platformd.sock")
	server, err := controlrpc.ListenServer(controlrpc.ServerConfig{
		SocketPath:  socketPath,
		AllowedUIDs: []uint32{uint32(os.Getuid())},
		Capabilities: []*v1.CapabilityStatus{
			{
				Name:         "state.celld",
				Availability: v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_UNAVAILABLE,
				UnavailableReason: &v1.PublicError{
					Code:      v1.ErrorCode_ERROR_CODE_UNAVAILABLE,
					Reason:    "NOT_WIRED",
					Message:   "state adapter is not wired",
					Retryable: true,
					Metadata:  map[string]string{"source": "platformd"},
				},
			},
			{
				Name:         "control.protocol",
				Availability: v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_AVAILABLE,
				Attributes:   map[string]string{"transport": "uds"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	serverContext, stopServer := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(serverContext) }()
	t.Cleanup(func() {
		stopServer()
		_ = server.Close()
		select {
		case serveErr := <-serverDone:
			if serveErr != nil {
				t.Errorf("Server.Serve() error = %v", serveErr)
			}
		case <-time.After(3 * time.Second):
			t.Error("control server did not stop")
		}
	})

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	dependencies := defaultDependencies()
	dependencies.stdout = &stdout
	dependencies.stderr = &stderr
	exitCode := execute(context.Background(), []string{
		"capabilities",
		"--socket", socketPath,
		"--timeout", "2s",
	}, dependencies)
	if exitCode != 0 {
		t.Fatalf("execute() = %d, want 0; stderr=%q", exitCode, stderr.String())
	}
	var document capabilitiesOutput
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatalf("capabilities JSON: %v; output=%q", err, stdout.String())
	}
	if document.APIVersion != "v1alpha" || document.Protocol.Major != 1 || document.Protocol.Minor != 0 ||
		document.Protocol.DescriptorDigest != "sha256:ff942ae0643b6fa2a8b8ccee97e1593e0d4b56cd414ee771ad0b731ff5854f63" ||
		document.ServerSequence != "1" {
		t.Fatalf("capabilities envelope = %+v", document)
	}
	if len(document.Capabilities) != 2 || document.Capabilities[0].Name != "control.protocol" ||
		document.Capabilities[0].Availability != "available" || document.Capabilities[0].UnavailableReason != nil ||
		document.Capabilities[0].Attributes["transport"] != "uds" {
		t.Fatalf("available capability = %+v", document.Capabilities)
	}
	unavailable := document.Capabilities[1]
	if unavailable.Name != "state.celld" || unavailable.Availability != "unavailable" ||
		unavailable.UnavailableReason == nil || unavailable.UnavailableReason.Code != "unavailable" ||
		unavailable.UnavailableReason.Reason != "NOT_WIRED" || !unavailable.UnavailableReason.Retryable ||
		unavailable.UnavailableReason.Metadata["source"] != "platformd" {
		t.Fatalf("unavailable capability = %+v", unavailable)
	}
	if strings.Contains(stdout.String(), "requestId") || strings.Contains(stdout.String(), "request_id") {
		t.Fatalf("capabilities output leaked internal request identity: %q", stdout.String())
	}
}

func TestCapabilitiesCommandRejectsInvalidInputBeforeDialing(t *testing.T) {
	called := false
	dependencies := commandDependencies{
		stdout: &bytes.Buffer{},
		stderr: &bytes.Buffer{},
		getCapabilities: func(context.Context, string) (*v1.GetCapabilitiesResponse, error) {
			called = true
			return nil, errors.New("must not dial")
		},
	}
	invalidArguments := [][]string{
		{"capabilities", "--socket", "relative.sock"},
		{"capabilities", "--timeout", "0s"},
		{"capabilities", "--timeout", "10m"},
		{"capabilities", "unexpected"},
		{"capabilities", "--unknown"},
	}
	for index, arguments := range invalidArguments {
		if exitCode := execute(context.Background(), arguments, dependencies); exitCode != 2 {
			t.Fatalf("execute(invalidArguments[%d]) = %d, want 2", index, exitCode)
		}
	}
	if called {
		t.Fatal("invalid capabilities command dialed platformd")
	}
}

func TestCapabilitiesCommandFailsClosedOnContradictoryOrDuplicateStatus(t *testing.T) {
	tests := []struct {
		name         string
		capabilities []*v1.CapabilityStatus
	}{
		{
			name: "available with failure reason",
			capabilities: []*v1.CapabilityStatus{{
				Name:              "control.protocol",
				Availability:      v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_AVAILABLE,
				UnavailableReason: &v1.PublicError{Code: v1.ErrorCode_ERROR_CODE_UNAVAILABLE, Reason: "BAD", Message: "bad"},
			}},
		},
		{
			name: "unavailable without reason",
			capabilities: []*v1.CapabilityStatus{{
				Name:         "state.celld",
				Availability: v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_UNAVAILABLE,
			}},
		},
		{
			name: "duplicate name",
			capabilities: []*v1.CapabilityStatus{
				{Name: "state.celld", Availability: v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_AVAILABLE},
				{Name: "state.celld", Availability: v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_AVAILABLE},
			},
		},
		{
			name:         "unspecified availability",
			capabilities: []*v1.CapabilityStatus{{Name: "state.celld"}},
		},
		{
			name: "invalid capability name",
			capabilities: []*v1.CapabilityStatus{{
				Name:         "state celld",
				Availability: v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_AVAILABLE,
			}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			exitCode := execute(context.Background(), []string{"capabilities"}, commandDependencies{
				stdout: &stdout,
				stderr: &stderr,
				getCapabilities: func(context.Context, string) (*v1.GetCapabilitiesResponse, error) {
					return &v1.GetCapabilitiesResponse{
						Meta:             &v1.RpcResponseMeta{ServerSequence: 1},
						ProtocolVersion:  &v1.ProtocolVersion{Major: 1},
						DescriptorDigest: &v1.Digest{Algorithm: v1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: make([]byte, 32)},
						Capabilities:     test.capabilities,
					}, nil
				},
			})
			if exitCode != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "invalid capability response") {
				t.Fatalf("execute()=%d stdout=%q stderr=%q", exitCode, stdout.String(), stderr.String())
			}
		})
	}
}

func TestCapabilitiesCommandReportsOnlyStructuredTransportCode(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := execute(context.Background(), []string{"capabilities"}, commandDependencies{
		stdout: &stdout,
		stderr: &stderr,
		getCapabilities: func(context.Context, string) (*v1.GetCapabilitiesResponse, error) {
			return nil, errors.New("credential=must-not-leak")
		},
	})
	if exitCode != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "code=unknown") ||
		strings.Contains(stderr.String(), "credential") {
		t.Fatalf("execute()=%d stdout=%q stderr=%q", exitCode, stdout.String(), stderr.String())
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
