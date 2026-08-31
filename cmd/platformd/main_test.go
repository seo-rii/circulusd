package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/controlrpc"
	"github.com/hancomac/circulusd/internal/statebootstrap"
)

type recordingRuntime struct {
	events *[]string
	closes int
}

func (runtime *recordingRuntime) Close() {
	runtime.closes++
	if runtime.events != nil {
		*runtime.events = append(*runtime.events, "runtime.close")
	}
}

type recordingServer struct {
	mu        sync.Mutex
	events    *[]string
	serveErr  error
	closes    int
	closed    chan struct{}
	closeOnce sync.Once
}

func (server *recordingServer) Serve(context.Context) error {
	server.mu.Lock()
	if server.events != nil {
		*server.events = append(*server.events, "server.serve")
	}
	err := server.serveErr
	closed := server.closed
	server.mu.Unlock()
	if closed != nil {
		<-closed
	}
	return err
}

func (server *recordingServer) Close() error {
	server.mu.Lock()
	server.closes++
	if server.events != nil {
		*server.events = append(*server.events, "server.close")
	}
	server.mu.Unlock()
	server.closeOnce.Do(func() {
		if server.closed != nil {
			close(server.closed)
		}
	})
	return nil
}

func blockingRecordingServer() *recordingServer {
	return &recordingServer{closed: make(chan struct{})}
}

func TestPlatformdServesHonestCapabilitiesAndRemovesItsSocket(t *testing.T) {
	socketPath := platformdSocketPath(t)
	var stderr bytes.Buffer
	dependencies := defaultDependencies()
	dependencies.stderr = &stderr
	dependencies.bootstrap = func(context.Context, statebootstrap.Files) (stateRuntime, error) {
		return &recordingRuntime{}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- execute(ctx, []string{"--socket", socketPath}, dependencies)
	}()
	waitForSocket(t, socketPath)

	client, err := controlrpc.NewClient(controlrpc.ClientConfig{
		SocketPath: socketPath,
		Peer:       v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL,
	})
	if err != nil {
		cancel()
		t.Fatalf("NewClient() error = %v", err)
	}
	requestContext, requestCancel := context.WithTimeout(context.Background(), 3*time.Second)
	response, err := client.GetCapabilities(requestContext)
	requestCancel()
	if closeErr := client.Close(); closeErr != nil {
		t.Errorf("Client.Close() error = %v", closeErr)
	}
	if err != nil {
		cancel()
		t.Fatalf("GetCapabilities() error = %v", err)
	}

	wantNames := []string{
		"agent.isolation",
		"api.public",
		"control.protocol",
		"execution.docker",
		"execution.environments",
		"execution.firecracker",
		"execution.nsjail",
		"extension.registry",
		"mcp.gateway",
		"model.gateway",
		"resource.profiles",
		"state.celld",
	}
	if len(response.GetCapabilities()) != len(wantNames) {
		cancel()
		t.Fatalf("capabilities count = %d, want %d: %v", len(response.GetCapabilities()), len(wantNames), response.GetCapabilities())
	}
	for index, capability := range response.GetCapabilities() {
		if capability.GetName() != wantNames[index] {
			cancel()
			t.Fatalf("capability[%d].name = %q, want %q", index, capability.GetName(), wantNames[index])
		}
		if capability.GetName() == "control.protocol" {
			if capability.GetAvailability() != v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_AVAILABLE || capability.GetUnavailableReason() != nil {
				cancel()
				t.Fatalf("control protocol capability = %v", capability)
			}
			continue
		}
		if capability.GetAvailability() != v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_UNAVAILABLE ||
			capability.GetUnavailableReason().GetCode() != v1.ErrorCode_ERROR_CODE_UNAVAILABLE ||
			capability.GetUnavailableReason().GetReason() != "NOT_WIRED" ||
			capability.GetUnavailableReason().GetMessage() == "" {
			cancel()
			t.Fatalf("unwired capability = %v", capability)
		}
	}

	cancel()
	select {
	case exitCode := <-done:
		if exitCode != 0 {
			t.Fatalf("execute() = %d, want 0; stderr=%q", exitCode, stderr.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("platformd did not stop after cancellation")
	}
	if _, err := os.Lstat(socketPath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("socket remains after shutdown: %v", err)
	}
}

func TestPlatformdRejectsInvalidCLIWithoutReplacingExistingPaths(t *testing.T) {
	tests := []struct {
		name      string
		arguments []string
	}{
		{name: "relative socket", arguments: []string{"--socket", "platformd.sock"}},
		{name: "invalid UID", arguments: []string{"--allow-uid", "not-a-uid"}},
		{name: "duplicate UID", arguments: []string{"--allow-uid", "1000", "--allow-uid", "1000"}},
		{name: "unexpected argument", arguments: []string{"unexpected"}},
		{name: "unknown flag", arguments: []string{"--unknown"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stderr bytes.Buffer
			dependencies := defaultDependencies()
			dependencies.stderr = &stderr
			dependencies.bootstrap = func(context.Context, statebootstrap.Files) (stateRuntime, error) {
				return &recordingRuntime{}, nil
			}
			if exitCode := execute(context.Background(), test.arguments, dependencies); exitCode != 2 {
				t.Fatalf("execute() = %d, want 2; stderr=%q", exitCode, stderr.String())
			}
		})
	}

	existingPath := platformdSocketPath(t)
	if err := os.WriteFile(existingPath, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	dependencies := defaultDependencies()
	dependencies.stderr = &stderr
	dependencies.bootstrap = func(context.Context, statebootstrap.Files) (stateRuntime, error) {
		return &recordingRuntime{}, nil
	}
	if exitCode := execute(context.Background(), []string{"--socket", existingPath}, dependencies); exitCode != 1 {
		t.Fatalf("execute(existing path) = %d, want 1; stderr=%q", exitCode, stderr.String())
	}
	contents, err := os.ReadFile(existingPath)
	if err != nil || string(contents) != "preserve" {
		t.Fatalf("existing path changed: contents=%q error=%v", contents, err)
	}
}

func TestPlatformdMalformedCLIWithMissingDependenciesFailsWithoutPanicking(t *testing.T) {
	if exitCode := execute(context.Background(), []string{"--unknown"}, daemonDependencies{}); exitCode != 2 {
		t.Fatalf("execute() = %d, want 2", exitCode)
	}
}

func TestPlatformdUsesExplicitUIDAllowlist(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("requires a non-root caller so UID 0 is disallowed by SO_PEERCRED")
	}
	socketPath := platformdSocketPath(t)
	var stderr bytes.Buffer
	dependencies := defaultDependencies()
	dependencies.stderr = &stderr
	dependencies.bootstrap = func(context.Context, statebootstrap.Files) (stateRuntime, error) {
		return &recordingRuntime{}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- execute(ctx, []string{"--socket", socketPath, "--allow-uid", "0"}, dependencies)
	}()
	waitForSocket(t, socketPath)

	client, err := controlrpc.NewClient(controlrpc.ClientConfig{SocketPath: socketPath})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	requestContext, requestCancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	_, callErr := client.GetCapabilities(requestContext)
	requestCancel()
	_ = client.Close()
	if callErr == nil {
		cancel()
		t.Fatal("current UID connected despite an explicit root-only allowlist")
	}

	cancel()
	select {
	case exitCode := <-done:
		if exitCode != 0 {
			t.Fatalf("execute() = %d, want 0; stderr=%q", exitCode, stderr.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("platformd did not stop")
	}
}

func platformdSocketPath(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "cpd-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Errorf("remove temporary socket directory: %v", err)
		}
	})
	return filepath.Join(directory, "platformd.sock")
}

func waitForSocket(t *testing.T, socketPath string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		info, err := os.Lstat(socketPath)
		if err == nil && info.Mode()&os.ModeSocket != 0 && info.Mode().Perm() == 0o600 {
			return
		}
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("inspect platformd socket: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("platformd socket was not created; path=%q", socketPath)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestDefaultCapabilitiesNeverClaimMockOrReferenceReadiness(t *testing.T) {
	dependencies := defaultDependencies()
	capabilities, err := dependencies.capabilityProvider(context.Background())
	if err != nil {
		t.Fatalf("capabilityProvider() error = %v", err)
	}
	for _, capability := range capabilities {
		for key, value := range capability.GetAttributes() {
			if strings.Contains(strings.ToLower(key+"="+value), "mock") || strings.Contains(strings.ToLower(key+"="+value), "reference") {
				t.Fatalf("default capability reports non-production evidence: %v", capability)
			}
		}
	}
}

func TestDefaultStateCapabilityReportsTheRemainingProductionGate(t *testing.T) {
	dependencies := defaultDependencies()
	capabilities, err := dependencies.capabilityProvider(context.Background())
	if err != nil {
		t.Fatalf("capabilityProvider() error = %v", err)
	}
	for _, capability := range capabilities {
		if capability.GetName() != "state.celld" {
			continue
		}
		if capability.GetAvailability() != v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_UNAVAILABLE ||
			capability.GetUnavailableReason().GetReason() != "NOT_WIRED" ||
			capability.GetUnavailableReason().GetMessage() != "state.celld native signer and restart conformance are not qualified" {
			t.Fatalf("state.celld capability = %v", capability)
		}
		return
	}
	t.Fatal("state.celld capability is missing")
}

func TestPlatformdForwardsDefaultAndExplicitProductionStatePaths(t *testing.T) {
	tests := []struct {
		name      string
		arguments []string
		want      statebootstrap.Files
	}{
		{
			name:      "defaults",
			arguments: []string{"--socket", "/tmp/platformd-defaults.sock", "--allow-uid", "1000"},
			want: statebootstrap.Files{
				Configuration:     "/etc/pi-platform/config.yaml",
				ReleaseManifest:   "/usr/lib/pi-platform/release-manifest.json",
				ReleaseTrustRoots: "/etc/pi-platform/release-trust-roots.json",
			},
		},
		{
			name: "explicit",
			arguments: []string{
				"--socket", "/tmp/platformd-explicit.sock",
				"--allow-uid", "1000",
				"--config", "/srv/platform/config.yaml",
				"--release-manifest", "/srv/platform/release.json",
				"--release-trust-roots", "/srv/platform/roots.json",
			},
			want: statebootstrap.Files{
				Configuration:     "/srv/platform/config.yaml",
				ReleaseManifest:   "/srv/platform/release.json",
				ReleaseTrustRoots: "/srv/platform/roots.json",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stderr bytes.Buffer
			var got statebootstrap.Files
			dependencies := defaultDependencies()
			dependencies.stderr = &stderr
			dependencies.bootstrap = func(_ context.Context, files statebootstrap.Files) (stateRuntime, error) {
				got = files
				return &recordingRuntime{}, nil
			}
			dependencies.listen = func(controlrpc.ServerConfig) (controlServer, error) {
				return &recordingServer{}, nil
			}

			if exitCode := execute(context.Background(), test.arguments, dependencies); exitCode != 0 {
				t.Fatalf("execute() = %d, want 0; stderr=%q", exitCode, stderr.String())
			}
			if got.Configuration != test.want.Configuration ||
				got.ReleaseManifest != test.want.ReleaseManifest ||
				got.ReleaseTrustRoots != test.want.ReleaseTrustRoots {
				t.Fatalf("bootstrap files = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestPlatformdBootstrapsBeforeListeningAndClosesInDependencyOrder(t *testing.T) {
	var stderr bytes.Buffer
	var events []string
	runtime := &recordingRuntime{events: &events}
	server := &recordingServer{events: &events}
	publicServer := blockingRecordingServer()
	dependencies := defaultDependencies()
	dependencies.stderr = &stderr
	dependencies.bootstrap = func(context.Context, statebootstrap.Files) (stateRuntime, error) {
		events = append(events, "bootstrap")
		return runtime, nil
	}
	dependencies.listen = func(controlrpc.ServerConfig) (controlServer, error) {
		events = append(events, "listen")
		return server, nil
	}
	dependencies.listenPublic = func(context.Context, stateRuntime) (controlServer, error) {
		events = append(events, "public.listen")
		return publicServer, nil
	}

	if exitCode := execute(context.Background(), []string{"--allow-uid", "1000"}, dependencies); exitCode != 0 {
		t.Fatalf("execute() = %d, want 0; stderr=%q", exitCode, stderr.String())
	}
	want := []string{"bootstrap", "public.listen", "listen", "server.serve", "server.close", "runtime.close"}
	if strings.Join(events, ",") != strings.Join(want, ",") {
		t.Fatalf("events = %v, want %v", events, want)
	}
	if server.closes != 1 || publicServer.closes != 1 || runtime.closes != 1 {
		t.Fatalf("close counts = control %d public %d runtime %d, want one each", server.closes, publicServer.closes, runtime.closes)
	}
}

func TestPlatformdBootstrapFailureKeepsOnlyTheDiagnosticControlPlaneAvailable(t *testing.T) {
	var stderr bytes.Buffer
	var events []string
	runtime := &recordingRuntime{events: &events}
	listenCalls := 0
	server := &recordingServer{events: &events}
	dependencies := defaultDependencies()
	dependencies.stderr = &stderr
	dependencies.bootstrap = func(context.Context, statebootstrap.Files) (stateRuntime, error) {
		events = append(events, "bootstrap")
		return runtime, errors.New("private bootstrap detail")
	}
	dependencies.listen = func(config controlrpc.ServerConfig) (controlServer, error) {
		listenCalls++
		events = append(events, "listen")
		capabilities, err := config.CapabilityProvider(context.Background())
		if err != nil {
			t.Fatalf("CapabilityProvider() error = %v", err)
		}
		for _, capability := range capabilities {
			if capability.GetName() == "state.celld" &&
				(capability.GetAvailability() != v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_UNAVAILABLE ||
					capability.GetUnavailableReason().GetReason() != "NOT_WIRED") {
				t.Fatalf("state.celld capability = %v, want NOT_WIRED", capability)
			}
		}
		return server, nil
	}

	if exitCode := execute(context.Background(), []string{"--allow-uid", "1000"}, dependencies); exitCode != 0 {
		t.Fatalf("execute() = %d, want 0", exitCode)
	}
	if listenCalls != 1 {
		t.Fatalf("listen calls = %d, want 1", listenCalls)
	}
	if runtime.closes != 1 || server.closes != 1 {
		t.Fatalf("close counts = runtime %d server %d, want one each", runtime.closes, server.closes)
	}
	wantEvents := []string{"bootstrap", "runtime.close", "listen", "server.serve", "server.close"}
	if strings.Join(events, ",") != strings.Join(wantEvents, ",") {
		t.Fatalf("events = %v, want %v", events, wantEvents)
	}
	if !strings.Contains(stderr.String(), "production graph is unavailable") {
		t.Fatalf("stderr = %q, want stable bootstrap failure", stderr.String())
	}
	if strings.Contains(stderr.String(), "private bootstrap detail") {
		t.Fatalf("stderr leaked bootstrap detail: %q", stderr.String())
	}
}

func TestPlatformdBootstrapFailureNeverConstructsPublicListener(t *testing.T) {
	var stderr bytes.Buffer
	publicListenCalls := 0
	dependencies := defaultDependencies()
	dependencies.stderr = &stderr
	dependencies.bootstrap = func(context.Context, statebootstrap.Files) (stateRuntime, error) {
		return &recordingRuntime{}, errors.New("private bootstrap detail")
	}
	dependencies.listenPublic = func(context.Context, stateRuntime) (controlServer, error) {
		publicListenCalls++
		return &recordingServer{}, nil
	}
	dependencies.listen = func(controlrpc.ServerConfig) (controlServer, error) {
		return &recordingServer{}, nil
	}

	if exitCode := execute(context.Background(), []string{"--allow-uid", "1000"}, dependencies); exitCode != 0 {
		t.Fatalf("execute() = %d, want diagnostic-only success", exitCode)
	}
	if publicListenCalls != 0 {
		t.Fatalf("public listen calls = %d, want zero", publicListenCalls)
	}
}

func TestPlatformdPublicListenerFailureDiscardsTheGraphBeforeDiagnosticServe(t *testing.T) {
	var stderr bytes.Buffer
	var events []string
	runtime := &recordingRuntime{events: &events}
	publicCandidate := &recordingServer{events: &events}
	diagnostic := &recordingServer{events: &events}
	dependencies := defaultDependencies()
	dependencies.stderr = &stderr
	dependencies.bootstrap = func(context.Context, statebootstrap.Files) (stateRuntime, error) {
		events = append(events, "bootstrap")
		return runtime, nil
	}
	dependencies.listenPublic = func(context.Context, stateRuntime) (controlServer, error) {
		events = append(events, "public.listen")
		return publicCandidate, errors.New("private public bind detail")
	}
	dependencies.listen = func(controlrpc.ServerConfig) (controlServer, error) {
		events = append(events, "diagnostic.listen")
		return diagnostic, nil
	}

	if exitCode := execute(context.Background(), []string{"--allow-uid", "1000"}, dependencies); exitCode != 0 {
		t.Fatalf("execute() = %d, want diagnostic-only success", exitCode)
	}
	want := []string{
		"bootstrap", "public.listen", "server.close", "runtime.close",
		"diagnostic.listen", "server.serve", "server.close",
	}
	if strings.Join(events, ",") != strings.Join(want, ",") {
		t.Fatalf("events = %v, want %v", events, want)
	}
	if publicCandidate.closes != 1 || diagnostic.closes != 1 || runtime.closes != 1 {
		t.Fatalf(
			"close counts = public %d diagnostic %d runtime %d, want one each",
			publicCandidate.closes, diagnostic.closes, runtime.closes,
		)
	}
	if !strings.Contains(stderr.String(), "production public service is unavailable") ||
		strings.Contains(stderr.String(), "private public bind detail") {
		t.Fatalf("stderr = %q, want stable redacted public failure", stderr.String())
	}
}

func TestPlatformdNilPublicListenerDowngradesToDiagnosticOnly(t *testing.T) {
	for _, typed := range []bool{false, true} {
		t.Run(fmt.Sprintf("typed=%t", typed), func(t *testing.T) {
			runtime := &recordingRuntime{}
			diagnostic := &recordingServer{}
			dependencies := defaultDependencies()
			dependencies.stderr = io.Discard
			dependencies.bootstrap = func(context.Context, statebootstrap.Files) (stateRuntime, error) {
				return runtime, nil
			}
			dependencies.listenPublic = func(context.Context, stateRuntime) (controlServer, error) {
				if typed {
					var nilServer *recordingServer
					return nilServer, nil
				}
				return nil, nil
			}
			dependencies.listen = func(controlrpc.ServerConfig) (controlServer, error) {
				return diagnostic, nil
			}

			if exitCode := execute(context.Background(), []string{"--allow-uid", "1000"}, dependencies); exitCode != 0 {
				t.Fatalf("execute() = %d, want diagnostic-only success", exitCode)
			}
			if runtime.closes != 1 || diagnostic.closes != 1 {
				t.Fatalf("close counts = runtime %d diagnostic %d", runtime.closes, diagnostic.closes)
			}
		})
	}
}

func TestPlatformdListenFailureClosesBootstrapRuntime(t *testing.T) {
	var stderr bytes.Buffer
	var events []string
	runtime := &recordingRuntime{events: &events}
	server := &recordingServer{events: &events}
	publicServer := &recordingServer{events: &events}
	dependencies := defaultDependencies()
	dependencies.stderr = &stderr
	dependencies.bootstrap = func(context.Context, statebootstrap.Files) (stateRuntime, error) {
		events = append(events, "bootstrap")
		return runtime, nil
	}
	dependencies.listen = func(controlrpc.ServerConfig) (controlServer, error) {
		events = append(events, "listen")
		return server, errors.New("listen failed")
	}
	dependencies.listenPublic = func(context.Context, stateRuntime) (controlServer, error) {
		events = append(events, "public.listen")
		return publicServer, nil
	}

	if exitCode := execute(context.Background(), []string{"--allow-uid", "1000"}, dependencies); exitCode != 1 {
		t.Fatalf("execute() = %d, want 1", exitCode)
	}
	want := []string{"bootstrap", "public.listen", "listen", "server.close", "server.close", "runtime.close"}
	if strings.Join(events, ",") != strings.Join(want, ",") {
		t.Fatalf("events = %v, want %v", events, want)
	}
	if server.closes != 1 || publicServer.closes != 1 || runtime.closes != 1 {
		t.Fatalf("close counts = control %d public %d runtime %d, want one each", server.closes, publicServer.closes, runtime.closes)
	}
}

func TestPlatformdServeOutcomesAlwaysCloseServerBeforeRuntime(t *testing.T) {
	tests := []struct {
		name     string
		serveErr error
		wantExit int
	}{
		{name: "return", wantExit: 0},
		{name: "error", serveErr: errors.New("serve failed"), wantExit: 1},
		{name: "context error without daemon cancellation", serveErr: context.Canceled, wantExit: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stderr bytes.Buffer
			var events []string
			runtime := &recordingRuntime{events: &events}
			server := &recordingServer{events: &events, serveErr: test.serveErr}
			publicServer := blockingRecordingServer()
			dependencies := defaultDependencies()
			dependencies.stderr = &stderr
			dependencies.bootstrap = func(context.Context, statebootstrap.Files) (stateRuntime, error) {
				return runtime, nil
			}
			dependencies.listen = func(controlrpc.ServerConfig) (controlServer, error) {
				return server, nil
			}
			dependencies.listenPublic = func(context.Context, stateRuntime) (controlServer, error) {
				return publicServer, nil
			}

			if exitCode := execute(context.Background(), []string{"--allow-uid", "1000"}, dependencies); exitCode != test.wantExit {
				t.Fatalf("execute() = %d, want %d", exitCode, test.wantExit)
			}
			want := []string{"server.serve", "server.close", "runtime.close"}
			if strings.Join(events, ",") != strings.Join(want, ",") {
				t.Fatalf("events = %v, want %v", events, want)
			}
			if server.closes != 1 || publicServer.closes != 1 || runtime.closes != 1 {
				t.Fatalf("close counts = control %d public %d runtime %d, want one each", server.closes, publicServer.closes, runtime.closes)
			}
		})
	}
}

func TestPlatformdRejectsMalformedProductionPathsBeforeBootstrapOrListen(t *testing.T) {
	tests := []struct {
		name      string
		arguments []string
	}{
		{name: "relative socket", arguments: []string{"--socket", "run/platformd.sock"}},
		{name: "root socket", arguments: []string{"--socket", "/"}},
		{name: "unclean socket", arguments: []string{"--socket", "/run/../run/platformd.sock"}},
		{name: "relative config", arguments: []string{"--config", "config.yaml"}},
		{name: "root config", arguments: []string{"--config", "/"}},
		{name: "unclean config", arguments: []string{"--config", "/etc/../etc/config.yaml"}},
		{name: "control character config", arguments: []string{"--config", "/etc/pi-platform/config\n.yaml"}},
		{name: "invalid UTF-8 config", arguments: []string{"--config", "/etc/pi-platform/config-\xff.yaml"}},
		{name: "relative manifest", arguments: []string{"--release-manifest", "release.json"}},
		{name: "root manifest", arguments: []string{"--release-manifest", "/"}},
		{name: "unclean manifest", arguments: []string{"--release-manifest", "/usr/lib/../lib/release.json"}},
		{name: "relative roots", arguments: []string{"--release-trust-roots", "roots.json"}},
		{name: "root roots", arguments: []string{"--release-trust-roots", "/"}},
		{name: "unclean roots", arguments: []string{"--release-trust-roots", "/etc/../etc/roots.json"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stderr bytes.Buffer
			bootstrapCalls := 0
			listenCalls := 0
			dependencies := defaultDependencies()
			dependencies.stderr = &stderr
			dependencies.bootstrap = func(context.Context, statebootstrap.Files) (stateRuntime, error) {
				bootstrapCalls++
				return &recordingRuntime{}, nil
			}
			dependencies.listen = func(controlrpc.ServerConfig) (controlServer, error) {
				listenCalls++
				return &recordingServer{}, nil
			}

			if exitCode := execute(context.Background(), test.arguments, dependencies); exitCode != 2 {
				t.Fatalf("execute() = %d, want 2; stderr=%q", exitCode, stderr.String())
			}
			if bootstrapCalls != 0 || listenCalls != 0 {
				t.Fatalf("calls = bootstrap %d listen %d, want zero", bootstrapCalls, listenCalls)
			}
		})
	}
}

func TestPlatformdMissingDependenciesAndNilContextFailBeforeBootstrap(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		name   string
		ctx    context.Context
		mutate func(*daemonDependencies)
	}{
		{name: "nil context", mutate: func(*daemonDependencies) {}},
		{name: "pre-canceled context", ctx: canceled, mutate: func(*daemonDependencies) {}},
		{name: "nil stderr", ctx: context.Background(), mutate: func(dependencies *daemonDependencies) { dependencies.stderr = nil }},
		{name: "nil effective UID", ctx: context.Background(), mutate: func(dependencies *daemonDependencies) { dependencies.effectiveUID = nil }},
		{name: "nil capabilities", ctx: context.Background(), mutate: func(dependencies *daemonDependencies) { dependencies.capabilityProvider = nil }},
		{name: "nil bootstrap", ctx: context.Background(), mutate: func(dependencies *daemonDependencies) { dependencies.bootstrap = nil }},
		{name: "nil listen", ctx: context.Background(), mutate: func(dependencies *daemonDependencies) { dependencies.listen = nil }},
		{name: "nil public listen", ctx: context.Background(), mutate: func(dependencies *daemonDependencies) { dependencies.listenPublic = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bootstrapCalls := 0
			dependencies := defaultDependencies()
			dependencies.stderr = io.Discard
			dependencies.bootstrap = func(context.Context, statebootstrap.Files) (stateRuntime, error) {
				bootstrapCalls++
				return &recordingRuntime{}, nil
			}
			test.mutate(&dependencies)

			wantExit := 1
			if test.ctx == canceled {
				wantExit = 0
			}
			if exitCode := execute(test.ctx, []string{"--allow-uid", "1000"}, dependencies); exitCode != wantExit {
				t.Fatalf("execute() = %d, want %d", exitCode, wantExit)
			}
			if bootstrapCalls != 0 {
				t.Fatalf("bootstrap calls = %d, want 0", bootstrapCalls)
			}
		})
	}
}

func TestPlatformdNilRuntimeOrServerFailsSafely(t *testing.T) {
	tests := []struct {
		name            string
		runtimeTypedNil bool
		serverFailure   bool
		serverTypedNil  bool
		wantExit        int
		wantListen      int
	}{
		{name: "nil runtime", wantListen: 1},
		{name: "typed nil runtime", runtimeTypedNil: true, wantListen: 1},
		{name: "nil server", serverFailure: true, wantExit: 1, wantListen: 1},
		{name: "typed nil server", serverFailure: true, serverTypedNil: true, wantExit: 1, wantListen: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime := &recordingRuntime{}
			server := &recordingServer{}
			listenCalls := 0
			dependencies := defaultDependencies()
			dependencies.stderr = io.Discard
			dependencies.bootstrap = func(context.Context, statebootstrap.Files) (stateRuntime, error) {
				if !test.serverFailure {
					if test.runtimeTypedNil {
						var nilRuntime *recordingRuntime
						return nilRuntime, nil
					}
					return nil, nil
				}
				return runtime, nil
			}
			dependencies.listen = func(controlrpc.ServerConfig) (controlServer, error) {
				listenCalls++
				if !test.serverFailure {
					return server, nil
				}
				if test.serverTypedNil {
					var nilServer *recordingServer
					return nilServer, nil
				}
				return nil, nil
			}
			if exitCode := execute(context.Background(), []string{"--allow-uid", "1000"}, dependencies); exitCode != test.wantExit {
				t.Fatalf("execute() = %d, want %d", exitCode, test.wantExit)
			}
			if listenCalls != test.wantListen {
				t.Fatalf("listen calls = %d, want %d", listenCalls, test.wantListen)
			}
			wantRuntimeCloses := 0
			if test.serverFailure {
				wantRuntimeCloses = 1
			}
			if runtime.closes != wantRuntimeCloses {
				t.Fatalf("runtime closes = %d, want %d", runtime.closes, wantRuntimeCloses)
			}
		})
	}
}

func TestPlatformdCancellationDuringBootstrapClosesRuntimeWithoutListening(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	runtime := &recordingRuntime{}
	listenCalls := 0
	dependencies := defaultDependencies()
	dependencies.stderr = io.Discard
	dependencies.bootstrap = func(got context.Context, _ statebootstrap.Files) (stateRuntime, error) {
		if got != ctx {
			t.Fatal("bootstrap did not receive the exact daemon context")
		}
		cancel()
		return runtime, nil
	}
	dependencies.listen = func(controlrpc.ServerConfig) (controlServer, error) {
		listenCalls++
		return &recordingServer{}, nil
	}

	if exitCode := execute(ctx, []string{"--allow-uid", "1000"}, dependencies); exitCode != 0 {
		t.Fatalf("execute() = %d, want 0", exitCode)
	}
	if runtime.closes != 1 || listenCalls != 0 {
		t.Fatalf("runtime closes/listen calls = %d/%d, want 1/0", runtime.closes, listenCalls)
	}
}

func TestPlatformdPassesCancellationFenceToPublicListener(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	runtime := &recordingRuntime{}
	publicServer := &recordingServer{}
	diagnosticListenCalls := 0
	dependencies := defaultDependencies()
	dependencies.stderr = io.Discard
	dependencies.bootstrap = func(context.Context, statebootstrap.Files) (stateRuntime, error) {
		return runtime, nil
	}
	dependencies.listenPublic = func(got context.Context, _ stateRuntime) (controlServer, error) {
		if got != ctx {
			t.Fatal("public listener did not receive the exact daemon context")
		}
		cancel()
		return publicServer, nil
	}
	dependencies.listen = func(controlrpc.ServerConfig) (controlServer, error) {
		diagnosticListenCalls++
		return &recordingServer{}, nil
	}

	if exitCode := execute(ctx, []string{"--allow-uid", "1000"}, dependencies); exitCode != 0 {
		t.Fatalf("execute() = %d, want 0", exitCode)
	}
	if publicServer.closes != 1 || runtime.closes != 1 || diagnosticListenCalls != 0 {
		t.Fatalf(
			"public/runtime closes and diagnostic listens = %d/%d/%d, want 1/1/0",
			publicServer.closes, runtime.closes, diagnosticListenCalls,
		)
	}
}
