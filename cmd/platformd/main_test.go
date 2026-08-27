package main

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/controlrpc"
)

func TestPlatformdServesHonestCapabilitiesAndRemovesItsSocket(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "platformd.sock")
	var stderr bytes.Buffer
	dependencies := defaultDependencies()
	dependencies.stderr = &stderr
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
			if exitCode := execute(context.Background(), test.arguments, dependencies); exitCode != 2 {
				t.Fatalf("execute() = %d, want 2; stderr=%q", exitCode, stderr.String())
			}
		})
	}

	existingPath := filepath.Join(t.TempDir(), "platformd.sock")
	if err := os.WriteFile(existingPath, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	dependencies := defaultDependencies()
	dependencies.stderr = &stderr
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
	socketPath := filepath.Join(t.TempDir(), "platformd.sock")
	var stderr bytes.Buffer
	dependencies := defaultDependencies()
	dependencies.stderr = &stderr
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

func waitForSocket(t *testing.T, socketPath string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		info, err := os.Lstat(socketPath)
		if err == nil && info.Mode()&os.ModeSocket != 0 {
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
