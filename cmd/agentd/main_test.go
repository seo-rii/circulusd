package main

import (
	"bytes"
	"context"
	"testing"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/daemonshell"
)

func TestExecuteAgentdSelectsOnlyTheAgentDiagnosticShell(t *testing.T) {
	t.Parallel()

	var captured daemonshell.ListenerConfig
	dependencies := daemonshell.Dependencies{
		Stderr: &bytes.Buffer{},
		Listen: func(_ context.Context, config daemonshell.ListenerConfig) (daemonshell.Server, error) {
			captured = config
			return immediateServer{}, nil
		},
	}
	if exitCode := executeAgentd(context.Background(), []string{"--allow-platformd-uid", "1001"}, dependencies); exitCode != 0 {
		t.Fatalf("executeAgentd() = %d, want 0", exitCode)
	}
	if captured.Control.ServerPeer != v1.ProtocolPeer_PROTOCOL_PEER_AGENTD ||
		captured.Control.SocketPath != "/run/pi-platform/agentd.sock" {
		t.Fatalf("agentd listener config = %+v", captured)
	}
}

func TestExecuteAgentdFailsClosedWithoutExplicitPeerUIDAuthority(t *testing.T) {
	t.Parallel()

	var listened bool
	dependencies := daemonshell.Dependencies{
		Stderr: &bytes.Buffer{},
		Listen: func(context.Context, daemonshell.ListenerConfig) (daemonshell.Server, error) {
			listened = true
			return immediateServer{}, nil
		},
	}
	if exitCode := executeAgentd(context.Background(), nil, dependencies); exitCode != 2 {
		t.Fatalf("executeAgentd() = %d, want 2", exitCode)
	}
	if listened {
		t.Fatal("agentd listened without an explicit peer UID authority")
	}
}

type immediateServer struct{}

func (immediateServer) Serve(context.Context) error { return nil }
func (immediateServer) Close() error                { return nil }
