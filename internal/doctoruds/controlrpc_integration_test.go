//go:build linux

package doctoruds

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/conformance"
	"github.com/hancomac/circulusd/internal/controlrpc"
)

func TestDefaultQueryPassesAgainstThreeAuthenticatedControlServers(t *testing.T) {
	directory := shortSocketDirectory(t)
	endpoints := []Endpoint{
		startIntegrationServer(t, directory, Platformd, v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD, []v1.ProtocolPeer{v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL}, staticCapabilities(Platformd), nil),
		startIntegrationServer(t, directory, Agentd, v1.ProtocolPeer_PROTOCOL_PEER_AGENTD, []v1.ProtocolPeer{v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL}, staticCapabilities(Agentd), nil),
		startIntegrationServer(t, directory, Executord, v1.ProtocolPeer_PROTOCOL_PEER_EXECUTORD, []v1.ProtocolPeer{v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL}, staticCapabilities(Executord), nil),
	}
	probe, err := BuildProbe(Config{Endpoints: endpoints, Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("BuildProbe(default query) error = %v", err)
	}

	result := probe.Run(context.Background())
	if result.Status != conformance.Pass {
		t.Fatalf("default-query result = %+v, want PASS", result)
	}
	if len(result.Evidence.ArtifactReferences) != 3 {
		t.Fatalf("default-query artifacts = %+v", result.Evidence.ArtifactReferences)
	}
}

func TestControlRPCQueryRejectsWrongAuthenticatedServerRole(t *testing.T) {
	directory := shortSocketDirectory(t)
	endpoint := startIntegrationServer(
		t,
		directory,
		Platformd,
		v1.ProtocolPeer_PROTOCOL_PEER_AGENTD,
		[]v1.ProtocolPeer{v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL},
		staticCapabilities(Platformd),
		nil,
	)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	response, err := ControlRPCQuery(ctx, endpoint)
	if response != nil || connect.CodeOf(err) != connect.CodeDataLoss {
		t.Fatalf("ControlRPCQuery(wrong role) response=%v error=%v code=%v, want data_loss", response, err, connect.CodeOf(err))
	}
}

func TestDefaultProbeHidesWrongRoleAndPeerAuthorityDetails(t *testing.T) {
	tests := []struct {
		name         string
		serverPeer   v1.ProtocolPeer
		allowedPeers []v1.ProtocolPeer
	}{
		{
			name:         "wrong authenticated server role",
			serverPeer:   v1.ProtocolPeer_PROTOCOL_PEER_AGENTD,
			allowedPeers: []v1.ProtocolPeer{v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL},
		},
		{
			name:         "platformctl lacks authority",
			serverPeer:   v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD,
			allowedPeers: []v1.ProtocolPeer{v1.ProtocolPeer_PROTOCOL_PEER_AGENTD},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := shortSocketDirectory(t)
			platformd := startIntegrationServer(t, directory, Platformd, test.serverPeer, test.allowedPeers, staticCapabilities(Platformd), nil)
			endpoints := []Endpoint{
				platformd,
				{Name: Agentd, SocketPath: filepath.Join(directory, "agentd.sock"), ExpectedServerPeer: v1.ProtocolPeer_PROTOCOL_PEER_AGENTD},
				{Name: Executord, SocketPath: filepath.Join(directory, "executord.sock"), ExpectedServerPeer: v1.ProtocolPeer_PROTOCOL_PEER_EXECUTORD},
			}
			probe, err := BuildProbe(Config{Endpoints: endpoints, Timeout: 3 * time.Second})
			if err != nil {
				t.Fatalf("BuildProbe() error = %v", err)
			}
			result := probe.Run(context.Background())
			if result.Status != conformance.Fail || result.Reason != "daemon protocol verification failed" {
				t.Fatalf("result = %+v, want generic FAIL", result)
			}
			assertNoSensitiveReason(t, result.Reason)
		})
	}
}

func TestDefaultProbeMapsInFlightCancellationToNotRun(t *testing.T) {
	directory := shortSocketDirectory(t)
	entered := make(chan struct{})
	var enteredOnce sync.Once
	provider := func(ctx context.Context) ([]*v1.CapabilityStatus, error) {
		enteredOnce.Do(func() { close(entered) })
		<-ctx.Done()
		return nil, ctx.Err()
	}
	platformd := startIntegrationServer(
		t,
		directory,
		Platformd,
		v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD,
		[]v1.ProtocolPeer{v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL},
		nil,
		provider,
	)
	endpoints := []Endpoint{
		platformd,
		{Name: Agentd, SocketPath: filepath.Join(directory, "agentd.sock"), ExpectedServerPeer: v1.ProtocolPeer_PROTOCOL_PEER_AGENTD},
		{Name: Executord, SocketPath: filepath.Join(directory, "executord.sock"), ExpectedServerPeer: v1.ProtocolPeer_PROTOCOL_PEER_EXECUTORD},
	}
	probe, err := BuildProbe(Config{Endpoints: endpoints, Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("BuildProbe() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	resultChannel := make(chan conformance.Result, 1)
	go func() {
		resultChannel <- probe.Run(ctx)
	}()

	select {
	case <-entered:
		cancel()
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("capability provider was not called")
	}
	select {
	case result := <-resultChannel:
		if result.Status != conformance.NotRun || result.Reason != "daemon protocol probe canceled" {
			t.Fatalf("canceled result = %+v, want NOT_RUN", result)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("probe did not return after cancellation")
	}
}

func startIntegrationServer(
	t *testing.T,
	directory string,
	name string,
	serverPeer v1.ProtocolPeer,
	allowedPeers []v1.ProtocolPeer,
	capabilities []*v1.CapabilityStatus,
	provider controlrpc.CapabilityProvider,
) Endpoint {
	t.Helper()
	path := filepath.Join(directory, name+".sock")
	server, err := controlrpc.ListenServer(controlrpc.ServerConfig{
		SocketPath:         path,
		AllowedUIDs:        []uint32{uint32(os.Geteuid())},
		AllowedPeers:       append([]v1.ProtocolPeer(nil), allowedPeers...),
		ServerPeer:         serverPeer,
		Capabilities:       capabilities,
		CapabilityProvider: provider,
	})
	if err != nil {
		t.Fatalf("ListenServer(%s) error = %v", name, err)
	}
	serveContext, cancelServe := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(serveContext)
	}()
	t.Cleanup(func() {
		cancelServe()
		_ = server.Close()
		select {
		case serveErr := <-done:
			if serveErr != nil {
				t.Errorf("Serve(%s) error = %v", name, serveErr)
			}
		case <-time.After(3 * time.Second):
			t.Errorf("Serve(%s) did not stop", name)
		}
	})
	return Endpoint{Name: name, SocketPath: path, ExpectedServerPeer: expectedPeer(name)}
}

func staticCapabilities(name string) []*v1.CapabilityStatus {
	capabilities := []*v1.CapabilityStatus{{
		Name:         "control.protocol",
		Availability: v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_AVAILABLE,
	}}
	if name != Platformd {
		capabilities = append(capabilities, &v1.CapabilityStatus{
			Name:         "daemon." + name,
			Availability: v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_AVAILABLE,
		})
	}
	return capabilities
}

func expectedPeer(name string) v1.ProtocolPeer {
	switch name {
	case Platformd:
		return v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD
	case Agentd:
		return v1.ProtocolPeer_PROTOCOL_PEER_AGENTD
	case Executord:
		return v1.ProtocolPeer_PROTOCOL_PEER_EXECUTORD
	default:
		return v1.ProtocolPeer_PROTOCOL_PEER_UNSPECIFIED
	}
}

func shortSocketDirectory(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp(os.TempDir(), "du-")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Errorf("RemoveAll(%s) error = %v", directory, err)
		}
	})
	return directory
}
