//go:build linux

package doctoruds

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/conformance"
	"github.com/hancomac/circulusd/internal/daemonshell"
)

// TestDefaultQueryPassesAgainstRealDaemonshellServers wires the REAL agentd and
// executord control servers — started through daemonshell.Execute with their
// production capability providers — together with a real platformd control
// server, and runs the real uds.protocol probe across all three in canonical
// order. Unlike the plain-controlrpc integration test, this exercises the actual
// daemon serving path (flag parsing, peer-UID authority wiring, the honest
// capability snapshot, and platformdaemon.Serve) end to end behind the probe.
func TestDefaultQueryPassesAgainstRealDaemonshellServers(t *testing.T) {
	directory := shortSocketDirectory(t)
	platformd := startIntegrationServer(
		t, directory, Platformd,
		v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD,
		[]v1.ProtocolPeer{v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL},
		staticCapabilities(Platformd), nil,
	)
	agentd := startDaemonshellServer(t, directory, Agentd, daemonshell.AgentdProfile())
	executord := startDaemonshellServer(t, directory, Executord, daemonshell.ExecutordProfile())

	probe, err := BuildProbe(Config{
		Endpoints: []Endpoint{platformd, agentd, executord},
		Timeout:   5 * time.Second,
	})
	if err != nil {
		t.Fatalf("BuildProbe() error = %v", err)
	}
	result := probe.Run(context.Background())
	if result.Status != conformance.Pass {
		t.Fatalf("probe result = %+v, want PASS", result)
	}
	if len(result.Evidence.ArtifactReferences) != 3 {
		t.Fatalf("probe artifacts = %+v, want 3", result.Evidence.ArtifactReferences)
	}
}

// startDaemonshellServer runs a real agentd/executord control server through
// daemonshell.Execute on a private socket and returns its probe Endpoint once
// the socket is bound.
func startDaemonshellServer(t *testing.T, directory, name string, profile daemonshell.Profile) Endpoint {
	t.Helper()
	path := filepath.Join(directory, name+".sock")
	arguments := []string{
		"--socket", path,
		"--allow-platformctl-uid", fmt.Sprint(os.Geteuid()),
	}
	serveContext, cancelServe := context.WithCancel(context.Background())
	var stderr bytes.Buffer
	exit := make(chan int, 1)
	go func() {
		exit <- daemonshell.Execute(serveContext, arguments, profile, daemonshell.DefaultDependencies(&stderr))
	}()
	t.Cleanup(func() {
		cancelServe()
		select {
		case code := <-exit:
			if code != 0 {
				t.Errorf("daemonshell Execute(%s) exit = %d, stderr = %q", name, code, stderr.String())
			}
		case <-time.After(3 * time.Second):
			t.Errorf("daemonshell Execute(%s) did not stop", name)
		}
	})
	waitForControlSocket(t, path)
	return Endpoint{Name: name, SocketPath: path, ExpectedServerPeer: expectedPeer(name)}
}

// waitForControlSocket blocks until a private control socket (mode 0600) exists
// at path, matching the readiness check the production daemons rely on.
func waitForControlSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		info, err := os.Lstat(path)
		if err == nil {
			if info.Mode()&os.ModeSocket == 0 {
				t.Fatalf("control path %q is not a socket (mode %v)", path, info.Mode())
			}
			if perm := info.Mode().Perm(); perm != 0o600 {
				t.Fatalf("control socket %q mode = %04o, want 0600", path, perm)
			}
			return
		}
		if !os.IsNotExist(err) {
			t.Fatalf("Lstat(%q) error = %v", path, err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("control socket %q did not appear within the deadline", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
