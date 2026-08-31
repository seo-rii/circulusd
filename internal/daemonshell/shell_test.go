package daemonshell

import (
	"bytes"
	"context"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/controlrpc"
)

func TestProductionDaemonMainsKeepMinimalDiagnosticImportSurface(t *testing.T) {
	t.Parallel()

	allowed := map[string]struct{}{
		"context":   {},
		"os":        {},
		"os/signal": {},
		"syscall":   {},
		"github.com/hancomac/circulusd/internal/daemonshell": {},
	}
	for _, daemon := range []string{"agentd", "executord"} {
		daemon := daemon
		t.Run(daemon, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join("..", "..", "cmd", daemon, "main.go")
			parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("ParseFile(%q) error = %v", path, err)
			}
			seen := make(map[string]struct{}, len(parsed.Imports))
			for _, specification := range parsed.Imports {
				importPath, err := strconv.Unquote(specification.Path.Value)
				if err != nil {
					t.Fatalf("invalid import %q: %v", specification.Path.Value, err)
				}
				if _, permitted := allowed[importPath]; !permitted {
					t.Fatalf("production %s main imports non-diagnostic dependency %q", daemon, importPath)
				}
				seen[importPath] = struct{}{}
			}
			if !reflect.DeepEqual(seen, allowed) {
				t.Fatalf("production %s main imports = %#v, want %#v", daemon, seen, allowed)
			}
		})
	}
}

func TestProfilesExposeOnlyDiagnosticControlAndHonestRoleCapabilities(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		profile     Profile
		peer        v1.ProtocolPeer
		defaultPath string
		roleName    string
		unavailable []string
	}{
		{
			name: "agentd", profile: AgentdProfile(),
			peer: v1.ProtocolPeer_PROTOCOL_PEER_AGENTD, defaultPath: "/run/pi-platform/agentd.sock",
			roleName: "daemon.agentd", unavailable: []string{"agent.isolation", "agent.workerd"},
		},
		{
			name: "executord", profile: ExecutordProfile(),
			peer: v1.ProtocolPeer_PROTOCOL_PEER_EXECUTORD, defaultPath: "/run/pi-platform/executord.sock",
			roleName: "daemon.executord",
			unavailable: []string{
				"execution.docker", "execution.environments", "execution.firecracker", "execution.nsjail",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if test.profile.ServerPeer() != test.peer || test.profile.DefaultSocketPath() != test.defaultPath {
				t.Fatalf("profile identity = %v/%q", test.profile.ServerPeer(), test.profile.DefaultSocketPath())
			}
			provider := test.profile.CapabilityProvider()
			first, err := provider(context.Background())
			if err != nil {
				t.Fatalf("CapabilityProvider() error = %v", err)
			}
			wantNames := append([]string{"control.protocol", test.roleName}, test.unavailable...)
			if len(first) != len(wantNames) {
				t.Fatalf("capabilities = %d, want %d: %+v", len(first), len(wantNames), first)
			}
			byName := make(map[string]*v1.CapabilityStatus, len(first))
			for _, capability := range first {
				if capability == nil {
					t.Fatal("capability is nil")
				}
				if _, duplicate := byName[capability.GetName()]; duplicate {
					t.Fatalf("capability %q is duplicated", capability.GetName())
				}
				byName[capability.GetName()] = capability
				if capability.GetAttributes()["daemonRole"] != test.name ||
					capability.GetAttributes()["admissionEnabled"] != "false" ||
					capability.GetAttributes()["productionEligible"] != "false" ||
					capability.GetAttributes()["runtimeProfile"] != "diagnostic-only" {
					t.Fatalf("capability %q attributes = %#v", capability.GetName(), capability.GetAttributes())
				}
			}
			for _, name := range []string{"control.protocol", test.roleName} {
				capability := byName[name]
				if capability == nil || capability.GetAvailability() != v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_AVAILABLE ||
					capability.GetUnavailableReason() != nil {
					t.Fatalf("available capability %q = %+v", name, capability)
				}
			}
			for _, name := range test.unavailable {
				capability := byName[name]
				reason := capability.GetUnavailableReason()
				if capability == nil || capability.GetAvailability() != v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_UNAVAILABLE ||
					reason.GetCode() != v1.ErrorCode_ERROR_CODE_UNAVAILABLE || reason.GetReason() != "NOT_WIRED" ||
					!strings.Contains(reason.GetMessage(), "diagnostic shell") {
					t.Fatalf("unavailable capability %q = %+v", name, capability)
				}
			}

			first[0].Attributes["daemonRole"] = "mutated"
			second, err := provider(context.Background())
			if err != nil || second[0].GetAttributes()["daemonRole"] != test.name {
				t.Fatalf("capability snapshot aliases caller mutation: %+v err=%v", second, err)
			}
			cancelled, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err := provider(cancelled); !errors.Is(err, context.Canceled) {
				t.Fatalf("CapabilityProvider(cancelled) error = %v", err)
			}
		})
	}
}

func TestExecuteBuildsRoleBoundControlListenerWithExplicitUIDs(t *testing.T) {
	t.Parallel()

	t.Run("explicit role UID pairs and socket", func(t *testing.T) {
		t.Parallel()

		var captured ListenerConfig
		server := &returningServer{}
		dependencies := Dependencies{
			Stderr: &bytes.Buffer{},
			Listen: func(_ context.Context, config ListenerConfig) (Server, error) {
				captured = config
				return server, nil
			},
		}
		arguments := []string{
			"--socket", "/run/pi-platform/custom-executord.sock",
			"--allow-platformd-uid", "42",
			"--allow-platformd-uid", "7",
			"--allow-platformctl-uid", "9",
		}
		if exitCode := Execute(context.Background(), arguments, ExecutordProfile(), dependencies); exitCode != 0 {
			t.Fatalf("Execute() = %d, want 0", exitCode)
		}
		if captured.Control.ServerPeer != v1.ProtocolPeer_PROTOCOL_PEER_EXECUTORD ||
			captured.Control.SocketPath != "/run/pi-platform/custom-executord.sock" ||
			!reflect.DeepEqual(captured.Control.PeerUIDAuthorities, []controlrpc.PeerUIDAuthority{
				{UID: 42, Peer: v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD},
				{UID: 7, Peer: v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD},
				{UID: 9, Peer: v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL},
			}) {
			t.Fatalf("listener config = %+v", captured)
		}
	})

	t.Run("one explicit role grants no implicit peer", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name        string
			arguments   []string
			authorities []controlrpc.PeerUIDAuthority
		}{
			{
				name: "platformd only", arguments: []string{"--allow-platformd-uid", "21"},
				authorities: []controlrpc.PeerUIDAuthority{{UID: 21, Peer: v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD}},
			},
			{
				name: "platformctl only", arguments: []string{"--allow-platformctl-uid", "22"},
				authorities: []controlrpc.PeerUIDAuthority{{UID: 22, Peer: v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL}},
			},
			{
				name:      "same UID intentionally has both roles",
				arguments: []string{"--allow-platformd-uid", "23", "--allow-platformctl-uid", "23"},
				authorities: []controlrpc.PeerUIDAuthority{
					{UID: 23, Peer: v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD},
					{UID: 23, Peer: v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL},
				},
			},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				t.Parallel()

				var captured ListenerConfig
				dependencies := Dependencies{
					Stderr: &bytes.Buffer{},
					Listen: func(_ context.Context, config ListenerConfig) (Server, error) {
						captured = config
						return &returningServer{}, nil
					},
				}
				if exitCode := Execute(context.Background(), test.arguments, AgentdProfile(), dependencies); exitCode != 0 {
					t.Fatalf("Execute() = %d, want 0", exitCode)
				}
				if !reflect.DeepEqual(captured.Control.PeerUIDAuthorities, test.authorities) {
					t.Fatalf("peer UID authorities = %+v, want %+v", captured.Control.PeerUIDAuthorities, test.authorities)
				}
			})
		}
	})
}

func TestExecuteRequiresAtLeastOneExplicitPeerUIDAuthority(t *testing.T) {
	t.Parallel()

	var listened atomic.Bool
	var stderr bytes.Buffer
	dependencies := Dependencies{
		Stderr: &stderr,
		Listen: func(context.Context, ListenerConfig) (Server, error) {
			listened.Store(true)
			return &returningServer{}, nil
		},
	}
	if exitCode := Execute(context.Background(), nil, AgentdProfile(), dependencies); exitCode != 2 {
		t.Fatalf("Execute() = %d, want 2", exitCode)
	}
	if listened.Load() {
		t.Fatal("missing explicit peer UID authority reached listener")
	}
	if !strings.Contains(stderr.String(), "at least one peer UID authority is required") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestExecuteRejectsInvalidAndDuplicateFlagsBeforeListening(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		arguments []string
	}{
		{name: "unknown", arguments: []string{"--unknown"}},
		{name: "positional", arguments: []string{"extra"}},
		{name: "relative socket", arguments: []string{"--socket", "agentd.sock"}},
		{name: "root socket", arguments: []string{"--socket", "/"}},
		{name: "unclean socket", arguments: []string{"--socket", "/run/../run/agentd.sock"}},
		{name: "control character", arguments: []string{"--socket", "/run/pi-platform/agentd\n.sock"}},
		{name: "duplicate socket", arguments: []string{"--socket", "/run/pi-platform/one.sock", "--socket", "/run/pi-platform/two.sock"}},
		{name: "ambiguous legacy UID", arguments: []string{"--allow-uid", "7"}},
		{name: "negative UID", arguments: []string{"--allow-platformd-uid", "-1"}},
		{name: "noncanonical UID", arguments: []string{"--allow-platformctl-uid", "01"}},
		{name: "overflow UID", arguments: []string{"--allow-platformd-uid", "4294967296"}},
		{name: "duplicate platformd UID", arguments: []string{"--allow-platformd-uid", "7", "--allow-platformd-uid", "7"}},
		{name: "duplicate platformctl UID", arguments: []string{"--allow-platformctl-uid", "8", "--allow-platformctl-uid", "8"}},
	}
	tooMany := make([]string, 0, 2*65)
	for uid := 0; uid < 65; uid++ {
		tooMany = append(tooMany, "--allow-platformctl-uid", strconv.Itoa(uid))
	}
	tests = append(tests, struct {
		name      string
		arguments []string
	}{name: "too many UIDs", arguments: tooMany})

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var listened atomic.Bool
			dependencies := Dependencies{
				Stderr: &bytes.Buffer{},
				Listen: func(context.Context, ListenerConfig) (Server, error) {
					listened.Store(true)
					return nil, nil
				},
			}
			if exitCode := Execute(context.Background(), test.arguments, AgentdProfile(), dependencies); exitCode != 2 {
				t.Fatalf("Execute() = %d, want 2", exitCode)
			}
			if listened.Load() {
				t.Fatal("invalid CLI reached listener")
			}
		})
	}
}

func TestExecuteRejectsInvalidDependencies(t *testing.T) {
	t.Parallel()

	valid := Dependencies{Stderr: &bytes.Buffer{}, Listen: func(context.Context, ListenerConfig) (Server, error) {
		return &returningServer{}, nil
	}}
	tests := []struct {
		name         string
		ctx          context.Context
		dependencies Dependencies
	}{
		{name: "nil context", dependencies: valid},
		{name: "nil stderr", ctx: context.Background(), dependencies: Dependencies{Listen: valid.Listen}},
		{name: "nil listener", ctx: context.Background(), dependencies: Dependencies{Stderr: valid.Stderr}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if exitCode := Execute(test.ctx, []string{"--allow-platformd-uid", "1"}, AgentdProfile(), test.dependencies); exitCode != 1 {
				t.Fatalf("Execute() = %d, want 1", exitCode)
			}
		})
	}
}

func TestExecuteRejectsTypedNilStderrBeforeParsingOrListening(t *testing.T) {
	t.Parallel()

	var stderr *bytes.Buffer
	var listened atomic.Bool
	dependencies := Dependencies{
		Stderr: stderr,
		Listen: func(context.Context, ListenerConfig) (Server, error) {
			listened.Store(true)
			return &returningServer{}, nil
		},
	}
	if exitCode := Execute(
		context.Background(),
		[]string{"--allow-platformd-uid", "1"},
		AgentdProfile(),
		dependencies,
	); exitCode != 1 {
		t.Fatalf("Execute() = %d, want 1", exitCode)
	}
	if listened.Load() {
		t.Fatal("typed-nil stderr reached listener")
	}
}

func TestExecuteRejectsCrossWiredDaemonIdentityBeforeListening(t *testing.T) {
	t.Parallel()

	profile := AgentdProfile()
	profile.serverPeer = v1.ProtocolPeer_PROTOCOL_PEER_EXECUTORD
	var listened atomic.Bool
	dependencies := Dependencies{
		Stderr: &bytes.Buffer{},
		Listen: func(context.Context, ListenerConfig) (Server, error) {
			listened.Store(true)
			return &returningServer{}, nil
		},
	}
	if exitCode := Execute(context.Background(), nil, profile, dependencies); exitCode != 1 {
		t.Fatalf("Execute(cross-wired profile) = %d, want 1", exitCode)
	}
	if listened.Load() {
		t.Fatal("cross-wired profile reached listener")
	}
}

func TestExecuteClosesPartialAndRejectsNilListenerResults(t *testing.T) {
	t.Parallel()

	listenError := errors.New("secret listener detail")
	tests := []struct {
		name       string
		listenKind string
		wantClosed int64
	}{
		{name: "nil", listenKind: "nil"},
		{name: "typed nil", listenKind: "typed-nil"},
		{name: "error", listenKind: "error"},
		{name: "partial error", listenKind: "partial", wantClosed: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var partial *blockingServer
			var stderr bytes.Buffer
			dependencies := Dependencies{Stderr: &stderr, Listen: func(context.Context, ListenerConfig) (Server, error) {
				switch test.listenKind {
				case "nil":
					return nil, nil
				case "typed-nil":
					var server *blockingServer
					return server, nil
				case "error":
					return nil, listenError
				case "partial":
					partial = newBlockingServer(nil)
					return partial, listenError
				default:
					t.Fatalf("unknown listener kind %q", test.listenKind)
					return nil, nil
				}
			}}
			if exitCode := Execute(context.Background(), []string{"--allow-platformd-uid", "1"}, AgentdProfile(), dependencies); exitCode != 1 {
				t.Fatalf("Execute() = %d, want 1", exitCode)
			}
			if partial != nil && partial.closeCalls.Load() != test.wantClosed {
				t.Fatalf("Close() calls = %d, want %d", partial.closeCalls.Load(), test.wantClosed)
			}
			if strings.Contains(stderr.String(), "secret listener detail") {
				t.Fatalf("listener detail leaked: %q", stderr.String())
			}
		})
	}
}

func TestExecuteTreatsPreCancellationAsGracefulAndClosesOnCancellation(t *testing.T) {
	t.Parallel()

	t.Run("pre-cancelled", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		var listened atomic.Bool
		dependencies := Dependencies{Stderr: &bytes.Buffer{}, Listen: func(context.Context, ListenerConfig) (Server, error) {
			listened.Store(true)
			return nil, nil
		}}
		if exitCode := Execute(ctx, []string{"--allow-platformd-uid", "1"}, AgentdProfile(), dependencies); exitCode != 0 || listened.Load() {
			t.Fatalf("Execute() = %d listened=%t", exitCode, listened.Load())
		}
	})

	t.Run("active cancellation", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		server := newBlockingServer(nil)
		dependencies := Dependencies{Stderr: &bytes.Buffer{}, Listen: func(context.Context, ListenerConfig) (Server, error) {
			return server, nil
		}}
		done := make(chan int, 1)
		go func() {
			done <- Execute(ctx, []string{"--allow-platformctl-uid", "1"}, ExecutordProfile(), dependencies)
		}()
		select {
		case <-server.started:
		case <-time.After(3 * time.Second):
			t.Fatal("server did not start")
		}
		cancel()
		select {
		case exitCode := <-done:
			if exitCode != 0 {
				t.Fatalf("Execute() = %d, want 0", exitCode)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("Execute() did not return after cancellation")
		}
		if server.closeCalls.Load() != 1 {
			t.Fatalf("Close() calls = %d, want 1", server.closeCalls.Load())
		}
	})
}

func TestExecutePropagatesCancellationToListenerCreation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	dependencies := Dependencies{
		Stderr: &bytes.Buffer{},
		Listen: func(listenContext context.Context, _ ListenerConfig) (Server, error) {
			close(started)
			<-listenContext.Done()
			return nil, listenContext.Err()
		},
	}
	done := make(chan int, 1)
	go func() {
		done <- Execute(ctx, []string{"--allow-platformd-uid", "1"}, AgentdProfile(), dependencies)
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("listener creation did not start")
	}
	cancel()
	select {
	case exitCode := <-done:
		if exitCode != 0 {
			t.Fatalf("Execute() = %d, want 0", exitCode)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("listener creation did not observe cancellation")
	}
}

func TestExecuteTreatsCancellationCleanupFailureAsSanitizedFailure(t *testing.T) {
	t.Parallel()

	t.Run("cancelled after listener creation", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		server := &returningServer{closeError: errors.New("secret close detail")}
		var stderr bytes.Buffer
		dependencies := Dependencies{
			Stderr: &stderr,
			Listen: func(context.Context, ListenerConfig) (Server, error) {
				cancel()
				return server, nil
			},
		}
		exitCode := Execute(ctx, []string{"--allow-platformd-uid", "1"}, AgentdProfile(), dependencies)
		if exitCode != 1 {
			t.Fatalf("Execute() = %d, want 1", exitCode)
		}
		if server.closeCalls.Load() != 1 || server.serveCalls.Load() != 0 {
			t.Fatalf("Close() calls = %d Serve() calls = %d", server.closeCalls.Load(), server.serveCalls.Load())
		}
		if !strings.Contains(stderr.String(), "diagnostic control socket cleanup failed") ||
			strings.Contains(stderr.String(), "secret close detail") {
			t.Fatalf("stderr = %q", stderr.String())
		}
	})

	t.Run("partial listener after cancellation", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		server := &returningServer{closeError: errors.New("secret partial close detail")}
		var stderr bytes.Buffer
		dependencies := Dependencies{
			Stderr: &stderr,
			Listen: func(context.Context, ListenerConfig) (Server, error) {
				cancel()
				return server, errors.New("secret partial listen detail")
			},
		}
		exitCode := Execute(ctx, []string{"--allow-platformctl-uid", "1"}, ExecutordProfile(), dependencies)
		if exitCode != 1 {
			t.Fatalf("Execute() = %d, want 1", exitCode)
		}
		if server.closeCalls.Load() != 1 || server.serveCalls.Load() != 0 {
			t.Fatalf("Close() calls = %d Serve() calls = %d", server.closeCalls.Load(), server.serveCalls.Load())
		}
		if !strings.Contains(stderr.String(), "diagnostic control socket cleanup failed") ||
			strings.Contains(stderr.String(), "secret partial") {
			t.Fatalf("stderr = %q", stderr.String())
		}
	})

	t.Run("active service cancellation", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		server := newBlockingServer(nil)
		server.closeError = errors.New("secret active close detail")
		var stderr bytes.Buffer
		dependencies := Dependencies{
			Stderr: &stderr,
			Listen: func(context.Context, ListenerConfig) (Server, error) { return server, nil },
		}
		done := make(chan int, 1)
		go func() {
			done <- Execute(ctx, []string{"--allow-platformd-uid", "1"}, AgentdProfile(), dependencies)
		}()
		select {
		case <-server.started:
		case <-time.After(3 * time.Second):
			t.Fatal("server did not start")
		}
		cancel()
		select {
		case exitCode := <-done:
			if exitCode != 1 {
				t.Fatalf("Execute() = %d, want 1", exitCode)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("Execute() did not return after cancellation")
		}
		if !strings.Contains(stderr.String(), "diagnostic control service failed") ||
			strings.Contains(stderr.String(), "secret active close detail") {
			t.Fatalf("stderr = %q", stderr.String())
		}
	})
}

func TestDefaultDependenciesCreatePrivateControlUDSAndRemoveItOnCancel(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "circulusd-ds-")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	socketPath := filepath.Join(root, "agentd.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stderr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- Execute(ctx, []string{
			"--socket", socketPath,
			"--allow-platformctl-uid", strconv.Itoa(os.Geteuid()),
		}, AgentdProfile(), DefaultDependencies(&stderr))
	}()

	deadline := time.Now().Add(3 * time.Second)
	for {
		information, statErr := os.Lstat(socketPath)
		if statErr == nil {
			if information.Mode()&os.ModeSocket == 0 || information.Mode().Perm() != 0o600 {
				t.Fatalf("control endpoint mode = %v", information.Mode())
			}
			client, clientErr := controlrpc.NewClient(controlrpc.ClientConfig{
				SocketPath:         socketPath,
				Peer:               v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL,
				ExpectedServerPeer: v1.ProtocolPeer_PROTOCOL_PEER_AGENTD,
			})
			if clientErr != nil {
				t.Fatalf("NewClient() error = %v", clientErr)
			}
			requestContext, cancelRequest := context.WithTimeout(context.Background(), time.Second)
			response, requestErr := client.GetCapabilities(requestContext)
			cancelRequest()
			_ = client.Close()
			if requestErr != nil {
				t.Fatalf("GetCapabilities() error = %v", requestErr)
			}
			seenRole := false
			for _, capability := range response.GetCapabilities() {
				if capability.GetName() == "daemon.agentd" &&
					capability.GetAvailability() == v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_AVAILABLE {
					seenRole = true
				}
			}
			if !seenRole {
				t.Fatalf("agentd role capability is absent: %+v", response.GetCapabilities())
			}
			break
		}
		if !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("Lstat() error = %v", statErr)
		}
		if time.Now().After(deadline) {
			t.Fatalf("control socket was not created: %s", stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case exitCode := <-done:
		if exitCode != 0 {
			t.Fatalf("Execute() = %d, want 0; stderr=%q", exitCode, stderr.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Execute() did not stop")
	}
	if _, err := os.Lstat(socketPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket remains after cancellation: %v", err)
	}
}

func TestExecuteReportsServeFailureWithoutLeakingDetails(t *testing.T) {
	t.Parallel()

	var stderr bytes.Buffer
	server := newBlockingServer(errors.New("secret serve detail"))
	dependencies := Dependencies{Stderr: &stderr, Listen: func(context.Context, ListenerConfig) (Server, error) {
		return server, nil
	}}
	if exitCode := Execute(context.Background(), []string{"--allow-platformd-uid", "1"}, ExecutordProfile(), dependencies); exitCode != 1 {
		t.Fatalf("Execute() = %d, want 1", exitCode)
	}
	if strings.Contains(stderr.String(), "secret serve detail") {
		t.Fatalf("serve detail leaked: %q", stderr.String())
	}
}

func TestExecuteReportsServeFailureReleasedByCancellationClose(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	server := newCloseReleasedErrorServer(errors.New("secret raced serve detail"))
	var stderr bytes.Buffer
	dependencies := Dependencies{Stderr: &stderr, Listen: func(context.Context, ListenerConfig) (Server, error) {
		return server, nil
	}}
	done := make(chan int, 1)
	go func() {
		done <- Execute(ctx, []string{"--allow-platformd-uid", "1"}, AgentdProfile(), dependencies)
	}()
	select {
	case <-server.started:
	case <-time.After(3 * time.Second):
		t.Fatal("server did not start")
	}
	cancel()
	select {
	case exitCode := <-done:
		if exitCode != 1 {
			t.Fatalf("Execute() = %d, want 1", exitCode)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Execute() did not return after cancellation")
	}
	if server.closeCalls.Load() != 1 {
		t.Fatalf("Close() calls = %d, want 1", server.closeCalls.Load())
	}
	if !strings.Contains(stderr.String(), "diagnostic control service failed") ||
		strings.Contains(stderr.String(), "secret raced serve detail") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

type blockingServer struct {
	started    chan struct{}
	closed     chan struct{}
	closeOnce  sync.Once
	serveError error
	closeError error
	closeCalls atomic.Int64
}

type closeReleasedErrorServer struct {
	started    chan struct{}
	closed     chan struct{}
	closeOnce  sync.Once
	serveError error
	closeCalls atomic.Int64
}

type returningServer struct {
	closeCalls atomic.Int64
	serveCalls atomic.Int64
	closeError error
}

func (server *returningServer) Serve(context.Context) error {
	server.serveCalls.Add(1)
	return nil
}

func (server *returningServer) Close() error {
	server.closeCalls.Add(1)
	return server.closeError
}

func newBlockingServer(serveError error) *blockingServer {
	return &blockingServer{started: make(chan struct{}), closed: make(chan struct{}), serveError: serveError}
}

func newCloseReleasedErrorServer(serveError error) *closeReleasedErrorServer {
	return &closeReleasedErrorServer{
		started:    make(chan struct{}),
		closed:     make(chan struct{}),
		serveError: serveError,
	}
}

func (server *blockingServer) Serve(context.Context) error {
	close(server.started)
	if server.serveError != nil {
		return server.serveError
	}
	<-server.closed
	return nil
}

func (server *blockingServer) Close() error {
	server.closeCalls.Add(1)
	server.closeOnce.Do(func() { close(server.closed) })
	return server.closeError
}

func (server *closeReleasedErrorServer) Serve(context.Context) error {
	close(server.started)
	<-server.closed
	return server.serveError
}

func (server *closeReleasedErrorServer) Close() error {
	server.closeCalls.Add(1)
	server.closeOnce.Do(func() { close(server.closed) })
	return nil
}
