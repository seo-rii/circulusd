//go:build linux

package sandboxrpc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/sandboxd"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

func TestClientReadyAuthenticatesOneSessionConcurrently(t *testing.T) {
	t.Parallel()

	server, client, _ := startTestTransport(t)
	defer server.Close()
	defer client.Close()

	const callers = 64
	results := make(chan error, callers)
	var start sync.WaitGroup
	start.Add(callers)
	for range callers {
		go func() {
			start.Done()
			start.Wait()
			results <- client.Ready(context.Background())
		}()
	}
	for range callers {
		if err := <-results; err != nil {
			t.Fatalf("Ready() error = %v", err)
		}
	}
	server.handler.handshakeMu.Lock()
	nonceUsed := server.handler.nonceUsed
	sessionEstablished := !bytes.Equal(server.handler.session[:], make([]byte, len(server.handler.session)))
	server.handler.handshakeMu.Unlock()
	if !nonceUsed || !sessionEstablished {
		t.Fatal("Ready() did not establish exactly one authenticated server session")
	}
}

func TestClientPinnedEndpointFencesPathnameABA(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	authorityPath := filepath.Join(root, "control.sock")
	decoyPath := filepath.Join(root, "decoy.sock")
	parkedPath := filepath.Join(root, "parked.sock")
	nonce := bytes.Repeat([]byte{0x6b}, handshakeNonceBytes)
	paths := []string{authorityPath, decoyPath}
	servers := make([]*Server, len(paths))
	for index, socketPath := range paths {
		workspace := filepath.Join(root, "workspace-"+string(rune('a'+index)))
		if err := os.Mkdir(workspace, 0o700); err != nil {
			t.Fatal(err)
		}
		supervisor, err := sandboxd.NewSupervisor(sandboxd.Config{
			Authority:         sandboxd.LaunchAuthority{SandboxID: "sandbox-alpha", Generation: 7},
			WorkspaceRoot:     workspace,
			Commands:          map[string]string{"echo": "/bin/echo"},
			Runner:            sandboxd.NewFakeRunner(),
			ReplayLimitBytes:  1 << 20,
			ReplayLimitEvents: 128,
			SubscriberBuffer:  16,
			ReadChunkBytes:    4096,
		})
		if err != nil {
			t.Fatal(err)
		}
		server, err := ListenServer(ServerConfig{
			SocketPath:        socketPath,
			AllowedClientUIDs: []uint32{uint32(os.Geteuid())},
			SandboxID:         []byte("sandbox-alpha"),
			SandboxGeneration: 7,
			OneTimeNonce:      nonce,
			Supervisor:        supervisor,
		})
		if err != nil {
			t.Fatalf("ListenServer(%q) error = %v", socketPath, err)
		}
		servers[index] = server
		serveContext, cancelServe := context.WithCancel(context.Background())
		serveDone := make(chan error, 1)
		go func() { serveDone <- server.Serve(serveContext) }()
		t.Cleanup(func() {
			cancelServe()
			_ = server.Close()
			select {
			case err := <-serveDone:
				if err != nil {
					t.Errorf("Serve(%q) error = %v", socketPath, err)
				}
			case <-time.After(5 * time.Second):
				t.Errorf("Serve(%q) did not stop", socketPath)
			}
		})
	}

	var swaps atomic.Int32
	client, err := newClientWithDependencies(ClientConfig{
		SocketPath:        authorityPath,
		ServerUID:         uint32(os.Geteuid()),
		SandboxID:         []byte("sandbox-alpha"),
		SandboxGeneration: 7,
		OneTimeNonce:      nonce,
	}, -1, clientDependencies{
		dialUnix: func(ctx context.Context, socketPath string) (net.Conn, error) {
			if !swaps.CompareAndSwap(0, 1) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			}
			if err := os.Rename(authorityPath, parkedPath); err != nil {
				return nil, err
			}
			if err := os.Rename(decoyPath, authorityPath); err != nil {
				return nil, errors.Join(err, os.Rename(parkedPath, authorityPath))
			}
			connection, dialErr := (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			restoreErr := errors.Join(
				os.Rename(authorityPath, decoyPath),
				os.Rename(parkedPath, authorityPath),
			)
			if restoreErr != nil {
				_ = connection.Close()
				return nil, errors.Join(dialErr, restoreErr)
			}
			return connection, dialErr
		},
	})
	if err != nil {
		t.Fatalf("newClientWithDependencies() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	readyContext, cancelReady := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelReady()
	if err := client.Ready(readyContext); err != nil {
		t.Fatalf("Ready() error = %v", err)
	}
	if swaps.Load() != 1 {
		t.Fatalf("pathname swaps = %d, want 1", swaps.Load())
	}
	servers[0].handler.handshakeMu.Lock()
	authorityUsed := servers[0].handler.nonceUsed
	servers[0].handler.handshakeMu.Unlock()
	servers[1].handler.handshakeMu.Lock()
	decoyUsed := servers[1].handler.nonceUsed
	servers[1].handler.handshakeMu.Unlock()
	if !authorityUsed || decoyUsed {
		t.Fatalf("authenticated endpoints authority/decoy = %t/%t, want true/false", authorityUsed, decoyUsed)
	}
}

func TestClientPinnedEndpointFailsClosedWhenProcFDDialIsUnavailable(t *testing.T) {
	server, unusedClient, _ := startTestTransport(t)
	if err := unusedClient.Close(); err != nil {
		t.Fatalf("Close(unused client) error = %v", err)
	}
	var dialCalls atomic.Int32
	var dialPath atomic.Value
	client, err := newClientWithDependencies(ClientConfig{
		SocketPath:        server.SocketPath(),
		ServerUID:         uint32(os.Geteuid()),
		SandboxID:         []byte("sandbox-alpha"),
		SandboxGeneration: 7,
		OneTimeNonce:      bytes.Repeat([]byte{0x5a}, handshakeNonceBytes),
	}, -1, clientDependencies{
		dialUnix: func(_ context.Context, socketPath string) (net.Conn, error) {
			dialCalls.Add(1)
			dialPath.Store(socketPath)
			return nil, os.ErrPermission
		},
	})
	if err != nil {
		t.Fatalf("newClientWithDependencies() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Ready(context.Background()); err == nil {
		t.Fatal("Ready() error = nil, want fail-closed procfd dial error")
	}
	if dialCalls.Load() != 1 {
		t.Fatalf("dial calls = %d, want 1 without pathname fallback", dialCalls.Load())
	}
	path, _ := dialPath.Load().(string)
	if !strings.HasPrefix(path, "/proc/self/fd/") {
		t.Fatalf("dial path = %q, want process-owned descriptor path", path)
	}
	server.handler.handshakeMu.Lock()
	nonceUsed := server.handler.nonceUsed
	server.handler.handshakeMu.Unlock()
	if nonceUsed {
		t.Fatal("server consumed the nonce after the pinned endpoint dial failed")
	}
}

func TestClientFromPinnedSocketFDSurvivesPathRenameDuringConstruction(t *testing.T) {
	server, unusedClient, _ := startTestTransport(t)
	if err := unusedClient.Close(); err != nil {
		t.Fatalf("Close(unused client) error = %v", err)
	}
	pinnedFD, err := unix.Open(server.SocketPath(), unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatalf("Open(pinned socket) error = %v", err)
	}
	socketDirectory := filepath.Dir(server.SocketPath())
	parkedDirectory := socketDirectory + ".parked"
	if err := os.Rename(socketDirectory, parkedDirectory); err != nil {
		_ = unix.Close(pinnedFD)
		t.Fatalf("Rename(socket directory) error = %v", err)
	}

	client, err := NewClientFromPinnedSocketFD(ClientConfig{
		SocketPath:        server.SocketPath(),
		ServerUID:         uint32(os.Geteuid()),
		SandboxID:         []byte("sandbox-alpha"),
		SandboxGeneration: 7,
		OneTimeNonce:      bytes.Repeat([]byte{0x5a}, handshakeNonceBytes),
	}, pinnedFD)
	restoreErr := os.Rename(parkedDirectory, socketDirectory)
	closeErr := unix.Close(pinnedFD)
	if restoreErr != nil {
		if client != nil {
			_ = client.Close()
		}
		t.Fatalf("restore socket directory error = %v", restoreErr)
	}
	if err != nil {
		t.Fatalf("NewClientFromPinnedSocketFD(renamed path) error = %v", err)
	}
	if closeErr != nil {
		_ = client.Close()
		t.Fatalf("Close(borrowed socket FD) error = %v", closeErr)
	}
	t.Cleanup(func() { _ = client.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ready(ctx); err != nil {
		t.Fatalf("Ready() through duplicated pinned endpoint error = %v", err)
	}
}

func TestClientCloseKeepsInFlightDialDescriptorAlive(t *testing.T) {
	server, unusedClient, _ := startTestTransport(t)
	if err := unusedClient.Close(); err != nil {
		t.Fatalf("Close(unused client) error = %v", err)
	}
	dialEntered := make(chan string, 1)
	releaseDial := make(chan struct{})
	defer func() {
		select {
		case <-releaseDial:
		default:
			close(releaseDial)
		}
	}()
	dialError := errors.New("dial released")
	client, err := newClientWithDependencies(ClientConfig{
		SocketPath:        server.SocketPath(),
		ServerUID:         uint32(os.Geteuid()),
		SandboxID:         []byte("sandbox-alpha"),
		SandboxGeneration: 7,
		OneTimeNonce:      bytes.Repeat([]byte{0x5a}, handshakeNonceBytes),
	}, -1, clientDependencies{
		dialUnix: func(_ context.Context, socketPath string) (net.Conn, error) {
			dialEntered <- socketPath
			<-releaseDial
			return nil, dialError
		},
	})
	if err != nil {
		t.Fatalf("newClientWithDependencies() error = %v", err)
	}
	dialResult := make(chan error, 1)
	go func() {
		_, dialErr := client.dialContext(context.Background(), "", "")
		dialResult <- dialErr
	}()
	var descriptorPath string
	select {
	case descriptorPath = <-dialEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("dial did not duplicate the pinned endpoint")
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, err := os.Stat(descriptorPath); err != nil {
		t.Fatalf("in-flight dial descriptor was closed early: %v", err)
	}
	close(releaseDial)
	if err := <-dialResult; !errors.Is(err, dialError) {
		t.Fatalf("dial error = %v, want injected error", err)
	}
}

func TestClientReadyRejectsInvalidLifecycleWithoutBurningPreCancelledNonce(t *testing.T) {
	t.Parallel()

	var nilClient *Client
	if err := nilClient.Ready(context.Background()); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("nil Ready() error = %v", err)
	}

	server, client, _ := startTestTransport(t)
	defer server.Close()
	if err := client.Ready(nil); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("nil-context Ready() error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := client.Ready(cancelled); !errors.Is(err, context.Canceled) && connect.CodeOf(err) != connect.CodeCanceled {
		t.Fatalf("cancelled Ready() error = %v", err)
	}
	if err := client.Ready(context.Background()); err != nil {
		t.Fatalf("Ready() after pre-cancellation error = %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := client.Ready(context.Background()); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("Ready() after Close error = %v", err)
	}
}

func TestPrivateTransportProcessLifecycleAndConcurrentIdempotency(t *testing.T) {
	t.Parallel()

	server, client, runner := startTestTransport(t)
	defer server.Close()
	defer client.Close()

	request := validSpawnRequest("spawn-once", "invocation-00001")
	const callers = 16
	responses := make(chan *v1.SpawnProcessResponse, callers)
	errorsSeen := make(chan error, callers)
	var start sync.WaitGroup
	start.Add(callers)
	for range callers {
		go func() {
			start.Done()
			start.Wait()
			response, err := client.Spawn(context.Background(), request)
			if err != nil {
				errorsSeen <- err
				return
			}
			responses <- response
		}()
	}

	var handle *v1.ProcessHandle
	for range callers {
		select {
		case err := <-errorsSeen:
			t.Fatalf("concurrent Spawn() error = %v", err)
		case response := <-responses:
			if handle == nil {
				handle = response.GetProcess()
			}
			if !proto.Equal(handle, response.GetProcess()) {
				t.Fatalf("concurrent Spawn() handle differs: %v vs %v", handle, response.GetProcess())
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for concurrent Spawn()")
		}
	}
	if got := runner.StartCount(); got != 1 {
		t.Fatalf("runner starts = %d, want 1", got)
	}
	process := nextFakeProcess(t, runner)
	resolved := process.Spec()
	if resolved.ExecutablePath != "/bin/echo" || resolved.WorkingDirectory != testWorkspaceRoot(t, server) {
		t.Fatalf("trusted RunSpec = %#v", resolved)
	}

	write := &v1.WriteStdinRequest{
		Meta:          idempotentMeta("stdin-0000000001"),
		Process:       proto.Clone(handle).(*v1.ProcessHandle),
		ChunkSequence: 1,
		Data:          []byte("hello"),
	}
	firstWrite, err := client.WriteStdin(context.Background(), write)
	if err != nil {
		t.Fatalf("WriteStdin() error = %v", err)
	}
	secondWrite, err := client.WriteStdin(context.Background(), write)
	if err != nil {
		t.Fatalf("retry WriteStdin() error = %v", err)
	}
	if firstWrite.GetAcceptedSequence() != 1 || secondWrite.GetAcceptedSequence() != 1 ||
		!bytes.Equal(process.StdinBytes(), []byte("hello")) {
		t.Fatalf("idempotent stdin responses = (%v, %v), bytes = %q", firstWrite, secondWrite, process.StdinBytes())
	}

	closed, err := client.CloseStdin(context.Background(), &v1.CloseStdinRequest{
		Meta:    idempotentMeta("close-stdin-0001"),
		Process: proto.Clone(handle).(*v1.ProcessHandle),
	})
	if err != nil || !closed.GetClosed() {
		t.Fatalf("CloseStdin() = (%v, %v)", closed, err)
	}
	process.Complete(sandboxd.RunResult{ExitCode: 0})
	waited, err := client.Wait(context.Background(), &v1.WaitProcessRequest{
		Meta:    idempotentMeta("wait-process-001"),
		Process: proto.Clone(handle).(*v1.ProcessHandle),
	})
	if err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	if waited.GetState() != v1.ProcessLifecycleState_PROCESS_LIFECYCLE_STATE_EXITED || waited.GetResult().GetExitCode() != 0 {
		t.Fatalf("Wait() = %v", waited)
	}

	secondSpawn, err := client.Spawn(context.Background(), validSpawnRequest("spawn-cancel", "invocation-00002"))
	if err != nil {
		t.Fatalf("second Spawn() error = %v", err)
	}
	secondProcess := nextFakeProcess(t, runner)
	signaled, err := client.Signal(context.Background(), &v1.SignalProcessRequest{
		Meta:    idempotentMeta("signal-process01"),
		Process: secondSpawn.GetProcess(),
		Signal:  v1.ProcessSignal_PROCESS_SIGNAL_INTERRUPT,
	})
	if err != nil || !signaled.GetDelivered() {
		t.Fatalf("Signal() = (%v, %v)", signaled, err)
	}
	cancelled, err := client.Cancel(context.Background(), &v1.CancelProcessRequest{
		Meta:    idempotentMeta("cancel-process01"),
		Process: secondSpawn.GetProcess(),
		Reason:  "caller cancelled",
	})
	if err != nil || !cancelled.GetProcessGroupTerminationStarted() {
		t.Fatalf("Cancel() = (%v, %v)", cancelled, err)
	}
	if got := secondProcess.Signals(); len(got) != 2 || got[0] != sandboxd.SignalInterrupt || got[1] != sandboxd.SignalCancel {
		t.Fatalf("process-group signals = %v", got)
	}
}

func TestClientAttachStreamsAndReplaysOrderedProcessEvents(t *testing.T) {
	t.Parallel()

	server, client, runner := startTestTransport(t)
	defer server.Close()
	defer client.Close()

	spawned, err := client.Spawn(context.Background(), validSpawnRequest("attach-spawn-001", "attach-invocat01"))
	if err != nil {
		t.Fatalf("Spawn() error = %v", err)
	}
	process := nextFakeProcess(t, runner)
	stream, err := client.Attach(context.Background(), &v1.AttachProcessRequest{
		Meta:    idempotentMeta("attach-stream-01"),
		Process: proto.Clone(spawned.GetProcess()).(*v1.ProcessHandle),
	})
	if err != nil {
		t.Fatalf("Attach() error = %v", err)
	}
	defer stream.Close()

	received := make([]*v1.ProcessEvent, 0, 4)
	if !stream.Receive() {
		t.Fatalf("Receive(sequence 1) = false, error = %v", stream.Err())
	}
	startedEvent := stream.Msg()
	received = append(received, startedEvent)
	if started := startedEvent.GetStarted(); startedEvent.GetSequence() != 1 ||
		!proto.Equal(startedEvent.GetProcess(), spawned.GetProcess()) || started == nil || started.GetStartedAtUnixMs() == 0 {
		t.Fatalf("started event = %v", startedEvent)
	}
	if err := process.EmitStdout([]byte("out")); err != nil {
		t.Fatalf("EmitStdout() error = %v", err)
	}
	if !stream.Receive() {
		t.Fatalf("Receive(sequence 2) = false, error = %v", stream.Err())
	}
	stdoutEvent := stream.Msg()
	received = append(received, stdoutEvent)
	if stdout := stdoutEvent.GetStdout(); stdoutEvent.GetSequence() != 2 ||
		!proto.Equal(stdoutEvent.GetProcess(), spawned.GetProcess()) || stdout == nil ||
		string(stdout.GetData()) != "out" || stdout.GetTruncated() {
		t.Fatalf("stdout event = %v", stdoutEvent)
	}
	if err := process.EmitStderr([]byte("err")); err != nil {
		t.Fatalf("EmitStderr() error = %v", err)
	}
	if !stream.Receive() {
		t.Fatalf("Receive(sequence 3) = false, error = %v", stream.Err())
	}
	stderrEvent := stream.Msg()
	received = append(received, stderrEvent)
	if stderr := stderrEvent.GetStderr(); stderrEvent.GetSequence() != 3 ||
		!proto.Equal(stderrEvent.GetProcess(), spawned.GetProcess()) || stderr == nil ||
		string(stderr.GetData()) != "err" || stderr.GetTruncated() {
		t.Fatalf("stderr event = %v", stderrEvent)
	}
	process.Complete(sandboxd.RunResult{ExitCode: 23})
	if !stream.Receive() {
		t.Fatalf("Receive(sequence 4) = false, error = %v", stream.Err())
	}
	exitEvent := stream.Msg()
	received = append(received, exitEvent)
	if exited := exitEvent.GetExit(); exitEvent.GetSequence() != 4 ||
		!proto.Equal(exitEvent.GetProcess(), spawned.GetProcess()) || exited == nil ||
		exited.GetExitCode() != 23 || exited.GetFinishedAtUnixMs() == 0 {
		t.Fatalf("exit event = %v", exitEvent)
	}
	if stream.Receive() || stream.Err() != nil {
		t.Fatalf("terminal Receive() = true or error = %v", stream.Err())
	}
	waited, err := client.Wait(context.Background(), &v1.WaitProcessRequest{
		Meta:    idempotentMeta("attach-wait-0001"),
		Process: proto.Clone(spawned.GetProcess()).(*v1.ProcessHandle),
	})
	if err != nil || !proto.Equal(waited.GetResult(), exitEvent.GetExit()) {
		t.Fatalf("Wait() = (%v, %v), want streamed terminal result %v", waited, err, exitEvent.GetExit())
	}

	replay, err := client.Attach(context.Background(), &v1.AttachProcessRequest{
		Meta:          idempotentMeta("attach-replay-01"),
		Process:       proto.Clone(spawned.GetProcess()).(*v1.ProcessHandle),
		AfterSequence: 1,
	})
	if err != nil {
		t.Fatalf("Attach(replay) error = %v", err)
	}
	defer replay.Close()
	for index := 1; index < len(received); index++ {
		if !replay.Receive() {
			t.Fatalf("replay Receive(%d) = false, error = %v", index, replay.Err())
		}
		if event := replay.Msg(); !proto.Equal(event, received[index]) {
			t.Fatalf("replay event = %v, want %v", event, received[index])
		}
	}
	if replay.Receive() || replay.Err() != nil {
		t.Fatalf("terminal replay Receive() = true or error = %v", replay.Err())
	}

	invalid, err := client.Attach(context.Background(), &v1.AttachProcessRequest{
		Meta:          idempotentMeta("attach-future-01"),
		Process:       proto.Clone(spawned.GetProcess()).(*v1.ProcessHandle),
		AfterSequence: 5,
	})
	if err != nil {
		t.Fatalf("Attach(future cursor) construction error = %v", err)
	}
	defer invalid.Close()
	if invalid.Receive() || connect.CodeOf(invalid.Err()) != connect.CodeInvalidArgument {
		t.Fatalf("future cursor Receive() = true or error = %v", invalid.Err())
	}
}

func TestPrivateTransportFailsClosedAtWireBoundary(t *testing.T) {
	t.Parallel()

	server, client, runner := startTestTransport(t)
	defer server.Close()
	defer client.Close()

	invalidCases := []struct {
		name   string
		mutate func(*v1.SpawnProcessRequest)
	}{
		{name: "host executable path", mutate: func(request *v1.SpawnProcessRequest) { request.Executable = "/bin/sh" }},
		{name: "host working path", mutate: func(request *v1.SpawnProcessRequest) { request.WorkingDirectory = "/tmp" }},
		{name: "raw secret handle", mutate: func(request *v1.SpawnProcessRequest) {
			request.EnvironmentHandles = []*v1.SecretHandle{{Value: []byte("secret")}}
		}},
		{name: "stale generation", mutate: func(request *v1.SpawnProcessRequest) { request.Sandbox.Generation++ }},
		{name: "unknown protocol field", mutate: func(request *v1.SpawnProcessRequest) {
			request.ProtoReflect().SetUnknown([]byte{0xf8, 0x07, 0x01})
		}},
	}
	for index, test := range invalidCases {
		t.Run(test.name, func(t *testing.T) {
			request := validSpawnRequest("invalid-spawn-"+string(rune('a'+index)), "invalid-invoc-01")
			test.mutate(request)
			_, err := client.Spawn(context.Background(), request)
			if got := connect.CodeOf(err); got != connect.CodeInvalidArgument && got != connect.CodeFailedPrecondition {
				t.Fatalf("Spawn() code = %v error = %v", got, err)
			}
		})
	}
	if runner.StartCount() != 0 {
		t.Fatalf("invalid requests started %d processes", runner.StartCount())
	}

	request := validSpawnRequest("valid-spawn-0001", "valid-invocat-01")
	if _, err := client.Spawn(context.Background(), request); err != nil {
		t.Fatalf("valid Spawn() error = %v", err)
	}
	process := nextFakeProcess(t, runner)
	process.Complete(sandboxd.RunResult{ExitCode: 0})

	// The launch capability nonce is consumed by the first client's handshake.
	second, err := NewClient(ClientConfig{
		SocketPath:        server.SocketPath(),
		ServerUID:         uint32(os.Geteuid()),
		SandboxID:         []byte("sandbox-alpha"),
		SandboxGeneration: 7,
		OneTimeNonce:      bytes.Repeat([]byte{0x5a}, 32),
	})
	if err != nil {
		t.Fatalf("NewClient(second) error = %v", err)
	}
	defer second.Close()
	_, err = second.Wait(context.Background(), &v1.WaitProcessRequest{
		Meta:    idempotentMeta("second-client-001"),
		Process: &v1.ProcessHandle{},
	})
	if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
		t.Fatalf("second one-time handshake code = %v error = %v", got, err)
	}
}

func TestServerRequiresPrivateSocketDirectory(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	supervisor, err := sandboxd.NewSupervisor(sandboxd.Config{
		Authority:         sandboxd.LaunchAuthority{SandboxID: "sandbox-alpha", Generation: 7},
		WorkspaceRoot:     root,
		Commands:          map[string]string{"echo": "/bin/echo"},
		Runner:            sandboxd.NewFakeRunner(),
		ReplayLimitBytes:  1 << 20,
		ReplayLimitEvents: 128,
		SubscriberBuffer:  16,
		ReadChunkBytes:    4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ListenServer(ServerConfig{
		SocketPath:        filepath.Join(root, "control.sock"),
		AllowedClientUIDs: []uint32{uint32(os.Geteuid())},
		SandboxID:         []byte("sandbox-alpha"),
		SandboxGeneration: 7,
		OneTimeNonce:      bytes.Repeat([]byte{0x5a}, 32),
		Supervisor:        supervisor,
	})
	if err == nil {
		t.Fatal("ListenServer() succeeded with a non-private socket directory")
	}
}

func TestServerRejectsSupervisorLaunchAuthorityMismatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		authority sandboxd.LaunchAuthority
	}{
		{
			name:      "sandbox identity",
			authority: sandboxd.LaunchAuthority{SandboxID: "sandbox-other", Generation: 7},
		},
		{
			name:      "sandbox generation",
			authority: sandboxd.LaunchAuthority{SandboxID: "sandbox-alpha", Generation: 8},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			root := t.TempDir()
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}
			supervisor, err := sandboxd.NewSupervisor(sandboxd.Config{
				Authority:         test.authority,
				WorkspaceRoot:     root,
				Commands:          map[string]string{"echo": "/bin/echo"},
				Runner:            sandboxd.NewFakeRunner(),
				ReplayLimitBytes:  1 << 20,
				ReplayLimitEvents: 128,
				SubscriberBuffer:  16,
				ReadChunkBytes:    4096,
			})
			if err != nil {
				t.Fatal(err)
			}
			server, err := ListenServer(ServerConfig{
				SocketPath:        filepath.Join(root, "control.sock"),
				AllowedClientUIDs: []uint32{uint32(os.Geteuid())},
				SandboxID:         []byte("sandbox-alpha"),
				SandboxGeneration: 7,
				OneTimeNonce:      bytes.Repeat([]byte{0x5a}, 32),
				Supervisor:        supervisor,
			})
			if server != nil {
				_ = server.Close()
			}
			if err == nil {
				t.Fatal("ListenServer() accepted a supervisor with different launch authority")
			}
		})
	}
}

func TestHandshakeRequiresFixedFrameWithoutConsumingNonce(t *testing.T) {
	t.Parallel()

	server, client, runner := startTestTransport(t)
	defer server.Close()
	defer client.Close()
	oversized := connect.NewRequest(&v1.HandshakeRequest{
		Peer:              v1.ProtocolPeer_PROTOCOL_PEER_EXECUTORD,
		MinimumVersion:    protocolVersion(),
		MaximumVersion:    protocolVersion(),
		MaximumFrameSize:  maximumMessageBytes + 1,
		DescriptorDigest:  descriptorDigest(),
		OneTimeNonce:      bytes.Repeat([]byte{0x5a}, 32),
		SandboxId:         &v1.OpaqueId{Value: []byte("sandbox-alpha")},
		SandboxGeneration: 7,
	})
	_, err := client.control.Handshake(context.Background(), oversized)
	if got := connect.CodeOf(err); got != connect.CodeFailedPrecondition {
		t.Fatalf("oversized handshake code = %v error = %v", got, err)
	}

	response, err := client.Spawn(context.Background(), validSpawnRequest("fixed-frame-spawn", "fixed-frame-inv"))
	if err != nil {
		t.Fatalf("Spawn() after rejected negotiation error = %v", err)
	}
	if response.GetProcess() == nil {
		t.Fatal("Spawn() returned no process")
	}
	process := nextFakeProcess(t, runner)
	process.Complete(sandboxd.RunResult{ExitCode: 0})
}

func TestRequestDigestAndIdempotencyConflictFailClosed(t *testing.T) {
	t.Parallel()

	server, client, runner := startTestTransport(t)
	defer server.Close()
	defer client.Close()
	session, err := client.ensureHandshake(context.Background())
	if err != nil {
		t.Fatalf("ensureHandshake() error = %v", err)
	}
	prepared, _, err := prepareRequest(context.Background(), validSpawnRequest("tampered-digest", "tampered-invocat"))
	if err != nil {
		t.Fatalf("prepareRequest() error = %v", err)
	}
	tampered := prepared.(*v1.SpawnProcessRequest)
	tampered.Meta.RequestDigest.Value[0] ^= 0xff
	raw := connect.NewRequest(tampered)
	raw.Header().Set(sessionHeader, session)
	if _, err := client.process.Spawn(context.Background(), raw); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("tampered request digest error = %v", err)
	}
	if runner.StartCount() != 0 {
		t.Fatalf("tampered request started %d processes", runner.StartCount())
	}

	request := validSpawnRequest("conflicting-key", "conflict-invocat")
	if _, err := client.Spawn(context.Background(), request); err != nil {
		t.Fatalf("first Spawn() error = %v", err)
	}
	process := nextFakeProcess(t, runner)
	changed := proto.Clone(request).(*v1.SpawnProcessRequest)
	changed.Arguments = []string{"changed"}
	if _, err := client.Spawn(context.Background(), changed); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("conflicting idempotency key error = %v", err)
	}
	if runner.StartCount() != 1 {
		t.Fatalf("conflicting retry started %d processes", runner.StartCount())
	}
	process.Complete(sandboxd.RunResult{ExitCode: 0})
}

func startTestTransport(t *testing.T) (*Server, *Client, *sandboxd.FakeRunner) {
	t.Helper()
	root, err := os.MkdirTemp("", "circulusd-srpc-")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Errorf("RemoveAll(%q) error = %v", root, err)
		}
	})
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	workspace := filepath.Join(root, "workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	runner := sandboxd.NewFakeRunner()
	supervisor, err := sandboxd.NewSupervisor(sandboxd.Config{
		Authority:         sandboxd.LaunchAuthority{SandboxID: "sandbox-alpha", Generation: 7},
		WorkspaceRoot:     workspace,
		Commands:          map[string]string{"echo": "/bin/echo"},
		Runner:            runner,
		ReplayLimitBytes:  1 << 20,
		ReplayLimitEvents: 128,
		SubscriberBuffer:  16,
		ReadChunkBytes:    4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{0x5a}, 32)
	server, err := ListenServer(ServerConfig{
		SocketPath:        filepath.Join(root, "control.sock"),
		AllowedClientUIDs: []uint32{uint32(os.Geteuid())},
		SandboxID:         []byte("sandbox-alpha"),
		SandboxGeneration: 7,
		OneTimeNonce:      nonce,
		Supervisor:        supervisor,
	})
	if err != nil {
		t.Fatalf("ListenServer() error = %v", err)
	}
	serveContext, cancelServe := context.WithCancel(context.Background())
	t.Cleanup(cancelServe)
	go func() {
		if err := server.Serve(serveContext); err != nil {
			t.Errorf("Serve() error = %v", err)
		}
	}()
	client, err := NewClient(ClientConfig{
		SocketPath:        server.SocketPath(),
		ServerUID:         uint32(os.Geteuid()),
		SandboxID:         []byte("sandbox-alpha"),
		SandboxGeneration: 7,
		OneTimeNonce:      nonce,
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return server, client, runner
}

func validSpawnRequest(idempotencyKey, invocationID string) *v1.SpawnProcessRequest {
	digest := sha256.Sum256([]byte("authorized execution request"))
	invocation := &v1.OpaqueId{Value: []byte(invocationID)}
	return &v1.SpawnProcessRequest{
		Meta:                idempotentMeta(idempotencyKey),
		DispatchPermit:      &v1.DispatchPermit{Value: []byte("opaque-dispatch-permit")},
		Sandbox:             &v1.SandboxHandle{SandboxId: &v1.OpaqueId{Value: []byte("sandbox-alpha")}, Generation: 7},
		WorkspaceProtection: &v1.WorkspaceProtectionPermit{Value: []byte("opaque-workspace-permit")},
		InvocationId:        invocation,
		RequestDigest:       &v1.Digest{Algorithm: v1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: digest[:]},
		Executable:          "echo",
		Arguments:           []string{"hello"},
		WorkingDirectory:    "",
		TimeoutMs:           5_000,
		OutputLimitBytes:    1 << 20,
		StdinMode:           v1.StdinMode_STDIN_MODE_STREAM,
	}
}

func idempotentMeta(key string) *v1.RpcRequestMeta {
	digest := sha256.Sum256([]byte(key))
	return &v1.RpcRequestMeta{IdempotencyKey: append([]byte(nil), digest[:16]...)}
}

func nextFakeProcess(t *testing.T, runner *sandboxd.FakeRunner) *sandboxd.FakeProcess {
	t.Helper()
	select {
	case process := <-runner.Started():
		return process
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for fake process")
		return nil
	}
}

func testWorkspaceRoot(t *testing.T, server *Server) string {
	t.Helper()
	return filepath.Join(filepath.Dir(server.SocketPath()), "workspace")
}

func TestClientRejectsNilAndCancelledCalls(t *testing.T) {
	t.Parallel()

	server, client, _ := startTestTransport(t)
	defer server.Close()
	defer client.Close()
	if _, err := client.Spawn(context.Background(), nil); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("Spawn(nil) error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := client.Spawn(ctx, validSpawnRequest("cancelled-call01", "cancelled-invoc"))
	if !errors.Is(err, context.Canceled) && connect.CodeOf(err) != connect.CodeCanceled {
		t.Fatalf("Spawn(cancelled) error = %v", err)
	}
}
