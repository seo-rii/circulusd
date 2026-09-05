//go:build linux

package sandboxrpc

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	v1connect "github.com/hancomac/circulusd/api/generated/circulus/v1alpha/circulusv1alphaconnect"
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

func TestSandboxServerBoundsWholeIOAndRejectsGeneralOptions(t *testing.T) {
	server, client, _ := startTestTransport(t)
	defer server.Close()
	defer client.Close()
	if server.httpServer.ReadTimeout != 5*time.Second {
		t.Fatalf("ReadTimeout = %s, want 5s", server.httpServer.ReadTimeout)
	}
	if server.httpServer.WriteTimeout != maximumRPCDeadline+sandboxHTTPIOTimeout {
		t.Fatalf("WriteTimeout = %s, want bounded long-lived RPC horizon", server.httpServer.WriteTimeout)
	}
	if !server.httpServer.DisableGeneralOptionsHandler {
		t.Fatal("general OPTIONS handler is enabled outside the Connect RPC routes")
	}

	connection, err := net.DialTimeout("unix", server.SocketPath(), time.Second)
	if err != nil {
		t.Fatalf("dial sandbox socket: %v", err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set connection deadline: %v", err)
	}
	if _, err := connection.Write([]byte(
		"OPTIONS * HTTP/1.1\r\nHost: sandbox.invalid\r\nConnection: close\r\n\r\n",
	)); err != nil {
		t.Fatalf("write OPTIONS request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodOptions})
	if err != nil {
		t.Fatalf("read OPTIONS response: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 400 || response.StatusCode >= 500 {
		t.Fatalf("OPTIONS * status = %d, want a 4xx rejection", response.StatusCode)
	}
}

func TestServerCloseCachesCleanupError(t *testing.T) {
	closeFailure := errors.New("sandbox listener cleanup failed")
	listener := newFailingCloseListener(closeFailure)
	server := &Server{
		listener:   listener,
		httpServer: &http.Server{},
		handler:    &rpcHandler{},
	}

	if err := server.Close(); !errors.Is(err, closeFailure) {
		t.Fatalf("first Close() error = %v, want cleanup failure", err)
	}
	if err := server.Close(); !errors.Is(err, closeFailure) {
		t.Fatalf("second Close() error = %v, want cached cleanup failure", err)
	}
}

func TestServerServeReturnsCancellationCleanupError(t *testing.T) {
	closeFailure := errors.New("sandbox cancellation cleanup failed")
	listener := newFailingCloseListener(closeFailure)
	server := &Server{
		listener:   listener,
		httpServer: &http.Server{},
		handler:    &rpcHandler{},
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- server.Serve(ctx)
	}()
	select {
	case <-listener.accepting:
	case <-time.After(time.Second):
		t.Fatal("Serve() did not begin accepting")
	}
	cancel()
	select {
	case err := <-serveDone:
		if !errors.Is(err, closeFailure) {
			t.Fatalf("Serve() error = %v, want cleanup failure", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve() did not return after cancellation")
	}
}

func TestSandboxRPCRejectsWrongDaemonPeerAndBindsNonceProof(t *testing.T) {
	server, client, _ := startTestTransport(t)
	defer server.Close()
	defer client.Close()

	client.control = wrongPeerSandboxControlClient{}
	err := client.Ready(context.Background())
	if got := connect.CodeOf(err); got != connect.CodeDataLoss {
		t.Fatalf("Ready(wrong daemon) code = %v error=%v, want data_loss", got, err)
	}

	nonce := bytes.Repeat([]byte{0xa5}, handshakeNonceBytes)
	sandboxdProof := nonceProof(nonce, []byte("sandbox-alpha"), 7, v1.ProtocolPeer_PROTOCOL_PEER_SANDBOXD)
	executordProof := nonceProof(nonce, []byte("sandbox-alpha"), 7, v1.ProtocolPeer_PROTOCOL_PEER_EXECUTORD)
	if bytes.Equal(sandboxdProof, executordProof) {
		t.Fatal("sandbox nonce proof is not bound to the authenticated server peer")
	}
}

func TestSandboxServerRejectsDisallowedUDSPeerUID(t *testing.T) {
	root, err := os.MkdirTemp("", "circulusd-srpc-uid-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	workspace := filepath.Join(root, "workspace")
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
	nonce := bytes.Repeat([]byte{0x5a}, handshakeNonceBytes)
	server, err := ListenServer(ServerConfig{
		SocketPath:                 filepath.Join(root, "control.sock"),
		AllowedClientUIDs:          []uint32{uint32(os.Getuid()) + 1},
		SandboxID:                  []byte("sandbox-alpha"),
		SandboxGeneration:          7,
		Backend:                    v1.ExecutionBackend_EXECUTION_BACKEND_NSJAIL,
		ExecutionEnvironmentDigest: testExecutionEnvironmentDigest(),
		OneTimeNonce:               nonce,
		Supervisor:                 supervisor,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() { _ = server.Serve(context.Background()) }()
	client, err := NewClient(ClientConfig{
		SocketPath:        server.SocketPath(),
		ServerUID:         uint32(os.Geteuid()),
		SandboxID:         []byte("sandbox-alpha"),
		SandboxGeneration: 7,
		OneTimeNonce:      nonce,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := client.Ready(ctx); err == nil {
		t.Fatal("Ready() from disallowed UDS peer UID succeeded")
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
			SocketPath:                 socketPath,
			AllowedClientUIDs:          []uint32{uint32(os.Geteuid())},
			SandboxID:                  []byte("sandbox-alpha"),
			SandboxGeneration:          7,
			Backend:                    v1.ExecutionBackend_EXECUTION_BACKEND_NSJAIL,
			ExecutionEnvironmentDigest: testExecutionEnvironmentDigest(),
			OneTimeNonce:               nonce,
			Supervisor:                 supervisor,
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

func TestSpawnRejectsForgedServiceAuthorityBeforeExecution(t *testing.T) {
	t.Parallel()

	server, client, runner := startTestTransport(t)
	defer server.Close()
	defer client.Close()

	tests := []struct {
		name   string
		mutate func(*v1.SpawnProcessRequest)
	}{
		{name: "wrong service", mutate: func(request *v1.SpawnProcessRequest) {
			request.DispatchPermit.Service = v1.EffectService_EFFECT_SERVICE_MODEL
		}},
		{name: "wrong operation", mutate: func(request *v1.SpawnProcessRequest) {
			request.DispatchPermit.Operation = "executor.retry"
		}},
		{name: "unspecified replay policy", mutate: func(request *v1.SpawnProcessRequest) {
			request.DispatchPermit.ReplayPolicy = v1.ReplayPolicy_REPLAY_POLICY_UNSPECIFIED
		}},
		{name: "unknown replay policy", mutate: func(request *v1.SpawnProcessRequest) {
			request.DispatchPermit.ReplayPolicy = v1.ReplayPolicy(99)
		}},
		{name: "malformed parent operation", mutate: func(request *v1.SpawnProcessRequest) {
			request.DispatchPermit.ParentOperationId.Value = nil
		}},
		{name: "orphan ordinal", mutate: func(request *v1.SpawnProcessRequest) {
			request.DispatchPermit.ParentOperationId = nil
			request.DispatchPermit.Ordinal = 1
		}},
		{name: "dispatch invocation", mutate: func(request *v1.SpawnProcessRequest) {
			request.DispatchPermit.InvocationId.Value = []byte("other-invocation")
		}},
		{name: "dispatch request digest", mutate: func(request *v1.SpawnProcessRequest) {
			request.DispatchPermit.RequestDigest.Value[0] ^= 0xff
		}},
		{name: "workspace invocation", mutate: func(request *v1.SpawnProcessRequest) {
			request.WorkspaceProtection.InvocationId.Value = []byte("other-invocation")
		}},
		{name: "workspace request digest", mutate: func(request *v1.SpawnProcessRequest) {
			request.WorkspaceProtection.RequestDigest.Value[0] ^= 0xff
		}},
		{name: "tenant", mutate: func(request *v1.SpawnProcessRequest) {
			request.WorkspaceProtection.TenantId.Value = []byte("other-tenant")
		}},
		{name: "user", mutate: func(request *v1.SpawnProcessRequest) {
			request.WorkspaceProtection.UserId.Value = []byte("other-user")
		}},
		{name: "session", mutate: func(request *v1.SpawnProcessRequest) {
			request.WorkspaceProtection.SessionId.Value = []byte("other-session")
		}},
		{name: "effect", mutate: func(request *v1.SpawnProcessRequest) {
			request.WorkspaceProtection.EffectId.Value = []byte("other-effect")
		}},
		{name: "dispatch attempt", mutate: func(request *v1.SpawnProcessRequest) {
			request.WorkspaceProtection.DispatchAttempt++
		}},
		{name: "turn lease generation", mutate: func(request *v1.SpawnProcessRequest) {
			request.WorkspaceProtection.TurnLeaseGeneration++
		}},
		{name: "placement generation", mutate: func(request *v1.SpawnProcessRequest) {
			request.WorkspaceProtection.PlacementGeneration++
		}},
		{name: "authorization generation", mutate: func(request *v1.SpawnProcessRequest) {
			request.WorkspaceProtection.AuthorizationGeneration++
		}},
		{name: "sandbox identity", mutate: func(request *v1.SpawnProcessRequest) {
			request.WorkspaceProtection.SandboxId.Value = []byte("other-sandbox")
		}},
		{name: "sandbox generation", mutate: func(request *v1.SpawnProcessRequest) {
			request.WorkspaceProtection.SandboxGeneration++
		}},
		{name: "dispatch sandbox generation", mutate: func(request *v1.SpawnProcessRequest) {
			request.DispatchPermit.SandboxGeneration++
		}},
		{name: "backend", mutate: func(request *v1.SpawnProcessRequest) {
			request.WorkspaceProtection.Backend = v1.ExecutionBackend_EXECUTION_BACKEND_DOCKER
		}},
		{name: "launch backend", mutate: func(request *v1.SpawnProcessRequest) {
			request.Sandbox.Backend = v1.ExecutionBackend_EXECUTION_BACKEND_DOCKER
			request.WorkspaceProtection.Backend = v1.ExecutionBackend_EXECUTION_BACKEND_DOCKER
		}},
		{name: "execution environment", mutate: func(request *v1.SpawnProcessRequest) {
			request.Sandbox.ExecutionEnvironmentDigest.Value[0] ^= 0xff
		}},
		{name: "read-write lease identity", mutate: func(request *v1.SpawnProcessRequest) {
			request.WorkspaceProtection.LeaseId = nil
		}},
		{name: "read-write lease generation", mutate: func(request *v1.SpawnProcessRequest) {
			request.WorkspaceProtection.LeaseGeneration = 0
		}},
		{name: "read-write enqueue sequence", mutate: func(request *v1.SpawnProcessRequest) {
			request.WorkspaceProtection.EnqueueSequence = 0
		}},
		{name: "future workspace authority", mutate: func(request *v1.SpawnProcessRequest) {
			request.WorkspaceProtection.IssuedAtUnixMs = uint64(time.Now().Add(time.Minute).UnixMilli())
		}},
		{name: "non-canonical dispatch deadline", mutate: func(request *v1.SpawnProcessRequest) {
			request.DispatchPermit.DeadlineUnixMs = ^uint64(0)
		}},
		{name: "non-canonical workspace deadline", mutate: func(request *v1.SpawnProcessRequest) {
			request.WorkspaceProtection.ExpiresAtUnixMs = ^uint64(0)
			request.WorkspaceProtection.MaximumHoldDeadlineUnixMs = ^uint64(0)
		}},
		{name: "workspace expiry beyond maximum hold", mutate: func(request *v1.SpawnProcessRequest) {
			request.WorkspaceProtection.MaximumHoldDeadlineUnixMs = uint64(time.Now().Add(time.Minute).UnixMilli())
		}},
		{name: "expired dispatch authority", mutate: func(request *v1.SpawnProcessRequest) {
			request.DispatchPermit.DeadlineUnixMs = uint64(time.Now().Add(-time.Second).UnixMilli())
		}},
		{name: "expired workspace authority", mutate: func(request *v1.SpawnProcessRequest) {
			request.WorkspaceProtection.ExpiresAtUnixMs = uint64(time.Now().Add(-time.Second).UnixMilli())
		}},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := validSpawnRequest("forged-authority-"+string(rune('a'+index)), "authority-invoc")
			test.mutate(request)
			_, err := client.Spawn(context.Background(), request)
			if got := connect.CodeOf(err); got != connect.CodeFailedPrecondition {
				t.Fatalf("Spawn() code = %v error=%v, want failed_precondition", got, err)
			}
		})
	}
	if runner.StartCount() != 0 {
		t.Fatalf("forged authorities started %d processes", runner.StartCount())
	}

	validCases := []struct {
		name   string
		mutate func(*v1.SpawnProcessRequest)
	}{
		{name: "top-level effect", mutate: func(request *v1.SpawnProcessRequest) {
			request.DispatchPermit.ParentOperationId = nil
			request.DispatchPermit.Ordinal = 0
		}},
		{name: "genesis revision and initial renewal", mutate: func(request *v1.SpawnProcessRequest) {
			request.WorkspaceProtection.PinnedRevision = 0
			request.WorkspaceProtection.RenewalSequence = 0
		}},
		{name: "read-only without write lease", mutate: func(request *v1.SpawnProcessRequest) {
			request.WorkspaceProtection.AccessMode = v1.WorkspaceAccessMode_WORKSPACE_ACCESS_MODE_READ_ONLY
			request.WorkspaceProtection.LeaseId = nil
			request.WorkspaceProtection.LeaseGeneration = 0
			request.WorkspaceProtection.RenewalSequence = 0
			request.WorkspaceProtection.EnqueueSequence = 0
		}},
	}
	for index, test := range validCases {
		t.Run(test.name, func(t *testing.T) {
			request := validSpawnRequest("valid-authority-"+string(rune('a'+index)), "valid-auth-invoc")
			test.mutate(request)
			if _, err := client.Spawn(context.Background(), request); err != nil {
				t.Fatalf("Spawn() error = %v", err)
			}
			nextFakeProcess(t, runner).Complete(sandboxd.RunResult{ExitCode: 0})
		})
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
		SocketPath:                 filepath.Join(root, "control.sock"),
		AllowedClientUIDs:          []uint32{uint32(os.Geteuid())},
		SandboxID:                  []byte("sandbox-alpha"),
		SandboxGeneration:          7,
		Backend:                    v1.ExecutionBackend_EXECUTION_BACKEND_NSJAIL,
		ExecutionEnvironmentDigest: testExecutionEnvironmentDigest(),
		OneTimeNonce:               bytes.Repeat([]byte{0x5a}, 32),
		Supervisor:                 supervisor,
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
				SocketPath:                 filepath.Join(root, "control.sock"),
				AllowedClientUIDs:          []uint32{uint32(os.Geteuid())},
				SandboxID:                  []byte("sandbox-alpha"),
				SandboxGeneration:          7,
				Backend:                    v1.ExecutionBackend_EXECUTION_BACKEND_NSJAIL,
				ExecutionEnvironmentDigest: testExecutionEnvironmentDigest(),
				OneTimeNonce:               bytes.Repeat([]byte{0x5a}, 32),
				Supervisor:                 supervisor,
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

func TestSandboxHandshakeRejectsWrongPeerAndVersionWithoutConsumingNonce(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		mutate   func(*v1.HandshakeRequest)
		wantCode connect.Code
	}{
		{
			name: "wrong peer",
			mutate: func(request *v1.HandshakeRequest) {
				request.Peer = v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD
			},
			wantCode: connect.CodePermissionDenied,
		},
		{
			name: "wrong version",
			mutate: func(request *v1.HandshakeRequest) {
				request.MinimumVersion = &v1.ProtocolVersion{Major: 2}
				request.MaximumVersion = &v1.ProtocolVersion{Major: 2}
			},
			wantCode: connect.CodeFailedPrecondition,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, client, runner := startTestTransport(t)
			defer server.Close()
			defer client.Close()
			request := &v1.HandshakeRequest{
				Peer:              v1.ProtocolPeer_PROTOCOL_PEER_EXECUTORD,
				MinimumVersion:    protocolVersion(),
				MaximumVersion:    protocolVersion(),
				MaximumFrameSize:  maximumMessageBytes,
				DescriptorDigest:  descriptorDigest(),
				OneTimeNonce:      bytes.Repeat([]byte{0x5a}, handshakeNonceBytes),
				SandboxId:         &v1.OpaqueId{Value: []byte("sandbox-alpha")},
				SandboxGeneration: 7,
			}
			test.mutate(request)
			_, err := client.control.Handshake(context.Background(), connect.NewRequest(request))
			if got := connect.CodeOf(err); got != test.wantCode {
				t.Fatalf("Handshake() code = %v error=%v, want %v", got, err, test.wantCode)
			}
			if _, err := client.Spawn(context.Background(), validSpawnRequest("post-reject-spawn", "post-reject-invoc")); err != nil {
				t.Fatalf("Spawn() after rejected handshake error = %v", err)
			}
			nextFakeProcess(t, runner).Complete(sandboxd.RunResult{ExitCode: 0})
		})
	}
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

func TestSandboxWireRejectsWrongVersionMissingAndExpiredDeadline(t *testing.T) {
	t.Parallel()

	server, client, runner := startTestTransport(t)
	defer server.Close()
	defer client.Close()
	session, err := client.ensureHandshake(context.Background())
	if err != nil {
		t.Fatalf("ensureHandshake() error = %v", err)
	}
	tests := []struct {
		name     string
		mutate   func(*v1.RpcRequestMeta)
		wantCode connect.Code
	}{
		{
			name: "wrong version",
			mutate: func(meta *v1.RpcRequestMeta) {
				meta.ProtocolVersion = &v1.ProtocolVersion{Major: 2}
			},
			wantCode: connect.CodeFailedPrecondition,
		},
		{
			name: "missing deadline",
			mutate: func(meta *v1.RpcRequestMeta) {
				meta.DeadlineUnixMs = 0
			},
			wantCode: connect.CodeFailedPrecondition,
		},
		{
			name: "expired deadline",
			mutate: func(meta *v1.RpcRequestMeta) {
				meta.DeadlineUnixMs = uint64(time.Now().Add(-time.Second).UnixMilli())
			},
			wantCode: connect.CodeDeadlineExceeded,
		},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, _, err := prepareRequest(
				context.Background(),
				validSpawnRequest("wire-boundary-"+string(rune('a'+index)), "wire-invocation"),
			)
			if err != nil {
				t.Fatal(err)
			}
			message := prepared.(*v1.SpawnProcessRequest)
			test.mutate(message.Meta)
			message.Meta.RequestDigest = nil
			message.Meta.RequestDigest, err = requestDigest(message)
			if err != nil {
				t.Fatal(err)
			}
			request := connect.NewRequest(message)
			request.Header().Set(sessionHeader, session)
			_, err = client.process.Spawn(context.Background(), request)
			if got := connect.CodeOf(err); got != test.wantCode {
				t.Fatalf("Spawn() code = %v error=%v, want %v", got, err, test.wantCode)
			}
		})
	}
	if runner.StartCount() != 0 {
		t.Fatalf("invalid wire requests started %d processes", runner.StartCount())
	}
}

func TestSandboxWireRejectsOversizedRequest(t *testing.T) {
	t.Parallel()

	server, client, runner := startTestTransport(t)
	defer server.Close()
	defer client.Close()
	session, err := client.ensureHandshake(context.Background())
	if err != nil {
		t.Fatalf("ensureHandshake() error = %v", err)
	}
	prepared, _, err := prepareRequest(
		context.Background(),
		validSpawnRequest("oversized-wire-01", "oversized-invocat"),
	)
	if err != nil {
		t.Fatal(err)
	}
	message := prepared.(*v1.SpawnProcessRequest)
	message.Arguments = []string{strings.Repeat("x", maximumMessageBytes)}
	message.Meta.RequestDigest = nil
	message.Meta.RequestDigest, err = requestDigest(message)
	if err != nil {
		t.Fatal(err)
	}
	rawProcess := v1connect.NewSandboxProcessServiceClient(
		&http.Client{Transport: client.transport},
		"http://sandbox.invalid",
		connect.WithReadMaxBytes(maximumMessageBytes),
	)
	request := connect.NewRequest(message)
	request.Header().Set(sessionHeader, session)
	_, err = rawProcess.Spawn(context.Background(), request)
	if got := connect.CodeOf(err); got != connect.CodeResourceExhausted {
		t.Fatalf("oversized Spawn() code = %v error=%v, want resource_exhausted", got, err)
	}
	if runner.StartCount() != 0 {
		t.Fatalf("oversized request started %d processes", runner.StartCount())
	}
}

func TestSandboxWirePropagatesInFlightCancellation(t *testing.T) {
	t.Parallel()

	server, client, runner := startTestTransport(t)
	defer server.Close()
	defer client.Close()
	spawned, err := client.Spawn(context.Background(), validSpawnRequest("cancel-wire-spawn", "cancel-wire-invoc"))
	if err != nil {
		t.Fatalf("Spawn() error = %v", err)
	}
	process := nextFakeProcess(t, runner)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, waitErr := client.Wait(ctx, &v1.WaitProcessRequest{
			Meta:    idempotentMeta("cancel-wire-wait"),
			Process: spawned.GetProcess(),
		})
		result <- waitErr
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		server.handler.mu.Lock()
		waiting := false
		for key := range server.handler.operations {
			if strings.HasPrefix(key, "wait\x00") {
				waiting = true
				break
			}
		}
		server.handler.mu.Unlock()
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("Wait() did not reach the server")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case err := <-result:
		if got := connect.CodeOf(err); got != connect.CodeCanceled {
			t.Fatalf("Wait() code = %v error=%v, want canceled", got, err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("canceled Wait() did not return")
	}
	if signals := process.Signals(); len(signals) != 0 {
		t.Fatalf("transport cancellation signaled the process: %v", signals)
	}
	process.Complete(sandboxd.RunResult{ExitCode: 0})
}

type wrongPeerSandboxControlClient struct{}

func (wrongPeerSandboxControlClient) Handshake(
	_ context.Context,
	request *connect.Request[v1.HandshakeRequest],
) (*connect.Response[v1.HandshakeResponse], error) {
	response := connect.NewResponse(&v1.HandshakeResponse{
		SelectedVersion:  protocolVersion(),
		MaximumFrameSize: maximumMessageBytes,
		DescriptorDigest: descriptorDigest(),
		ServerPeer:       v1.ProtocolPeer_PROTOCOL_PEER_EXECUTORD,
		Status: &v1.CapabilityStatus{
			Name:         "sandbox.process",
			Availability: v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_AVAILABLE,
		},
		NonceProof: nonceProof(
			request.Msg.GetOneTimeNonce(),
			request.Msg.GetSandboxId().GetValue(),
			request.Msg.GetSandboxGeneration(),
			v1.ProtocolPeer_PROTOCOL_PEER_EXECUTORD,
		),
	})
	response.Header().Set(sessionHeader, "wrong-daemon-session")
	return response, nil
}

func (wrongPeerSandboxControlClient) GetCapabilities(
	context.Context,
	*connect.Request[v1.GetCapabilitiesRequest],
) (*connect.Response[v1.GetCapabilitiesResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("unused"))
}

func startTestTransport(t *testing.T) (*Server, *Client, *sandboxd.FakeRunner) {
	t.Helper()
	runner := sandboxd.NewFakeRunner()
	server, client := startTestTransportWithRunner(t, runner)
	return server, client, runner
}

func startTestTransportWithRunner(t *testing.T, runner sandboxd.Runner, configure ...func(*Server)) (*Server, *Client) {
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
		SocketPath:                 filepath.Join(root, "control.sock"),
		AllowedClientUIDs:          []uint32{uint32(os.Geteuid())},
		SandboxID:                  []byte("sandbox-alpha"),
		SandboxGeneration:          7,
		Backend:                    v1.ExecutionBackend_EXECUTION_BACKEND_NSJAIL,
		ExecutionEnvironmentDigest: testExecutionEnvironmentDigest(),
		OneTimeNonce:               nonce,
		Supervisor:                 supervisor,
	})
	if err != nil {
		t.Fatalf("ListenServer() error = %v", err)
	}
	for _, configureServer := range configure {
		configureServer(server)
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
	return server, client
}

func validSpawnRequest(idempotencyKey, invocationID string) *v1.SpawnProcessRequest {
	digest := sha256.Sum256([]byte("authorized execution request"))
	environmentDigest := testExecutionEnvironmentDigest()
	invocation := &v1.OpaqueId{Value: []byte(invocationID)}
	tenant := &v1.OpaqueId{Value: []byte("tenant-alpha")}
	user := &v1.OpaqueId{Value: []byte("user-alpha")}
	session := &v1.OpaqueId{Value: []byte("session-alpha")}
	effect := &v1.OpaqueId{Value: []byte("effect-alpha")}
	now := time.Now()
	return &v1.SpawnProcessRequest{
		Meta: idempotentMeta(idempotencyKey),
		DispatchPermit: &v1.DispatchPermit{
			Value:                   bytes.Repeat([]byte{0xd1}, 32),
			TenantId:                proto.Clone(tenant).(*v1.OpaqueId),
			UserId:                  proto.Clone(user).(*v1.OpaqueId),
			SessionId:               proto.Clone(session).(*v1.OpaqueId),
			TurnId:                  &v1.OpaqueId{Value: []byte("turn-alpha")},
			EffectId:                proto.Clone(effect).(*v1.OpaqueId),
			InvocationId:            proto.Clone(invocation).(*v1.OpaqueId),
			RequestDigest:           &v1.Digest{Algorithm: v1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: append([]byte(nil), digest[:]...)},
			Service:                 v1.EffectService_EFFECT_SERVICE_EXECUTOR,
			Operation:               "executor.run",
			ReplayPolicy:            v1.ReplayPolicy_REPLAY_POLICY_IDEMPOTENCY_KEY,
			ParentOperationId:       &v1.OpaqueId{Value: []byte("parent-operation")},
			Ordinal:                 1,
			DispatchAttempt:         2,
			TurnLeaseGeneration:     3,
			PlacementGeneration:     4,
			SandboxGeneration:       7,
			AuthorizationGeneration: 5,
			DeadlineUnixMs:          uint64(now.Add(time.Hour).UnixMilli()),
		},
		Sandbox: &v1.SandboxHandle{
			SandboxId:                  &v1.OpaqueId{Value: []byte("sandbox-alpha")},
			Generation:                 7,
			Backend:                    v1.ExecutionBackend_EXECUTION_BACKEND_NSJAIL,
			ExecutionEnvironmentDigest: &v1.Digest{Algorithm: v1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: environmentDigest},
		},
		WorkspaceProtection: &v1.WorkspaceProtectionPermit{
			Value:                     bytes.Repeat([]byte{0xe2}, 32),
			TenantId:                  proto.Clone(tenant).(*v1.OpaqueId),
			UserId:                    proto.Clone(user).(*v1.OpaqueId),
			WorkspaceId:               &v1.OpaqueId{Value: []byte("workspace-alpha")},
			LeaseId:                   &v1.OpaqueId{Value: []byte("lease-alpha")},
			InvocationId:              proto.Clone(invocation).(*v1.OpaqueId),
			RequestDigest:             &v1.Digest{Algorithm: v1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: append([]byte(nil), digest[:]...)},
			EffectId:                  proto.Clone(effect).(*v1.OpaqueId),
			SessionId:                 proto.Clone(session).(*v1.OpaqueId),
			SandboxId:                 &v1.OpaqueId{Value: []byte("sandbox-alpha")},
			Backend:                   v1.ExecutionBackend_EXECUTION_BACKEND_NSJAIL,
			AccessMode:                v1.WorkspaceAccessMode_WORKSPACE_ACCESS_MODE_READ_WRITE,
			PinnedRevision:            11,
			LeaseGeneration:           6,
			DispatchAttempt:           2,
			TurnLeaseGeneration:       3,
			PlacementGeneration:       4,
			SandboxGeneration:         7,
			ProjectionGeneration:      8,
			AuthorizationGeneration:   5,
			IssuedAtUnixMs:            uint64(now.Add(-time.Minute).UnixMilli()),
			ExpiresAtUnixMs:           uint64(now.Add(30 * time.Minute).UnixMilli()),
			MaximumHoldDeadlineUnixMs: uint64(now.Add(time.Hour).UnixMilli()),
			RenewalSequence:           1,
			EnqueueSequence:           1,
		},
		InvocationId:     invocation,
		RequestDigest:    &v1.Digest{Algorithm: v1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: append([]byte(nil), digest[:]...)},
		Executable:       "echo",
		Arguments:        []string{"hello"},
		WorkingDirectory: "",
		TimeoutMs:        5_000,
		OutputLimitBytes: 1 << 20,
		StdinMode:        v1.StdinMode_STDIN_MODE_STREAM,
	}
}

func testExecutionEnvironmentDigest() []byte {
	digest := sha256.Sum256([]byte("authorized execution environment"))
	return append([]byte(nil), digest[:]...)
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

type failingCloseListener struct {
	accepting chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
	err       error
}

func newFailingCloseListener(err error) *failingCloseListener {
	return &failingCloseListener{
		accepting: make(chan struct{}),
		closed:    make(chan struct{}),
		err:       err,
	}
}

func (listener *failingCloseListener) Accept() (net.Conn, error) {
	select {
	case <-listener.accepting:
	default:
		close(listener.accepting)
	}
	<-listener.closed
	return nil, net.ErrClosed
}

func (listener *failingCloseListener) Close() error {
	listener.closeOnce.Do(func() { close(listener.closed) })
	return listener.err
}

func (*failingCloseListener) Addr() net.Addr {
	return &net.UnixAddr{Name: "sandbox-test", Net: "unix"}
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
