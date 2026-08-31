//go:build linux

package nsjail

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/identity"
	"github.com/hancomac/circulusd/internal/sandboxd"
	"github.com/hancomac/circulusd/internal/sandboxrpc"
	"golang.org/x/sys/unix"
)

func TestHandshakeBrokerAuthenticatesRegisteredLaunchExactlyOnce(t *testing.T) {
	t.Parallel()
	fixture := newHandshakeBrokerFixture(t)
	broker := NewHandshakeBroker()
	nonce := bytes.Repeat([]byte{0x5a}, handshakeNonceBytes)
	serverNonce := append([]byte(nil), nonce...)
	request := fixture.registrationRequest(t, 7, nonce)
	registration, err := broker.RegisterHandshakeNonce(context.Background(), request)
	if err != nil {
		t.Fatalf("RegisterHandshakeNonce() error = %v", err)
	}
	clear(nonce)
	clear(request.OneTimeNonce)

	server := fixture.listen(t, request.SocketPath, request.Generation, serverNonce)
	serveSandboxRPC(t, server)

	const callers = 32
	start := make(chan struct{})
	sessions := make(chan ControlSession, callers)
	errorsChannel := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			session, readyErr := broker.AwaitReady(ctx, fixture.sandboxID, request.Generation)
			sessions <- session
			errorsChannel <- readyErr
		}()
	}
	close(start)
	wait.Wait()
	close(sessions)
	close(errorsChannel)
	for readyErr := range errorsChannel {
		if readyErr != nil {
			t.Fatalf("AwaitReady() error = %v", readyErr)
		}
	}
	var first ControlSession
	for session := range sessions {
		if session == nil {
			t.Fatal("AwaitReady() returned a nil session")
		}
		if first == nil {
			first = session
		} else if session != first {
			t.Fatal("concurrent AwaitReady calls received different sessions")
		}
	}
	if err := registration.Revoke(context.Background()); err != nil {
		t.Fatalf("Revoke(first) error = %v", err)
	}
	if err := registration.Revoke(context.Background()); err != nil {
		t.Fatalf("Revoke(second) error = %v", err)
	}
	client, ok := first.(*sandboxrpc.Client)
	if !ok {
		t.Fatalf("session type = %T, want *sandboxrpc.Client", first)
	}
	if err := client.Ready(context.Background()); err == nil {
		t.Fatal("revoked session remained usable")
	}
}

func TestHandshakeBrokerRejectsDuplicateAndStaleGenerations(t *testing.T) {
	t.Parallel()
	fixture := newHandshakeBrokerFixture(t)
	broker := NewHandshakeBroker()
	firstRequest := fixture.registrationRequest(t, 7, bytes.Repeat([]byte{0x17}, handshakeNonceBytes))
	first, err := broker.RegisterHandshakeNonce(context.Background(), firstRequest)
	if err != nil {
		t.Fatalf("RegisterHandshakeNonce(first) error = %v", err)
	}
	if _, err := broker.RegisterHandshakeNonce(context.Background(), firstRequest); !errors.Is(err, ErrDuplicateHandshakeRegistration) {
		t.Fatalf("RegisterHandshakeNonce(duplicate) error = %v, want ErrDuplicateHandshakeRegistration", err)
	}

	secondRequest := fixture.registrationRequest(t, 8, bytes.Repeat([]byte{0x18}, handshakeNonceBytes))
	if _, err := broker.RegisterHandshakeNonce(context.Background(), secondRequest); !errors.Is(err, ErrActiveHandshakeRegistration) {
		t.Fatalf("RegisterHandshakeNonce(concurrent generation) error = %v, want ErrActiveHandshakeRegistration", err)
	}
	if err := first.Revoke(context.Background()); err != nil {
		t.Fatalf("Revoke(first) error = %v", err)
	}
	second, err := broker.RegisterHandshakeNonce(context.Background(), secondRequest)
	if err != nil {
		t.Fatalf("RegisterHandshakeNonce(second) error = %v", err)
	}
	t.Cleanup(func() { _ = second.Revoke(context.Background()) })

	if _, err := broker.RegisterHandshakeNonce(context.Background(), firstRequest); !errors.Is(err, ErrStaleHandshakeGeneration) {
		t.Fatalf("RegisterHandshakeNonce(stale) error = %v, want ErrStaleHandshakeGeneration", err)
	}
	if _, err := broker.AwaitReady(context.Background(), fixture.sandboxID, firstRequest.Generation); !errors.Is(err, ErrStaleHandshakeGeneration) {
		t.Fatalf("AwaitReady(stale) error = %v, want ErrStaleHandshakeGeneration", err)
	}
	if _, err := broker.AwaitReady(context.Background(), fixture.sandboxID, secondRequest.Generation+1); !errors.Is(err, ErrHandshakeRegistrationNotFound) {
		t.Fatalf("AwaitReady(future) error = %v, want ErrHandshakeRegistrationNotFound", err)
	}
}

func TestHandshakeBrokerConcurrentDuplicateRegistrationHasOneWinner(t *testing.T) {
	t.Parallel()
	fixture := newHandshakeBrokerFixture(t)
	broker := NewHandshakeBroker()
	request := fixture.registrationRequest(t, 7, bytes.Repeat([]byte{0x19}, handshakeNonceBytes))

	const callers = 64
	start := make(chan struct{})
	registrations := make(chan HandshakeNonceRegistration, callers)
	errorsChannel := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			registration, err := broker.RegisterHandshakeNonce(context.Background(), request)
			registrations <- registration
			errorsChannel <- err
		}()
	}
	close(start)
	wait.Wait()
	close(registrations)
	close(errorsChannel)

	winners := 0
	var winner HandshakeNonceRegistration
	for registration := range registrations {
		if registration != nil {
			winners++
			winner = registration
		}
	}
	duplicates := 0
	for err := range errorsChannel {
		switch {
		case err == nil:
		case errors.Is(err, ErrDuplicateHandshakeRegistration):
			duplicates++
		default:
			t.Fatalf("RegisterHandshakeNonce() error = %v", err)
		}
	}
	if winners != 1 || duplicates != callers-1 {
		t.Fatalf("concurrent registration winners/duplicates = %d/%d, want 1/%d", winners, duplicates, callers-1)
	}
	if err := winner.Revoke(context.Background()); err != nil {
		t.Fatalf("Revoke(winner) error = %v", err)
	}
}

func TestHandshakeBrokerFencesServerUIDAndControlDirectoryIdentity(t *testing.T) {
	t.Parallel()
	t.Run("server UID", func(t *testing.T) {
		fixture := newHandshakeBrokerFixture(t)
		broker := NewHandshakeBroker()
		request := fixture.registrationRequest(t, 7, bytes.Repeat([]byte{0x27}, handshakeNonceBytes))
		request.ServerUID++
		if _, err := broker.RegisterHandshakeNonce(context.Background(), request); !errors.Is(err, ErrInvalidHandshakeRegistration) {
			t.Fatalf("RegisterHandshakeNonce(wrong UID) error = %v, want ErrInvalidHandshakeRegistration", err)
		}
	})

	t.Run("replaced directory", func(t *testing.T) {
		fixture := newHandshakeBrokerFixture(t)
		var factoryCalls atomic.Int32
		broker := newHandshakeBrokerWithDependencies(handshakeBrokerDependencies{
			newClient: func(sandboxrpc.ClientConfig, int) (handshakeControlClient, error) {
				factoryCalls.Add(1)
				return nil, errors.New("must not reach client factory")
			},
			retryInterval: time.Millisecond,
		})
		request := fixture.registrationRequest(t, 7, bytes.Repeat([]byte{0x28}, handshakeNonceBytes))
		registration, err := broker.RegisterHandshakeNonce(context.Background(), request)
		if err != nil {
			t.Fatalf("RegisterHandshakeNonce() error = %v", err)
		}
		t.Cleanup(func() { _ = registration.Revoke(context.Background()) })

		controlDirectory := filepath.Dir(request.SocketPath)
		sealedDirectory := controlDirectory + "-sealed"
		if err := os.Rename(controlDirectory, sealedDirectory); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(controlDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := broker.AwaitReady(ctx, fixture.sandboxID, request.Generation); !errors.Is(err, ErrHandshakeSocketIdentity) {
			t.Fatalf("AwaitReady(replaced directory) error = %v, want ErrHandshakeSocketIdentity", err)
		}
		if calls := factoryCalls.Load(); calls != 0 {
			t.Fatalf("client factory calls = %d, want 0", calls)
		}
	})
}

func TestOpenHandshakeDirectoryRejectsSymlinkAncestorReplacement(t *testing.T) {
	fixture := newHandshakeBrokerFixture(t)
	request := fixture.registrationRequest(t, 7, bytes.Repeat([]byte{0x29}, handshakeNonceBytes))
	generationDirectory := filepath.Dir(filepath.Dir(request.SocketPath))
	parkedDirectory := filepath.Join(fixture.root, "parked")
	decoyDirectory := filepath.Join(fixture.root, "decoy")
	if err := os.MkdirAll(filepath.Join(decoyDirectory, "control"), 0o700); err != nil {
		t.Fatalf("MkdirAll(decoy control directory) error = %v", err)
	}

	directoryFD, _, openErr := openHandshakeDirectoryWithDependencies(
		filepath.Dir(request.SocketPath),
		request.ServerUID,
		handshakeDirectoryOpenDependencies{
			beforeOpen: func() error {
				if err := os.Rename(generationDirectory, parkedDirectory); err != nil {
					return err
				}
				return os.Symlink(decoyDirectory, generationDirectory)
			},
		},
	)
	if directoryFD >= 0 {
		_ = unix.Close(directoryFD)
	}
	removeErr := os.Remove(generationDirectory)
	restoreErr := os.Rename(parkedDirectory, generationDirectory)
	if removeErr != nil || restoreErr != nil {
		t.Fatalf("restore swapped ancestor errors = %v", errors.Join(removeErr, restoreErr))
	}
	if openErr == nil {
		t.Fatal("openHandshakeDirectoryWithDependencies() error = nil, want symlink ancestor rejection")
	}
}

func TestHandshakeBrokerCallerCancellationDoesNotPoisonSharedReadiness(t *testing.T) {
	t.Parallel()
	fixture := newHandshakeBrokerFixture(t)
	request := fixture.registrationRequest(t, 7, bytes.Repeat([]byte{0x37}, handshakeNonceBytes))

	client := newBlockingHandshakeClient()
	var factoryCalls atomic.Int32
	var captured sandboxrpc.ClientConfig
	broker := newHandshakeBrokerWithDependencies(handshakeBrokerDependencies{
		newClient: func(config sandboxrpc.ClientConfig, _ int) (handshakeControlClient, error) {
			factoryCalls.Add(1)
			captured = config
			captured.SandboxID = append([]byte(nil), config.SandboxID...)
			captured.OneTimeNonce = append([]byte(nil), config.OneTimeNonce...)
			return client, nil
		},
		retryInterval: time.Millisecond,
	})
	registration, err := broker.RegisterHandshakeNonce(context.Background(), request)
	if err != nil {
		t.Fatalf("RegisterHandshakeNonce() error = %v", err)
	}
	t.Cleanup(func() { _ = registration.Revoke(context.Background()) })
	listener := listenHandshakeSocket(t, request.SocketPath)
	t.Cleanup(func() { _ = listener.Close() })

	firstContext, cancelFirst := context.WithCancel(context.Background())
	firstResult := make(chan error, 1)
	go func() {
		_, readyErr := broker.AwaitReady(firstContext, fixture.sandboxID, request.Generation)
		firstResult <- readyErr
	}()
	select {
	case <-client.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("client Ready was not entered")
	}
	cancelFirst()
	if err := <-firstResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("first AwaitReady() error = %v, want context.Canceled", err)
	}

	secondResult := make(chan struct {
		session ControlSession
		err     error
	}, 1)
	go func() {
		session, readyErr := broker.AwaitReady(context.Background(), fixture.sandboxID, request.Generation)
		secondResult <- struct {
			session ControlSession
			err     error
		}{session: session, err: readyErr}
	}()
	close(client.release)
	result := <-secondResult
	if result.err != nil || result.session != client {
		t.Fatalf("second AwaitReady() = %T, %v; want shared client", result.session, result.err)
	}
	if calls := factoryCalls.Load(); calls != 1 {
		t.Fatalf("client factory calls = %d, want 1", calls)
	}
	if captured.SocketPath != request.SocketPath || captured.ServerUID != request.ServerUID ||
		string(captured.SandboxID) != request.SandboxID || captured.SandboxGeneration != request.Generation ||
		!bytes.Equal(captured.OneTimeNonce, request.OneTimeNonce) {
		t.Fatalf("client config = %#v, want exact registered launch authority", captured)
	}
}

func TestHandshakeBrokerRevokeCancelsAndWaitsForInFlightReadiness(t *testing.T) {
	t.Parallel()
	fixture := newHandshakeBrokerFixture(t)
	request := fixture.registrationRequest(t, 7, bytes.Repeat([]byte{0x47}, handshakeNonceBytes))

	client := newBlockingHandshakeClient()
	broker := newHandshakeBrokerWithDependencies(handshakeBrokerDependencies{
		newClient:     func(sandboxrpc.ClientConfig, int) (handshakeControlClient, error) { return client, nil },
		retryInterval: time.Millisecond,
	})
	registration, err := broker.RegisterHandshakeNonce(context.Background(), request)
	if err != nil {
		t.Fatalf("RegisterHandshakeNonce() error = %v", err)
	}
	listener := listenHandshakeSocket(t, request.SocketPath)
	t.Cleanup(func() { _ = listener.Close() })
	readyResult := make(chan error, 1)
	go func() {
		_, readyErr := broker.AwaitReady(context.Background(), fixture.sandboxID, request.Generation)
		readyResult <- readyErr
	}()
	select {
	case <-client.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("client Ready was not entered")
	}

	revokeContext, cancelRevoke := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelRevoke()
	if err := registration.Revoke(revokeContext); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if err := <-readyResult; !errors.Is(err, ErrHandshakeRegistrationRevoked) {
		t.Fatalf("AwaitReady() error = %v, want ErrHandshakeRegistrationRevoked", err)
	}
	if closes := client.closes.Load(); closes != 1 {
		t.Fatalf("client closes = %d, want 1", closes)
	}
	if err := registration.Revoke(context.Background()); err != nil {
		t.Fatalf("Revoke(repeated) error = %v", err)
	}
	if closes := client.closes.Load(); closes != 1 {
		t.Fatalf("client closes after repeated revoke = %d, want 1", closes)
	}
}

func TestHandshakeBrokerRejectsSocketReplacementAfterClientPin(t *testing.T) {
	t.Parallel()
	fixture := newHandshakeBrokerFixture(t)
	nonce := bytes.Repeat([]byte{0x57}, handshakeNonceBytes)
	request := fixture.registrationRequest(t, 7, nonce)
	clientPinned := make(chan struct{})
	releaseFactory := make(chan struct{})
	broker := newHandshakeBrokerWithDependencies(handshakeBrokerDependencies{
		newClient: func(config sandboxrpc.ClientConfig, pinnedSocketFD int) (handshakeControlClient, error) {
			client, err := sandboxrpc.NewClientFromPinnedSocketFD(config, pinnedSocketFD)
			if err == nil {
				close(clientPinned)
				<-releaseFactory
			}
			return client, err
		},
		retryInterval: time.Millisecond,
	})
	registration, err := broker.RegisterHandshakeNonce(context.Background(), request)
	if err != nil {
		t.Fatalf("RegisterHandshakeNonce() error = %v", err)
	}
	t.Cleanup(func() { _ = registration.Revoke(context.Background()) })

	firstServer := fixture.listen(t, request.SocketPath, request.Generation, nonce)
	readyResult := make(chan error, 1)
	go func() {
		_, readyErr := broker.AwaitReady(context.Background(), fixture.sandboxID, request.Generation)
		readyResult <- readyErr
	}()
	select {
	case <-clientPinned:
	case <-time.After(5 * time.Second):
		t.Fatal("client did not pin the first socket")
	}
	if err := firstServer.Close(); err != nil {
		t.Fatalf("Close(first server) error = %v", err)
	}
	secondServer := fixture.listen(t, request.SocketPath, request.Generation, nonce)
	serveSandboxRPC(t, secondServer)
	close(releaseFactory)
	if err := <-readyResult; !errors.Is(err, ErrSandboxHandshakeFailed) {
		t.Fatalf("AwaitReady(replaced socket) error = %v, want ErrSandboxHandshakeFailed", err)
	}

	directClient, err := sandboxrpc.NewClient(sandboxrpc.ClientConfig{
		SocketPath:        request.SocketPath,
		ServerUID:         request.ServerUID,
		SandboxID:         []byte(request.SandboxID),
		SandboxGeneration: request.Generation,
		OneTimeNonce:      nonce,
	})
	if err != nil {
		t.Fatalf("NewClient(replacement) error = %v", err)
	}
	defer directClient.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := directClient.Ready(ctx); err != nil {
		t.Fatalf("replacement server nonce was consumed by stale client: %v", err)
	}
}

func TestHandshakeBrokerAuthenticatesPinnedSocketAcrossPathnameABA(t *testing.T) {
	fixture := newHandshakeBrokerFixture(t)
	nonce := bytes.Repeat([]byte{0x58}, handshakeNonceBytes)
	request := fixture.registrationRequest(t, 7, nonce)
	decoyPath := filepath.Join(filepath.Dir(request.SocketPath), "decoy.sock")
	parkedPath := filepath.Join(filepath.Dir(request.SocketPath), "parked.sock")
	var swaps atomic.Int32
	broker := newHandshakeBrokerWithDependencies(handshakeBrokerDependencies{
		newClient: func(config sandboxrpc.ClientConfig, pinnedSocketFD int) (handshakeControlClient, error) {
			if !swaps.CompareAndSwap(0, 1) {
				return sandboxrpc.NewClientFromPinnedSocketFD(config, pinnedSocketFD)
			}
			if err := os.Rename(request.SocketPath, parkedPath); err != nil {
				return nil, err
			}
			if err := os.Rename(decoyPath, request.SocketPath); err != nil {
				return nil, errors.Join(err, os.Rename(parkedPath, request.SocketPath))
			}
			client, clientErr := sandboxrpc.NewClientFromPinnedSocketFD(config, pinnedSocketFD)
			restoreErr := errors.Join(
				os.Rename(request.SocketPath, decoyPath),
				os.Rename(parkedPath, request.SocketPath),
			)
			if restoreErr != nil {
				if client != nil {
					_ = client.Close()
				}
				return nil, errors.Join(clientErr, restoreErr)
			}
			return client, clientErr
		},
		retryInterval: time.Millisecond,
	})
	registration, err := broker.RegisterHandshakeNonce(context.Background(), request)
	if err != nil {
		t.Fatalf("RegisterHandshakeNonce() error = %v", err)
	}
	t.Cleanup(func() { _ = registration.Revoke(context.Background()) })
	authorityServer := fixture.listen(t, request.SocketPath, request.Generation, nonce)
	decoyServer := fixture.listen(t, decoyPath, request.Generation, nonce)
	serveSandboxRPC(t, authorityServer)
	serveSandboxRPC(t, decoyServer)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := broker.AwaitReady(ctx, fixture.sandboxID, request.Generation); err != nil {
		t.Fatalf("AwaitReady() error = %v", err)
	}
	if swaps.Load() != 1 {
		t.Fatalf("pathname swaps = %d, want 1", swaps.Load())
	}

	authorityClient, err := sandboxrpc.NewClient(sandboxrpc.ClientConfig{
		SocketPath:        request.SocketPath,
		ServerUID:         request.ServerUID,
		SandboxID:         []byte(request.SandboxID),
		SandboxGeneration: request.Generation,
		OneTimeNonce:      nonce,
	})
	if err != nil {
		t.Fatalf("NewClient(authority) error = %v", err)
	}
	defer authorityClient.Close()
	authorityErr := authorityClient.Ready(ctx)
	decoyClient, err := sandboxrpc.NewClient(sandboxrpc.ClientConfig{
		SocketPath:        decoyPath,
		ServerUID:         request.ServerUID,
		SandboxID:         []byte(request.SandboxID),
		SandboxGeneration: request.Generation,
		OneTimeNonce:      nonce,
	})
	if err != nil {
		t.Fatalf("NewClient(decoy) error = %v", err)
	}
	defer decoyClient.Close()
	decoyErr := decoyClient.Ready(ctx)
	if authorityErr == nil || decoyErr != nil {
		t.Fatalf("post-handshake authority/decoy readiness errors = %v/%v, want used/unused", authorityErr, decoyErr)
	}
}

func TestHandshakeRegistrationFormattingRedactsNonce(t *testing.T) {
	t.Parallel()
	fixture := newHandshakeBrokerFixture(t)
	request := fixture.registrationRequest(t, 7, bytes.Repeat([]byte{0x67}, handshakeNonceBytes))
	formatted := fmt.Sprintf("%v %#v", request, request)
	if strings.Contains(formatted, "103 103 103") || strings.Contains(formatted, strings.Repeat("67", handshakeNonceBytes)) {
		t.Fatalf("registration formatting disclosed the nonce: %s", formatted)
	}
}

type handshakeBrokerFixture struct {
	root      string
	sandboxID identity.ID
}

func newHandshakeBrokerFixture(t *testing.T) *handshakeBrokerFixture {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "cb-")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Errorf("RemoveAll(%q) error = %v", root, err)
		}
	})
	sandboxID, err := (identity.Generator{Random: bytes.NewReader(bytes.Repeat([]byte{0x73}, 16))}).New(identity.Sandbox)
	if err != nil {
		t.Fatalf("New(sandbox ID) error = %v", err)
	}
	return &handshakeBrokerFixture{root: root, sandboxID: sandboxID}
}

func (fixture *handshakeBrokerFixture) registrationRequest(
	t *testing.T,
	generation uint64,
	nonce []byte,
) HandshakeNonceRegistrationRequest {
	t.Helper()
	controlDirectory := filepath.Join(fixture.root, fmt.Sprintf("g-%d", generation), "control")
	if err := os.MkdirAll(controlDirectory, 0o700); err != nil {
		t.Fatalf("MkdirAll(control directory) error = %v", err)
	}
	if err := os.Chmod(controlDirectory, 0o700); err != nil {
		t.Fatalf("Chmod(control directory) error = %v", err)
	}
	return HandshakeNonceRegistrationRequest{
		SandboxID:    fixture.sandboxID.String(),
		Generation:   generation,
		SocketPath:   filepath.Join(controlDirectory, sandboxControlSocketName),
		ServerUID:    uint32(os.Geteuid()),
		OneTimeNonce: append([]byte(nil), nonce...),
	}
}

func (fixture *handshakeBrokerFixture) listen(
	t *testing.T,
	socketPath string,
	generation uint64,
	nonce []byte,
) *sandboxrpc.Server {
	t.Helper()
	workspace := filepath.Join(fixture.root, fmt.Sprintf("workspace-%d", generation))
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	supervisor, err := sandboxd.NewSupervisor(sandboxd.Config{
		Authority:         sandboxd.LaunchAuthority{SandboxID: fixture.sandboxID.String(), Generation: generation},
		WorkspaceRoot:     workspace,
		Commands:          map[string]string{"echo": "/bin/echo"},
		Runner:            sandboxd.NewFakeRunner(),
		ReplayLimitBytes:  1 << 20,
		ReplayLimitEvents: 128,
		SubscriberBuffer:  16,
		ReadChunkBytes:    4096,
	})
	if err != nil {
		t.Fatalf("NewSupervisor() error = %v", err)
	}
	server, err := sandboxrpc.ListenServer(sandboxrpc.ServerConfig{
		SocketPath:                 socketPath,
		AllowedClientUIDs:          []uint32{uint32(os.Geteuid())},
		SandboxID:                  []byte(fixture.sandboxID.String()),
		SandboxGeneration:          generation,
		Backend:                    v1.ExecutionBackend_EXECUTION_BACKEND_NSJAIL,
		ExecutionEnvironmentDigest: bytes.Repeat([]byte{0x42}, 32),
		OneTimeNonce:               append([]byte(nil), nonce...),
		Supervisor:                 supervisor,
	})
	if err != nil {
		t.Fatalf("ListenServer() error = %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server
}

func serveSandboxRPC(t *testing.T, server *sandboxrpc.Server) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve() error = %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Serve() did not stop")
		}
	})
}

func listenHandshakeSocket(t *testing.T, socketPath string) *net.UnixListener {
	t.Helper()
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatalf("ListenUnix() error = %v", err)
	}
	listener.SetUnlinkOnClose(true)
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = listener.Close()
		t.Fatalf("Chmod(socket) error = %v", err)
	}
	return listener
}

type blockingHandshakeClient struct {
	entered   chan struct{}
	release   chan struct{}
	enterOnce sync.Once
	closeOnce sync.Once
	closes    atomic.Int32
}

func newBlockingHandshakeClient() *blockingHandshakeClient {
	return &blockingHandshakeClient{entered: make(chan struct{}), release: make(chan struct{})}
}

func (client *blockingHandshakeClient) Ready(ctx context.Context) error {
	client.enterOnce.Do(func() { close(client.entered) })
	select {
	case <-client.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (client *blockingHandshakeClient) Close() error {
	client.closeOnce.Do(func() { client.closes.Add(1) })
	return nil
}
