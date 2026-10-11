//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/sandboxd"
	"github.com/hancomac/circulusd/internal/sandboxrpc"
)

type harnessTransport struct {
	server      *sandboxrpc.Server
	runner      *sandboxd.FakeRunner
	inst        *instance
	nonce       []byte
	environment string
}

func newHarnessTransport(t *testing.T) *harnessTransport {
	t.Helper()
	root, err := os.MkdirTemp("", "circulusd-harness-rpc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	})
	workspace := filepath.Join(root, "workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	fixture := &harnessTransport{runner: sandboxd.NewFakeRunner(), nonce: bytes.Repeat([]byte{0x5a}, 32)}
	fixture.inst = &instance{ID: "sandbox-harness", Generation: 7, ServerUID: uint32(os.Geteuid()), SocketPath: filepath.Join(root, "control.sock"), done: make(chan struct{})}
	supervisor, err := sandboxd.NewSupervisor(sandboxd.Config{Authority: sandboxd.LaunchAuthority{SandboxID: fixture.inst.ID, Generation: fixture.inst.Generation}, WorkspaceRoot: workspace, Commands: map[string]string{pythonCommand: "/bin/echo"}, Runner: fixture.runner, ReplayLimitBytes: 1 << 20, ReplayLimitEvents: 128, SubscriberBuffer: 16, ReadChunkBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("harness environment"))
	fixture.environment = "sha256:" + hex.EncodeToString(digest[:])
	fixture.server, err = sandboxrpc.ListenServer(sandboxrpc.ServerConfig{SocketPath: fixture.inst.SocketPath, AllowedClientUIDs: []uint32{uint32(os.Geteuid())}, SandboxID: []byte(fixture.inst.ID), SandboxGeneration: fixture.inst.Generation, Backend: v1.ExecutionBackend_EXECUTION_BACKEND_NSJAIL, ExecutionEnvironmentDigest: digest[:], OneTimeNonce: fixture.nonce, Supervisor: supervisor})
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- fixture.server.Serve(context.Background()) }()
	t.Cleanup(func() {
		if err := fixture.server.Close(); err != nil {
			t.Error(err)
		}
		select {
		case err := <-finished:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Error("sandbox RPC did not stop")
		}
	})
	return fixture
}

func (fixture *harnessTransport) client(t *testing.T) *sandboxClient {
	t.Helper()
	client, err := newSandboxClient(fixture.inst.SocketPath, fixture.inst.ServerUID, fixture.inst.ID, fixture.inst.Generation, fixture.nonce)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := client.close(); err != nil {
			t.Error(err)
		}
	})
	return client
}

func TestSharedSandboxClientRunsHarnessSpawnStdinAndOrderedEvents(t *testing.T) {
	fixture := newHarnessTransport(t)
	client := fixture.client(t)
	// The pool clears its launch nonce as soon as the shared client snapshots it.
	clear(fixture.nonce)
	var ready sync.WaitGroup
	errors := make(chan error, 32)
	for range 32 {
		ready.Add(1)
		go func() { defer ready.Done(); errors <- client.handshake(context.Background()) }()
	}
	ready.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	executor := newExecutor(client, fixture.inst, "nsjail", fixture.environment)
	finished := make(chan struct {
		result *runResult
		err    error
	}, 1)
	go func() {
		result, err := executor.run(context.Background(), runRequest{SessionID: "session-harness", TurnID: "turn-harness", ToolCallID: "call-harness", Code: "print('hello')", Stdin: "harness-input", ReplayPolicy: "never", TimeoutMs: 2000})
		finished <- struct {
			result *runResult
			err    error
		}{result, err}
	}()
	var process *sandboxd.FakeProcess
	select {
	case process = <-fixture.runner.Started():
	case <-time.After(2 * time.Second):
		t.Fatal("harness spawn did not reach shared server")
	}
	defer process.Complete(sandboxd.RunResult{})
	deadline := time.Now().Add(2 * time.Second)
	for string(process.StdinBytes()) != "harness-input" {
		if time.Now().After(deadline) {
			t.Fatal("stdin did not cross shared client")
		}
		time.Sleep(time.Millisecond)
	}
	if err := process.EmitStdout([]byte("hello\n")); err != nil {
		t.Fatal(err)
	}
	process.Complete(sandboxd.RunResult{ExitCode: 0})
	select {
	case outcome := <-finished:
		if outcome.err != nil || outcome.result.Stdout != "hello\n" || outcome.result.ExitCode != 0 {
			t.Fatalf("result=%+v error=%v", outcome.result, outcome.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("harness did not receive terminal stream")
	}
	if fixture.runner.StartCount() != 1 {
		t.Fatal("harness repeated spawn")
	}
}

func TestSharedSandboxClientRejectsLaunchBindingChangesBeforeRunner(t *testing.T) {
	for _, changed := range []string{"sandbox", "generation", "backend", "environment"} {
		t.Run(changed, func(t *testing.T) {
			fixture := newHarnessTransport(t)
			client := fixture.client(t)
			if err := client.handshake(context.Background()); err != nil {
				t.Fatal(err)
			}
			executor := newExecutor(client, fixture.inst, "nsjail", fixture.environment)
			switch changed {
			case "sandbox":
				fixture.inst.ID = "sandbox-changed"
			case "generation":
				fixture.inst.Generation++
			case "backend":
				executor.backend = "docker"
			case "environment":
				executor.envDigest = "sha256:" + hex.EncodeToString(bytes.Repeat([]byte{1}, 32))
			}
			_, err := executor.run(context.Background(), runRequest{SessionID: "session-harness", TurnID: "turn-harness", ToolCallID: "call-harness", Code: "pass", ReplayPolicy: "never", TimeoutMs: 1000})
			if err == nil || fixture.runner.StartCount() != 0 {
				t.Fatalf("changed %s reached runner: %v", changed, err)
			}
		})
	}
}

func TestSharedSandboxClientRetainsPrivateSocketAndUIDChecks(t *testing.T) {
	fixture := newHarnessTransport(t)
	if client, err := newSandboxClient(fixture.inst.SocketPath, fixture.inst.ServerUID+1, fixture.inst.ID, fixture.inst.Generation, fixture.nonce); err == nil {
		_ = client.close()
		t.Fatal("wrong socket owner accepted")
	}
	if err := os.Chmod(filepath.Dir(fixture.inst.SocketPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if client, err := newSandboxClient(fixture.inst.SocketPath, fixture.inst.ServerUID, fixture.inst.ID, fixture.inst.Generation, fixture.nonce); err == nil {
		_ = client.close()
		t.Fatal("nonprivate directory accepted")
	}
	if err := os.Chmod(filepath.Dir(fixture.inst.SocketPath), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(fixture.inst.SocketPath), "linked.sock")
	if err := os.Symlink(fixture.inst.SocketPath, link); err != nil {
		t.Fatal(err)
	}
	if client, err := newSandboxClient(link, fixture.inst.ServerUID, fixture.inst.ID, fixture.inst.Generation, fixture.nonce); err == nil {
		_ = client.close()
		t.Fatal("symlink socket accepted")
	}
}

func TestSharedSandboxClientNeverRetriesWrongLaunchNonce(t *testing.T) {
	fixture := newHarnessTransport(t)
	fixture.nonce[0] ^= 1
	client := fixture.client(t)
	first := client.handshake(context.Background())
	second := client.handshake(context.Background())
	if first == nil || second == nil || connect.CodeOf(first) != connect.CodeOf(second) {
		t.Fatalf("nonce failure changed: %v, %v", first, second)
	}
	if fixture.runner.StartCount() != 0 {
		t.Fatal("bad nonce executed")
	}
}

func TestSharedSandboxClientSessionStopClosesTransportAuthority(t *testing.T) {
	fixture := newHarnessTransport(t)
	client := fixture.client(t)
	if err := client.handshake(context.Background()); err != nil {
		t.Fatal(err)
	}
	session := &sessionSandbox{sessionID: "session-harness", sandboxID: fixture.inst.ID, generation: fixture.inst.Generation, exec: newExecutor(client, fixture.inst, "nsjail", fixture.environment)}
	session.stop("test")
	if session.exec != nil {
		t.Fatal("stop retained executor")
	}
	if err := client.handshake(context.Background()); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("stopped client retained authority: %v", err)
	}
	if err := client.close(); err != nil {
		t.Fatal(err)
	}
}
