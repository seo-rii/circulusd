//go:build linux

package sandboxrpc

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/sandboxd"
	"google.golang.org/protobuf/proto"
)

func TestSandboxWireStdinCancellationSettlesReceiptsAndFencesPartialRetry(t *testing.T) {
	t.Parallel()
	stdin := &blockedRPCStdin{entered: make(chan struct{}), closed: make(chan struct{})}
	fake := sandboxd.NewFakeRunner()
	server, client := startTestTransportWithRunner(t, &blockedStdinRunner{Runner: fake, stdin: stdin})
	defer server.Close()
	defer client.Close()
	spawned, err := client.Spawn(context.Background(), validSpawnRequest("stdin-cancel-spawn", "stdin-cancel-invocation"))
	if err != nil {
		t.Fatal(err)
	}
	process := nextFakeProcess(t, fake)
	defer process.Complete(sandboxd.RunResult{ExitCode: 0})
	write := &v1.WriteStdinRequest{
		Meta: idempotentMeta("stdin-admitted-01"), Process: spawned.GetProcess(),
		ChunkSequence: 1, Data: []byte("delivered-prefix-and-blocked-suffix"),
	}
	writeContext, cancelWrite := context.WithCancel(context.Background())
	defer cancelWrite()
	writeDone := make(chan error, 1)
	go func() {
		_, err := client.WriteStdin(writeContext, write)
		writeDone <- err
	}()
	select {
	case <-stdin.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("stdin request did not reach the writer")
	}
	admitted := waitStdinOperation(t, server, "write-stdin", "stdin-admitted-01")
	queuedContext, cancelQueued := context.WithCancel(context.Background())
	defer cancelQueued()
	queued := make(chan error, 2)
	go func() {
		_, err := client.WriteStdin(queuedContext, &v1.WriteStdinRequest{
			Meta: idempotentMeta("stdin-queued-0001"), Process: spawned.GetProcess(),
			ChunkSequence: 2, Data: []byte("must-not-be-written"),
		})
		queued <- err
	}()
	go func() {
		_, err := client.CloseStdin(queuedContext, &v1.CloseStdinRequest{
			Meta: idempotentMeta("stdin-close-00001"), Process: spawned.GetProcess(),
		})
		queued <- err
	}()
	queuedWrite := waitStdinOperation(t, server, "write-stdin", "stdin-queued-0001")
	queuedClose := waitStdinOperation(t, server, "close-stdin", "stdin-close-00001")
	cancelQueued()
	for range 2 {
		select {
		case err := <-queued:
			if connect.CodeOf(err) != connect.CodeCanceled {
				t.Fatalf("queued client operation error = %v, want canceled", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("queued client stdin operation ignored cancellation")
		}
	}
	for _, call := range []*operationCall{queuedWrite, queuedClose} {
		select {
		case <-call.done:
			if connect.CodeOf(call.err) != connect.CodeCanceled {
				t.Fatalf("queued server receipt error = %v, want canceled", call.err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("queued server operation remained in flight after client cancellation")
		}
	}
	select {
	case <-admitted.done:
		t.Fatal("queued cancellation interrupted another admitted stdin request")
	default:
	}
	cancelWrite()
	select {
	case err := <-writeDone:
		if connect.CodeOf(err) != connect.CodeCanceled {
			t.Fatalf("admitted client operation error = %v, want canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("admitted client stdin operation ignored cancellation")
	}
	select {
	case <-admitted.done:
		if connect.CodeOf(admitted.err) != connect.CodeCanceled {
			t.Fatalf("admitted server receipt error = %v, want canceled", admitted.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("admitted server operation remained in flight after client cancellation")
	}
	// A same-key retry returns the recorded result. A fresh key cannot resend
	// the partial prefix because the supervisor permanently closed this input.
	if _, err := client.WriteStdin(context.Background(), write); connect.CodeOf(err) != connect.CodeCanceled {
		t.Fatalf("same-key retry error = %v, want recorded canceled result", err)
	}
	fresh := proto.Clone(write).(*v1.WriteStdinRequest)
	fresh.Meta = idempotentMeta("stdin-fresh-retry")
	if _, err := client.WriteStdin(context.Background(), fresh); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("fresh-key partial retry error = %v, want failed precondition", err)
	}
	stdin.mu.Lock()
	writes, delivered := stdin.writes, append([]byte(nil), stdin.delivered...)
	stdin.mu.Unlock()
	if writes != 1 || !bytes.Equal(delivered, write.Data[:2]) {
		t.Fatalf("stdin received %d writes and %q, want one original prefix", writes, delivered)
	}
	if signals := process.Signals(); len(signals) != 0 {
		t.Fatalf("stdin cancellation signaled the process: %v", signals)
	}
}

type blockedStdinRunner struct {
	sandboxd.Runner
	stdin *blockedRPCStdin
}

func (runner *blockedStdinRunner) Start(ctx context.Context, spec sandboxd.RunSpec) (sandboxd.RunningProcess, error) {
	process, err := runner.Runner.Start(ctx, spec)
	if err != nil {
		return nil, err
	}
	return &blockedStdinProcess{RunningProcess: process, stdin: runner.stdin}, nil
}

type blockedStdinProcess struct {
	sandboxd.RunningProcess
	stdin *blockedRPCStdin
}

func (process *blockedStdinProcess) Stdin() sandboxd.ProcessStdin {
	return process.stdin
}

type blockedRPCStdin struct {
	mu        sync.Mutex
	writes    int
	delivered []byte
	entered   chan struct{}
	closed    chan struct{}
	enterOnce sync.Once
	closeOnce sync.Once
}

func (stdin *blockedRPCStdin) WriteContext(ctx context.Context, data []byte) (int, error) {
	stdin.mu.Lock()
	count := min(2, len(data))
	stdin.delivered = append(stdin.delivered, data[:count]...)
	stdin.writes++
	stdin.mu.Unlock()
	stdin.enterOnce.Do(func() { close(stdin.entered) })
	select {
	case <-ctx.Done():
		return count, ctx.Err()
	case <-stdin.closed:
		return count, io.ErrClosedPipe
	}
}

func (stdin *blockedRPCStdin) Close() error {
	stdin.closeOnce.Do(func() { close(stdin.closed) })
	return nil
}

func waitStdinOperation(t *testing.T, server *Server, method, key string) *operationCall {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		server.handler.mu.Lock()
		call := server.handler.operations[method+"\x00"+string(idempotentMeta(key).GetIdempotencyKey())]
		server.handler.mu.Unlock()
		if call != nil {
			return call
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s request did not reach the operation ledger", method)
		}
		time.Sleep(time.Millisecond)
	}
}
