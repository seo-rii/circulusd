//go:build linux

package sandboxd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestDevelopmentExecStdinCancelsPartiallyWrittenPipe(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		name := "cancel"
		if deadline {
			name = "deadline"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			defer writer.Close()
			capacity := stdinPipeValue(t, writer, false)
			payload := bytes.Repeat([]byte("x"), capacity*2)
			ctx, cancel := context.WithCancel(context.Background())
			wantError := context.Canceled
			if deadline {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
				wantError = context.DeadlineExceeded
			}
			defer cancel()
			type writeResult struct {
				count int
				err   error
			}
			result := make(chan writeResult, 1)
			stdin := &developmentExecStdin{pipe: writer}
			go func() {
				count, err := stdin.WriteContext(ctx, payload)
				result <- writeResult{count: count, err: err}
			}()
			// Seeing a byte proves the write has delivered a prefix. The rest
			// exceeds the pipe capacity and cannot complete without a reader.
			first := make([]byte, 1)
			if _, err := io.ReadFull(reader, first); err != nil {
				t.Fatal(err)
			}
			if !deadline {
				cancel()
			}
			select {
			case got := <-result:
				if !errors.Is(got.err, wantError) || got.count == 0 || got.count >= len(payload) {
					t.Fatalf("WriteContext() = (%d, %v), want partial write and %v", got.count, got.err, wantError)
				}
				remaining, err := io.ReadAll(reader)
				if err != nil || len(remaining)+1 != got.count {
					t.Fatalf("drain after cancellation = (%d bytes, %v), want %d bytes and EOF", len(remaining)+1, err, got.count)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("canceled pipe write did not return")
			}
		})
	}
}

func TestSupervisorExecStdinBoundsQueuedWritesAndClose(t *testing.T) {
	t.Parallel()
	command, _ := ParseCommandName("sleep")
	workingDirectory, _ := ParseWorkspacePath("")
	supervisor, err := NewSupervisor(Config{
		Authority:         LaunchAuthority{SandboxID: "stdin-cancellation", Generation: 1},
		WorkspaceRoot:     t.TempDir(),
		Commands:          map[string]string{"sleep": "/bin/sleep"},
		Runner:            NewDevelopmentExecRunner(),
		ReplayLimitBytes:  1024,
		ReplayLimitEvents: 16,
		SubscriberBuffer:  4,
		ReadChunkBytes:    64,
	})
	if err != nil {
		t.Fatal(err)
	}
	created, err := supervisor.Spawn(context.Background(), SpawnRequest{
		RequestID: "request", ProcessID: "process", InvocationID: "invocation",
		Command: command, WorkingDirectory: workingDirectory, Arguments: []string{"30"},
		StdinMode: StdinStream, OutputLimitBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = supervisor.Signal(context.Background(), created.Handle, SignalKill)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := supervisor.Wait(ctx, created.Handle); err != nil {
			t.Errorf("cleanup Wait() error = %v", err)
		}
	})
	record, err := supervisor.processForHandle(created.Handle)
	if err != nil {
		t.Fatal(err)
	}
	pipe := record.stdin.(*developmentExecStdin).pipe.(*os.File)
	capacity := stdinPipeValue(t, pipe, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	writeDone := make(chan error, 1)
	go func() {
		writeDone <- supervisor.WriteStdin(ctx, created.Handle, bytes.Repeat([]byte("x"), capacity*2))
	}()
	until := time.Now().Add(3 * time.Second)
	for stdinPipeValue(t, pipe, true) == 0 {
		if time.Now().After(until) {
			t.Fatal("native write did not reach the non-reading process")
		}
		time.Sleep(time.Millisecond)
	}
	queuedContext, cancelQueued := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelQueued()
	queued := make(chan error, 2)
	go func() { queued <- supervisor.WriteStdin(queuedContext, created.Handle, []byte("late")) }()
	go func() { queued <- supervisor.CloseStdin(queuedContext, created.Handle) }()
	for range 2 {
		select {
		case err := <-queued:
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("queued stdin operation error = %v, want deadline exceeded", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("queued stdin operation ignored its deadline")
		}
	}
	select {
	case err := <-writeDone:
		t.Fatalf("queued cancellation interrupted the admitted write: %v", err)
	default:
	}
	cancel()
	select {
	case err := <-writeDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("WriteStdin() error = %v, want canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("admitted stdin write ignored cancellation")
	}
	if err := supervisor.WriteStdin(context.Background(), created.Handle, []byte("retry")); !errors.Is(err, ErrStdinClosed) {
		t.Fatalf("WriteStdin(partial retry) error = %v, want stdin closed", err)
	}
	if err := supervisor.CloseStdin(context.Background(), created.Handle); err != nil {
		t.Fatalf("CloseStdin(after canceled write) error = %v", err)
	}
}

func stdinPipeValue(t *testing.T, pipe *os.File, pending bool) int {
	t.Helper()
	connection, err := pipe.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var value int
	var syscallErr error
	err = connection.Control(func(fd uintptr) {
		if pending {
			value, syscallErr = unix.IoctlGetInt(int(fd), unix.TIOCINQ)
		} else {
			value, syscallErr = unix.FcntlInt(fd, unix.F_GETPIPE_SZ, 0)
		}
	})
	if err != nil || syscallErr != nil {
		t.Fatalf("inspect pipe: %v", errors.Join(err, syscallErr))
	}
	return value
}
