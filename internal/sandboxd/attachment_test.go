package sandboxd

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAttachmentWatcherPreservesBackpressureResult(t *testing.T) {
	for _, liveWatcher := range []bool{false, true} {
		name := "completion-before-watcher"
		if liveWatcher {
			name = "cancellable-attachment"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			runner := NewFakeRunner()
			supervisor, err := NewSupervisor(Config{
				Authority:     LaunchAuthority{SandboxID: "attachment-watch", Generation: 1},
				WorkspaceRoot: "/workspace", Commands: map[string]string{"tool": "/bin/tool"},
				Runner: runner, ReplayLimitBytes: 1024, ReplayLimitEvents: 16,
				SubscriberBuffer: 1, ReadChunkBytes: 1,
			})
			if err != nil {
				t.Fatal(err)
			}
			command, _ := ParseCommandName("tool")
			workingDirectory, _ := ParseWorkspacePath("")
			created, err := supervisor.Spawn(context.Background(), SpawnRequest{
				RequestID: "request", ProcessID: "process", InvocationID: "invocation",
				Command: command, WorkingDirectory: workingDirectory,
				StdinMode: StdinClosed, OutputLimitBytes: 1024,
			})
			if err != nil {
				t.Fatal(err)
			}
			process := <-runner.Started()
			defer process.Complete(RunResult{ExitCode: 0})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			attachmentContext := context.Background()
			if liveWatcher {
				attachmentContext = ctx
			}
			attachment, err := supervisor.Attach(attachmentContext, created.Handle, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer attachment.Close()
			record, err := supervisor.processForHandle(created.Handle)
			if err != nil {
				t.Fatal(err)
			}
			record.mu.Lock()
			subscriber := record.subscribers[record.nextSubscriberID]
			record.mu.Unlock()
			for _, value := range []byte("abcd") {
				if err := process.EmitStdout([]byte{value}); err != nil {
					t.Fatal(err)
				}
			}
			for range attachment.Events {
			}
			// Run the actual watcher body to completion before reading Done.
			// This deterministically detects a watcher stealing the public error
			// without relying on a sleep or racing the caller against it.
			watcherDone := make(chan struct{})
			go func() {
				supervisor.watchAttachment(ctx, record, subscriber)
				close(watcherDone)
			}()
			select {
			case <-watcherDone:
			case <-time.After(3 * time.Second):
				t.Fatal("watcher did not observe attachment completion")
			}
			if err := <-attachment.Done; !errors.Is(err, ErrOutputBackpressure) {
				t.Fatalf("attachment result = %v, want output backpressure", err)
			}
			if _, open := <-attachment.Done; open {
				t.Fatal("attachment result channel did not close after its one error")
			}
		})
	}
}
