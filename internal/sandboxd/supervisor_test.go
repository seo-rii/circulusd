package sandboxd_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/sandboxd"
)

func TestSupervisorSpawnAttachWaitAndIdempotency(t *testing.T) {
	t.Parallel()

	supervisor, runner := newFakeSupervisor(t, sandboxd.Config{})
	request := validSpawnRequest(t)
	created, err := supervisor.Spawn(context.Background(), request)
	if err != nil {
		t.Fatalf("Spawn() error = %v", err)
	}
	if created.Reused || created.Handle.IsZero() || created.Handle.Generation() != 7 {
		t.Fatalf("Spawn() = %#v", created)
	}
	reused, err := supervisor.Spawn(context.Background(), request)
	if err != nil {
		t.Fatalf("second Spawn() error = %v", err)
	}
	if !reused.Reused || reused.Handle != created.Handle {
		t.Fatalf("second Spawn() = %#v, want reused handle", reused)
	}
	if runner.StartCount() != 1 {
		t.Fatalf("runner start count = %d, want 1", runner.StartCount())
	}

	process := nextFakeProcess(t, runner)
	attachment, err := supervisor.Attach(context.Background(), created.Handle, 0)
	if err != nil {
		t.Fatalf("Attach() error = %v", err)
	}
	if err := process.EmitStdout([]byte("out")); err != nil {
		t.Fatalf("EmitStdout() error = %v", err)
	}
	if err := process.EmitStderr([]byte("err")); err != nil {
		t.Fatalf("EmitStderr() error = %v", err)
	}
	process.Complete(sandboxd.RunResult{ExitCode: 0})

	result, err := supervisor.Wait(context.Background(), created.Handle)
	if err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	if result.Reason != sandboxd.ExitReasonExited || result.ExitCode != 0 {
		t.Fatalf("Wait() = %#v", result)
	}

	events, streamErr := collectAttachment(t, attachment)
	if streamErr != nil {
		t.Fatalf("attachment error = %v", streamErr)
	}
	if len(events) != 4 {
		t.Fatalf("events = %#v, want started/stdout/stderr/exit", events)
	}
	seenOutput := map[sandboxd.EventType]string{}
	for i, event := range events {
		if event.Sequence != uint64(i+1) {
			t.Fatalf("event %d sequence = %d", i, event.Sequence)
		}
		if event.Type == sandboxd.EventStdout || event.Type == sandboxd.EventStderr {
			seenOutput[event.Type] += string(event.Data)
		}
	}
	if events[0].Type != sandboxd.EventStarted || events[len(events)-1].Type != sandboxd.EventExit {
		t.Fatalf("terminal event ordering = %#v", events)
	}
	if seenOutput[sandboxd.EventStdout] != "out" || seenOutput[sandboxd.EventStderr] != "err" {
		t.Fatalf("output events = %#v", seenOutput)
	}

	changed := request
	changed.Arguments = []string{"different"}
	if _, err := supervisor.Spawn(context.Background(), changed); !errors.Is(err, sandboxd.ErrIDConflict) {
		t.Fatalf("Spawn(same request ID, changed body) error = %v, want ErrIDConflict", err)
	}
	changed = request
	changed.RequestID = "request-2"
	if _, err := supervisor.Spawn(context.Background(), changed); !errors.Is(err, sandboxd.ErrIDConflict) {
		t.Fatalf("Spawn(same process ID, changed request ID) error = %v, want ErrIDConflict", err)
	}
}

func TestSupervisorConcurrentDuplicateSpawnStartsOnce(t *testing.T) {
	t.Parallel()

	supervisor, runner := newFakeSupervisor(t, sandboxd.Config{})
	request := validSpawnRequest(t)

	const callers = 64
	start := make(chan struct{})
	results := make(chan sandboxd.SpawnResult, callers)
	errs := make(chan error, callers)
	for range callers {
		go func() {
			<-start
			result, err := supervisor.Spawn(context.Background(), request)
			if err != nil {
				errs <- err
				return
			}
			results <- result
		}()
	}
	close(start)

	var handle sandboxd.ProcessHandle
	created := 0
	for range callers {
		select {
		case err := <-errs:
			t.Fatalf("concurrent Spawn() error = %v", err)
		case result := <-results:
			if handle.IsZero() {
				handle = result.Handle
			}
			if result.Handle != handle {
				t.Fatalf("concurrent Spawn() handle = %v, want %v", result.Handle, handle)
			}
			if !result.Reused {
				created++
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for concurrent Spawn()")
		}
	}
	if created != 1 || runner.StartCount() != 1 {
		t.Fatalf("created = %d, runner starts = %d; want 1 and 1", created, runner.StartCount())
	}

	process := nextFakeProcess(t, runner)
	process.Complete(sandboxd.RunResult{ExitCode: 0})
	if _, err := supervisor.Wait(context.Background(), handle); err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
}

func TestSupervisorAttachReconnectReplaysFromSequence(t *testing.T) {
	t.Parallel()

	supervisor, runner := newFakeSupervisor(t, sandboxd.Config{})
	created, err := supervisor.Spawn(context.Background(), validSpawnRequest(t))
	if err != nil {
		t.Fatalf("Spawn() error = %v", err)
	}
	process := nextFakeProcess(t, runner)
	first, err := supervisor.Attach(context.Background(), created.Handle, 0)
	if err != nil {
		t.Fatalf("Attach() error = %v", err)
	}

	started := <-first.Events
	if started.Type != sandboxd.EventStarted || started.Sequence != 1 {
		t.Fatalf("first event = %#v", started)
	}
	if err := process.EmitStdout([]byte("first")); err != nil {
		t.Fatalf("EmitStdout(first) error = %v", err)
	}
	firstOutput := <-first.Events
	if firstOutput.Type != sandboxd.EventStdout {
		t.Fatalf("first output = %#v", firstOutput)
	}
	first.Close()

	if err := process.EmitStdout([]byte("second")); err != nil {
		t.Fatalf("EmitStdout(second) error = %v", err)
	}
	process.Complete(sandboxd.RunResult{ExitCode: 0})
	if _, err := supervisor.Wait(context.Background(), created.Handle); err != nil {
		t.Fatalf("Wait() error = %v", err)
	}

	reconnected, err := supervisor.Attach(context.Background(), created.Handle, firstOutput.Sequence)
	if err != nil {
		t.Fatalf("Attach(reconnect) error = %v", err)
	}
	events, streamErr := collectAttachment(t, reconnected)
	if streamErr != nil {
		t.Fatalf("reconnected attachment error = %v", streamErr)
	}
	if len(events) != 2 || events[0].Type != sandboxd.EventStdout || string(events[0].Data) != "second" || events[1].Type != sandboxd.EventExit {
		t.Fatalf("reconnected events = %#v", events)
	}
}

func TestSupervisorConcurrentReconnectHasNoSequenceGaps(t *testing.T) {
	t.Parallel()

	supervisor, runner := newFakeSupervisor(t, sandboxd.Config{
		ReplayLimitBytes:  4096,
		ReplayLimitEvents: 256,
		SubscriberBuffer:  128,
	})
	created, err := supervisor.Spawn(context.Background(), validSpawnRequest(t))
	if err != nil {
		t.Fatalf("Spawn() error = %v", err)
	}
	process := nextFakeProcess(t, runner)

	type attachmentResult struct {
		events []sandboxd.ProcessEvent
		err    error
	}
	const clients = 32
	start := make(chan struct{})
	attachments := make(chan attachmentResult, clients)
	for range clients {
		go func() {
			<-start
			attachment, err := supervisor.Attach(context.Background(), created.Handle, 0)
			if err != nil {
				attachments <- attachmentResult{err: err}
				return
			}
			var events []sandboxd.ProcessEvent
			for event := range attachment.Events {
				events = append(events, event)
			}
			attachments <- attachmentResult{events: events, err: <-attachment.Done}
		}()
	}
	close(start)

	emitErr := make(chan error, 1)
	go func() {
		for i := range 40 {
			if err := process.EmitStdout([]byte{byte(i)}); err != nil {
				emitErr <- err
				return
			}
		}
		process.Complete(sandboxd.RunResult{ExitCode: 0})
		emitErr <- nil
	}()

	for range clients {
		select {
		case result := <-attachments:
			if result.err != nil {
				t.Fatalf("concurrent Attach() error = %v", result.err)
			}
			if len(result.events) != 42 {
				t.Fatalf("concurrent Attach() received %d events, want 42", len(result.events))
			}
			for i, event := range result.events {
				if event.Sequence != uint64(i+1) {
					t.Fatalf("event %d sequence = %d, want %d", i, event.Sequence, i+1)
				}
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for concurrent Attach()")
		}
	}
	if err := <-emitErr; err != nil {
		t.Fatalf("EmitStdout() error = %v", err)
	}
}

func TestSupervisorDisconnectsSlowClientAndBoundsReplay(t *testing.T) {
	t.Parallel()

	supervisor, runner := newFakeSupervisor(t, sandboxd.Config{
		ReplayLimitBytes:  1024,
		ReplayLimitEvents: 3,
		SubscriberBuffer:  1,
		ReadChunkBytes:    1,
	})
	request := validSpawnRequest(t)
	request.OutputLimitBytes = 1024
	created, err := supervisor.Spawn(context.Background(), request)
	if err != nil {
		t.Fatalf("Spawn() error = %v", err)
	}
	process := nextFakeProcess(t, runner)
	slow, err := supervisor.Attach(context.Background(), created.Handle, 0)
	if err != nil {
		t.Fatalf("Attach() error = %v", err)
	}

	for _, output := range []string{"a", "b", "c", "d"} {
		if err := process.EmitStdout([]byte(output)); err != nil {
			t.Fatalf("EmitStdout(%q) error = %v", output, err)
		}
	}
	select {
	case streamErr := <-slow.Done:
		if !errors.Is(streamErr, sandboxd.ErrOutputBackpressure) {
			t.Fatalf("slow attachment error = %v, want ErrOutputBackpressure", streamErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("slow attachment was not disconnected")
	}
	process.Complete(sandboxd.RunResult{ExitCode: 0})
	if _, err := supervisor.Wait(context.Background(), created.Handle); err != nil {
		t.Fatalf("Wait() error = %v", err)
	}

	if _, err := supervisor.Attach(context.Background(), created.Handle, 0); !errors.Is(err, sandboxd.ErrReplayUnavailable) {
		t.Fatalf("Attach(evicted cursor) error = %v, want ErrReplayUnavailable", err)
	}
}

func TestSupervisorRejectsCursorWhenReplayIsFullyEvicted(t *testing.T) {
	t.Parallel()

	supervisor, runner := newFakeSupervisor(t, sandboxd.Config{
		ReplayLimitBytes:  1,
		ReplayLimitEvents: 16,
		SubscriberBuffer:  4,
		ReadChunkBytes:    64,
	})
	created, err := supervisor.Spawn(context.Background(), validSpawnRequest(t))
	if err != nil {
		t.Fatalf("Spawn() error = %v", err)
	}
	process := nextFakeProcess(t, runner)
	current, err := supervisor.Attach(context.Background(), created.Handle, 0)
	if err != nil {
		t.Fatalf("Attach() error = %v", err)
	}
	if event := <-current.Events; event.Type != sandboxd.EventStarted {
		t.Fatalf("first event = %#v", event)
	}
	if err := process.EmitStdout([]byte("larger-than-replay")); err != nil {
		t.Fatalf("EmitStdout() error = %v", err)
	}
	if event := <-current.Events; event.Type != sandboxd.EventStdout {
		t.Fatalf("output event = %#v", event)
	}
	current.Close()

	if _, err := supervisor.Attach(context.Background(), created.Handle, 0); !errors.Is(err, sandboxd.ErrReplayUnavailable) {
		t.Fatalf("Attach(fully evicted cursor) error = %v, want ErrReplayUnavailable", err)
	}
	process.Complete(sandboxd.RunResult{ExitCode: 0})
}

func TestSupervisorConcurrentStdinWaitSignalAndAttach(t *testing.T) {
	t.Parallel()

	supervisor, runner := newFakeSupervisor(t, sandboxd.Config{})
	created, err := supervisor.Spawn(context.Background(), validSpawnRequest(t))
	if err != nil {
		t.Fatalf("Spawn() error = %v", err)
	}
	process := nextFakeProcess(t, runner)

	const writers = 32
	var writes sync.WaitGroup
	writes.Add(writers)
	for i := range writers {
		go func() {
			defer writes.Done()
			payload := []byte(fmt.Sprintf("[%02d]", i))
			if err := supervisor.WriteStdin(context.Background(), created.Handle, payload); err != nil {
				t.Errorf("WriteStdin() error = %v", err)
			}
		}()
	}
	writes.Wait()
	if err := supervisor.CloseStdin(context.Background(), created.Handle); err != nil {
		t.Fatalf("CloseStdin() error = %v", err)
	}
	if err := supervisor.CloseStdin(context.Background(), created.Handle); err != nil {
		t.Fatalf("second CloseStdin() error = %v", err)
	}
	if err := supervisor.WriteStdin(context.Background(), created.Handle, []byte("late")); !errors.Is(err, sandboxd.ErrStdinClosed) {
		t.Fatalf("WriteStdin(closed) error = %v, want ErrStdinClosed", err)
	}
	stdin := process.StdinBytes()
	for i := range writers {
		if token := fmt.Sprintf("[%02d]", i); !bytes.Contains(stdin, []byte(token)) {
			t.Errorf("stdin is missing token %q: %q", token, stdin)
		}
	}

	const waiters = 16
	results := make(chan sandboxd.ProcessResult, waiters)
	errs := make(chan error, waiters)
	for range waiters {
		go func() {
			result, err := supervisor.Wait(context.Background(), created.Handle)
			if err != nil {
				errs <- err
				return
			}
			results <- result
		}()
	}
	var signals sync.WaitGroup
	signals.Add(8)
	for range 8 {
		go func() {
			defer signals.Done()
			if err := supervisor.Signal(context.Background(), created.Handle, sandboxd.SignalInterrupt); err != nil {
				t.Errorf("Signal(interrupt) error = %v", err)
			}
		}()
	}
	signals.Wait()
	if err := supervisor.Signal(context.Background(), created.Handle, sandboxd.SignalCancel); err != nil {
		t.Fatalf("Signal(cancel) error = %v", err)
	}

	for range waiters {
		select {
		case err := <-errs:
			t.Fatalf("Wait() error = %v", err)
		case result := <-results:
			if result.Reason != sandboxd.ExitReasonCanceled {
				t.Fatalf("Wait().Reason = %q, want canceled", result.Reason)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for concurrent Wait()")
		}
	}
}

func TestSupervisorSignalRequestDoesNotOverrideActualExit(t *testing.T) {
	t.Parallel()

	supervisor, runner := newFakeSupervisor(t, sandboxd.Config{})
	created, err := supervisor.Spawn(context.Background(), validSpawnRequest(t))
	if err != nil {
		t.Fatalf("Spawn() error = %v", err)
	}
	process := nextFakeProcess(t, runner)
	if err := supervisor.Signal(context.Background(), created.Handle, sandboxd.SignalInterrupt); err != nil {
		t.Fatalf("Signal(interrupt) error = %v", err)
	}
	process.Complete(sandboxd.RunResult{ExitCode: 0})

	result, err := supervisor.Wait(context.Background(), created.Handle)
	if err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	if result.Reason != sandboxd.ExitReasonExited || result.Signal != "" {
		t.Fatalf("Wait() = %#v, want a normal exit", result)
	}
}

func TestSupervisorEnforcesOutputLimitAndDeadline(t *testing.T) {
	t.Parallel()

	t.Run("output limit", func(t *testing.T) {
		t.Parallel()

		supervisor, runner := newFakeSupervisor(t, sandboxd.Config{ReadChunkBytes: 64})
		request := validSpawnRequest(t)
		request.OutputLimitBytes = 4
		created, err := supervisor.Spawn(context.Background(), request)
		if err != nil {
			t.Fatalf("Spawn() error = %v", err)
		}
		process := nextFakeProcess(t, runner)
		if err := process.EmitStdout([]byte("abcdefghij")); err != nil {
			t.Fatalf("EmitStdout() error = %v", err)
		}
		result, err := supervisor.Wait(context.Background(), created.Handle)
		if err != nil {
			t.Fatalf("Wait() error = %v", err)
		}
		if result.Reason != sandboxd.ExitReasonOutputLimit {
			t.Fatalf("Wait().Reason = %q, want output-limit", result.Reason)
		}
		attachment, err := supervisor.Attach(context.Background(), created.Handle, 0)
		if err != nil {
			t.Fatalf("Attach() error = %v", err)
		}
		events, streamErr := collectAttachment(t, attachment)
		if streamErr != nil {
			t.Fatalf("attachment error = %v", streamErr)
		}
		var stdout strings.Builder
		for _, event := range events {
			if event.Type == sandboxd.EventStdout {
				stdout.Write(event.Data)
			}
		}
		if stdout.String() != "abcd" {
			t.Fatalf("replayed stdout = %q, want abcd", stdout.String())
		}
	})

	t.Run("expired deadline", func(t *testing.T) {
		t.Parallel()

		supervisor, runner := newFakeSupervisor(t, sandboxd.Config{})
		request := validSpawnRequest(t)
		request.Deadline = time.Now().Add(-time.Second)
		created, err := supervisor.Spawn(context.Background(), request)
		if err != nil {
			t.Fatalf("Spawn() error = %v", err)
		}
		_ = nextFakeProcess(t, runner)
		result, err := supervisor.Wait(context.Background(), created.Handle)
		if err != nil {
			t.Fatalf("Wait() error = %v", err)
		}
		if result.Reason != sandboxd.ExitReasonDeadline {
			t.Fatalf("Wait().Reason = %q, want deadline", result.Reason)
		}
	})
}

func TestSupervisorGenerationFenceRejectsOldHandlesAndAdmission(t *testing.T) {
	t.Parallel()

	supervisor, runner := newFakeSupervisor(t, sandboxd.Config{})
	created, err := supervisor.Spawn(context.Background(), validSpawnRequest(t))
	if err != nil {
		t.Fatalf("Spawn() error = %v", err)
	}
	_ = nextFakeProcess(t, runner)
	if err := supervisor.Fence(8); err != nil {
		t.Fatalf("Fence() error = %v", err)
	}
	if err := supervisor.Fence(8); !errors.Is(err, sandboxd.ErrInvalidGeneration) {
		t.Fatalf("second Fence() error = %v, want ErrInvalidGeneration", err)
	}
	if _, err := supervisor.Wait(context.Background(), created.Handle); !errors.Is(err, sandboxd.ErrStaleGeneration) {
		t.Fatalf("Wait(stale) error = %v, want ErrStaleGeneration", err)
	}
	if err := supervisor.Signal(context.Background(), created.Handle, sandboxd.SignalCancel); !errors.Is(err, sandboxd.ErrStaleGeneration) {
		t.Fatalf("Signal(stale) error = %v, want ErrStaleGeneration", err)
	}
	if _, err := supervisor.Spawn(context.Background(), validSpawnRequest(t)); !errors.Is(err, sandboxd.ErrSandboxFenced) {
		t.Fatalf("Spawn(fenced) error = %v, want ErrSandboxFenced", err)
	}
}

func newFakeSupervisor(t *testing.T, overrides sandboxd.Config) (*sandboxd.Supervisor, *sandboxd.FakeRunner) {
	t.Helper()

	runner := sandboxd.NewFakeRunner()
	config := sandboxd.Config{
		Authority: sandboxd.LaunchAuthority{
			SandboxID:  "sandbox-test",
			Generation: 7,
		},
		WorkspaceRoot:     "/trusted/workspace",
		Commands:          map[string]string{"tool": "/trusted/bin/tool"},
		Runner:            runner,
		ReplayLimitBytes:  4096,
		ReplayLimitEvents: 128,
		SubscriberBuffer:  16,
		ReadChunkBytes:    64,
	}
	if overrides.ReplayLimitBytes != 0 {
		config.ReplayLimitBytes = overrides.ReplayLimitBytes
	}
	if overrides.ReplayLimitEvents != 0 {
		config.ReplayLimitEvents = overrides.ReplayLimitEvents
	}
	if overrides.SubscriberBuffer != 0 {
		config.SubscriberBuffer = overrides.SubscriberBuffer
	}
	if overrides.ReadChunkBytes != 0 {
		config.ReadChunkBytes = overrides.ReadChunkBytes
	}
	supervisor, err := sandboxd.NewSupervisor(config)
	if err != nil {
		t.Fatalf("NewSupervisor() error = %v", err)
	}
	return supervisor, runner
}

func validSpawnRequest(t *testing.T) sandboxd.SpawnRequest {
	t.Helper()

	command, err := sandboxd.ParseCommandName("tool")
	if err != nil {
		t.Fatalf("ParseCommandName() error = %v", err)
	}
	workingDirectory, err := sandboxd.ParseWorkspacePath("")
	if err != nil {
		t.Fatalf("ParseWorkspacePath() error = %v", err)
	}
	return sandboxd.SpawnRequest{
		RequestID:        "request-1",
		ProcessID:        "process-1",
		InvocationID:     "invocation-1",
		Command:          command,
		Arguments:        []string{"arg"},
		WorkingDirectory: workingDirectory,
		StdinMode:        sandboxd.StdinStream,
		OutputLimitBytes: 1024,
	}
}

func nextFakeProcess(t *testing.T, runner *sandboxd.FakeRunner) *sandboxd.FakeProcess {
	t.Helper()

	select {
	case process := <-runner.Started():
		return process
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for fake process start")
		return nil
	}
}

func collectAttachment(t *testing.T, attachment *sandboxd.Attachment) ([]sandboxd.ProcessEvent, error) {
	t.Helper()

	var events []sandboxd.ProcessEvent
	for event := range attachment.Events {
		events = append(events, event)
	}
	return events, <-attachment.Done
}
