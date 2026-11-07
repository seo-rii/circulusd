package sandboxd_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/sandboxd"
)

func completedAttachmentProcess(t *testing.T, supervisor *sandboxd.Supervisor, runner *sandboxd.FakeRunner) sandboxd.ProcessHandle {
	t.Helper()
	created, err := supervisor.Spawn(context.Background(), validSpawnRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	process := nextFakeProcess(t, runner)
	if err := process.EmitStdout([]byte("retained output")); err != nil {
		t.Fatal(err)
	}
	process.Complete(sandboxd.RunResult{})
	if _, err := supervisor.Wait(context.Background(), created.Handle); err != nil {
		t.Fatal(err)
	}
	return created.Handle
}

func TestAttachmentCapacityIncludesCompletedReplay(t *testing.T) {
	supervisor, runner := newFakeSupervisor(t, sandboxd.Config{MaximumAttachments: 1})
	handle := completedAttachmentProcess(t, supervisor, runner)
	first, err := supervisor.Attach(context.Background(), handle, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := supervisor.Attach(context.Background(), handle, 0); !errors.Is(err, sandboxd.ErrAttachmentLimit) {
		t.Fatalf("Attach while completed replay is retained = %v, want capacity limit", err)
	}
	first.Close()
	if _, ok := <-first.Events; ok {
		t.Fatal("Close retained unread payloads after releasing capacity")
	}
	second, err := supervisor.Attach(context.Background(), handle, 0)
	if err != nil {
		t.Fatalf("Attach after Close = %v", err)
	}
	defer second.Close()
	events, err := collectAttachment(t, second)
	if err != nil {
		t.Fatal(err)
	}
	var output string
	for _, event := range events {
		if event.Type == sandboxd.EventStdout {
			output += string(event.Data)
		}
	}
	if output != "retained output" {
		t.Fatalf("closing a copy changed retained process history: %q", output)
	}
}

func TestAttachmentCancellationReleasesCompletedReplay(t *testing.T) {
	supervisor, runner := newFakeSupervisor(t, sandboxd.Config{MaximumAttachments: 1})
	handle := completedAttachmentProcess(t, supervisor, runner)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first, err := supervisor.Attach(ctx, handle, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	cancel()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		next, err := supervisor.Attach(context.Background(), handle, 0)
		if err == nil {
			next.Close()
			if _, ok := <-first.Events; ok {
				t.Fatal("cancellation released capacity without discarding copied replay")
			}
			return
		}
		if !errors.Is(err, sandboxd.ErrAttachmentLimit) {
			t.Fatal(err)
		}
		select {
		case <-tick.C:
		case <-timer.C:
			t.Fatal("cancellation did not release completed replay capacity")
		}
	}
}

func TestAttachmentCapacityIsSharedAcrossProcesses(t *testing.T) {
	supervisor, runner := newFakeSupervisor(t, sandboxd.Config{MaximumAttachments: 1})
	firstHandle := completedAttachmentProcess(t, supervisor, runner)
	request := validSpawnRequest(t)
	request.RequestID, request.ProcessID, request.InvocationID = "second-request", "second-process", "second-invocation"
	second, err := supervisor.Spawn(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	nextFakeProcess(t, runner).Complete(sandboxd.RunResult{})
	if _, err := supervisor.Wait(context.Background(), second.Handle); err != nil {
		t.Fatal(err)
	}
	first, err := supervisor.Attach(context.Background(), firstHandle, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := supervisor.Attach(context.Background(), second.Handle, 0); !errors.Is(err, sandboxd.ErrAttachmentLimit) {
		t.Fatalf("second process bypassed the sandbox attachment limit: %v", err)
	}
	first.Close()
	attachment, err := supervisor.Attach(context.Background(), second.Handle, 0)
	if err != nil {
		t.Fatal(err)
	}
	attachment.Close()
}

func TestConcurrentAttachmentsRespectGlobalCapacity(t *testing.T) {
	const capacity, callers = 4, 32
	supervisor, runner := newFakeSupervisor(t, sandboxd.Config{MaximumAttachments: capacity})
	handle := completedAttachmentProcess(t, supervisor, runner)
	start := make(chan struct{})
	accepted := make(chan *sandboxd.Attachment, callers)
	errorsSeen := make(chan error, callers)
	var group sync.WaitGroup
	for range callers {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			attachment, err := supervisor.Attach(context.Background(), handle, 0)
			if err != nil {
				errorsSeen <- err
				return
			}
			accepted <- attachment
		}()
	}
	close(start)
	group.Wait()
	close(accepted)
	close(errorsSeen)
	count := 0
	for attachment := range accepted {
		count++
		attachment.Close()
		attachment.Close()
	}
	if count != capacity {
		t.Fatalf("accepted %d simultaneous attachments, want %d", count, capacity)
	}
	for err := range errorsSeen {
		if !errors.Is(err, sandboxd.ErrAttachmentLimit) {
			t.Fatal(err)
		}
	}
	next, err := supervisor.Attach(context.Background(), handle, 0)
	if err != nil {
		t.Fatalf("capacity leaked after repeated Close: %v", err)
	}
	next.Close()
}
