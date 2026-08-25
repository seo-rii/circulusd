package sandboxd_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/hancomac/circulusd/internal/sandboxd"
)

func TestDevelopmentExecRunnerSmoke(t *testing.T) {
	t.Parallel()

	const shell = "/bin/sh"
	if _, err := os.Stat(shell); err != nil {
		t.Skipf("development shell unavailable: %v", err)
	}
	command, err := sandboxd.ParseCommandName("shell")
	if err != nil {
		t.Fatalf("ParseCommandName() error = %v", err)
	}
	workingDirectory, err := sandboxd.ParseWorkspacePath("")
	if err != nil {
		t.Fatalf("ParseWorkspacePath() error = %v", err)
	}
	supervisor, err := sandboxd.NewSupervisor(sandboxd.Config{
		Authority: sandboxd.LaunchAuthority{
			SandboxID:  "exec-runner-test",
			Generation: 1,
		},
		WorkspaceRoot:     t.TempDir(),
		Commands:          map[string]string{"shell": shell},
		Runner:            sandboxd.NewDevelopmentExecRunner(),
		ReplayLimitBytes:  4096,
		ReplayLimitEvents: 64,
		SubscriberBuffer:  8,
		ReadChunkBytes:    64,
	})
	if err != nil {
		t.Fatalf("NewSupervisor() error = %v", err)
	}
	created, err := supervisor.Spawn(context.Background(), sandboxd.SpawnRequest{
		RequestID:        "exec-request",
		ProcessID:        "exec-process",
		InvocationID:     "exec-invocation",
		Command:          command,
		Arguments:        []string{"-c", "printf stdout; printf stderr >&2"},
		WorkingDirectory: workingDirectory,
		StdinMode:        sandboxd.StdinClosed,
		OutputLimitBytes: 1024,
	})
	if err != nil {
		t.Fatalf("Spawn() error = %v", err)
	}
	result, err := supervisor.Wait(context.Background(), created.Handle)
	if err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	if result.Reason != sandboxd.ExitReasonExited || result.ExitCode != 0 {
		t.Fatalf("Wait() = %#v", result)
	}
	attachment, err := supervisor.Attach(context.Background(), created.Handle, 0)
	if err != nil {
		t.Fatalf("Attach() error = %v", err)
	}
	events, streamErr := collectAttachment(t, attachment)
	if streamErr != nil {
		t.Fatalf("attachment error = %v", streamErr)
	}
	var stdout, stderr strings.Builder
	for _, event := range events {
		switch event.Type {
		case sandboxd.EventStdout:
			stdout.Write(event.Data)
		case sandboxd.EventStderr:
			stderr.Write(event.Data)
		}
	}
	if stdout.String() != "stdout" || stderr.String() != "stderr" {
		t.Fatalf("output = stdout %q stderr %q", stdout.String(), stderr.String())
	}
}

func TestDevelopmentExecRunnerDoesNotInheritSupervisorEnvironment(t *testing.T) {
	const shell = "/bin/sh"
	if _, err := os.Stat(shell); err != nil {
		t.Skipf("development shell unavailable: %v", err)
	}
	t.Setenv("CIRCULUSD_SANDBOXD_TEST_SECRET", "must-not-cross-process-boundary")

	command, err := sandboxd.ParseCommandName("shell")
	if err != nil {
		t.Fatalf("ParseCommandName() error = %v", err)
	}
	workingDirectory, err := sandboxd.ParseWorkspacePath("")
	if err != nil {
		t.Fatalf("ParseWorkspacePath() error = %v", err)
	}
	supervisor, err := sandboxd.NewSupervisor(sandboxd.Config{
		Authority: sandboxd.LaunchAuthority{
			SandboxID:  "exec-runner-environment-test",
			Generation: 1,
		},
		WorkspaceRoot:     t.TempDir(),
		Commands:          map[string]string{"shell": shell},
		Runner:            sandboxd.NewDevelopmentExecRunner(),
		ReplayLimitBytes:  4096,
		ReplayLimitEvents: 64,
		SubscriberBuffer:  8,
		ReadChunkBytes:    64,
	})
	if err != nil {
		t.Fatalf("NewSupervisor() error = %v", err)
	}
	created, err := supervisor.Spawn(context.Background(), sandboxd.SpawnRequest{
		RequestID:        "environment-request",
		ProcessID:        "environment-process",
		InvocationID:     "environment-invocation",
		Command:          command,
		Arguments:        []string{"-c", `printf %s "$CIRCULUSD_SANDBOXD_TEST_SECRET"`},
		WorkingDirectory: workingDirectory,
		StdinMode:        sandboxd.StdinClosed,
		OutputLimitBytes: 1024,
	})
	if err != nil {
		t.Fatalf("Spawn() error = %v", err)
	}
	if _, err := supervisor.Wait(context.Background(), created.Handle); err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	attachment, err := supervisor.Attach(context.Background(), created.Handle, 0)
	if err != nil {
		t.Fatalf("Attach() error = %v", err)
	}
	events, streamErr := collectAttachment(t, attachment)
	if streamErr != nil {
		t.Fatalf("attachment error = %v", streamErr)
	}
	for _, event := range events {
		if event.Type == sandboxd.EventStdout && len(event.Data) != 0 {
			t.Fatalf("development child inherited supervisor environment: %q", event.Data)
		}
	}
}
