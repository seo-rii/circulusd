//go:build linux

package sandboxd_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/sandboxd"
)

// A descendant that leaves the process group with setsid keeps the output
// pipes open after the leader exits, and group signals cannot reach it. The
// process must still finish with the leader's status and its earlier output.
func TestSupervisorFinishesWhenDetachedDescendantHoldsOutput(t *testing.T) {
	t.Parallel()

	// The leader leaves a pipe-sized burst of unread output as it exits.
	result, stdout, _ := runLeaderWithDescendant(t, `/usr/bin/setsid /bin/sh -c 'echo $$ > "$1"; exec /bin/sleep 60' descendant "$1" &
while [ ! -s "$1" ]; do /bin/sleep 0.01; done
printf before-exit
/usr/bin/head -c 49152 /dev/zero
exit 7`)
	if result.Reason != sandboxd.ExitReasonExited || result.ExitCode != 7 {
		t.Fatalf("Wait() = %#v, want the leader's exit status 7", result)
	}
	want := append([]byte("before-exit"), make([]byte, 49152)...)
	if !bytes.Equal(stdout, want) {
		t.Fatalf("stdout has %d bytes (prefix %q), want %d bytes written before exit",
			len(stdout), stdout[:min(len(stdout), 16)], len(want))
	}
}

// A background job left in the process group keeps the output pipes open
// after the leader exits. It must not outlive supervision: the group is killed
// once the post-exit drain ends, as a deadline or cancel would.
func TestSupervisorKillsProcessGroupHoldingOutputAfterLeaderExit(t *testing.T) {
	t.Parallel()

	result, stdout, pid := runLeaderWithDescendant(t, `/bin/sh -c 'echo $$ > "$1"; exec /bin/sleep 60' background "$1" &
while [ ! -s "$1" ]; do /bin/sleep 0.01; done
printf before-exit
exit 5`)
	if result.Reason != sandboxd.ExitReasonExited || result.ExitCode != 5 {
		t.Fatalf("Wait() = %#v, want the leader's exit status 5", result)
	}
	if string(stdout) != "before-exit" {
		t.Fatalf("stdout = %q, want output written before exit", stdout)
	}
	// The orphaned job is reaped by its new parent, which may take a moment.
	for deadline := time.Now().Add(5 * time.Second); processAlive(pid); {
		if time.Now().After(deadline) {
			t.Fatalf("background job %d survived its process group", pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// runLeaderWithDescendant runs script with a PID file as $1, waits for the
// descendant to record its PID there, and returns the leader's result, its
// stdout, and that PID. The descendant is killed during cleanup.
func runLeaderWithDescendant(t *testing.T, script string) (sandboxd.ProcessResult, []byte, int) {
	t.Helper()

	for _, executable := range []string{"/bin/sh", "/bin/sleep", "/usr/bin/setsid", "/usr/bin/head"} {
		if _, err := os.Stat(executable); err != nil {
			t.Skipf("development executable unavailable: %v", err)
		}
	}
	pidFile := filepath.Join(t.TempDir(), "descendant.pid")
	readPID := func() int {
		data, err := os.ReadFile(pidFile)
		if err != nil {
			return 0
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil {
			return 0
		}
		return pid
	}
	t.Cleanup(func() {
		if pid := readPID(); pid > 0 {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})

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
			SandboxID:  "leader-exit-test",
			Generation: 1,
		},
		WorkspaceRoot:     t.TempDir(),
		Commands:          map[string]string{"shell": "/bin/sh"},
		Runner:            sandboxd.NewDevelopmentExecRunner(),
		ReplayLimitBytes:  1 << 20,
		ReplayLimitEvents: 4096,
		SubscriberBuffer:  16,
		ReadChunkBytes:    4096,
	})
	if err != nil {
		t.Fatalf("NewSupervisor() error = %v", err)
	}
	created, err := supervisor.Spawn(context.Background(), sandboxd.SpawnRequest{
		RequestID:        "leader-exit-request",
		ProcessID:        "leader-exit-process",
		InvocationID:     "leader-exit-invocation",
		Command:          command,
		Arguments:        []string{"-c", script, "leader", pidFile},
		WorkingDirectory: workingDirectory,
		StdinMode:        sandboxd.StdinClosed,
		OutputLimitBytes: 1 << 20,
	})
	if err != nil {
		t.Fatalf("Spawn() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := supervisor.Wait(ctx, created.Handle)
	if err != nil {
		t.Fatalf("Wait() error = %v; a descendant kept the process open", err)
	}
	attachment, err := supervisor.Attach(ctx, created.Handle, 0)
	if err != nil {
		t.Fatalf("Attach() error = %v", err)
	}
	events, streamErr := collectAttachment(t, attachment)
	if streamErr != nil {
		t.Fatalf("attachment error = %v", streamErr)
	}
	var stdout bytes.Buffer
	for _, event := range events {
		switch event.Type {
		case sandboxd.EventStdout:
			stdout.Write(event.Data)
		case sandboxd.EventError:
			t.Fatalf("unexpected stream error event: %q", event.Error)
		}
	}
	if last := events[len(events)-1]; last.Type != sandboxd.EventExit {
		t.Fatalf("last event = %q, want exit", last.Type)
	}
	pid := readPID()
	if pid <= 0 {
		t.Fatal("descendant did not record its PID")
	}
	return result, stdout.Bytes(), pid
}

// processAlive treats zombies as dead: a killed orphan stays visible to
// kill(pid, 0) until its new parent reaps it.
func processAlive(pid int) bool {
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	fields := strings.Fields(string(stat[bytes.LastIndexByte(stat, ')')+1:]))
	return len(fields) > 0 && fields[0] != "Z" && fields[0] != "X"
}
