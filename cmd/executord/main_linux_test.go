//go:build linux

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/daemonshell"
)

const hungShutdownHelperEnvironment = "CIRCULUSD_EXECUTORD_HUNG_SHUTDOWN_HELPER"

func TestRunExecutordSecondSignalEndsHungShutdown(t *testing.T) {
	if os.Getenv(hungShutdownHelperEnvironment) == "1" {
		os.Exit(runExecutord([]string{"--allow-platformctl-uid", "1002"}, daemonshell.Dependencies{
			Stderr: os.Stderr,
			Listen: func(context.Context, daemonshell.ListenerConfig) (daemonshell.Server, error) {
				return hungShutdownServer{}, nil
			},
		}))
	}
	t.Parallel()

	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable() error = %v", err)
	}
	command := exec.Command(executable, "-test.run=^TestRunExecutordSecondSignalEndsHungShutdown$")
	command.Env = append(os.Environ(), hungShutdownHelperEnvironment+"=1")
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe() error = %v", err)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	exited := make(chan error, 1)
	lines := make(chan string, 4)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
		close(lines)
		exited <- command.Wait()
	}()
	t.Cleanup(func() {
		_ = command.Process.Kill()
	})
	awaitLine := func(want string) {
		t.Helper()
		select {
		case line := <-lines:
			if line != want {
				t.Fatalf("helper printed %q, want %q", line, want)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("helper did not print %q", want)
		}
	}

	awaitLine("serving")
	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("first SIGTERM error = %v", err)
	}
	awaitLine("closing")
	// The second signal may race the handler hand-off, so repeat it until
	// the hung shutdown ends.
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case err := <-exited:
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) {
				t.Fatalf("helper exit = %v, want termination by SIGTERM", err)
			}
			status, ok := exitErr.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGTERM {
				t.Fatalf("helper exit = %v, want termination by SIGTERM", err)
			}
			return
		case <-ticker.C:
			_ = command.Process.Signal(syscall.SIGTERM)
		case <-deadline:
			t.Fatal("a second SIGTERM did not end a hung shutdown")
		}
	}
}

// hungShutdownServer serves until the process exits and never finishes
// closing, like a shutdown stuck on a wedged listener.
type hungShutdownServer struct{}

func (hungShutdownServer) Serve(context.Context) error {
	fmt.Println("serving")
	time.Sleep(time.Hour)
	return nil
}

func (hungShutdownServer) Close() error {
	fmt.Println("closing")
	time.Sleep(time.Hour)
	return nil
}
