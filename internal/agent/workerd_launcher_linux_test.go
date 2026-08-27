//go:build linux

package agent

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestOSWorkerdProcessStarterUsesCloneIntoCgroupWithoutExtraFile(t *testing.T) {
	var startedCommand *exec.Cmd
	starter := osWorkerdProcessStarter{start: func(command *exec.Cmd) error {
		startedCommand = command
		command.Process = &os.Process{Pid: 20_010}
		return nil
	}}
	process, err := starter.Start(workerdLaunchCommand{
		Executable: "/sealed/workerd", CgroupFD: 47, ExtraFiles: make([]*os.File, 0),
		Stdout: io.Discard, Stderr: io.Discard,
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if process.PID() != 20_010 {
		t.Fatalf("PID() = %d, want 20010", process.PID())
	}
	var attributes *syscall.SysProcAttr
	if startedCommand != nil {
		attributes = startedCommand.SysProcAttr
	}
	if attributes == nil || !attributes.UseCgroupFD || attributes.CgroupFD != 47 {
		t.Fatalf("SysProcAttr = %#v, want UseCgroupFD with fd 47", attributes)
	}
	if len(startedCommand.ExtraFiles) != 0 {
		t.Fatalf("ExtraFiles = %d, want cgroup fd excluded", len(startedCommand.ExtraFiles))
	}
}

func TestNewWorkerdProcessLauncherFailsClosedWithoutCgroupBoundary(t *testing.T) {
	config, _ := newWorkerdLauncherFixture(t, &recordingWorkerdStarter{}, WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }))
	launcher, err := NewWorkerdProcessLauncher(config)
	if launcher != nil {
		_ = launcher.Close(context.Background())
	}
	if launcher != nil || !errors.Is(err, ErrInvalidWorkerdLauncherConfig) {
		t.Fatalf("NewWorkerdProcessLauncher(without cgroup) = %#v, %v, want nil, invalid config", launcher, err)
	}
}

func TestNewWorkerdProcessLauncherRejectsUnpinnedOrUnsafeExecutable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		mutate  func(*testing.T, *WorkerdLauncherConfig)
		wantErr error
	}{
		{name: "relative path", mutate: func(_ *testing.T, config *WorkerdLauncherConfig) {
			config.ExecutablePath = "workerd"
		}, wantErr: ErrInvalidWorkerdLauncherConfig},
		{name: "non-canonical path", mutate: func(_ *testing.T, config *WorkerdLauncherConfig) {
			config.ExecutablePath = filepath.Dir(config.ExecutablePath) + "/./" + filepath.Base(config.ExecutablePath)
		}, wantErr: ErrInvalidWorkerdLauncherConfig},
		{name: "malformed digest", mutate: func(_ *testing.T, config *WorkerdLauncherConfig) {
			config.ExecutableDigest = "sha256:not-a-digest"
		}, wantErr: ErrInvalidWorkerdLauncherConfig},
		{name: "non-canonical digest", mutate: func(_ *testing.T, config *WorkerdLauncherConfig) {
			config.ExecutableDigest = "sha256:" + strings.ToUpper(strings.TrimPrefix(config.ExecutableDigest, "sha256:"))
		}, wantErr: ErrInvalidWorkerdLauncherConfig},
		{name: "digest mismatch", mutate: func(_ *testing.T, config *WorkerdLauncherConfig) {
			config.ExecutableDigest = "sha256:" + strings.Repeat("0", sha256.Size*2)
		}, wantErr: ErrWorkerdDigestMismatch},
		{name: "symlink", mutate: func(t *testing.T, config *WorkerdLauncherConfig) {
			linkPath := filepath.Join(filepath.Dir(config.ExecutablePath), "workerd-link")
			if err := os.Symlink(config.ExecutablePath, linkPath); err != nil {
				t.Fatal(err)
			}
			config.ExecutablePath = linkPath
		}, wantErr: ErrUnsafeWorkerdExecutable},
		{name: "directory", mutate: func(_ *testing.T, config *WorkerdLauncherConfig) {
			config.ExecutablePath = filepath.Dir(config.ExecutablePath)
		}, wantErr: ErrUnsafeWorkerdExecutable},
		{name: "not executable", mutate: func(t *testing.T, config *WorkerdLauncherConfig) {
			if err := os.Chmod(config.ExecutablePath, 0o400); err != nil {
				t.Fatal(err)
			}
		}, wantErr: ErrUnsafeWorkerdExecutable},
		{name: "group writable", mutate: func(t *testing.T, config *WorkerdLauncherConfig) {
			if err := os.Chmod(config.ExecutablePath, 0o520); err != nil {
				t.Fatal(err)
			}
		}, wantErr: ErrUnsafeWorkerdExecutable},
		{name: "world writable", mutate: func(t *testing.T, config *WorkerdLauncherConfig) {
			if err := os.Chmod(config.ExecutablePath, 0o502); err != nil {
				t.Fatal(err)
			}
		}, wantErr: ErrUnsafeWorkerdExecutable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config, _ := newWorkerdLauncherFixture(t, &recordingWorkerdStarter{}, WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }))
			test.mutate(t, &config)
			launcher, err := newWorkerdProcessLauncher(config, osWorkerdProcessStarter{})
			if launcher != nil || !errors.Is(err, test.wantErr) {
				t.Fatalf("NewWorkerdProcessLauncher() = %#v, %v, want nil, %v", launcher, err, test.wantErr)
			}
		})
	}
}

func TestNewWorkerdProcessLauncherFallsBackFromMFDExecOnlyOnEINVAL(t *testing.T) {
	config, _ := newWorkerdLauncherFixture(t, &recordingWorkerdStarter{}, WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }))
	var flags []int
	launcher, err := newWorkerdProcessLauncherWithMemfd(config, &recordingWorkerdStarter{}, func(name string, requested int) (int, error) {
		flags = append(flags, requested)
		if len(flags) == 1 {
			return -1, unix.EINVAL
		}
		return unix.MemfdCreate(name, requested)
	})
	if err != nil {
		t.Fatalf("newWorkerdProcessLauncherWithMemfd() error = %v", err)
	}
	t.Cleanup(func() { _ = launcher.Close(context.Background()) })
	if len(flags) != 2 || flags[0]&unix.MFD_EXEC == 0 || flags[1]&unix.MFD_EXEC != 0 {
		t.Fatalf("memfd flags = %#v, want MFD_EXEC then compatibility fallback", flags)
	}
}

func TestNewWorkerdProcessLauncherDoesNotFallbackFromMFDExecPermissionFailure(t *testing.T) {
	config, _ := newWorkerdLauncherFixture(t, &recordingWorkerdStarter{}, WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }))
	calls := 0
	_, err := newWorkerdProcessLauncherWithMemfd(config, &recordingWorkerdStarter{}, func(string, int) (int, error) {
		calls++
		return -1, unix.EPERM
	})
	if !errors.Is(err, ErrUnsafeWorkerdExecutable) || calls != 1 {
		t.Fatalf("constructor error = %v, calls = %d; want unsafe executable after one call", err, calls)
	}
}

func TestWorkerdLauncherFixtureCleanupBoundsFileDescriptors(t *testing.T) {
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for index := range 32 {
		t.Run(fmt.Sprintf("fixture-%d", index), func(t *testing.T) {
			newWorkerdLauncherFixture(t, &recordingWorkerdStarter{}, WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }))
		})
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) > len(before)+4 {
		t.Fatalf("open file descriptors grew from %d to %d", len(before), len(after))
	}
}

func TestWorkerdLauncherConfigOnlyFixtureSecondaryConstructorsCloseFileDescriptors(t *testing.T) {
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for index := range 32 {
		t.Run(fmt.Sprintf("secondary-%d", index), func(t *testing.T) {
			config, _ := newWorkerdLauncherFixture(t, &recordingWorkerdStarter{}, WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }))
			launcher, constructorErr := newWorkerdProcessLauncherForTest(t, config, &recordingWorkerdStarter{})
			if constructorErr != nil {
				t.Fatal(constructorErr)
			}
			_ = launcher
		})
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) > len(before)+4 {
		t.Fatalf("open file descriptors grew from %d to %d", len(before), len(after))
	}
}

func TestNewWorkerdProcessLauncherRejectsUnboundedConfiguration(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*WorkerdLauncherConfig)
	}{
		{name: "readiness timeout", mutate: func(config *WorkerdLauncherConfig) {
			config.ReadinessTimeout = 5*time.Minute + time.Nanosecond
		}},
		{name: "stop grace period", mutate: func(config *WorkerdLauncherConfig) {
			config.StopGracePeriod = 30*time.Second + time.Nanosecond
		}},
		{name: "output capture", mutate: func(config *WorkerdLauncherConfig) {
			config.OutputLimitBytes = 1<<20 + 1
		}},
		{name: "zero history capacity", mutate: func(config *WorkerdLauncherConfig) {
			config.HistoryCapacity = 0
		}},
		{name: "excessive history capacity", mutate: func(config *WorkerdLauncherConfig) {
			config.HistoryCapacity = 4097
		}},
		{name: "environment value", mutate: func(config *WorkerdLauncherConfig) {
			config.Environment = map[string]string{"HOME": strings.Repeat("x", 64<<10+1)}
		}},
		{name: "environment total", mutate: func(config *WorkerdLauncherConfig) {
			value := strings.Repeat("x", 60<<10)
			config.Environment = map[string]string{
				"HOME": value, "LANG": value, "LC_ALL": value, "LC_CTYPE": value, "TMPDIR": value,
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config, _ := newWorkerdLauncherFixture(t, &recordingWorkerdStarter{}, WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }))
			test.mutate(&config)
			launcher, err := newWorkerdProcessLauncher(config, osWorkerdProcessStarter{})
			if launcher != nil || !errors.Is(err, ErrInvalidWorkerdLauncherConfig) {
				t.Fatalf("NewWorkerdProcessLauncher() = %#v, %v, want nil, invalid config", launcher, err)
			}
		})
	}
}

func TestNewWorkerdProcessLauncherAcceptsClosedProductionBounds(t *testing.T) {
	t.Parallel()
	config, _ := newWorkerdLauncherFixture(t, &recordingWorkerdStarter{}, WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }))
	config.ReadinessTimeout = 5 * time.Minute
	config.StopGracePeriod = 30 * time.Second
	config.OutputLimitBytes = 1 << 20
	config.Environment = map[string]string{"HOME": strings.Repeat("x", 64<<10)}
	launcher, err := newWorkerdProcessLauncher(config, osWorkerdProcessStarter{})
	if err != nil {
		t.Fatalf("NewWorkerdProcessLauncher(maximum bounds) error = %v", err)
	}
	if err := launcher.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestWorkerdProcessLauncherRejectsUnboundedArgumentsBeforeStart(t *testing.T) {
	t.Parallel()
	starter := &recordingWorkerdStarter{}
	_, launcher := newWorkerdLauncherFixture(t, starter, WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }))
	tests := []struct {
		name      string
		arguments []string
	}{
		{name: "count", arguments: make([]string, 129)},
		{name: "individual", arguments: []string{strings.Repeat("x", 64<<10+1)}},
		{name: "total", arguments: func() []string {
			arguments := make([]string, 17)
			for index := range arguments {
				arguments[index] = strings.Repeat("x", 64<<10)
			}
			return arguments
		}()},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
				ShardID: fmt.Sprintf("unbounded-args-%d", index), PlacementGeneration: 1, Arguments: test.arguments,
			})
			if handle != nil || !errors.Is(err, ErrInvalidWorkerdEnsureRequest) {
				t.Fatalf("Ensure() = %#v, %v, want nil, invalid request", handle, err)
			}
		})
	}
	if starts := len(starter.commandSnapshot()); starts != 0 {
		t.Fatalf("invalid arguments started %d process(es)", starts)
	}

	maximumArguments := make([]string, 16)
	for index := range maximumArguments {
		maximumArguments[index] = strings.Repeat("x", 64<<10)
	}
	handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
		ShardID: "bounded-args", PlacementGeneration: 1, Arguments: maximumArguments,
	})
	if err != nil {
		t.Fatalf("Ensure(exact 1 MiB arguments) error = %v", err)
	}
	if err := handle.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}

func TestWorkerdProcessLauncherHistoryCapacityRejectsBeforeAllocationOrStart(t *testing.T) {
	t.Parallel()
	starter := &recordingWorkerdStarter{}
	readinessFailure := errors.New("injected readiness failure")
	config, _ := newWorkerdLauncherFixture(t, starter, WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error {
		return readinessFailure
	}))
	config.HistoryCapacity = 4
	launcher, err := newWorkerdProcessLauncherForTest(t, config, starter)
	if err != nil {
		t.Fatal(err)
	}
	for index := range 32 {
		_, ensureErr := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
			ShardID: fmt.Sprintf("failed-history-%02d", index), PlacementGeneration: 1,
		})
		if index < config.HistoryCapacity {
			if !errors.Is(ensureErr, ErrWorkerdNotReady) {
				t.Fatalf("Ensure(within capacity %d) error = %v", index, ensureErr)
			}
		} else if !errors.Is(ensureErr, ErrWorkerdHistoryCapacity) {
			t.Fatalf("Ensure(over capacity %d) error = %v, want history capacity", index, ensureErr)
		}
	}
	if starts := len(starter.commandSnapshot()); starts != config.HistoryCapacity {
		t.Fatalf("process starts = %d, want cap %d", starts, config.HistoryCapacity)
	}
	launcher.mu.Lock()
	latest, identities := len(launcher.latestGenerations), len(launcher.launchIdentities)
	pending, instances := len(launcher.pending), len(launcher.instances)
	launcher.mu.Unlock()
	if latest > config.HistoryCapacity || identities > config.HistoryCapacity || pending != 0 || instances != 0 {
		t.Fatalf("bounded state latest=%d identities=%d pending=%d instances=%d cap=%d", latest, identities, pending, instances, config.HistoryCapacity)
	}
}

func TestWorkerdProcessLauncherCanceledShardHistoryRemainsBounded(t *testing.T) {
	starter := &recordingWorkerdStarter{}
	entered := make(chan struct{}, 4)
	config, _ := newWorkerdLauncherFixture(t, starter, WorkerdReadinessProbeFunc(func(ctx context.Context, _ WorkerdProcessInfo) error {
		entered <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	}))
	config.HistoryCapacity = 4
	launcher, err := newWorkerdProcessLauncherForTest(t, config, starter)
	if err != nil {
		t.Fatal(err)
	}
	for index := range config.HistoryCapacity {
		request := WorkerdEnsureRequest{ShardID: fmt.Sprintf("canceled-history-%d", index), PlacementGeneration: 1}
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() {
			_, ensureErr := launcher.Ensure(ctx, request)
			result <- ensureErr
		}()
		<-entered
		cancel()
		if ensureErr := <-result; !errors.Is(ensureErr, context.Canceled) {
			t.Fatalf("Ensure(canceled %d) error = %v", index, ensureErr)
		}
		waitForNoPendingWorkerdLaunch(t, launcher, request)
	}
	_, err = launcher.Ensure(context.Background(), WorkerdEnsureRequest{ShardID: "over-canceled-cap", PlacementGeneration: 1})
	if !errors.Is(err, ErrWorkerdHistoryCapacity) {
		t.Fatalf("Ensure(over capacity) error = %v, want history capacity", err)
	}
	if starts := len(starter.commandSnapshot()); starts != config.HistoryCapacity {
		t.Fatalf("process starts = %d, want %d", starts, config.HistoryCapacity)
	}
}

func TestWorkerdProcessLauncherExecutesSealedSnapshotAfterPathReplacement(t *testing.T) {
	t.Setenv("CIRCULUSD_AMBIENT_SECRET", "must-not-be-inherited")
	process := newFakeWorkerdProcess(101, true)
	starter := &recordingWorkerdStarter{
		processes:     []*fakeWorkerdProcess{process},
		stdoutPayload: "0123456789",
		stderrPayload: "abcdefghij",
	}
	config, launcher := newWorkerdLauncherFixture(t, starter, WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }))
	config.Environment = map[string]string{"LANG": "C", "TZ": "UTC"}
	config.OutputLimitBytes = 8
	launcher, err := newWorkerdProcessLauncherForTest(t, config, starter)
	if err != nil {
		t.Fatalf("newWorkerdProcessLauncher() error = %v", err)
	}

	original := []byte("verified-workerd-inode")
	if err := os.Remove(config.ExecutablePath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.ExecutablePath, []byte("substituted-path"), 0o500); err != nil {
		t.Fatal(err)
	}
	handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
		ShardID: "shared-shard-a", PlacementGeneration: 7, Arguments: []string{"serve", "--config=/sealed/workerd.capnp"},
	})
	if err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	if got := handle.ID(); got != "shared-shard-a" {
		t.Fatalf("ID() = %q, want shared-shard-a", got)
	}
	commands := starter.commandSnapshot()
	if len(commands) != 1 {
		t.Fatalf("process starts = %d, want 1", len(commands))
	}
	command := commands[0]
	if !strings.HasPrefix(command.Executable, "/proc/self/fd/") || command.Executable == config.ExecutablePath {
		t.Fatalf("executable = %q, want opened /proc inode", command.Executable)
	}
	if !reflect.DeepEqual(command.executableContent, original) {
		t.Fatalf("opened executable = %q, want %q", command.executableContent, original)
	}
	if !reflect.DeepEqual(command.Arguments, []string{"serve", "--config=/sealed/workerd.capnp"}) {
		t.Fatalf("arguments = %#v", command.Arguments)
	}
	if !reflect.DeepEqual(command.Environment, []string{"LANG=C", "TZ=UTC"}) {
		t.Fatalf("environment = %#v, want explicit sorted allowlist", command.Environment)
	}
	if strings.Contains(strings.Join(command.Environment, "\x00"), "CIRCULUSD_AMBIENT_SECRET") {
		t.Fatalf("ambient environment inherited: %#v", command.Environment)
	}
	if len(command.ExtraFiles) != 0 {
		t.Fatalf("extra files = %d, want none", len(command.ExtraFiles))
	}
	if command.ShardID != "shared-shard-a" || command.PlacementGeneration != 7 {
		t.Fatalf("command identity = %q/%d", command.ShardID, command.PlacementGeneration)
	}
	output := handle.Output()
	if output.Stdout != "01234567" || output.Stderr != "abcdefgh" || !output.StdoutTruncated || !output.StderrTruncated {
		t.Fatalf("bounded output = %#v", output)
	}
	if err := handle.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}

func TestWorkerdProcessLauncherExecutesSealedSnapshotAfterOwnerMutatesOriginalInode(t *testing.T) {
	t.Parallel()
	process := newFakeWorkerdProcess(151, true)
	starter := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{process}}
	config, _ := newWorkerdLauncherFixture(t, starter, WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }))
	if err := os.Chmod(config.ExecutablePath, 0o700); err != nil {
		t.Fatal(err)
	}
	originalInfo, err := os.Stat(config.ExecutablePath)
	if err != nil {
		t.Fatal(err)
	}
	launcher, err := newWorkerdProcessLauncherForTest(t, config, starter)
	if err != nil {
		t.Fatalf("newWorkerdProcessLauncher(owner-writable executable) error = %v", err)
	}
	mutated := []byte("mutated-workerd-inode")
	if err := os.WriteFile(config.ExecutablePath, mutated, 0o700); err != nil {
		t.Fatal(err)
	}
	mutatedInfo, err := os.Stat(config.ExecutablePath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(originalInfo, mutatedInfo) {
		t.Fatal("test replaced the path instead of mutating the verified inode")
	}
	handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{ShardID: "sealed-owner-writable", PlacementGeneration: 1})
	if err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	commands := starter.commandSnapshot()
	if len(commands) != 1 || string(commands[0].executableContent) != "verified-workerd-inode" {
		t.Fatalf("executed snapshot = %q, want verified bytes; original inode now %q", commands[0].executableContent, mutated)
	}
	wantSeals := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	seals, err := unix.FcntlInt(launcher.executable.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || seals&wantSeals != wantSeals {
		t.Fatalf("sealed executable F_GET_SEALS = %#x, %v, want %#x", seals, err, wantSeals)
	}
	if _, err := launcher.executable.WriteAt([]byte("x"), 0); !errors.Is(err, unix.EPERM) {
		t.Fatalf("WriteAt(sealed executable) error = %v, want EPERM", err)
	}
	if err := handle.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if err := launcher.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestNewWorkerdProcessLauncherRejectsOversizedExecutableBeforeHashing(t *testing.T) {
	t.Parallel()
	config, _ := newWorkerdLauncherFixture(t, &recordingWorkerdStarter{}, WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }))
	oversizedPath := filepath.Join(t.TempDir(), "oversized-workerd")
	oversized, err := os.OpenFile(oversizedPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o500)
	if err != nil {
		t.Fatal(err)
	}
	if err := oversized.Truncate(256<<20 + 1); err != nil {
		_ = oversized.Close()
		t.Fatal(err)
	}
	if err := oversized.Close(); err != nil {
		t.Fatal(err)
	}
	config.ExecutablePath = oversizedPath
	launcher, err := newWorkerdProcessLauncher(config, osWorkerdProcessStarter{})
	if launcher != nil || !errors.Is(err, ErrUnsafeWorkerdExecutable) {
		t.Fatalf("NewWorkerdProcessLauncher(oversized) = %#v, %v, want nil, unsafe executable", launcher, err)
	}
}

func TestWorkerdProcessLauncherCoalescesConcurrentEnsureAfterReadiness(t *testing.T) {
	t.Parallel()
	process := newFakeWorkerdProcess(201, true)
	starter := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{process}}
	probe := newControlledWorkerdProbe()
	_, launcher := newWorkerdLauncherFixture(t, starter, probe)
	request := WorkerdEnsureRequest{ShardID: "shared-shard", PlacementGeneration: 9, Arguments: []string{"serve"}}

	const workers = 64
	results := startConcurrentWorkerdEnsures(launcher, request, workers)
	entered := awaitProbe(t, probe.entered)
	if entered.ShardID != request.ShardID || entered.PlacementGeneration != request.PlacementGeneration || entered.PID != process.pid {
		t.Fatalf("readiness identity = %#v", entered)
	}
	waitForPendingWorkerdWaiters(t, launcher, request, workers)
	select {
	case result := <-results:
		t.Fatalf("Ensure returned before readiness: %#v", result)
	default:
	}

	_, conflictErr := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
		ShardID: request.ShardID, PlacementGeneration: request.PlacementGeneration, Arguments: []string{"different"},
	})
	if !errors.Is(conflictErr, ErrWorkerdLaunchConflict) {
		t.Fatalf("Ensure(conflicting immutable identity) error = %v", conflictErr)
	}
	probe.release(request.ShardID)
	var first *WorkerdShardHandle
	for range workers {
		result := <-results
		if result.err != nil {
			t.Fatalf("Ensure() error = %v", result.err)
		}
		if first == nil {
			first = result.handle
		} else if result.handle != first {
			t.Fatalf("coalesced handles differ: %p != %p", result.handle, first)
		}
	}
	if calls := starter.commandSnapshot(); len(calls) != 1 {
		t.Fatalf("process starts = %d, want 1", len(calls))
	}
	if calls := probe.callCount(); calls != 1 {
		t.Fatalf("readiness probes = %d, want 1", calls)
	}
	if err := first.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}

func TestWorkerdProcessLauncherSnapshotsArgumentsAndStoresFixedIdentity(t *testing.T) {
	t.Parallel()
	process := newFakeWorkerdProcess(251, true)
	starter := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{process}}
	probe := newControlledWorkerdProbe()
	_, launcher := newWorkerdLauncherFixture(t, starter, probe)
	arguments := []string{"serve", "original"}
	request := WorkerdEnsureRequest{ShardID: "argument-snapshot", PlacementGeneration: 1, Arguments: arguments}
	resultChannel := make(chan workerdEnsureResult, 1)
	go func() {
		handle, err := launcher.Ensure(context.Background(), request)
		resultChannel <- workerdEnsureResult{handle: handle, err: err}
	}()
	waitForPendingWorkerdWaiters(t, launcher, request, 1)
	arguments[1] = "mutated-after-call"
	_ = awaitProbe(t, probe.entered)
	probe.release(request.ShardID)
	result := <-resultChannel
	if result.err != nil {
		t.Fatalf("Ensure() error = %v", result.err)
	}
	commands := starter.commandSnapshot()
	if len(commands) != 1 || !reflect.DeepEqual(commands[0].Arguments, []string{"serve", "original"}) {
		t.Fatalf("launched arguments = %#v, want immutable snapshot", commands)
	}
	launcher.mu.Lock()
	identityBytes := len(launcher.launchIdentities[workerdLaunchKey{shardID: request.ShardID, generation: request.PlacementGeneration}])
	launcher.mu.Unlock()
	if identityBytes != sha256.Size {
		t.Fatalf("stored launch identity bytes = %d, want fixed SHA-256 size", identityBytes)
	}
	if _, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
		ShardID: request.ShardID, PlacementGeneration: request.PlacementGeneration, Arguments: []string{"serve", "original"},
	}); err != nil {
		t.Fatalf("Ensure(original replay) error = %v", err)
	}
	if _, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
		ShardID: request.ShardID, PlacementGeneration: request.PlacementGeneration, Arguments: arguments,
	}); !errors.Is(err, ErrWorkerdLaunchConflict) {
		t.Fatalf("Ensure(mutated replay) error = %v, want conflict", err)
	}
	if err := result.handle.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}

func TestWorkerdProcessLauncherPrunesOlderGenerationIdentities(t *testing.T) {
	t.Parallel()
	starter := &recordingWorkerdStarter{}
	_, launcher := newWorkerdLauncherFixture(t, starter, WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }))
	var handle *WorkerdShardHandle
	for generation := uint64(1); generation <= 12; generation++ {
		var err error
		handle, err = launcher.Ensure(context.Background(), WorkerdEnsureRequest{
			ShardID: "identity-pruning", PlacementGeneration: generation, Arguments: []string{fmt.Sprintf("generation-%d", generation)},
		})
		if err != nil {
			t.Fatalf("Ensure(generation %d) error = %v", generation, err)
		}
	}
	launcher.mu.Lock()
	identities := len(launcher.launchIdentities)
	launcher.mu.Unlock()
	if identities != 1 {
		t.Fatalf("retained launch identities = %d, want current generation only", identities)
	}
	if err := handle.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}

func TestWorkerdProcessLauncherOutputBuffersAllocateLazily(t *testing.T) {
	t.Parallel()
	starter := &recordingWorkerdStarter{}
	_, launcher := newWorkerdLauncherFixture(t, starter, WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }))
	handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{ShardID: "lazy-output", PlacementGeneration: 1})
	if err != nil {
		t.Fatal(err)
	}
	if stdoutCapacity, stderrCapacity := cap(handle.instance.stdout.data), cap(handle.instance.stderr.data); stdoutCapacity != 0 || stderrCapacity != 0 {
		t.Fatalf("empty output capacities = %d/%d, want lazy zero allocation", stdoutCapacity, stderrCapacity)
	}
	if err := handle.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}

func TestWorkerdProcessLauncherStartsDifferentShardsIndependently(t *testing.T) {
	t.Parallel()
	starter := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{
		newFakeWorkerdProcess(301, true), newFakeWorkerdProcess(302, true),
	}}
	probe := newControlledWorkerdProbe()
	_, launcher := newWorkerdLauncherFixture(t, starter, probe)
	requests := []WorkerdEnsureRequest{
		{ShardID: "shard-a", PlacementGeneration: 1, Arguments: []string{"serve", "a"}},
		{ShardID: "shard-b", PlacementGeneration: 1, Arguments: []string{"serve", "b"}},
	}
	results := make(chan workerdEnsureResult, len(requests))
	for _, request := range requests {
		request := request
		go func() {
			handle, err := launcher.Ensure(context.Background(), request)
			results <- workerdEnsureResult{handle: handle, err: err}
		}()
	}
	entered := map[string]bool{}
	for range requests {
		info := awaitProbe(t, probe.entered)
		entered[info.ShardID] = true
	}
	if !entered["shard-a"] || !entered["shard-b"] {
		t.Fatalf("parallel readiness entries = %#v", entered)
	}
	for _, request := range requests {
		probe.release(request.ShardID)
	}
	for range requests {
		result := <-results
		if result.err != nil {
			t.Fatalf("Ensure() error = %v", result.err)
		}
		if err := result.handle.Stop(context.Background()); err != nil {
			t.Fatalf("Stop() error = %v", err)
		}
	}
}

func TestWorkerdProcessLauncherSerializesGenerationsBeforeStartingReplacement(t *testing.T) {
	t.Parallel()
	firstProcess := newFakeWorkerdProcess(351, true)
	secondProcess := newFakeWorkerdProcess(352, true)
	starter := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{firstProcess, secondProcess}}
	entered := make(chan WorkerdProcessInfo, 2)
	firstReady := make(chan struct{})
	secondReady := make(chan struct{})
	probe := WorkerdReadinessProbeFunc(func(ctx context.Context, info WorkerdProcessInfo) error {
		entered <- info
		ready := firstReady
		if info.PlacementGeneration == 2 {
			ready = secondReady
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ready:
			return nil
		}
	})
	_, launcher := newWorkerdLauncherFixture(t, starter, probe)
	firstResult := make(chan workerdEnsureResult, 1)
	go func() {
		handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
			ShardID: "serialized-generation", PlacementGeneration: 1,
		})
		firstResult <- workerdEnsureResult{handle: handle, err: err}
	}()
	if info := awaitProbe(t, entered); info.PlacementGeneration != 1 {
		t.Fatalf("first readiness generation = %d, want 1", info.PlacementGeneration)
	}
	secondResult := make(chan workerdEnsureResult, 1)
	go func() {
		handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
			ShardID: "serialized-generation", PlacementGeneration: 2,
		})
		secondResult <- workerdEnsureResult{handle: handle, err: err}
	}()
	select {
	case info := <-entered:
		t.Fatalf("generation %d started before generation 1 resolved", info.PlacementGeneration)
	case <-time.After(50 * time.Millisecond):
	}
	close(firstReady)
	first := <-firstResult
	if first.err != nil {
		t.Fatalf("Ensure(generation 1) error = %v", first.err)
	}
	if info := awaitProbe(t, entered); info.PlacementGeneration != 2 {
		t.Fatalf("second readiness generation = %d, want 2", info.PlacementGeneration)
	}
	close(secondReady)
	second := <-secondResult
	if second.err != nil {
		t.Fatalf("Ensure(generation 2) error = %v", second.err)
	}
	if err := first.handle.Stop(context.Background()); err != nil {
		t.Fatalf("Stop(retired exact handle) error = %v", err)
	}
	if err := second.handle.Stop(context.Background()); err != nil {
		t.Fatalf("Stop(generation 2) error = %v", err)
	}
}

func TestWorkerdProcessLauncherFansOutReadinessTimeoutAndCleansProcessGroup(t *testing.T) {
	t.Parallel()
	process := newFakeWorkerdProcess(401, false)
	starter := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{process}}
	probe := WorkerdReadinessProbeFunc(func(ctx context.Context, _ WorkerdProcessInfo) error {
		<-ctx.Done()
		return ctx.Err()
	})
	config, _ := newWorkerdLauncherFixture(t, starter, probe)
	config.ReadinessTimeout = 250 * time.Millisecond
	config.StopGracePeriod = 100 * time.Millisecond
	launcher, err := newWorkerdProcessLauncherForTest(t, config, starter)
	if err != nil {
		t.Fatal(err)
	}
	request := WorkerdEnsureRequest{ShardID: "timeout-shard", PlacementGeneration: 1}
	const workers = 16
	results := startConcurrentWorkerdEnsures(launcher, request, workers)
	waitForPendingWorkerdWaiters(t, launcher, request, workers)
	var first error
	for range workers {
		result := <-results
		if !errors.Is(result.err, ErrWorkerdReadinessTimeout) {
			t.Fatalf("Ensure() error = %v, want readiness timeout", result.err)
		}
		if first == nil {
			first = result.err
		} else if result.err != first {
			t.Fatalf("waiters received different error objects: %p != %p", result.err, first)
		}
	}
	if signals := process.signalSnapshot(); !reflect.DeepEqual(signals, []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL}) {
		t.Fatalf("failure cleanup signals = %#v, want TERM then KILL", signals)
	}
}

func TestWorkerdProcessLauncherFansOutEarlyExitAndKillsDescendantGroup(t *testing.T) {
	t.Parallel()
	process := newFakeWorkerdProcess(501, false)
	starter := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{process}}
	probe := newControlledWorkerdProbe()
	_, launcher := newWorkerdLauncherFixture(t, starter, probe)
	request := WorkerdEnsureRequest{ShardID: "early-exit-shard", PlacementGeneration: 3}
	const workers = 8
	results := startConcurrentWorkerdEnsures(launcher, request, workers)
	_ = awaitProbe(t, probe.entered)
	waitForPendingWorkerdWaiters(t, launcher, request, workers)
	exitCause := errors.New("workerd exited unexpectedly")
	process.finish(exitCause)
	var first error
	for range workers {
		result := <-results
		if !errors.Is(result.err, ErrWorkerdExitedBeforeReady) || !errors.Is(result.err, exitCause) {
			t.Fatalf("Ensure() error = %v, want early exit cause", result.err)
		}
		if first == nil {
			first = result.err
		} else if result.err != first {
			t.Fatalf("waiters received different error objects: %p != %p", result.err, first)
		}
	}
	if signals := process.signalSnapshot(); !reflect.DeepEqual(signals, []syscall.Signal{syscall.SIGKILL}) {
		t.Fatalf("early-exit descendant cleanup signals = %#v, want KILL", signals)
	}
}

func TestWorkerdProcessLauncherWaiterCancellationDoesNotCancelSharedStart(t *testing.T) {
	t.Parallel()
	process := newFakeWorkerdProcess(601, true)
	starter := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{process}}
	probe := newControlledWorkerdProbe()
	_, launcher := newWorkerdLauncherFixture(t, starter, probe)
	request := WorkerdEnsureRequest{ShardID: "shared-cancel-shard", PlacementGeneration: 1}
	firstContext, cancelFirst := context.WithCancel(context.Background())
	firstResult := make(chan workerdEnsureResult, 1)
	secondResult := make(chan workerdEnsureResult, 1)
	go func() {
		handle, err := launcher.Ensure(firstContext, request)
		firstResult <- workerdEnsureResult{handle: handle, err: err}
	}()
	go func() {
		handle, err := launcher.Ensure(context.Background(), request)
		secondResult <- workerdEnsureResult{handle: handle, err: err}
	}()
	_ = awaitProbe(t, probe.entered)
	waitForPendingWorkerdWaiters(t, launcher, request, 2)
	cancelFirst()
	if result := <-firstResult; !errors.Is(result.err, context.Canceled) || result.handle != nil {
		t.Fatalf("canceled waiter result = %#v", result)
	}
	if signals := process.signalSnapshot(); len(signals) != 0 {
		t.Fatalf("one canceled waiter signaled shared process: %#v", signals)
	}
	probe.release(request.ShardID)
	result := <-secondResult
	if result.err != nil || result.handle == nil {
		t.Fatalf("remaining waiter result = %#v", result)
	}
	if err := result.handle.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}

func TestWorkerdProcessLauncherLastWaiterCancellationAbandonsAndCleansStart(t *testing.T) {
	t.Parallel()
	firstProcess := newFakeWorkerdProcess(701, false)
	secondProcess := newFakeWorkerdProcess(702, true)
	starter := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{firstProcess, secondProcess}}
	var probeMu sync.Mutex
	probeCalls := 0
	probe := WorkerdReadinessProbeFunc(func(ctx context.Context, _ WorkerdProcessInfo) error {
		probeMu.Lock()
		probeCalls++
		call := probeCalls
		probeMu.Unlock()
		if call == 1 {
			<-ctx.Done()
			return ctx.Err()
		}
		return nil
	})
	config, _ := newWorkerdLauncherFixture(t, starter, probe)
	config.StopGracePeriod = 100 * time.Millisecond
	launcher, err := newWorkerdProcessLauncherForTest(t, config, starter)
	if err != nil {
		t.Fatal(err)
	}
	request := WorkerdEnsureRequest{ShardID: "abandoned-shard", PlacementGeneration: 11}
	waiterContext, cancelWaiter := context.WithCancel(context.Background())
	resultChannel := make(chan workerdEnsureResult, 1)
	go func() {
		handle, ensureErr := launcher.Ensure(waiterContext, request)
		resultChannel <- workerdEnsureResult{handle: handle, err: ensureErr}
	}()
	waitForPendingWorkerdWaiters(t, launcher, request, 1)
	startDeadline := time.Now().Add(2 * time.Second)
	for len(starter.commandSnapshot()) != 1 && time.Now().Before(startDeadline) {
		time.Sleep(time.Millisecond)
	}
	if starts := len(starter.commandSnapshot()); starts != 1 {
		t.Fatalf("process starts before cancellation = %d, want 1", starts)
	}
	cancelWaiter()
	if result := <-resultChannel; !errors.Is(result.err, context.Canceled) {
		t.Fatalf("last canceled waiter error = %v", result.err)
	}
	waitForNoPendingWorkerdLaunch(t, launcher, request)
	if signals := firstProcess.signalSnapshot(); !reflect.DeepEqual(signals, []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL}) {
		t.Fatalf("abandoned launch cleanup signals = %#v", signals)
	}

	handle, err := launcher.Ensure(context.Background(), request)
	if err != nil {
		t.Fatalf("Ensure(retry) error = %v", err)
	}
	if calls := starter.commandSnapshot(); len(calls) != 2 {
		t.Fatalf("retry process starts = %d, want 2", len(calls))
	}
	if err := handle.Stop(context.Background()); err != nil {
		t.Fatalf("Stop(retry) error = %v", err)
	}
}

func TestWorkerdShardHandleStopIsIdempotentTermThenKill(t *testing.T) {
	t.Parallel()
	process := newFakeWorkerdProcess(801, false)
	starter := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{process}}
	config, _ := newWorkerdLauncherFixture(t, starter, WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }))
	config.StopGracePeriod = 100 * time.Millisecond
	launcher, err := newWorkerdProcessLauncherForTest(t, config, starter)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{ShardID: "stop-shard", PlacementGeneration: 1})
	if err != nil {
		t.Fatal(err)
	}
	const workers = 32
	errorsChannel := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errorsChannel <- handle.Stop(context.Background())
		}()
	}
	wait.Wait()
	close(errorsChannel)
	for stopErr := range errorsChannel {
		if stopErr != nil {
			t.Fatalf("Stop() error = %v", stopErr)
		}
	}
	if err := handle.Stop(context.Background()); err != nil {
		t.Fatalf("Stop(replay) error = %v", err)
	}
	if signals := process.signalSnapshot(); !reflect.DeepEqual(signals, []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL}) {
		t.Fatalf("stop signals = %#v, want exactly TERM then KILL", signals)
	}
}

func TestWorkerdShardHandleStopRetriesAfterTimedOutRound(t *testing.T) {
	t.Parallel()
	process := newFakeWorkerdProcess(851, false)
	process.killClearsGroup = []bool{false, true}
	starter := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{process}}
	config, _ := newWorkerdLauncherFixture(t, starter, WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }))
	config.StopGracePeriod = 20 * time.Millisecond
	launcher, err := newWorkerdProcessLauncherForTest(t, config, starter)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{ShardID: "retry-stop", PlacementGeneration: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := handle.Stop(context.Background()); !errors.Is(err, ErrWorkerdStopTimeout) {
		t.Fatalf("Stop(first round) error = %v, want timeout", err)
	}
	if err := handle.Stop(context.Background()); err != nil {
		t.Fatalf("Stop(second round) error = %v", err)
	}
	wantSignals := []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL, syscall.SIGTERM, syscall.SIGKILL}
	if signals := process.signalSnapshot(); !reflect.DeepEqual(signals, wantSignals) {
		t.Fatalf("stop retry signals = %#v, want %#v", signals, wantSignals)
	}
}

func TestWorkerdProcessLauncherBlocksReplacementUntilFailedStopIsRetried(t *testing.T) {
	t.Parallel()
	oldProcess := newFakeWorkerdProcess(853, false)
	oldProcess.killClearsGroup = []bool{false, false, true}
	newProcess := newFakeWorkerdProcess(854, true)
	starter := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{oldProcess, newProcess}}
	_, launcher := newWorkerdLauncherFixture(t, starter, WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }))
	oldHandle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
		ShardID: "failed-stop-replacement", PlacementGeneration: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := oldHandle.Stop(context.Background()); !errors.Is(err, ErrWorkerdStopTimeout) {
		t.Fatalf("Stop(first round) error = %v, want timeout", err)
	}
	if handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
		ShardID: "failed-stop-replacement", PlacementGeneration: 2,
	}); handle != nil || !errors.Is(err, ErrWorkerdStopTimeout) {
		t.Fatalf("Ensure(while old group lives) = %#v, %v, want nil, stop timeout", handle, err)
	}
	if starts := len(starter.commandSnapshot()); starts != 1 {
		t.Fatalf("process starts before termination proof = %d, want 1", starts)
	}
	if err := oldHandle.Stop(context.Background()); err != nil {
		t.Fatalf("Stop(retry) error = %v", err)
	}
	newHandle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
		ShardID: "failed-stop-replacement", PlacementGeneration: 2,
	})
	if err != nil {
		t.Fatalf("Ensure(after termination proof) error = %v", err)
	}
	if err := newHandle.Stop(context.Background()); err != nil {
		t.Fatalf("Stop(replacement) error = %v", err)
	}
}

func TestWorkerdProcessLauncherCleansDescendantsAfterNaturalLeaderExit(t *testing.T) {
	t.Parallel()
	process := newFakeWorkerdProcess(852, false)
	starter := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{process}}
	_, launcher := newWorkerdLauncherFixture(t, starter, WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }))
	handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{ShardID: "leader-exit-descendant", PlacementGeneration: 1})
	if err != nil {
		t.Fatal(err)
	}
	process.finish(nil)
	select {
	case <-process.waitObserved:
	case <-time.After(2 * time.Second):
		t.Fatal("launcher did not observe natural leader exit")
	}
	waitForWorkerdSignals(t, process, []syscall.Signal{syscall.SIGKILL})
	if err := handle.Stop(context.Background()); err != nil {
		t.Fatalf("Stop(exact handle after leader exit) error = %v", err)
	}
	wantSignals := []syscall.Signal{syscall.SIGKILL}
	if signals := process.signalSnapshot(); !reflect.DeepEqual(signals, wantSignals) {
		t.Fatalf("descendant cleanup signals = %#v, want %#v", signals, wantSignals)
	}
}

func TestWorkerdShardHandleStaleGenerationCannotStopReplacement(t *testing.T) {
	t.Parallel()
	oldProcess := newFakeWorkerdProcess(901, true)
	newProcess := newFakeWorkerdProcess(902, true)
	starter := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{oldProcess, newProcess}}
	_, launcher := newWorkerdLauncherFixture(t, starter, WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }))
	oldHandle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{ShardID: "replacement-shard", PlacementGeneration: 4})
	if err != nil {
		t.Fatal(err)
	}
	newHandle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{ShardID: "replacement-shard", PlacementGeneration: 5})
	if err != nil {
		t.Fatal(err)
	}
	if oldHandle == newHandle || newHandle.PlacementGeneration() != 5 {
		t.Fatalf("replacement handles = %p/%p generation=%d", oldHandle, newHandle, newHandle.PlacementGeneration())
	}
	if signals := oldProcess.signalSnapshot(); !reflect.DeepEqual(signals, []syscall.Signal{syscall.SIGTERM}) {
		t.Fatalf("replaced process signals = %#v, want TERM", signals)
	}
	if err := oldHandle.Stop(context.Background()); err != nil {
		t.Fatalf("Stop(retired exact generation) error = %v", err)
	}
	if signals := newProcess.signalSnapshot(); len(signals) != 0 {
		t.Fatalf("stale handle signaled replacement: %#v", signals)
	}
	if err := newHandle.Stop(context.Background()); err != nil {
		t.Fatalf("Stop(replacement) error = %v", err)
	}
}

func TestWorkerdProcessLauncherEvidenceFailsClosedWithoutResourceAuthority(t *testing.T) {
	t.Parallel()
	config, launcher := newWorkerdLauncherFixture(t, &recordingWorkerdStarter{}, WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }))
	evidence := launcher.Evidence()
	if evidence.ExecutableDigest != config.ExecutableDigest || !evidence.VerifiedOpenExecutable || !evidence.SealedExecutableSnapshot ||
		evidence.ProcessGroupTermination || !evidence.ExplicitEnvironment || evidence.ChildFDAllowlist ||
		!evidence.BoundedOutput || !evidence.ReadinessGated {
		t.Fatalf("implemented launcher evidence = %#v", evidence)
	}
	if evidence.AtomicCgroupPlacement || evidence.CgroupLimits || evidence.CgroupTermination || evidence.CPUAccounting ||
		evidence.RSSAccounting || evidence.KillReconstruction || evidence.AdmissionReady {
		t.Fatalf("resource authority must fail closed: %#v", evidence)
	}
	wantMissing := []string{
		"agentd-cgroup-limits",
		"agentd-cgroup-termination",
		"agentd-cpu-accounting",
		"agentd-rss-accounting",
		"workerd-child-fd-allowlist",
		"workerd-kill-reconstruction",
	}
	if !reflect.DeepEqual(evidence.MissingCapabilities, wantMissing) {
		t.Fatalf("missing capabilities = %#v, want %#v", evidence.MissingCapabilities, wantMissing)
	}
}

func TestWorkerdProcessLauncherCloseIsConcurrentIdempotentAndClosesExecutable(t *testing.T) {
	t.Parallel()
	process := newFakeWorkerdProcess(1_001, false)
	starter := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{process}}
	config, _ := newWorkerdLauncherFixture(t, starter, WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }))
	config.StopGracePeriod = 100 * time.Millisecond
	launcher, err := newWorkerdProcessLauncherForTest(t, config, starter)
	if err != nil {
		t.Fatal(err)
	}
	_, err = launcher.Ensure(context.Background(), WorkerdEnsureRequest{ShardID: "close-current", PlacementGeneration: 1})
	if err != nil {
		t.Fatal(err)
	}
	executable := launcher.executable

	const closers = 32
	errorsChannel := make(chan error, closers)
	var wait sync.WaitGroup
	for range closers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errorsChannel <- launcher.Close(context.Background())
		}()
	}
	wait.Wait()
	close(errorsChannel)
	for closeErr := range errorsChannel {
		if closeErr != nil {
			t.Fatalf("Close() error = %v", closeErr)
		}
	}
	if err := launcher.Close(context.Background()); err != nil {
		t.Fatalf("Close(replay) error = %v", err)
	}
	waitForWorkerdSignals(t, process, []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL})
	waitForClosedWorkerdExecutable(t, executable)
	if handle, ensureErr := launcher.Ensure(context.Background(), WorkerdEnsureRequest{ShardID: "after-close", PlacementGeneration: 1}); handle != nil || !errors.Is(ensureErr, ErrWorkerdLauncherClosed) {
		t.Fatalf("Ensure(after Close) = %#v, %v, want nil, closed", handle, ensureErr)
	}
}

func TestWorkerdProcessLauncherCloseCallerCancellationOnlyStopsWaiting(t *testing.T) {
	t.Parallel()
	process := newFakeWorkerdProcess(1_101, false)
	starter := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{process}}
	config, _ := newWorkerdLauncherFixture(t, starter, WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }))
	config.StopGracePeriod = 100 * time.Millisecond
	launcher, err := newWorkerdProcessLauncherForTest(t, config, starter)
	if err != nil {
		t.Fatal(err)
	}
	_, err = launcher.Ensure(context.Background(), WorkerdEnsureRequest{ShardID: "canceled-close", PlacementGeneration: 1})
	if err != nil {
		t.Fatal(err)
	}
	executable := launcher.executable
	closeContext, cancelClose := context.WithCancel(context.Background())
	cancelClose()
	if err := launcher.Close(closeContext); !errors.Is(err, context.Canceled) {
		t.Fatalf("Close(canceled caller) error = %v", err)
	}
	waitForWorkerdSignals(t, process, []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL})
	waitForClosedWorkerdExecutable(t, executable)
	if err := launcher.Close(context.Background()); err != nil {
		t.Fatalf("Close(wait for shared cleanup) error = %v", err)
	}
}

func TestWorkerdProcessLauncherCloseRetriesFailedCleanupRound(t *testing.T) {
	t.Parallel()
	process := newFakeWorkerdProcess(1_111, false)
	process.killClearsGroup = []bool{false, true}
	starter := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{process}}
	config, _ := newWorkerdLauncherFixture(t, starter, WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }))
	config.StopGracePeriod = 20 * time.Millisecond
	launcher, err := newWorkerdProcessLauncherForTest(t, config, starter)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{ShardID: "retry-close", PlacementGeneration: 1}); err != nil {
		t.Fatal(err)
	}
	executable := launcher.executable
	if err := launcher.Close(context.Background()); !errors.Is(err, ErrWorkerdStopTimeout) {
		t.Fatalf("Close(first round) error = %v, want timeout", err)
	}
	if _, err := executable.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("sealed executable after failed Close Stat() error = %v, want closed", err)
	}
	if err := launcher.Close(context.Background()); err != nil {
		t.Fatalf("Close(second round) error = %v", err)
	}
	wantSignals := []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL, syscall.SIGTERM, syscall.SIGKILL}
	if signals := process.signalSnapshot(); !reflect.DeepEqual(signals, wantSignals) {
		t.Fatalf("close retry signals = %#v, want %#v", signals, wantSignals)
	}
}

func TestWorkerdProcessLauncherCloseStartsAllCurrentProcessGroupsConcurrently(t *testing.T) {
	t.Parallel()
	firstProcess := newFakeWorkerdProcess(1_151, false)
	secondProcess := newFakeWorkerdProcess(1_152, false)
	starter := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{firstProcess, secondProcess}}
	config, _ := newWorkerdLauncherFixture(t, starter, WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }))
	config.StopGracePeriod = 500 * time.Millisecond
	launcher, err := newWorkerdProcessLauncherForTest(t, config, starter)
	if err != nil {
		t.Fatal(err)
	}
	for index, shardID := range []string{"close-concurrent-a", "close-concurrent-b"} {
		if _, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{ShardID: shardID, PlacementGeneration: uint64(index + 1)}); err != nil {
			t.Fatalf("Ensure(%s) error = %v", shardID, err)
		}
	}
	closeResult := make(chan error, 1)
	go func() { closeResult <- launcher.Close(context.Background()) }()
	waitForWorkerdLauncherClosed(t, launcher)
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		firstSignals := firstProcess.signalSnapshot()
		secondSignals := secondProcess.signalSnapshot()
		if reflect.DeepEqual(firstSignals, []syscall.Signal{syscall.SIGTERM}) &&
			reflect.DeepEqual(secondSignals, []syscall.Signal{syscall.SIGTERM}) {
			firstProcess.finishGroup(nil)
			secondProcess.finishGroup(nil)
			if err := <-closeResult; err != nil {
				t.Fatalf("Close() error = %v", err)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("Close did not fan out TERM: first=%#v second=%#v", firstProcess.signalSnapshot(), secondProcess.signalSnapshot())
}

func TestWorkerdProcessLauncherCloseWinsReadinessPublicationRace(t *testing.T) {
	t.Parallel()
	process := newFakeWorkerdProcess(1_201, false)
	starter := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{process}}
	entered := make(chan WorkerdProcessInfo, 1)
	release := make(chan struct{})
	probe := WorkerdReadinessProbeFunc(func(_ context.Context, info WorkerdProcessInfo) error {
		entered <- info
		<-release
		return nil
	})
	config, _ := newWorkerdLauncherFixture(t, starter, probe)
	config.StopGracePeriod = 100 * time.Millisecond
	launcher, err := newWorkerdProcessLauncherForTest(t, config, starter)
	if err != nil {
		t.Fatal(err)
	}
	ensureResult := make(chan workerdEnsureResult, 1)
	go func() {
		handle, ensureErr := launcher.Ensure(context.Background(), WorkerdEnsureRequest{ShardID: "publication-race", PlacementGeneration: 1})
		ensureResult <- workerdEnsureResult{handle: handle, err: ensureErr}
	}()
	_ = awaitProbe(t, entered)
	closeResult := make(chan error, 1)
	go func() { closeResult <- launcher.Close(context.Background()) }()
	waitForWorkerdLauncherClosed(t, launcher)
	close(release)
	if result := <-ensureResult; result.handle != nil || !errors.Is(result.err, ErrWorkerdLauncherClosed) {
		t.Fatalf("Ensure(close/publication race) = %#v, %v, want nil, closed", result.handle, result.err)
	}
	if err := <-closeResult; err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if signals := process.signalSnapshot(); !reflect.DeepEqual(signals, []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL}) {
		t.Fatalf("publication-race cleanup signals = %#v", signals)
	}
}

func TestWorkerdProcessLauncherCloseRacesReplacementAndHandleStopWithoutCrossSignal(t *testing.T) {
	t.Parallel()
	oldProcess := newFakeWorkerdProcess(1_301, false)
	newProcess := newFakeWorkerdProcess(1_302, false)
	starter := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{oldProcess, newProcess}}
	replacementEntered := make(chan WorkerdProcessInfo, 1)
	releaseReplacement := make(chan struct{})
	probe := WorkerdReadinessProbeFunc(func(_ context.Context, info WorkerdProcessInfo) error {
		if info.PlacementGeneration == 1 {
			return nil
		}
		replacementEntered <- info
		<-releaseReplacement
		return nil
	})
	config, _ := newWorkerdLauncherFixture(t, starter, probe)
	config.StopGracePeriod = 100 * time.Millisecond
	launcher, err := newWorkerdProcessLauncherForTest(t, config, starter)
	if err != nil {
		t.Fatal(err)
	}
	oldHandle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{ShardID: "close-replacement", PlacementGeneration: 1})
	if err != nil {
		t.Fatal(err)
	}
	replacementResult := make(chan workerdEnsureResult, 1)
	go func() {
		handle, ensureErr := launcher.Ensure(context.Background(), WorkerdEnsureRequest{ShardID: "close-replacement", PlacementGeneration: 2})
		replacementResult <- workerdEnsureResult{handle: handle, err: ensureErr}
	}()
	_ = awaitProbe(t, replacementEntered)
	closeResult := make(chan error, 1)
	go func() { closeResult <- launcher.Close(context.Background()) }()
	waitForWorkerdLauncherClosed(t, launcher)
	stopResult := make(chan error, 1)
	go func() { stopResult <- oldHandle.Stop(context.Background()) }()
	close(releaseReplacement)
	if result := <-replacementResult; result.handle != nil || !errors.Is(result.err, ErrWorkerdLauncherClosed) {
		t.Fatalf("replacement Ensure() = %#v, %v, want nil, closed", result.handle, result.err)
	}
	if err := <-stopResult; err != nil {
		t.Fatalf("old handle Stop() error = %v", err)
	}
	if err := <-closeResult; err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	wantSignals := []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL}
	if signals := oldProcess.signalSnapshot(); !reflect.DeepEqual(signals, wantSignals) {
		t.Fatalf("old process signals = %#v, want %#v", signals, wantSignals)
	}
	if signals := newProcess.signalSnapshot(); !reflect.DeepEqual(signals, wantSignals) {
		t.Fatalf("replacement process signals = %#v, want %#v", signals, wantSignals)
	}
}

func TestWorkerdProcessLauncherProductionStarterRunsOpenedTestBinary(t *testing.T) {
	t.Setenv("CIRCULUSD_AMBIENT_SECRET", "must-not-cross-exec")
	currentExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(currentExecutable)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	executablePath := filepath.Join(t.TempDir(), "workerd-test-binary")
	target, err := os.OpenFile(executablePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	if _, err := io.Copy(io.MultiWriter(target, hash), source); err != nil {
		_ = target.Close()
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(executablePath, 0o500); err != nil {
		t.Fatal(err)
	}
	readyPath := filepath.Join(t.TempDir(), "ready")
	probe := WorkerdReadinessProbeFunc(func(ctx context.Context, _ WorkerdProcessInfo) error {
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			if _, statErr := os.Stat(readyPath); statErr == nil {
				return nil
			} else if !errors.Is(statErr, os.ErrNotExist) {
				return statErr
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
			}
		}
	})
	launcher, err := newWorkerdProcessLauncher(WorkerdLauncherConfig{
		ExecutablePath:   executablePath,
		ExecutableDigest: fmt.Sprintf("sha256:%x", hash.Sum(nil)),
		ReadinessTimeout: 2 * time.Second,
		StopGracePeriod:  250 * time.Millisecond,
		OutputLimitBytes: 4096,
		HistoryCapacity:  128,
		ReadinessProbe:   probe,
	}, osWorkerdProcessStarter{})
	if err != nil {
		t.Fatalf("NewWorkerdProcessLauncher() error = %v", err)
	}
	closeWorkerdLauncherForTest(t, launcher)
	handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
		ShardID: "production-starter-shard", PlacementGeneration: 1,
		Arguments: []string{"-test.run=^TestWorkerdLauncherChildProcess$", "--", "--workerd-launcher-child", readyPath},
	})
	if err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	if handle.PID() <= 0 {
		t.Fatalf("PID() = %d", handle.PID())
	}
	ambient, err := os.ReadFile(readyPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(ambient) != 0 {
		t.Fatalf("child inherited ambient secret %q", ambient)
	}
	if err := handle.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error = %v; output=%#v", err, handle.Output())
	}
}

func TestWorkerdLauncherChildProcess(t *testing.T) {
	index := slices.Index(os.Args, "--workerd-launcher-child")
	if index < 0 {
		return
	}
	if index+1 >= len(os.Args) {
		t.Fatal("missing child readiness path")
	}
	if err := os.WriteFile(os.Args[index+1], []byte(os.Getenv("CIRCULUSD_AMBIENT_SECRET")), 0o600); err != nil {
		t.Fatal(err)
	}
	select {}
}

type workerdEnsureResult struct {
	handle *WorkerdShardHandle
	err    error
}

func newWorkerdLauncherFixture(t *testing.T, starter workerdProcessStarter, probe WorkerdReadinessProbe) (WorkerdLauncherConfig, *WorkerdProcessLauncher) {
	t.Helper()
	executablePath := filepath.Join(t.TempDir(), "workerd")
	content := []byte("verified-workerd-inode")
	if err := os.WriteFile(executablePath, content, 0o500); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	config := WorkerdLauncherConfig{
		ExecutablePath:   executablePath,
		ExecutableDigest: fmt.Sprintf("sha256:%x", digest),
		ReadinessTimeout: time.Second,
		StopGracePeriod:  20 * time.Millisecond,
		OutputLimitBytes: 1024,
		HistoryCapacity:  128,
		ReadinessProbe:   probe,
	}
	launcher, err := newWorkerdProcessLauncherForTest(t, config, starter)
	if err != nil {
		t.Fatalf("newWorkerdProcessLauncher() error = %v", err)
	}
	return config, launcher
}

func newWorkerdProcessLauncherForTest(t *testing.T, config WorkerdLauncherConfig, starter workerdProcessStarter) (*WorkerdProcessLauncher, error) {
	t.Helper()
	launcher, err := newWorkerdProcessLauncher(config, starter)
	if err == nil {
		closeWorkerdLauncherForTest(t, launcher)
	}
	return launcher, err
}

func closeWorkerdLauncherForTest(t *testing.T, launcher *WorkerdProcessLauncher) {
	t.Helper()
	t.Cleanup(func() {
		cleanupContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if closeErr := launcher.Close(cleanupContext); closeErr != nil {
			t.Errorf("launcher Close() error = %v", closeErr)
		}
	})
}

func startConcurrentWorkerdEnsures(launcher *WorkerdProcessLauncher, request WorkerdEnsureRequest, count int) <-chan workerdEnsureResult {
	start := make(chan struct{})
	results := make(chan workerdEnsureResult, count)
	for range count {
		go func() {
			<-start
			handle, err := launcher.Ensure(context.Background(), request)
			results <- workerdEnsureResult{handle: handle, err: err}
		}()
	}
	close(start)
	return results
}

func waitForPendingWorkerdWaiters(t *testing.T, launcher *WorkerdProcessLauncher, request WorkerdEnsureRequest, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	key := workerdLaunchKey{shardID: request.ShardID, generation: request.PlacementGeneration}
	for time.Now().Before(deadline) {
		launcher.mu.Lock()
		pending := launcher.pending[key]
		got := 0
		if pending != nil {
			got = pending.waiters
		}
		launcher.mu.Unlock()
		if got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("pending waiters did not reach %d", want)
}

func waitForNoPendingWorkerdLaunch(t *testing.T, launcher *WorkerdProcessLauncher, request WorkerdEnsureRequest) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	key := workerdLaunchKey{shardID: request.ShardID, generation: request.PlacementGeneration}
	for time.Now().Before(deadline) {
		launcher.mu.Lock()
		_, found := launcher.pending[key]
		launcher.mu.Unlock()
		if !found {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("pending launch was not removed")
}

func waitForWorkerdLauncherClosed(t *testing.T, launcher *WorkerdProcessLauncher) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		launcher.mu.Lock()
		closed := launcher.closed
		launcher.mu.Unlock()
		if closed {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("workerd launcher did not enter closed state")
}

func waitForWorkerdSignals(t *testing.T, process *fakeWorkerdProcess, want []syscall.Signal) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if signals := process.signalSnapshot(); reflect.DeepEqual(signals, want) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("process signals = %#v, want %#v", process.signalSnapshot(), want)
}

func waitForClosedWorkerdExecutable(t *testing.T, executable *os.File) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := executable.Stat(); errors.Is(err, os.ErrClosed) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	_, err := executable.Stat()
	t.Fatalf("retained executable Stat() error = %v, want closed", err)
}

func awaitProbe(t *testing.T, entered <-chan WorkerdProcessInfo) WorkerdProcessInfo {
	t.Helper()
	select {
	case info := <-entered:
		return info
	case <-time.After(2 * time.Second):
		t.Fatal("readiness probe did not start")
		return WorkerdProcessInfo{}
	}
}

type controlledWorkerdProbe struct {
	mu       sync.Mutex
	entered  chan WorkerdProcessInfo
	releases map[string]chan struct{}
	calls    int
}

func newControlledWorkerdProbe() *controlledWorkerdProbe {
	return &controlledWorkerdProbe{entered: make(chan WorkerdProcessInfo, 16), releases: make(map[string]chan struct{})}
}

func (probe *controlledWorkerdProbe) WaitReady(ctx context.Context, info WorkerdProcessInfo) error {
	probe.mu.Lock()
	probe.calls++
	release := probe.releases[info.ShardID]
	if release == nil {
		release = make(chan struct{})
		probe.releases[info.ShardID] = release
	}
	probe.mu.Unlock()
	select {
	case probe.entered <- info:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (probe *controlledWorkerdProbe) release(shardID string) {
	probe.mu.Lock()
	release := probe.releases[shardID]
	probe.mu.Unlock()
	close(release)
}

func (probe *controlledWorkerdProbe) callCount() int {
	probe.mu.Lock()
	defer probe.mu.Unlock()
	return probe.calls
}

type recordedWorkerdCommand struct {
	Executable          string
	Arguments           []string
	Environment         []string
	ExtraFiles          []*os.File
	CgroupFD            int
	ShardID             string
	PlacementGeneration uint64
	executableContent   []byte
}

type recordingWorkerdStarter struct {
	mu            sync.Mutex
	commands      []recordedWorkerdCommand
	processes     []*fakeWorkerdProcess
	startErr      error
	startErrors   []error
	stdoutPayload string
	stderrPayload string
}

func (starter *recordingWorkerdStarter) Start(command workerdLaunchCommand) (workerdStartedProcess, error) {
	content, readErr := os.ReadFile(command.Executable)
	recorded := recordedWorkerdCommand{
		Executable: command.Executable, Arguments: slices.Clone(command.Arguments),
		Environment: slices.Clone(command.Environment), ExtraFiles: slices.Clone(command.ExtraFiles),
		CgroupFD: command.CgroupFD,
		ShardID:  command.ShardID, PlacementGeneration: command.PlacementGeneration,
		executableContent: content,
	}
	starter.mu.Lock()
	index := len(starter.commands)
	starter.commands = append(starter.commands, recorded)
	var process *fakeWorkerdProcess
	if index < len(starter.processes) {
		process = starter.processes[index]
	}
	startErr := starter.startErr
	if index < len(starter.startErrors) {
		startErr = starter.startErrors[index]
	}
	stdoutPayload, stderrPayload := starter.stdoutPayload, starter.stderrPayload
	starter.mu.Unlock()
	if readErr != nil {
		return nil, readErr
	}
	if startErr != nil {
		return nil, startErr
	}
	if process == nil {
		process = newFakeWorkerdProcess(10_000+index, true)
	}
	if _, err := io.WriteString(command.Stdout, stdoutPayload); err != nil {
		return nil, err
	}
	if _, err := io.WriteString(command.Stderr, stderrPayload); err != nil {
		return nil, err
	}
	return process, nil
}

func (starter *recordingWorkerdStarter) commandSnapshot() []recordedWorkerdCommand {
	starter.mu.Lock()
	defer starter.mu.Unlock()
	return slices.Clone(starter.commands)
}

type fakeWorkerdProcess struct {
	mu               sync.Mutex
	pid              int
	exit             chan struct{}
	exitOnce         sync.Once
	waitErr          error
	signals          []syscall.Signal
	terminateOnTERM  bool
	groupAlive       bool
	killClearsGroup  []bool
	killCalls        int
	waitObserved     chan struct{}
	waitObservedOnce sync.Once
}

func newFakeWorkerdProcess(pid int, terminateOnTERM bool) *fakeWorkerdProcess {
	return &fakeWorkerdProcess{
		pid: pid, exit: make(chan struct{}), terminateOnTERM: terminateOnTERM,
		groupAlive: true, waitObserved: make(chan struct{}),
	}
}

func (process *fakeWorkerdProcess) PID() int {
	return process.pid
}

func (process *fakeWorkerdProcess) Wait() error {
	<-process.exit
	process.waitObservedOnce.Do(func() { close(process.waitObserved) })
	process.mu.Lock()
	defer process.mu.Unlock()
	return process.waitErr
}

func (process *fakeWorkerdProcess) SignalGroup(signal syscall.Signal) error {
	process.mu.Lock()
	process.signals = append(process.signals, signal)
	terminate := signal == syscall.SIGTERM && process.terminateOnTERM
	if signal == syscall.SIGKILL {
		terminate = true
		if process.killCalls < len(process.killClearsGroup) {
			terminate = process.killClearsGroup[process.killCalls]
		}
		process.killCalls++
	}
	if terminate {
		process.groupAlive = false
	}
	process.mu.Unlock()
	if terminate {
		process.finish(nil)
	}
	return nil
}

func (process *fakeWorkerdProcess) GroupAlive() (bool, error) {
	process.mu.Lock()
	defer process.mu.Unlock()
	return process.groupAlive, nil
}

func (process *fakeWorkerdProcess) finish(err error) {
	process.exitOnce.Do(func() {
		process.mu.Lock()
		process.waitErr = err
		process.mu.Unlock()
		close(process.exit)
	})
}

func (process *fakeWorkerdProcess) finishGroup(err error) {
	process.mu.Lock()
	process.groupAlive = false
	process.mu.Unlock()
	process.finish(err)
}

func (process *fakeWorkerdProcess) signalSnapshot() []syscall.Signal {
	process.mu.Lock()
	defer process.mu.Unlock()
	return slices.Clone(process.signals)
}
