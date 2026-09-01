//go:build linux

package agent

import (
	"bytes"
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

	"github.com/hancomac/circulusd/internal/identity"
	"golang.org/x/sys/unix"
)

func TestWorkerdProcessBoundaryUsesOnlyTypedShardGeneration(t *testing.T) {
	agentInstanceIDType := reflect.TypeOf(identity.ID{})
	shardGenerationType := reflect.TypeOf(ShardGeneration(0))
	for _, contract := range []struct {
		name       string
		value      any
		wantedName string
	}{
		{name: "ensure request", value: WorkerdEnsureRequest{}, wantedName: "ShardGeneration"},
		{name: "readiness info", value: WorkerdProcessInfo{}, wantedName: "ShardGeneration"},
		{name: "launch command", value: workerdLaunchCommand{}, wantedName: "ShardGeneration"},
	} {
		contractType := reflect.TypeOf(contract.value)
		if _, found := contractType.FieldByName("PlacementGeneration"); found {
			t.Errorf("%s still exposes PlacementGeneration", contract.name)
		}
		field, found := contractType.FieldByName(contract.wantedName)
		if !found || field.Type != shardGenerationType {
			t.Errorf("%s %s field = %#v, want %v", contract.name, contract.wantedName, field, shardGenerationType)
		}
		agentInstanceID, found := contractType.FieldByName("AgentInstanceID")
		if !found || agentInstanceID.Type != agentInstanceIDType {
			t.Errorf("%s AgentInstanceID field = %#v, want %v", contract.name, agentInstanceID, agentInstanceIDType)
		}
	}
	for _, contract := range []struct {
		name      string
		value     any
		fieldName string
		agentName string
	}{
		{name: "launch key", value: workerdLaunchKey{}, fieldName: "generation", agentName: "agentInstanceID"},
		{name: "cgroup lease", value: workerdCgroupLease{}, fieldName: "generation", agentName: "agentInstanceID"},
		{name: "cgroup sample", value: workerdCgroupResourceSample{}, fieldName: "Generation", agentName: "AgentInstanceID"},
	} {
		contractType := reflect.TypeOf(contract.value)
		field, found := contractType.FieldByName(contract.fieldName)
		if !found || field.Type != shardGenerationType {
			t.Errorf("%s generation field = %#v, want %v", contract.name, field, shardGenerationType)
		}
		agentInstanceID, found := contractType.FieldByName(contract.agentName)
		if !found || agentInstanceID.Type != agentInstanceIDType {
			t.Errorf("%s AgentInstanceID field = %#v, want %v", contract.name, agentInstanceID, agentInstanceIDType)
		}
	}
	shardKeyType := reflect.TypeOf(workerdShardKey{})
	for _, fieldName := range []string{"current", "latestGenerations", "retiredGenerations"} {
		field, found := reflect.TypeOf(WorkerdProcessLauncher{}).FieldByName(fieldName)
		if !found || field.Type.Kind() != reflect.Map || field.Type.Key() != shardKeyType {
			t.Errorf("WorkerdProcessLauncher.%s = %#v, want map keyed by %v", fieldName, field, shardKeyType)
		}
	}
	for _, fieldName := range []string{"agentInstanceID", "shardID"} {
		if _, found := shardKeyType.FieldByName(fieldName); !found {
			t.Errorf("workerdShardKey missing %s", fieldName)
		}
	}
	handleType := reflect.TypeOf((*WorkerdShardHandle)(nil))
	if _, found := handleType.MethodByName("PlacementGeneration"); found {
		t.Error("WorkerdShardHandle still exposes PlacementGeneration")
	}
	method, found := handleType.MethodByName("ShardGeneration")
	if !found || method.Type.NumOut() != 1 || method.Type.Out(0) != shardGenerationType {
		t.Errorf("WorkerdShardHandle.ShardGeneration = %#v, want %v result", method, shardGenerationType)
	}
	agentMethod, found := handleType.MethodByName("AgentInstanceID")
	if !found || agentMethod.Type.NumOut() != 1 || agentMethod.Type.Out(0) != agentInstanceIDType {
		t.Errorf("WorkerdShardHandle.AgentInstanceID = %#v, want %v result", agentMethod, agentInstanceIDType)
	}
}

func TestOSWorkerdProcessStarterUsesCloneIntoCgroupWithoutExtraFile(t *testing.T) {
	var startedCommand *exec.Cmd
	starter := osWorkerdProcessStarter{start: func(command *exec.Cmd) error {
		startedCommand = command
		command.Process = &os.Process{Pid: 20_010}
		return nil
	}}
	process, err := starter.Start(workerdLaunchCommand{
		Executable: "/sealed/workerd", CgroupFD: 47, ExtraFiles: make([]*os.File, 0),
		Stdout: io.Discard, Stderr: io.Discard, AgentInstanceID: workerdTestAgentInstanceID(0),
		ShardID: "starter-shard", ShardGeneration: 1,
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

func TestOSWorkerdProcessStarterRejectsMissingOrWrongKindAgentIdentityBeforeCallback(t *testing.T) {
	tenantID, err := identity.New(identity.Tenant)
	if err != nil {
		t.Fatalf("identity.New(tenant) error = %v", err)
	}
	for name, agentInstanceID := range map[string]identity.ID{
		"empty":      {},
		"wrong kind": tenantID,
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			starter := osWorkerdProcessStarter{start: func(command *exec.Cmd) error {
				calls++
				command.Process = &os.Process{Pid: 20_011}
				return nil
			}}
			process, startErr := starter.Start(workerdLaunchCommand{
				Executable: "/sealed/workerd", CgroupFD: -1, Stdout: io.Discard, Stderr: io.Discard,
				AgentInstanceID: agentInstanceID, ShardID: "starter-shard", ShardGeneration: 1,
			})
			if process != nil || !errors.Is(startErr, ErrInvalidWorkerdEnsureRequest) || calls != 0 {
				t.Fatalf("Start() = %#v, %v, calls=%d; want nil/invalid request/no callback", process, startErr, calls)
			}
		})
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
			handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0),
				ShardID: fmt.Sprintf("unbounded-args-%d", index), ShardGeneration: 1, Arguments: test.arguments,
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
	handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0),
		ShardID: "bounded-args", ShardGeneration: 1, Arguments: maximumArguments,
	})
	if err != nil {
		t.Fatalf("Ensure(exact 1 MiB arguments) error = %v", err)
	}
	if err := handle.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}

func TestWorkerdProcessLauncherRejectsMissingOrWrongKindAgentIdentityBeforeStart(t *testing.T) {
	t.Parallel()
	starter := &recordingWorkerdStarter{}
	_, launcher := newWorkerdLauncherFixture(t, starter, WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }))
	tenantID, err := identity.New(identity.Tenant)
	if err != nil {
		t.Fatalf("identity.New(tenant) error = %v", err)
	}
	for name, agentInstanceID := range map[string]identity.ID{
		"empty":      {},
		"wrong kind": tenantID,
	} {
		t.Run(name, func(t *testing.T) {
			handle, ensureErr := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
				AgentInstanceID: agentInstanceID,
				ShardID:         "invalid-agent-identity",
				ShardGeneration: 1,
			})
			if handle != nil || !errors.Is(ensureErr, ErrInvalidWorkerdEnsureRequest) {
				t.Fatalf("Ensure() = %#v, %v, want nil/ErrInvalidWorkerdEnsureRequest", handle, ensureErr)
			}
		})
	}
	if commands := starter.commandSnapshot(); len(commands) != 0 {
		t.Fatalf("invalid agent identities started %d process(es)", len(commands))
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
		_, ensureErr := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0),
			ShardID: fmt.Sprintf("failed-history-%02d", index), ShardGeneration: 1,
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
		request := WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0), ShardID: fmt.Sprintf("canceled-history-%d", index), ShardGeneration: 1}
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
	_, err = launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0), ShardID: "over-canceled-cap", ShardGeneration: 1})
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
	handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0),
		ShardID: "shared-shard-a", ShardGeneration: 7, Arguments: []string{"serve", "--config=/sealed/workerd.capnp"},
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
	if command.ShardID != "shared-shard-a" || command.ShardGeneration != 7 {
		t.Fatalf("command identity = %q/%d", command.ShardID, command.ShardGeneration)
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
	handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0), ShardID: "sealed-owner-writable", ShardGeneration: 1})
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
	request := WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0), ShardID: "shared-shard", ShardGeneration: 9, Arguments: []string{"serve"}}

	const workers = 64
	results := startConcurrentWorkerdEnsures(launcher, request, workers)
	entered := awaitProbe(t, probe.entered)
	if entered.AgentInstanceID != request.AgentInstanceID || entered.ShardID != request.ShardID || entered.ShardGeneration != request.ShardGeneration || entered.PID != process.pid {
		t.Fatalf("readiness identity = %#v", entered)
	}
	waitForPendingWorkerdWaiters(t, launcher, request, workers)
	select {
	case result := <-results:
		t.Fatalf("Ensure returned before readiness: %#v", result)
	default:
	}

	_, conflictErr := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0),
		ShardID: request.ShardID, ShardGeneration: request.ShardGeneration, Arguments: []string{"different"},
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

func TestWorkerdProcessLauncherStaysBoundToFirstAgentBootAfterStopAtCapacityOne(t *testing.T) {
	t.Parallel()
	oldProcess := newFakeWorkerdProcess(221, true)
	starter := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{oldProcess}}
	config, _ := newWorkerdLauncherFixture(t, starter, WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }))
	config.HistoryCapacity = 1
	launcher, err := newWorkerdProcessLauncherForTest(t, config, starter)
	if err != nil {
		t.Fatalf("newWorkerdProcessLauncherForTest() error = %v", err)
	}
	oldAgentInstanceID := workerdTestAgentInstanceID(0)
	newAgentInstanceID := workerdTestAgentInstanceID(1)
	oldHandle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
		AgentInstanceID: oldAgentInstanceID,
		ShardID:         "cross-boot-shard",
		ShardGeneration: 7,
		Arguments:       []string{"serve"},
	})
	if err != nil {
		t.Fatalf("Ensure(old boot) error = %v", err)
	}
	if err := oldHandle.Stop(context.Background()); err != nil {
		t.Fatalf("Stop(old boot) error = %v", err)
	}
	newHandle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
		AgentInstanceID: newAgentInstanceID,
		ShardID:         "cross-boot-shard",
		ShardGeneration: 7,
		Arguments:       []string{"serve"},
	})
	if newHandle != nil || !errors.Is(err, ErrWorkerdAgentInstanceMismatch) {
		t.Fatalf("Ensure(new boot) = %#v, %v, want nil/ErrWorkerdAgentInstanceMismatch", newHandle, err)
	}
	commands := starter.commandSnapshot()
	if len(commands) != 1 || commands[0].AgentInstanceID != oldAgentInstanceID {
		t.Fatalf("lifetime-bound launch commands = %#v, want only old boot", commands)
	}
}

func TestWorkerdProcessLauncherConcurrentFirstBindAdmitsExactlyOneAgentBoot(t *testing.T) {
	t.Parallel()
	starter := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{
		newFakeWorkerdProcess(231, true), newFakeWorkerdProcess(232, true),
	}}
	var readinessMu sync.Mutex
	readinessCalls := 0
	_, launcher := newWorkerdLauncherFixture(t, starter, WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error {
		readinessMu.Lock()
		readinessCalls++
		readinessMu.Unlock()
		return nil
	}))
	type bindResult struct {
		agentInstanceID identity.ID
		handle          *WorkerdShardHandle
		err             error
	}
	start := make(chan struct{})
	results := make(chan bindResult, 2)
	for _, agentInstanceID := range []identity.ID{workerdTestAgentInstanceID(2), workerdTestAgentInstanceID(3)} {
		agentInstanceID := agentInstanceID
		go func() {
			<-start
			handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
				AgentInstanceID: agentInstanceID,
				ShardID:         "first-bind-race",
				ShardGeneration: 1,
				Arguments:       []string{"serve"},
			})
			results <- bindResult{agentInstanceID: agentInstanceID, handle: handle, err: err}
		}()
	}
	close(start)
	var winner bindResult
	successes := 0
	mismatches := 0
	for range 2 {
		result := <-results
		switch {
		case result.err == nil && result.handle != nil:
			successes++
			winner = result
		case result.handle == nil && errors.Is(result.err, ErrWorkerdAgentInstanceMismatch):
			mismatches++
		default:
			t.Fatalf("first-bind result = %#v", result)
		}
	}
	if successes != 1 || mismatches != 1 {
		t.Fatalf("first-bind outcomes = successes:%d mismatches:%d, want 1/1", successes, mismatches)
	}
	commands := starter.commandSnapshot()
	if len(commands) != 1 || commands[0].AgentInstanceID != winner.agentInstanceID {
		t.Fatalf("first-bind commands = %#v, winner = %q", commands, winner.agentInstanceID)
	}
	readinessMu.Lock()
	observedReadinessCalls := readinessCalls
	readinessMu.Unlock()
	if observedReadinessCalls != 1 {
		t.Fatalf("first-bind readiness callbacks = %d, want one", observedReadinessCalls)
	}
	if err := winner.handle.Stop(context.Background()); err != nil {
		t.Fatalf("Stop(winner) error = %v", err)
	}
}

func TestWorkerdProcessLauncherSnapshotsArgumentsAndStoresFixedIdentity(t *testing.T) {
	t.Parallel()
	process := newFakeWorkerdProcess(251, true)
	starter := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{process}}
	probe := newControlledWorkerdProbe()
	_, launcher := newWorkerdLauncherFixture(t, starter, probe)
	arguments := []string{"serve", "original"}
	request := WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0), ShardID: "argument-snapshot", ShardGeneration: 1, Arguments: arguments}
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
	identityBytes := len(launcher.launchIdentities[workerdLaunchKey{agentInstanceID: request.AgentInstanceID, shardID: request.ShardID, generation: request.ShardGeneration}])
	launcher.mu.Unlock()
	if identityBytes != sha256.Size {
		t.Fatalf("stored launch identity bytes = %d, want fixed SHA-256 size", identityBytes)
	}
	if _, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0),
		ShardID: request.ShardID, ShardGeneration: request.ShardGeneration, Arguments: []string{"serve", "original"},
	}); err != nil {
		t.Fatalf("Ensure(original replay) error = %v", err)
	}
	if _, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0),
		ShardID: request.ShardID, ShardGeneration: request.ShardGeneration, Arguments: arguments,
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
	for generation := ShardGeneration(1); generation <= 12; generation++ {
		var err error
		handle, err = launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0),
			ShardID: "identity-pruning", ShardGeneration: generation, Arguments: []string{fmt.Sprintf("generation-%d", generation)},
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
	handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0), ShardID: "lazy-output", ShardGeneration: 1})
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
		{AgentInstanceID: workerdTestAgentInstanceID(0), ShardID: "shard-a", ShardGeneration: 1, Arguments: []string{"serve", "a"}},
		{AgentInstanceID: workerdTestAgentInstanceID(0), ShardID: "shard-b", ShardGeneration: 1, Arguments: []string{"serve", "b"}},
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
		if info.ShardGeneration == 2 {
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
		handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0),
			ShardID: "serialized-generation", ShardGeneration: 1,
		})
		firstResult <- workerdEnsureResult{handle: handle, err: err}
	}()
	if info := awaitProbe(t, entered); info.ShardGeneration != 1 {
		t.Fatalf("first readiness generation = %d, want 1", info.ShardGeneration)
	}
	secondResult := make(chan workerdEnsureResult, 1)
	go func() {
		handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0),
			ShardID: "serialized-generation", ShardGeneration: 2,
		})
		secondResult <- workerdEnsureResult{handle: handle, err: err}
	}()
	select {
	case info := <-entered:
		t.Fatalf("generation %d started before generation 1 resolved", info.ShardGeneration)
	case <-time.After(50 * time.Millisecond):
	}
	close(firstReady)
	first := <-firstResult
	if first.err != nil {
		t.Fatalf("Ensure(generation 1) error = %v", first.err)
	}
	if info := awaitProbe(t, entered); info.ShardGeneration != 2 {
		t.Fatalf("second readiness generation = %d, want 2", info.ShardGeneration)
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
	request := WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0), ShardID: "timeout-shard", ShardGeneration: 1}
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
	request := WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0), ShardID: "early-exit-shard", ShardGeneration: 3}
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
	request := WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0), ShardID: "shared-cancel-shard", ShardGeneration: 1}
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
	request := WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0), ShardID: "abandoned-shard", ShardGeneration: 11}
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
	handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0), ShardID: "stop-shard", ShardGeneration: 1})
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
	handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0), ShardID: "retry-stop", ShardGeneration: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := handle.Stop(context.Background()); !errors.Is(err, ErrWorkerdStopTimeout) || errors.Is(err, ErrTerminalShardCleanup) {
		t.Fatalf("Stop(first round) error = %v, want unmarked retryable timeout", err)
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
	oldHandle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0),
		ShardID: "failed-stop-replacement", ShardGeneration: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := oldHandle.Stop(context.Background()); !errors.Is(err, ErrWorkerdStopTimeout) {
		t.Fatalf("Stop(first round) error = %v, want timeout", err)
	}
	if handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0),
		ShardID: "failed-stop-replacement", ShardGeneration: 2,
	}); handle != nil || !errors.Is(err, ErrWorkerdStopTimeout) {
		t.Fatalf("Ensure(while old group lives) = %#v, %v, want nil, stop timeout", handle, err)
	}
	if starts := len(starter.commandSnapshot()); starts != 1 {
		t.Fatalf("process starts before termination proof = %d, want 1", starts)
	}
	if err := oldHandle.Stop(context.Background()); err != nil {
		t.Fatalf("Stop(retry) error = %v", err)
	}
	newHandle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0),
		ShardID: "failed-stop-replacement", ShardGeneration: 2,
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
	handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0), ShardID: "leader-exit-descendant", ShardGeneration: 1})
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
	oldHandle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0), ShardID: "replacement-shard", ShardGeneration: 4})
	if err != nil {
		t.Fatal(err)
	}
	newHandle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0), ShardID: "replacement-shard", ShardGeneration: 5})
	if err != nil {
		t.Fatal(err)
	}
	if oldHandle == newHandle || newHandle.ShardGeneration() != 5 {
		t.Fatalf("replacement handles = %p/%p generation=%d", oldHandle, newHandle, newHandle.ShardGeneration())
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

func TestWorkerdShardHandleStaleExactIdentityIsTerminalAndSideEffectFree(t *testing.T) {
	t.Parallel()
	_, launcher := newWorkerdLauncherFixture(t, &recordingWorkerdStarter{}, WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }))
	instance := &workerdInstance{
		key: workerdLaunchKey{
			agentInstanceID: workerdTestAgentInstanceID(0),
			shardID:         "untracked-stale-handle",
			generation:      7,
		},
	}
	handle := &WorkerdShardHandle{launcher: launcher, instance: instance}

	var firstErr error
	for attempt := 0; attempt < 2; attempt++ {
		err := handle.Stop(context.Background())
		if !errors.Is(err, ErrStaleWorkerdGeneration) || !errors.Is(err, ErrTerminalShardCleanup) {
			t.Fatalf("Stop(stale exact handle attempt %d) error = %v", attempt+1, err)
		}
		if attempt == 0 {
			firstErr = err
		} else if err != firstErr {
			t.Fatalf("Stop(stale exact handle) replay error = %p, want cached %p", err, firstErr)
		}
	}
	launcher.mu.Lock()
	instances := len(launcher.instances)
	launcher.mu.Unlock()
	instance.mu.Lock()
	stop := instance.stop
	requested := instance.handleStopRequested
	instance.mu.Unlock()
	if instances != 0 || stop != nil || requested {
		t.Fatalf("stale Stop side effects = instances %d, stop %#v, requested %v", instances, stop, requested)
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
	_, err = launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0), ShardID: "close-current", ShardGeneration: 1})
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
	if handle, ensureErr := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0), ShardID: "after-close", ShardGeneration: 1}); handle != nil || !errors.Is(ensureErr, ErrWorkerdLauncherClosed) {
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
	_, err = launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0), ShardID: "canceled-close", ShardGeneration: 1})
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
	if _, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0), ShardID: "retry-close", ShardGeneration: 1}); err != nil {
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
		if _, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0), ShardID: shardID, ShardGeneration: ShardGeneration(index + 1)}); err != nil {
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
		handle, ensureErr := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0), ShardID: "publication-race", ShardGeneration: 1})
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
		if info.ShardGeneration == 1 {
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
	oldHandle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0), ShardID: "close-replacement", ShardGeneration: 1})
	if err != nil {
		t.Fatal(err)
	}
	replacementResult := make(chan workerdEnsureResult, 1)
	go func() {
		handle, ensureErr := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0), ShardID: "close-replacement", ShardGeneration: 2})
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
	handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0),
		ShardID: "production-starter-shard", ShardGeneration: 1,
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

func newWorkerdLauncherConfigForTest(t *testing.T, probe WorkerdReadinessProbe) WorkerdLauncherConfig {
	t.Helper()
	executablePath := filepath.Join(t.TempDir(), "workerd")
	content := []byte("verified-workerd-inode")
	if err := os.WriteFile(executablePath, content, 0o500); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	return WorkerdLauncherConfig{
		ExecutablePath:   executablePath,
		ExecutableDigest: fmt.Sprintf("sha256:%x", digest),
		ReadinessTimeout: time.Second,
		StopGracePeriod:  20 * time.Millisecond,
		OutputLimitBytes: 1024,
		HistoryCapacity:  128,
		ReadinessProbe:   probe,
	}
}

func newWorkerdLauncherFixture(t *testing.T, starter workerdProcessStarter, probe WorkerdReadinessProbe) (WorkerdLauncherConfig, *WorkerdProcessLauncher) {
	t.Helper()
	config := newWorkerdLauncherConfigForTest(t, probe)
	launcher, err := newWorkerdProcessLauncherForTest(t, config, starter)
	if err != nil {
		t.Fatalf("newWorkerdProcessLauncher() error = %v", err)
	}
	return config, launcher
}

func newWorkerdProcessLauncherForTest(t *testing.T, config WorkerdLauncherConfig, starter workerdProcessStarter) (*WorkerdProcessLauncher, error) {
	t.Helper()
	launcher, _, err := newWorkerdProcessLauncherWithIdentityForTest(t, config, starter)
	return launcher, err
}

func newWorkerdProcessLauncherWithIdentityForTest(t *testing.T, config WorkerdLauncherConfig, starter workerdProcessStarter) (*WorkerdProcessLauncher, *fakeWorkerdIdentityCapture, error) {
	t.Helper()
	capture := newFakeWorkerdIdentityCapture()
	launcher, err := newWorkerdProcessLauncherWithResources(config, starter, unix.MemfdCreate, nil, capture.capture)
	if err == nil {
		closeWorkerdLauncherForTest(t, launcher)
	}
	return launcher, capture, err
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
	key := workerdLaunchKey{agentInstanceID: request.AgentInstanceID, shardID: request.ShardID, generation: request.ShardGeneration}
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
	key := workerdLaunchKey{agentInstanceID: request.AgentInstanceID, shardID: request.ShardID, generation: request.ShardGeneration}
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
	Executable        string
	Arguments         []string
	Environment       []string
	ExtraFiles        []*os.File
	CgroupFD          int
	AgentInstanceID   identity.ID
	ShardID           string
	ShardGeneration   ShardGeneration
	executableContent []byte
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
		CgroupFD:        command.CgroupFD,
		AgentInstanceID: command.AgentInstanceID, ShardID: command.ShardID, ShardGeneration: command.ShardGeneration,
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

func workerdTestAgentInstanceID(fill byte) identity.ID {
	random := bytes.NewReader(bytes.Repeat([]byte{fill}, 16))
	id, err := (identity.Generator{Random: random}).New(identity.Process)
	if err != nil {
		panic(err)
	}
	return id
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

const workerdFakeIdentityStatm = "8 2 1 1 0 1 0\n"

func workerdFakeIdentityStartTicks(pid int) uint64 {
	return uint64(pid)*3 + 11
}

type fakeWorkerdCapturedIdentity struct {
	pid     int
	ticks   uint64
	reader  *fakeWorkerdProcessReader
	backend *fakeWorkerdPIDFDBackend
	owner   *workerdProcessIdentity
}

// fakeWorkerdIdentityCapture builds one real workerdProcessIdentity owner per
// captured PID on top of injected proc/pidfd fakes, so launcher tests with
// fake PIDs never touch the live /proc boundary.
type fakeWorkerdIdentityCapture struct {
	mu          sync.Mutex
	nextFD      int
	captureErrs map[int]error
	closeErrs   map[int]error
	gatePID     int
	entered     chan int
	gate        <-chan struct{}
	captured    []*fakeWorkerdCapturedIdentity
}

func newFakeWorkerdIdentityCapture() *fakeWorkerdIdentityCapture {
	return &fakeWorkerdIdentityCapture{
		captureErrs: make(map[int]error),
		closeErrs:   make(map[int]error),
	}
}

func (capture *fakeWorkerdIdentityCapture) setCaptureErr(pid int, err error) {
	capture.mu.Lock()
	capture.captureErrs[pid] = err
	capture.mu.Unlock()
}

func (capture *fakeWorkerdIdentityCapture) setCloseErr(pid int, err error) {
	capture.mu.Lock()
	capture.closeErrs[pid] = err
	capture.mu.Unlock()
}

func (capture *fakeWorkerdIdentityCapture) gateCapture(pid int, entered chan int, gate <-chan struct{}) {
	capture.mu.Lock()
	capture.gatePID = pid
	capture.entered = entered
	capture.gate = gate
	capture.mu.Unlock()
}

func (capture *fakeWorkerdIdentityCapture) capture(pid int) (*workerdProcessIdentity, error) {
	capture.mu.Lock()
	entered := capture.entered
	gate := capture.gate
	gated := capture.gatePID == pid
	captureErr := capture.captureErrs[pid]
	closeErr := capture.closeErrs[pid]
	capture.nextFD++
	fd := 40_000 + capture.nextFD
	capture.mu.Unlock()
	if gated && entered != nil {
		entered <- pid
	}
	if gated && gate != nil {
		<-gate
	}
	if captureErr != nil {
		return nil, captureErr
	}
	ticks := workerdFakeIdentityStartTicks(pid)
	stat := validWorkerdProcStat(pid, "workerd", ticks)
	reader := &fakeWorkerdProcessReader{
		stat:     stat,
		snapshot: workerdProcessRawSnapshot{StatBefore: stat, Statm: workerdFakeIdentityStatm, StatAfter: stat},
	}
	backend := &fakeWorkerdPIDFDBackend{openFD: fd, closeErr: closeErr}
	owner, err := captureWorkerdProcessIdentity(reader, backend, pid)
	if err != nil {
		return nil, err
	}
	capture.mu.Lock()
	capture.captured = append(capture.captured, &fakeWorkerdCapturedIdentity{
		pid: pid, ticks: ticks, reader: reader, backend: backend, owner: owner,
	})
	capture.mu.Unlock()
	return owner, nil
}

func (capture *fakeWorkerdIdentityCapture) capturedSnapshot() []*fakeWorkerdCapturedIdentity {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return slices.Clone(capture.captured)
}

func (capture *fakeWorkerdIdentityCapture) capturedForPID(pid int) *fakeWorkerdCapturedIdentity {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	for index := len(capture.captured) - 1; index >= 0; index-- {
		if capture.captured[index].pid == pid {
			return capture.captured[index]
		}
	}
	return nil
}

type workerdStarterFunc func(workerdLaunchCommand) (workerdStartedProcess, error)

func (start workerdStarterFunc) Start(command workerdLaunchCommand) (workerdStartedProcess, error) {
	return start(command)
}

type waitEntryWorkerdProcess struct {
	*fakeWorkerdProcess
	waitEntered chan struct{}
	waitOnce    sync.Once
}

func (process *waitEntryWorkerdProcess) Wait() error {
	process.waitOnce.Do(func() { close(process.waitEntered) })
	return process.fakeWorkerdProcess.Wait()
}

func waitUntilWorkerdCondition(t *testing.T, timeout time.Duration, condition func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal(message)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestWorkerdLauncherProcessIdentityAttachmentContract(t *testing.T) {
	t.Parallel()
	instanceField, found := reflect.TypeOf(workerdInstance{}).FieldByName("processIdentity")
	if !found || instanceField.Type != reflect.TypeOf((*workerdProcessIdentity)(nil)) {
		t.Errorf("workerdInstance.processIdentity = %#v, want *workerdProcessIdentity", instanceField)
	}
	launcherField, found := reflect.TypeOf(WorkerdProcessLauncher{}).FieldByName("captureIdentity")
	if !found || launcherField.Type != reflect.TypeOf(workerdProcessIdentityCapturer(nil)) {
		t.Errorf("WorkerdProcessLauncher.captureIdentity = %#v, want workerdProcessIdentityCapturer", launcherField)
	}
}

func TestNewWorkerdProcessLauncherRejectsNilIdentityCapturer(t *testing.T) {
	t.Parallel()
	config := newWorkerdLauncherConfigForTest(t, WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }))
	launcher, err := newWorkerdProcessLauncherWithResources(config, &recordingWorkerdStarter{}, unix.MemfdCreate, nil, nil)
	if launcher != nil || !errors.Is(err, ErrInvalidWorkerdLauncherConfig) {
		t.Fatalf("newWorkerdProcessLauncherWithResources(nil capturer) = %#v, %v, want nil, invalid config", launcher, err)
	}
}

func TestWorkerdEnsureCapturesIdentityBeforeWaitReadinessAndPublication(t *testing.T) {
	t.Parallel()
	inner := newFakeWorkerdProcess(31_001, true)
	process := &waitEntryWorkerdProcess{fakeWorkerdProcess: inner, waitEntered: make(chan struct{})}
	starter := workerdStarterFunc(func(workerdLaunchCommand) (workerdStartedProcess, error) { return process, nil })
	probeCalls := make(chan WorkerdProcessInfo, 1)
	probe := WorkerdReadinessProbeFunc(func(_ context.Context, info WorkerdProcessInfo) error {
		probeCalls <- info
		return nil
	})
	config := newWorkerdLauncherConfigForTest(t, probe)
	launcher, capture, err := newWorkerdProcessLauncherWithIdentityForTest(t, config, starter)
	if err != nil {
		t.Fatalf("construct launcher: %v", err)
	}
	entered := make(chan int, 1)
	gate := make(chan struct{})
	capture.gateCapture(31_001, entered, gate)
	results := make(chan workerdEnsureResult, 1)
	go func() {
		handle, ensureErr := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
			AgentInstanceID: workerdTestAgentInstanceID(1), ShardID: "identity-order", ShardGeneration: 1,
		})
		results <- workerdEnsureResult{handle: handle, err: ensureErr}
	}()
	select {
	case pid := <-entered:
		if pid != 31_001 {
			t.Fatalf("captured pid = %d, want 31001", pid)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("identity capture was not entered after start")
	}
	select {
	case <-process.waitEntered:
		t.Fatal("Wait started before identity capture completed")
	case info := <-probeCalls:
		t.Fatalf("readiness probe ran before identity capture completed: %+v", info)
	case result := <-results:
		t.Fatalf("Ensure returned before identity capture completed: %#v, %v", result.handle, result.err)
	case <-time.After(50 * time.Millisecond):
	}
	close(gate)
	var result workerdEnsureResult
	select {
	case result = <-results:
	case <-time.After(2 * time.Second):
		t.Fatal("Ensure did not complete after capture gate release")
	}
	if result.err != nil || result.handle == nil {
		t.Fatalf("Ensure() = %#v, %v", result.handle, result.err)
	}
	select {
	case info := <-probeCalls:
		if info.PID != 31_001 {
			t.Fatalf("readiness PID = %d, want 31001", info.PID)
		}
	default:
		t.Fatal("readiness probe was not called for the published shard")
	}
	select {
	case <-process.waitEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("Wait was not started after identity capture")
	}
	captured := capture.capturedForPID(31_001)
	if captured == nil || len(capture.capturedSnapshot()) != 1 {
		t.Fatalf("captured identities = %#v, want exactly one for pid 31001", capture.capturedSnapshot())
	}
	if result.handle.instance.processIdentity != captured.owner {
		t.Fatal("published instance does not store the exact captured identity owner")
	}
	sample, sampleErr := captured.owner.sample(captured.reader, 4096)
	if sampleErr != nil || sample.PID != 31_001 || sample.StartTicks != captured.ticks {
		t.Fatalf("owner sample = %+v, %v, want capture-time identity", sample, sampleErr)
	}
	if stopErr := result.handle.Stop(context.Background()); stopErr != nil {
		t.Fatalf("Stop() error = %v", stopErr)
	}
	if _, closeFDs := captured.backend.calls(); len(closeFDs) != 1 {
		t.Fatalf("identity close calls = %d, want exactly one after stop", len(closeFDs))
	}
}

func TestWorkerdEnsureIdentityCaptureFailureFailsClosedWithOneCleanupOwner(t *testing.T) {
	t.Parallel()
	captureFailure := errors.New("test: identity capture failure")
	process := newFakeWorkerdProcess(31_002, true)
	starter := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{process}}
	probeCalls := make(chan WorkerdProcessInfo, 4)
	probe := WorkerdReadinessProbeFunc(func(_ context.Context, info WorkerdProcessInfo) error {
		probeCalls <- info
		return nil
	})
	config := newWorkerdLauncherConfigForTest(t, probe)
	launcher, capture, err := newWorkerdProcessLauncherWithIdentityForTest(t, config, starter)
	if err != nil {
		t.Fatalf("construct launcher: %v", err)
	}
	capture.setCaptureErr(31_002, captureFailure)
	handle, ensureErr := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
		AgentInstanceID: workerdTestAgentInstanceID(2), ShardID: "identity-capture-failure", ShardGeneration: 1,
	})
	if handle != nil || !errors.Is(ensureErr, ErrWorkerdIdentityCaptureFailed) || !errors.Is(ensureErr, captureFailure) {
		t.Fatalf("Ensure() = %#v, %v, want nil handle and wrapped identity capture failure", handle, ensureErr)
	}
	select {
	case info := <-probeCalls:
		t.Fatalf("readiness probe ran after identity capture failure: %+v", info)
	default:
	}
	if signals := process.signalSnapshot(); !reflect.DeepEqual(signals, []syscall.Signal{syscall.SIGTERM}) {
		t.Fatalf("capture-failure cleanup signals = %#v, want exactly one graceful stop owner", signals)
	}
	launcher.mu.Lock()
	tracked := len(launcher.instances)
	launcher.mu.Unlock()
	if tracked != 0 {
		t.Fatalf("tracked instances after capture failure = %d, want 0", tracked)
	}

	unsupported := errors.Join(errWorkerdPIDFDUnsupported, errors.New("open workerd pidfd: functionality not supported"))
	capture.setCaptureErr(10_001, unsupported)
	_, unsupportedErr := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
		AgentInstanceID: workerdTestAgentInstanceID(2), ShardID: "identity-capture-failure", ShardGeneration: 2,
	})
	if !errors.Is(unsupportedErr, ErrWorkerdIdentityCaptureFailed) || !errors.Is(unsupportedErr, errWorkerdPIDFDUnsupported) {
		t.Fatalf("Ensure(unsupported pidfd) error = %v, want preserved unsupported classification", unsupportedErr)
	}

	retryHandle, retryErr := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
		AgentInstanceID: workerdTestAgentInstanceID(2), ShardID: "identity-capture-failure", ShardGeneration: 3,
	})
	if retryErr != nil || retryHandle == nil {
		t.Fatalf("Ensure(fresh generation after capture failures) = %#v, %v", retryHandle, retryErr)
	}
	if stopErr := retryHandle.Stop(context.Background()); stopErr != nil {
		t.Fatalf("Stop(retry) error = %v", stopErr)
	}
}

func TestWorkerdInstanceIdentityRejectsPIDReuseWithoutReconstruction(t *testing.T) {
	t.Parallel()
	process := newFakeWorkerdProcess(31_003, true)
	starter := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{process}}
	config := newWorkerdLauncherConfigForTest(t, WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }))
	launcher, capture, err := newWorkerdProcessLauncherWithIdentityForTest(t, config, starter)
	if err != nil {
		t.Fatalf("construct launcher: %v", err)
	}
	handle, ensureErr := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
		AgentInstanceID: workerdTestAgentInstanceID(3), ShardID: "identity-pid-reuse", ShardGeneration: 1,
	})
	if ensureErr != nil {
		t.Fatalf("Ensure() error = %v", ensureErr)
	}
	captured := capture.capturedForPID(31_003)
	if captured == nil {
		t.Fatal("identity was not captured for pid 31003")
	}
	if token := captured.owner.token; token.PID != 31_003 || token.StartTicks != captured.ticks {
		t.Fatalf("owner token = %+v, want capture-time identity", token)
	}
	reusedStat := validWorkerdProcStat(31_003, "workerd", captured.ticks+9)
	captured.reader.mu.Lock()
	captured.reader.snapshot = workerdProcessRawSnapshot{StatBefore: reusedStat, Statm: workerdFakeIdentityStatm, StatAfter: reusedStat}
	captured.reader.mu.Unlock()
	if _, sampleErr := captured.owner.sample(captured.reader, 4096); !errors.Is(sampleErr, errStaleWorkerdProcessIdentity) {
		t.Fatalf("sample(reused pid) error = %v, want stale process identity", sampleErr)
	}
	if stopErr := handle.Stop(context.Background()); stopErr != nil {
		t.Fatalf("Stop() error = %v", stopErr)
	}
}

func TestWorkerdRetryableStopRetainsIdentityOwnerForNextCleanupEpoch(t *testing.T) {
	t.Parallel()
	process := newFakeWorkerdProcess(31_004, false)
	process.killClearsGroup = []bool{false}
	starter := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{process}}
	config := newWorkerdLauncherConfigForTest(t, WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }))
	launcher, capture, err := newWorkerdProcessLauncherWithIdentityForTest(t, config, starter)
	if err != nil {
		t.Fatalf("construct launcher: %v", err)
	}
	handle, ensureErr := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
		AgentInstanceID: workerdTestAgentInstanceID(4), ShardID: "identity-retryable-stop", ShardGeneration: 1,
	})
	if ensureErr != nil {
		t.Fatalf("Ensure() error = %v", ensureErr)
	}
	captured := capture.capturedForPID(31_004)
	if captured == nil {
		t.Fatal("identity was not captured for pid 31004")
	}
	stopErr := handle.Stop(context.Background())
	if !errors.Is(stopErr, ErrWorkerdStopTimeout) || errors.Is(stopErr, ErrTerminalShardCleanup) {
		t.Fatalf("Stop(timeout) error = %v, want retryable stop timeout", stopErr)
	}
	if _, closeFDs := captured.backend.calls(); len(closeFDs) != 0 {
		t.Fatalf("identity closes after retryable stop = %d, want retained open owner", len(closeFDs))
	}
	if _, sampleErr := captured.owner.sample(captured.reader, 4096); sampleErr != nil {
		t.Fatalf("sample(retained owner) error = %v, want owner usable for next epoch", sampleErr)
	}
	if retryErr := handle.Stop(context.Background()); retryErr != nil {
		t.Fatalf("Stop(retry epoch) error = %v", retryErr)
	}
	if _, closeFDs := captured.backend.calls(); len(closeFDs) != 1 {
		t.Fatalf("identity closes after successful epoch = %d, want exactly one", len(closeFDs))
	}
}

func TestWorkerdIdentityOwnerClosesExactlyOncePerLifecyclePath(t *testing.T) {
	t.Parallel()
	t.Run("natural exit", func(t *testing.T) {
		t.Parallel()
		process := newFakeWorkerdProcess(31_005, true)
		starter := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{process}}
		config := newWorkerdLauncherConfigForTest(t, WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }))
		launcher, capture, err := newWorkerdProcessLauncherWithIdentityForTest(t, config, starter)
		if err != nil {
			t.Fatalf("construct launcher: %v", err)
		}
		handle, ensureErr := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
			AgentInstanceID: workerdTestAgentInstanceID(5), ShardID: "identity-natural-exit", ShardGeneration: 1,
		})
		if ensureErr != nil {
			t.Fatalf("Ensure() error = %v", ensureErr)
		}
		captured := capture.capturedForPID(31_005)
		if captured == nil {
			t.Fatal("identity was not captured for pid 31005")
		}
		process.finishGroup(nil)
		waitUntilWorkerdCondition(t, 2*time.Second, func() bool {
			_, closeFDs := captured.backend.calls()
			return len(closeFDs) == 1
		}, "identity owner was not closed after natural exit")
		if stopErr := handle.Stop(context.Background()); stopErr != nil {
			t.Fatalf("Stop(after natural exit) error = %v", stopErr)
		}
		if _, closeFDs := captured.backend.calls(); len(closeFDs) != 1 {
			t.Fatalf("identity closes = %d, want exactly one", len(closeFDs))
		}
	})
	t.Run("readiness failure", func(t *testing.T) {
		t.Parallel()
		readinessFailure := errors.New("test: readiness failure")
		process := newFakeWorkerdProcess(31_015, true)
		starter := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{process}}
		config := newWorkerdLauncherConfigForTest(t, WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return readinessFailure }))
		launcher, capture, err := newWorkerdProcessLauncherWithIdentityForTest(t, config, starter)
		if err != nil {
			t.Fatalf("construct launcher: %v", err)
		}
		handle, ensureErr := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
			AgentInstanceID: workerdTestAgentInstanceID(5), ShardID: "identity-readiness-failure", ShardGeneration: 1,
		})
		if handle != nil || !errors.Is(ensureErr, ErrWorkerdNotReady) {
			t.Fatalf("Ensure() = %#v, %v, want readiness failure", handle, ensureErr)
		}
		captured := capture.capturedForPID(31_015)
		if captured == nil {
			t.Fatal("identity was not captured for pid 31015")
		}
		if _, closeFDs := captured.backend.calls(); len(closeFDs) != 1 {
			t.Fatalf("identity closes after readiness failure = %d, want exactly one", len(closeFDs))
		}
	})
	t.Run("launcher close", func(t *testing.T) {
		t.Parallel()
		processes := []*fakeWorkerdProcess{newFakeWorkerdProcess(31_016, true), newFakeWorkerdProcess(31_017, true)}
		starter := &recordingWorkerdStarter{processes: processes}
		config := newWorkerdLauncherConfigForTest(t, WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }))
		launcher, capture, err := newWorkerdProcessLauncherWithIdentityForTest(t, config, starter)
		if err != nil {
			t.Fatalf("construct launcher: %v", err)
		}
		for _, shard := range []string{"identity-close-a", "identity-close-b"} {
			if _, ensureErr := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
				AgentInstanceID: workerdTestAgentInstanceID(5), ShardID: shard, ShardGeneration: 1,
			}); ensureErr != nil {
				t.Fatalf("Ensure(%s) error = %v", shard, ensureErr)
			}
		}
		if closeErr := launcher.Close(context.Background()); closeErr != nil {
			t.Fatalf("Close() error = %v", closeErr)
		}
		for _, pid := range []int{31_016, 31_017} {
			captured := capture.capturedForPID(pid)
			if captured == nil {
				t.Fatalf("identity was not captured for pid %d", pid)
			}
			if _, closeFDs := captured.backend.calls(); len(closeFDs) != 1 {
				t.Fatalf("identity closes for pid %d = %d, want exactly one", pid, len(closeFDs))
			}
		}
	})
}

func TestWorkerdIdentityCloseFailureIsTerminalAndReplayedWithoutSecondSyscall(t *testing.T) {
	t.Parallel()
	process := newFakeWorkerdProcess(31_006, true)
	starter := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{process}}
	config := newWorkerdLauncherConfigForTest(t, WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }))
	capture := newFakeWorkerdIdentityCapture()
	launcher, err := newWorkerdProcessLauncherWithResources(config, starter, unix.MemfdCreate, nil, capture.capture)
	if err != nil {
		t.Fatalf("construct launcher: %v", err)
	}
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if closeErr := launcher.Close(closeCtx); !errors.Is(closeErr, ErrTerminalShardCleanup) {
			t.Errorf("Close() error = %v, want remembered terminal identity close failure", closeErr)
		}
	})
	capture.setCloseErr(31_006, unix.EIO)
	handle, ensureErr := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
		AgentInstanceID: workerdTestAgentInstanceID(6), ShardID: "identity-close-failure", ShardGeneration: 1,
	})
	if ensureErr != nil {
		t.Fatalf("Ensure() error = %v", ensureErr)
	}
	captured := capture.capturedForPID(31_006)
	if captured == nil {
		t.Fatal("identity was not captured for pid 31006")
	}
	stopErr := handle.Stop(context.Background())
	if !errors.Is(stopErr, ErrTerminalShardCleanup) || !errors.Is(stopErr, unix.EIO) {
		t.Fatalf("Stop(close failure) error = %v, want terminal identity close failure", stopErr)
	}
	if _, closeFDs := captured.backend.calls(); len(closeFDs) != 1 {
		t.Fatalf("identity closes = %d, want exactly one syscall", len(closeFDs))
	}
	replayErr := handle.Stop(context.Background())
	if !errors.Is(replayErr, ErrTerminalShardCleanup) || !errors.Is(replayErr, unix.EIO) {
		t.Fatalf("Stop(replay) error = %v, want replayed terminal close failure", replayErr)
	}
	if _, closeFDs := captured.backend.calls(); len(closeFDs) != 1 {
		t.Fatalf("replayed terminal close performed another close syscall: %d", len(closeFDs))
	}
}

func TestWorkerdOldGenerationIdentityCannotActOnReplacement(t *testing.T) {
	t.Parallel()
	oldProcess := newFakeWorkerdProcess(31_007, true)
	newProcess := newFakeWorkerdProcess(31_008, true)
	starter := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{oldProcess, newProcess}}
	config := newWorkerdLauncherConfigForTest(t, WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }))
	launcher, capture, err := newWorkerdProcessLauncherWithIdentityForTest(t, config, starter)
	if err != nil {
		t.Fatalf("construct launcher: %v", err)
	}
	agentID := workerdTestAgentInstanceID(7)
	oldHandle, ensureErr := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
		AgentInstanceID: agentID, ShardID: "identity-replacement", ShardGeneration: 1,
	})
	if ensureErr != nil {
		t.Fatalf("Ensure(generation 1) error = %v", ensureErr)
	}
	newHandle, ensureErr := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
		AgentInstanceID: agentID, ShardID: "identity-replacement", ShardGeneration: 2,
	})
	if ensureErr != nil {
		t.Fatalf("Ensure(generation 2) error = %v", ensureErr)
	}
	oldCaptured := capture.capturedForPID(31_007)
	newCaptured := capture.capturedForPID(31_008)
	if oldCaptured == nil || newCaptured == nil {
		t.Fatalf("captured identities = %#v, want both generations captured", capture.capturedSnapshot())
	}
	if _, closeFDs := oldCaptured.backend.calls(); len(closeFDs) != 1 {
		t.Fatalf("old generation identity closes = %d, want exactly one after replacement", len(closeFDs))
	}
	if _, sampleErr := oldCaptured.owner.sample(oldCaptured.reader, 4096); !errors.Is(sampleErr, errWorkerdProcessIdentityUnavailable) {
		t.Fatalf("sample(closed old owner) error = %v, want identity unavailable", sampleErr)
	}
	if replayErr := oldCaptured.owner.close(); replayErr != nil {
		t.Fatalf("close(old owner replay) error = %v", replayErr)
	}
	if _, closeFDs := oldCaptured.backend.calls(); len(closeFDs) != 1 {
		t.Fatalf("old owner replay performed another close syscall: %d", len(closeFDs))
	}
	if _, closeFDs := newCaptured.backend.calls(); len(closeFDs) != 0 {
		t.Fatalf("replacement owner was closed by old generation cleanup: %d", len(closeFDs))
	}
	sample, sampleErr := newCaptured.owner.sample(newCaptured.reader, 4096)
	if sampleErr != nil || sample.PID != 31_008 {
		t.Fatalf("sample(replacement owner) = %+v, %v, want live replacement identity", sample, sampleErr)
	}
	if stopErr := oldHandle.Stop(context.Background()); stopErr != nil {
		t.Fatalf("Stop(retired old handle) error = %v", stopErr)
	}
	if stopErr := newHandle.Stop(context.Background()); stopErr != nil {
		t.Fatalf("Stop(replacement) error = %v", stopErr)
	}
	if _, closeFDs := newCaptured.backend.calls(); len(closeFDs) != 1 {
		t.Fatalf("replacement identity closes = %d, want exactly one", len(closeFDs))
	}
}

func TestWorkerdLauncherHoldsNoLockAcrossIdentityCaptureAndClose(t *testing.T) {
	t.Parallel()
	processA := newFakeWorkerdProcess(31_009, true)
	processB := newFakeWorkerdProcess(31_010, true)
	processC := newFakeWorkerdProcess(31_011, true)
	starter := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{processA, processB, processC}}
	config := newWorkerdLauncherConfigForTest(t, WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }))
	launcher, capture, err := newWorkerdProcessLauncherWithIdentityForTest(t, config, starter)
	if err != nil {
		t.Fatalf("construct launcher: %v", err)
	}
	agentID := workerdTestAgentInstanceID(9)
	entered := make(chan int, 1)
	gate := make(chan struct{})
	capture.gateCapture(31_009, entered, gate)
	results := make(chan workerdEnsureResult, 1)
	go func() {
		handle, ensureErr := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
			AgentInstanceID: agentID, ShardID: "lock-a", ShardGeneration: 1,
		})
		results <- workerdEnsureResult{handle: handle, err: ensureErr}
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("identity capture was not entered")
	}
	ensureCtx, cancelEnsure := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelEnsure()
	handleB, ensureBErr := launcher.Ensure(ensureCtx, WorkerdEnsureRequest{
		AgentInstanceID: agentID, ShardID: "lock-b", ShardGeneration: 1,
	})
	if ensureBErr != nil {
		t.Fatalf("Ensure(lock-b) during gated capture error = %v, want independent progress", ensureBErr)
	}
	close(gate)
	var resultA workerdEnsureResult
	select {
	case resultA = <-results:
	case <-time.After(2 * time.Second):
		t.Fatal("Ensure(lock-a) did not complete")
	}
	if resultA.err != nil || resultA.handle == nil {
		t.Fatalf("Ensure(lock-a) = %#v, %v", resultA.handle, resultA.err)
	}

	capturedA := capture.capturedForPID(31_009)
	if capturedA == nil {
		t.Fatal("identity was not captured for pid 31009")
	}
	closeEntered := make(chan struct{})
	closeGate := make(chan struct{})
	capturedA.backend.mu.Lock()
	capturedA.backend.closeEntered = closeEntered
	capturedA.backend.closeGate = closeGate
	capturedA.backend.mu.Unlock()
	stopResults := make(chan error, 1)
	go func() { stopResults <- resultA.handle.Stop(context.Background()) }()
	select {
	case <-closeEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("identity close was not entered")
	}
	handleC, ensureCErr := launcher.Ensure(ensureCtx, WorkerdEnsureRequest{
		AgentInstanceID: agentID, ShardID: "lock-c", ShardGeneration: 1,
	})
	if ensureCErr != nil {
		t.Fatalf("Ensure(lock-c) during gated close error = %v, want independent progress", ensureCErr)
	}
	waitCtx, cancelWait := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelWait()
	if waitErr := resultA.handle.Stop(waitCtx); !errors.Is(waitErr, context.DeadlineExceeded) {
		t.Fatalf("Stop(waiter during gated close) error = %v, want caller-local deadline", waitErr)
	}
	close(closeGate)
	if stopErr := <-stopResults; stopErr != nil {
		t.Fatalf("Stop(lock-a) error = %v", stopErr)
	}
	for _, handle := range []*WorkerdShardHandle{handleB, handleC} {
		if stopErr := handle.Stop(context.Background()); stopErr != nil {
			t.Fatalf("cleanup Stop() error = %v", stopErr)
		}
	}
}
