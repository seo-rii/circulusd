//go:build linux

package agent

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/identity"
	"golang.org/x/sys/unix"
)

var errWorkerdCgroupIntegrationStart = errors.New("test: workerd cgroup start failure")

type firstWorkerdContextErrObserver struct {
	context.Context
	once     sync.Once
	checked  chan struct{}
	release  chan struct{}
	returned chan struct{}
}

func (observed *firstWorkerdContextErrObserver) Err() error {
	err := observed.Context.Err()
	observed.once.Do(func() {
		close(observed.checked)
		<-observed.release
		close(observed.returned)
	})
	return err
}

func TestWorkerdCgroupLauncherConstructorFailureClosesController(t *testing.T) {
	_, backend, cgroups := newWorkerdCgroupLauncherController(t)
	launcher, err := newWorkerdProcessLauncherWithCgroup(
		WorkerdLauncherConfig{}, &recordingWorkerdStarter{}, unix.MemfdCreate, cgroups,
	)
	if launcher != nil || !errors.Is(err, ErrInvalidWorkerdLauncherConfig) {
		t.Fatalf("newWorkerdProcessLauncherWithCgroup(invalid) = %#v, %v, want nil, invalid config", launcher, err)
	}
	if descriptors := backend.openFileDescriptors(); descriptors != 0 {
		t.Fatalf("open descriptors after constructor failure = %d, want controller closed", descriptors)
	}
}

func TestWorkerdCgroupLauncherEvidenceReportsMechanicalBoundaryOnly(t *testing.T) {
	_, _, cgroups := newWorkerdCgroupLauncherController(t)
	launcher := newWorkerdCgroupLauncherForTest(t, &recordingWorkerdStarter{}, cgroups)
	evidence := launcher.Evidence()
	if !evidence.AtomicCgroupPlacement || !evidence.CgroupLimits || !evidence.CgroupTermination {
		t.Fatalf("integrated cgroup evidence = %#v, want placement, limits, and termination", evidence)
	}
	if evidence.CPUAccounting || evidence.RSSAccounting || evidence.KillReconstruction || evidence.AdmissionReady {
		t.Fatalf("production evidence must remain fail closed: %#v", evidence)
	}
	wantMissing := []string{
		"workerd-cgroup-authority-isolation",
		"agentd-cpu-accounting",
		"agentd-rss-accounting",
		"workerd-child-fd-allowlist",
		"workerd-kill-reconstruction",
	}
	if !reflect.DeepEqual(evidence.MissingCapabilities, wantMissing) {
		t.Fatalf("missing capabilities = %#v, want %#v", evidence.MissingCapabilities, wantMissing)
	}
	closeWorkerdCgroupIntegratedLauncher(t, launcher, nil)
}

func TestWorkerdCgroupLauncherPreparesExactControlsBeforeStart(t *testing.T) {
	cgroupConfig, backend, cgroups := newWorkerdCgroupLauncherController(t)
	inner := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{newFakeWorkerdProcess(20_001, true)}}
	backend.killHook = func() { inner.processes[0].finishGroup(nil) }
	starter := &cgroupObservingWorkerdStarter{backend: backend, inner: inner}
	launcher := newWorkerdCgroupLauncherForTest(t, starter, cgroups)

	handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0),
		ShardID: "cgroup-before-start", ShardGeneration: 1,
	})
	if err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	observation := starter.snapshot()
	wantControls := []fakeWorkerdCgroupWrite{
		{Name: "cgroup.max.depth", Value: "0"},
		{Name: "cgroup.max.descendants", Value: "0"},
		{Name: "memory.max", Value: fmt.Sprint(cgroupConfig.MemoryMaxBytes)},
		{Name: "memory.swap.max", Value: "0"},
		{Name: "cpu.max", Value: "50000 100000"},
		{Name: "pids.max", Value: fmt.Sprint(cgroupConfig.PIDsMax)},
	}
	if observation.calls != 1 || observation.cgroupFD < 0 || !observation.cgroupFDOpen || !observation.cgroupFDNamesChild {
		t.Fatalf("start observation = %+v, want one call with held child cgroup fd", observation)
	}
	if observation.extraFiles != 0 {
		t.Fatalf("Start ExtraFiles = %d, want none", observation.extraFiles)
	}
	if !reflect.DeepEqual(observation.controlsBeforeStart, wantControls) {
		t.Fatalf("controls before Start = %#v, want %#v", observation.controlsBeforeStart, wantControls)
	}
	if err := handle.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	closeWorkerdCgroupIntegratedLauncher(t, launcher, nil)
}

func TestWorkerdCgroupLauncherRejectsDifferentAgentBeforeCgroupAndStartCallbacks(t *testing.T) {
	_, backend, cgroups := newWorkerdCgroupLauncherController(t)
	process := newFakeWorkerdProcess(20_002, true)
	inner := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{process}}
	backend.killHook = func() { process.finishGroup(nil) }
	starter := &cgroupObservingWorkerdStarter{backend: backend, inner: inner}
	launcher := newWorkerdCgroupLauncherForTest(t, starter, cgroups)

	oldAgentInstanceID := workerdTestAgentInstanceID(4)
	handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
		AgentInstanceID: oldAgentInstanceID,
		ShardID:         "cgroup-lifetime-bind",
		ShardGeneration: 1,
	})
	if err != nil {
		t.Fatalf("Ensure(old boot) error = %v", err)
	}
	if err := handle.Stop(context.Background()); err != nil {
		t.Fatalf("Stop(old boot) error = %v", err)
	}
	beforeMkdir := len(backend.mkdirModesSeen())
	beforeStarts := starter.snapshot().calls

	newHandle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
		AgentInstanceID: workerdTestAgentInstanceID(5),
		ShardID:         "cgroup-lifetime-bind",
		ShardGeneration: 1,
	})
	if newHandle != nil || !errors.Is(err, ErrWorkerdAgentInstanceMismatch) {
		t.Fatalf("Ensure(new boot) = %#v, %v, want nil/ErrWorkerdAgentInstanceMismatch", newHandle, err)
	}
	if afterMkdir := len(backend.mkdirModesSeen()); afterMkdir != beforeMkdir {
		t.Fatalf("mismatched boot cgroup mkdir calls = %d -> %d", beforeMkdir, afterMkdir)
	}
	if afterStarts := starter.snapshot().calls; afterStarts != beforeStarts {
		t.Fatalf("mismatched boot process Start calls = %d -> %d", beforeStarts, afterStarts)
	}
	closeWorkerdCgroupIntegratedLauncher(t, launcher, nil)
}

func TestWorkerdCgroupLauncherCanceledFirstRequestDoesNotBindLifetime(t *testing.T) {
	_, backend, cgroups := newWorkerdCgroupLauncherController(t)
	process := newFakeWorkerdProcess(20_003, true)
	inner := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{process}}
	backend.killHook = func() { process.finishGroup(nil) }
	starter := &cgroupObservingWorkerdStarter{backend: backend, inner: inner}
	var readinessMu sync.Mutex
	readinessCalls := 0
	probe := WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error {
		readinessMu.Lock()
		readinessCalls++
		readinessMu.Unlock()
		return nil
	})
	launcher := newWorkerdCgroupLauncherWithProbeForTest(t, starter, cgroups, probe)
	t.Cleanup(func() { closeWorkerdCgroupIntegratedLauncher(t, launcher, nil) })

	baseContext, cancelFirst := context.WithCancel(context.Background())
	defer cancelFirst()
	observedContext := &firstWorkerdContextErrObserver{
		Context: baseContext, checked: make(chan struct{}), release: make(chan struct{}), returned: make(chan struct{}),
	}
	releasedContextCheck := false
	defer func() {
		if !releasedContextCheck {
			close(observedContext.release)
		}
	}()
	firstAgentInstanceID := workerdTestAgentInstanceID(6)
	request := WorkerdEnsureRequest{
		AgentInstanceID: firstAgentInstanceID,
		ShardID:         "cgroup-canceled-first-bind",
		ShardGeneration: 1,
	}
	launcher.mu.Lock()
	mutexHeld := true
	defer func() {
		if mutexHeld {
			launcher.mu.Unlock()
		}
	}()
	firstResult := make(chan workerdEnsureResult, 1)
	go func() {
		handle, err := launcher.Ensure(observedContext, request)
		firstResult <- workerdEnsureResult{handle: handle, err: err}
	}()
	select {
	case <-observedContext.checked:
	case <-time.After(3 * time.Second):
		t.Fatal("Ensure did not complete its first context check")
	}
	close(observedContext.release)
	releasedContextCheck = true
	select {
	case <-observedContext.returned:
	case <-time.After(3 * time.Second):
		t.Fatal("Ensure did not return from its first context check")
	}
	cancelFirst()
	launcher.mu.Unlock()
	mutexHeld = false

	var canceledResult workerdEnsureResult
	select {
	case canceledResult = <-firstResult:
	case <-time.After(3 * time.Second):
		t.Fatal("canceled Ensure did not return")
	}
	if canceledResult.handle != nil || !errors.Is(canceledResult.err, context.Canceled) {
		t.Fatalf("canceled first Ensure = %#v, %v, want nil/context.Canceled", canceledResult.handle, canceledResult.err)
	}
	launcher.mu.Lock()
	boundAgentInstanceID := launcher.boundAgentInstanceID
	pendingLaunches := len(launcher.pending)
	launcher.mu.Unlock()
	readinessMu.Lock()
	observedReadinessCalls := readinessCalls
	readinessMu.Unlock()
	if boundAgentInstanceID != (identity.ID{}) || pendingLaunches != 0 || backend.mkdirCallCount() != 0 || starter.snapshot().calls != 0 || observedReadinessCalls != 0 {
		t.Fatalf("canceled first request effects = bound:%q pending:%d mkdir:%d starts:%d readiness:%d, want none",
			boundAgentInstanceID, pendingLaunches, backend.mkdirCallCount(), starter.snapshot().calls, observedReadinessCalls)
	}

	secondAgentInstanceID := workerdTestAgentInstanceID(7)
	request.AgentInstanceID = secondAgentInstanceID
	handle, err := launcher.Ensure(context.Background(), request)
	if err != nil {
		t.Fatalf("Ensure(second boot) error = %v", err)
	}
	launcher.mu.Lock()
	boundAgentInstanceID = launcher.boundAgentInstanceID
	launcher.mu.Unlock()
	readinessMu.Lock()
	observedReadinessCalls = readinessCalls
	readinessMu.Unlock()
	commands := inner.commandSnapshot()
	if boundAgentInstanceID != secondAgentInstanceID || backend.mkdirCallCount() != 1 || starter.snapshot().calls != 1 || observedReadinessCalls != 1 || len(commands) != 1 || commands[0].AgentInstanceID != secondAgentInstanceID {
		t.Fatalf("second request effects = bound:%q mkdir:%d starts:%d readiness:%d commands:%#v",
			boundAgentInstanceID, backend.mkdirCallCount(), starter.snapshot().calls, observedReadinessCalls, commands)
	}
	if err := handle.Stop(context.Background()); err != nil {
		t.Fatalf("Stop(second boot) error = %v", err)
	}
}

func TestWorkerdCgroupLauncherStartFailureCleansLeaseBeforeReturning(t *testing.T) {
	_, backend, cgroups := newWorkerdCgroupLauncherController(t)
	inner := &recordingWorkerdStarter{startErr: errWorkerdCgroupIntegrationStart}
	starter := &cgroupObservingWorkerdStarter{backend: backend, inner: inner}
	launcher := newWorkerdCgroupLauncherForTest(t, starter, cgroups)

	handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0),
		ShardID: "cgroup-start-failure", ShardGeneration: 1,
	})
	if handle != nil || !errors.Is(err, ErrWorkerdLaunchFailed) {
		t.Fatalf("Ensure(start failure) = %#v, %v, want nil, launch failed", handle, err)
	}
	if calls := len(inner.commandSnapshot()); calls != 1 {
		t.Fatalf("Start calls = %d, want 1", calls)
	}
	if children := backend.childCount(); children != 0 {
		t.Fatalf("children when Ensure returned = %d, want 0", children)
	}
	if descriptors := backend.openFileDescriptors(); descriptors != 1 {
		t.Fatalf("open descriptors when Ensure returned = %d, want delegated root only", descriptors)
	}
	if backend.killCallCount() != 1 || backend.removeCallCount() != 1 {
		t.Fatalf("cleanup kill/remove calls = %d/%d, want 1/1", backend.killCallCount(), backend.removeCallCount())
	}
	closeWorkerdCgroupIntegratedLauncher(t, launcher, nil)
}

func TestWorkerdCgroupLauncherCleansPartialPrepareAuthorityWithoutStarting(t *testing.T) {
	_, backend, cgroups := newWorkerdCgroupLauncherController(t)
	backend.corruptReadback["cpu.max"] = "99999 100000\n"
	backend.removeFailures = 1
	inner := &recordingWorkerdStarter{}
	starter := &cgroupObservingWorkerdStarter{backend: backend, inner: inner}
	launcher := newWorkerdCgroupLauncherForTest(t, starter, cgroups)

	handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0),
		ShardID: "cgroup-partial-prepare", ShardGeneration: 1,
	})
	if handle != nil || !errors.Is(err, errWorkerdCgroupContract) {
		t.Fatalf("Ensure(partial prepare) = %#v, %v, want nil, cgroup contract error", handle, err)
	}
	if calls := len(inner.commandSnapshot()); calls != 0 {
		t.Fatalf("Start calls after partial prepare = %d, want 0", calls)
	}
	if children := backend.childCount(); children != 0 {
		t.Fatalf("children when Ensure returned = %d, want 0", children)
	}
	if descriptors := backend.openFileDescriptors(); descriptors != 1 {
		t.Fatalf("open descriptors when Ensure returned = %d, want delegated root only", descriptors)
	}
	if backend.killCallCount() != 0 || backend.removeCallCount() != 2 {
		t.Fatalf("cleanup kill/remove calls = %d/%d, want 0/2", backend.killCallCount(), backend.removeCallCount())
	}
	closeWorkerdCgroupIntegratedLauncher(t, launcher, nil)
}

func TestWorkerdCgroupLauncherConcurrentStopCoalescesCgroupDestroy(t *testing.T) {
	_, backend, cgroups := newWorkerdCgroupLauncherController(t)
	process := newFakeWorkerdProcess(20_002, true)
	backend.killHook = func() { process.finishGroup(nil) }
	inner := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{process}}
	starter := &cgroupObservingWorkerdStarter{backend: backend, inner: inner}
	launcher := newWorkerdCgroupLauncherForTest(t, starter, cgroups)
	handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0),
		ShardID: "cgroup-concurrent-stop", ShardGeneration: 1,
	})
	if err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}

	const callers = 32
	errorsSeen := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errorsSeen <- handle.Stop(context.Background())
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for stopErr := range errorsSeen {
		if stopErr != nil {
			t.Fatalf("Stop() error = %v", stopErr)
		}
	}
	if backend.killCallCount() != 1 || backend.removeCallCount() != 1 {
		t.Fatalf("coalesced kill/remove calls = %d/%d, want 1/1", backend.killCallCount(), backend.removeCallCount())
	}
	if signals := process.signalSnapshot(); len(signals) != 0 {
		t.Fatalf("numeric process-group signals = %v, want none for integrated cgroup termination", signals)
	}
	if backend.childCount() != 0 || backend.openFileDescriptors() != 1 {
		t.Fatalf("post-Stop children/descriptors = %d/%d, want 0/root-only", backend.childCount(), backend.openFileDescriptors())
	}
	closeWorkerdCgroupIntegratedLauncher(t, launcher, nil)
}

func TestWorkerdCgroupLauncherPoisonedControllerNeverStarts(t *testing.T) {
	_, backend, cgroups := newWorkerdCgroupLauncherController(t)
	backend.openFailures = 1
	inner := &recordingWorkerdStarter{}
	starter := &cgroupObservingWorkerdStarter{backend: backend, inner: inner}
	launcher := newWorkerdCgroupLauncherForTest(t, starter, cgroups)

	for index, shardID := range []string{"poison-trigger", "poison-must-fence"} {
		handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0),
			ShardID: shardID, ShardGeneration: 1,
		})
		if handle != nil || !errors.Is(err, errWorkerdCgroupPoisoned) {
			t.Fatalf("Ensure(poison call %d) = %#v, %v, want nil, poisoned", index+1, handle, err)
		}
	}
	if calls := len(inner.commandSnapshot()); calls != 0 {
		t.Fatalf("Start calls after poison = %d, want 0", calls)
	}
	if calls := backend.mkdirCallCount(); calls != 1 {
		t.Fatalf("mkdir calls after poison = %d, want only triggering call", calls)
	}
	closeWorkerdCgroupIntegratedLauncher(t, launcher, errWorkerdCgroupPoisoned)
	if descriptors := backend.openFileDescriptors(); descriptors != 0 {
		t.Fatalf("open descriptors after poisoned Close = %d, want 0", descriptors)
	}
}

func TestWorkerdCgroupLauncherReplaysTerminalPoisonWithoutRetryingKill(t *testing.T) {
	_, backend, cgroups := newWorkerdCgroupLauncherController(t)
	process := newFakeWorkerdProcess(20_011, true)
	inner := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{process}}
	launcher := newWorkerdCgroupLauncherForTest(t, &cgroupObservingWorkerdStarter{backend: backend, inner: inner}, cgroups)
	handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0),
		ShardID: "terminal-poison-replay", ShardGeneration: 1,
	})
	if err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	childName := backend.onlyChildName(t)
	backend.killHook = func() {
		process.finishGroup(nil)
		backend.replaceChild(childName)
	}

	if err := handle.Stop(context.Background()); !errors.Is(err, errWorkerdCgroupPoisoned) || !errors.Is(err, ErrTerminalShardCleanup) {
		t.Fatalf("first Stop() error = %v, want poisoned terminal cleanup", err)
	}
	if err := handle.Stop(context.Background()); !errors.Is(err, errWorkerdCgroupPoisoned) || !errors.Is(err, ErrTerminalShardCleanup) {
		t.Fatalf("replayed Stop() error = %v, want cached terminal poison", err)
	}
	if calls := backend.killCallCount(); calls != 1 {
		t.Fatalf("cgroup.kill calls after poison replay = %d, want 1", calls)
	}
	launcher.mu.Lock()
	instances := len(launcher.instances)
	allocations := len(launcher.allocations)
	launcher.mu.Unlock()
	if instances != 0 || allocations != 0 {
		t.Fatalf("terminal poison ownership = instances %d, allocations %d, want none", instances, allocations)
	}
	closeWorkerdCgroupIntegratedLauncher(t, launcher, errWorkerdCgroupPoisoned)
}

func TestWorkerdCgroupLauncherReplaysTerminalLeafCloseFailure(t *testing.T) {
	_, backend, cgroups := newWorkerdCgroupLauncherController(t)
	process := newFakeWorkerdProcess(20_017, true)
	inner := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{process}}
	launcher := newWorkerdCgroupLauncherForTest(t, &cgroupObservingWorkerdStarter{backend: backend, inner: inner}, cgroups)
	handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0),
		ShardID: "terminal-leaf-close-replay", ShardGeneration: 1,
	})
	if err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	leaseFD := inner.commandSnapshot()[0].CgroupFD
	backend.closeFailures[leaseFD] = 1
	backend.killHook = func() { process.finishGroup(nil) }

	if err := handle.Stop(context.Background()); !errors.Is(err, errWorkerdCgroupContract) || !errors.Is(err, ErrTerminalShardCleanup) {
		t.Fatalf("first Stop() error = %v, want terminal close contract error and marker", err)
	}
	if err := handle.Stop(context.Background()); !errors.Is(err, errWorkerdCgroupContract) || !errors.Is(err, ErrTerminalShardCleanup) {
		t.Fatalf("replayed Stop() error = %v, want cached terminal close error and marker", err)
	}
	if backend.killCallCount() != 1 || backend.closeCalls[leaseFD] != 1 {
		t.Fatalf("terminal replay kill/leaf-close calls = %d/%d, want 1/1", backend.killCallCount(), backend.closeCalls[leaseFD])
	}
	launcher.mu.Lock()
	instances := len(launcher.instances)
	allocations := len(launcher.allocations)
	launcher.mu.Unlock()
	if instances != 0 || allocations != 0 {
		t.Fatalf("terminal close ownership = instances %d, allocations %d, want none", instances, allocations)
	}
	closeWorkerdCgroupIntegratedLauncher(t, launcher, errWorkerdCgroupContract)
	if err := launcher.Close(context.Background()); !errors.Is(err, errWorkerdCgroupContract) {
		t.Fatalf("replayed Close() error = %v, want terminal close contract error", err)
	}
	if descriptors := backend.openFileDescriptors(); descriptors != 0 {
		t.Fatalf("descriptors after terminal close replay = %d, want none", descriptors)
	}
}

func TestWorkerdCgroupLauncherRetriesRemovalWithoutTerminalMarker(t *testing.T) {
	_, backend, cgroups := newWorkerdCgroupLauncherController(t)
	process := newFakeWorkerdProcess(20_018, true)
	backend.killHook = func() { process.finishGroup(nil) }
	backend.removeFailures = 1
	inner := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{process}}
	launcher := newWorkerdCgroupLauncherForTest(t, &cgroupObservingWorkerdStarter{backend: backend, inner: inner}, cgroups)
	handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0),
		ShardID: "retryable-removal", ShardGeneration: 1,
	})
	if err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}

	firstErr := handle.Stop(context.Background())
	if !errors.Is(firstErr, errWorkerdCgroupContract) || errors.Is(firstErr, ErrTerminalShardCleanup) {
		t.Fatalf("Stop(retryable removal) error = %v, want unmarked cgroup contract error", firstErr)
	}
	if err := handle.Stop(context.Background()); err != nil {
		t.Fatalf("Stop(removal retry) error = %v", err)
	}
	if err := handle.Stop(context.Background()); err != nil {
		t.Fatalf("Stop(after successful removal) error = %v", err)
	}
	if kills, removes := backend.killCallCount(), backend.removeCallCount(); kills != 2 || removes != 2 {
		t.Fatalf("retry kill/remove calls = %d/%d, want 2/2", kills, removes)
	}
	closeWorkerdCgroupIntegratedLauncher(t, launcher, nil)
}

func TestWorkerdCgroupLauncherDrainsResidualBeforeStartingNewGeneration(t *testing.T) {
	_, backend, cgroups := newWorkerdCgroupLauncherController(t)
	backend.removeFailures = 1
	process := newFakeWorkerdProcess(20_003, true)
	inner := &recordingWorkerdStarter{
		processes:   []*fakeWorkerdProcess{nil, process},
		startErrors: []error{errWorkerdCgroupIntegrationStart, nil},
	}
	starter := &cgroupObservingWorkerdStarter{backend: backend, inner: inner}
	launcher := newWorkerdCgroupLauncherForTest(t, starter, cgroups)
	firstRequest := WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0), ShardID: "cgroup-residual-retry", ShardGeneration: 1}

	firstHandle, firstErr := launcher.Ensure(context.Background(), firstRequest)
	if firstHandle != nil || !errors.Is(firstErr, ErrWorkerdLaunchFailed) {
		t.Fatalf("first Ensure() = %#v, %v, want nil, launch failed", firstHandle, firstErr)
	}
	if backend.childCount() != 1 || backend.openFileDescriptors() != 2 {
		t.Fatalf("residual children/descriptors = %d/%d, want 1/root+lease", backend.childCount(), backend.openFileDescriptors())
	}

	handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0),
		ShardID: firstRequest.ShardID, ShardGeneration: 2,
	})
	if err != nil {
		t.Fatalf("second Ensure() error = %v", err)
	}
	if backend.childCount() != 1 || backend.openFileDescriptors() != 2 {
		t.Fatalf("children/descriptors before second Start returned = %d/%d, want one active lease", backend.childCount(), backend.openFileDescriptors())
	}
	if calls := len(inner.commandSnapshot()); calls != 2 {
		t.Fatalf("Start calls after residual retry = %d, want 2", calls)
	}
	backend.killHook = func() { process.finishGroup(nil) }
	if err := handle.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	closeWorkerdCgroupIntegratedLauncher(t, launcher, nil)
}

func TestWorkerdCgroupLauncherStartsIndependentShardsInParallel(t *testing.T) {
	_, backend, cgroups := newWorkerdCgroupLauncherController(t)
	firstProcess := newFakeWorkerdProcess(20_005, true)
	secondProcess := newFakeWorkerdProcess(20_006, true)
	firstRelease := make(chan struct{})
	secondRelease := make(chan struct{})
	starter := &parallelCgroupWorkerdStarter{
		entered: make(chan string, 2),
		releases: map[string]<-chan struct{}{
			"parallel-a": firstRelease,
			"parallel-b": secondRelease,
		},
		processes: map[string]*fakeWorkerdProcess{
			"parallel-a": firstProcess,
			"parallel-b": secondProcess,
		},
	}
	launcher := newWorkerdCgroupLauncherForTest(t, starter, cgroups)
	type ensureResult struct {
		handle *WorkerdShardHandle
		err    error
	}
	firstResult := make(chan ensureResult, 1)
	secondResult := make(chan ensureResult, 1)
	go func() {
		handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0), ShardID: "parallel-a", ShardGeneration: 1})
		firstResult <- ensureResult{handle: handle, err: err}
	}()
	if entered := <-starter.entered; entered != "parallel-a" {
		t.Fatalf("first Start shard = %q, want parallel-a", entered)
	}
	go func() {
		handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0), ShardID: "parallel-b", ShardGeneration: 1})
		secondResult <- ensureResult{handle: handle, err: err}
	}()
	parallel := false
	select {
	case entered := <-starter.entered:
		parallel = entered == "parallel-b"
	case <-time.After(250 * time.Millisecond):
	}
	close(firstRelease)
	if !parallel {
		if entered := <-starter.entered; entered != "parallel-b" {
			t.Fatalf("second Start shard = %q, want parallel-b", entered)
		}
	}
	close(secondRelease)
	first := <-firstResult
	second := <-secondResult
	backend.killHook = func() {
		firstProcess.finishGroup(nil)
		secondProcess.finishGroup(nil)
	}
	if first.err != nil || second.err != nil {
		t.Fatalf("parallel Ensure errors = %v, %v", first.err, second.err)
	}
	if err := first.handle.Stop(context.Background()); err != nil {
		t.Fatalf("first Stop() error = %v", err)
	}
	if err := second.handle.Stop(context.Background()); err != nil {
		t.Fatalf("second Stop() error = %v", err)
	}
	closeWorkerdCgroupIntegratedLauncher(t, launcher, nil)
	if !parallel {
		t.Fatal("second shard Start did not enter while first shard Start was blocked")
	}
}

func TestWorkerdCgroupLauncherCloseCancellationDoesNotCancelGatedStartCleanup(t *testing.T) {
	_, backend, cgroups := newWorkerdCgroupLauncherController(t)
	process := newFakeWorkerdProcess(20_007, true)
	startRelease := make(chan struct{})
	starter := &parallelCgroupWorkerdStarter{
		entered:   make(chan string, 1),
		releases:  map[string]<-chan struct{}{"close-gated-start": startRelease},
		processes: map[string]*fakeWorkerdProcess{"close-gated-start": process},
	}
	launcher := newWorkerdCgroupLauncherForTest(t, starter, cgroups)
	ensureResult := make(chan error, 1)
	go func() {
		_, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0),
			ShardID: "close-gated-start", ShardGeneration: 1,
		})
		ensureResult <- err
	}()
	if entered := <-starter.entered; entered != "close-gated-start" {
		t.Fatalf("Start shard = %q, want close-gated-start", entered)
	}

	closeContext, cancelClose := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelClose()
	if err := launcher.Close(closeContext); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close(gated Start) error = %v, want caller deadline", err)
	}
	if handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0),
		ShardID: "must-remain-closed", ShardGeneration: 1,
	}); handle != nil || !errors.Is(err, ErrWorkerdLauncherClosed) {
		t.Fatalf("Ensure(after Close began) = %#v, %v, want permanently closed", handle, err)
	}
	backend.killHook = func() { process.finishGroup(nil) }
	close(startRelease)
	if err := <-ensureResult; !errors.Is(err, ErrWorkerdLauncherClosed) {
		t.Fatalf("gated Ensure() error = %v, want launcher closed", err)
	}
	closeWorkerdCgroupIntegratedLauncher(t, launcher, nil)
	if backend.childCount() != 0 || backend.openFileDescriptors() != 0 {
		t.Fatalf("post-Close children/descriptors = %d/%d, want none", backend.childCount(), backend.openFileDescriptors())
	}
}

func TestWorkerdCgroupLauncherCloseCanFenceWhilePrepareIsGated(t *testing.T) {
	_, backend, cgroups := newWorkerdCgroupLauncherController(t)
	mkdirRelease := make(chan struct{})
	backend.mkdirEntered = make(chan struct{}, 1)
	backend.mkdirGate = mkdirRelease
	inner := &recordingWorkerdStarter{}
	launcher := newWorkerdCgroupLauncherForTest(t, &cgroupObservingWorkerdStarter{backend: backend, inner: inner}, cgroups)
	ensureResult := make(chan error, 1)
	go func() {
		_, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0),
			ShardID: "close-gated-prepare", ShardGeneration: 1,
		})
		ensureResult <- err
	}()
	<-backend.mkdirEntered

	closeContext, cancelClose := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelClose()
	if err := launcher.Close(closeContext); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close(gated prepare) error = %v, want caller deadline", err)
	}
	if handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0),
		ShardID: "closed-during-prepare", ShardGeneration: 1,
	}); handle != nil || !errors.Is(err, ErrWorkerdLauncherClosed) {
		t.Fatalf("Ensure(after gated prepare Close) = %#v, %v, want closed", handle, err)
	}
	close(mkdirRelease)
	if err := <-ensureResult; !errors.Is(err, ErrWorkerdLauncherClosed) {
		t.Fatalf("gated prepare Ensure() error = %v, want launcher closed", err)
	}
	if calls := len(inner.commandSnapshot()); calls != 0 {
		t.Fatalf("Start calls after canceled gated prepare = %d, want 0", calls)
	}
	closeWorkerdCgroupIntegratedLauncher(t, launcher, nil)
}

func TestWorkerdCgroupLauncherStopCancellationOnlyCancelsCallerWait(t *testing.T) {
	_, backend, cgroups := newWorkerdCgroupLauncherController(t)
	process := newFakeWorkerdProcess(20_008, true)
	killRelease := make(chan struct{})
	backend.killEntered = make(chan struct{}, 1)
	backend.killGate = killRelease
	backend.killHook = func() { process.finishGroup(nil) }
	inner := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{process}}
	launcher := newWorkerdCgroupLauncherForTest(t, &cgroupObservingWorkerdStarter{backend: backend, inner: inner}, cgroups)
	handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0),
		ShardID: "cancel-stop-wait", ShardGeneration: 1,
	})
	if err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}

	stopContext, cancelStop := context.WithCancel(context.Background())
	stopResult := make(chan error, 1)
	go func() { stopResult <- handle.Stop(stopContext) }()
	<-backend.killEntered
	cancelStop()
	if err := <-stopResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("Stop(canceled waiter) error = %v, want context canceled", err)
	}
	close(killRelease)
	if err := handle.Stop(context.Background()); err != nil {
		t.Fatalf("Stop(join background cleanup) error = %v", err)
	}
	if backend.killCallCount() != 1 || backend.childCount() != 0 {
		t.Fatalf("background cleanup kill/children = %d/%d, want 1/0", backend.killCallCount(), backend.childCount())
	}
	closeWorkerdCgroupIntegratedLauncher(t, launcher, nil)
}

func TestWorkerdCgroupLauncherSameGenerationEnsureRejectsGatedStop(t *testing.T) {
	_, backend, cgroups := newWorkerdCgroupLauncherController(t)
	process := newFakeWorkerdProcess(20_014, true)
	killRelease := make(chan struct{})
	backend.killEntered = make(chan struct{}, 1)
	backend.killGate = killRelease
	backend.killHook = func() { process.finishGroup(nil) }
	inner := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{process}}
	launcher := newWorkerdCgroupLauncherForTest(t, &cgroupObservingWorkerdStarter{backend: backend, inner: inner}, cgroups)
	request := WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0), ShardID: "same-generation-during-stop", ShardGeneration: 1}
	handle, err := launcher.Ensure(context.Background(), request)
	if err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	stopResult := make(chan error, 1)
	go func() { stopResult <- handle.Stop(context.Background()) }()
	<-backend.killEntered

	if replacement, err := launcher.Ensure(context.Background(), request); replacement != nil || !errors.Is(err, ErrStaleWorkerdGeneration) {
		t.Fatalf("Ensure(during gated Stop) = %#v, %v, want stale generation and no handle", replacement, err)
	}
	close(killRelease)
	if err := <-stopResult; err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if calls := backend.killCallCount(); calls != 1 {
		t.Fatalf("cgroup.kill calls = %d, want one shared destroy", calls)
	}
	closeWorkerdCgroupIntegratedLauncher(t, launcher, nil)
}

func TestWorkerdCgroupLauncherCloseRetriesActiveInstanceRemoval(t *testing.T) {
	_, backend, cgroups := newWorkerdCgroupLauncherController(t)
	process := newFakeWorkerdProcess(20_015, true)
	backend.killHook = func() { process.finishGroup(nil) }
	backend.removeFailures = 1
	inner := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{process}}
	launcher := newWorkerdCgroupLauncherForTest(t, &cgroupObservingWorkerdStarter{backend: backend, inner: inner}, cgroups)
	handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0),
		ShardID: "active-removal-retry", ShardGeneration: 1,
	})
	if err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	if err := handle.Stop(context.Background()); !errors.Is(err, errWorkerdCgroupContract) {
		t.Fatalf("first Stop() error = %v, want retryable cgroup contract error", err)
	}
	if err := launcher.Close(context.Background()); err != nil {
		t.Fatalf("Close(active removal retry) error = %v", err)
	}
	if backend.killCallCount() != 2 || backend.removeCallCount() != 2 {
		t.Fatalf("retry kill/remove calls = %d/%d, want 2/2", backend.killCallCount(), backend.removeCallCount())
	}
	if backend.childCount() != 0 || backend.openFileDescriptors() != 0 {
		t.Fatalf("post-retry children/descriptors = %d/%d, want none", backend.childCount(), backend.openFileDescriptors())
	}
}

func TestWorkerdCgroupLauncherNaturalLeaderExitUsesOnlyCgroupCleanup(t *testing.T) {
	_, backend, cgroups := newWorkerdCgroupLauncherController(t)
	process := newFakeWorkerdProcess(20_009, true)
	backend.killEntered = make(chan struct{}, 1)
	backend.killHook = func() { process.finishGroup(nil) }
	inner := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{process}}
	launcher := newWorkerdCgroupLauncherForTest(t, &cgroupObservingWorkerdStarter{backend: backend, inner: inner}, cgroups)
	request := WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0), ShardID: "natural-leader-exit", ShardGeneration: 1}
	handle, err := launcher.Ensure(context.Background(), request)
	if err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}

	process.finish(errors.New("test: leader exited"))
	<-backend.killEntered
	if err := handle.Stop(context.Background()); err != nil {
		t.Fatalf("Stop(join natural-exit cleanup) error = %v", err)
	}
	if signals := process.signalSnapshot(); len(signals) != 0 {
		t.Fatalf("numeric process-group signals after natural exit = %v, want none", signals)
	}
	if replacement, err := launcher.Ensure(context.Background(), request); replacement != nil || !errors.Is(err, ErrStaleWorkerdGeneration) {
		t.Fatalf("Ensure(naturally exited generation) = %#v, %v, want stale", replacement, err)
	}
	closeWorkerdCgroupIntegratedLauncher(t, launcher, nil)
}

func TestWorkerdCgroupLauncherNaturalExitStopAndCloseShareOneDestroy(t *testing.T) {
	_, backend, cgroups := newWorkerdCgroupLauncherController(t)
	process := newFakeWorkerdProcess(20_016, true)
	killRelease := make(chan struct{})
	backend.killEntered = make(chan struct{}, 1)
	backend.killGate = killRelease
	backend.killHook = func() { process.finishGroup(nil) }
	inner := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{process}}
	launcher := newWorkerdCgroupLauncherForTest(t, &cgroupObservingWorkerdStarter{backend: backend, inner: inner}, cgroups)
	handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0),
		ShardID: "natural-stop-close-race", ShardGeneration: 1,
	})
	if err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	process.finish(errors.New("test: natural leader exit"))
	<-backend.killEntered

	stopResult := make(chan error, 1)
	go func() { stopResult <- handle.Stop(context.Background()) }()
	const closeCallers = 16
	closeResults := make(chan error, closeCallers)
	for range closeCallers {
		go func() { closeResults <- launcher.Close(context.Background()) }()
	}
	close(killRelease)
	if err := <-stopResult; err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	for range closeCallers {
		if err := <-closeResults; err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}
	if backend.killCallCount() != 1 || backend.removeCallCount() != 1 {
		t.Fatalf("coalesced kill/remove calls = %d/%d, want 1/1", backend.killCallCount(), backend.removeCallCount())
	}
	if signals := process.signalSnapshot(); len(signals) != 0 {
		t.Fatalf("numeric signals = %v, want none", signals)
	}
}

func TestWorkerdCgroupLauncherCloseRetriesResidualPreStartCleanup(t *testing.T) {
	_, backend, cgroups := newWorkerdCgroupLauncherController(t)
	backend.removeFailures = 2
	inner := &recordingWorkerdStarter{startErr: errWorkerdCgroupIntegrationStart}
	starter := &cgroupObservingWorkerdStarter{backend: backend, inner: inner}
	launcher := newWorkerdCgroupLauncherForTest(t, starter, cgroups)

	handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0),
		ShardID: "cgroup-close-residual", ShardGeneration: 1,
	})
	if handle != nil || !errors.Is(err, ErrWorkerdLaunchFailed) {
		t.Fatalf("Ensure() = %#v, %v, want nil, launch failed", handle, err)
	}
	firstCloseErr := launcher.Close(context.Background())
	if firstCloseErr == nil {
		t.Fatal("first Close() error = nil, want retryable residual cleanup failure")
	}
	if err := launcher.Close(context.Background()); err != nil {
		t.Fatalf("second Close() error = %v, want successful cleanup retry", err)
	}
	if backend.childCount() != 0 || backend.openFileDescriptors() != 0 {
		t.Fatalf("post-retry children/descriptors = %d/%d, want none", backend.childCount(), backend.openFileDescriptors())
	}
}

func TestWorkerdCgroupLauncherCloseDropsTransientErrorResolvedByConcurrentStop(t *testing.T) {
	_, backend, cgroups := newWorkerdCgroupLauncherController(t)
	firstProcess := newFakeWorkerdProcess(20_012, true)
	secondProcess := newFakeWorkerdProcess(20_013, true)
	inner := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{firstProcess, secondProcess}}
	launcher := newWorkerdCgroupLauncherForTest(t, &cgroupObservingWorkerdStarter{backend: backend, inner: inner}, cgroups)
	firstHandle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0),
		ShardID: "close-race-a", ShardGeneration: 1,
	})
	if err != nil {
		t.Fatalf("Ensure(first) error = %v", err)
	}
	secondHandle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0),
		ShardID: "close-race-b", ShardGeneration: 1,
	})
	if err != nil {
		t.Fatalf("Ensure(second) error = %v", err)
	}
	commands := inner.commandSnapshot()
	firstFD := commands[0].CgroupFD
	secondFD := commands[1].CgroupFD
	firstKillEntered := make(chan struct{}, 1)
	secondKillRelease := make(chan struct{})
	backend.killEnteredByFD[firstFD] = firstKillEntered
	backend.killGatesByFD[secondFD] = secondKillRelease
	backend.killHooksByFD[firstFD] = func() { firstProcess.finishGroup(nil) }
	backend.killHooksByFD[secondFD] = func() { secondProcess.finishGroup(nil) }
	backend.removeFailures = 1
	closeResult := make(chan error, 1)
	go func() { closeResult <- launcher.Close(context.Background()) }()
	<-firstKillEntered

	retryErr := firstHandle.Stop(context.Background())
	if retryErr != nil {
		retryErr = firstHandle.Stop(context.Background())
	}
	if retryErr != nil {
		t.Fatalf("concurrent Stop cleanup retry error = %v", retryErr)
	}
	select {
	case closeErr := <-closeResult:
		t.Fatalf("Close() returned before second cleanup release: %v", closeErr)
	default:
	}
	close(secondKillRelease)
	if err := <-closeResult; err != nil {
		t.Fatalf("Close() retained resolved transient error = %v", err)
	}
	if err := launcher.Close(context.Background()); err != nil {
		t.Fatalf("replayed Close() error = %v", err)
	}
	if err := secondHandle.Stop(context.Background()); err != nil {
		t.Fatalf("Stop(second handle after Close) error = %v", err)
	}
}

func TestWorkerdCgroupLauncherDoesNotReturnExitedCurrentGeneration(t *testing.T) {
	_, backend, cgroups := newWorkerdCgroupLauncherController(t)
	process := newFakeWorkerdProcess(20_004, true)
	inner := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{process}}
	starter := &cgroupObservingWorkerdStarter{backend: backend, inner: inner}
	launcher := newWorkerdCgroupLauncherForTest(t, starter, cgroups)
	request := WorkerdEnsureRequest{AgentInstanceID: workerdTestAgentInstanceID(0), ShardID: "cgroup-exited-current", ShardGeneration: 1}

	handle, err := launcher.Ensure(context.Background(), request)
	if err != nil {
		t.Fatalf("first Ensure() error = %v", err)
	}
	launcher.mu.Lock()
	handle.instance.mu.Lock()
	handle.instance.exited = true
	handle.instance.exitErr = errors.New("test: leader exited while descendants remain")
	handle.instance.mu.Unlock()
	launcher.mu.Unlock()
	backend.killHook = func() { process.finishGroup(nil) }

	replacement, err := launcher.Ensure(context.Background(), request)
	if replacement != nil || !errors.Is(err, ErrStaleWorkerdGeneration) {
		t.Fatalf("Ensure(exited current) = %#v, %v, want nil, stale generation", replacement, err)
	}
	if backend.killCallCount() != 1 {
		t.Fatalf("cgroup.kill calls = %d, want 1", backend.killCallCount())
	}
	closeWorkerdCgroupIntegratedLauncher(t, launcher, nil)
}

type cgroupWorkerdStartObservation struct {
	calls               int
	cgroupFD            int
	cgroupFDOpen        bool
	cgroupFDNamesChild  bool
	extraFiles          int
	controlsBeforeStart []fakeWorkerdCgroupWrite
}

type cgroupObservingWorkerdStarter struct {
	mu      sync.Mutex
	backend *fakeWorkerdCgroupBackend
	inner   *recordingWorkerdStarter
	seen    cgroupWorkerdStartObservation
}

type parallelCgroupWorkerdStarter struct {
	entered   chan string
	releases  map[string]<-chan struct{}
	processes map[string]*fakeWorkerdProcess
}

func (starter *parallelCgroupWorkerdStarter) Start(command workerdLaunchCommand) (workerdStartedProcess, error) {
	starter.entered <- command.ShardID
	<-starter.releases[command.ShardID]
	return starter.processes[command.ShardID], nil
}

func (starter *cgroupObservingWorkerdStarter) Start(command workerdLaunchCommand) (workerdStartedProcess, error) {
	starter.backend.mu.Lock()
	_, fdOpen := starter.backend.openFDs[command.CgroupFD]
	_, namesChild := starter.backend.groupsByFD[command.CgroupFD]
	starter.backend.mu.Unlock()
	observation := cgroupWorkerdStartObservation{
		calls: 1, cgroupFD: command.CgroupFD, cgroupFDOpen: fdOpen, cgroupFDNamesChild: namesChild,
		extraFiles: len(command.ExtraFiles), controlsBeforeStart: starter.backend.limitWrites(),
	}
	starter.mu.Lock()
	observation.calls += starter.seen.calls
	starter.seen = observation
	starter.mu.Unlock()
	return starter.inner.Start(command)
}

func (starter *cgroupObservingWorkerdStarter) snapshot() cgroupWorkerdStartObservation {
	starter.mu.Lock()
	defer starter.mu.Unlock()
	observation := starter.seen
	observation.controlsBeforeStart = append([]fakeWorkerdCgroupWrite(nil), starter.seen.controlsBeforeStart...)
	return observation
}

func newWorkerdCgroupLauncherController(t *testing.T) (workerdCgroupConfig, *fakeWorkerdCgroupBackend, *workerdCgroupController) {
	t.Helper()
	config := validWorkerdCgroupConfig()
	backend := newFakeWorkerdCgroupBackend()
	controller, err := newWorkerdCgroupControllerWithBackend(config, backend)
	if err != nil {
		t.Fatalf("newWorkerdCgroupControllerWithBackend() error = %v", err)
	}
	return config, backend, controller
}

func newWorkerdCgroupLauncherForTest(t *testing.T, starter workerdProcessStarter, cgroups *workerdCgroupController) *WorkerdProcessLauncher {
	t.Helper()
	return newWorkerdCgroupLauncherWithProbeForTest(t, starter, cgroups, WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }))
}

func newWorkerdCgroupLauncherWithProbeForTest(t *testing.T, starter workerdProcessStarter, cgroups *workerdCgroupController, probe WorkerdReadinessProbe) *WorkerdProcessLauncher {
	t.Helper()
	content := []byte("verified-cgroup-workerd-inode")
	executablePath := t.TempDir() + "/workerd"
	if err := os.WriteFile(executablePath, content, 0o500); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	config := WorkerdLauncherConfig{
		ExecutablePath: executablePath, ExecutableDigest: fmt.Sprintf("sha256:%x", digest),
		ReadinessTimeout: time.Second, StopGracePeriod: 20 * time.Millisecond,
		OutputLimitBytes: 1024, HistoryCapacity: 128,
		ReadinessProbe: probe,
	}
	launcher, err := newWorkerdProcessLauncherWithCgroup(config, starter, unix.MemfdCreate, cgroups)
	if err != nil {
		t.Fatalf("newWorkerdProcessLauncherWithCgroup() error = %v", err)
	}
	return launcher
}

func closeWorkerdCgroupIntegratedLauncher(t *testing.T, launcher *WorkerdProcessLauncher, wantErr error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := launcher.Close(ctx)
	if wantErr == nil && err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if wantErr != nil && !errors.Is(err, wantErr) {
		t.Fatalf("Close() error = %v, want %v", err, wantErr)
	}
}
