//go:build linux

package agent

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type recordingWorkerdObservationSink struct {
	mu           sync.Mutex
	observations []ShardObservation
	observeErr   error
	observe      func(ShardObservation) error
	received     chan ShardObservation
}

func newRecordingWorkerdObservationSink() *recordingWorkerdObservationSink {
	return &recordingWorkerdObservationSink{received: make(chan ShardObservation, 256)}
}

func (sink *recordingWorkerdObservationSink) Observe(observation ShardObservation) error {
	sink.mu.Lock()
	sink.observations = append(sink.observations, observation)
	observeErr := sink.observeErr
	observe := sink.observe
	sink.mu.Unlock()
	select {
	case sink.received <- observation:
	default:
	}
	if observe != nil {
		return observe(observation)
	}
	return observeErr
}

func (sink *recordingWorkerdObservationSink) snapshot() []ShardObservation {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return append([]ShardObservation(nil), sink.observations...)
}

func (sink *recordingWorkerdObservationSink) receive(t *testing.T, timeout time.Duration, message string) ShardObservation {
	t.Helper()
	select {
	case observation := <-sink.received:
		return observation
	case <-time.After(timeout):
		t.Fatal(message)
		return ShardObservation{}
	}
}

func newWorkerdObserverLauncherForTest(t *testing.T, starter workerdProcessStarter, backend *fakeWorkerdCgroupBackend, cgroups *workerdCgroupController, probe WorkerdReadinessProbe, sink WorkerdObservationSink, interval time.Duration) (*WorkerdProcessLauncher, *fakeWorkerdIdentityCapture) {
	t.Helper()
	content := []byte("verified-observer-workerd-inode")
	executablePath := filepath.Join(t.TempDir(), "workerd")
	if err := os.WriteFile(executablePath, content, 0o500); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	config := WorkerdLauncherConfig{
		ExecutablePath: executablePath, ExecutableDigest: fmt.Sprintf("sha256:%x", digest),
		ReadinessTimeout: time.Second, StopGracePeriod: 20 * time.Millisecond,
		OutputLimitBytes: 1024, HistoryCapacity: 128,
		ReadinessProbe:      probe,
		ObservationSink:     sink,
		ObservationInterval: interval,
	}
	capture := newFakeWorkerdIdentityCapture()
	launcher, err := newWorkerdProcessLauncherWithCgroup(config, starter, unix.MemfdCreate, cgroups, capture.capture)
	if err != nil {
		t.Fatalf("newWorkerdProcessLauncherWithCgroup() error = %v", err)
	}
	closeWorkerdLauncherForTest(t, launcher)
	return launcher, capture
}

func installWorkerdObserverKillOrder(backend *fakeWorkerdCgroupBackend, processes []*fakeWorkerdProcess) {
	var killMu sync.Mutex
	killIndex := 0
	backend.killHook = func() {
		killMu.Lock()
		index := killIndex
		killIndex++
		killMu.Unlock()
		if index < len(processes) {
			processes[index].finishGroup(nil)
		}
	}
}

func observerRegistrySize(launcher *WorkerdProcessLauncher) int {
	launcher.mu.Lock()
	defer launcher.mu.Unlock()
	return len(launcher.observers)
}

func observerOf(t *testing.T, handle *WorkerdShardHandle) *workerdShardObserver {
	t.Helper()
	handle.instance.mu.Lock()
	observer := handle.instance.observer
	handle.instance.mu.Unlock()
	if observer == nil {
		t.Fatal("published instance has no observer owner")
	}
	return observer
}

func TestWorkerdLauncherRejectsIncoherentObservationConfig(t *testing.T) {
	okProbe := WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil })
	sink := newRecordingWorkerdObservationSink()
	for name, mutate := range map[string]func(*WorkerdLauncherConfig){
		"interval without sink": func(config *WorkerdLauncherConfig) { config.ObservationSink = nil },
		"sink without interval": func(config *WorkerdLauncherConfig) { config.ObservationInterval = 0 },
		"negative interval":     func(config *WorkerdLauncherConfig) { config.ObservationInterval = -time.Millisecond },
		"interval above maximum": func(config *WorkerdLauncherConfig) {
			config.ObservationInterval = maximumWorkerdObservationInterval + 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, cgroups := newWorkerdCgroupLauncherController(t)
			config := newWorkerdLauncherConfigForTest(t, okProbe)
			config.ObservationSink = sink
			config.ObservationInterval = 2 * time.Millisecond
			mutate(&config)
			launcher, err := newWorkerdProcessLauncherWithCgroup(config, &recordingWorkerdStarter{}, unix.MemfdCreate, cgroups, newFakeWorkerdIdentityCapture().capture)
			if launcher != nil || !errors.Is(err, ErrInvalidWorkerdLauncherConfig) {
				t.Fatalf("constructor = %#v, %v, want nil, invalid config", launcher, err)
			}
		})
	}
	t.Run("sink without cgroup boundary", func(t *testing.T) {
		config := newWorkerdLauncherConfigForTest(t, okProbe)
		config.ObservationSink = sink
		config.ObservationInterval = 2 * time.Millisecond
		launcher, err := newWorkerdProcessLauncherWithResources(config, &recordingWorkerdStarter{}, unix.MemfdCreate, nil, newFakeWorkerdIdentityCapture().capture)
		if launcher != nil || !errors.Is(err, ErrInvalidWorkerdLauncherConfig) {
			t.Fatalf("constructor = %#v, %v, want nil, invalid config", launcher, err)
		}
	})
}

func TestWorkerdObservationSequenceNeverWraps(t *testing.T) {
	t.Parallel()
	if next, ok := nextWorkerdObservationSequence(0); next != 1 || !ok {
		t.Fatalf("nextWorkerdObservationSequence(0) = %d, %v, want 1, true", next, ok)
	}
	if next, ok := nextWorkerdObservationSequence(41); next != 42 || !ok {
		t.Fatalf("nextWorkerdObservationSequence(41) = %d, %v, want 42, true", next, ok)
	}
	if next, ok := nextWorkerdObservationSequence(math.MaxUint64); next != 0 || ok {
		t.Fatalf("nextWorkerdObservationSequence(max) = %d, %v, want fail closed", next, ok)
	}
}

func TestWorkerdObserverDeliversExactTupleWithIncreasingSequences(t *testing.T) {
	process := newFakeWorkerdProcess(32_001, true)
	_, backend, cgroups := newWorkerdCgroupLauncherController(t)
	installWorkerdObserverKillOrder(backend, []*fakeWorkerdProcess{process})
	starter := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{process}}
	sink := newRecordingWorkerdObservationSink()
	launcher, capture := newWorkerdObserverLauncherForTest(t, starter, backend, cgroups,
		WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }),
		sink, 2*time.Millisecond)
	agentID := workerdTestAgentInstanceID(1)
	handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
		AgentInstanceID: agentID, ShardID: "observer-tuple", ShardGeneration: 3,
	})
	if err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	first := sink.receive(t, 2*time.Second, "no first observation was delivered")
	second := sink.receive(t, 2*time.Second, "no second observation was delivered")
	third := sink.receive(t, 2*time.Second, "no third observation was delivered")
	wantRSS := 2 * launcher.observationPageSize
	for index, observation := range []ShardObservation{first, second, third} {
		if observation.AgentInstanceID != agentID || observation.ShardID != "observer-tuple" ||
			observation.ShardGeneration != 3 {
			t.Fatalf("observation %d tuple = %+v, want exact boot/shard/generation", index+1, observation)
		}
		if observation.ObservationSequence != uint64(index+1) {
			t.Fatalf("observation %d sequence = %d, want %d", index+1, observation.ObservationSequence, index+1)
		}
		if observation.RSSBytes != wantRSS {
			t.Fatalf("observation %d RSS = %d, want process statm RSS %d", index+1, observation.RSSBytes, wantRSS)
		}
		if observation.OOMObserved || observation.HeapPressure {
			t.Fatalf("observation %d = %+v, want no pressure at generation baseline", index+1, observation)
		}
		if observation.ObservedAt.IsZero() {
			t.Fatalf("observation %d has no diagnostic ObservedAt", index+1)
		}
	}
	if registry := observerRegistrySize(launcher); registry != 1 {
		t.Fatalf("observer registry size = %d, want exactly one per adopted generation", registry)
	}
	observer := observerOf(t, handle)
	if stopErr := handle.Stop(context.Background()); stopErr != nil {
		t.Fatalf("Stop() error = %v", stopErr)
	}
	select {
	case <-observer.done:
	case <-time.After(2 * time.Second):
		t.Fatal("observer did not exit after stop")
	}
	if captured := capture.capturedForPID(32_001); captured != nil {
		if _, closeFDs := captured.backend.calls(); len(closeFDs) != 1 {
			t.Fatalf("identity closes after stop = %d, want exactly one", len(closeFDs))
		}
	} else {
		t.Fatal("identity was not captured for pid 32001")
	}
	settled := len(sink.snapshot())
	time.Sleep(20 * time.Millisecond)
	if final := len(sink.snapshot()); final != settled {
		t.Fatalf("observations grew after observer exit: %d -> %d", settled, final)
	}
}

func TestWorkerdObserverComparesCountersAgainstGenerationBaseline(t *testing.T) {
	baselineMemory := workerdCgroupMemoryEvents{Low: 1, High: 0, Max: 3, OOM: 2, OOMKill: 5, OOMGroupKill: 1}
	baselineCPU := workerdCgroupCPUStat{UsageMicros: 10, UserMicros: 4, SystemMicros: 6, Periods: 8, ThrottledPeriods: 3, ThrottledMicros: 2}
	process := newFakeWorkerdProcess(32_002, true)
	_, backend, cgroups := newWorkerdCgroupLauncherController(t)
	backend.initialMemoryEvents = formatFakeWorkerdCgroupMemoryEvents(baselineMemory)
	backend.initialCPUStat = formatFakeWorkerdCgroupCPUStat(baselineCPU)
	installWorkerdObserverKillOrder(backend, []*fakeWorkerdProcess{process})
	starter := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{process}}
	sink := newRecordingWorkerdObservationSink()
	launcher, _ := newWorkerdObserverLauncherForTest(t, starter, backend, cgroups,
		WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }),
		sink, 2*time.Millisecond)
	handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
		AgentInstanceID: workerdTestAgentInstanceID(2), ShardID: "observer-baseline", ShardGeneration: 1,
	})
	if err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	first := sink.receive(t, 2*time.Second, "no baseline observation was delivered")
	if first.OOMObserved || first.HeapPressure {
		t.Fatalf("baseline observation = %+v, want unchanged cumulative counters to report no pressure", first)
	}

	oomMemory := baselineMemory
	oomMemory.OOMKill++
	backend.setOnlyChildControl(t, "memory.events", formatFakeWorkerdCgroupMemoryEvents(oomMemory))
	deadline := time.After(2 * time.Second)
	var oomObservation ShardObservation
	for !oomObservation.OOMObserved {
		select {
		case oomObservation = <-sink.received:
		case <-deadline:
			t.Fatal("no observation reported the oom_kill counter increase over the generation baseline")
		}
	}
	if oomObservation.HeapPressure {
		t.Fatalf("oom observation = %+v, want no heap pressure before max events move", oomObservation)
	}

	pressureMemory := oomMemory
	pressureMemory.Max++
	backend.setOnlyChildControl(t, "memory.events", formatFakeWorkerdCgroupMemoryEvents(pressureMemory))
	deadline = time.After(2 * time.Second)
	var pressureObservation ShardObservation
	for !pressureObservation.HeapPressure {
		select {
		case pressureObservation = <-sink.received:
		case <-deadline:
			t.Fatal("no observation reported the max-event counter increase over the generation baseline")
		}
	}
	if !pressureObservation.OOMObserved {
		t.Fatalf("pressure observation = %+v, want oom delta still visible", pressureObservation)
	}
	if stopErr := handle.Stop(context.Background()); stopErr != nil {
		t.Fatalf("Stop() error = %v", stopErr)
	}
}

func TestWorkerdObserverSelfStopDrainDoesNotDeadlock(t *testing.T) {
	processes := []*fakeWorkerdProcess{newFakeWorkerdProcess(32_003, true), newFakeWorkerdProcess(32_004, true)}
	_, backend, cgroups := newWorkerdCgroupLauncherController(t)
	installWorkerdObserverKillOrder(backend, processes)
	starter := &recordingWorkerdStarter{processes: processes}
	sink := newRecordingWorkerdObservationSink()
	handleReady := make(chan *WorkerdShardHandle, 1)
	drainResult := make(chan error, 1)
	var drainOnce sync.Once
	sink.observe = func(ShardObservation) error {
		var drainErr error
		drainOnce.Do(func() {
			handle := <-handleReady
			drainErr = handle.Stop(context.Background())
			drainResult <- drainErr
		})
		return drainErr
	}
	launcher, capture := newWorkerdObserverLauncherForTest(t, starter, backend, cgroups,
		WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }),
		sink, 2*time.Millisecond)
	agentID := workerdTestAgentInstanceID(3)
	handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
		AgentInstanceID: agentID, ShardID: "observer-self-stop", ShardGeneration: 1,
	})
	if err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	observer := observerOf(t, handle)
	handleReady <- handle
	select {
	case drainErr := <-drainResult:
		if drainErr != nil {
			t.Fatalf("Stop(inside sink) error = %v, want observation-triggered cleanup to complete", drainErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("observation-triggered stop deadlocked against its own observer")
	}
	select {
	case <-observer.done:
	case <-time.After(2 * time.Second):
		t.Fatal("observer did not exit after the sink-triggered stop returned")
	}
	if captured := capture.capturedForPID(32_003); captured != nil {
		if _, closeFDs := captured.backend.calls(); len(closeFDs) != 1 {
			t.Fatalf("identity closes after sink-triggered stop = %d, want exactly one", len(closeFDs))
		}
	} else {
		t.Fatal("identity was not captured for pid 32003")
	}
	replacement, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
		AgentInstanceID: agentID, ShardID: "observer-self-stop", ShardGeneration: 2,
	})
	if err != nil {
		t.Fatalf("Ensure(replacement generation) error = %v", err)
	}
	if stopErr := replacement.Stop(context.Background()); stopErr != nil {
		t.Fatalf("Stop(replacement) error = %v", stopErr)
	}
}

func TestWorkerdObserverSuppressesSampleWhenCancellationWinsBeforeDelivery(t *testing.T) {
	process := newFakeWorkerdProcess(32_005, true)
	_, backend, cgroups := newWorkerdCgroupLauncherController(t)
	installWorkerdObserverKillOrder(backend, []*fakeWorkerdProcess{process})
	starter := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{process}}
	sink := newRecordingWorkerdObservationSink()
	launcher, capture := newWorkerdObserverLauncherForTest(t, starter, backend, cgroups,
		WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }),
		sink, 2*time.Millisecond)
	handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
		AgentInstanceID: workerdTestAgentInstanceID(4), ShardID: "observer-suppress", ShardGeneration: 1,
	})
	if err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	sink.receive(t, 2*time.Second, "no observation was delivered before the gated sample")
	captured := capture.capturedForPID(32_005)
	if captured == nil {
		t.Fatal("identity was not captured for pid 32005")
	}
	snapshotEntered := make(chan struct{}, 1)
	snapshotGate := make(chan struct{})
	var gateOnce sync.Once
	releaseGate := func() { gateOnce.Do(func() { close(snapshotGate) }) }
	t.Cleanup(releaseGate)
	captured.reader.mu.Lock()
	captured.reader.snapshotEntered = snapshotEntered
	captured.reader.snapshotGate = snapshotGate
	captured.reader.mu.Unlock()
	select {
	case <-snapshotEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("observer did not enter the gated RSS snapshot")
	}
	suppressedBaseline := len(sink.snapshot())
	observer := observerOf(t, handle)
	stopResult := make(chan error, 1)
	go func() { stopResult <- handle.Stop(context.Background()) }()
	waitUntilWorkerdCondition(t, 2*time.Second, func() bool {
		return observer.ctx.Err() != nil
	}, "stop did not cancel the observer")
	releaseGate()
	select {
	case stopErr := <-stopResult:
		if stopErr != nil {
			t.Fatalf("Stop() error = %v", stopErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() did not complete after the gated sample was released")
	}
	select {
	case <-observer.done:
	case <-time.After(2 * time.Second):
		t.Fatal("observer did not exit after suppression")
	}
	if final := len(sink.snapshot()); final != suppressedBaseline {
		t.Fatalf("suppressed sample was delivered anyway: %d -> %d observations", suppressedBaseline, final)
	}
}

func TestWorkerdObserverSinkErrorEndsProducerWithoutStoppingShard(t *testing.T) {
	sinkFailure := errors.New("test: observation sink failure")
	process := newFakeWorkerdProcess(32_006, true)
	_, backend, cgroups := newWorkerdCgroupLauncherController(t)
	installWorkerdObserverKillOrder(backend, []*fakeWorkerdProcess{process})
	starter := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{process}}
	sink := newRecordingWorkerdObservationSink()
	sink.observeErr = sinkFailure
	launcher, capture := newWorkerdObserverLauncherForTest(t, starter, backend, cgroups,
		WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }),
		sink, 2*time.Millisecond)
	handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
		AgentInstanceID: workerdTestAgentInstanceID(5), ShardID: "observer-sink-error", ShardGeneration: 1,
	})
	if err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	sink.receive(t, 2*time.Second, "no observation was delivered to the failing sink")
	waitUntilWorkerdCondition(t, 2*time.Second, func() bool {
		return observerRegistrySize(launcher) == 0
	}, "observer did not fail closed after the sink error")
	if delivered := len(sink.snapshot()); delivered != 1 {
		t.Fatalf("deliveries after sink failure = %d, want exactly one", delivered)
	}
	if alive, groupErr := process.GroupAlive(); groupErr != nil || !alive {
		t.Fatalf("process group alive = %v, %v, want sink failure to leave the shard running", alive, groupErr)
	}
	if captured := capture.capturedForPID(32_006); captured != nil {
		if _, closeFDs := captured.backend.calls(); len(closeFDs) != 0 {
			t.Fatalf("identity closes after sink failure = %d, want retained running shard", len(closeFDs))
		}
	} else {
		t.Fatal("identity was not captured for pid 32006")
	}
	if stopErr := handle.Stop(context.Background()); stopErr != nil {
		t.Fatalf("Stop() error = %v", stopErr)
	}
}

func TestWorkerdShardHandleSamplesResourcesWithExactIdentity(t *testing.T) {
	baselineMemory := workerdCgroupMemoryEvents{Low: 1, High: 2, Max: 3, OOM: 4, OOMKill: 5, OOMGroupKill: 6}
	baselineCPU := workerdCgroupCPUStat{UsageMicros: 10, UserMicros: 4, SystemMicros: 6, Periods: 8, ThrottledPeriods: 3, ThrottledMicros: 2}
	process := newFakeWorkerdProcess(32_010, true)
	cgroupConfig, backend, cgroups := newWorkerdCgroupLauncherController(t)
	backend.initialMemoryEvents = formatFakeWorkerdCgroupMemoryEvents(baselineMemory)
	backend.initialCPUStat = formatFakeWorkerdCgroupCPUStat(baselineCPU)
	installWorkerdObserverKillOrder(backend, []*fakeWorkerdProcess{process})
	starter := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{process}}
	sink := newRecordingWorkerdObservationSink()
	launcher, capture := newWorkerdObserverLauncherForTest(t, starter, backend, cgroups,
		WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }),
		sink, 2*time.Millisecond)
	agentID := workerdTestAgentInstanceID(8)
	handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
		AgentInstanceID: agentID, ShardID: "resource-sample", ShardGeneration: 7,
	})
	if err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	currentMemory := workerdCgroupMemoryEvents{Low: 2, High: 4, Max: 6, OOM: 8, OOMKill: 10, OOMGroupKill: 12}
	currentCPU := workerdCgroupCPUStat{UsageMicros: 30, UserMicros: 14, SystemMicros: 16, Periods: 18, ThrottledPeriods: 8, ThrottledMicros: 7}
	backend.setOnlyChildControl(t, "memory.current", "67108864\n")
	backend.setOnlyChildControl(t, "memory.events", formatFakeWorkerdCgroupMemoryEvents(currentMemory))
	backend.setOnlyChildControl(t, "cpu.stat", formatFakeWorkerdCgroupCPUStat(currentCPU))
	backend.setOnlyChildControl(t, "pids.current", "17\n")
	sample, sampleErr := handle.SampleResources(context.Background())
	if sampleErr != nil {
		t.Fatalf("SampleResources() error = %v", sampleErr)
	}
	captured := capture.capturedForPID(32_010)
	if captured == nil {
		t.Fatal("identity was not captured for pid 32010")
	}
	want := WorkerdShardResourceSample{
		AgentInstanceID:    agentID,
		ShardID:            "resource-sample",
		ShardGeneration:    7,
		PID:                32_010,
		ProcessStartTicks:  captured.ticks,
		ProcessRSSBytes:    2 * launcher.observationPageSize,
		CPUMax:             cgroupConfig.CPUMax,
		MemoryCurrentBytes: 67_108_864,
		MemoryEvents:       WorkerdMemoryEventCounters{Low: 2, High: 4, Max: 6, OOM: 8, OOMKill: 10, OOMGroupKill: 12},
		MemoryEventsDelta:  WorkerdMemoryEventCounters{Low: 1, High: 2, Max: 3, OOM: 4, OOMKill: 5, OOMGroupKill: 6},
		CPUStat:            WorkerdCPUStatCounters{UsageMicros: 30, UserMicros: 14, SystemMicros: 16, Periods: 18, ThrottledPeriods: 8, ThrottledMicros: 7},
		CPUStatDelta:       WorkerdCPUStatCounters{UsageMicros: 20, UserMicros: 10, SystemMicros: 10, Periods: 10, ThrottledPeriods: 5, ThrottledMicros: 5},
		PIDsCurrent:        17,
	}
	if sample != want {
		t.Fatalf("SampleResources() = %+v, want %+v", sample, want)
	}
	if stopErr := handle.Stop(context.Background()); stopErr != nil {
		t.Fatalf("Stop() error = %v", stopErr)
	}
	if _, closedErr := handle.SampleResources(context.Background()); closedErr == nil {
		t.Fatal("SampleResources(after stop) error = nil, want closed resource boundary")
	}
	var nilHandle *WorkerdShardHandle
	if _, nilErr := nilHandle.SampleResources(context.Background()); !errors.Is(nilErr, ErrInvalidWorkerdEnsureRequest) {
		t.Fatalf("SampleResources(nil handle) error = %v, want invalid request", nilErr)
	}
}

func TestWorkerdObserverLifecycleJoinsOnCloseAndSkipsFailedLaunches(t *testing.T) {
	t.Run("close joins every observer", func(t *testing.T) {
		processes := []*fakeWorkerdProcess{newFakeWorkerdProcess(32_007, true), newFakeWorkerdProcess(32_008, true)}
		_, backend, cgroups := newWorkerdCgroupLauncherController(t)
		installWorkerdObserverKillOrder(backend, processes)
		starter := &recordingWorkerdStarter{processes: processes}
		sink := newRecordingWorkerdObservationSink()
		launcher, capture := newWorkerdObserverLauncherForTest(t, starter, backend, cgroups,
			WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return nil }),
			sink, 2*time.Millisecond)
		agentID := workerdTestAgentInstanceID(6)
		for _, shard := range []string{"observer-close-a", "observer-close-b"} {
			if _, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
				AgentInstanceID: agentID, ShardID: shard, ShardGeneration: 1,
			}); err != nil {
				t.Fatalf("Ensure(%s) error = %v", shard, err)
			}
		}
		if registry := observerRegistrySize(launcher); registry != 2 {
			t.Fatalf("observer registry size = %d, want one per adopted generation", registry)
		}
		if closeErr := launcher.Close(context.Background()); closeErr != nil {
			t.Fatalf("Close() error = %v", closeErr)
		}
		if registry := observerRegistrySize(launcher); registry != 0 {
			t.Fatalf("observer registry size after close = %d, want joined and empty", registry)
		}
		for _, pid := range []int{32_007, 32_008} {
			captured := capture.capturedForPID(pid)
			if captured == nil {
				t.Fatalf("identity was not captured for pid %d", pid)
			}
			if _, closeFDs := captured.backend.calls(); len(closeFDs) != 1 {
				t.Fatalf("identity closes for pid %d = %d, want exactly one", pid, len(closeFDs))
			}
		}
	})
	t.Run("failed launch starts no observer", func(t *testing.T) {
		readinessFailure := errors.New("test: readiness failure")
		process := newFakeWorkerdProcess(32_009, true)
		_, backend, cgroups := newWorkerdCgroupLauncherController(t)
		installWorkerdObserverKillOrder(backend, []*fakeWorkerdProcess{process})
		starter := &recordingWorkerdStarter{processes: []*fakeWorkerdProcess{process}}
		sink := newRecordingWorkerdObservationSink()
		launcher, _ := newWorkerdObserverLauncherForTest(t, starter, backend, cgroups,
			WorkerdReadinessProbeFunc(func(context.Context, WorkerdProcessInfo) error { return readinessFailure }),
			sink, 2*time.Millisecond)
		handle, err := launcher.Ensure(context.Background(), WorkerdEnsureRequest{
			AgentInstanceID: workerdTestAgentInstanceID(6), ShardID: "observer-not-ready", ShardGeneration: 1,
		})
		if handle != nil || !errors.Is(err, ErrWorkerdNotReady) {
			t.Fatalf("Ensure() = %#v, %v, want readiness failure", handle, err)
		}
		if registry := observerRegistrySize(launcher); registry != 0 {
			t.Fatalf("observer registry size = %d, want none for a failed launch", registry)
		}
		if delivered := len(sink.snapshot()); delivered != 0 {
			t.Fatalf("deliveries for failed launch = %d, want none", delivered)
		}
	})
}
