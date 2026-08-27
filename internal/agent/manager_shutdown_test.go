package agent

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

var errControlledStop = errors.New("test: controlled stop failure")

type controlledStopLauncher struct {
	process *controlledStopProcess
}

func (launcher controlledStopLauncher) Start(_ context.Context, spec ShardSpec) (ShardProcess, error) {
	launcher.process.mu.Lock()
	launcher.process.id = spec.ShardID
	launcher.process.mu.Unlock()
	return launcher.process, nil
}

type controlledStopProcess struct {
	mu              sync.Mutex
	id              string
	calls           int
	failures        int
	stopEntered     chan struct{}
	stopGate        <-chan struct{}
	stopEnteredOnce sync.Once
}

func (process *controlledStopProcess) ID() string {
	process.mu.Lock()
	defer process.mu.Unlock()
	return process.id
}

func (process *controlledStopProcess) Stop(ctx context.Context) error {
	process.mu.Lock()
	process.calls++
	call := process.calls
	failures := process.failures
	process.mu.Unlock()
	if process.stopEntered != nil {
		process.stopEnteredOnce.Do(func() { close(process.stopEntered) })
	}
	if process.stopGate != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-process.stopGate:
		}
	}
	if call <= failures {
		return errControlledStop
	}
	return nil
}

func (process *controlledStopProcess) stopCalls() int {
	process.mu.Lock()
	defer process.mu.Unlock()
	return process.calls
}

func TestManagerShutdownFencesAndDrainsAnInflightLaunch(t *testing.T) {
	launcher := &fakeLauncher{startGate: make(chan struct{})}
	manager := mustManager(t, launcher, Limits{
		MaximumSessions: 4, MemoryLimitBytes: 1_000,
		AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour,
	})
	request := baseRequest(t, "shutdown-tenant", "shutdown-session", 1, time.Unix(2_000_001_000, 0).UTC())

	acquireResult := make(chan error, 1)
	go func() {
		_, err := manager.Acquire(context.Background(), request)
		acquireResult <- err
	}()
	waitForLauncherStarts(t, launcher, 1)

	shutdownResult := make(chan error, 1)
	go func() {
		shutdownResult <- manager.Shutdown(context.Background())
	}()
	waitForManagerClosed(t, manager)
	close(launcher.startGate)

	if err := <-acquireResult; !errors.Is(err, ErrManagerClosed) {
		t.Fatalf("Acquire(during shutdown) error = %v, want ErrManagerClosed", err)
	}
	if err := <-shutdownResult; err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	if _, err := manager.Acquire(context.Background(), request); !errors.Is(err, ErrManagerClosed) {
		t.Fatalf("Acquire(after shutdown) error = %v, want ErrManagerClosed", err)
	}
	starts, stops := launcher.counts()
	if starts != 1 || len(stops) != 1 {
		t.Fatalf("launcher starts/stops = %d/%#v, want 1/one", starts, stops)
	}
	if snapshot := manager.Snapshot(); snapshot != (ManagerSnapshot{}) {
		t.Fatalf("post-shutdown snapshot = %#v", snapshot)
	}
}

func TestManagerConcurrentShutdownStopsEveryShardExactlyOnce(t *testing.T) {
	launcher := &fakeLauncher{}
	manager := mustManager(t, launcher, Limits{
		MaximumSessions: 1, MemoryLimitBytes: 1_000,
		AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour,
	})
	now := time.Unix(2_000_001_100, 0).UTC()
	for index, seed := range []string{"a", "b", "c"} {
		mustAcquire(t, manager, baseRequest(t, "shutdown-tenant-"+seed, "shutdown-session-"+seed, 1, now.Add(time.Duration(index)*time.Second)))
	}

	const callers = 32
	errorsSeen := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errorsSeen <- manager.Shutdown(context.Background())
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatalf("Shutdown() error = %v", err)
		}
	}
	starts, stops := launcher.counts()
	if starts != 3 || len(stops) != 3 {
		t.Fatalf("launcher starts/stops = %d/%#v, want 3/three", starts, stops)
	}
	seen := make(map[string]struct{}, len(stops))
	for _, shardID := range stops {
		if _, duplicate := seen[shardID]; duplicate {
			t.Fatalf("shard %q stopped more than once: %#v", shardID, stops)
		}
		seen[shardID] = struct{}{}
	}
}

func TestManagerShutdownCanResumeAfterWaitingContextExpires(t *testing.T) {
	launcher := &fakeLauncher{startGate: make(chan struct{})}
	manager := mustManager(t, launcher, Limits{
		MaximumSessions: 4, MemoryLimitBytes: 1_000,
		AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour,
	})
	request := baseRequest(t, "retry-tenant", "retry-session", 1, time.Unix(2_000_001_200, 0).UTC())
	acquireResult := make(chan error, 1)
	go func() {
		_, err := manager.Acquire(context.Background(), request)
		acquireResult <- err
	}()
	waitForLauncherStarts(t, launcher, 1)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := manager.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown(timeout) error = %v, want context deadline", err)
	}
	close(launcher.startGate)
	if err := <-acquireResult; !errors.Is(err, ErrManagerClosed) {
		t.Fatalf("Acquire(after timed-out shutdown) error = %v, want ErrManagerClosed", err)
	}
	if err := manager.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown(retry) error = %v", err)
	}
	_, stops := launcher.counts()
	if len(stops) != 1 {
		t.Fatalf("stops = %#v, want one", stops)
	}
}

func TestManagerShutdownWaitsForAConcurrentReleaseStop(t *testing.T) {
	stopGate := make(chan struct{})
	process := &controlledStopProcess{stopEntered: make(chan struct{}), stopGate: stopGate}
	manager := mustManager(t, controlledStopLauncher{process: process}, Limits{
		MaximumSessions: 1, MemoryLimitBytes: 1_000,
		AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour,
	})
	request := dedicatedRequest(t, "release-race", time.Unix(2_000_001_300, 0).UTC())
	mustAcquire(t, manager, request)
	releaseResult := make(chan error, 1)
	go func() {
		releaseResult <- manager.Release(context.Background(), ReleaseRequest{
			SessionID: request.SessionID, PlacementGeneration: request.PlacementGeneration,
		})
	}()
	<-process.stopEntered
	shutdownResult := make(chan error, 1)
	go func() { shutdownResult <- manager.Shutdown(context.Background()) }()
	select {
	case err := <-shutdownResult:
		t.Fatalf("Shutdown returned before the tracked stop completed: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(stopGate)
	if err := <-releaseResult; err != nil {
		t.Fatalf("Release() error = %v", err)
	}
	if err := <-shutdownResult; err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	if calls := process.stopCalls(); calls != 1 {
		t.Fatalf("Stop() calls = %d, want 1", calls)
	}
}

func TestManagerShutdownRetriesAnUncertainEarlierStop(t *testing.T) {
	process := &controlledStopProcess{failures: 1}
	manager := mustManager(t, controlledStopLauncher{process: process}, Limits{
		MaximumSessions: 1, MemoryLimitBytes: 1_000,
		AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour,
	})
	request := dedicatedRequest(t, "stop-retry", time.Unix(2_000_001_400, 0).UTC())
	mustAcquire(t, manager, request)
	if err := manager.Release(context.Background(), ReleaseRequest{
		SessionID: request.SessionID, PlacementGeneration: request.PlacementGeneration,
	}); !errors.Is(err, errControlledStop) {
		t.Fatalf("Release(first stop) error = %v, want controlled failure", err)
	}
	if err := manager.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown(retry stop) error = %v", err)
	}
	if calls := process.stopCalls(); calls != 2 {
		t.Fatalf("Stop() calls = %d, want 2", calls)
	}
}

func dedicatedRequest(t *testing.T, seed string, now time.Time) PlacementRequest {
	t.Helper()
	request := baseRequest(t, "tenant-"+seed, "session-"+seed, 1, now)
	request.TrustClass = TrustUnreviewed
	request.Profile = PlacementProfile{ProcessScope: ScopeSession, OuterIsolation: IsolationFirecracker}
	return request
}

func waitForLauncherStarts(t *testing.T, launcher *fakeLauncher, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		starts, _ := launcher.counts()
		if starts >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("launcher starts = %d, want at least %d", starts, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func waitForManagerClosed(t *testing.T, manager *Manager) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		manager.mu.Lock()
		closed := manager.closed
		manager.mu.Unlock()
		if closed {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("manager did not enter closed state")
		}
		time.Sleep(time.Millisecond)
	}
}
