package agent

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/identity"
)

var errControlledStop = errors.New("test: controlled stop failure")

func TestTerminalShardCleanupMarkerSurvivesWrappingAndJoining(t *testing.T) {
	wrapped := fmt.Errorf("terminal cleanup: %w", ErrTerminalShardCleanup)
	joined := errors.Join(errControlledStop, wrapped)
	if !errors.Is(wrapped, ErrTerminalShardCleanup) {
		t.Fatalf("errors.Is(wrapped, ErrTerminalShardCleanup) = false")
	}
	if !errors.Is(joined, ErrTerminalShardCleanup) {
		t.Fatalf("errors.Is(joined, ErrTerminalShardCleanup) = false")
	}
}

type controlledStopLauncher struct {
	mu      sync.Mutex
	process *controlledStopProcess
	starts  int
	specs   []ShardSpec
}

type controlledStopSequenceLauncher struct {
	mu        sync.Mutex
	processes []*controlledStopProcess
	next      int
}

func (launcher *controlledStopSequenceLauncher) Start(_ context.Context, spec ShardSpec) (ShardProcess, error) {
	launcher.mu.Lock()
	process := launcher.processes[launcher.next]
	launcher.next++
	launcher.mu.Unlock()
	process.mu.Lock()
	process.agentInstanceID = spec.AgentInstanceID
	process.id = spec.ShardID
	process.shardGeneration = spec.ShardGeneration
	process.mu.Unlock()
	return process, nil
}

func (launcher *controlledStopLauncher) Start(_ context.Context, spec ShardSpec) (ShardProcess, error) {
	launcher.mu.Lock()
	launcher.starts++
	launcher.specs = append(launcher.specs, spec)
	launcher.mu.Unlock()
	launcher.process.mu.Lock()
	launcher.process.agentInstanceID = spec.AgentInstanceID
	launcher.process.id = spec.ShardID
	launcher.process.shardGeneration = spec.ShardGeneration
	launcher.process.mu.Unlock()
	return launcher.process, nil
}

func (launcher *controlledStopLauncher) launchState() (int, []ShardSpec) {
	launcher.mu.Lock()
	defer launcher.mu.Unlock()
	return launcher.starts, append([]ShardSpec(nil), launcher.specs...)
}

type controlledStopProcess struct {
	mu              sync.Mutex
	agentInstanceID identity.ID
	id              string
	shardGeneration ShardGeneration
	calls           int
	failures        int
	failureErr      error
	stopEntered     chan struct{}
	stopGate        <-chan struct{}
	stopCallEntered chan int
	stopCallGates   map[int]<-chan struct{}
	stopEnteredOnce sync.Once
}

func (process *controlledStopProcess) ID() string {
	process.mu.Lock()
	defer process.mu.Unlock()
	return process.id
}

func (process *controlledStopProcess) AgentInstanceID() identity.ID {
	process.mu.Lock()
	defer process.mu.Unlock()
	return process.agentInstanceID
}

func (process *controlledStopProcess) ShardGeneration() ShardGeneration {
	process.mu.Lock()
	defer process.mu.Unlock()
	return process.shardGeneration
}

func (process *controlledStopProcess) Stop(ctx context.Context) error {
	process.mu.Lock()
	process.calls++
	call := process.calls
	failures := process.failures
	failureErr := process.failureErr
	callEntered := process.stopCallEntered
	callGate := process.stopCallGates[call]
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
	if callEntered != nil {
		callEntered <- call
	}
	if callGate != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-callGate:
		}
	}
	if call <= failures {
		if failureErr != nil {
			return failureErr
		}
		return errControlledStop
	}
	return nil
}

type observedDoneContext struct {
	context.Context
	observed chan struct{}
	once     sync.Once
}

type mutexObservingTerminalError struct {
	manager *Manager
	result  chan bool
	once    sync.Once
}

func (*mutexObservingTerminalError) Error() string { return "test: terminal cleanup" }

func (err *mutexObservingTerminalError) Is(target error) bool {
	managerLockHeld := !err.manager.mu.TryLock()
	if !managerLockHeld {
		err.manager.mu.Unlock()
	}
	err.once.Do(func() { err.result <- managerLockHeld })
	return target == ErrTerminalShardCleanup
}

func (ctx *observedDoneContext) Done() <-chan struct{} {
	ctx.once.Do(func() { close(ctx.observed) })
	return ctx.Context.Done()
}

func newObservedDoneContext() (*observedDoneContext, context.CancelFunc) {
	inner, cancel := context.WithCancel(context.Background())
	return &observedDoneContext{Context: inner, observed: make(chan struct{})}, cancel
}

func (process *controlledStopProcess) stopCalls() int {
	process.mu.Lock()
	defer process.mu.Unlock()
	return process.calls
}

type parallelStopLauncher struct {
	entered     chan string
	stopGate    chan struct{}
	releaseOnce sync.Once
	failStops   bool
}

func newParallelStopLauncher() *parallelStopLauncher {
	return &parallelStopLauncher{entered: make(chan string, 16), stopGate: make(chan struct{})}
}

func (launcher *parallelStopLauncher) Start(_ context.Context, spec ShardSpec) (ShardProcess, error) {
	return &parallelStopProcess{
		agentInstanceID: spec.AgentInstanceID,
		id:              spec.ShardID,
		shardGeneration: spec.ShardGeneration,
		launcher:        launcher,
	}, nil
}

func (launcher *parallelStopLauncher) releaseStops() {
	launcher.releaseOnce.Do(func() { close(launcher.stopGate) })
}

type parallelStopProcess struct {
	agentInstanceID identity.ID
	id              string
	shardGeneration ShardGeneration
	launcher        *parallelStopLauncher
}

func (process *parallelStopProcess) ID() string { return process.id }

func (process *parallelStopProcess) AgentInstanceID() identity.ID { return process.agentInstanceID }

func (process *parallelStopProcess) ShardGeneration() ShardGeneration { return process.shardGeneration }

func (process *parallelStopProcess) Stop(ctx context.Context) error {
	process.launcher.entered <- process.id
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-process.launcher.stopGate:
		if process.launcher.failStops {
			return errors.New("test: stop " + process.id)
		}
		return nil
	}
}

type abandonedLaunchLauncher struct {
	process         *controlledStopProcess
	startEntered    chan struct{}
	startReturnGate chan struct{}
	releaseOnce     sync.Once
}

func newAbandonedLaunchLauncher(process *controlledStopProcess) *abandonedLaunchLauncher {
	return &abandonedLaunchLauncher{
		process: process, startEntered: make(chan struct{}), startReturnGate: make(chan struct{}),
	}
}

func (launcher *abandonedLaunchLauncher) Start(ctx context.Context, spec ShardSpec) (ShardProcess, error) {
	launcher.process.mu.Lock()
	launcher.process.agentInstanceID = spec.AgentInstanceID
	launcher.process.id = spec.ShardID
	launcher.process.shardGeneration = spec.ShardGeneration
	launcher.process.mu.Unlock()
	close(launcher.startEntered)
	<-ctx.Done()
	<-launcher.startReturnGate
	return launcher.process, nil
}

func (launcher *abandonedLaunchLauncher) releaseStart() {
	launcher.releaseOnce.Do(func() { close(launcher.startReturnGate) })
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

func TestManagerCanceledLastClaimAfterCompletedLaunchTransfersOneStopEpoch(t *testing.T) {
	stopGate := make(chan struct{})
	process := &controlledStopProcess{stopEntered: make(chan struct{}), stopGate: stopGate}
	launcher := &controlledStopLauncher{process: process}
	manager := mustManager(t, launcher, Limits{
		MaximumSessions: 4, MemoryLimitBytes: 1_000,
		AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour,
	})
	request := baseRequest(t, "completed-cancel-tenant", "completed-cancel-session", 1, time.Unix(2_000_001_025, 0).UTC())
	pending := registerUnadoptedLaunch(t, manager, request)
	manager.runLaunch(pending)

	// Cancellation is already observable when the completed result is resolved,
	// so the claim must not adopt even though the result channel is also ready.
	claimCtx, cancelClaim := context.WithCancel(context.Background())
	cancelClaim()
	if err := manager.waitForLaunch(claimCtx, pending, &launchClaim{request: request}); !errors.Is(err, context.Canceled) {
		t.Fatalf("waitForLaunch(canceled completed claim) error = %v, want context.Canceled", err)
	}
	key := shardProcessKeyFor(pending.spec)
	manager.mu.Lock()
	liveShards := len(manager.shards)
	livePlacements := len(manager.placements)
	tracked := manager.pendingStops[key]
	manager.mu.Unlock()
	if liveShards != 0 || livePlacements != 0 || tracked == nil {
		t.Fatalf("post-cancel ownership = shards:%d placements:%d stop:%v, want 0/0/tracked", liveShards, livePlacements, tracked != nil)
	}
	select {
	case <-process.stopEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("manager-owned Stop epoch did not start")
	}
	close(stopGate)
	if err := manager.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown(join cleanup) error = %v", err)
	}
	if calls := process.stopCalls(); calls != 1 {
		t.Fatalf("Stop() calls = %d, want exactly one epoch", calls)
	}
}

func TestManagerShutdownClaimsFinishedUnadoptedLaunch(t *testing.T) {
	process := &controlledStopProcess{}
	launcher := &controlledStopLauncher{process: process}
	manager := mustManager(t, launcher, Limits{
		MaximumSessions: 4, MemoryLimitBytes: 1_000,
		AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour,
	})
	request := baseRequest(t, "shutdown-pending-tenant", "shutdown-pending-session", 1, time.Unix(2_000_001_050, 0).UTC())
	pending := registerUnadoptedLaunch(t, manager, request)
	manager.runLaunch(pending)

	shutdownResult := make(chan error, 1)
	go func() { shutdownResult <- manager.Shutdown(context.Background()) }()
	if err := receiveError(t, shutdownResult); err != nil {
		t.Fatalf("Shutdown(finished unadopted launch) error = %v", err)
	}
	manager.mu.Lock()
	pendingScopes := len(manager.pendingScopes)
	pendingSessions := len(manager.pendingSessions)
	manager.mu.Unlock()
	if pendingScopes != 0 || pendingSessions != 0 || manager.Snapshot() != (ManagerSnapshot{}) {
		t.Fatalf("shutdown pending state = scopes:%d sessions:%d snapshot:%#v", pendingScopes, pendingSessions, manager.Snapshot())
	}
	if calls := process.stopCalls(); calls != 1 {
		t.Fatalf("Stop() calls = %d, want one", calls)
	}
}

func TestManagerLateLaunchClaimJoinsShutdownStopEpoch(t *testing.T) {
	process := &controlledStopProcess{}
	launcher := &controlledStopLauncher{process: process}
	manager := mustManager(t, launcher, Limits{
		MaximumSessions: 4, MemoryLimitBytes: 1_000,
		AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour,
	})
	request := baseRequest(t, "late-claim-tenant", "late-claim-session", 1, time.Unix(2_000_001_075, 0).UTC())
	pending := registerUnadoptedLaunch(t, manager, request)
	manager.runLaunch(pending)
	if err := manager.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown(claim result) error = %v", err)
	}
	if err := manager.waitForLaunch(context.Background(), pending, &launchClaim{request: request}); !errors.Is(err, ErrManagerClosed) {
		t.Fatalf("late waitForLaunch() error = %v, want ErrManagerClosed", err)
	}
	if err := manager.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown(join late claim) error = %v", err)
	}
	if calls := process.stopCalls(); calls != 1 {
		t.Fatalf("Stop() calls = %d, want late claim to join the first epoch", calls)
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
	manager := mustManager(t, &controlledStopLauncher{process: process}, Limits{
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
	manager := mustManager(t, &controlledStopLauncher{process: process}, Limits{
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

func TestManagerReleaseRetriesACompletedRetryableCleanupInANewEpoch(t *testing.T) {
	process := &controlledStopProcess{failures: 1}
	manager := mustManager(t, &controlledStopLauncher{process: process}, Limits{
		MaximumSessions: 1, MemoryLimitBytes: 1_000,
		AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour,
	})
	request := dedicatedRequest(t, "release-epoch-retry", time.Unix(2_000_001_410, 0).UTC())
	mustAcquire(t, manager, request)
	release := ReleaseRequest{SessionID: request.SessionID, PlacementGeneration: request.PlacementGeneration}

	if err := manager.Release(context.Background(), release); !errors.Is(err, errControlledStop) {
		t.Fatalf("Release(epoch 1) error = %v, want controlled failure", err)
	}
	if calls := process.stopCalls(); calls != 1 {
		t.Fatalf("Stop() calls after epoch 1 = %d, want 1", calls)
	}
	if err := manager.Release(context.Background(), release); err != nil {
		t.Fatalf("Release(epoch 2) error = %v", err)
	}
	if calls := process.stopCalls(); calls != 2 {
		t.Fatalf("Stop() calls after epoch 2 = %d, want 2", calls)
	}
	manager.mu.Lock()
	cleanup := manager.releaseCleanups[request.SessionID]
	_, cleanupRetained := manager.pendingStops[cleanup.key]
	manager.mu.Unlock()
	if cleanupRetained {
		t.Fatal("successful cleanup epoch remained in pendingStops")
	}
	if err := manager.Release(context.Background(), release); err != nil {
		t.Fatalf("Release(after successful cleanup) error = %v", err)
	}
	if calls := process.stopCalls(); calls != 2 {
		t.Fatalf("Stop() calls after completed cleanup = %d, want 2", calls)
	}
}

func TestManagerReleaseCancellationOnlyCancelsWaitAndShutdownJoinsStop(t *testing.T) {
	stopGate := make(chan struct{})
	var releaseGate sync.Once
	releaseStop := func() { releaseGate.Do(func() { close(stopGate) }) }
	defer releaseStop()
	process := &controlledStopProcess{stopEntered: make(chan struct{}), stopGate: stopGate}
	manager := mustManager(t, &controlledStopLauncher{process: process}, Limits{
		MaximumSessions: 1, MemoryLimitBytes: 1_000,
		AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour,
	})
	request := dedicatedRequest(t, "release-cancel", time.Unix(2_000_001_450, 0).UTC())
	mustAcquire(t, manager, request)

	releaseCtx, cancelRelease := context.WithCancel(context.Background())
	releaseResult := make(chan error, 1)
	go func() {
		releaseResult <- manager.Release(releaseCtx, ReleaseRequest{
			SessionID: request.SessionID, PlacementGeneration: request.PlacementGeneration,
		})
	}()
	<-process.stopEntered
	cancelRelease()
	if err := receiveError(t, releaseResult); !errors.Is(err, context.Canceled) {
		t.Fatalf("Release() error = %v, want context.Canceled", err)
	}

	shutdownResult := make(chan error, 1)
	go func() { shutdownResult <- manager.Shutdown(context.Background()) }()
	select {
	case err := <-shutdownResult:
		t.Fatalf("Shutdown() returned before manager-owned Stop completed: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	releaseStop()
	if err := receiveError(t, shutdownResult); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	if calls := process.stopCalls(); calls != 1 {
		t.Fatalf("Stop() calls = %d, want one shared stop epoch", calls)
	}
}

func TestManagerRepeatedReleaseJoinsTheSameCleanupEpoch(t *testing.T) {
	stopGate := make(chan struct{})
	var releaseGate sync.Once
	releaseStop := func() { releaseGate.Do(func() { close(stopGate) }) }
	defer releaseStop()
	process := &controlledStopProcess{stopEntered: make(chan struct{}), stopGate: stopGate}
	manager := mustManager(t, &controlledStopLauncher{process: process}, Limits{
		MaximumSessions: 1, MemoryLimitBytes: 1_000,
		AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour,
	})
	request := dedicatedRequest(t, "repeat-release", time.Unix(2_000_001_452, 0).UTC())
	mustAcquire(t, manager, request)
	releaseRequest := ReleaseRequest{SessionID: request.SessionID, PlacementGeneration: request.PlacementGeneration}

	firstCtx, cancelFirst := context.WithCancel(context.Background())
	firstResult := make(chan error, 1)
	go func() { firstResult <- manager.Release(firstCtx, releaseRequest) }()
	<-process.stopEntered
	cancelFirst()
	if err := receiveError(t, firstResult); !errors.Is(err, context.Canceled) {
		t.Fatalf("first Release() error = %v, want context.Canceled", err)
	}

	secondResult := make(chan error, 1)
	go func() { secondResult <- manager.Release(context.Background(), releaseRequest) }()
	select {
	case err := <-secondResult:
		t.Fatalf("second Release() returned before shared cleanup completed: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	releaseStop()
	if err := receiveError(t, secondResult); err != nil {
		t.Fatalf("second Release() error = %v", err)
	}
	if calls := process.stopCalls(); calls != 1 {
		t.Fatalf("Stop() calls = %d, want one shared cleanup epoch", calls)
	}
}

func TestManagerCanceledReleaseWaiterDoesNotSplitAnInflightEpoch(t *testing.T) {
	stopGate := make(chan struct{})
	process := &controlledStopProcess{
		failures: 1, stopEntered: make(chan struct{}), stopGate: stopGate,
	}
	manager := mustManager(t, &controlledStopLauncher{process: process}, Limits{
		MaximumSessions: 1, MemoryLimitBytes: 1_000,
		AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour,
	})
	request := dedicatedRequest(t, "cancel-inflight-epoch", time.Unix(2_000_001_453, 0).UTC())
	mustAcquire(t, manager, request)
	release := ReleaseRequest{SessionID: request.SessionID, PlacementGeneration: request.PlacementGeneration}

	firstResult := make(chan error, 1)
	go func() { firstResult <- manager.Release(context.Background(), release) }()
	<-process.stopEntered
	secondContext, cancelSecond := newObservedDoneContext()
	secondResult := make(chan error, 1)
	go func() { secondResult <- manager.Release(secondContext, release) }()
	<-secondContext.observed
	cancelSecond()
	if err := receiveError(t, secondResult); !errors.Is(err, context.Canceled) {
		t.Fatalf("Release(canceled waiter) error = %v, want context.Canceled", err)
	}
	if calls := process.stopCalls(); calls != 1 {
		t.Fatalf("Stop() calls while epoch 1 is in flight = %d, want 1", calls)
	}

	close(stopGate)
	if err := receiveError(t, firstResult); !errors.Is(err, errControlledStop) {
		t.Fatalf("Release(epoch 1 owner) error = %v, want controlled failure", err)
	}
	if err := manager.Release(context.Background(), release); err != nil {
		t.Fatalf("Release(epoch 2) error = %v", err)
	}
	if calls := process.stopCalls(); calls != 2 {
		t.Fatalf("Stop() calls after epoch 2 = %d, want 2", calls)
	}
}

func TestManagerConcurrentLateReleaseCallersShareOneFreshRetryEpoch(t *testing.T) {
	retryGate := make(chan struct{})
	process := &controlledStopProcess{
		failures:        1,
		stopCallEntered: make(chan int, 2),
		stopCallGates:   map[int]<-chan struct{}{2: retryGate},
	}
	manager := mustManager(t, &controlledStopLauncher{process: process}, Limits{
		MaximumSessions: 1, MemoryLimitBytes: 1_000,
		AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour,
	})
	request := dedicatedRequest(t, "concurrent-late-retry", time.Unix(2_000_001_453, 0).UTC())
	mustAcquire(t, manager, request)
	release := ReleaseRequest{SessionID: request.SessionID, PlacementGeneration: request.PlacementGeneration}
	if err := manager.Release(context.Background(), release); !errors.Is(err, errControlledStop) {
		t.Fatalf("Release(epoch 1) error = %v, want controlled failure", err)
	}
	if call := <-process.stopCallEntered; call != 1 {
		t.Fatalf("entered Stop call = %d, want epoch 1", call)
	}
	manager.mu.Lock()
	cleanup := manager.releaseCleanups[request.SessionID]
	oldPending := manager.pendingStops[cleanup.key]
	manager.mu.Unlock()
	if oldPending == nil {
		t.Fatal("completed retryable epoch was not retained")
	}

	firstResult := make(chan error, 1)
	go func() { firstResult <- manager.Release(context.Background(), release) }()
	if call := <-process.stopCallEntered; call != 2 {
		t.Fatalf("entered Stop call = %d, want epoch 2", call)
	}
	secondContext, cancelSecond := newObservedDoneContext()
	defer cancelSecond()
	secondResult := make(chan error, 1)
	go func() { secondResult <- manager.Release(secondContext, release) }()
	<-secondContext.observed

	manager.mu.Lock()
	newPending := manager.pendingStops[cleanup.key]
	oldErr := oldPending.err
	manager.mu.Unlock()
	if newPending == nil || newPending == oldPending {
		t.Fatalf("retry pending = %p, old = %p; want a fresh immutable epoch", newPending, oldPending)
	}
	if !errors.Is(oldErr, errControlledStop) {
		t.Fatalf("old immutable epoch error = %v, want controlled failure", oldErr)
	}
	if calls := process.stopCalls(); calls != 2 {
		t.Fatalf("Stop() calls with two epoch 2 waiters = %d, want 2", calls)
	}

	close(retryGate)
	if err := receiveError(t, firstResult); err != nil {
		t.Fatalf("Release(first epoch 2 waiter) error = %v", err)
	}
	if err := receiveError(t, secondResult); err != nil {
		t.Fatalf("Release(second epoch 2 waiter) error = %v", err)
	}
	if calls := process.stopCalls(); calls != 2 {
		t.Fatalf("Stop() calls after shared epoch 2 = %d, want 2", calls)
	}
}

func TestManagerTerminalCleanupIsReplayedWithoutAnotherStopEpoch(t *testing.T) {
	terminalErr := errors.Join(errControlledStop, fmt.Errorf("wrapped terminal marker: %w", ErrTerminalShardCleanup))
	process := &controlledStopProcess{failures: 10, failureErr: terminalErr}
	launcher := &controlledStopLauncher{process: process}
	manager := mustManager(t, launcher, Limits{
		MaximumSessions: 1, MemoryLimitBytes: 1_000,
		AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour,
	})
	request := dedicatedRequest(t, "terminal-cleanup", time.Unix(2_000_001_454, 0).UTC())
	mustAcquire(t, manager, request)
	release := ReleaseRequest{SessionID: request.SessionID, PlacementGeneration: request.PlacementGeneration}

	if err := manager.Release(context.Background(), release); !errors.Is(err, ErrTerminalShardCleanup) || !errors.Is(err, errControlledStop) {
		t.Fatalf("Release(terminal attempt 1) error = %v", err)
	}
	manager.mu.Lock()
	cleanup := manager.releaseCleanups[request.SessionID]
	terminalPending := manager.pendingStops[cleanup.key]
	manager.mu.Unlock()
	if terminalPending == nil {
		t.Fatal("terminal cleanup epoch was not retained")
	}
	for attempt := 1; attempt < 2; attempt++ {
		err := manager.Release(context.Background(), release)
		if !errors.Is(err, ErrTerminalShardCleanup) || !errors.Is(err, errControlledStop) {
			t.Fatalf("Release(terminal attempt %d) error = %v", attempt+1, err)
		}
	}
	request.PlacementGeneration++
	if placement, err := manager.Acquire(context.Background(), request); placement != (Placement{}) || !errors.Is(err, ErrTerminalShardCleanup) {
		t.Fatalf("Acquire(terminal prior cleanup) = %#v, %v", placement, err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := manager.Shutdown(context.Background()); !errors.Is(err, ErrTerminalShardCleanup) {
			t.Fatalf("Shutdown(terminal attempt %d) error = %v", attempt+1, err)
		}
	}
	if calls := process.stopCalls(); calls != 1 {
		t.Fatalf("Stop() calls for terminal cleanup = %d, want 1", calls)
	}
	if starts, _ := launcher.launchState(); starts != 1 {
		t.Fatalf("launcher starts = %d, want no replacement behind terminal cleanup", starts)
	}
	manager.mu.Lock()
	cachedPending := manager.pendingStops[cleanup.key]
	cachedErr := terminalPending.err
	manager.mu.Unlock()
	if cachedPending != terminalPending || !errors.Is(cachedErr, ErrTerminalShardCleanup) {
		t.Fatalf("cached terminal epoch = %p/%p, error %v; want immutable replay", cachedPending, terminalPending, cachedErr)
	}
}

func TestManagerClassifiesTerminalCleanupOutsideItsMutex(t *testing.T) {
	process := &controlledStopProcess{failures: 10}
	manager := mustManager(t, &controlledStopLauncher{process: process}, Limits{
		MaximumSessions: 1, MemoryLimitBytes: 1_000,
		AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour,
	})
	terminalErr := &mutexObservingTerminalError{manager: manager, result: make(chan bool, 1)}
	process.failureErr = terminalErr
	request := dedicatedRequest(t, "terminal-classification-lock", time.Unix(2_000_001_454, 0).UTC())
	mustAcquire(t, manager, request)
	release := ReleaseRequest{SessionID: request.SessionID, PlacementGeneration: request.PlacementGeneration}
	if err := manager.Release(context.Background(), release); err == nil {
		t.Fatal("Release(epoch 1) error = nil, want terminal failure")
	}
	secondErr := manager.Release(context.Background(), release)
	if managerLockHeld := <-terminalErr.result; managerLockHeld {
		t.Fatal("terminal error classification called Is while manager.mu was held")
	}
	if !errors.Is(secondErr, ErrTerminalShardCleanup) {
		t.Fatalf("Release(replay terminal) error = %v, want terminal marker", secondErr)
	}
	if calls := process.stopCalls(); calls != 1 {
		t.Fatalf("Stop() calls = %d, want one terminal epoch", calls)
	}
}

func TestManagerShutdownCancellationOnlyCancelsWaitForSameStopEpoch(t *testing.T) {
	stopGate := make(chan struct{})
	var releaseGate sync.Once
	releaseStop := func() { releaseGate.Do(func() { close(stopGate) }) }
	defer releaseStop()
	process := &controlledStopProcess{stopEntered: make(chan struct{}), stopGate: stopGate}
	manager := mustManager(t, &controlledStopLauncher{process: process}, Limits{
		MaximumSessions: 1, MemoryLimitBytes: 1_000,
		AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour,
	})
	mustAcquire(t, manager, dedicatedRequest(t, "shutdown-cancel", time.Unix(2_000_001_455, 0).UTC()))

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelShutdown()
	if err := manager.Shutdown(shutdownCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown(timeout) error = %v, want context deadline", err)
	}
	if calls := process.stopCalls(); calls != 1 {
		t.Fatalf("Stop() calls after timeout = %d, want one", calls)
	}

	shutdownResult := make(chan error, 1)
	go func() { shutdownResult <- manager.Shutdown(context.Background()) }()
	select {
	case err := <-shutdownResult:
		t.Fatalf("Shutdown(retry) returned before existing Stop completed: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	releaseStop()
	if err := receiveError(t, shutdownResult); err != nil {
		t.Fatalf("Shutdown(retry) error = %v", err)
	}
	if calls := process.stopCalls(); calls != 1 {
		t.Fatalf("Stop() calls = %d, want the original manager-owned epoch", calls)
	}
}

func TestManagerShutdownStartsIndependentShardStopsBeforeWaiting(t *testing.T) {
	launcher := newParallelStopLauncher()
	defer launcher.releaseStops()
	manager := mustManager(t, launcher, Limits{
		MaximumSessions: 1, MemoryLimitBytes: 1_000,
		AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour,
	})
	now := time.Unix(2_000_001_460, 0).UTC()
	for index, seed := range []string{"parallel-a", "parallel-b", "parallel-c"} {
		mustAcquire(t, manager, baseRequest(t, "tenant-"+seed, "session-"+seed, 1, now.Add(time.Duration(index)*time.Second)))
	}

	shutdownResult := make(chan error, 1)
	go func() { shutdownResult <- manager.Shutdown(context.Background()) }()
	seen := make(map[string]struct{}, 3)
	for len(seen) < 3 {
		select {
		case shardID := <-launcher.entered:
			seen[shardID] = struct{}{}
		case <-time.After(100 * time.Millisecond):
			t.Fatalf("Stop callbacks entered for %d shards, want all three before releasing any", len(seen))
		}
	}
	launcher.releaseStops()
	if err := receiveError(t, shutdownResult); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
}

func TestManagerShutdownRetriesOnlyRetryableEpochsBeforeDeterministicJoin(t *testing.T) {
	firstRetryGate := make(chan struct{})
	secondRetryGate := make(chan struct{})
	terminal := &controlledStopProcess{
		failures: 10,
		failureErr: errors.Join(
			errControlledStop,
			fmt.Errorf("terminal cleanup: %w", ErrTerminalShardCleanup),
		),
	}
	firstRetryable := &controlledStopProcess{
		failures:        1,
		stopCallEntered: make(chan int, 2),
		stopCallGates:   map[int]<-chan struct{}{2: firstRetryGate},
	}
	secondRetryable := &controlledStopProcess{
		failures:        1,
		stopCallEntered: make(chan int, 2),
		stopCallGates:   map[int]<-chan struct{}{2: secondRetryGate},
	}
	launcher := &controlledStopSequenceLauncher{processes: []*controlledStopProcess{terminal, firstRetryable, secondRetryable}}
	manager := mustManager(t, launcher, Limits{
		MaximumSessions: 1, MemoryLimitBytes: 1_000,
		AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour,
	})
	now := time.Unix(2_000_001_462, 0).UTC()
	terminalRequest := dedicatedRequest(t, "mixed-terminal", now)
	firstRetryableRequest := dedicatedRequest(t, "mixed-retryable-a", now.Add(time.Second))
	secondRetryableRequest := dedicatedRequest(t, "mixed-retryable-b", now.Add(2*time.Second))
	mustAcquire(t, manager, terminalRequest)
	mustAcquire(t, manager, firstRetryableRequest)
	mustAcquire(t, manager, secondRetryableRequest)

	if err := manager.Release(context.Background(), ReleaseRequest{SessionID: terminalRequest.SessionID, PlacementGeneration: terminalRequest.PlacementGeneration}); !errors.Is(err, ErrTerminalShardCleanup) {
		t.Fatalf("Release(terminal) error = %v", err)
	}
	if err := manager.Release(context.Background(), ReleaseRequest{SessionID: firstRetryableRequest.SessionID, PlacementGeneration: firstRetryableRequest.PlacementGeneration}); !errors.Is(err, errControlledStop) {
		t.Fatalf("Release(first retryable) error = %v", err)
	}
	if err := manager.Release(context.Background(), ReleaseRequest{SessionID: secondRetryableRequest.SessionID, PlacementGeneration: secondRetryableRequest.PlacementGeneration}); !errors.Is(err, errControlledStop) {
		t.Fatalf("Release(second retryable) error = %v", err)
	}
	if call := <-firstRetryable.stopCallEntered; call != 1 {
		t.Fatalf("first retryable entered call = %d, want epoch 1", call)
	}
	if call := <-secondRetryable.stopCallEntered; call != 1 {
		t.Fatalf("second retryable entered call = %d, want epoch 1", call)
	}

	shutdownResult := make(chan error, 1)
	go func() { shutdownResult <- manager.Shutdown(context.Background()) }()
	if call := <-firstRetryable.stopCallEntered; call != 2 {
		t.Fatalf("first retryable entered call = %d, want epoch 2", call)
	}
	if call := <-secondRetryable.stopCallEntered; call != 2 {
		t.Fatalf("second retryable entered call = %d, want epoch 2", call)
	}
	if terminalCalls := terminal.stopCalls(); terminalCalls != 1 {
		t.Fatalf("terminal Stop() calls before retry join = %d, want 1", terminalCalls)
	}
	close(firstRetryGate)
	close(secondRetryGate)
	if err := receiveError(t, shutdownResult); !errors.Is(err, ErrTerminalShardCleanup) {
		t.Fatalf("Shutdown(mixed cleanup) error = %v, want terminal marker", err)
	}
	if firstCalls, secondCalls := firstRetryable.stopCalls(), secondRetryable.stopCalls(); firstCalls != 2 || secondCalls != 2 {
		t.Fatalf("retryable Stop() calls = %d/%d, want 2/2", firstCalls, secondCalls)
	}
	if err := manager.Shutdown(context.Background()); !errors.Is(err, ErrTerminalShardCleanup) {
		t.Fatalf("Shutdown(replay terminal cleanup) error = %v", err)
	}
	if terminalCalls, firstCalls, secondCalls := terminal.stopCalls(), firstRetryable.stopCalls(), secondRetryable.stopCalls(); terminalCalls != 1 || firstCalls != 2 || secondCalls != 2 {
		t.Fatalf("replayed Shutdown Stop() calls = terminal %d, retryable %d/%d; want 1,2/2", terminalCalls, firstCalls, secondCalls)
	}
}

func TestManagerShutdownJoinsParallelStopErrorsInShardGenerationOrder(t *testing.T) {
	launcher := newParallelStopLauncher()
	launcher.failStops = true
	defer launcher.releaseStops()
	manager := mustManager(t, launcher, Limits{
		MaximumSessions: 1, MemoryLimitBytes: 1_000,
		AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour,
	})
	now := time.Unix(2_000_001_465, 0).UTC()
	shardIDs := make([]string, 0, 3)
	for index, seed := range []string{"ordered-a", "ordered-b", "ordered-c"} {
		placement := mustAcquire(t, manager, baseRequest(t, "tenant-"+seed, "session-"+seed, 1, now.Add(time.Duration(index)*time.Second)))
		shardIDs = append(shardIDs, placement.ShardID)
	}

	shutdownResult := make(chan error, 1)
	go func() { shutdownResult <- manager.Shutdown(context.Background()) }()
	for range shardIDs {
		select {
		case <-launcher.entered:
		case <-time.After(3 * time.Second):
			t.Fatal("not every Stop callback entered")
		}
	}
	launcher.releaseStops()
	err := receiveError(t, shutdownResult)
	if err == nil {
		t.Fatal("Shutdown() error = nil, want joined stop errors")
	}
	sort.Strings(shardIDs)
	message := err.Error()
	previous := -1
	for _, shardID := range shardIDs {
		index := strings.Index(message, shardID)
		if index <= previous {
			t.Fatalf("Shutdown() error order = %q, want shard order %#v", message, shardIDs)
		}
		previous = index
	}
}

func TestManagerReplacementRetriesPriorUncertainShardGenerationCleanup(t *testing.T) {
	process := &controlledStopProcess{failures: 1}
	launcher := &controlledStopLauncher{process: process}
	manager := mustManager(t, launcher, Limits{
		MaximumSessions: 1, MemoryLimitBytes: 1_000,
		AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour,
	})
	request := dedicatedRequest(t, "generation-fence", time.Unix(2_000_001_470, 0).UTC())
	first := mustAcquire(t, manager, request)
	_, specs := launcher.launchState()
	if len(specs) != 1 {
		t.Fatalf("launch specs = %#v, want one", specs)
	}

	request.PlacementGeneration++
	if placement, err := manager.Acquire(context.Background(), request); !errors.Is(err, errControlledStop) || placement != (Placement{}) {
		t.Fatalf("replacement Acquire() = %#v, %v; want uncertain stop error", placement, err)
	}
	key := shardProcessKeyFor(specs[0])
	manager.mu.Lock()
	pending := manager.pendingStops[key]
	pendingCount := len(manager.pendingStops)
	manager.mu.Unlock()
	if pending == nil || pendingCount != 1 || key.shardID != first.ShardID || key.shardGeneration != specs[0].ShardGeneration {
		t.Fatalf("pending stop key = %#v, count=%d, spec=%#v", key, pendingCount, specs[0])
	}

	second, err := manager.Acquire(context.Background(), request)
	if err != nil {
		t.Fatalf("Acquire(retry prior cleanup) error = %v", err)
	}
	if second.ShardID == "" {
		t.Fatal("Acquire(retry prior cleanup) returned an empty placement")
	}
	if starts, _ := launcher.launchState(); starts != 2 {
		t.Fatalf("launcher starts = %d, want replacement after cleanup retry", starts)
	}
	if calls := process.stopCalls(); calls != 2 {
		t.Fatalf("Stop() calls = %d, want failed cleanup plus Acquire retry", calls)
	}
	if err := manager.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
}

func TestManagerShutdownRetriesAbandonedLaunchCleanupFailure(t *testing.T) {
	process := &controlledStopProcess{failures: 1}
	launcher := newAbandonedLaunchLauncher(process)
	defer launcher.releaseStart()
	manager := mustManager(t, launcher, Limits{
		MaximumSessions: 1, MemoryLimitBytes: 1_000,
		AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour,
	})
	request := dedicatedRequest(t, "abandoned-cleanup", time.Unix(2_000_001_480, 0).UTC())
	acquireCtx, cancelAcquire := context.WithCancel(context.Background())
	acquireResult := make(chan error, 1)
	go func() {
		_, err := manager.Acquire(acquireCtx, request)
		acquireResult <- err
	}()
	select {
	case <-launcher.startEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("launch did not start")
	}
	cancelAcquire()
	if err := receiveError(t, acquireResult); !errors.Is(err, context.Canceled) {
		t.Fatalf("Acquire() error = %v, want context.Canceled", err)
	}

	shutdownResult := make(chan error, 1)
	go func() { shutdownResult <- manager.Shutdown(context.Background()) }()
	waitForManagerClosed(t, manager)
	launcher.releaseStart()
	if err := receiveError(t, shutdownResult); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	if calls := process.stopCalls(); calls != 2 {
		t.Fatalf("Stop() calls = %d, want failed abandoned cleanup plus shutdown retry", calls)
	}
}

func dedicatedRequest(t *testing.T, seed string, now time.Time) PlacementRequest {
	t.Helper()
	request := baseRequest(t, "tenant-"+seed, "session-"+seed, 1, now)
	request.TrustClass = TrustUnreviewed
	request.Profile = PlacementProfile{ProcessScope: ScopeSession, OuterIsolation: IsolationFirecracker}
	return request
}

func registerUnadoptedLaunch(t *testing.T, manager *Manager, request PlacementRequest) *launchPending {
	t.Helper()
	workerID, err := WorkerIdentity(request.SessionID, request.Runtime)
	if err != nil {
		t.Fatalf("WorkerIdentity() error = %v", err)
	}
	scopeKey := string(request.Profile.ProcessScope) + "/" + string(request.Profile.OuterIsolation)
	switch request.Profile.ProcessScope {
	case ScopeTenant:
		scopeKey += "/" + request.TenantID.String()
	case ScopeSession:
		scopeKey += "/" + request.SessionID.String()
	}
	launchCtx, cancelLaunch := context.WithCancel(context.Background())
	pending := &launchPending{
		ctx: launchCtx, cancel: cancelLaunch, done: make(chan struct{}),
		spec: ShardSpec{
			AgentInstanceID: manager.agentInstanceID,
			ShardID:         "agent-shard-00000000000000000001",
			ShardGeneration: 1,
			ScopeKey:        scopeKey,
			Profile:         request.Profile,
			Limits:          manager.limits,
			CreatedAt:       request.Now,
		},
		sessions: map[identity.ID]struct{}{request.SessionID: {}},
		waiters:  1,
	}
	manager.mu.Lock()
	manager.latestGenerations[request.SessionID] = request.PlacementGeneration
	manager.requestIdentities[request.SessionID] = requestIdentity{
		tenantID: request.TenantID, workerID: workerID, profile: request.Profile,
		estimatedMemoryBytes: request.EstimatedMemoryBytes,
	}
	manager.pendingScopes[scopeKey] = pending
	manager.pendingSessions[request.SessionID] = pending
	manager.mu.Unlock()
	return pending
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
