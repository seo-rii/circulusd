package agent

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/identity"
)

var errControlledStop = errors.New("test: controlled stop failure")

type controlledStopLauncher struct {
	mu      sync.Mutex
	process *controlledStopProcess
	starts  int
	specs   []ShardSpec
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
	stopEntered     chan struct{}
	stopGate        <-chan struct{}
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

func TestManagerReplacementWaitsForPriorUncertainShardGenerationCleanup(t *testing.T) {
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

	if placement, err := manager.Acquire(context.Background(), request); !errors.Is(err, errControlledStop) || placement != (Placement{}) {
		t.Fatalf("Acquire(behind uncertain stop) = %#v, %v; want same stop fence", placement, err)
	}
	if starts, _ := launcher.launchState(); starts != 1 {
		t.Fatalf("launcher starts = %d, want no replacement before cleanup confirmation", starts)
	}
	if err := manager.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown(retry cleanup) error = %v", err)
	}
	if calls := process.stopCalls(); calls != 2 {
		t.Fatalf("Stop() calls = %d, want failure plus shutdown retry", calls)
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
