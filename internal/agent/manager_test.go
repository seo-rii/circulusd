package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/identity"
)

var errLaunch = errors.New("test: launch failed")

type fakeLauncher struct {
	mu         sync.Mutex
	starts     int
	specs      []ShardSpec
	stops      []string
	failNext   bool
	startGate  chan struct{}
	returnedID string
}

func (launcher *fakeLauncher) Start(ctx context.Context, spec ShardSpec) (ShardProcess, error) {
	launcher.mu.Lock()
	launcher.starts++
	launcher.specs = append(launcher.specs, spec)
	fail := launcher.failNext
	launcher.failNext = false
	gate := launcher.startGate
	id := spec.ShardID
	if launcher.returnedID != "" {
		id = launcher.returnedID
	}
	launcher.mu.Unlock()
	if gate != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-gate:
		}
	}
	if fail {
		return nil, errLaunch
	}
	return &fakeProcess{id: id, launcher: launcher}, nil
}

func (launcher *fakeLauncher) counts() (int, []string) {
	launcher.mu.Lock()
	defer launcher.mu.Unlock()
	return launcher.starts, append([]string(nil), launcher.stops...)
}

func (launcher *fakeLauncher) launchSpecs() []ShardSpec {
	launcher.mu.Lock()
	defer launcher.mu.Unlock()
	return append([]ShardSpec(nil), launcher.specs...)
}

type fakeProcess struct {
	id       string
	launcher *fakeLauncher
	once     sync.Once
}

func (process *fakeProcess) ID() string { return process.id }

func (process *fakeProcess) Stop(context.Context) error {
	process.once.Do(func() {
		process.launcher.mu.Lock()
		process.launcher.stops = append(process.launcher.stops, process.id)
		process.launcher.mu.Unlock()
	})
	return nil
}

type delayedCancellationLauncher struct {
	mu              sync.Mutex
	specs           []ShardSpec
	contextCanceled chan struct{}
	returnGate      chan struct{}
	releaseOnce     sync.Once
}

type retryAfterCancellationLauncher struct {
	mu      sync.Mutex
	starts  int
	started chan ShardSpec
}

func (launcher *retryAfterCancellationLauncher) Start(ctx context.Context, spec ShardSpec) (ShardProcess, error) {
	launcher.mu.Lock()
	launcher.starts++
	call := launcher.starts
	launcher.mu.Unlock()
	launcher.started <- spec
	if call == 1 {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return &fakeProcess{id: spec.ShardID, launcher: &fakeLauncher{}}, nil
}

func newDelayedCancellationLauncher() *delayedCancellationLauncher {
	return &delayedCancellationLauncher{
		contextCanceled: make(chan struct{}),
		returnGate:      make(chan struct{}),
	}
}

func (launcher *delayedCancellationLauncher) Start(ctx context.Context, spec ShardSpec) (ShardProcess, error) {
	launcher.mu.Lock()
	launcher.specs = append(launcher.specs, spec)
	call := len(launcher.specs)
	launcher.mu.Unlock()
	if call == 1 {
		<-ctx.Done()
		close(launcher.contextCanceled)
		<-launcher.returnGate
		return nil, ctx.Err()
	}
	return &fakeProcess{id: spec.ShardID, launcher: &fakeLauncher{}}, nil
}

func (launcher *delayedCancellationLauncher) releaseFirstStart() {
	launcher.releaseOnce.Do(func() { close(launcher.returnGate) })
}

func (launcher *delayedCancellationLauncher) launchSpecs() []ShardSpec {
	launcher.mu.Lock()
	defer launcher.mu.Unlock()
	return append([]ShardSpec(nil), launcher.specs...)
}

type blockingIDLauncher struct {
	idEntered   chan struct{}
	idGate      chan struct{}
	releaseOnce sync.Once
}

func newBlockingIDLauncher() *blockingIDLauncher {
	return &blockingIDLauncher{idEntered: make(chan struct{}), idGate: make(chan struct{})}
}

func (launcher *blockingIDLauncher) Start(_ context.Context, spec ShardSpec) (ShardProcess, error) {
	return &blockingIDProcess{id: spec.ShardID, launcher: launcher}, nil
}

func (launcher *blockingIDLauncher) releaseID() {
	launcher.releaseOnce.Do(func() { close(launcher.idGate) })
}

type blockingIDProcess struct {
	id       string
	launcher *blockingIDLauncher
}

func (process *blockingIDProcess) ID() string {
	close(process.launcher.idEntered)
	<-process.launcher.idGate
	return process.id
}

func (*blockingIDProcess) Stop(context.Context) error { return nil }

type typedNilLauncher struct{}

func (typedNilLauncher) Start(context.Context, ShardSpec) (ShardProcess, error) {
	var process *typedNilProcess
	return process, nil
}

type typedNilProcess struct{}

func (*typedNilProcess) ID() string { panic("typed-nil process ID callback") }

func (*typedNilProcess) Stop(context.Context) error { panic("typed-nil process Stop callback") }

func TestValidateProfileEnforcesTrustClassMinimums(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		trust   TrustClass
		profile PlacementProfile
		wantErr bool
	}{
		{name: "reviewed shared", trust: TrustPlatformReviewed, profile: PlacementProfile{ProcessScope: ScopeShared, OuterIsolation: IsolationNone}},
		{name: "tenant reviewed rejects shared", trust: TrustTenantReviewed, profile: PlacementProfile{ProcessScope: ScopeShared, OuterIsolation: IsolationNone}, wantErr: true},
		{name: "tenant reviewed tenant", trust: TrustTenantReviewed, profile: PlacementProfile{ProcessScope: ScopeTenant, OuterIsolation: IsolationNone}},
		{name: "signed rejects none", trust: TrustSignedThirdParty, profile: PlacementProfile{ProcessScope: ScopeTenant, OuterIsolation: IsolationNone}, wantErr: true},
		{name: "signed nsjail", trust: TrustSignedThirdParty, profile: PlacementProfile{ProcessScope: ScopeTenant, OuterIsolation: IsolationNSJail}},
		{name: "signed docker", trust: TrustSignedThirdParty, profile: PlacementProfile{ProcessScope: ScopeTenant, OuterIsolation: IsolationDocker}},
		{name: "unreviewed rejects shared kernel", trust: TrustUnreviewed, profile: PlacementProfile{ProcessScope: ScopeSession, OuterIsolation: IsolationDocker}, wantErr: true},
		{name: "unreviewed firecracker", trust: TrustUnreviewed, profile: PlacementProfile{ProcessScope: ScopeSession, OuterIsolation: IsolationFirecracker}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateProfile(test.trust, test.profile)
			if test.wantErr && !errors.Is(err, ErrIsolationDowngrade) {
				t.Fatalf("ValidateProfile() error = %v, want ErrIsolationDowngrade", err)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("ValidateProfile() error = %v", err)
			}
		})
	}
}

func TestWorkerIdentityIsContentAddressedAndCanonical(t *testing.T) {
	t.Parallel()
	session := mustID(t, identity.Session, "worker-session")
	left, err := WorkerIdentity(session, RuntimeIdentity{
		RuntimeRevisionDigest: digest("a"), PiAdapterABI: 3,
		CompatibilityDate: "2026-08-26", CompatibilityFlags: []string{"nodejs_compat", "streams_enable_constructors"},
	})
	if err != nil {
		t.Fatalf("WorkerIdentity(left) error = %v", err)
	}
	right, err := WorkerIdentity(session, RuntimeIdentity{
		RuntimeRevisionDigest: digest("a"), PiAdapterABI: 3,
		CompatibilityDate: "2026-08-26", CompatibilityFlags: []string{"streams_enable_constructors", "nodejs_compat"},
	})
	if err != nil {
		t.Fatalf("WorkerIdentity(right) error = %v", err)
	}
	if left != right {
		t.Fatalf("canonical identities differ: %q != %q", left, right)
	}
	changed, err := WorkerIdentity(session, RuntimeIdentity{
		RuntimeRevisionDigest: digest("b"), PiAdapterABI: 3,
		CompatibilityDate: "2026-08-26", CompatibilityFlags: []string{"nodejs_compat", "streams_enable_constructors"},
	})
	if err != nil {
		t.Fatalf("WorkerIdentity(changed) error = %v", err)
	}
	if changed == left {
		t.Fatal("runtime revision change did not rotate worker identity")
	}
}

func TestWorkerIdentityMatchesTypeScriptGoldenVectors(t *testing.T) {
	t.Parallel()

	encoded, err := os.ReadFile("../../packages/protocol-types/fixtures/runtime-identity-v1.json")
	if err != nil {
		t.Fatalf("ReadFile(runtime identity golden) error = %v", err)
	}
	var fixture struct {
		Vectors []struct {
			Name                  string   `json:"name"`
			SessionID             string   `json:"sessionId"`
			RuntimeRevisionDigest string   `json:"runtimeRevisionDigest"`
			PiAdapterABI          uint64   `json:"piAdapterAbi"`
			CompatibilityDate     string   `json:"compatibilityDate"`
			CompatibilityFlags    []string `json:"compatibilityFlags"`
			RuntimeIdentityDigest string   `json:"runtimeIdentityDigest"`
			WorkerID              string   `json:"workerId"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(encoded, &fixture); err != nil {
		t.Fatalf("Unmarshal(runtime identity golden) error = %v", err)
	}
	for _, vector := range fixture.Vectors {
		vector := vector
		t.Run(vector.Name, func(t *testing.T) {
			t.Parallel()
			sessionID, err := identity.Parse(identity.Session, vector.SessionID)
			if err != nil {
				t.Fatalf("Parse(session ID) error = %v", err)
			}
			workerID, err := WorkerIdentity(sessionID, RuntimeIdentity{
				RuntimeRevisionDigest: vector.RuntimeRevisionDigest,
				PiAdapterABI:          vector.PiAdapterABI,
				CompatibilityDate:     vector.CompatibilityDate,
				CompatibilityFlags:    vector.CompatibilityFlags,
			})
			if err != nil {
				t.Fatalf("WorkerIdentity() error = %v", err)
			}
			if workerID != vector.WorkerID {
				t.Fatalf("WorkerIdentity() = %q, want %q", workerID, vector.WorkerID)
			}
			if strings.TrimPrefix(workerID, "pi/"+vector.SessionID+"/sha256-") != strings.TrimPrefix(vector.RuntimeIdentityDigest, "sha256:") {
				t.Fatalf("WorkerIdentity() digest does not match %q", vector.RuntimeIdentityDigest)
			}
		})
	}
}

func TestManagerReusesOnlyCompatibleShardScopesAndHonorsCapacity(t *testing.T) {
	t.Parallel()
	launcher := &fakeLauncher{}
	manager := mustManager(t, launcher, Limits{MaximumSessions: 2, MemoryLimitBytes: 1_000, AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour})
	now := time.Unix(2_000_000_000, 0).UTC()

	sharedA := baseRequest(t, "tenant-a", "session-a", 1, now)
	first := mustAcquire(t, manager, sharedA)
	sharedB := baseRequest(t, "tenant-b", "session-b", 1, now)
	second := mustAcquire(t, manager, sharedB)
	if first.ShardID != second.ShardID {
		t.Fatalf("shared placements used %q and %q", first.ShardID, second.ShardID)
	}
	third := mustAcquire(t, manager, baseRequest(t, "tenant-c", "session-c", 1, now))
	if third.ShardID == first.ShardID {
		t.Fatal("full shard admitted a third resident session")
	}

	tenantA := baseRequest(t, "tenant-a", "session-tenant-a", 1, now)
	tenantA.Profile.ProcessScope = ScopeTenant
	tenantA.TrustClass = TrustTenantReviewed
	tenantB := baseRequest(t, "tenant-b", "session-tenant-b", 1, now)
	tenantB.Profile.ProcessScope = ScopeTenant
	tenantB.TrustClass = TrustTenantReviewed
	if mustAcquire(t, manager, tenantA).ShardID == mustAcquire(t, manager, tenantB).ShardID {
		t.Fatal("tenant-scoped placements shared an OS process across tenants")
	}

	sessionA := baseRequest(t, "tenant-a", "session-dedicated-a", 1, now)
	sessionA.Profile = PlacementProfile{ProcessScope: ScopeSession, OuterIsolation: IsolationFirecracker}
	sessionA.TrustClass = TrustUnreviewed
	sessionB := baseRequest(t, "tenant-a", "session-dedicated-b", 1, now)
	sessionB.Profile = sessionA.Profile
	sessionB.TrustClass = sessionA.TrustClass
	if mustAcquire(t, manager, sessionA).ShardID == mustAcquire(t, manager, sessionB).ShardID {
		t.Fatal("session-scoped placements shared an OS process")
	}
}

func TestManagerRejectsPressureAndDrainsShardBeforeStopping(t *testing.T) {
	t.Parallel()
	launcher := &fakeLauncher{}
	manager := mustManager(t, launcher, Limits{MaximumSessions: 4, MemoryLimitBytes: 1_000, AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour})
	now := time.Unix(2_000_000_100, 0).UTC()
	firstRequest := baseRequest(t, "tenant-a", "session-a", 1, now)
	first := mustAcquire(t, manager, firstRequest)
	if err := manager.Observe(ShardObservation{ShardID: first.ShardID, RSSBytes: 750, HeapPressure: true, ObservedAt: now.Add(time.Second)}); err != nil {
		t.Fatalf("Observe() error = %v", err)
	}
	second := mustAcquire(t, manager, baseRequest(t, "tenant-b", "session-b", 1, now.Add(2*time.Second)))
	if second.ShardID == first.ShardID {
		t.Fatal("draining pressure shard accepted a new session")
	}
	_, stops := launcher.counts()
	if len(stops) != 0 {
		t.Fatalf("resident draining shard stopped early: %#v", stops)
	}
	if err := manager.Release(context.Background(), ReleaseRequest{SessionID: firstRequest.SessionID, PlacementGeneration: 1}); err != nil {
		t.Fatalf("Release() error = %v", err)
	}
	_, stops = launcher.counts()
	if len(stops) != 1 || stops[0] != first.ShardID {
		t.Fatalf("stopped shards = %#v, want %q", stops, first.ShardID)
	}
}

func TestManagerNeverAdmitsIntoAnExpiredLifetimeShard(t *testing.T) {
	t.Parallel()
	launcher := &fakeLauncher{}
	manager := mustManager(t, launcher, Limits{MaximumSessions: 4, MemoryLimitBytes: 1_000, AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Minute})
	now := time.Unix(2_000_000_150, 0).UTC()
	first := mustAcquire(t, manager, baseRequest(t, "tenant-a", "session-old", 1, now))
	second := mustAcquire(t, manager, baseRequest(t, "tenant-b", "session-new", 1, now.Add(time.Minute)))
	if second.ShardID == first.ShardID {
		t.Fatal("maximum-lifetime shard accepted a new resident session")
	}
	if snapshot := manager.Snapshot(); snapshot.DrainingShards != 1 {
		t.Fatalf("expired shard snapshot = %#v, want one draining shard", snapshot)
	}
}

func TestManagerFencesStalePlacementRelease(t *testing.T) {
	t.Parallel()
	launcher := &fakeLauncher{}
	manager := mustManager(t, launcher, Limits{MaximumSessions: 4, MemoryLimitBytes: 1_000, AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour})
	now := time.Unix(2_000_000_200, 0).UTC()
	request := baseRequest(t, "tenant-a", "session-a", 1, now)
	first := mustAcquire(t, manager, request)
	request.PlacementGeneration = 2
	replacement := mustAcquire(t, manager, request)
	if replacement.PlacementGeneration != 2 || replacement.Replayed {
		t.Fatalf("replacement = %#v", replacement)
	}
	if err := manager.Release(context.Background(), ReleaseRequest{SessionID: request.SessionID, PlacementGeneration: 1}); !errors.Is(err, ErrStalePlacement) {
		t.Fatalf("stale Release() error = %v, want ErrStalePlacement", err)
	}
	replayed := mustAcquire(t, manager, request)
	if !replayed.Replayed || replayed.ShardID != replacement.ShardID || replayed.WorkerID != replacement.WorkerID {
		t.Fatalf("current placement after stale release = %#v, first=%#v", replayed, first)
	}
}

func TestManagerGenerationReplacementAccountsOldReservationBeforeNewInputs(t *testing.T) {
	t.Parallel()
	launcher := &fakeLauncher{}
	manager := mustManager(t, launcher, Limits{MaximumSessions: 4, MemoryLimitBytes: 1_000, AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour})
	request := baseRequest(t, "tenant-a", "session-accounting", 1, time.Unix(2_000_000_250, 0).UTC())
	request.EstimatedMemoryBytes = 100
	first := mustAcquire(t, manager, request)
	request.PlacementGeneration = 2
	request.EstimatedMemoryBytes = 300
	replacement := mustAcquire(t, manager, request)
	if replacement.ShardID != first.ShardID {
		t.Fatalf("replacement shard = %q, want reusable %q", replacement.ShardID, first.ShardID)
	}
	if snapshot := manager.Snapshot(); snapshot.Shards != 1 || snapshot.ResidentSessions != 1 || snapshot.ResidentMemoryReservationBytes != 300 {
		t.Fatalf("replacement snapshot = %#v", snapshot)
	}
}

func TestManagerDoesNotResurrectAReleasedPlacementGeneration(t *testing.T) {
	t.Parallel()
	launcher := &fakeLauncher{}
	manager := mustManager(t, launcher, Limits{MaximumSessions: 4, MemoryLimitBytes: 1_000, AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour})
	request := baseRequest(t, "tenant-a", "session-released", 1, time.Unix(2_000_000_275, 0).UTC())
	mustAcquire(t, manager, request)
	if err := manager.Release(context.Background(), ReleaseRequest{SessionID: request.SessionID, PlacementGeneration: 1}); err != nil {
		t.Fatalf("Release() error = %v", err)
	}
	if placement, err := manager.Acquire(context.Background(), request); !errors.Is(err, ErrStalePlacement) || placement != (Placement{}) {
		t.Fatalf("released generation Acquire() = %#v, %v; want ErrStalePlacement", placement, err)
	}
	request.PlacementGeneration = 2
	if placement, err := manager.Acquire(context.Background(), request); err != nil || placement.PlacementGeneration != 2 {
		t.Fatalf("next generation Acquire() = %#v, %v", placement, err)
	}
}

func TestManagerConcurrentSameSessionStartsAndAdmitsExactlyOnce(t *testing.T) {
	t.Parallel()
	launcher := &fakeLauncher{startGate: make(chan struct{})}
	manager := mustManager(t, launcher, Limits{MaximumSessions: 8, MemoryLimitBytes: 1_000, AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour})
	request := baseRequest(t, "tenant-a", "session-a", 1, time.Unix(2_000_000_300, 0).UTC())
	const callers = 64
	results := make(chan Placement, callers)
	errorsSeen := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			placement, err := manager.Acquire(context.Background(), request)
			results <- placement
			errorsSeen <- err
		}()
	}
	close(launcher.startGate)
	wait.Wait()
	close(results)
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatalf("Acquire() error = %v", err)
		}
	}
	var workerID, shardID string
	fresh := 0
	for placement := range results {
		if !placement.Replayed {
			fresh++
		}
		if workerID == "" {
			workerID, shardID = placement.WorkerID, placement.ShardID
		} else if placement.WorkerID != workerID || placement.ShardID != shardID {
			t.Fatalf("concurrent placement = %#v, want worker=%q shard=%q", placement, workerID, shardID)
		}
	}
	starts, _ := launcher.counts()
	if fresh != 1 || starts != 1 || manager.Snapshot().ResidentSessions != 1 {
		t.Fatalf("fresh=%d starts=%d snapshot=%#v", fresh, starts, manager.Snapshot())
	}
}

func TestManagerSuccessfulLaunchStaysPendingUntilAtomicPlacementAdoption(t *testing.T) {
	launcher := &fakeLauncher{}
	manager := mustManager(t, launcher, Limits{MaximumSessions: 8, MemoryLimitBytes: 1_000, AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour})
	request := baseRequest(t, "pending-result-tenant", "pending-result-session", 1, time.Unix(2_000_000_340, 0).UTC())
	workerID, err := WorkerIdentity(request.SessionID, request.Runtime)
	if err != nil {
		t.Fatalf("WorkerIdentity() error = %v", err)
	}
	scopeKey := string(request.Profile.ProcessScope) + "/" + string(request.Profile.OuterIsolation)
	spec := ShardSpec{
		AgentInstanceID: manager.agentInstanceID,
		ShardID:         "agent-shard-00000000000000000001",
		ShardGeneration: 1,
		ScopeKey:        scopeKey,
		Profile:         request.Profile,
		Limits:          manager.limits,
		CreatedAt:       request.Now,
	}
	launchCtx, cancelLaunch := context.WithCancel(context.Background())
	defer cancelLaunch()
	pending := &launchPending{
		ctx: launchCtx, cancel: cancelLaunch, done: make(chan struct{}), spec: spec,
		sessions: map[identity.ID]struct{}{request.SessionID: {}}, waiters: 1,
	}
	fingerprint := requestIdentity{
		tenantID: request.TenantID, workerID: workerID, profile: request.Profile,
		estimatedMemoryBytes: request.EstimatedMemoryBytes,
	}
	manager.mu.Lock()
	manager.latestGenerations[request.SessionID] = request.PlacementGeneration
	manager.requestIdentities[request.SessionID] = fingerprint
	manager.pendingScopes[scopeKey] = pending
	manager.pendingSessions[request.SessionID] = pending
	manager.mu.Unlock()

	manager.runLaunch(pending)
	manager.mu.Lock()
	published := manager.shards[spec.ShardID] != nil
	stillPending := manager.pendingScopes[scopeKey] == pending && manager.pendingSessions[request.SessionID] == pending
	finished := pending.finished
	manager.mu.Unlock()
	if published || !stillPending || !finished {
		t.Fatalf("completed launch state = published:%t pending:%t finished:%t, want false/true/true", published, stillPending, finished)
	}
	if snapshot := manager.Snapshot(); snapshot != (ManagerSnapshot{}) {
		t.Fatalf("pre-adoption snapshot = %#v, want no live shard or session", snapshot)
	}

	claim := &launchClaim{
		request: request, workerID: workerID,
		fingerprint: fingerprint,
	}
	if err := manager.waitForLaunch(context.Background(), pending, claim); err != nil {
		t.Fatalf("waitForLaunch(adopt pending result) error = %v", err)
	}
	placement := claim.placement
	if placement.ShardID != spec.ShardID || placement.Replayed {
		t.Fatalf("adopted placement = %#v, want fresh placement on %q", placement, spec.ShardID)
	}
	if snapshot := manager.Snapshot(); snapshot.Shards != 1 || snapshot.ResidentSessions != 1 {
		t.Fatalf("post-adoption snapshot = %#v", snapshot)
	}
	if err := manager.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	starts, stops := launcher.counts()
	if starts != 1 || len(stops) != 1 || stops[0] != spec.ShardID {
		t.Fatalf("launch/stop ownership = %d/%#v, want one start and one stop", starts, stops)
	}
}

func TestManagerInitiatorCancellationDoesNotCancelAttachedSameSessionFollower(t *testing.T) {
	launcher := &fakeLauncher{startGate: make(chan struct{})}
	var releaseGate sync.Once
	releaseStart := func() { releaseGate.Do(func() { close(launcher.startGate) }) }
	defer releaseStart()
	manager := mustManager(t, launcher, Limits{MaximumSessions: 8, MemoryLimitBytes: 1_000, AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour})
	request := baseRequest(t, "shared-context-tenant", "shared-context-session", 1, time.Unix(2_000_000_350, 0).UTC())
	initiatorCtx, cancelInitiator := context.WithCancel(context.Background())
	defer cancelInitiator()
	initiatorResult := make(chan error, 1)
	go func() {
		_, err := manager.Acquire(initiatorCtx, request)
		initiatorResult <- err
	}()
	waitForLauncherStarts(t, launcher, 1)

	followerResult := make(chan error, 1)
	go func() {
		_, err := manager.Acquire(context.Background(), request)
		followerResult <- err
	}()
	waitForPendingLaunchWaiters(t, manager, request.SessionID, 2)
	cancelInitiator()
	if err := receiveError(t, initiatorResult); !errors.Is(err, context.Canceled) {
		t.Fatalf("initiator Acquire() error = %v, want context.Canceled", err)
	}
	releaseStart()
	if err := receiveError(t, followerResult); err != nil {
		t.Fatalf("follower Acquire() error = %v", err)
	}
	starts, _ := launcher.counts()
	if starts != 1 {
		t.Fatalf("launcher starts = %d, want one shared attempt", starts)
	}
}

func TestManagerInitiatorCancellationDoesNotCancelAttachedSameScopeFollower(t *testing.T) {
	launcher := &fakeLauncher{startGate: make(chan struct{})}
	var releaseGate sync.Once
	releaseStart := func() { releaseGate.Do(func() { close(launcher.startGate) }) }
	defer releaseStart()
	manager := mustManager(t, launcher, Limits{MaximumSessions: 8, MemoryLimitBytes: 1_000, AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour})
	now := time.Unix(2_000_000_360, 0).UTC()
	initiatorRequest := baseRequest(t, "shared-scope-tenant-a", "shared-scope-session-a", 1, now)
	followerRequest := baseRequest(t, "shared-scope-tenant-b", "shared-scope-session-b", 1, now)
	initiatorCtx, cancelInitiator := context.WithCancel(context.Background())
	defer cancelInitiator()
	initiatorResult := make(chan error, 1)
	go func() {
		_, err := manager.Acquire(initiatorCtx, initiatorRequest)
		initiatorResult <- err
	}()
	waitForLauncherStarts(t, launcher, 1)

	followerResult := make(chan error, 1)
	go func() {
		_, err := manager.Acquire(context.Background(), followerRequest)
		followerResult <- err
	}()
	waitForPendingLaunchWaiters(t, manager, followerRequest.SessionID, 2)
	cancelInitiator()
	if err := receiveError(t, initiatorResult); !errors.Is(err, context.Canceled) {
		t.Fatalf("initiator Acquire() error = %v, want context.Canceled", err)
	}
	releaseStart()
	if err := receiveError(t, followerResult); err != nil {
		t.Fatalf("same-scope follower Acquire() error = %v", err)
	}
	starts, _ := launcher.counts()
	if starts != 1 {
		t.Fatalf("launcher starts = %d, want one shared attempt", starts)
	}
}

func TestManagerSharedLaunchFailureFansOutWithoutFollowerRetry(t *testing.T) {
	launcher := &fakeLauncher{failNext: true, startGate: make(chan struct{})}
	var releaseGate sync.Once
	releaseStart := func() { releaseGate.Do(func() { close(launcher.startGate) }) }
	defer releaseStart()
	manager := mustManager(t, launcher, Limits{MaximumSessions: 8, MemoryLimitBytes: 1_000, AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour})
	now := time.Unix(2_000_000_370, 0).UTC()
	firstRequest := baseRequest(t, "failure-fanout-tenant-a", "failure-fanout-session-a", 1, now)
	secondRequest := baseRequest(t, "failure-fanout-tenant-b", "failure-fanout-session-b", 1, now)
	firstResult := make(chan error, 1)
	go func() {
		_, err := manager.Acquire(context.Background(), firstRequest)
		firstResult <- err
	}()
	waitForLauncherStarts(t, launcher, 1)
	secondResult := make(chan error, 1)
	go func() {
		_, err := manager.Acquire(context.Background(), secondRequest)
		secondResult <- err
	}()
	waitForPendingLaunchWaiters(t, manager, secondRequest.SessionID, 2)
	releaseStart()
	if err := receiveError(t, firstResult); !errors.Is(err, errLaunch) {
		t.Fatalf("first Acquire() error = %v, want launch failure", err)
	}
	if err := receiveError(t, secondResult); !errors.Is(err, errLaunch) {
		t.Fatalf("second Acquire() error = %v, want same launch failure", err)
	}
	starts, _ := launcher.counts()
	if starts != 1 {
		t.Fatalf("launcher starts = %d, want failed attempt shared without retry", starts)
	}
}

func TestManagerLastLaunchWaiterCancellationLeavesAbandonedBarrierUntilStartReturns(t *testing.T) {
	launcher := newDelayedCancellationLauncher()
	defer launcher.releaseFirstStart()
	manager := mustManager(t, launcher, Limits{MaximumSessions: 8, MemoryLimitBytes: 1_000, AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour})
	request := baseRequest(t, "abandoned-tenant", "abandoned-session", 1, time.Unix(2_000_000_380, 0).UTC())
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := manager.Acquire(ctx, request)
		result <- err
	}()
	waitForDelayedLauncherStarts(t, launcher, 1)
	cancel()
	if err := receiveError(t, result); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Acquire() error = %v, want context.Canceled", err)
	}
	select {
	case <-launcher.contextCanceled:
	case <-time.After(3 * time.Second):
		t.Fatal("manager-owned launch context was not canceled after its last waiter left")
	}
	waitForPendingLaunchAbandoned(t, manager, request.SessionID)

	barrierCtx, cancelBarrier := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelBarrier()
	if _, err := manager.Acquire(barrierCtx, request); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Acquire(behind abandoned launch) error = %v, want deadline", err)
	}
	if specs := launcher.launchSpecs(); len(specs) != 1 {
		t.Fatalf("launches before abandoned attempt returned = %#v, want one", specs)
	}

	launcher.releaseFirstStart()
	waitForNoPendingLaunch(t, manager, request.SessionID)
	if _, err := manager.Acquire(context.Background(), request); err != nil {
		t.Fatalf("Acquire(retry) error = %v", err)
	}
	specs := launcher.launchSpecs()
	if len(specs) != 2 || specs[1].ShardGeneration != specs[0].ShardGeneration+1 {
		t.Fatalf("retry launch specs = %#v, want a fresh generation", specs)
	}
}

func TestManagerRecoversAfterShardLaunchFailure(t *testing.T) {
	t.Parallel()
	launcher := &fakeLauncher{failNext: true}
	manager := mustManager(t, launcher, Limits{MaximumSessions: 2, MemoryLimitBytes: 1_000, AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour})
	request := baseRequest(t, "tenant-a", "session-a", 1, time.Unix(2_000_000_400, 0).UTC())
	if _, err := manager.Acquire(context.Background(), request); !errors.Is(err, errLaunch) {
		t.Fatalf("first Acquire() error = %v, want launch error", err)
	}
	if placement, err := manager.Acquire(context.Background(), request); err != nil || placement.ShardID == "" {
		t.Fatalf("retry Acquire() = %#v, %v", placement, err)
	}
	starts, _ := launcher.counts()
	if starts != 2 {
		t.Fatalf("launcher starts = %d, want 2", starts)
	}
}

func TestManagerLaunchSpecBindsOneAgentInstanceAndFreshShardGeneration(t *testing.T) {
	t.Parallel()
	launcher := &fakeLauncher{}
	manager := mustManager(t, launcher, Limits{MaximumSessions: 1, MemoryLimitBytes: 1_000, AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour})
	now := time.Unix(2_000_000_425, 0).UTC()
	mustAcquire(t, manager, baseRequest(t, "identity-tenant-a", "identity-session-a", 1, now))
	mustAcquire(t, manager, baseRequest(t, "identity-tenant-b", "identity-session-b", 1, now.Add(time.Second)))

	specs := launcher.launchSpecs()
	if len(specs) != 2 {
		t.Fatalf("launch specs = %#v, want two", specs)
	}
	if specs[0].AgentInstanceID.Kind() != identity.Process || specs[0].AgentInstanceID.String() == "" {
		t.Fatalf("first AgentInstanceID = %q (%q), want process identity", specs[0].AgentInstanceID.String(), specs[0].AgentInstanceID.Kind())
	}
	if specs[1].AgentInstanceID != specs[0].AgentInstanceID {
		t.Fatalf("AgentInstanceIDs = %q and %q, want one manager-owned identity", specs[0].AgentInstanceID, specs[1].AgentInstanceID)
	}
	if specs[0].ShardGeneration == 0 || specs[1].ShardGeneration != specs[0].ShardGeneration+1 {
		t.Fatalf("ShardGenerations = %d and %d, want consecutive nonzero generations", specs[0].ShardGeneration, specs[1].ShardGeneration)
	}
	if specs[0].ShardID == specs[1].ShardID {
		t.Fatalf("capacity launch ShardIDs = %q and %q, want distinct logical slots", specs[0].ShardID, specs[1].ShardID)
	}
}

func TestManagerLaunchRetryConsumesFreshShardGeneration(t *testing.T) {
	t.Parallel()
	launcher := &fakeLauncher{failNext: true}
	manager := mustManager(t, launcher, Limits{MaximumSessions: 1, MemoryLimitBytes: 1_000, AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour})
	request := baseRequest(t, "retry-generation-tenant", "retry-generation-session", 1, time.Unix(2_000_000_430, 0).UTC())

	if _, err := manager.Acquire(context.Background(), request); !errors.Is(err, errLaunch) {
		t.Fatalf("first Acquire() error = %v, want launch error", err)
	}
	mustAcquire(t, manager, request)

	specs := launcher.launchSpecs()
	if len(specs) != 2 {
		t.Fatalf("launch specs = %#v, want two", specs)
	}
	if specs[0].ShardGeneration == 0 || specs[1].ShardGeneration != specs[0].ShardGeneration+1 {
		t.Fatalf("retry ShardGenerations = %d and %d, want fresh consecutive generations", specs[0].ShardGeneration, specs[1].ShardGeneration)
	}
	if specs[0].ShardID != specs[1].ShardID {
		t.Fatalf("retry ShardIDs = %q and %q, want one logical slot", specs[0].ShardID, specs[1].ShardID)
	}
	if specs[0].AgentInstanceID != specs[1].AgentInstanceID {
		t.Fatalf("retry AgentInstanceIDs = %q and %q", specs[0].AgentInstanceID, specs[1].AgentInstanceID)
	}
}

func TestManagerCanceledLaunchRetryReusesShardIDWithFreshGeneration(t *testing.T) {
	launcher := &retryAfterCancellationLauncher{started: make(chan ShardSpec, 2)}
	manager := mustManager(t, launcher, Limits{MaximumSessions: 1, MemoryLimitBytes: 1_000, AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour})
	request := baseRequest(t, "cancel-retry-tenant", "cancel-retry-session", 1, time.Unix(2_000_000_432, 0).UTC())
	firstCtx, cancelFirst := context.WithCancel(context.Background())
	firstResult := make(chan error, 1)
	go func() {
		_, acquireErr := manager.Acquire(firstCtx, request)
		firstResult <- acquireErr
	}()
	var firstSpec ShardSpec
	select {
	case firstSpec = <-launcher.started:
	case <-time.After(3 * time.Second):
		t.Fatal("first launch did not start")
	}
	cancelFirst()
	if acquireErr := receiveError(t, firstResult); !errors.Is(acquireErr, context.Canceled) {
		t.Fatalf("first Acquire() error = %v, want context.Canceled", acquireErr)
	}

	type acquireResult struct {
		placement Placement
		err       error
	}
	retryResult := make(chan acquireResult, 1)
	go func() {
		placement, acquireErr := manager.Acquire(context.Background(), request)
		retryResult <- acquireResult{placement: placement, err: acquireErr}
	}()
	var retrySpec ShardSpec
	select {
	case retrySpec = <-launcher.started:
	case <-time.After(3 * time.Second):
		t.Fatal("retry launch did not start")
	}
	result := <-retryResult
	if result.err != nil {
		t.Fatalf("retry Acquire() error = %v", result.err)
	}
	if retrySpec.ShardID != firstSpec.ShardID || result.placement.ShardID != firstSpec.ShardID {
		t.Fatalf("cancel retry IDs = first:%q retry:%q placement:%q, want one logical slot", firstSpec.ShardID, retrySpec.ShardID, result.placement.ShardID)
	}
	if firstSpec.ShardGeneration == 0 || retrySpec.ShardGeneration != firstSpec.ShardGeneration+1 {
		t.Fatalf("cancel retry generations = %d and %d, want fresh generation", firstSpec.ShardGeneration, retrySpec.ShardGeneration)
	}
}

func TestManagerShardGenerationOverflowFailsClosedBeforeAnotherStart(t *testing.T) {
	t.Parallel()
	launcher := &fakeLauncher{failNext: true}
	manager := mustManager(t, launcher, Limits{MaximumSessions: 1, MemoryLimitBytes: 1_000, AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour})
	manager.nextShardGeneration = ^ShardGeneration(0)
	request := baseRequest(t, "overflow-tenant", "overflow-session", 1, time.Unix(2_000_000_435, 0).UTC())

	if _, err := manager.Acquire(context.Background(), request); !errors.Is(err, errLaunch) {
		t.Fatalf("maximum generation Acquire() error = %v, want launch error", err)
	}
	if _, err := manager.Acquire(context.Background(), request); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("post-overflow Acquire() error = %v, want ErrInvalidConfig", err)
	}
	specs := launcher.launchSpecs()
	if len(specs) != 1 || specs[0].ShardGeneration != ^ShardGeneration(0) {
		t.Fatalf("overflow launch specs = %#v, want one maximum-generation attempt", specs)
	}
}

func TestManagerStopsAProcessThatViolatesTheLauncherIdentityContract(t *testing.T) {
	t.Parallel()
	launcher := &fakeLauncher{returnedID: "wrong-shard"}
	manager := mustManager(t, launcher, Limits{MaximumSessions: 2, MemoryLimitBytes: 1_000, AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour})
	request := baseRequest(t, "tenant-a", "session-bad-launcher", 1, time.Unix(2_000_000_450, 0).UTC())
	if placement, err := manager.Acquire(context.Background(), request); !errors.Is(err, ErrInvalidConfig) || placement != (Placement{}) {
		t.Fatalf("Acquire() = %#v, %v; want ErrInvalidConfig", placement, err)
	}
	_, stops := launcher.counts()
	if len(stops) != 1 || stops[0] != "wrong-shard" {
		t.Fatalf("invalid launcher process stops = %#v", stops)
	}
}

func TestManagerProcessIDCallbackRunsWithoutManagerMutex(t *testing.T) {
	launcher := newBlockingIDLauncher()
	defer launcher.releaseID()
	manager := mustManager(t, launcher, Limits{MaximumSessions: 2, MemoryLimitBytes: 1_000, AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour})
	request := baseRequest(t, "callback-tenant", "callback-session", 1, time.Unix(2_000_000_460, 0).UTC())
	acquireResult := make(chan error, 1)
	go func() {
		_, err := manager.Acquire(context.Background(), request)
		acquireResult <- err
	}()
	select {
	case <-launcher.idEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("process ID callback was not entered")
	}

	snapshotResult := make(chan ManagerSnapshot, 1)
	go func() { snapshotResult <- manager.Snapshot() }()
	select {
	case snapshot := <-snapshotResult:
		if snapshot != (ManagerSnapshot{}) {
			t.Fatalf("Snapshot() while identity callback blocked = %#v", snapshot)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Snapshot() blocked behind process ID callback")
	}
	launcher.releaseID()
	if err := receiveError(t, acquireResult); err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
}

func TestManagerRejectsTypedNilShardProcessWithoutInvokingIt(t *testing.T) {
	manager := mustManager(t, typedNilLauncher{}, Limits{MaximumSessions: 2, MemoryLimitBytes: 1_000, AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour})
	request := baseRequest(t, "typed-nil-tenant", "typed-nil-session", 1, time.Unix(2_000_000_465, 0).UTC())
	if placement, err := manager.Acquire(context.Background(), request); !errors.Is(err, ErrInvalidConfig) || placement != (Placement{}) {
		t.Fatalf("Acquire() = %#v, %v; want ErrInvalidConfig", placement, err)
	}
}

func baseRequest(t *testing.T, tenantSeed, sessionSeed string, generation uint64, now time.Time) PlacementRequest {
	t.Helper()
	return PlacementRequest{
		TenantID: mustID(t, identity.Tenant, tenantSeed), SessionID: mustID(t, identity.Session, sessionSeed),
		PlacementGeneration: generation, TrustClass: TrustPlatformReviewed,
		Profile:              PlacementProfile{ProcessScope: ScopeShared, OuterIsolation: IsolationNone},
		Runtime:              RuntimeIdentity{RuntimeRevisionDigest: digest("a"), PiAdapterABI: 1, CompatibilityDate: "2026-08-26"},
		EstimatedMemoryBytes: 100, Now: now,
	}
}

func mustManager(t *testing.T, launcher Launcher, limits Limits) *Manager {
	t.Helper()
	manager, err := NewManager(launcher, limits)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	return manager
}

func mustAcquire(t *testing.T, manager *Manager, request PlacementRequest) Placement {
	t.Helper()
	placement, err := manager.Acquire(context.Background(), request)
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	return placement
}

func mustID(t *testing.T, kind identity.Kind, seed string) identity.ID {
	t.Helper()
	entropy := sha256.Sum256([]byte(seed))
	id, err := (identity.Generator{Random: bytes.NewReader(entropy[:])}).New(kind)
	if err != nil {
		t.Fatalf("identity.Generator.New() error = %v", err)
	}
	return id
}

func digest(character string) string { return "sha256:" + strings.Repeat(character, 64) }

func waitForPendingLaunchWaiters(t *testing.T, manager *Manager, sessionID identity.ID, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		manager.mu.Lock()
		pending := manager.pendingSessions[sessionID]
		waiters := 0
		if pending != nil {
			waiters = pending.waiters
		}
		manager.mu.Unlock()
		if waiters == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("pending launch waiters = %d, want %d", waiters, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func waitForPendingLaunchAbandoned(t *testing.T, manager *Manager, sessionID identity.ID) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		manager.mu.Lock()
		pending := manager.pendingSessions[sessionID]
		abandoned := pending != nil && pending.abandoned
		manager.mu.Unlock()
		if abandoned {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("pending launch did not enter abandoned state")
		}
		time.Sleep(time.Millisecond)
	}
}

func waitForNoPendingLaunch(t *testing.T, manager *Manager, sessionID identity.ID) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		manager.mu.Lock()
		pending := manager.pendingSessions[sessionID]
		manager.mu.Unlock()
		if pending == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("pending launch was not removed")
		}
		time.Sleep(time.Millisecond)
	}
}

func waitForDelayedLauncherStarts(t *testing.T, launcher *delayedCancellationLauncher, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		starts := len(launcher.launchSpecs())
		if starts >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("launcher starts = %d, want at least %d", starts, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func receiveError(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for operation result")
		return nil
	}
}
