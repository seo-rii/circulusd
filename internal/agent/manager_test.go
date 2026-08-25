package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
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
	stops      []string
	failNext   bool
	startGate  chan struct{}
	returnedID string
}

func (launcher *fakeLauncher) Start(ctx context.Context, spec ShardSpec) (ShardProcess, error) {
	launcher.mu.Lock()
	launcher.starts++
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
