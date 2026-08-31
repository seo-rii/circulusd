package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/identity"
)

var errLaunch = errors.New("test: launch failed")

func TestShardProcessRequiresManagerOwnedIdentityTuple(t *testing.T) {
	processType := reflect.TypeOf((*ShardProcess)(nil)).Elem()
	for _, contract := range []struct {
		name       string
		resultType reflect.Type
	}{
		{name: "ID", resultType: reflect.TypeOf("")},
		{name: "AgentInstanceID", resultType: reflect.TypeOf(identity.ID{})},
		{name: "ShardGeneration", resultType: reflect.TypeOf(ShardGeneration(0))},
	} {
		method, found := processType.MethodByName(contract.name)
		if !found || method.Type.NumIn() != 0 || method.Type.NumOut() != 1 || method.Type.Out(0) != contract.resultType {
			t.Errorf("ShardProcess.%s = %#v, want no inputs and %v result", contract.name, method, contract.resultType)
		}
	}
}

type fakeLauncher struct {
	mu                      sync.Mutex
	starts                  int
	specs                   []ShardSpec
	stops                   []string
	failNext                bool
	startGate               chan struct{}
	returnedAgentInstanceID identity.ID
	returnedID              string
	returnedShardGeneration ShardGeneration
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
	agentInstanceID := spec.AgentInstanceID
	if launcher.returnedAgentInstanceID != (identity.ID{}) {
		agentInstanceID = launcher.returnedAgentInstanceID
	}
	shardGeneration := spec.ShardGeneration
	if launcher.returnedShardGeneration != 0 {
		shardGeneration = launcher.returnedShardGeneration
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
	return &fakeProcess{
		agentInstanceID: agentInstanceID,
		id:              id,
		shardGeneration: shardGeneration,
		launcher:        launcher,
	}, nil
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
	agentInstanceID identity.ID
	id              string
	shardGeneration ShardGeneration
	launcher        *fakeLauncher
	once            sync.Once
}

type reentrantObservationStopResult struct {
	snapshot   ManagerSnapshot
	observeErr error
}

type reentrantObservationStopProcess struct {
	manager     *Manager
	spec        ShardSpec
	observation ShardObservation
	result      chan reentrantObservationStopResult
}

func (process *reentrantObservationStopProcess) ID() string {
	return process.spec.ShardID
}

func (process *reentrantObservationStopProcess) AgentInstanceID() identity.ID {
	return process.spec.AgentInstanceID
}

func (process *reentrantObservationStopProcess) ShardGeneration() ShardGeneration {
	return process.spec.ShardGeneration
}

func (process *reentrantObservationStopProcess) Stop(context.Context) error {
	process.result <- reentrantObservationStopResult{
		snapshot:   process.manager.Snapshot(),
		observeErr: process.manager.Observe(process.observation),
	}
	return nil
}

func (process *fakeProcess) ID() string { return process.id }

func (process *fakeProcess) AgentInstanceID() identity.ID { return process.agentInstanceID }

func (process *fakeProcess) ShardGeneration() ShardGeneration { return process.shardGeneration }

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
	return &fakeProcess{
		agentInstanceID: spec.AgentInstanceID,
		id:              spec.ShardID,
		shardGeneration: spec.ShardGeneration,
		launcher:        &fakeLauncher{},
	}, nil
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
	return &fakeProcess{
		agentInstanceID: spec.AgentInstanceID,
		id:              spec.ShardID,
		shardGeneration: spec.ShardGeneration,
		launcher:        &fakeLauncher{},
	}, nil
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
	identityEntered     [3]chan struct{}
	identityGates       [3]chan struct{}
	identityEnteredOnce [3]sync.Once
	identityReleaseOnce [3]sync.Once
}

func (launcher *blockingIDLauncher) Start(_ context.Context, spec ShardSpec) (ShardProcess, error) {
	return &blockingIDProcess{
		agentInstanceID: spec.AgentInstanceID,
		id:              spec.ShardID,
		shardGeneration: spec.ShardGeneration,
		launcher:        launcher,
	}, nil
}

type blockingIDProcess struct {
	agentInstanceID identity.ID
	id              string
	shardGeneration ShardGeneration
	launcher        *blockingIDLauncher
}

func (process *blockingIDProcess) ID() string {
	process.blockIdentityCallback(0)
	return process.id
}

func (process *blockingIDProcess) AgentInstanceID() identity.ID {
	process.blockIdentityCallback(1)
	return process.agentInstanceID
}

func (process *blockingIDProcess) ShardGeneration() ShardGeneration {
	process.blockIdentityCallback(2)
	return process.shardGeneration
}

func (process *blockingIDProcess) blockIdentityCallback(index int) {
	process.launcher.identityEnteredOnce[index].Do(func() { close(process.launcher.identityEntered[index]) })
	<-process.launcher.identityGates[index]
}

func (*blockingIDProcess) Stop(context.Context) error { return nil }

type typedNilLauncher struct{}

func (typedNilLauncher) Start(context.Context, ShardSpec) (ShardProcess, error) {
	var process *typedNilProcess
	return process, nil
}

type typedNilProcess struct{}

func (*typedNilProcess) ID() string { panic("typed-nil process ID callback") }

func (*typedNilProcess) AgentInstanceID() identity.ID {
	panic("typed-nil process AgentInstanceID callback")
}

func (*typedNilProcess) ShardGeneration() ShardGeneration {
	panic("typed-nil process ShardGeneration callback")
}

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
	spec := launcher.launchSpecs()[0]
	if err := manager.Observe(ShardObservation{
		AgentInstanceID: spec.AgentInstanceID, ShardID: first.ShardID, ShardGeneration: spec.ShardGeneration,
		ObservationSequence: 1, RSSBytes: 750, HeapPressure: true, ObservedAt: now.Add(time.Second),
	}); err != nil {
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

func TestManagerObserveRejectsInvalidIdentityBeforeMutation(t *testing.T) {
	launcher := &fakeLauncher{}
	manager := mustManager(t, launcher, Limits{MaximumSessions: 4, MemoryLimitBytes: 1_000, AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour})
	now := time.Unix(2_000_000_110, 0).UTC()
	request := baseRequest(t, "observation-invalid-tenant", "observation-invalid-session", 1, now)
	placement := mustAcquire(t, manager, request)
	spec := launcher.launchSpecs()[0]

	valid := ShardObservation{
		AgentInstanceID:     spec.AgentInstanceID,
		ShardID:             placement.ShardID,
		ShardGeneration:     spec.ShardGeneration,
		ObservationSequence: 99,
		RSSBytes:            900,
		OOMObserved:         true,
		ObservedAt:          now.Add(time.Second),
	}
	for _, test := range []struct {
		name        string
		observation ShardObservation
	}{
		{name: "zero agent instance", observation: func() ShardObservation { value := valid; value.AgentInstanceID = identity.ID{}; return value }()},
		{name: "wrong agent kind", observation: func() ShardObservation { value := valid; value.AgentInstanceID = request.TenantID; return value }()},
		{name: "empty shard", observation: func() ShardObservation { value := valid; value.ShardID = ""; return value }()},
		{name: "zero shard generation", observation: func() ShardObservation { value := valid; value.ShardGeneration = 0; return value }()},
		{name: "zero sequence", observation: func() ShardObservation { value := valid; value.ObservationSequence = 0; return value }()},
		{name: "zero timestamp", observation: func() ShardObservation { value := valid; value.ObservedAt = time.Time{}; return value }()},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := manager.Observe(test.observation); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("Observe() error = %v, want ErrInvalidRequest", err)
			}
			manager.mu.Lock()
			current := manager.shards[placement.ShardID]
			if current == nil || current.lastObservationSequence != 0 || current.rssBytes != 0 || current.draining {
				t.Fatalf("shard mutated after invalid observation: %#v", current)
			}
			manager.mu.Unlock()
		})
	}

	valid.ObservationSequence = 1
	valid.RSSBytes = 100
	valid.OOMObserved = false
	if err := manager.Observe(valid); err != nil {
		t.Fatalf("Observe(valid after invalid high sequence) error = %v", err)
	}
	manager.mu.Lock()
	current := manager.shards[placement.ShardID]
	if current == nil || current.lastObservationSequence != 1 || current.rssBytes != 100 || current.draining {
		t.Fatalf("shard after valid observation = %#v", current)
	}
	manager.mu.Unlock()
}

func TestManagerObserveUsesStableErrorPrecedenceWithoutLeakingShardExistenceAcrossBoots(t *testing.T) {
	launcher := &fakeLauncher{}
	manager := mustManager(t, launcher, Limits{MaximumSessions: 4, MemoryLimitBytes: 1_000, AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour})
	now := time.Unix(2_000_000_115, 0).UTC()
	placement := mustAcquire(t, manager, baseRequest(t, "observation-precedence-tenant", "observation-precedence-session", 1, now))
	spec := launcher.launchSpecs()[0]
	otherAgentInstanceID, err := identity.New(identity.Process)
	if err != nil {
		t.Fatalf("identity.New(process) error = %v", err)
	}
	valid := ShardObservation{
		AgentInstanceID: spec.AgentInstanceID, ShardID: placement.ShardID, ShardGeneration: spec.ShardGeneration,
		ObservationSequence: 1, RSSBytes: 100, ObservedAt: now.Add(time.Second),
	}

	wrongBootMissing := valid
	wrongBootMissing.AgentInstanceID = otherAgentInstanceID
	wrongBootMissing.ShardID = "missing-shard"
	if observeErr := manager.Observe(wrongBootMissing); !errors.Is(observeErr, ErrStaleObservation) {
		t.Fatalf("Observe(wrong boot and missing shard) error = %v, want ErrStaleObservation", observeErr)
	}
	missing := valid
	missing.ShardID = "missing-shard"
	if observeErr := manager.Observe(missing); !errors.Is(observeErr, ErrShardNotFound) {
		t.Fatalf("Observe(current boot and missing shard) error = %v, want ErrShardNotFound", observeErr)
	}
	wrongGenerationAndSequence := valid
	wrongGenerationAndSequence.ShardGeneration++
	if observeErr := manager.Observe(wrongGenerationAndSequence); !errors.Is(observeErr, ErrStaleObservation) {
		t.Fatalf("Observe(wrong generation and duplicate sequence) error = %v, want ErrStaleObservation", observeErr)
	}

	manager.mu.Lock()
	current := manager.shards[placement.ShardID]
	if current == nil || current.lastObservationSequence != 0 || current.rssBytes != 0 || current.draining {
		t.Fatalf("shard mutated while classifying observation errors: %#v", current)
	}
	manager.closed = true
	manager.mu.Unlock()
	if observeErr := manager.Observe(wrongBootMissing); !errors.Is(observeErr, ErrManagerClosed) {
		t.Fatalf("Observe(closed, wrong boot, missing shard) error = %v, want ErrManagerClosed", observeErr)
	}
	malformed := wrongBootMissing
	malformed.AgentInstanceID = identity.ID{}
	if observeErr := manager.Observe(malformed); !errors.Is(observeErr, ErrInvalidRequest) {
		t.Fatalf("Observe(malformed closed request) error = %v, want ErrInvalidRequest", observeErr)
	}
}

func TestManagerObserveRejectsStaleTupleAndSequenceBeforeMutation(t *testing.T) {
	launcher := &fakeLauncher{}
	manager := mustManager(t, launcher, Limits{MaximumSessions: 4, MemoryLimitBytes: 1_000, AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour})
	now := time.Unix(2_000_000_120, 0).UTC()
	request := baseRequest(t, "observation-stale-tenant", "observation-stale-session", 1, now)
	placement := mustAcquire(t, manager, request)
	spec := launcher.launchSpecs()[0]
	initial := ShardObservation{
		AgentInstanceID: spec.AgentInstanceID, ShardID: placement.ShardID, ShardGeneration: spec.ShardGeneration,
		ObservationSequence: 10, RSSBytes: 100, ObservedAt: now.Add(time.Second),
	}
	if err := manager.Observe(initial); err != nil {
		t.Fatalf("Observe(initial) error = %v", err)
	}
	otherAgentInstanceID, err := identity.New(identity.Process)
	if err != nil {
		t.Fatalf("identity.New(process) error = %v", err)
	}
	for _, test := range []struct {
		name        string
		observation ShardObservation
		wantErr     error
	}{
		{name: "wrong boot", observation: func() ShardObservation {
			value := initial
			value.AgentInstanceID = otherAgentInstanceID
			value.ObservationSequence = 100
			value.RSSBytes = 900
			value.OOMObserved = true
			return value
		}(), wantErr: ErrStaleObservation},
		{name: "wrong generation", observation: func() ShardObservation {
			value := initial
			value.ShardGeneration++
			value.ObservationSequence = 100
			value.RSSBytes = 900
			value.OOMObserved = true
			return value
		}(), wantErr: ErrStaleObservation},
		{name: "duplicate sequence", observation: func() ShardObservation {
			value := initial
			value.RSSBytes = 900
			value.OOMObserved = true
			return value
		}(), wantErr: ErrStaleObservationSequence},
		{name: "decreasing sequence", observation: func() ShardObservation {
			value := initial
			value.ObservationSequence = 9
			value.RSSBytes = 900
			value.OOMObserved = true
			return value
		}(), wantErr: ErrStaleObservationSequence},
	} {
		t.Run(test.name, func(t *testing.T) {
			if observeErr := manager.Observe(test.observation); !errors.Is(observeErr, test.wantErr) {
				t.Fatalf("Observe() error = %v, want %v", observeErr, test.wantErr)
			}
			manager.mu.Lock()
			current := manager.shards[placement.ShardID]
			if current == nil || current.lastObservationSequence != 10 || current.rssBytes != 100 || current.draining {
				t.Fatalf("shard mutated after stale observation: %#v", current)
			}
			manager.mu.Unlock()
		})
	}

	gap := initial
	gap.ObservationSequence = 20
	gap.RSSBytes = 200
	gap.ObservedAt = now.Add(-time.Hour)
	if err := manager.Observe(gap); err != nil {
		t.Fatalf("Observe(gapped sequence with older timestamp) error = %v", err)
	}
	manager.mu.Lock()
	current := manager.shards[placement.ShardID]
	if current == nil || current.lastObservationSequence != 20 || current.rssBytes != 200 || current.draining {
		t.Fatalf("shard after gapped observation = %#v", current)
	}
	manager.mu.Unlock()
}

func TestManagerObserveAcceptsOneConcurrentDuplicateWithoutLoserMutation(t *testing.T) {
	launcher := &fakeLauncher{}
	manager := mustManager(t, launcher, Limits{MaximumSessions: 4, MemoryLimitBytes: 1_000, AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour})
	now := time.Unix(2_000_000_125, 0).UTC()
	placement := mustAcquire(t, manager, baseRequest(t, "observation-race-tenant", "observation-race-session", 1, now))
	spec := launcher.launchSpecs()[0]
	type observationResult struct {
		name string
		err  error
	}
	observations := map[string]ShardObservation{
		"low": {
			AgentInstanceID: spec.AgentInstanceID, ShardID: placement.ShardID, ShardGeneration: spec.ShardGeneration,
			ObservationSequence: 7, RSSBytes: 100, ObservedAt: now.Add(time.Second),
		},
		"pressure": {
			AgentInstanceID: spec.AgentInstanceID, ShardID: placement.ShardID, ShardGeneration: spec.ShardGeneration,
			ObservationSequence: 7, RSSBytes: 900, HeapPressure: true, ObservedAt: now.Add(2 * time.Second),
		},
	}
	ready := make(chan struct{}, len(observations))
	start := make(chan struct{})
	results := make(chan observationResult, len(observations))
	manager.mu.Lock()
	for name, observation := range observations {
		name := name
		observation := observation
		go func() {
			ready <- struct{}{}
			<-start
			results <- observationResult{name: name, err: manager.Observe(observation)}
		}()
	}
	for range observations {
		<-ready
	}
	close(start)
	manager.mu.Unlock()

	winner := ""
	loser := ""
	for range observations {
		result := <-results
		if result.err == nil {
			if winner != "" {
				t.Fatalf("multiple observations succeeded: %q and %q", winner, result.name)
			}
			winner = result.name
			continue
		}
		if !errors.Is(result.err, ErrStaleObservationSequence) {
			t.Fatalf("Observe(%s) error = %v, want nil or ErrStaleObservationSequence", result.name, result.err)
		}
		loser = result.name
	}
	if winner == "" || loser == "" || winner == loser {
		t.Fatalf("concurrent observation results winner=%q loser=%q", winner, loser)
	}
	manager.mu.Lock()
	current := manager.shards[placement.ShardID]
	want := observations[winner]
	if current == nil || current.lastObservationSequence != want.ObservationSequence || current.rssBytes != want.RSSBytes || current.draining != (want.OOMObserved || want.HeapPressure || want.RSSBytes >= manager.limits.AdmissionMemoryWatermarkBytes) {
		t.Fatalf("shard = %#v, want only winner %q payload %#v", current, winner, want)
	}
	manager.mu.Unlock()
}

func TestManagerObserveHigherSequenceCannotResurrectDrainingShard(t *testing.T) {
	launcher := &fakeLauncher{}
	manager := mustManager(t, launcher, Limits{MaximumSessions: 4, MemoryLimitBytes: 1_000, AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour})
	now := time.Unix(2_000_000_127, 0).UTC()
	placement := mustAcquire(t, manager, baseRequest(t, "observation-drain-tenant", "observation-drain-session", 1, now))
	spec := launcher.launchSpecs()[0]
	if err := manager.Observe(ShardObservation{
		AgentInstanceID: spec.AgentInstanceID, ShardID: placement.ShardID, ShardGeneration: spec.ShardGeneration,
		ObservationSequence: 1, RSSBytes: 900, HeapPressure: true, ObservedAt: now.Add(time.Second),
	}); err != nil {
		t.Fatalf("Observe(pressure) error = %v", err)
	}
	if err := manager.Observe(ShardObservation{
		AgentInstanceID: spec.AgentInstanceID, ShardID: placement.ShardID, ShardGeneration: spec.ShardGeneration,
		ObservationSequence: 2, RSSBytes: 1, ObservedAt: now.Add(2 * time.Second),
	}); err != nil {
		t.Fatalf("Observe(lower RSS) error = %v", err)
	}
	manager.mu.Lock()
	current := manager.shards[placement.ShardID]
	if current == nil || current.lastObservationSequence != 2 || current.rssBytes != 1 || !current.draining {
		t.Fatalf("draining shard was resurrected: %#v", current)
	}
	manager.mu.Unlock()
}

func TestManagerObserveTreatsObservedAtAsDiagnosticOnly(t *testing.T) {
	launcher := &fakeLauncher{}
	manager := mustManager(t, launcher, Limits{MaximumSessions: 4, MemoryLimitBytes: 1_000, AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Minute})
	now := time.Unix(2_000_000_130, 0).UTC()
	placement := mustAcquire(t, manager, baseRequest(t, "observation-time-tenant", "observation-time-session", 1, now))
	spec := launcher.launchSpecs()[0]
	if err := manager.Observe(ShardObservation{
		AgentInstanceID: spec.AgentInstanceID, ShardID: placement.ShardID, ShardGeneration: spec.ShardGeneration,
		ObservationSequence: 1, RSSBytes: 100, ObservedAt: now.Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("Observe(future diagnostic timestamp) error = %v", err)
	}
	if err := manager.Observe(ShardObservation{
		AgentInstanceID: spec.AgentInstanceID, ShardID: placement.ShardID, ShardGeneration: spec.ShardGeneration,
		ObservationSequence: 2, RSSBytes: 200, ObservedAt: now.Add(-24 * time.Hour),
	}); err != nil {
		t.Fatalf("Observe(older diagnostic timestamp) error = %v", err)
	}
	manager.mu.Lock()
	current := manager.shards[placement.ShardID]
	if current == nil || current.lastObservationSequence != 2 || current.rssBytes != 200 || current.draining {
		t.Fatalf("diagnostic timestamps changed shard lifecycle: %#v", current)
	}
	manager.mu.Unlock()
}

func TestManagerObserveRejectsDelayedOldGenerationWithoutRewritingReplacement(t *testing.T) {
	launcher := &fakeLauncher{}
	manager := mustManager(t, launcher, Limits{MaximumSessions: 4, MemoryLimitBytes: 1_000, AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour})
	now := time.Unix(2_000_000_140, 0).UTC()
	placement := mustAcquire(t, manager, baseRequest(t, "observation-replacement-tenant", "observation-replacement-session", 1, now))
	oldSpec := launcher.launchSpecs()[0]

	manager.mu.Lock()
	oldShard := manager.shards[placement.ShardID]
	replacementSpec := oldShard.spec
	replacementSpec.ShardGeneration++
	replacementProcess := &fakeProcess{
		agentInstanceID: replacementSpec.AgentInstanceID,
		id:              replacementSpec.ShardID,
		shardGeneration: replacementSpec.ShardGeneration,
		launcher:        launcher,
	}
	replacement := &shard{
		spec: replacementSpec, process: replacementProcess, sessions: oldShard.sessions,
		estimatedResidentBytes: oldShard.estimatedResidentBytes, rssBytes: 700,
	}
	manager.shards[placement.ShardID] = replacement
	manager.mu.Unlock()

	if err := manager.Observe(ShardObservation{
		AgentInstanceID: oldSpec.AgentInstanceID, ShardID: placement.ShardID, ShardGeneration: oldSpec.ShardGeneration,
		ObservationSequence: 100, RSSBytes: 1, ObservedAt: now.Add(time.Second),
	}); !errors.Is(err, ErrStaleObservation) {
		t.Fatalf("Observe(delayed old generation) error = %v, want ErrStaleObservation", err)
	}
	manager.mu.Lock()
	current := manager.shards[placement.ShardID]
	if current != replacement || current.lastObservationSequence != 0 || current.rssBytes != 700 || current.draining {
		t.Fatalf("replacement mutated by delayed old observation: %#v", current)
	}
	manager.mu.Unlock()

	if err := manager.Observe(ShardObservation{
		AgentInstanceID: replacementSpec.AgentInstanceID, ShardID: placement.ShardID, ShardGeneration: replacementSpec.ShardGeneration,
		ObservationSequence: 1, RSSBytes: 600, ObservedAt: now.Add(2 * time.Second),
	}); err != nil {
		t.Fatalf("Observe(replacement first sequence) error = %v", err)
	}
	manager.mu.Lock()
	current = manager.shards[placement.ShardID]
	if current != replacement || current.lastObservationSequence != 1 || current.rssBytes != 600 || current.draining {
		t.Fatalf("replacement first observation = %#v", current)
	}
	manager.mu.Unlock()
}

func TestManagerObserveNeverWrapsSequenceWithinAGeneration(t *testing.T) {
	launcher := &fakeLauncher{}
	manager := mustManager(t, launcher, Limits{MaximumSessions: 4, MemoryLimitBytes: 1_000, AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour})
	now := time.Unix(2_000_000_142, 0).UTC()
	placement := mustAcquire(t, manager, baseRequest(t, "observation-exhaustion-tenant", "observation-exhaustion-session", 1, now))
	spec := launcher.launchSpecs()[0]
	maximum := ShardObservation{
		AgentInstanceID: spec.AgentInstanceID, ShardID: placement.ShardID, ShardGeneration: spec.ShardGeneration,
		ObservationSequence: math.MaxUint64, RSSBytes: 100, ObservedAt: now.Add(time.Second),
	}
	if err := manager.Observe(maximum); err != nil {
		t.Fatalf("Observe(maximum sequence) error = %v", err)
	}
	wrapped := maximum
	wrapped.ObservationSequence = 1
	wrapped.RSSBytes = 900
	wrapped.HeapPressure = true
	if err := manager.Observe(wrapped); !errors.Is(err, ErrStaleObservationSequence) {
		t.Fatalf("Observe(wrapped sequence) error = %v, want ErrStaleObservationSequence", err)
	}
	manager.mu.Lock()
	current := manager.shards[placement.ShardID]
	if current == nil || current.lastObservationSequence != math.MaxUint64 || current.rssBytes != 100 || current.draining {
		t.Fatalf("shard mutated by wrapped observation: %#v", current)
	}
	manager.mu.Unlock()
}

func TestManagerObserveStopsZeroSessionDrainingShardWithoutHoldingManagerMutex(t *testing.T) {
	launcher := &fakeLauncher{}
	manager := mustManager(t, launcher, Limits{MaximumSessions: 4, MemoryLimitBytes: 1_000, AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour})
	now := time.Unix(2_000_000_145, 0).UTC()
	request := baseRequest(t, "observation-stop-tenant", "observation-stop-session", 1, now)
	placement := mustAcquire(t, manager, request)
	spec := launcher.launchSpecs()[0]
	if err := manager.Release(context.Background(), ReleaseRequest{SessionID: request.SessionID, PlacementGeneration: request.PlacementGeneration}); err != nil {
		t.Fatalf("Release() error = %v", err)
	}
	stopResult := make(chan reentrantObservationStopResult, 1)
	manager.mu.Lock()
	current := manager.shards[placement.ShardID]
	current.process = &reentrantObservationStopProcess{
		manager: manager,
		spec:    spec,
		observation: ShardObservation{
			AgentInstanceID: spec.AgentInstanceID, ShardID: spec.ShardID, ShardGeneration: spec.ShardGeneration,
			ObservationSequence: 2, RSSBytes: 1, ObservedAt: now.Add(2 * time.Second),
		},
		result: stopResult,
	}
	manager.mu.Unlock()

	observeResult := make(chan error, 1)
	go func() {
		observeResult <- manager.Observe(ShardObservation{
			AgentInstanceID: spec.AgentInstanceID, ShardID: spec.ShardID, ShardGeneration: spec.ShardGeneration,
			ObservationSequence: 1, RSSBytes: 900, HeapPressure: true, ObservedAt: now.Add(time.Second),
		})
	}()
	select {
	case result := <-stopResult:
		if result.snapshot != (ManagerSnapshot{}) {
			t.Fatalf("Snapshot() from Stop = %#v, want empty", result.snapshot)
		}
		if !errors.Is(result.observeErr, ErrShardNotFound) {
			t.Fatalf("reentrant Observe() error = %v, want ErrShardNotFound", result.observeErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ShardProcess.Stop blocked while reentering Manager")
	}
	select {
	case err := <-observeResult:
		if err != nil {
			t.Fatalf("Observe() error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Observe() did not join reentrant Stop")
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
	for name, launcher := range map[string]*fakeLauncher{
		"agent instance": {returnedAgentInstanceID: mustID(t, identity.Process, "wrong-agent-instance")},
		"shard ID":       {returnedID: "wrong-shard"},
		"generation":     {returnedShardGeneration: 999},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			manager := mustManager(t, launcher, Limits{MaximumSessions: 2, MemoryLimitBytes: 1_000, AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour})
			request := baseRequest(t, "tenant-a-"+name, "session-bad-launcher-"+name, 1, time.Unix(2_000_000_450, 0).UTC())
			if placement, err := manager.Acquire(context.Background(), request); !errors.Is(err, ErrInvalidConfig) || placement != (Placement{}) {
				t.Fatalf("Acquire() = %#v, %v; want ErrInvalidConfig", placement, err)
			}
			_, stops := launcher.counts()
			if len(stops) != 1 {
				t.Fatalf("invalid launcher process stops = %#v, want one", stops)
			}
		})
	}
}

func TestManagerProcessIdentityCallbacksRunWithoutManagerMutex(t *testing.T) {
	launcher := &blockingIDLauncher{}
	for index := range launcher.identityEntered {
		launcher.identityEntered[index] = make(chan struct{})
		launcher.identityGates[index] = make(chan struct{})
	}
	defer func() {
		for index := range launcher.identityGates {
			index := index
			launcher.identityReleaseOnce[index].Do(func() { close(launcher.identityGates[index]) })
		}
	}()
	manager := mustManager(t, launcher, Limits{MaximumSessions: 2, MemoryLimitBytes: 1_000, AdmissionMemoryWatermarkBytes: 800, MaximumLifetime: time.Hour})
	request := baseRequest(t, "callback-tenant", "callback-session", 1, time.Unix(2_000_000_460, 0).UTC())
	acquireResult := make(chan error, 1)
	go func() {
		_, err := manager.Acquire(context.Background(), request)
		acquireResult <- err
	}()
	for index, callbackName := range []string{"ID", "AgentInstanceID", "ShardGeneration"} {
		select {
		case <-launcher.identityEntered[index]:
		case <-time.After(3 * time.Second):
			t.Fatalf("process %s callback was not entered", callbackName)
		}

		snapshotResult := make(chan ManagerSnapshot, 1)
		go func() { snapshotResult <- manager.Snapshot() }()
		select {
		case snapshot := <-snapshotResult:
			if snapshot != (ManagerSnapshot{}) {
				t.Fatalf("Snapshot() while %s callback blocked = %#v", callbackName, snapshot)
			}
		case <-time.After(100 * time.Millisecond):
			t.Fatalf("Snapshot() blocked behind process %s callback", callbackName)
		}
		index := index
		launcher.identityReleaseOnce[index].Do(func() { close(launcher.identityGates[index]) })
	}
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
