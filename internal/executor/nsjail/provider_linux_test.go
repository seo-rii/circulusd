//go:build linux

package nsjail

import (
	"bytes"
	"context"
	"errors"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/executor"
	"github.com/hancomac/circulusd/internal/executor/contracttest"
	"github.com/hancomac/circulusd/internal/identity"
)

func TestProviderSatisfiesLifecycleContract(t *testing.T) {
	contracttest.Run(t, contracttest.Factory{
		New: func(faults executor.FaultInjector) executor.Provider {
			provider, _ := newTestProvider(t, faults, nil)
			return provider
		},
		Mode:    executor.DeploymentProduction,
		Backend: executor.BackendNsJail,
		Spec:    testSandboxSpec(t, 1),
	})
}

func TestProviderDoesNotPublishBeforeHandshake(t *testing.T) {
	ready := make(chan struct{})
	provider, fixture := newTestProvider(t, nil, func(ctx context.Context, _ identity.ID, _ uint64) (ControlSession, error) {
		select {
		case <-ready:
			return &fakeControlSession{}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})

	result := make(chan error, 1)
	go func() {
		_, err := provider.EnsureSandbox(context.Background(), executor.EnsureRequest{
			Mode: executor.DeploymentProduction,
			Spec: testSandboxSpec(t, 1),
		})
		result <- err
	}()
	fixture.waitForStarts(t, 1)

	snapshot, err := provider.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if len(snapshot) != 0 {
		t.Fatalf("Snapshot() during handshake = %#v, want no published sandbox", snapshot)
	}
	close(ready)
	if err := <-result; err != nil {
		t.Fatalf("EnsureSandbox() error = %v", err)
	}
}

func TestProviderHandshakeFailureDestroysUnpublishedInstance(t *testing.T) {
	handshakeFailure := errors.New("injected handshake failure")
	provider, fixture := newTestProvider(t, nil, func(context.Context, identity.ID, uint64) (ControlSession, error) {
		return nil, handshakeFailure
	})

	_, err := provider.EnsureSandbox(context.Background(), executor.EnsureRequest{
		Mode: executor.DeploymentProduction,
		Spec: testSandboxSpec(t, 1),
	})
	if !errors.Is(err, handshakeFailure) {
		t.Fatalf("EnsureSandbox() error = %v, want handshake failure", err)
	}
	if fixture.destroyCount.Load() != 1 {
		t.Fatalf("unpublished instance destroys = %d, want 1", fixture.destroyCount.Load())
	}
	snapshot, snapshotErr := provider.Snapshot(context.Background())
	if snapshotErr != nil || len(snapshot) != 0 {
		t.Fatalf("Snapshot() = %#v, %v, want empty", snapshot, snapshotErr)
	}
}

func TestProviderAuthorityFenceInvalidatesOldExecuteAuthority(t *testing.T) {
	provider, _ := newTestProvider(t, nil, nil)
	firstSpec := testSandboxSpec(t, 7)
	created, err := provider.EnsureSandbox(context.Background(), executor.EnsureRequest{
		Mode: executor.DeploymentProduction,
		Spec: firstSpec,
	})
	if err != nil {
		t.Fatalf("EnsureSandbox(first) error = %v", err)
	}

	var calls atomic.Int32
	if err := provider.Execute(context.Background(), created.Handle, firstSpec.LaunchAuthority, func(context.Context, ControlSession) error {
		calls.Add(1)
		return nil
	}); err != nil {
		t.Fatalf("Execute(first authority) error = %v", err)
	}

	newerSpec := testSandboxSpec(t, 8)
	reused, err := provider.EnsureSandbox(context.Background(), executor.EnsureRequest{
		Mode: executor.DeploymentProduction,
		Spec: newerSpec,
	})
	if err != nil || !reused.Reused || reused.Handle != created.Handle {
		t.Fatalf("EnsureSandbox(new authority) = %#v, %v", reused, err)
	}
	if err := provider.Execute(context.Background(), created.Handle, firstSpec.LaunchAuthority, func(context.Context, ControlSession) error {
		calls.Add(1)
		return nil
	}); !errors.Is(err, executor.ErrStaleAuthority) {
		t.Fatalf("Execute(stale authority) error = %v, want ErrStaleAuthority", err)
	}
	if err := provider.Execute(context.Background(), created.Handle, newerSpec.LaunchAuthority, func(context.Context, ControlSession) error {
		calls.Add(1)
		return nil
	}); err != nil {
		t.Fatalf("Execute(new authority) error = %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("executed callbacks = %d, want 2", calls.Load())
	}
	if _, err := provider.EnsureSandbox(context.Background(), executor.EnsureRequest{
		Mode: executor.DeploymentProduction,
		Spec: firstSpec,
	}); !errors.Is(err, executor.ErrStaleAuthority) {
		t.Fatalf("EnsureSandbox(stale authority) error = %v, want ErrStaleAuthority", err)
	}
}

func TestNewAuthorityFencesLaunchStillAwaitingHandshake(t *testing.T) {
	ready := make(chan struct{})
	provider, fixture := newTestProvider(t, nil, func(ctx context.Context, _ identity.ID, _ uint64) (ControlSession, error) {
		select {
		case <-ready:
			return &fakeControlSession{}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	oldSpec := testSandboxSpec(t, 7)
	newSpec := testSandboxSpec(t, 8)
	oldResult := make(chan error, 1)
	newResult := make(chan error, 1)
	go func() {
		_, err := provider.EnsureSandbox(context.Background(), executor.EnsureRequest{
			Mode: executor.DeploymentProduction,
			Spec: oldSpec,
		})
		oldResult <- err
	}()
	fixture.waitForStarts(t, 1)
	go func() {
		_, err := provider.EnsureSandbox(context.Background(), executor.EnsureRequest{
			Mode: executor.DeploymentProduction,
			Spec: newSpec,
		})
		newResult <- err
	}()

	key, err := newSpec.CanonicalCacheKey()
	if err != nil {
		t.Fatalf("CanonicalCacheKey() error = %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		provider.mu.Lock()
		generation := provider.fences[key].Generation()
		provider.mu.Unlock()
		if generation == 8 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("new authority did not fence the in-flight launch")
		}
		runtime.Gosched()
	}
	close(ready)
	if err := <-oldResult; !errors.Is(err, executor.ErrStaleAuthority) {
		t.Fatalf("old EnsureSandbox() error = %v, want ErrStaleAuthority", err)
	}
	if err := <-newResult; err != nil {
		t.Fatalf("new EnsureSandbox() error = %v", err)
	}
	snapshot, err := provider.Snapshot(context.Background())
	if err != nil || len(snapshot) != 1 {
		t.Fatalf("Snapshot() = %#v, %v", snapshot, err)
	}
	if snapshot[0].Spec.LaunchAuthority.Generation() != 8 {
		t.Fatalf("published authority generation = %d, want 8", snapshot[0].Spec.LaunchAuthority.Generation())
	}
}

func TestCanceledResolverCannotLaunch(t *testing.T) {
	provider, fixture := newTestProvider(t, nil, nil)
	resolverStarted := make(chan struct{})
	releaseResolver := make(chan struct{})
	fixture.mu.Lock()
	fixture.resolve = func(context.Context, executor.SandboxSpec) (ResolvedLaunch, error) {
		close(resolverStarted)
		<-releaseResolver
		return testResolvedLaunch(), nil
	}
	fixture.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := provider.EnsureSandbox(ctx, executor.EnsureRequest{
			Mode: executor.DeploymentProduction,
			Spec: testSandboxSpec(t, 1),
		})
		result <- err
	}()
	<-resolverStarted
	cancel()
	close(releaseResolver)
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("EnsureSandbox() error = %v, want context.Canceled", err)
	}
	if fixture.startCount.Load() != 0 {
		t.Fatalf("starts after canceled resolution = %d, want 0", fixture.startCount.Load())
	}
}

func TestCanceledCapabilityProbeCannotFenceReadySandbox(t *testing.T) {
	provider, fixture := newTestProvider(t, nil, nil)
	oldSpec := testSandboxSpec(t, 1)
	created, err := provider.EnsureSandbox(context.Background(), executor.EnsureRequest{
		Mode: executor.DeploymentProduction,
		Spec: oldSpec,
	})
	if err != nil {
		t.Fatalf("EnsureSandbox() error = %v", err)
	}

	probeStarted := make(chan struct{})
	releaseProbe := make(chan struct{})
	fixture.mu.Lock()
	fixture.probe = func(context.Context) (HostCapability, error) {
		close(probeStarted)
		<-releaseProbe
		return HostCapability{Available: true}, nil
	}
	fixture.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	ensureResult := make(chan error, 1)
	go func() {
		_, ensureErr := provider.EnsureSandbox(ctx, executor.EnsureRequest{
			Mode: executor.DeploymentProduction,
			Spec: testSandboxSpec(t, 2),
		})
		ensureResult <- ensureErr
	}()
	<-probeStarted
	cancel()
	close(releaseProbe)
	if ensureErr := <-ensureResult; !errors.Is(ensureErr, context.Canceled) {
		t.Fatalf("EnsureSandbox() error = %v, want context.Canceled", ensureErr)
	}
	if executeErr := provider.Execute(
		context.Background(),
		created.Handle,
		oldSpec.LaunchAuthority,
		func(context.Context, ControlSession) error { return nil },
	); executeErr != nil {
		t.Fatalf("Execute(old authority) after canceled probe error = %v", executeErr)
	}
}

func TestCapabilitiesCannotHideProbeCancellation(t *testing.T) {
	provider, fixture := newTestProvider(t, nil, nil)
	probeStarted := make(chan struct{})
	releaseProbe := make(chan struct{})
	fixture.mu.Lock()
	fixture.probe = func(context.Context) (HostCapability, error) {
		close(probeStarted)
		<-releaseProbe
		return HostCapability{Available: true}, nil
	}
	fixture.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, capabilityErr := provider.Capabilities(ctx, executor.DeploymentProduction)
		result <- capabilityErr
	}()
	<-probeStarted
	cancel()
	close(releaseProbe)
	if capabilityErr := <-result; !errors.Is(capabilityErr, context.Canceled) {
		t.Fatalf("Capabilities() error = %v, want context.Canceled", capabilityErr)
	}
}

func TestCanceledHandshakeCannotPublishSandbox(t *testing.T) {
	readyStarted := make(chan struct{})
	releaseReady := make(chan struct{})
	var sessionCloseCount atomic.Int32
	provider, fixture := newTestProvider(t, nil, func(context.Context, identity.ID, uint64) (ControlSession, error) {
		close(readyStarted)
		<-releaseReady
		return &fakeControlSession{closes: &sessionCloseCount}, nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, ensureErr := provider.EnsureSandbox(ctx, executor.EnsureRequest{
			Mode: executor.DeploymentProduction,
			Spec: testSandboxSpec(t, 1),
		})
		result <- ensureErr
	}()
	<-readyStarted
	cancel()
	close(releaseReady)
	if ensureErr := <-result; !errors.Is(ensureErr, context.Canceled) {
		t.Fatalf("EnsureSandbox() error = %v, want context.Canceled", ensureErr)
	}
	if fixture.destroyCount.Load() != 1 {
		t.Fatalf("destroy count = %d, want 1", fixture.destroyCount.Load())
	}
	if sessionCloseCount.Load() != 1 {
		t.Fatalf("control session closes = %d, want 1", sessionCloseCount.Load())
	}
	snapshot, snapshotErr := provider.Snapshot(context.Background())
	if snapshotErr != nil || len(snapshot) != 0 {
		t.Fatalf("Snapshot() = %#v, %v, want empty", snapshot, snapshotErr)
	}
}

func TestExecuteCannotHideCallerCancellation(t *testing.T) {
	provider, _ := newTestProvider(t, nil, nil)
	spec := testSandboxSpec(t, 1)
	created, err := provider.EnsureSandbox(context.Background(), executor.EnsureRequest{
		Mode: executor.DeploymentProduction,
		Spec: spec,
	})
	if err != nil {
		t.Fatalf("EnsureSandbox() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- provider.Execute(ctx, created.Handle, spec.LaunchAuthority, func(operationContext context.Context, _ ControlSession) error {
			close(started)
			<-operationContext.Done()
			return nil
		})
	}()
	<-started
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("Execute() error = %v, want context.Canceled", err)
	}
}

func TestNaturalExitDoesNotCloseSessionUnderProviderLock(t *testing.T) {
	closeEntered := make(chan struct{})
	releaseClose := make(chan struct{})
	provider, fixture := newTestProvider(t, nil, func(context.Context, identity.ID, uint64) (ControlSession, error) {
		return &blockingControlSession{entered: closeEntered, release: releaseClose}, nil
	})
	spec := testSandboxSpec(t, 1)
	created, err := provider.EnsureSandbox(context.Background(), executor.EnsureRequest{
		Mode: executor.DeploymentProduction,
		Spec: spec,
	})
	if err != nil {
		t.Fatalf("EnsureSandbox() error = %v", err)
	}
	fixture.latestInstance(t).finish()
	select {
	case <-closeEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("natural exit did not close the control session")
	}

	healthResult := make(chan error, 1)
	go func() {
		health, healthErr := provider.Health(context.Background(), created.Handle)
		if healthErr == nil && health.State != executor.LifecycleStopped {
			healthErr = errors.New("health did not observe stopped state")
		}
		healthResult <- healthErr
	}()
	select {
	case healthErr := <-healthResult:
		close(releaseClose)
		if healthErr != nil {
			t.Fatalf("Health() error = %v", healthErr)
		}
	case <-time.After(250 * time.Millisecond):
		close(releaseClose)
		<-healthResult
		t.Fatal("Health() blocked behind ControlSession.Close while provider mutex was held")
	}
}

func TestAuthorityAdvanceDuringFailedStopCancelsOldExecute(t *testing.T) {
	stopFailure := errors.New("injected stop failure")
	stopEntered := make(chan struct{})
	releaseStop := make(chan struct{})
	var failed atomic.Bool
	provider, _ := newTestProvider(t, executor.FaultInjectorFunc(func(
		_ context.Context,
		point executor.FaultPoint,
		_ executor.FaultMetadata,
	) error {
		if point == executor.FaultStopDraining && failed.CompareAndSwap(false, true) {
			close(stopEntered)
			<-releaseStop
			return stopFailure
		}
		return nil
	}), nil)
	oldSpec := testSandboxSpec(t, 11)
	created, err := provider.EnsureSandbox(context.Background(), executor.EnsureRequest{
		Mode: executor.DeploymentProduction,
		Spec: oldSpec,
	})
	if err != nil {
		t.Fatalf("EnsureSandbox() error = %v", err)
	}

	executeStarted := make(chan struct{})
	forceExecuteReturn := make(chan struct{})
	oldExecuteCanceled := atomic.Bool{}
	oldExecuteResult := make(chan error, 1)
	go func() {
		oldExecuteResult <- provider.Execute(context.Background(), created.Handle, oldSpec.LaunchAuthority, func(ctx context.Context, _ ControlSession) error {
			close(executeStarted)
			select {
			case <-ctx.Done():
				oldExecuteCanceled.Store(true)
				return ctx.Err()
			case <-forceExecuteReturn:
				return nil
			}
		})
	}()
	<-executeStarted
	stopResult := make(chan error, 1)
	go func() { stopResult <- provider.Stop(context.Background(), created.Handle) }()
	<-stopEntered

	newSpec := testSandboxSpec(t, 12)
	if _, err := provider.EnsureSandbox(context.Background(), executor.EnsureRequest{
		Mode: executor.DeploymentProduction,
		Spec: newSpec,
	}); !errors.Is(err, executor.ErrSandboxDraining) {
		t.Fatalf("EnsureSandbox(during stop) error = %v, want ErrSandboxDraining", err)
	}
	close(releaseStop)
	if err := <-stopResult; !errors.Is(err, stopFailure) {
		t.Fatalf("Stop() error = %v, want injected failure", err)
	}

	select {
	case err := <-oldExecuteResult:
		if !errors.Is(err, executor.ErrStaleAuthority) {
			t.Fatalf("old Execute() error = %v, want ErrStaleAuthority", err)
		}
	case <-time.After(250 * time.Millisecond):
		close(forceExecuteReturn)
		err := <-oldExecuteResult
		t.Fatalf("old Execute was not canceled by authority fence; eventual error = %v", err)
	}
	if !oldExecuteCanceled.Load() {
		t.Fatal("old Execute callback did not observe cancellation")
	}
	if err := provider.Execute(context.Background(), created.Handle, newSpec.LaunchAuthority, func(context.Context, ControlSession) error {
		return nil
	}); err != nil {
		t.Fatalf("Execute(new authority after failed stop) error = %v", err)
	}
}

func TestProcessExitBeforeHandshakeIsLaunchFailure(t *testing.T) {
	provider, fixture := newTestProvider(t, nil, func(ctx context.Context, _ identity.ID, _ uint64) (ControlSession, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	result := make(chan error, 1)
	go func() {
		_, err := provider.EnsureSandbox(context.Background(), executor.EnsureRequest{
			Mode: executor.DeploymentProduction,
			Spec: testSandboxSpec(t, 1),
		})
		result <- err
	}()
	fixture.waitForStarts(t, 1)
	fixture.latestInstance(t).finish()
	if err := <-result; !errors.Is(err, ErrLaunchFailed) {
		t.Fatalf("EnsureSandbox() error = %v, want ErrLaunchFailed", err)
	}
	if fixture.destroyCount.Load() != 1 {
		t.Fatalf("destroy count = %d, want 1", fixture.destroyCount.Load())
	}
}

func TestStartErrorCleansReturnedInstance(t *testing.T) {
	startFailure := errors.New("injected ambiguous start failure")
	fixture := &providerFixture{}
	instance := newFakeInstance(fixture)
	provider, err := newProvider(providerDependencies{
		build: func(Request) (LaunchPlan, error) {
			return LaunchPlan{}, nil
		},
		start: func(context.Context, LaunchPlan) (sandboxInstance, error) {
			return instance, startFailure
		},
		resolve: RequestResolverFunc(func(context.Context, executor.SandboxSpec) (ResolvedLaunch, error) {
			return testResolvedLaunch(), nil
		}),
		ready: func(context.Context, identity.ID, uint64) (ControlSession, error) {
			return nil, errors.New("readiness must not run after a start error")
		},
		probe: func(context.Context) (HostCapability, error) {
			return HostCapability{Available: true}, nil
		},
		newSandboxID: func() (identity.ID, error) {
			return identity.New(identity.Sandbox)
		},
		protocolVersion: 1,
	})
	if err != nil {
		t.Fatalf("newProvider() error = %v", err)
	}

	if _, err := provider.EnsureSandbox(context.Background(), executor.EnsureRequest{
		Mode: executor.DeploymentProduction,
		Spec: testSandboxSpec(t, 1),
	}); !errors.Is(err, startFailure) {
		t.Fatalf("EnsureSandbox() error = %v, want start failure", err)
	}
	if fixture.destroyCount.Load() != 1 {
		t.Fatalf("ambiguous start instance destroys = %d, want 1", fixture.destroyCount.Load())
	}
}

func TestProviderDoesNotRaiseResolvedMaximumLifetime(t *testing.T) {
	provider, fixture := newTestProvider(t, nil, nil)
	requests := make(chan Request, 1)
	fixture.mu.Lock()
	fixture.resolve = func(context.Context, executor.SandboxSpec) (ResolvedLaunch, error) {
		resolved := testResolvedLaunch()
		resolved.Resources.MaximumLifetimeSeconds = 45
		return resolved, nil
	}
	fixture.build = func(request Request) (LaunchPlan, error) {
		requests <- request
		return LaunchPlan{}, nil
	}
	fixture.mu.Unlock()

	if _, err := provider.EnsureSandbox(context.Background(), executor.EnsureRequest{
		Mode: executor.DeploymentProduction,
		Spec: testSandboxSpec(t, 1),
	}); err != nil {
		t.Fatalf("EnsureSandbox() error = %v", err)
	}
	request := <-requests
	if request.Resources.MaximumLifetimeSeconds != 45 {
		t.Fatalf(
			"launch maximum lifetime = %d, want resolver hard limit 45",
			request.Resources.MaximumLifetimeSeconds,
		)
	}
}

func TestProviderRejectsTypedNilDependenciesAndSession(t *testing.T) {
	var resolver *typedNilResolver
	if _, err := newProvider(providerDependencies{
		build:           func(Request) (LaunchPlan, error) { return LaunchPlan{}, nil },
		start:           func(context.Context, LaunchPlan) (sandboxInstance, error) { return nil, errors.New("unused") },
		resolve:         resolver,
		ready:           func(context.Context, identity.ID, uint64) (ControlSession, error) { return nil, errors.New("unused") },
		probe:           func(context.Context) (HostCapability, error) { return HostCapability{Available: true}, nil },
		newSandboxID:    func() (identity.ID, error) { return identity.New(identity.Sandbox) },
		protocolVersion: 1,
	}); !errors.Is(err, ErrProviderConfig) {
		t.Fatalf("newProvider(typed nil resolver) error = %v, want ErrProviderConfig", err)
	}

	provider, fixture := newTestProvider(t, nil, func(context.Context, identity.ID, uint64) (ControlSession, error) {
		var session *typedNilSession
		return session, nil
	})
	if _, err := provider.EnsureSandbox(context.Background(), executor.EnsureRequest{
		Mode: executor.DeploymentProduction,
		Spec: testSandboxSpec(t, 1),
	}); !errors.Is(err, ErrLaunchFailed) {
		t.Fatalf("EnsureSandbox(typed nil session) error = %v, want ErrLaunchFailed", err)
	}
	if fixture.destroyCount.Load() != 1 {
		t.Fatalf("typed nil session destroy count = %d, want 1", fixture.destroyCount.Load())
	}
}

func TestNewProviderRejectsTypedNilInterfaceDependencies(t *testing.T) {
	validBroker := &typedNilBroker{}
	validResolver := RequestResolverFunc(func(context.Context, executor.SandboxSpec) (ResolvedLaunch, error) {
		return testResolvedLaunch(), nil
	})
	validProbe := CapabilityProbeFunc(func(context.Context) (HostCapability, error) {
		return HostCapability{Available: true}, nil
	})

	tests := []struct {
		name   string
		mutate func(*ProviderConfig)
	}{
		{
			name: "broker",
			mutate: func(config *ProviderConfig) {
				var broker *typedNilBroker
				config.Broker = broker
			},
		},
		{
			name: "resolver",
			mutate: func(config *ProviderConfig) {
				var resolver *typedNilResolver
				config.Resolver = resolver
			},
		},
		{
			name: "probe",
			mutate: func(config *ProviderConfig) {
				var probe *typedNilProbe
				config.Probe = probe
			},
		},
		{
			name: "fault injector",
			mutate: func(config *ProviderConfig) {
				var faults *typedNilFaultInjector
				config.Faults = faults
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := ProviderConfig{
				Planner:  validConfig(),
				Broker:   validBroker,
				Resolver: validResolver,
				Probe:    validProbe,
			}
			test.mutate(&config)
			if _, err := NewProvider(config); !errors.Is(err, ErrProviderConfig) {
				t.Fatalf("NewProvider() error = %v, want ErrProviderConfig", err)
			}
		})
	}
}

func TestConcurrentDestroyCancelsExecuteAndCleansExactlyOnce(t *testing.T) {
	provider, fixture := newTestProvider(t, nil, nil)
	spec := testSandboxSpec(t, 3)
	created, err := provider.EnsureSandbox(context.Background(), executor.EnsureRequest{
		Mode: executor.DeploymentProduction,
		Spec: spec,
	})
	if err != nil {
		t.Fatalf("EnsureSandbox() error = %v", err)
	}

	executing := make(chan struct{})
	executeResult := make(chan error, 1)
	go func() {
		executeResult <- provider.Execute(context.Background(), created.Handle, spec.LaunchAuthority, func(ctx context.Context, _ ControlSession) error {
			close(executing)
			<-ctx.Done()
			return ctx.Err()
		})
	}()
	<-executing

	const destroyers = 48
	start := make(chan struct{})
	errorsSeen := make(chan error, destroyers)
	var group sync.WaitGroup
	group.Add(destroyers)
	for range destroyers {
		go func() {
			defer group.Done()
			<-start
			errorsSeen <- provider.Destroy(context.Background(), created.Handle)
		}()
	}
	close(start)
	group.Wait()
	close(errorsSeen)
	for destroyErr := range errorsSeen {
		if destroyErr != nil {
			t.Errorf("Destroy() error = %v", destroyErr)
		}
	}
	if executeErr := <-executeResult; !errors.Is(executeErr, context.Canceled) &&
		!errors.Is(executeErr, executor.ErrSandboxDraining) &&
		!errors.Is(executeErr, executor.ErrSandboxStopped) {
		t.Fatalf("Execute() error = %v, want cancellation/fence", executeErr)
	}
	if fixture.killCount.Load() != 1 || fixture.destroyCount.Load() != 1 {
		t.Fatalf("kill/destroy counts = %d/%d, want 1/1", fixture.killCount.Load(), fixture.destroyCount.Load())
	}
	if fixture.sessionCloseCount.Load() != 1 {
		t.Fatalf("control session closes = %d, want 1", fixture.sessionCloseCount.Load())
	}
}

func TestDestroyClosesControlSessionOnlyOnce(t *testing.T) {
	session := &strictControlSession{}
	provider, _ := newTestProvider(t, nil, func(context.Context, identity.ID, uint64) (ControlSession, error) {
		return session, nil
	})
	created, err := provider.EnsureSandbox(context.Background(), executor.EnsureRequest{
		Mode: executor.DeploymentProduction,
		Spec: testSandboxSpec(t, 1),
	})
	if err != nil {
		t.Fatalf("EnsureSandbox() error = %v", err)
	}
	if err := provider.Destroy(context.Background(), created.Handle); err != nil {
		t.Fatalf("Destroy() error = %v", err)
	}
	if session.closes.Load() != 1 {
		t.Fatalf("control session Close calls = %d, want 1", session.closes.Load())
	}
}

func TestProcessExitDuringFailedStopClosesControlSession(t *testing.T) {
	stopFailure := errors.New("injected stop failure")
	stopEntered := make(chan struct{})
	releaseStop := make(chan struct{})
	var sessionCloseCount atomic.Int32
	provider, fixture := newTestProvider(t, executor.FaultInjectorFunc(func(
		_ context.Context,
		point executor.FaultPoint,
		_ executor.FaultMetadata,
	) error {
		if point == executor.FaultStopDraining {
			close(stopEntered)
			<-releaseStop
			return stopFailure
		}
		return nil
	}), func(context.Context, identity.ID, uint64) (ControlSession, error) {
		return &fakeControlSession{closes: &sessionCloseCount}, nil
	})
	created, err := provider.EnsureSandbox(context.Background(), executor.EnsureRequest{
		Mode: executor.DeploymentProduction,
		Spec: testSandboxSpec(t, 1),
	})
	if err != nil {
		t.Fatalf("EnsureSandbox() error = %v", err)
	}

	stopResult := make(chan error, 1)
	go func() { stopResult <- provider.Stop(context.Background(), created.Handle) }()
	<-stopEntered
	provider.mu.Lock()
	record, recordErr := provider.recordForHandle(created.Handle)
	if recordErr != nil {
		provider.mu.Unlock()
		t.Fatalf("recordForHandle() error = %v", recordErr)
	}
	runtimeDone := record.runtime.done
	provider.mu.Unlock()
	fixture.latestInstance(t).finish()
	<-runtimeDone
	close(releaseStop)
	if err := <-stopResult; !errors.Is(err, stopFailure) {
		t.Fatalf("Stop() error = %v, want injected failure", err)
	}
	if sessionCloseCount.Load() != 1 {
		t.Fatalf("control session closes = %d, want 1", sessionCloseCount.Load())
	}
	health, err := provider.Health(context.Background(), created.Handle)
	if err != nil || health.State != executor.LifecycleStopped {
		t.Fatalf("Health() = %#v, %v, want stopped", health, err)
	}
}

func TestFaultInjectorCannotHideCallerCancellation(t *testing.T) {
	injectorStarted := make(chan struct{})
	releaseInjector := make(chan struct{})
	provider, _ := newTestProvider(t, executor.FaultInjectorFunc(func(
		_ context.Context,
		point executor.FaultPoint,
		_ executor.FaultMetadata,
	) error {
		if point == executor.FaultHealth {
			close(injectorStarted)
			<-releaseInjector
		}
		return nil
	}), nil)
	created, err := provider.EnsureSandbox(context.Background(), executor.EnsureRequest{
		Mode: executor.DeploymentProduction,
		Spec: testSandboxSpec(t, 1),
	})
	if err != nil {
		t.Fatalf("EnsureSandbox() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, healthErr := provider.Health(ctx, created.Handle)
		result <- healthErr
	}()
	<-injectorStarted
	cancel()
	close(releaseInjector)
	if healthErr := <-result; !errors.Is(healthErr, context.Canceled) {
		t.Fatalf("Health() error = %v, want context.Canceled", healthErr)
	}
}

func TestProviderRecreationFencesOldHandle(t *testing.T) {
	provider, _ := newTestProvider(t, nil, nil)
	spec := testSandboxSpec(t, 2)
	first, err := provider.EnsureSandbox(context.Background(), executor.EnsureRequest{
		Mode: executor.DeploymentProduction,
		Spec: spec,
	})
	if err != nil {
		t.Fatalf("EnsureSandbox(first) error = %v", err)
	}
	if err := provider.Destroy(context.Background(), first.Handle); err != nil {
		t.Fatalf("Destroy(first) error = %v", err)
	}
	second, err := provider.EnsureSandbox(context.Background(), executor.EnsureRequest{
		Mode: executor.DeploymentProduction,
		Spec: spec,
	})
	if err != nil {
		t.Fatalf("EnsureSandbox(second) error = %v", err)
	}
	if second.Handle.Generation() <= first.Handle.Generation() {
		t.Fatalf("generations = %d then %d", first.Handle.Generation(), second.Handle.Generation())
	}
	if _, err := provider.Health(context.Background(), first.Handle); !errors.Is(err, executor.ErrStaleHandle) {
		t.Fatalf("Health(old handle) error = %v, want ErrStaleHandle", err)
	}
}

func TestProviderFailsClosedOnInvalidCapabilityAndRequest(t *testing.T) {
	provider, fixture := newTestProvider(t, nil, nil)
	fixture.mu.Lock()
	fixture.capability = HostCapability{Available: false, UnavailableReason: "required namespaces unavailable"}
	fixture.mu.Unlock()
	capability, err := provider.Capabilities(context.Background(), executor.DeploymentProduction)
	if err != nil || capability.Available || capability.UnavailableReason == "" {
		t.Fatalf("Capabilities() = %#v, %v", capability, err)
	}

	request := executor.EnsureRequest{Mode: executor.DeploymentProduction, Spec: testSandboxSpec(t, 1)}
	request.Spec.Backend = executor.BackendDocker
	if _, err := provider.EnsureSandbox(context.Background(), request); !errors.Is(err, executor.ErrBackendMismatch) {
		t.Fatalf("EnsureSandbox(docker) error = %v, want ErrBackendMismatch", err)
	}
	request.Spec = testSandboxSpec(t, 1)
	request.Spec.Projection = executor.ProjectionFUSEExperimental
	if _, err := provider.EnsureSandbox(context.Background(), request); !errors.Is(err, executor.ErrInvalidSpec) {
		t.Fatalf("EnsureSandbox(FUSE) error = %v, want ErrInvalidSpec", err)
	}
	if fixture.startCount.Load() != 0 {
		t.Fatalf("invalid requests started %d instances", fixture.startCount.Load())
	}

	fixture.mu.Lock()
	fixture.capability = HostCapability{Available: true, UnavailableReason: "contradictory probe result"}
	fixture.mu.Unlock()
	request.Spec = testSandboxSpec(t, 1)
	if _, err := provider.EnsureSandbox(context.Background(), request); !errors.Is(err, ErrProviderConfig) {
		t.Fatalf("EnsureSandbox(inconsistent probe) error = %v, want ErrProviderConfig", err)
	}
	if fixture.startCount.Load() != 0 {
		t.Fatalf("inconsistent probe started %d instances", fixture.startCount.Load())
	}
}

type providerFixture struct {
	startCount        atomic.Int32
	killCount         atomic.Int32
	destroyCount      atomic.Int32
	sessionCloseCount atomic.Int32

	mu         sync.Mutex
	started    chan struct{}
	capability HostCapability
	build      func(Request) (LaunchPlan, error)
	probe      func(context.Context) (HostCapability, error)
	resolve    func(context.Context, executor.SandboxSpec) (ResolvedLaunch, error)
	instances  []*fakeInstance
}

func newTestProvider(
	t *testing.T,
	faults executor.FaultInjector,
	ready func(context.Context, identity.ID, uint64) (ControlSession, error),
) (*Provider, *providerFixture) {
	t.Helper()
	fixture := &providerFixture{
		started:    make(chan struct{}, 128),
		capability: HostCapability{Available: true},
		build: func(Request) (LaunchPlan, error) {
			return LaunchPlan{}, nil
		},
		resolve: func(context.Context, executor.SandboxSpec) (ResolvedLaunch, error) {
			return testResolvedLaunch(), nil
		},
	}
	fixture.probe = func(context.Context) (HostCapability, error) {
		fixture.mu.Lock()
		defer fixture.mu.Unlock()
		return fixture.capability, nil
	}
	if ready == nil {
		ready = func(context.Context, identity.ID, uint64) (ControlSession, error) {
			return &fakeControlSession{closes: &fixture.sessionCloseCount}, nil
		}
	}
	provider, err := newProvider(providerDependencies{
		build: func(request Request) (LaunchPlan, error) {
			fixture.mu.Lock()
			build := fixture.build
			fixture.mu.Unlock()
			return build(request)
		},
		start: func(context.Context, LaunchPlan) (sandboxInstance, error) {
			instance := newFakeInstance(fixture)
			fixture.mu.Lock()
			fixture.instances = append(fixture.instances, instance)
			fixture.mu.Unlock()
			fixture.startCount.Add(1)
			fixture.started <- struct{}{}
			return instance, nil
		},
		resolve: RequestResolverFunc(func(ctx context.Context, spec executor.SandboxSpec) (ResolvedLaunch, error) {
			fixture.mu.Lock()
			resolve := fixture.resolve
			fixture.mu.Unlock()
			return resolve(ctx, spec)
		}),
		ready: ready,
		probe: func(ctx context.Context) (HostCapability, error) {
			fixture.mu.Lock()
			probe := fixture.probe
			fixture.mu.Unlock()
			return probe(ctx)
		},
		newSandboxID: func() (identity.ID, error) {
			return identity.New(identity.Sandbox)
		},
		protocolVersion: 1,
		faults:          faults,
	})
	if err != nil {
		t.Fatalf("newProvider() error = %v", err)
	}
	return provider, fixture
}

func (fixture *providerFixture) latestInstance(t *testing.T) *fakeInstance {
	t.Helper()
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if len(fixture.instances) == 0 {
		t.Fatal("no fake instance was started")
	}
	return fixture.instances[len(fixture.instances)-1]
}

func (fixture *providerFixture) waitForStarts(t *testing.T, count int) {
	t.Helper()
	for range count {
		select {
		case <-fixture.started:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for instance start")
		}
	}
}

type fakeInstance struct {
	fixture     *providerFixture
	done        chan struct{}
	finishOnce  sync.Once
	killOnce    sync.Once
	destroyOnce sync.Once
}

func newFakeInstance(fixture *providerFixture) *fakeInstance {
	return &fakeInstance{fixture: fixture, done: make(chan struct{})}
}

func (instance *fakeInstance) Wait(ctx context.Context) error {
	select {
	case <-instance.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (instance *fakeInstance) Kill(context.Context) error {
	instance.killOnce.Do(func() {
		instance.fixture.killCount.Add(1)
		instance.finishOnce.Do(func() { close(instance.done) })
	})
	return nil
}

func (instance *fakeInstance) Destroy(context.Context) error {
	instance.destroyOnce.Do(func() {
		instance.fixture.destroyCount.Add(1)
		instance.finishOnce.Do(func() { close(instance.done) })
	})
	return nil
}

func (instance *fakeInstance) finish() {
	instance.finishOnce.Do(func() { close(instance.done) })
}

type fakeControlSession struct {
	closes *atomic.Int32
	once   sync.Once
}

func (session *fakeControlSession) Close() error {
	session.once.Do(func() {
		if session.closes != nil {
			session.closes.Add(1)
		}
	})
	return nil
}

type blockingControlSession struct {
	entered chan<- struct{}
	release <-chan struct{}
	once    sync.Once
}

type typedNilResolver struct{}

func (*typedNilResolver) Resolve(context.Context, executor.SandboxSpec) (ResolvedLaunch, error) {
	return ResolvedLaunch{}, nil
}

type typedNilSession struct{}

func (session *typedNilSession) Close() error {
	if session == nil {
		panic("typed-nil control session must not be closed")
	}
	return nil
}

type typedNilBroker struct{}

func (*typedNilBroker) RegisterHandshakeNonce(
	context.Context,
	string,
	uint64,
	[]byte,
) (HandshakeNonceRegistration, error) {
	return nil, errors.New("unused")
}

func (*typedNilBroker) AwaitReady(
	context.Context,
	identity.ID,
	uint64,
) (ControlSession, error) {
	return nil, errors.New("unused")
}

type typedNilProbe struct{}

func (*typedNilProbe) Probe(context.Context) (HostCapability, error) {
	return HostCapability{}, nil
}

type typedNilFaultInjector struct{}

func (*typedNilFaultInjector) Inject(
	context.Context,
	executor.FaultPoint,
	executor.FaultMetadata,
) error {
	return nil
}

type strictControlSession struct {
	closes atomic.Int32
}

func (session *strictControlSession) Close() error {
	if session.closes.Add(1) > 1 {
		return errors.New("control session closed more than once")
	}
	return nil
}

func (session *blockingControlSession) Close() error {
	session.once.Do(func() {
		close(session.entered)
		<-session.release
	})
	return nil
}

func testSandboxSpec(t *testing.T, authorityGeneration uint64) executor.SandboxSpec {
	t.Helper()
	tenant, err := (identity.Generator{Random: bytes.NewReader(bytes.Repeat([]byte{0x41}, 16))}).New(identity.Tenant)
	if err != nil {
		t.Fatalf("tenant identity: %v", err)
	}
	authority, err := executor.NewLaunchAuthority(tenant, authorityGeneration)
	if err != nil {
		t.Fatalf("launch authority: %v", err)
	}
	return executor.SandboxSpec{
		LaunchAuthority:        authority,
		Backend:                executor.BackendNsJail,
		EnvironmentDigest:      digest(0x11),
		ResourceDigest:         digest(0x12),
		NetworkDigest:          digest(0x13),
		EffectivePolicyDigest:  digest(0x14),
		SecretExposure:         executor.SecretProxyOnly,
		SandboxProtocolVersion: 1,
		IdleTimeoutSeconds:     30,
		MaximumLifetimeSeconds: 300,
		WorkspaceAccess:        executor.WorkspaceReadWrite,
		Projection:             executor.ProjectionMaterializedManifest,
		Scope:                  executor.SandboxScope{Kind: executor.ScopeWorkspace, Identity: "workspace-alpha"},
	}
}

func digest(fill byte) string {
	const alphabet = "0123456789abcdef"
	encoded := make([]byte, 64)
	for index := range encoded {
		if index%2 == 0 {
			encoded[index] = alphabet[fill>>4]
		} else {
			encoded[index] = alphabet[fill&0x0f]
		}
	}
	return "sha256:" + string(encoded)
}

func testResolvedLaunch() ResolvedLaunch {
	return ResolvedLaunch{
		RootfsDigest:         digest(0x51),
		SeccompProfileDigest: digest(0x52),
		SandboxdDigest:       digest(0x53),
		HostUID:              10001,
		HostGID:              10001,
		Network:              NetworkNone,
		Resources: ResourceLimits{
			MemoryBytes:        64 << 20,
			MaximumProcesses:   32,
			CPUMillisPerSecond: 1000,
			ScratchBytes:       16 << 20,
			TemporaryBytes:     16 << 20,
			RunBytes:           1 << 20,
			MaximumOpenFiles:   256,
			MaximumFileBytes:   8 << 20,
		},
	}
}

var _ io.Closer = (*fakeControlSession)(nil)
