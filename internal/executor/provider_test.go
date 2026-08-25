package executor_test

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/executor"
	"github.com/hancomac/circulusd/internal/executor/contracttest"
)

func TestDevelopmentMockProviderContract(t *testing.T) {
	contracttest.Run(t, contracttest.Factory{
		New: func(faults executor.FaultInjector) executor.Provider {
			return executor.NewDevelopmentMockProvider(faults)
		},
		Mode:    executor.DeploymentDevelopment,
		Backend: executor.BackendMock,
		Spec:    validSpec(),
	})
}

func TestDevelopmentMockProviderFailsClosed(t *testing.T) {
	t.Parallel()

	provider := executor.NewDevelopmentMockProvider(nil)
	capability, err := provider.Capabilities(context.Background(), executor.DeploymentProduction)
	if err != nil {
		t.Fatalf("Capabilities(production) error = %v", err)
	}
	if capability.Available || !capability.DevelopmentOnly || capability.UnavailableReason == "" {
		t.Fatalf("Capabilities(production) = %#v", capability)
	}
	if !strings.Contains(capability.UnavailableReason, "development") {
		t.Fatalf("Capabilities(production).UnavailableReason = %q", capability.UnavailableReason)
	}

	_, err = provider.EnsureSandbox(context.Background(), executor.EnsureRequest{
		Mode: executor.DeploymentProduction,
		Spec: validSpec(),
	})
	if !errors.Is(err, executor.ErrDevelopmentOnly) {
		t.Fatalf("EnsureSandbox(production) error = %v, want ErrDevelopmentOnly", err)
	}

	for _, backend := range []executor.Backend{
		executor.BackendNsJail,
		executor.BackendDocker,
		executor.BackendFirecracker,
	} {
		t.Run(string(backend), func(t *testing.T) {
			t.Parallel()

			spec := validSpec()
			spec.Backend = backend
			_, err := provider.EnsureSandbox(context.Background(), executor.EnsureRequest{
				Mode: executor.DeploymentDevelopment,
				Spec: spec,
			})
			if !errors.Is(err, executor.ErrBackendMismatch) {
				t.Fatalf("EnsureSandbox(%s) error = %v, want ErrBackendMismatch", backend, err)
			}
		})
	}
}

func TestDevelopmentMockStopPublishesDrainingState(t *testing.T) {
	t.Parallel()

	gate := newGateInjector(executor.FaultStopDraining)
	provider := executor.NewDevelopmentMockProvider(gate)
	result, err := provider.EnsureSandbox(context.Background(), executor.EnsureRequest{
		Mode: executor.DeploymentDevelopment,
		Spec: validSpec(),
	})
	if err != nil {
		t.Fatalf("EnsureSandbox() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	firstStop := make(chan error, 1)
	go func() {
		firstStop <- provider.Stop(ctx, result.Handle)
	}()

	select {
	case <-gate.entered:
	case <-ctx.Done():
		t.Fatal("Stop() did not reach draining fault point")
	}
	health, err := provider.Health(ctx, result.Handle)
	if err != nil {
		t.Fatalf("Health(draining) error = %v", err)
	}
	if health.State != executor.LifecycleDraining || health.Healthy || health.AcceptingWork {
		t.Fatalf("Health(draining) = %#v", health)
	}
	if _, err := provider.EnsureSandbox(ctx, executor.EnsureRequest{
		Mode: executor.DeploymentDevelopment,
		Spec: validSpec(),
	}); !errors.Is(err, executor.ErrSandboxDraining) {
		t.Fatalf("EnsureSandbox(draining) error = %v, want ErrSandboxDraining", err)
	}

	secondStop := make(chan error, 1)
	go func() {
		secondStop <- provider.Stop(ctx, result.Handle)
	}()
	close(gate.release)
	if err := <-firstStop; err != nil {
		t.Fatalf("first Stop() error = %v", err)
	}
	if err := <-secondStop; err != nil {
		t.Fatalf("concurrent Stop() error = %v", err)
	}
	if got := gate.calls.Load(); got != 1 {
		t.Fatalf("draining fault point calls = %d, want 1", got)
	}
}

func TestDevelopmentMockEnsureFaultPointIsSingleflight(t *testing.T) {
	t.Parallel()

	gate := newGateInjector(executor.FaultEnsure)
	provider := executor.NewDevelopmentMockProvider(gate)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const callers = 32
	start := make(chan struct{})
	results := make(chan executor.EnsureResult, callers)
	errs := make(chan error, callers)
	for range callers {
		go func() {
			<-start
			result, err := provider.EnsureSandbox(ctx, executor.EnsureRequest{
				Mode: executor.DeploymentDevelopment,
				Spec: validSpec(),
			})
			if err != nil {
				errs <- err
				return
			}
			results <- result
		}()
	}
	close(start)
	select {
	case <-gate.entered:
	case <-ctx.Done():
		t.Fatal("EnsureSandbox() did not reach ensure fault point")
	}
	close(gate.release)

	var handle executor.SandboxHandle
	created := 0
	for range callers {
		select {
		case err := <-errs:
			t.Fatalf("EnsureSandbox() error = %v", err)
		case result := <-results:
			if handle.IsZero() {
				handle = result.Handle
			}
			if result.Handle != handle {
				t.Fatalf("EnsureSandbox() returned distinct handles %v and %v", handle, result.Handle)
			}
			if !result.Reused {
				created++
			}
		case <-ctx.Done():
			t.Fatal("timed out waiting for EnsureSandbox()")
		}
	}
	if created != 1 {
		t.Fatalf("EnsureSandbox() reported %d creations, want 1", created)
	}
	if got := gate.calls.Load(); got != 1 {
		t.Fatalf("ensure fault point calls = %d, want 1", got)
	}
}

func TestDevelopmentMockRejectsUnknownAndCrossProviderHandles(t *testing.T) {
	t.Parallel()

	first := executor.NewDevelopmentMockProvider(nil)
	second := executor.NewDevelopmentMockProvider(nil)
	created, err := first.EnsureSandbox(context.Background(), executor.EnsureRequest{
		Mode: executor.DeploymentDevelopment,
		Spec: validSpec(),
	})
	if err != nil {
		t.Fatalf("EnsureSandbox() error = %v", err)
	}

	if _, err := second.Health(context.Background(), created.Handle); !errors.Is(err, executor.ErrUnknownHandle) {
		t.Fatalf("Health(cross-provider handle) error = %v, want ErrUnknownHandle", err)
	}
	if err := first.Stop(context.Background(), executor.SandboxHandle{}); !errors.Is(err, executor.ErrUnknownHandle) {
		t.Fatalf("Stop(zero handle) error = %v, want ErrUnknownHandle", err)
	}
}

type gateInjector struct {
	point   executor.FaultPoint
	entered chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func newGateInjector(point executor.FaultPoint) *gateInjector {
	return &gateInjector{
		point:   point,
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (injector *gateInjector) Inject(
	ctx context.Context,
	point executor.FaultPoint,
	_ executor.FaultMetadata,
) error {
	if point != injector.point {
		return nil
	}
	if injector.calls.Add(1) == 1 {
		close(injector.entered)
	}
	select {
	case <-injector.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
