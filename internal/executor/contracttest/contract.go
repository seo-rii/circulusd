// Package contracttest contains the backend-neutral ExecutionProvider contract
// suite. Provider implementations should invoke Run from their own tests.
package contracttest

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/hancomac/circulusd/internal/executor"
)

// Factory describes one provider configuration to exercise.
type Factory struct {
	New     func(executor.FaultInjector) executor.Provider
	Mode    executor.DeploymentMode
	Backend executor.Backend
	Spec    executor.SandboxSpec
}

// Run executes the reusable provider lifecycle, concurrency, fencing, and
// fault-recovery contract.
func Run(t *testing.T, factory Factory) {
	t.Helper()

	t.Run("capability", func(t *testing.T) {
		t.Parallel()

		provider := factory.New(nil)
		capability, err := provider.Capabilities(context.Background(), factory.Mode)
		if err != nil {
			t.Fatalf("Capabilities() error = %v", err)
		}
		if !capability.Available {
			t.Fatalf("Capabilities() unavailable: %s", capability.UnavailableReason)
		}
		if capability.Backend != factory.Backend {
			t.Fatalf("Capabilities().Backend = %q, want %q", capability.Backend, factory.Backend)
		}
	})

	t.Run("concurrent same-key ensure is singleflight", func(t *testing.T) {
		provider := factory.New(nil)
		const callers = 64

		start := make(chan struct{})
		results := make(chan executor.EnsureResult, callers)
		errs := make(chan error, callers)
		var ready sync.WaitGroup
		ready.Add(callers)
		var done sync.WaitGroup
		done.Add(callers)
		for range callers {
			go func() {
				defer done.Done()
				ready.Done()
				<-start
				result, err := provider.EnsureSandbox(context.Background(), executor.EnsureRequest{
					Mode: factory.Mode,
					Spec: factory.Spec,
				})
				if err != nil {
					errs <- err
					return
				}
				results <- result
			}()
		}
		ready.Wait()
		close(start)
		done.Wait()
		close(results)
		close(errs)

		for err := range errs {
			t.Errorf("EnsureSandbox() error = %v", err)
		}
		var first executor.SandboxHandle
		created := 0
		seen := 0
		for result := range results {
			seen++
			if first.IsZero() {
				first = result.Handle
			}
			if result.Handle != first {
				t.Errorf("EnsureSandbox() returned distinct handles %v and %v", first, result.Handle)
			}
			if !result.Reused {
				created++
			}
		}
		if seen != callers {
			t.Fatalf("EnsureSandbox() returned %d results, want %d", seen, callers)
		}
		if created != 1 {
			t.Fatalf("EnsureSandbox() reported %d creations, want 1", created)
		}

		snapshot, err := provider.Snapshot(context.Background())
		if err != nil {
			t.Fatalf("Snapshot() error = %v", err)
		}
		if len(snapshot) != 1 || snapshot[0].Handle != first {
			t.Fatalf("Snapshot() = %#v, want one ensured sandbox", snapshot)
		}
	})

	t.Run("stop destroy and generation fencing", func(t *testing.T) {
		provider := factory.New(nil)
		created, err := provider.EnsureSandbox(context.Background(), executor.EnsureRequest{
			Mode: factory.Mode,
			Spec: factory.Spec,
		})
		if err != nil {
			t.Fatalf("EnsureSandbox() error = %v", err)
		}

		health, err := provider.Health(context.Background(), created.Handle)
		if err != nil {
			t.Fatalf("Health(ready) error = %v", err)
		}
		if health.State != executor.LifecycleReady || !health.Healthy || !health.AcceptingWork {
			t.Fatalf("Health(ready) = %#v", health)
		}

		if err := provider.Stop(context.Background(), created.Handle); err != nil {
			t.Fatalf("Stop() error = %v", err)
		}
		if err := provider.Stop(context.Background(), created.Handle); err != nil {
			t.Fatalf("second Stop() error = %v", err)
		}
		health, err = provider.Health(context.Background(), created.Handle)
		if err != nil {
			t.Fatalf("Health(stopped) error = %v", err)
		}
		if health.State != executor.LifecycleStopped || health.Healthy || health.AcceptingWork {
			t.Fatalf("Health(stopped) = %#v", health)
		}
		if _, err := provider.EnsureSandbox(context.Background(), executor.EnsureRequest{
			Mode: factory.Mode,
			Spec: factory.Spec,
		}); !errors.Is(err, executor.ErrSandboxStopped) {
			t.Fatalf("EnsureSandbox(stopped) error = %v, want ErrSandboxStopped", err)
		}

		if err := provider.Destroy(context.Background(), created.Handle); err != nil {
			t.Fatalf("Destroy() error = %v", err)
		}
		if err := provider.Destroy(context.Background(), created.Handle); err != nil {
			t.Fatalf("second Destroy() error = %v", err)
		}
		if err := provider.Stop(context.Background(), created.Handle); err != nil {
			t.Fatalf("Stop(destroyed) error = %v", err)
		}
		health, err = provider.Health(context.Background(), created.Handle)
		if err != nil {
			t.Fatalf("Health(destroyed) error = %v", err)
		}
		if health.State != executor.LifecycleDestroyed {
			t.Fatalf("Health(destroyed).State = %q", health.State)
		}

		recreated, err := provider.EnsureSandbox(context.Background(), executor.EnsureRequest{
			Mode: factory.Mode,
			Spec: factory.Spec,
		})
		if err != nil {
			t.Fatalf("EnsureSandbox(recreate) error = %v", err)
		}
		if recreated.Handle.Generation() <= created.Handle.Generation() {
			t.Fatalf(
				"recreated generation = %d, want greater than %d",
				recreated.Handle.Generation(),
				created.Handle.Generation(),
			)
		}
		if _, err := provider.Health(context.Background(), created.Handle); !errors.Is(err, executor.ErrStaleHandle) {
			t.Fatalf("Health(old handle) error = %v, want ErrStaleHandle", err)
		}
		if err := provider.Destroy(context.Background(), created.Handle); !errors.Is(err, executor.ErrStaleHandle) {
			t.Fatalf("Destroy(old handle) error = %v, want ErrStaleHandle", err)
		}
	})

	t.Run("ensure fault has no partial state and is retryable", func(t *testing.T) {
		injected := errors.New("injected ensure failure")
		faults := &failOnceInjector{point: executor.FaultEnsure, err: injected}
		provider := factory.New(faults)

		_, err := provider.EnsureSandbox(context.Background(), executor.EnsureRequest{
			Mode: factory.Mode,
			Spec: factory.Spec,
		})
		if !errors.Is(err, injected) {
			t.Fatalf("EnsureSandbox() error = %v, want injected failure", err)
		}
		snapshot, err := provider.Snapshot(context.Background())
		if err != nil {
			t.Fatalf("Snapshot() error = %v", err)
		}
		if len(snapshot) != 0 {
			t.Fatalf("Snapshot() after failed ensure = %#v, want empty", snapshot)
		}

		if _, err := provider.EnsureSandbox(context.Background(), executor.EnsureRequest{
			Mode: factory.Mode,
			Spec: factory.Spec,
		}); err != nil {
			t.Fatalf("EnsureSandbox(retry) error = %v", err)
		}
	})
}

type failOnceInjector struct {
	point executor.FaultPoint
	err   error
	used  atomic.Bool
}

func (injector *failOnceInjector) Inject(
	_ context.Context,
	point executor.FaultPoint,
	_ executor.FaultMetadata,
) error {
	if point == injector.point && injector.used.CompareAndSwap(false, true) {
		return injector.err
	}
	return nil
}
