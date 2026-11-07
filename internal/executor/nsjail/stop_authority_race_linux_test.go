//go:build linux

package nsjail

import (
	"context"
	"errors"
	"testing"

	"github.com/hancomac/circulusd/internal/executor"
)

func TestStopConcurrentAuthorityRefresh(t *testing.T) {
	// Exercise both schedulings at the point where Stop has published Draining
	// and released the provider mutex. The race detector must also cover the
	// cancellation function and the context initialized by the authority refresh.
	for range 100 {
		entered := make(chan struct{})
		release := make(chan struct{})
		provider, _ := newTestProvider(t, executor.FaultInjectorFunc(func(
			_ context.Context, point executor.FaultPoint, _ executor.FaultMetadata,
		) error {
			if point == executor.FaultStopDraining {
				close(entered)
				<-release
			}
			return nil
		}), nil)
		first, refreshed := testSandboxSpec(t, 1), testSandboxSpec(t, 2)
		created, err := provider.EnsureSandbox(context.Background(), executor.EnsureRequest{
			Mode: executor.DeploymentProduction, Spec: first,
		})
		if err != nil {
			t.Fatal(err)
		}
		stopped := make(chan error, 1)
		ensured := make(chan error, 1)
		go func() { stopped <- provider.Stop(context.Background(), created.Handle) }()
		<-entered
		go func() {
			<-release
			_, err := provider.EnsureSandbox(context.Background(), executor.EnsureRequest{
				Mode: executor.DeploymentProduction, Spec: refreshed,
			})
			ensured <- err
		}()
		close(release)
		stopErr, ensureErr := <-stopped, <-ensured
		if stopErr != nil {
			t.Fatalf("Stop() = %v", stopErr)
		}
		if !errors.Is(ensureErr, executor.ErrSandboxDraining) && !errors.Is(ensureErr, executor.ErrSandboxStopped) {
			t.Fatalf("EnsureSandbox() during stop = %v", ensureErr)
		}
		if err := provider.Destroy(context.Background(), created.Handle); err != nil {
			t.Fatalf("Destroy() = %v", err)
		}
	}
}
