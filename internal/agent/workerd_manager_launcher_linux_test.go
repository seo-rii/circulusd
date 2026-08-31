//go:build linux

package agent

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/identity"
)

var errManagerAdapterEnsure = errors.New("test: manager adapter ensure failed")

type managerAdapterRecordingEnsurer struct {
	mu       sync.Mutex
	contexts []context.Context
	requests []WorkerdEnsureRequest
	handle   *WorkerdShardHandle
	err      error
}

func (ensurer *managerAdapterRecordingEnsurer) Ensure(ctx context.Context, request WorkerdEnsureRequest) (*WorkerdShardHandle, error) {
	ensurer.mu.Lock()
	defer ensurer.mu.Unlock()
	ensurer.contexts = append(ensurer.contexts, ctx)
	ensurer.requests = append(ensurer.requests, request)
	return ensurer.handle, ensurer.err
}

func (ensurer *managerAdapterRecordingEnsurer) recordedRequests() []WorkerdEnsureRequest {
	ensurer.mu.Lock()
	defer ensurer.mu.Unlock()
	return append([]WorkerdEnsureRequest(nil), ensurer.requests...)
}

type managerAdapterGatedEnsurer struct {
	entered     chan WorkerdEnsureRequest
	gate        chan struct{}
	releaseOnce sync.Once
}

func (ensurer *managerAdapterGatedEnsurer) Ensure(ctx context.Context, request WorkerdEnsureRequest) (*WorkerdShardHandle, error) {
	ensurer.entered <- request
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-ensurer.gate:
		return newManagerAdapterHandle(request.AgentInstanceID, request.ShardID, request.ShardGeneration), nil
	}
}

func TestWorkerdManagerLauncherSnapshotsAndForwardsOnlyFixedArguments(t *testing.T) {
	processID := newManagerAdapterIdentity(t, identity.Process)
	arguments := []string{"serve", "--config=/release/workerd.capnp"}
	spec := ShardSpec{
		AgentInstanceID: processID,
		ShardID:         "manager-adapter-shard",
		ShardGeneration: 17,
	}
	handle := newManagerAdapterHandle(spec.AgentInstanceID, spec.ShardID, spec.ShardGeneration)
	lowLevel := &managerAdapterRecordingEnsurer{handle: handle}
	launcher, err := newWorkerdManagerLauncher(lowLevel, arguments)
	if err != nil {
		t.Fatalf("newWorkerdManagerLauncher() error = %v", err)
	}
	arguments[0] = "caller-mutated"
	arguments = append(arguments, "--caller-argument")
	ctx := context.WithValue(context.Background(), managerAdapterContextKey{}, "fixed-context")

	process, err := launcher.Start(ctx, spec)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if process != handle {
		t.Fatalf("Start() process = %#v, want exact low-level handle %#v", process, handle)
	}
	requests := lowLevel.recordedRequests()
	if len(requests) != 1 {
		t.Fatalf("Ensure requests = %#v, want one", requests)
	}
	if requests[0].AgentInstanceID != spec.AgentInstanceID || requests[0].ShardID != spec.ShardID || requests[0].ShardGeneration != spec.ShardGeneration ||
		len(requests[0].Arguments) != 2 || requests[0].Arguments[0] != "serve" || requests[0].Arguments[1] != "--config=/release/workerd.capnp" {
		t.Fatalf("first Ensure request = %#v", requests[0])
	}
	lowLevel.mu.Lock()
	contexts := append([]context.Context(nil), lowLevel.contexts...)
	lowLevel.mu.Unlock()
	if len(contexts) != 1 || contexts[0] != ctx {
		t.Fatalf("Ensure contexts = %#v, want exact Start context", contexts)
	}

	requests[0].Arguments[0] = "callback-mutated"
	if _, err := launcher.Start(ctx, spec); err != nil {
		t.Fatalf("Start(second) error = %v", err)
	}
	requests = lowLevel.recordedRequests()
	if len(requests) != 2 {
		t.Fatalf("Ensure requests = %#v, want two", requests)
	}
	if requests[1].AgentInstanceID != spec.AgentInstanceID || requests[1].ShardID != spec.ShardID || requests[1].ShardGeneration != spec.ShardGeneration ||
		len(requests[1].Arguments) != 2 || requests[1].Arguments[0] != "serve" || requests[1].Arguments[1] != "--config=/release/workerd.capnp" {
		t.Fatalf("second Ensure request = %#v", requests[1])
	}
}

func TestWorkerdManagerLauncherReturnsMismatchedHandleForManagerCleanup(t *testing.T) {
	spec := ShardSpec{
		AgentInstanceID: newManagerAdapterIdentity(t, identity.Process),
		ShardID:         "adapter-mismatch",
		ShardGeneration: 23,
	}
	for name, handle := range map[string]*WorkerdShardHandle{
		"agent instance": newManagerAdapterHandle(newManagerAdapterIdentity(t, identity.Process), spec.ShardID, spec.ShardGeneration),
		"shard ID":       newManagerAdapterHandle(spec.AgentInstanceID, "wrong-shard", spec.ShardGeneration),
		"generation":     newManagerAdapterHandle(spec.AgentInstanceID, spec.ShardID, spec.ShardGeneration+1),
	} {
		t.Run(name, func(t *testing.T) {
			lowLevel := &managerAdapterRecordingEnsurer{handle: handle}
			launcher, err := newWorkerdManagerLauncher(lowLevel, []string{"serve"})
			if err != nil {
				t.Fatalf("newWorkerdManagerLauncher() error = %v", err)
			}
			process, startErr := launcher.Start(context.Background(), spec)
			if process != handle || !errors.Is(startErr, ErrInvalidConfig) {
				t.Fatalf("Start() = %#v, %v, want exact handle/ErrInvalidConfig", process, startErr)
			}
		})
	}
}

func TestWorkerdManagerLauncherRejectsInvalidManagerOwnedIdentityBeforeEnsure(t *testing.T) {
	processID := newManagerAdapterIdentity(t, identity.Process)
	tenantID := newManagerAdapterIdentity(t, identity.Tenant)
	tests := []struct {
		name string
		ctx  context.Context
		spec ShardSpec
	}{
		{name: "nil context", spec: ShardSpec{AgentInstanceID: processID, ShardID: "valid", ShardGeneration: 1}},
		{name: "empty agent identity", ctx: context.Background(), spec: ShardSpec{ShardID: "valid", ShardGeneration: 1}},
		{name: "wrong agent identity kind", ctx: context.Background(), spec: ShardSpec{AgentInstanceID: tenantID, ShardID: "valid", ShardGeneration: 1}},
		{name: "empty shard ID", ctx: context.Background(), spec: ShardSpec{AgentInstanceID: processID, ShardGeneration: 1}},
		{name: "zero shard generation", ctx: context.Background(), spec: ShardSpec{AgentInstanceID: processID, ShardID: "valid"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			lowLevel := &managerAdapterRecordingEnsurer{handle: &WorkerdShardHandle{}}
			launcher, err := newWorkerdManagerLauncher(lowLevel, []string{"serve"})
			if err != nil {
				t.Fatalf("newWorkerdManagerLauncher() error = %v", err)
			}
			process, err := launcher.Start(test.ctx, test.spec)
			if process != nil || !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("Start() = %#v, %v, want nil/ErrInvalidRequest", process, err)
			}
			if requests := lowLevel.recordedRequests(); len(requests) != 0 {
				t.Fatalf("invalid Start reached Ensure: %#v", requests)
			}
		})
	}
}

func TestWorkerdManagerLauncherRejectsNilAndTypedNilLowLevelLauncher(t *testing.T) {
	var concrete *WorkerdProcessLauncher
	if launcher, err := NewWorkerdManagerLauncher(concrete, []string{"serve"}); launcher != nil || !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("NewWorkerdManagerLauncher(nil) = %#v, %v, want nil/ErrInvalidConfig", launcher, err)
	}
	var typedNil *managerAdapterRecordingEnsurer
	if launcher, err := newWorkerdManagerLauncher(typedNil, []string{"serve"}); launcher != nil || !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("newWorkerdManagerLauncher(typed nil) = %#v, %v, want nil/ErrInvalidConfig", launcher, err)
	}
}

func TestWorkerdManagerLauncherPropagatesEnsureResult(t *testing.T) {
	lowLevel := &managerAdapterRecordingEnsurer{err: errManagerAdapterEnsure}
	launcher, err := newWorkerdManagerLauncher(lowLevel, []string{"serve"})
	if err != nil {
		t.Fatalf("newWorkerdManagerLauncher() error = %v", err)
	}
	spec := ShardSpec{
		AgentInstanceID: newManagerAdapterIdentity(t, identity.Process),
		ShardID:         "ensure-error",
		ShardGeneration: 3,
	}
	if process, err := launcher.Start(context.Background(), spec); process != nil || !errors.Is(err, errManagerAdapterEnsure) {
		t.Fatalf("Start() = %#v, %v, want exact Ensure error", process, err)
	}
}

func TestWorkerdManagerLauncherCanceledContextDoesNotReachEnsure(t *testing.T) {
	lowLevel := &managerAdapterRecordingEnsurer{handle: &WorkerdShardHandle{}}
	launcher, err := newWorkerdManagerLauncher(lowLevel, []string{"serve"})
	if err != nil {
		t.Fatalf("newWorkerdManagerLauncher() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	spec := ShardSpec{
		AgentInstanceID: newManagerAdapterIdentity(t, identity.Process),
		ShardID:         "canceled-before-ensure",
		ShardGeneration: 5,
	}
	if process, err := launcher.Start(ctx, spec); process != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("Start(canceled) = %#v, %v, want nil/context.Canceled", process, err)
	}
	if requests := lowLevel.recordedRequests(); len(requests) != 0 {
		t.Fatalf("canceled Start reached Ensure: %#v", requests)
	}
}

func TestWorkerdManagerLauncherConcurrentStartsUseUnaliasedArgumentsAndDoNotSerializeEnsure(t *testing.T) {
	const callers = 32
	lowLevel := &managerAdapterGatedEnsurer{
		entered: make(chan WorkerdEnsureRequest, callers),
		gate:    make(chan struct{}),
	}
	defer lowLevel.releaseOnce.Do(func() { close(lowLevel.gate) })
	launcher, err := newWorkerdManagerLauncher(lowLevel, []string{"serve", "--fixed"})
	if err != nil {
		t.Fatalf("newWorkerdManagerLauncher() error = %v", err)
	}
	processID := newManagerAdapterIdentity(t, identity.Process)
	results := make(chan error, callers)
	for index := range callers {
		index := index
		go func() {
			_, startErr := launcher.Start(context.Background(), ShardSpec{
				AgentInstanceID: processID,
				ShardID:         "concurrent-shard-" + string(rune('a'+index)),
				ShardGeneration: ShardGeneration(index + 1),
			})
			results <- startErr
		}()
	}

	argumentAddresses := make(map[*string]struct{}, callers)
	for range callers {
		select {
		case request := <-lowLevel.entered:
			if request.AgentInstanceID != processID {
				t.Fatalf("concurrent Ensure AgentInstanceID = %q, want %q", request.AgentInstanceID, processID)
			}
			if len(request.Arguments) != 2 || request.Arguments[0] != "serve" || request.Arguments[1] != "--fixed" {
				t.Fatalf("concurrent Ensure arguments = %#v", request.Arguments)
			}
			address := &request.Arguments[0]
			if _, aliased := argumentAddresses[address]; aliased {
				t.Fatalf("concurrent Ensure requests share argv backing storage at %p", address)
			}
			argumentAddresses[address] = struct{}{}
		case <-time.After(3 * time.Second):
			t.Fatalf("only %d/%d Ensure callbacks entered before release", len(argumentAddresses), callers)
		}
	}
	lowLevel.releaseOnce.Do(func() { close(lowLevel.gate) })
	for range callers {
		select {
		case startErr := <-results:
			if startErr != nil {
				t.Fatalf("Start() error = %v", startErr)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for concurrent Start result")
		}
	}
}

type managerAdapterContextKey struct{}

func newManagerAdapterIdentity(t *testing.T, kind identity.Kind) identity.ID {
	t.Helper()
	id, err := identity.New(kind)
	if err != nil {
		t.Fatalf("identity.New(%q) error = %v", kind, err)
	}
	return id
}

func newManagerAdapterHandle(agentInstanceID identity.ID, shardID string, shardGeneration ShardGeneration) *WorkerdShardHandle {
	return &WorkerdShardHandle{instance: &workerdInstance{key: workerdLaunchKey{
		agentInstanceID: agentInstanceID,
		shardID:         shardID,
		generation:      shardGeneration,
	}}}
}
