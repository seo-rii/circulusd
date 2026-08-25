package executor

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
)

var mockProviderSequence atomic.Uint64

// MockProvider is a thread-safe, process-free development implementation of
// Provider. It is suitable for state-machine and fault-recovery tests only.
// Production admission and every non-mock backend fail closed.
type MockProvider struct {
	mu sync.Mutex

	providerID     uint64
	nextSlotID     uint64
	nextGeneration uint64
	faults         FaultInjector

	byKey    map[CacheKey]*mockSandbox
	bySlot   map[uint64]*mockSandbox
	inflight map[CacheKey]*mockEnsureCall
}

type mockSandbox struct {
	slotID      uint64
	generation  uint64
	cacheKey    CacheKey
	spec        SandboxSpec
	state       LifecycleState
	stopDone    chan struct{}
	destroyDone chan struct{}
}

type mockEnsureCall struct {
	done   chan struct{}
	result EnsureResult
	err    error
}

// NewDevelopmentMockProvider constructs an isolated provider instance. A nil
// injector disables fault injection.
func NewDevelopmentMockProvider(faults FaultInjector) *MockProvider {
	return &MockProvider{
		providerID: mockProviderSequence.Add(1),
		faults:     faults,
		byKey:      make(map[CacheKey]*mockSandbox),
		bySlot:     make(map[uint64]*mockSandbox),
		inflight:   make(map[CacheKey]*mockEnsureCall),
	}
}

func (provider *MockProvider) Capabilities(
	ctx context.Context,
	mode DeploymentMode,
) (Capability, error) {
	if err := provider.inject(ctx, FaultCapabilities, FaultMetadata{Backend: BackendMock}); err != nil {
		return Capability{}, err
	}

	capability := Capability{
		Backend:         BackendMock,
		DevelopmentOnly: true,
	}
	switch mode {
	case DeploymentDevelopment:
		capability.Available = true
	case DeploymentProduction:
		capability.UnavailableReason = "mock execution provider is development-only"
	default:
		capability.UnavailableReason = fmt.Sprintf("unsupported deployment mode %q", mode)
	}
	return capability, nil
}

func (provider *MockProvider) EnsureSandbox(
	ctx context.Context,
	request EnsureRequest,
) (EnsureResult, error) {
	if err := ctx.Err(); err != nil {
		return EnsureResult{}, err
	}
	if request.Mode != DeploymentDevelopment {
		return EnsureResult{}, fmt.Errorf(
			"%w: %w: mock backend cannot admit %q requests",
			ErrUnavailable,
			ErrDevelopmentOnly,
			request.Mode,
		)
	}
	if request.Spec.Backend != BackendMock {
		return EnsureResult{}, fmt.Errorf(
			"%w: mock provider cannot satisfy backend %q",
			ErrBackendMismatch,
			request.Spec.Backend,
		)
	}

	cacheKey, err := request.Spec.CanonicalCacheKey()
	if err != nil {
		return EnsureResult{}, err
	}

	provider.mu.Lock()
	if sandbox := provider.byKey[cacheKey]; sandbox != nil {
		switch sandbox.state {
		case LifecycleReady:
			result := EnsureResult{
				Handle:   provider.handleFor(sandbox),
				CacheKey: cacheKey,
				Reused:   true,
			}
			provider.mu.Unlock()
			return result, nil
		case LifecycleDraining:
			provider.mu.Unlock()
			return EnsureResult{}, ErrSandboxDraining
		case LifecycleStopped:
			provider.mu.Unlock()
			return EnsureResult{}, ErrSandboxStopped
		case LifecycleDestroyed:
		}
	}

	if call := provider.inflight[cacheKey]; call != nil {
		provider.mu.Unlock()
		select {
		case <-call.done:
			if call.err != nil {
				return EnsureResult{}, call.err
			}
			result := call.result
			result.Reused = true
			return result, nil
		case <-ctx.Done():
			return EnsureResult{}, ctx.Err()
		}
	}

	call := &mockEnsureCall{done: make(chan struct{})}
	provider.inflight[cacheKey] = call
	previous := provider.byKey[cacheKey]
	provider.mu.Unlock()

	err = provider.inject(ctx, FaultEnsure, FaultMetadata{
		Backend:  BackendMock,
		CacheKey: cacheKey,
		State:    LifecycleReady,
	})

	provider.mu.Lock()
	if err == nil {
		var slotID uint64
		if previous == nil {
			provider.nextSlotID++
			slotID = provider.nextSlotID
		} else {
			slotID = previous.slotID
		}
		provider.nextGeneration++
		sandbox := &mockSandbox{
			slotID:     slotID,
			generation: provider.nextGeneration,
			cacheKey:   cacheKey,
			spec:       request.Spec,
			state:      LifecycleReady,
		}
		provider.byKey[cacheKey] = sandbox
		provider.bySlot[slotID] = sandbox
		call.result = EnsureResult{
			Handle:   provider.handleFor(sandbox),
			CacheKey: cacheKey,
		}
	} else {
		call.err = err
	}
	delete(provider.inflight, cacheKey)
	close(call.done)
	result := call.result
	callErr := call.err
	provider.mu.Unlock()
	return result, callErr
}

func (provider *MockProvider) Stop(ctx context.Context, handle SandboxHandle) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		provider.mu.Lock()
		sandbox, err := provider.sandboxForHandle(handle)
		if err != nil {
			provider.mu.Unlock()
			return err
		}
		switch sandbox.state {
		case LifecycleStopped, LifecycleDestroyed:
			provider.mu.Unlock()
			return nil
		case LifecycleDraining:
			done := sandbox.stopDone
			provider.mu.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		case LifecycleReady:
			sandbox.state = LifecycleDraining
			sandbox.stopDone = make(chan struct{})
			done := sandbox.stopDone
			metadata := FaultMetadata{
				Backend:  BackendMock,
				CacheKey: sandbox.cacheKey,
				Handle:   handle,
				State:    LifecycleDraining,
			}
			provider.mu.Unlock()

			injectedErr := provider.inject(ctx, FaultStopDraining, metadata)

			provider.mu.Lock()
			if injectedErr != nil {
				sandbox.state = LifecycleReady
			} else {
				sandbox.state = LifecycleStopped
			}
			sandbox.stopDone = nil
			close(done)
			provider.mu.Unlock()
			return injectedErr
		}
	}
}

func (provider *MockProvider) Destroy(ctx context.Context, handle SandboxHandle) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		provider.mu.Lock()
		sandbox, err := provider.sandboxForHandle(handle)
		if err != nil {
			provider.mu.Unlock()
			return err
		}
		switch sandbox.state {
		case LifecycleDestroyed:
			provider.mu.Unlock()
			return nil
		case LifecycleReady, LifecycleDraining:
			provider.mu.Unlock()
			if err := provider.Stop(ctx, handle); err != nil {
				return err
			}
			continue
		case LifecycleStopped:
			if sandbox.destroyDone != nil {
				done := sandbox.destroyDone
				provider.mu.Unlock()
				select {
				case <-done:
					continue
				case <-ctx.Done():
					return ctx.Err()
				}
			}

			sandbox.destroyDone = make(chan struct{})
			done := sandbox.destroyDone
			metadata := FaultMetadata{
				Backend:  BackendMock,
				CacheKey: sandbox.cacheKey,
				Handle:   handle,
				State:    LifecycleStopped,
			}
			provider.mu.Unlock()

			injectedErr := provider.inject(ctx, FaultDestroy, metadata)

			provider.mu.Lock()
			if injectedErr == nil {
				sandbox.state = LifecycleDestroyed
			}
			sandbox.destroyDone = nil
			close(done)
			provider.mu.Unlock()
			return injectedErr
		}
	}
}

func (provider *MockProvider) Health(
	ctx context.Context,
	handle SandboxHandle,
) (SandboxHealth, error) {
	if err := provider.inject(ctx, FaultHealth, FaultMetadata{
		Backend: BackendMock,
		Handle:  handle,
	}); err != nil {
		return SandboxHealth{}, err
	}

	provider.mu.Lock()
	defer provider.mu.Unlock()
	sandbox, err := provider.sandboxForHandle(handle)
	if err != nil {
		return SandboxHealth{}, err
	}
	return SandboxHealth{
		Handle:        handle,
		State:         sandbox.state,
		Healthy:       sandbox.state == LifecycleReady,
		AcceptingWork: sandbox.state == LifecycleReady,
	}, nil
}

func (provider *MockProvider) Snapshot(ctx context.Context) ([]SandboxSnapshot, error) {
	if err := provider.inject(ctx, FaultSnapshot, FaultMetadata{Backend: BackendMock}); err != nil {
		return nil, err
	}

	provider.mu.Lock()
	snapshot := make([]SandboxSnapshot, 0, len(provider.byKey))
	for _, sandbox := range provider.byKey {
		snapshot = append(snapshot, SandboxSnapshot{
			Handle:   provider.handleFor(sandbox),
			CacheKey: sandbox.cacheKey,
			Spec:     sandbox.spec,
			State:    sandbox.state,
		})
	}
	provider.mu.Unlock()

	sort.Slice(snapshot, func(i, j int) bool {
		return snapshot[i].CacheKey.String() < snapshot[j].CacheKey.String()
	})
	return snapshot, nil
}

func (provider *MockProvider) inject(
	ctx context.Context,
	point FaultPoint,
	metadata FaultMetadata,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if provider.faults == nil {
		return nil
	}
	return provider.faults.Inject(ctx, point, metadata)
}

func (provider *MockProvider) sandboxForHandle(handle SandboxHandle) (*mockSandbox, error) {
	if handle.IsZero() || handle.providerID != provider.providerID {
		return nil, ErrUnknownHandle
	}
	sandbox := provider.bySlot[handle.slotID]
	if sandbox == nil {
		return nil, ErrUnknownHandle
	}
	if sandbox.generation != handle.generation {
		return nil, ErrStaleHandle
	}
	return sandbox, nil
}

func (provider *MockProvider) handleFor(sandbox *mockSandbox) SandboxHandle {
	return SandboxHandle{
		providerID: provider.providerID,
		slotID:     sandbox.slotID,
		generation: sandbox.generation,
	}
}

var _ Provider = (*MockProvider)(nil)
