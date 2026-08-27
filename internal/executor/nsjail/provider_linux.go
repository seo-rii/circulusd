//go:build linux

package nsjail

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"sync"

	"github.com/hancomac/circulusd/internal/executor"
	"github.com/hancomac/circulusd/internal/identity"
)

var ErrProviderConfig = errors.New("invalid NsJail provider configuration")

// ControlSession is an authenticated, generation-bound sandboxd session.
// Close must be safe when lifecycle fencing races an in-flight operation.
type ControlSession interface {
	io.Closer
}

// HandshakeBroker is deliberately both the launcher's raw nonce registry and
// the readiness boundary. This prevents a provider from registering a nonce
// in one broker while authenticating sandboxd through another.
type HandshakeBroker interface {
	HandshakeNonceRegistry
	AwaitReady(context.Context, identity.ID, uint64) (ControlSession, error)
}

// HostCapability is the fail-closed result of probing namespaces, cgroup v2,
// seccomp, the pinned NsJail binary, and any other mandatory host primitive.
type HostCapability struct {
	Available         bool
	UnavailableReason string
}

type CapabilityProbe interface {
	Probe(context.Context) (HostCapability, error)
}

type CapabilityProbeFunc func(context.Context) (HostCapability, error)

func (function CapabilityProbeFunc) Probe(ctx context.Context) (HostCapability, error) {
	return function(ctx)
}

// ResolvedLaunch is trusted executord metadata resolved from immutable
// environment, resource, and policy digests. It contains no host path.
type ResolvedLaunch struct {
	RootfsDigest         string
	SeccompProfileDigest string
	SandboxdDigest       string
	HostUID              uint32
	HostGID              uint32
	Network              NetworkMode
	Resources            ResourceLimits
}

type RequestResolver interface {
	Resolve(context.Context, executor.SandboxSpec) (ResolvedLaunch, error)
}

type RequestResolverFunc func(context.Context, executor.SandboxSpec) (ResolvedLaunch, error)

func (function RequestResolverFunc) Resolve(
	ctx context.Context,
	spec executor.SandboxSpec,
) (ResolvedLaunch, error) {
	return function(ctx, spec)
}

// ProviderConfig contains only trusted executord bootstrap dependencies.
// NewProvider constructs the Planner and Launcher together so their broker and
// protocol contracts cannot be accidentally split.
type ProviderConfig struct {
	Planner  Config
	Broker   HandshakeBroker
	Resolver RequestResolver
	Probe    CapabilityProbe
	Random   io.Reader
	Faults   executor.FaultInjector
}

// ControlOperation executes against one authenticated sandboxd session. The
// supplied context is canceled as soon as the sandbox generation is fenced.
type ControlOperation func(context.Context, ControlSession) error

type sandboxInstance interface {
	Wait(context.Context) error
	Kill(context.Context) error
	Destroy(context.Context) error
}

type providerDependencies struct {
	build           func(Request) (LaunchPlan, error)
	start           func(context.Context, LaunchPlan) (sandboxInstance, error)
	resolve         RequestResolver
	ready           func(context.Context, identity.ID, uint64) (ControlSession, error)
	probe           func(context.Context) (HostCapability, error)
	newSandboxID    func() (identity.ID, error)
	protocolVersion uint32
	faults          executor.FaultInjector
}

// Provider is the production lifecycle and admission adapter around Planner,
// Launcher, and the private sandboxd handshake broker.
type Provider struct {
	mu sync.Mutex

	dependencies   providerDependencies
	handles        *executor.HandleIssuer
	nextSlotID     uint64
	nextGeneration uint64

	byKey       map[executor.CacheKey]*sandboxRecord
	bySlot      map[uint64]*sandboxRecord
	fences      map[executor.CacheKey]executor.LaunchFence
	authorities map[executor.CacheKey]executor.LaunchAuthority
	inflight    map[executor.CacheKey]*ensureCall
}

type sandboxRecord struct {
	slotID     uint64
	generation uint64
	sandboxID  identity.ID
	cacheKey   executor.CacheKey
	spec       executor.SandboxSpec
	fence      executor.LaunchFence
	state      executor.LifecycleState
	runtime    *instanceRuntime
	session    ControlSession
	sessionMu  sync.Mutex
	sessionOff bool

	operationsContext context.Context
	cancelOperations  context.CancelFunc
	stopAttempt       *lifecycleAttempt
	destroyAttempt    *lifecycleAttempt
}

type instanceRuntime struct {
	instance sandboxInstance
	done     chan struct{}
	waitErr  error
}

type ensureCall struct {
	done   chan struct{}
	record *sandboxRecord
	err    error
}

type lifecycleAttempt struct {
	done chan struct{}
	err  error
}

func NewProvider(config ProviderConfig) (*Provider, error) {
	planner, err := NewPlanner(config.Planner)
	if err != nil {
		return nil, err
	}
	if isNilInterface(config.Broker) || isNilInterface(config.Resolver) || isNilInterface(config.Probe) ||
		(config.Faults != nil && isNilInterface(config.Faults)) {
		return nil, fmt.Errorf("%w: broker, resolver, and host probe are mandatory", ErrProviderConfig)
	}
	launcher := NewLauncher(config.Broker)
	generator := identity.Generator{Random: config.Random}
	return newProvider(providerDependencies{
		build: planner.Build,
		start: func(ctx context.Context, plan LaunchPlan) (sandboxInstance, error) {
			return launcher.Start(ctx, plan)
		},
		resolve: config.Resolver,
		ready:   config.Broker.AwaitReady,
		probe:   config.Probe.Probe,
		newSandboxID: func() (identity.ID, error) {
			return generator.New(identity.Sandbox)
		},
		protocolVersion: config.Planner.ProtocolVersion,
		faults:          config.Faults,
	})
}

func newProvider(dependencies providerDependencies) (*Provider, error) {
	if dependencies.build == nil || dependencies.start == nil || isNilInterface(dependencies.resolve) ||
		dependencies.ready == nil || dependencies.probe == nil || dependencies.newSandboxID == nil ||
		dependencies.protocolVersion == 0 ||
		(dependencies.faults != nil && isNilInterface(dependencies.faults)) {
		return nil, fmt.Errorf("%w: incomplete provider dependencies", ErrProviderConfig)
	}
	return &Provider{
		dependencies: dependencies,
		handles:      executor.NewHandleIssuer(),
		byKey:        make(map[executor.CacheKey]*sandboxRecord),
		bySlot:       make(map[uint64]*sandboxRecord),
		fences:       make(map[executor.CacheKey]executor.LaunchFence),
		authorities:  make(map[executor.CacheKey]executor.LaunchAuthority),
		inflight:     make(map[executor.CacheKey]*ensureCall),
	}, nil
}

func (provider *Provider) Capabilities(
	ctx context.Context,
	mode executor.DeploymentMode,
) (executor.Capability, error) {
	capability := executor.Capability{Backend: executor.BackendNsJail}
	if provider == nil || ctx == nil {
		return capability, fmt.Errorf("%w: nil provider or context", ErrProviderConfig)
	}
	if err := provider.inject(ctx, executor.FaultCapabilities, executor.FaultMetadata{Backend: executor.BackendNsJail}); err != nil {
		return capability, err
	}
	switch mode {
	case executor.DeploymentDevelopment, executor.DeploymentProduction:
	default:
		capability.UnavailableReason = fmt.Sprintf("unsupported deployment mode %q", mode)
		return capability, nil
	}
	host, err := provider.dependencies.probe(ctx)
	if err = errors.Join(err, ctx.Err()); err != nil {
		return capability, err
	}
	if err := validateHostCapability(host); err != nil {
		return capability, err
	}
	if !host.Available {
		if host.UnavailableReason == "" {
			host.UnavailableReason = "mandatory NsJail host capabilities are unavailable"
		}
		capability.UnavailableReason = host.UnavailableReason
		return capability, nil
	}
	capability.Available = true
	return capability, nil
}

func (provider *Provider) EnsureSandbox(
	ctx context.Context,
	request executor.EnsureRequest,
) (result executor.EnsureResult, returnErr error) {
	if provider == nil || ctx == nil {
		return executor.EnsureResult{}, fmt.Errorf("%w: nil provider or context", ErrProviderConfig)
	}
	if err := ctx.Err(); err != nil {
		return executor.EnsureResult{}, err
	}
	if request.Mode != executor.DeploymentDevelopment && request.Mode != executor.DeploymentProduction {
		return executor.EnsureResult{}, fmt.Errorf("%w: unsupported deployment mode %q", executor.ErrUnavailable, request.Mode)
	}
	if request.Spec.Backend != executor.BackendNsJail {
		return executor.EnsureResult{}, fmt.Errorf("%w: NsJail provider cannot satisfy backend %q", executor.ErrBackendMismatch, request.Spec.Backend)
	}
	if request.Spec.Projection != executor.ProjectionMaterializedManifest {
		return executor.EnsureResult{}, fmt.Errorf("%w: NsJail provider requires materialized workspace projection", executor.ErrInvalidSpec)
	}
	if request.Spec.SandboxProtocolVersion != provider.dependencies.protocolVersion {
		return executor.EnsureResult{}, fmt.Errorf("%w: sandbox protocol version mismatch", executor.ErrInvalidSpec)
	}
	cacheKey, err := request.Spec.CanonicalCacheKey()
	if err != nil {
		return executor.EnsureResult{}, err
	}
	host, err := provider.dependencies.probe(ctx)
	if err = errors.Join(err, ctx.Err()); err != nil {
		return executor.EnsureResult{}, err
	}
	if err := validateHostCapability(host); err != nil {
		return executor.EnsureResult{}, err
	}
	if !host.Available {
		if host.UnavailableReason == "" {
			host.UnavailableReason = "mandatory NsJail host capabilities are unavailable"
		}
		return executor.EnsureResult{}, fmt.Errorf("%w: %s", executor.ErrUnavailable, host.UnavailableReason)
	}
	candidateFence, err := executor.NewLaunchFence(request.Spec.LaunchAuthority)
	if err != nil {
		return executor.EnsureResult{}, err
	}

	for {
		provider.mu.Lock()
		currentFence, fenceExists := provider.fences[cacheKey]
		if fenceExists {
			candidateFence, err = currentFence.Admit(request.Spec.LaunchAuthority)
			if err != nil {
				provider.mu.Unlock()
				return executor.EnsureResult{}, err
			}
		}
		authorityAdvanced := !fenceExists || candidateFence.Generation() > currentFence.Generation()
		provider.fences[cacheKey] = candidateFence
		provider.authorities[cacheKey] = request.Spec.LaunchAuthority

		existing := provider.byKey[cacheKey]
		if existing != nil && authorityAdvanced {
			existing.fence = candidateFence
			existing.spec.LaunchAuthority = request.Spec.LaunchAuthority
			if existing.state == executor.LifecycleReady || existing.state == executor.LifecycleDraining {
				existing.cancelOperations()
				existing.operationsContext, existing.cancelOperations = context.WithCancel(context.Background())
			}
		}
		if existing != nil {
			switch existing.state {
			case executor.LifecycleReady:
				handle, handleErr := provider.handleFor(existing)
				provider.mu.Unlock()
				if handleErr != nil {
					return executor.EnsureResult{}, handleErr
				}
				return executor.EnsureResult{Handle: handle, CacheKey: cacheKey, Reused: true}, nil
			case executor.LifecycleDraining:
				provider.mu.Unlock()
				return executor.EnsureResult{}, executor.ErrSandboxDraining
			case executor.LifecycleStopped:
				provider.mu.Unlock()
				return executor.EnsureResult{}, executor.ErrSandboxStopped
			case executor.LifecycleDestroyed:
			}
		}

		if call := provider.inflight[cacheKey]; call != nil {
			done := call.done
			provider.mu.Unlock()
			select {
			case <-done:
				if call.err != nil {
					return executor.EnsureResult{}, call.err
				}
				continue
			case <-ctx.Done():
				return executor.EnsureResult{}, ctx.Err()
			}
		}

		call := &ensureCall{done: make(chan struct{})}
		provider.inflight[cacheKey] = call
		previous := existing
		var slotID uint64
		var sandboxID identity.ID
		if previous == nil {
			provider.nextSlotID++
			slotID = provider.nextSlotID
		} else {
			slotID = previous.slotID
			sandboxID = previous.sandboxID
		}
		provider.nextGeneration++
		generation := provider.nextGeneration
		provider.mu.Unlock()

		var published *sandboxRecord
		var creationErr error
		defer func() {
			provider.mu.Lock()
			call.record = published
			call.err = creationErr
			delete(provider.inflight, cacheKey)
			close(call.done)
			provider.mu.Unlock()
		}()

		if generation == 0 || generation > maximumSharedGeneration {
			creationErr = fmt.Errorf("%w: sandbox generation space exhausted", ErrLaunchFailed)
			return executor.EnsureResult{}, creationErr
		}
		if sandboxID.String() == "" {
			sandboxID, creationErr = provider.dependencies.newSandboxID()
			if creationErr != nil || sandboxID.Kind() != identity.Sandbox || sandboxID.String() == "" {
				if creationErr == nil {
					creationErr = errors.New("sandbox identity generator returned an invalid identity")
				}
				creationErr = fmt.Errorf("%w: %w", ErrLaunchFailed, creationErr)
				return executor.EnsureResult{}, creationErr
			}
		}
		if creationErr = provider.inject(ctx, executor.FaultEnsure, executor.FaultMetadata{
			Backend:  executor.BackendNsJail,
			CacheKey: cacheKey,
			State:    executor.LifecycleReady,
		}); creationErr != nil {
			return executor.EnsureResult{}, creationErr
		}
		resolved, resolveErr := provider.dependencies.resolve.Resolve(ctx, request.Spec)
		if resolveErr != nil {
			creationErr = resolveErr
			return executor.EnsureResult{}, creationErr
		}
		if creationErr = ctx.Err(); creationErr != nil {
			return executor.EnsureResult{}, creationErr
		}
		if resolved.Resources.MaximumLifetimeSeconds == 0 ||
			request.Spec.MaximumLifetimeSeconds < resolved.Resources.MaximumLifetimeSeconds {
			resolved.Resources.MaximumLifetimeSeconds = request.Spec.MaximumLifetimeSeconds
		}
		plan, buildErr := provider.dependencies.build(Request{
			SandboxID:            sandboxID,
			Generation:           generation,
			RootfsDigest:         resolved.RootfsDigest,
			SeccompProfileDigest: resolved.SeccompProfileDigest,
			SandboxdDigest:       resolved.SandboxdDigest,
			HostUID:              resolved.HostUID,
			HostGID:              resolved.HostGID,
			WorkspaceAccess:      request.Spec.WorkspaceAccess,
			Network:              resolved.Network,
			Resources:            resolved.Resources,
		})
		if buildErr != nil {
			creationErr = buildErr
			return executor.EnsureResult{}, creationErr
		}
		if creationErr = ctx.Err(); creationErr != nil {
			return executor.EnsureResult{}, creationErr
		}
		instance, startErr := provider.dependencies.start(ctx, plan)
		if startErr != nil || isNilInterface(instance) {
			if !isNilInterface(instance) {
				startErr = errors.Join(startErr, instance.Destroy(context.Background()))
			}
			if startErr == nil {
				startErr = errors.New("launcher returned a nil instance")
			}
			creationErr = fmt.Errorf("%w: %w", ErrLaunchFailed, startErr)
			return executor.EnsureResult{}, creationErr
		}

		runtime := &instanceRuntime{instance: instance, done: make(chan struct{})}
		go func() {
			runtime.waitErr = instance.Wait(context.Background())
			close(runtime.done)
		}()
		readyContext, cancelReady := context.WithCancel(ctx)
		go func() {
			select {
			case <-runtime.done:
				cancelReady()
			case <-readyContext.Done():
			}
		}()
		session, readyErr := provider.dependencies.ready(readyContext, sandboxID, generation)
		cancelReady()
		if readyErr == nil && isNilInterface(session) {
			readyErr = fmt.Errorf("%w: handshake broker returned a nil control session", ErrLaunchFailed)
		}
		readyErr = errors.Join(readyErr, ctx.Err())
		select {
		case <-runtime.done:
			readyErr = errors.Join(
				readyErr,
				fmt.Errorf("%w: sandboxd exited before readiness: %v", ErrLaunchFailed, runtime.waitErr),
			)
		default:
		}
		if readyErr != nil {
			if !isNilInterface(session) {
				_ = session.Close()
			}
			cleanupErr := instance.Destroy(context.Background())
			creationErr = errors.Join(readyErr, cleanupErr)
			return executor.EnsureResult{}, creationErr
		}

		operationsContext, cancelOperations := context.WithCancel(context.Background())
		provider.mu.Lock()
		publishedSpec := request.Spec
		publishedSpec.LaunchAuthority = provider.authorities[cacheKey]
		published = &sandboxRecord{
			slotID:            slotID,
			generation:        generation,
			sandboxID:         sandboxID,
			cacheKey:          cacheKey,
			spec:              publishedSpec,
			fence:             provider.fences[cacheKey],
			state:             executor.LifecycleReady,
			runtime:           runtime,
			session:           session,
			operationsContext: operationsContext,
			cancelOperations:  cancelOperations,
		}
		provider.byKey[cacheKey] = published
		provider.bySlot[slotID] = published
		handle, handleErr := provider.handleFor(published)
		authorized := published.fence.Authorizes(request.Spec.LaunchAuthority)
		provider.mu.Unlock()
		if handleErr != nil {
			creationErr = handleErr
			_ = session.Close()
			_ = instance.Destroy(context.Background())
			return executor.EnsureResult{}, creationErr
		}
		go provider.monitor(published)
		if !authorized {
			return executor.EnsureResult{}, executor.ErrStaleAuthority
		}
		return executor.EnsureResult{Handle: handle, CacheKey: cacheKey}, nil
	}
}

// Execute holds no raw process or host path. It leases the authenticated
// control session only while the exact sandbox and authority generation remain
// ready, and rechecks both fences before reporting success.
func (provider *Provider) Execute(
	ctx context.Context,
	handle executor.SandboxHandle,
	authority executor.LaunchAuthority,
	operation ControlOperation,
) error {
	if provider == nil || ctx == nil || operation == nil {
		return fmt.Errorf("%w: nil provider, context, or control operation", ErrProviderConfig)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	provider.mu.Lock()
	record, err := provider.recordForHandle(handle)
	if err != nil {
		provider.mu.Unlock()
		return err
	}
	if !record.fence.Authorizes(authority) {
		provider.mu.Unlock()
		return executor.ErrStaleAuthority
	}
	if record.state != executor.LifecycleReady {
		stateErr := lifecycleStateError(record.state)
		provider.mu.Unlock()
		return stateErr
	}
	operationsContext := record.operationsContext
	session := record.session
	provider.mu.Unlock()

	operationContext, cancelOperation := context.WithCancel(ctx)
	stopFence := context.AfterFunc(operationsContext, cancelOperation)
	operationErr := operation(operationContext, session)
	stopFence()
	cancelOperation()

	provider.mu.Lock()
	current, currentErr := provider.recordForHandle(handle)
	if currentErr == nil && !current.fence.Authorizes(authority) {
		currentErr = executor.ErrStaleAuthority
	}
	if currentErr == nil && current.state != executor.LifecycleReady {
		currentErr = lifecycleStateError(current.state)
	}
	provider.mu.Unlock()
	return errors.Join(operationErr, ctx.Err(), currentErr)
}

func (provider *Provider) Stop(ctx context.Context, handle executor.SandboxHandle) error {
	if provider == nil || ctx == nil {
		return fmt.Errorf("%w: nil provider or context", ErrProviderConfig)
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		provider.mu.Lock()
		record, err := provider.recordForHandle(handle)
		if err != nil {
			provider.mu.Unlock()
			return err
		}
		switch record.state {
		case executor.LifecycleStopped, executor.LifecycleDestroyed:
			provider.mu.Unlock()
			return nil
		case executor.LifecycleReady, executor.LifecycleDraining:
		}
		if record.stopAttempt != nil {
			attempt := record.stopAttempt
			provider.mu.Unlock()
			return waitLifecycleAttempt(ctx, attempt)
		}
		attempt := &lifecycleAttempt{done: make(chan struct{})}
		record.stopAttempt = attempt
		record.state = executor.LifecycleDraining
		metadata := executor.FaultMetadata{
			Backend:  executor.BackendNsJail,
			CacheKey: record.cacheKey,
			Handle:   handle,
			State:    executor.LifecycleDraining,
		}
		provider.mu.Unlock()

		if injectedErr := provider.inject(ctx, executor.FaultStopDraining, metadata); injectedErr != nil {
			provider.mu.Lock()
			runtimeStopped := false
			select {
			case <-record.runtime.done:
				runtimeStopped = true
			default:
				record.state = executor.LifecycleReady
			}
			if !runtimeStopped {
				record.stopAttempt = nil
				attempt.err = injectedErr
				close(attempt.done)
			}
			provider.mu.Unlock()
			if !runtimeStopped {
				return injectedErr
			}

			closeErr := record.closeSession()
			provider.mu.Lock()
			record.state = executor.LifecycleStopped
			record.stopAttempt = nil
			attempt.err = errors.Join(injectedErr, closeErr)
			close(attempt.done)
			provider.mu.Unlock()
			return attempt.err
		}

		record.cancelOperations()
		go func() {
			killErr := record.runtime.instance.Kill(context.Background())
			if killErr == nil {
				<-record.runtime.done
			}
			closeErr := record.closeSession()
			stopErr := errors.Join(killErr, closeErr)
			provider.mu.Lock()
			if stopErr == nil {
				record.state = executor.LifecycleStopped
			} else {
				record.state = executor.LifecycleDraining
			}
			record.stopAttempt = nil
			attempt.err = stopErr
			close(attempt.done)
			provider.mu.Unlock()
		}()
		return waitLifecycleAttempt(ctx, attempt)
	}
}

func (provider *Provider) Destroy(ctx context.Context, handle executor.SandboxHandle) error {
	if provider == nil || ctx == nil {
		return fmt.Errorf("%w: nil provider or context", ErrProviderConfig)
	}
	for {
		if err := provider.Stop(ctx, handle); err != nil {
			return err
		}
		provider.mu.Lock()
		record, err := provider.recordForHandle(handle)
		if err != nil {
			provider.mu.Unlock()
			return err
		}
		if record.state == executor.LifecycleDestroyed {
			provider.mu.Unlock()
			return nil
		}
		if record.destroyAttempt != nil {
			attempt := record.destroyAttempt
			provider.mu.Unlock()
			return waitLifecycleAttempt(ctx, attempt)
		}
		attempt := &lifecycleAttempt{done: make(chan struct{})}
		record.destroyAttempt = attempt
		metadata := executor.FaultMetadata{
			Backend:  executor.BackendNsJail,
			CacheKey: record.cacheKey,
			Handle:   handle,
			State:    executor.LifecycleStopped,
		}
		provider.mu.Unlock()

		if injectedErr := provider.inject(ctx, executor.FaultDestroy, metadata); injectedErr != nil {
			provider.mu.Lock()
			record.destroyAttempt = nil
			attempt.err = injectedErr
			close(attempt.done)
			provider.mu.Unlock()
			return injectedErr
		}
		go func() {
			destroyErr := record.runtime.instance.Destroy(context.Background())
			destroyErr = errors.Join(destroyErr, record.closeSession())
			provider.mu.Lock()
			if destroyErr == nil {
				record.state = executor.LifecycleDestroyed
			}
			record.destroyAttempt = nil
			attempt.err = destroyErr
			close(attempt.done)
			provider.mu.Unlock()
		}()
		return waitLifecycleAttempt(ctx, attempt)
	}
}

func (provider *Provider) Health(
	ctx context.Context,
	handle executor.SandboxHandle,
) (executor.SandboxHealth, error) {
	if provider == nil || ctx == nil {
		return executor.SandboxHealth{}, fmt.Errorf("%w: nil provider or context", ErrProviderConfig)
	}
	if err := provider.inject(ctx, executor.FaultHealth, executor.FaultMetadata{
		Backend: executor.BackendNsJail,
		Handle:  handle,
	}); err != nil {
		return executor.SandboxHealth{}, err
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	record, err := provider.recordForHandle(handle)
	if err != nil {
		return executor.SandboxHealth{}, err
	}
	return executor.SandboxHealth{
		Handle:        handle,
		State:         record.state,
		Healthy:       record.state == executor.LifecycleReady,
		AcceptingWork: record.state == executor.LifecycleReady,
	}, nil
}

func (provider *Provider) Snapshot(ctx context.Context) ([]executor.SandboxSnapshot, error) {
	if provider == nil || ctx == nil {
		return nil, fmt.Errorf("%w: nil provider or context", ErrProviderConfig)
	}
	if err := provider.inject(ctx, executor.FaultSnapshot, executor.FaultMetadata{Backend: executor.BackendNsJail}); err != nil {
		return nil, err
	}
	provider.mu.Lock()
	snapshot := make([]executor.SandboxSnapshot, 0, len(provider.byKey))
	for _, record := range provider.byKey {
		handle, err := provider.handleFor(record)
		if err != nil {
			provider.mu.Unlock()
			return nil, err
		}
		snapshot = append(snapshot, executor.SandboxSnapshot{
			Handle:   handle,
			CacheKey: record.cacheKey,
			Spec:     record.spec,
			State:    record.state,
		})
	}
	provider.mu.Unlock()
	sort.Slice(snapshot, func(left, right int) bool {
		return snapshot[left].CacheKey.String() < snapshot[right].CacheKey.String()
	})
	return snapshot, nil
}

func (provider *Provider) monitor(record *sandboxRecord) {
	<-record.runtime.done
	provider.mu.Lock()
	current := provider.bySlot[record.slotID]
	closeSession := false
	if current == record && current.generation == record.generation && current.state == executor.LifecycleReady {
		current.cancelOperations()
		current.state = executor.LifecycleStopped
		closeSession = true
	}
	provider.mu.Unlock()
	if closeSession {
		_ = record.closeSession()
	}
}

func (provider *Provider) inject(
	ctx context.Context,
	point executor.FaultPoint,
	metadata executor.FaultMetadata,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if provider.dependencies.faults == nil {
		return ctx.Err()
	}
	return errors.Join(provider.dependencies.faults.Inject(ctx, point, metadata), ctx.Err())
}

func (record *sandboxRecord) closeSession() error {
	record.sessionMu.Lock()
	defer record.sessionMu.Unlock()
	if record.sessionOff {
		return nil
	}
	err := record.session.Close()
	if err == nil {
		record.sessionOff = true
	}
	return err
}

func (provider *Provider) recordForHandle(handle executor.SandboxHandle) (*sandboxRecord, error) {
	slotID, generation, err := provider.handles.Resolve(handle)
	if err != nil {
		return nil, err
	}
	record := provider.bySlot[slotID]
	if record == nil {
		return nil, executor.ErrUnknownHandle
	}
	if record.generation != generation {
		return nil, executor.ErrStaleHandle
	}
	return record, nil
}

func (provider *Provider) handleFor(record *sandboxRecord) (executor.SandboxHandle, error) {
	return provider.handles.Issue(record.slotID, record.generation)
}

func waitLifecycleAttempt(ctx context.Context, attempt *lifecycleAttempt) error {
	select {
	case <-attempt.done:
		return attempt.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func lifecycleStateError(state executor.LifecycleState) error {
	switch state {
	case executor.LifecycleDraining:
		return executor.ErrSandboxDraining
	case executor.LifecycleStopped, executor.LifecycleDestroyed:
		return executor.ErrSandboxStopped
	default:
		return fmt.Errorf("%w: invalid sandbox lifecycle state %q", ErrProviderConfig, state)
	}
}

func validateHostCapability(capability HostCapability) error {
	if capability.Available && capability.UnavailableReason != "" {
		return fmt.Errorf("%w: available host capability carried an unavailable reason", ErrProviderConfig)
	}
	return nil
}

func isNilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var _ executor.Provider = (*Provider)(nil)
