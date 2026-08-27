//go:build linux

package agent

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var (
	ErrInvalidWorkerdLauncherConfig = errors.New("agent: invalid workerd launcher configuration")
	ErrInvalidWorkerdEnsureRequest  = errors.New("agent: invalid workerd ensure request")
	ErrUnsafeWorkerdExecutable      = errors.New("agent: unsafe workerd executable")
	ErrWorkerdDigestMismatch        = errors.New("agent: workerd executable digest mismatch")
	ErrWorkerdLaunchConflict        = errors.New("agent: workerd shard generation reused with different launch inputs")
	ErrStaleWorkerdGeneration       = errors.New("agent: stale workerd placement generation")
	ErrWorkerdReadinessTimeout      = errors.New("agent: workerd readiness timeout")
	ErrWorkerdExitedBeforeReady     = errors.New("agent: workerd exited before readiness")
	ErrWorkerdNotReady              = errors.New("agent: workerd readiness probe failed")
	ErrWorkerdLaunchFailed          = errors.New("agent: workerd process launch failed")
	ErrWorkerdStopTimeout           = errors.New("agent: workerd process-group stop timeout")
	ErrWorkerdLauncherClosed        = errors.New("agent: workerd process launcher is closed")
	ErrWorkerdHistoryCapacity       = errors.New("agent: workerd launcher history capacity exhausted")
)

const (
	maximumWorkerdReadinessTimeout      = 5 * time.Minute
	maximumWorkerdStopGracePeriod       = 30 * time.Second
	maximumWorkerdOutputLimitBytes      = 1 << 20
	maximumWorkerdEnvironmentValueBytes = 64 << 10
	maximumWorkerdEnvironmentTotalBytes = 256 << 10
	maximumWorkerdArgumentCount         = 128
	maximumWorkerdArgumentBytes         = 64 << 10
	maximumWorkerdArgumentsTotalBytes   = 1 << 20
	maximumWorkerdExecutableBytes       = 256 << 20
	maximumWorkerdHistoryCapacity       = 4096
)

// WorkerdLauncherConfig seals the process-wide launch boundary. Environment
// contains only explicit values selected from the fixed child allowlist; the
// ambient agentd environment is never inherited.
type WorkerdLauncherConfig struct {
	ExecutablePath   string
	ExecutableDigest string
	Environment      map[string]string
	ReadinessTimeout time.Duration
	StopGracePeriod  time.Duration
	OutputLimitBytes int
	HistoryCapacity  int
	ReadinessProbe   WorkerdReadinessProbe
	Cgroup           *WorkerdCgroupConfig
}

// WorkerdCgroupConfig defines the delegated cgroup v2 boundary consumed by a
// production launcher. The root must already exist with the ownership,
// permissions, and enabled controllers enforced by the controller contract.
type WorkerdCgroupConfig struct {
	RootPath       string
	MaximumShards  int
	DrainTimeout   time.Duration
	MemoryMaxBytes uint64
	SwapMaxBytes   uint64
	CPUCores       uint64
	PIDsMax        uint64
}

// WorkerdEnsureRequest is the immutable identity of one shard generation.
// Reusing the same identity with different arguments is rejected.
type WorkerdEnsureRequest struct {
	ShardID             string
	PlacementGeneration uint64
	Arguments           []string
}

// WorkerdProcessInfo is the process identity made available to a readiness
// probe. It is not an admission grant.
type WorkerdProcessInfo struct {
	ShardID             string
	PlacementGeneration uint64
	PID                 int
}

// WorkerdReadinessProbe gates publication of a shard handle. Implementations
// MUST honor ctx promptly; a probe that ignores cancellation can leak its own
// goroutine even though the launcher keeps admission fail closed.
type WorkerdReadinessProbe interface {
	WaitReady(context.Context, WorkerdProcessInfo) error
}

// WorkerdReadinessProbeFunc adapts a function into a readiness probe.
type WorkerdReadinessProbeFunc func(context.Context, WorkerdProcessInfo) error

func (probe WorkerdReadinessProbeFunc) WaitReady(ctx context.Context, info WorkerdProcessInfo) error {
	return probe(ctx, info)
}

// WorkerdLauncherEvidence exposes both implemented launch controls and the
// resource-authority gaps that keep this vertical slice fail closed for
// production admission.
type WorkerdLauncherEvidence struct {
	ExecutableDigest         string
	VerifiedOpenExecutable   bool
	SealedExecutableSnapshot bool
	ProcessGroupTermination  bool
	ExplicitEnvironment      bool
	ChildFDAllowlist         bool
	BoundedOutput            bool
	ReadinessGated           bool
	AtomicCgroupPlacement    bool
	CgroupLimits             bool
	CgroupTermination        bool
	CPUAccounting            bool
	RSSAccounting            bool
	KillReconstruction       bool
	AdmissionReady           bool
	MissingCapabilities      []string
}

// WorkerdOutput is the bounded diagnostic prefix captured for one process.
type WorkerdOutput struct {
	Stdout          string
	Stderr          string
	StdoutTruncated bool
	StderrTruncated bool
}

type workerdLaunchCommand struct {
	Executable          string
	Arguments           []string
	Environment         []string
	ExtraFiles          []*os.File
	CgroupFD            int
	Stdout              io.Writer
	Stderr              io.Writer
	ShardID             string
	PlacementGeneration uint64
}

type workerdProcessStarter interface {
	Start(workerdLaunchCommand) (workerdStartedProcess, error)
}

type workerdMemfdCreator func(string, int) (int, error)

type workerdStartedProcess interface {
	PID() int
	Wait() error
	SignalGroup(syscall.Signal) error
	GroupAlive() (bool, error)
}

type workerdLaunchKey struct {
	shardID    string
	generation uint64
}

type workerdLaunchIdentity [sha256.Size]byte

type workerdPendingLaunch struct {
	key       workerdLaunchKey
	identity  workerdLaunchIdentity
	arguments []string
	done      chan struct{}
	cancel    context.CancelFunc
	ctx       context.Context
	waiters   int
	abandoned bool
	handle    *WorkerdShardHandle
	err       error
}

type workerdStopOperation struct {
	done chan struct{}
	err  error
}

type workerdCloseOperation struct {
	done chan struct{}
	err  error
}

type workerdCgroupAllocation struct {
	key workerdLaunchKey
}

type workerdInstance struct {
	key      workerdLaunchKey
	identity workerdLaunchIdentity
	process  workerdStartedProcess
	stdout   *boundedWorkerdWriter
	stderr   *boundedWorkerdWriter
	exitDone chan struct{}
	cgroup   *workerdCgroupLease

	mu                  sync.Mutex
	exited              bool
	exitErr             error
	stop                *workerdStopOperation
	handleStopRequested bool
	groupGone           bool
	replacementRetired  bool
}

// WorkerdProcessLauncher owns the verified sealed executable snapshot and
// coordinates starts independently per immutable shard generation. This is a
// low-level launcher, not a Launcher implementation: ShardSpec cannot express
// its bounded static arguments or placement generation, and this slice does
// not yet provide the cgroup isolation required for Manager admission.
type WorkerdProcessLauncher struct {
	mu                 sync.Mutex
	executable         *os.File
	executableProcPath string
	executableDigest   string
	environment        []string
	readinessTimeout   time.Duration
	stopGracePeriod    time.Duration
	outputLimitBytes   int
	historyCapacity    int
	readinessProbe     WorkerdReadinessProbe
	starter            workerdProcessStarter
	cgroups            *workerdCgroupController
	pending            map[workerdLaunchKey]*workerdPendingLaunch
	allocations        map[*workerdCgroupLease]workerdCgroupAllocation
	current            map[string]*workerdInstance
	latestGenerations  map[string]uint64
	retiredGenerations map[string]uint64
	launchIdentities   map[workerdLaunchKey]workerdLaunchIdentity
	instances          map[*workerdInstance]struct{}
	closed             bool
	closeOperation     *workerdCloseOperation
	cgroupsClosed      bool
	terminalCloseErr   error
}

// WorkerdShardHandle is returned only after the configured readiness probe
// succeeds. It deliberately does not claim cgroup-backed admission authority.
type WorkerdShardHandle struct {
	launcher *WorkerdProcessLauncher
	instance *workerdInstance
}

var _ ShardProcess = (*WorkerdShardHandle)(nil)

type boundedWorkerdWriter struct {
	mu        sync.Mutex
	limit     int
	data      []byte
	truncated bool
}

// NewWorkerdProcessLauncher constructs the production Linux launcher.
func NewWorkerdProcessLauncher(config WorkerdLauncherConfig) (*WorkerdProcessLauncher, error) {
	if config.Cgroup == nil {
		return nil, ErrInvalidWorkerdLauncherConfig
	}
	cgroups, err := newWorkerdCgroupController(workerdCgroupConfig{
		RootPath:       config.Cgroup.RootPath,
		MaximumShards:  config.Cgroup.MaximumShards,
		DrainTimeout:   config.Cgroup.DrainTimeout,
		MemoryMaxBytes: config.Cgroup.MemoryMaxBytes,
		SwapMaxBytes:   config.Cgroup.SwapMaxBytes,
		CPUCores:       config.Cgroup.CPUCores,
		PIDsMax:        config.Cgroup.PIDsMax,
	})
	if err != nil {
		return nil, err
	}
	return newWorkerdProcessLauncherWithCgroup(config, osWorkerdProcessStarter{}, unix.MemfdCreate, cgroups)
}

func newWorkerdProcessLauncher(config WorkerdLauncherConfig, starter workerdProcessStarter) (*WorkerdProcessLauncher, error) {
	return newWorkerdProcessLauncherWithMemfd(config, starter, unix.MemfdCreate)
}

func newWorkerdProcessLauncherWithMemfd(config WorkerdLauncherConfig, starter workerdProcessStarter, createMemfd workerdMemfdCreator) (*WorkerdProcessLauncher, error) {
	return newWorkerdProcessLauncherWithResources(config, starter, createMemfd, nil)
}

func newWorkerdProcessLauncherWithCgroup(config WorkerdLauncherConfig, starter workerdProcessStarter, createMemfd workerdMemfdCreator, cgroups *workerdCgroupController) (*WorkerdProcessLauncher, error) {
	if cgroups == nil {
		return nil, ErrInvalidWorkerdLauncherConfig
	}
	launcher, err := newWorkerdProcessLauncherWithResources(config, starter, createMemfd, cgroups)
	if err != nil {
		return nil, errors.Join(err, cgroups.close())
	}
	return launcher, nil
}

func newWorkerdProcessLauncherWithResources(config WorkerdLauncherConfig, starter workerdProcessStarter, createMemfd workerdMemfdCreator, cgroups *workerdCgroupController) (*WorkerdProcessLauncher, error) {
	if starter == nil || config.ReadinessProbe == nil || config.ReadinessTimeout <= 0 ||
		config.ReadinessTimeout > maximumWorkerdReadinessTimeout ||
		config.StopGracePeriod <= 0 || config.StopGracePeriod > maximumWorkerdStopGracePeriod ||
		config.OutputLimitBytes <= 0 || config.OutputLimitBytes > maximumWorkerdOutputLimitBytes ||
		config.HistoryCapacity <= 0 || config.HistoryCapacity > maximumWorkerdHistoryCapacity ||
		!filepath.IsAbs(config.ExecutablePath) || filepath.Clean(config.ExecutablePath) != config.ExecutablePath ||
		config.ExecutablePath == string(filepath.Separator) ||
		!validDigest(config.ExecutableDigest) || createMemfd == nil {
		return nil, ErrInvalidWorkerdLauncherConfig
	}
	expectedDigest, err := hex.DecodeString(strings.TrimPrefix(config.ExecutableDigest, "sha256:"))
	if err != nil || len(expectedDigest) != sha256.Size {
		return nil, ErrInvalidWorkerdLauncherConfig
	}

	allowedEnvironment := map[string]struct{}{
		"HOME": {}, "LANG": {}, "LC_ALL": {}, "LC_CTYPE": {}, "TMPDIR": {}, "TZ": {},
	}
	environment := make([]string, 0, len(config.Environment))
	environmentBytes := 0
	for key, value := range config.Environment {
		entryBytes := len(key) + 1 + len(value)
		if _, allowed := allowedEnvironment[key]; !allowed || strings.ContainsRune(value, '\x00') ||
			len(value) > maximumWorkerdEnvironmentValueBytes ||
			environmentBytes > maximumWorkerdEnvironmentTotalBytes-entryBytes {
			return nil, fmt.Errorf("%w: child environment %q is not allowed", ErrInvalidWorkerdLauncherConfig, key)
		}
		environmentBytes += entryBytes
		environment = append(environment, key+"="+value)
	}
	sort.Strings(environment)

	rootFD, err := unix.Open(string(filepath.Separator), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: open filesystem root: %v", ErrUnsafeWorkerdExecutable, err)
	}
	currentFD := rootFD
	components := strings.Split(strings.TrimPrefix(config.ExecutablePath, string(filepath.Separator)), string(filepath.Separator))
	for index, component := range components {
		flags := uint64(unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC)
		if index == len(components)-1 {
			flags = uint64(unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW)
		}
		nextFD, openErr := unix.Openat2(currentFD, component, &unix.OpenHow{
			Flags:   flags,
			Resolve: uint64(unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS),
		})
		_ = unix.Close(currentFD)
		if openErr != nil {
			return nil, fmt.Errorf("%w: open %q: %v", ErrUnsafeWorkerdExecutable, config.ExecutablePath, openErr)
		}
		currentFD = nextFD
	}
	sourceExecutable := os.NewFile(uintptr(currentFD), config.ExecutablePath)
	if sourceExecutable == nil {
		_ = unix.Close(currentFD)
		return nil, fmt.Errorf("%w: wrap opened executable", ErrUnsafeWorkerdExecutable)
	}
	defer sourceExecutable.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(currentFD, &stat); err != nil {
		return nil, fmt.Errorf("%w: stat opened executable: %v", ErrUnsafeWorkerdExecutable, err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o111 == 0 || stat.Mode&0o022 != 0 ||
		stat.Mode&(unix.S_ISUID|unix.S_ISGID) != 0 {
		return nil, fmt.Errorf("%w: executable mode %#o", ErrUnsafeWorkerdExecutable, stat.Mode)
	}
	if stat.Size <= 0 || stat.Size > maximumWorkerdExecutableBytes {
		return nil, fmt.Errorf("%w: executable size %d exceeds 1..%d bytes", ErrUnsafeWorkerdExecutable, stat.Size, maximumWorkerdExecutableBytes)
	}
	sealedFD, err := createMemfd("circulusd-workerd", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING|unix.MFD_EXEC)
	if errors.Is(err, unix.EINVAL) {
		sealedFD, err = createMemfd("circulusd-workerd", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: create sealed executable snapshot: %v", ErrUnsafeWorkerdExecutable, err)
	}
	sealedExecutable := os.NewFile(uintptr(sealedFD), "sealed-workerd")
	if sealedExecutable == nil {
		_ = unix.Close(sealedFD)
		return nil, fmt.Errorf("%w: wrap sealed executable snapshot", ErrUnsafeWorkerdExecutable)
	}
	keepSealedExecutable := false
	defer func() {
		if !keepSealedExecutable {
			_ = sealedExecutable.Close()
		}
	}()
	hash := sha256.New()
	written, err := io.CopyN(io.MultiWriter(sealedExecutable, hash), sourceExecutable, stat.Size)
	if err != nil || written != stat.Size {
		return nil, fmt.Errorf("%w: copy executable snapshot: copied %d of %d bytes: %v", ErrUnsafeWorkerdExecutable, written, stat.Size, err)
	}
	var trailing [1]byte
	if count, readErr := sourceExecutable.Read(trailing[:]); count != 0 || !errors.Is(readErr, io.EOF) {
		return nil, fmt.Errorf("%w: executable size changed while copying", ErrUnsafeWorkerdExecutable)
	}
	if subtle.ConstantTimeCompare(hash.Sum(nil), expectedDigest) != 1 {
		return nil, ErrWorkerdDigestMismatch
	}
	if err := unix.Fchmod(sealedFD, 0o500); err != nil {
		return nil, fmt.Errorf("%w: set sealed executable mode: %v", ErrUnsafeWorkerdExecutable, err)
	}
	wantedSeals := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if _, err := unix.FcntlInt(sealedExecutable.Fd(), unix.F_ADD_SEALS, wantedSeals); err != nil {
		return nil, fmt.Errorf("%w: seal executable snapshot: %v", ErrUnsafeWorkerdExecutable, err)
	}
	seals, err := unix.FcntlInt(sealedExecutable.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || seals&wantedSeals != wantedSeals {
		return nil, fmt.Errorf("%w: verify executable seals %#x: %v", ErrUnsafeWorkerdExecutable, seals, err)
	}
	if _, err := sealedExecutable.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("%w: rewind sealed executable: %v", ErrUnsafeWorkerdExecutable, err)
	}

	keepSealedExecutable = true
	return &WorkerdProcessLauncher{
		executable:         sealedExecutable,
		executableProcPath: fmt.Sprintf("/proc/self/fd/%d", sealedFD),
		executableDigest:   config.ExecutableDigest,
		environment:        environment,
		readinessTimeout:   config.ReadinessTimeout,
		stopGracePeriod:    config.StopGracePeriod,
		outputLimitBytes:   config.OutputLimitBytes,
		historyCapacity:    config.HistoryCapacity,
		readinessProbe:     config.ReadinessProbe,
		starter:            starter,
		cgroups:            cgroups,
		pending:            make(map[workerdLaunchKey]*workerdPendingLaunch),
		allocations:        make(map[*workerdCgroupLease]workerdCgroupAllocation),
		current:            make(map[string]*workerdInstance),
		latestGenerations:  make(map[string]uint64),
		retiredGenerations: make(map[string]uint64),
		launchIdentities:   make(map[workerdLaunchKey]workerdLaunchIdentity),
		instances:          make(map[*workerdInstance]struct{}),
	}, nil
}

// Ensure coalesces a cold start for one immutable shard generation. Each
// caller owns only its wait: canceling the final waiter abandons and cleans the
// shared start, while canceling any earlier waiter leaves it running.
func (launcher *WorkerdProcessLauncher) Ensure(ctx context.Context, request WorkerdEnsureRequest) (*WorkerdShardHandle, error) {
	if len(request.Arguments) > maximumWorkerdArgumentCount {
		return nil, ErrInvalidWorkerdEnsureRequest
	}
	arguments := slices.Clone(request.Arguments)
	if ctx == nil || launcher == nil || launcher.starter == nil || launcher.readinessProbe == nil ||
		request.ShardID == "" || request.ShardID != strings.TrimSpace(request.ShardID) ||
		len(request.ShardID) > 256 || strings.ContainsRune(request.ShardID, '\x00') ||
		request.PlacementGeneration == 0 {
		return nil, ErrInvalidWorkerdEnsureRequest
	}
	argumentsBytes := 0
	identityHash := sha256.New()
	var encodedLength [8]byte
	binary.BigEndian.PutUint64(encodedLength[:], uint64(len(arguments)))
	_, _ = identityHash.Write(encodedLength[:])
	for _, argument := range arguments {
		if len(argument) > maximumWorkerdArgumentBytes || strings.ContainsRune(argument, '\x00') ||
			argumentsBytes > maximumWorkerdArgumentsTotalBytes-len(argument) {
			return nil, ErrInvalidWorkerdEnsureRequest
		}
		argumentsBytes += len(argument)
		binary.BigEndian.PutUint64(encodedLength[:], uint64(len(argument)))
		_, _ = identityHash.Write(encodedLength[:])
		_, _ = io.WriteString(identityHash, argument)
	}
	var identity workerdLaunchIdentity
	copy(identity[:], identityHash.Sum(nil))
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key := workerdLaunchKey{shardID: request.ShardID, generation: request.PlacementGeneration}

	for {
		launcher.mu.Lock()
		if launcher.closed {
			launcher.mu.Unlock()
			return nil, ErrWorkerdLauncherClosed
		}
		if _, known := launcher.latestGenerations[request.ShardID]; !known && len(launcher.latestGenerations) >= launcher.historyCapacity {
			launcher.mu.Unlock()
			return nil, ErrWorkerdHistoryCapacity
		}
		if retired := launcher.retiredGenerations[request.ShardID]; retired >= request.PlacementGeneration ||
			launcher.latestGenerations[request.ShardID] > request.PlacementGeneration {
			launcher.mu.Unlock()
			return nil, ErrStaleWorkerdGeneration
		}
		if existingIdentity, found := launcher.launchIdentities[key]; found && existingIdentity != identity {
			launcher.mu.Unlock()
			return nil, ErrWorkerdLaunchConflict
		}
		if pending := launcher.pending[key]; pending != nil {
			if pending.abandoned {
				done := pending.done
				launcher.mu.Unlock()
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-done:
					continue
				}
			}
			pending.waiters++
			launcher.mu.Unlock()
			select {
			case <-pending.done:
				return pending.handle, pending.err
			case <-ctx.Done():
				launcher.mu.Lock()
				completed := launcher.pending[key] != pending
				if launcher.pending[key] == pending && !pending.abandoned {
					pending.waiters--
					if pending.waiters == 0 {
						pending.abandoned = true
						pending.cancel()
					}
				}
				launcher.mu.Unlock()
				if completed {
					<-pending.done
					return pending.handle, pending.err
				}
				return nil, ctx.Err()
			}
		}
		if current := launcher.current[request.ShardID]; current != nil && current.key == key {
			if current.identity != identity {
				launcher.mu.Unlock()
				return nil, ErrWorkerdLaunchConflict
			}
			current.mu.Lock()
			unavailable := current.exited || current.groupGone || current.stop != nil || current.handleStopRequested
			current.mu.Unlock()
			if !unavailable {
				handle := &WorkerdShardHandle{launcher: launcher, instance: current}
				launcher.mu.Unlock()
				return handle, nil
			}
		}
		var earlierPending *workerdPendingLaunch
		for pendingKey, candidate := range launcher.pending {
			if pendingKey.shardID == request.ShardID {
				earlierPending = candidate
				break
			}
		}
		if earlierPending != nil {
			done := earlierPending.done
			launcher.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-done:
				continue
			}
		}
		unresolved := make([]*workerdInstance, 0, 1)
		for instance := range launcher.instances {
			if instance.key.shardID != request.ShardID {
				continue
			}
			instance.mu.Lock()
			if !instance.groupGone {
				instance.handleStopRequested = true
				if launcher.retiredGenerations[request.ShardID] < instance.key.generation {
					launcher.retiredGenerations[request.ShardID] = instance.key.generation
				}
				unresolved = append(unresolved, instance)
			}
			instance.mu.Unlock()
		}
		if len(unresolved) != 0 {
			launcher.mu.Unlock()
			stops := make([]*workerdStopOperation, len(unresolved))
			for index, instance := range unresolved {
				stops[index] = launcher.beginWorkerdStop(instance, false)
			}
			var stopErr error
			for _, stop := range stops {
				if err := launcher.waitWorkerdStop(ctx, stop); err != nil {
					stopErr = errors.Join(stopErr, err)
				}
			}
			if stopErr != nil {
				return nil, stopErr
			}
			continue
		}
		if len(launcher.pending) >= launcher.historyCapacity {
			launcher.mu.Unlock()
			return nil, ErrWorkerdHistoryCapacity
		}
		if request.PlacementGeneration > launcher.latestGenerations[request.ShardID] {
			for existingKey := range launcher.launchIdentities {
				if existingKey.shardID == request.ShardID && existingKey.generation < request.PlacementGeneration {
					delete(launcher.launchIdentities, existingKey)
				}
			}
			launcher.latestGenerations[request.ShardID] = request.PlacementGeneration
		}
		launcher.launchIdentities[key] = identity
		launchContext, cancel := context.WithTimeout(context.Background(), launcher.readinessTimeout)
		pending := &workerdPendingLaunch{
			key: key, identity: identity, arguments: arguments, done: make(chan struct{}),
			cancel: cancel, ctx: launchContext, waiters: 1,
		}
		launcher.pending[key] = pending
		launcher.mu.Unlock()
		go launcher.runLaunch(pending)

		select {
		case <-pending.done:
			return pending.handle, pending.err
		case <-ctx.Done():
			launcher.mu.Lock()
			completed := launcher.pending[key] != pending
			if launcher.pending[key] == pending && !pending.abandoned {
				pending.waiters--
				if pending.waiters == 0 {
					pending.abandoned = true
					pending.cancel()
				}
			}
			launcher.mu.Unlock()
			if completed {
				<-pending.done
				return pending.handle, pending.err
			}
			return nil, ctx.Err()
		}
	}
}

func (launcher *WorkerdProcessLauncher) runLaunch(pending *workerdPendingLaunch) {
	var resultHandle *WorkerdShardHandle
	var resultErr error
	defer func() {
		pending.cancel()
		launcher.mu.Lock()
		if launcher.pending[pending.key] == pending {
			if launcher.closed {
				resultHandle = nil
				if resultErr == nil {
					resultErr = ErrWorkerdLauncherClosed
				} else if !errors.Is(resultErr, ErrWorkerdLauncherClosed) {
					resultErr = errors.Join(ErrWorkerdLauncherClosed, resultErr)
				}
			}
			delete(launcher.pending, pending.key)
			pending.handle = resultHandle
			pending.err = resultErr
			close(pending.done)
		}
		launcher.mu.Unlock()
	}()
	var cgroupLease *workerdCgroupLease
	keepCgroupAllocation := false
	if launcher.cgroups != nil {
		type residualCgroupAllocation struct {
			lease *workerdCgroupLease
			key   workerdLaunchKey
		}
		launcher.mu.Lock()
		residuals := make([]residualCgroupAllocation, 0)
		for lease, allocation := range launcher.allocations {
			if allocation.key.shardID == pending.key.shardID {
				residuals = append(residuals, residualCgroupAllocation{lease: lease, key: allocation.key})
			}
		}
		launcher.mu.Unlock()
		sort.Slice(residuals, func(first, second int) bool {
			if residuals[first].key.generation != residuals[second].key.generation {
				return residuals[first].key.generation < residuals[second].key.generation
			}
			return residuals[first].lease.name < residuals[second].lease.name
		})
		for _, residual := range residuals {
			cleanupErr := residual.lease.destroy(context.Background())
			if residual.lease.destroyedState() {
				launcher.forgetWorkerdCgroupAllocation(residual.lease)
				launcher.rememberWorkerdTerminalCloseError(cleanupErr)
			}
			if cleanupErr != nil {
				resultErr = fmt.Errorf("clean residual workerd cgroup for shard %q generation %d: %w", residual.key.shardID, residual.key.generation, cleanupErr)
				return
			}
		}
		lease, prepareErr := launcher.cgroups.prepare(pending.ctx, pending.key.shardID, pending.key.generation)
		cgroupLease = lease
		if cgroupLease != nil {
			launcher.mu.Lock()
			_, alreadyRegistered := launcher.allocations[cgroupLease]
			if !alreadyRegistered {
				launcher.allocations[cgroupLease] = workerdCgroupAllocation{key: pending.key}
			}
			launcher.mu.Unlock()
			defer func() {
				if keepCgroupAllocation {
					return
				}
				cleanupErr := cgroupLease.destroy(context.Background())
				if cgroupLease.destroyedState() {
					launcher.forgetWorkerdCgroupAllocation(cgroupLease)
					launcher.rememberWorkerdTerminalCloseError(cleanupErr)
				}
				if cleanupErr != nil {
					resultErr = errors.Join(resultErr, cleanupErr)
				}
			}()
		}
		if prepareErr != nil {
			resultErr = prepareErr
			return
		}
		if cgroupLease == nil {
			resultErr = fmt.Errorf("%w: cgroup prepare returned no lease", errWorkerdCgroupContract)
			return
		}
	}

	if err := pending.ctx.Err(); err != nil {
		resultErr = fmt.Errorf("%w: shard %q generation %d was abandoned before start", ErrWorkerdNotReady, pending.key.shardID, pending.key.generation)
		return
	}
	stdout := &boundedWorkerdWriter{limit: launcher.outputLimitBytes}
	stderr := &boundedWorkerdWriter{limit: launcher.outputLimitBytes}
	arguments := slices.Clone(pending.arguments)
	command := workerdLaunchCommand{
		Executable:          launcher.executableProcPath,
		Arguments:           arguments,
		Environment:         slices.Clone(launcher.environment),
		ExtraFiles:          make([]*os.File, 0),
		CgroupFD:            -1,
		Stdout:              stdout,
		Stderr:              stderr,
		ShardID:             pending.key.shardID,
		PlacementGeneration: pending.key.generation,
	}
	var process workerdStartedProcess
	var startErr error
	if cgroupLease == nil {
		process, startErr = launcher.starter.Start(command)
	} else {
		startErr = cgroupLease.withDirectoryFD(func(fd int) error {
			command.CgroupFD = fd
			var err error
			process, err = launcher.starter.Start(command)
			return err
		})
	}
	pending.arguments = nil
	if startErr != nil {
		resultErr = fmt.Errorf("%w: shard %q generation %d: %w", ErrWorkerdLaunchFailed, pending.key.shardID, pending.key.generation, startErr)
		return
	}
	instance := &workerdInstance{
		key: pending.key, identity: pending.identity, process: process,
		stdout: stdout, stderr: stderr, exitDone: make(chan struct{}), cgroup: cgroupLease,
	}
	launcher.mu.Lock()
	if cgroupLease != nil {
		allocation, registered := launcher.allocations[cgroupLease]
		if !registered || allocation.key != pending.key {
			launcher.mu.Unlock()
			resultErr = fmt.Errorf("%w: cgroup allocation ownership was lost before process publication", errWorkerdCgroupContract)
			return
		}
		delete(launcher.allocations, cgroupLease)
		keepCgroupAllocation = true
	}
	launcher.instances[instance] = struct{}{}
	launcher.mu.Unlock()
	go func() {
		exitErr := process.Wait()
		launcher.mu.Lock()
		instance.mu.Lock()
		instance.exited = true
		instance.exitErr = exitErr
		close(instance.exitDone)
		if launcher.current[instance.key.shardID] == instance {
			if launcher.retiredGenerations[instance.key.shardID] < instance.key.generation {
				launcher.retiredGenerations[instance.key.shardID] = instance.key.generation
			}
		}
		instance.mu.Unlock()
		launcher.mu.Unlock()
		stop := launcher.beginWorkerdStop(instance, true)
		_ = launcher.waitWorkerdStop(context.Background(), stop)
	}()

	probeResult := make(chan error, 1)
	go func() {
		probeResult <- launcher.readinessProbe.WaitReady(pending.ctx, WorkerdProcessInfo{
			ShardID: pending.key.shardID, PlacementGeneration: pending.key.generation, PID: process.PID(),
		})
	}()
	readinessSucceeded := false
	earlyExit := false
	select {
	case probeErr := <-probeResult:
		if probeErr == nil {
			readinessSucceeded = true
		} else if errors.Is(probeErr, context.DeadlineExceeded) || errors.Is(pending.ctx.Err(), context.DeadlineExceeded) {
			resultErr = fmt.Errorf("%w: shard %q generation %d", ErrWorkerdReadinessTimeout, pending.key.shardID, pending.key.generation)
		} else {
			resultErr = fmt.Errorf("%w: shard %q generation %d: %v", ErrWorkerdNotReady, pending.key.shardID, pending.key.generation, probeErr)
		}
	case <-pending.ctx.Done():
		if errors.Is(pending.ctx.Err(), context.DeadlineExceeded) {
			resultErr = fmt.Errorf("%w: shard %q generation %d", ErrWorkerdReadinessTimeout, pending.key.shardID, pending.key.generation)
		} else {
			resultErr = fmt.Errorf("%w: shard %q generation %d was abandoned", ErrWorkerdNotReady, pending.key.shardID, pending.key.generation)
		}
	case <-instance.exitDone:
		instance.mu.Lock()
		exitErr := instance.exitErr
		instance.mu.Unlock()
		if exitErr == nil {
			exitErr = errors.New("process exited without an error")
		}
		resultErr = fmt.Errorf("%w: shard %q generation %d: %w", ErrWorkerdExitedBeforeReady, pending.key.shardID, pending.key.generation, exitErr)
		earlyExit = true
	}

	if readinessSucceeded {
		instance.mu.Lock()
		if instance.exited {
			exitErr := instance.exitErr
			if exitErr == nil {
				exitErr = errors.New("process exited without an error")
			}
			resultErr = fmt.Errorf("%w: shard %q generation %d: %w", ErrWorkerdExitedBeforeReady, pending.key.shardID, pending.key.generation, exitErr)
			earlyExit = true
			readinessSucceeded = false
		}
		instance.mu.Unlock()
	}

	if !readinessSucceeded {
		if earlyExit {
			stop := launcher.beginWorkerdStop(instance, true)
			if stopErr := launcher.waitWorkerdStop(context.Background(), stop); stopErr != nil {
				resultErr = errors.Join(resultErr, stopErr)
			}
			return
		}
		stop := launcher.beginWorkerdStop(instance, false)
		if stopErr := launcher.waitWorkerdStop(context.Background(), stop); stopErr != nil {
			resultErr = errors.Join(resultErr, stopErr)
		}
		return
	}

	launcher.mu.Lock()
	abandoned := pending.abandoned
	stale := launcher.latestGenerations[pending.key.shardID] != pending.key.generation
	closing := launcher.closed
	oldInstance := launcher.current[pending.key.shardID]
	launcher.mu.Unlock()
	if abandoned || stale || closing {
		stop := launcher.beginWorkerdStop(instance, false)
		stopErr := launcher.waitWorkerdStop(context.Background(), stop)
		if closing {
			resultErr = ErrWorkerdLauncherClosed
		} else if stale {
			resultErr = ErrStaleWorkerdGeneration
		} else {
			resultErr = fmt.Errorf("%w: shard %q generation %d was abandoned", ErrWorkerdNotReady, pending.key.shardID, pending.key.generation)
		}
		if stopErr != nil {
			resultErr = errors.Join(resultErr, stopErr)
		}
		return
	}
	if oldInstance != nil && oldInstance != instance {
		stop := launcher.beginWorkerdStop(oldInstance, false)
		if stopErr := launcher.waitWorkerdStop(context.Background(), stop); stopErr != nil {
			cleanup := launcher.beginWorkerdStop(instance, false)
			cleanupErr := launcher.waitWorkerdStop(context.Background(), cleanup)
			resultErr = errors.Join(fmt.Errorf("replace workerd shard generation: %w", stopErr), cleanupErr)
			return
		}
		oldInstance.mu.Lock()
		oldInstance.replacementRetired = true
		oldInstance.mu.Unlock()
	}

	launcher.mu.Lock()
	instance.mu.Lock()
	finalAbandoned := pending.abandoned
	finalStale := launcher.latestGenerations[pending.key.shardID] != pending.key.generation
	finalClosed := launcher.closed
	finalExited := instance.exited
	finalExitErr := instance.exitErr
	if finalAbandoned || finalStale || finalClosed || finalExited {
		instance.mu.Unlock()
		launcher.mu.Unlock()
		stop := launcher.beginWorkerdStop(instance, false)
		stopErr := launcher.waitWorkerdStop(context.Background(), stop)
		if finalClosed {
			resultErr = ErrWorkerdLauncherClosed
		} else if finalExited {
			if finalExitErr == nil {
				finalExitErr = errors.New("process exited without an error")
			}
			resultErr = fmt.Errorf("%w: shard %q generation %d: %w", ErrWorkerdExitedBeforeReady, pending.key.shardID, pending.key.generation, finalExitErr)
		} else if finalAbandoned {
			resultErr = fmt.Errorf("%w: shard %q generation %d was abandoned", ErrWorkerdNotReady, pending.key.shardID, pending.key.generation)
		} else {
			resultErr = ErrStaleWorkerdGeneration
		}
		if stopErr != nil {
			resultErr = errors.Join(resultErr, stopErr)
		}
		return
	}
	resultHandle = &WorkerdShardHandle{launcher: launcher, instance: instance}
	launcher.current[pending.key.shardID] = instance
	instance.mu.Unlock()
	launcher.mu.Unlock()
}

func (launcher *WorkerdProcessLauncher) forgetWorkerdCgroupAllocation(lease *workerdCgroupLease) {
	launcher.mu.Lock()
	delete(launcher.allocations, lease)
	launcher.mu.Unlock()
}

func (launcher *WorkerdProcessLauncher) rememberWorkerdTerminalCloseError(err error) {
	if err == nil {
		return
	}
	launcher.mu.Lock()
	launcher.terminalCloseErr = errors.Join(launcher.terminalCloseErr, err)
	launcher.mu.Unlock()
}

func (launcher *WorkerdProcessLauncher) beginWorkerdStop(instance *workerdInstance, forceKill bool) *workerdStopOperation {
	instance.mu.Lock()
	if instance.stop != nil {
		select {
		case <-instance.stop.done:
			if instance.stop.err == nil || (instance.cgroup != nil && instance.cgroup.destroyedState()) {
				stop := instance.stop
				instance.mu.Unlock()
				return stop
			}
		default:
			stop := instance.stop
			instance.mu.Unlock()
			return stop
		}
	}
	stop := &workerdStopOperation{done: make(chan struct{})}
	instance.stop = stop
	instance.mu.Unlock()
	go func() {
		if instance.cgroup != nil {
			cleanupErr := instance.cgroup.destroy(context.Background())
			if instance.cgroup.destroyedState() {
				launcher.mu.Lock()
				instance.mu.Lock()
				instance.groupGone = true
				delete(launcher.instances, instance)
				if launcher.current[instance.key.shardID] == instance {
					delete(launcher.current, instance.key.shardID)
				}
				if cleanupErr != nil {
					launcher.terminalCloseErr = errors.Join(launcher.terminalCloseErr, cleanupErr)
				}
				instance.mu.Unlock()
				launcher.mu.Unlock()
			}
			stop.err = cleanupErr
			close(stop.done)
			return
		}
		var roundErr error
		groupGone := false
		alive, groupErr := instance.process.GroupAlive()
		if groupErr != nil {
			roundErr = errors.Join(roundErr, fmt.Errorf("probe workerd process group: %w", groupErr))
		} else if !alive {
			groupGone = true
		}
		signals := []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL}
		if forceKill {
			signals = signals[1:]
		}
		for _, signal := range signals {
			if groupGone {
				break
			}
			if signalErr := instance.process.SignalGroup(signal); signalErr != nil {
				roundErr = errors.Join(roundErr, fmt.Errorf("signal workerd process group with %s: %w", signal, signalErr))
			}
			alive, groupErr = instance.process.GroupAlive()
			if groupErr == nil && !alive {
				groupGone = true
				break
			}
			if groupErr != nil {
				roundErr = errors.Join(roundErr, fmt.Errorf("probe workerd process group after %s: %w", signal, groupErr))
			}
			pollInterval := launcher.stopGracePeriod / 10
			if pollInterval <= 0 {
				pollInterval = time.Nanosecond
			} else if pollInterval > 10*time.Millisecond {
				pollInterval = 10 * time.Millisecond
			}
			ticker := time.NewTicker(pollInterval)
			timer := time.NewTimer(launcher.stopGracePeriod)
		waitForAbsence:
			for {
				select {
				case <-ticker.C:
					alive, groupErr = instance.process.GroupAlive()
					if groupErr == nil && !alive {
						groupGone = true
						break waitForAbsence
					}
					if groupErr != nil {
						roundErr = errors.Join(roundErr, fmt.Errorf("probe workerd process group after %s: %w", signal, groupErr))
					}
				case <-timer.C:
					break waitForAbsence
				}
			}
			ticker.Stop()
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
		if groupGone {
			launcher.mu.Lock()
			instance.mu.Lock()
			instance.groupGone = true
			delete(launcher.instances, instance)
			if launcher.current[instance.key.shardID] == instance {
				delete(launcher.current, instance.key.shardID)
			}
			instance.mu.Unlock()
			launcher.mu.Unlock()
			stop.err = nil
		} else {
			stop.err = errors.Join(roundErr, ErrWorkerdStopTimeout)
		}
		close(stop.done)
	}()
	return stop
}

func (launcher *WorkerdProcessLauncher) waitWorkerdStop(ctx context.Context, stop *workerdStopOperation) error {
	if ctx == nil {
		return ErrInvalidWorkerdEnsureRequest
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-stop.done:
		return stop.err
	}
}

// Close permanently rejects new starts, cancels and joins every pending start,
// then performs the shared bounded process-group cleanup before closing the
// verified executable descriptor. A caller cancellation stops only that
// caller's wait. Concurrent callers coalesce one cleanup round; a failed round
// can be retried while tracked process groups remain.
func (launcher *WorkerdProcessLauncher) Close(ctx context.Context) error {
	if launcher == nil || ctx == nil {
		return ErrInvalidWorkerdLauncherConfig
	}
	launcher.mu.Lock()
	operation := launcher.closeOperation
	startRound := operation == nil
	if operation != nil {
		select {
		case <-operation.done:
			retryableOwnership := len(launcher.instances) != 0 || len(launcher.allocations) != 0 ||
				(launcher.cgroups != nil && !launcher.cgroupsClosed)
			startRound = operation.err != nil && retryableOwnership
		default:
		}
	}
	if startRound {
		operation = &workerdCloseOperation{done: make(chan struct{})}
		launcher.closeOperation = operation
		launcher.closed = true
		pendingLaunches := make([]*workerdPendingLaunch, 0, len(launcher.pending))
		for _, pending := range launcher.pending {
			pendingLaunches = append(pendingLaunches, pending)
			pending.cancel()
		}
		launcher.mu.Unlock()

		sort.Slice(pendingLaunches, func(first, second int) bool {
			if pendingLaunches[first].key.shardID != pendingLaunches[second].key.shardID {
				return pendingLaunches[first].key.shardID < pendingLaunches[second].key.shardID
			}
			return pendingLaunches[first].key.generation < pendingLaunches[second].key.generation
		})
		go func() {
			for _, pending := range pendingLaunches {
				<-pending.done
			}

			launcher.mu.Lock()
			instances := make([]*workerdInstance, 0, len(launcher.instances))
			for instance := range launcher.instances {
				instances = append(instances, instance)
			}
			launcher.mu.Unlock()
			sort.Slice(instances, func(first, second int) bool {
				if instances[first].key.shardID != instances[second].key.shardID {
					return instances[first].key.shardID < instances[second].key.shardID
				}
				if instances[first].key.generation != instances[second].key.generation {
					return instances[first].key.generation < instances[second].key.generation
				}
				return instances[first].process.PID() < instances[second].process.PID()
			})
			var roundErr error
			stops := make([]*workerdStopOperation, len(instances))
			for index, instance := range instances {
				stops[index] = launcher.beginWorkerdStop(instance, false)
			}
			for _, stop := range stops {
				if stopErr := launcher.waitWorkerdStop(context.Background(), stop); stopErr != nil {
					roundErr = errors.Join(roundErr, stopErr)
				}
			}

			type residualCgroupAllocation struct {
				lease *workerdCgroupLease
				key   workerdLaunchKey
			}
			launcher.mu.Lock()
			residuals := make([]residualCgroupAllocation, 0, len(launcher.allocations))
			for lease, allocation := range launcher.allocations {
				residuals = append(residuals, residualCgroupAllocation{lease: lease, key: allocation.key})
			}
			launcher.mu.Unlock()
			sort.Slice(residuals, func(first, second int) bool {
				if residuals[first].key.shardID != residuals[second].key.shardID {
					return residuals[first].key.shardID < residuals[second].key.shardID
				}
				if residuals[first].key.generation != residuals[second].key.generation {
					return residuals[first].key.generation < residuals[second].key.generation
				}
				return residuals[first].lease.name < residuals[second].lease.name
			})
			for _, residual := range residuals {
				cleanupErr := residual.lease.destroy(context.Background())
				if residual.lease.destroyedState() {
					launcher.forgetWorkerdCgroupAllocation(residual.lease)
					launcher.rememberWorkerdTerminalCloseError(cleanupErr)
				}
				if cleanupErr != nil {
					roundErr = errors.Join(roundErr, fmt.Errorf("clean residual workerd cgroup for shard %q generation %d: %w", residual.key.shardID, residual.key.generation, cleanupErr))
				}
			}

			launcher.mu.Lock()
			ownershipRemains := len(launcher.instances) != 0 || len(launcher.allocations) != 0
			cgroups := launcher.cgroups
			cgroupsClosed := launcher.cgroupsClosed
			launcher.mu.Unlock()
			if cgroups != nil && !cgroupsClosed && !ownershipRemains {
				cgroupErr := cgroups.close()
				if errors.Is(cgroupErr, errWorkerdCgroupBusy) {
					roundErr = errors.Join(roundErr, cgroupErr)
				} else {
					launcher.mu.Lock()
					launcher.cgroupsClosed = true
					if cgroupErr != nil {
						launcher.terminalCloseErr = errors.Join(launcher.terminalCloseErr, cgroupErr)
					}
					launcher.mu.Unlock()
				}
			} else if cgroups != nil && !cgroupsClosed && ownershipRemains && roundErr == nil {
				roundErr = errWorkerdCgroupBusy
			}

			launcher.mu.Lock()
			executable := launcher.executable
			launcher.executable = nil
			launcher.mu.Unlock()
			if executable != nil {
				if executableErr := executable.Close(); executableErr != nil {
					launcher.mu.Lock()
					launcher.terminalCloseErr = errors.Join(launcher.terminalCloseErr, fmt.Errorf("close verified workerd executable: %w", executableErr))
					launcher.mu.Unlock()
				}
			}
			launcher.mu.Lock()
			terminalErr := launcher.terminalCloseErr
			cleanupComplete := len(launcher.instances) == 0 && len(launcher.allocations) == 0 &&
				(launcher.cgroups == nil || launcher.cgroupsClosed)
			launcher.mu.Unlock()
			if cleanupComplete {
				roundErr = nil
			}
			operation.err = errors.Join(roundErr, terminalErr)
			close(operation.done)
		}()
	} else {
		launcher.mu.Unlock()
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-operation.done:
		return operation.err
	}
}

// Stop removes this exact generation from service before terminating its
// process group. A stale handle never resolves through the shard name to a
// replacement process.
func (handle *WorkerdShardHandle) Stop(ctx context.Context) error {
	if handle == nil || handle.launcher == nil || handle.instance == nil || ctx == nil {
		return ErrInvalidWorkerdEnsureRequest
	}
	launcher := handle.launcher
	instance := handle.instance
	launcher.mu.Lock()
	instance.mu.Lock()
	if instance.groupGone {
		stop := instance.stop
		instance.mu.Unlock()
		launcher.mu.Unlock()
		if stop != nil {
			return launcher.waitWorkerdStop(ctx, stop)
		}
		return nil
	}
	if instance.replacementRetired {
		instance.mu.Unlock()
		launcher.mu.Unlock()
		return ErrStaleWorkerdGeneration
	}
	if launcher.current[instance.key.shardID] == instance {
		if launcher.retiredGenerations[instance.key.shardID] < instance.key.generation {
			launcher.retiredGenerations[instance.key.shardID] = instance.key.generation
		}
		instance.handleStopRequested = true
		instance.mu.Unlock()
		launcher.mu.Unlock()
		stop := launcher.beginWorkerdStop(instance, false)
		return launcher.waitWorkerdStop(ctx, stop)
	}
	_, tracked := launcher.instances[instance]
	if !tracked && !instance.handleStopRequested {
		instance.mu.Unlock()
		launcher.mu.Unlock()
		return ErrStaleWorkerdGeneration
	}
	instance.handleStopRequested = true
	instance.mu.Unlock()
	launcher.mu.Unlock()
	stop := launcher.beginWorkerdStop(instance, false)
	return launcher.waitWorkerdStop(ctx, stop)
}

// ShardID returns the immutable shard identity.
func (handle *WorkerdShardHandle) ShardID() string {
	if handle == nil || handle.instance == nil {
		return ""
	}
	return handle.instance.key.shardID
}

// ID implements ShardProcess using the immutable shard identity.
func (handle *WorkerdShardHandle) ID() string {
	return handle.ShardID()
}

// PlacementGeneration returns the immutable placement generation.
func (handle *WorkerdShardHandle) PlacementGeneration() uint64 {
	if handle == nil || handle.instance == nil {
		return 0
	}
	return handle.instance.key.generation
}

// PID returns the process leader PID captured at start.
func (handle *WorkerdShardHandle) PID() int {
	if handle == nil || handle.instance == nil || handle.instance.process == nil {
		return 0
	}
	return handle.instance.process.PID()
}

// Output returns copies of the bounded stdout and stderr diagnostic prefixes.
func (handle *WorkerdShardHandle) Output() WorkerdOutput {
	if handle == nil || handle.instance == nil {
		return WorkerdOutput{}
	}
	handle.instance.stdout.mu.Lock()
	stdout := string(handle.instance.stdout.data)
	stdoutTruncated := handle.instance.stdout.truncated
	handle.instance.stdout.mu.Unlock()
	handle.instance.stderr.mu.Lock()
	stderr := string(handle.instance.stderr.data)
	stderrTruncated := handle.instance.stderr.truncated
	handle.instance.stderr.mu.Unlock()
	return WorkerdOutput{
		Stdout: stdout, Stderr: stderr,
		StdoutTruncated: stdoutTruncated, StderrTruncated: stderrTruncated,
	}
}

// Evidence reports implemented controls and returns a fresh capability slice.
func (launcher *WorkerdProcessLauncher) Evidence() WorkerdLauncherEvidence {
	if launcher == nil {
		return WorkerdLauncherEvidence{}
	}
	integratedCgroup := launcher.cgroups != nil
	missingCapabilities := make([]string, 0, 7)
	if integratedCgroup {
		missingCapabilities = append(missingCapabilities, "workerd-cgroup-authority-isolation")
	} else {
		missingCapabilities = append(missingCapabilities,
			"agentd-cgroup-limits",
			"agentd-cgroup-termination",
		)
	}
	missingCapabilities = append(missingCapabilities,
		"agentd-cpu-accounting",
		"agentd-rss-accounting",
		"workerd-child-fd-allowlist",
		"workerd-kill-reconstruction",
	)
	return WorkerdLauncherEvidence{
		ExecutableDigest:         launcher.executableDigest,
		VerifiedOpenExecutable:   true,
		SealedExecutableSnapshot: true,
		ProcessGroupTermination:  false,
		ExplicitEnvironment:      true,
		ChildFDAllowlist:         false,
		BoundedOutput:            true,
		ReadinessGated:           true,
		AtomicCgroupPlacement:    integratedCgroup,
		CgroupLimits:             integratedCgroup,
		CgroupTermination:        integratedCgroup,
		CPUAccounting:            false,
		RSSAccounting:            false,
		KillReconstruction:       false,
		AdmissionReady:           false,
		MissingCapabilities:      missingCapabilities,
	}
}

func (writer *boundedWorkerdWriter) Write(content []byte) (int, error) {
	written := len(content)
	writer.mu.Lock()
	remaining := writer.limit - len(writer.data)
	if remaining > len(content) {
		remaining = len(content)
	}
	if remaining > 0 {
		writer.data = append(writer.data, content[:remaining]...)
	}
	if remaining < len(content) {
		writer.truncated = true
	}
	writer.mu.Unlock()
	return written, nil
}

type osWorkerdProcessStarter struct {
	start func(*exec.Cmd) error
}

func (starter osWorkerdProcessStarter) Start(command workerdLaunchCommand) (workerdStartedProcess, error) {
	process := exec.Command(command.Executable, command.Arguments...)
	process.Env = make([]string, len(command.Environment))
	copy(process.Env, command.Environment)
	process.ExtraFiles = make([]*os.File, len(command.ExtraFiles))
	copy(process.ExtraFiles, command.ExtraFiles)
	process.Stdout = command.Stdout
	process.Stderr = command.Stderr
	process.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if command.CgroupFD >= 0 {
		process.SysProcAttr.UseCgroupFD = true
		process.SysProcAttr.CgroupFD = command.CgroupFD
	}
	start := starter.start
	if start == nil {
		start = func(command *exec.Cmd) error { return command.Start() }
	}
	if err := start(process); err != nil {
		return nil, err
	}
	if process.Process == nil {
		return nil, errors.New("workerd process starter returned without a process")
	}
	return &osWorkerdStartedProcess{process: process, pid: process.Process.Pid}, nil
}

type osWorkerdStartedProcess struct {
	process *exec.Cmd
	pid     int
}

func (process *osWorkerdStartedProcess) PID() int {
	return process.pid
}

func (process *osWorkerdStartedProcess) Wait() error {
	return process.process.Wait()
}

func (process *osWorkerdStartedProcess) SignalGroup(signal syscall.Signal) error {
	err := unix.Kill(-process.pid, signal)
	if errors.Is(err, unix.ESRCH) {
		return nil
	}
	return err
}

func (process *osWorkerdStartedProcess) GroupAlive() (bool, error) {
	err := unix.Kill(-process.pid, 0)
	if err == nil || errors.Is(err, unix.EPERM) {
		return true, nil
	}
	if errors.Is(err, unix.ESRCH) {
		return false, nil
	}
	return false, err
}
