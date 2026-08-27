//go:build linux

package agent

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

var (
	errInvalidWorkerdCgroupConfig    = errors.New("agent: invalid workerd cgroup configuration")
	errInvalidWorkerdCgroupRequest   = errors.New("agent: invalid workerd cgroup request")
	errWorkerdCgroupUnavailable      = errors.New("agent: workerd cgroup boundary unavailable")
	errWorkerdCgroupContract         = errors.New("agent: workerd cgroup contract violation")
	errWorkerdCgroupCapacity         = errors.New("agent: workerd cgroup capacity exhausted")
	errWorkerdCgroupClosed           = errors.New("agent: workerd cgroup controller closed")
	errWorkerdCgroupBusy             = errors.New("agent: workerd cgroup controller still owns leases")
	errWorkerdCgroupPathReplaced     = errors.New("agent: workerd cgroup path identity replaced")
	errWorkerdCgroupDrainTimeout     = errors.New("agent: workerd cgroup drain timeout")
	errWorkerdCgroupPoisoned         = errors.New("agent: workerd cgroup controller integrity poisoned")
	errWorkerdCgroupLeaseUnavailable = errors.New("agent: workerd cgroup lease unavailable for attachment")
)

const (
	maximumWorkerdCgroupShards       = 4096
	maximumWorkerdCgroupDrainTimeout = 30 * time.Second
	maximumWorkerdCgroupMemoryBytes  = uint64(1 << 50)
	maximumWorkerdCgroupCPUCores     = uint64(1024)
	maximumWorkerdCgroupPIDs         = uint64(1 << 20)
	maximumWorkerdCgroupPathBytes    = 4096
	maximumWorkerdCgroupShardIDBytes = 1024
	maximumWorkerdCgroupControlBytes = 4096
	workerdCgroupCPUPeriodMicros     = uint64(100_000)
	workerdCgroupDrainPollInterval   = 10 * time.Millisecond
	workerdCgroupLeafDomain          = "circulusd/workerd-cgroup/v1\x00"
)

var workerdCgroupSecureResolve = uint64(unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS)

type workerdCgroupConfig struct {
	RootPath       string
	MaximumShards  int
	DrainTimeout   time.Duration
	MemoryMaxBytes uint64
	SwapMaxBytes   uint64
	CPUCores       uint64
	PIDsMax        uint64
}

type workerdCgroupEvidence struct {
	ReferenceOnly      bool
	ProductionEligible bool
	ConformanceClaimed bool
	SecureRootWalk     bool
	ExactLimitReadback bool
	ScopedCgroupKill   bool
	ReplacementFencing bool
}

type workerdCgroupAvailability struct {
	Status    string
	Available bool
	Reason    string
	Evidence  workerdCgroupEvidence
}

type workerdCgroupDirectoryMetadata struct {
	Device uint64
	Inode  uint64
	UID    uint32
	GID    uint32
	Mode   uint32
}

type workerdCgroupIdentity struct {
	Device uint64
	Inode  uint64
}

type workerdCgroupRootInspection struct {
	DirectoryFD      int
	FilesystemType   int64
	Components       []workerdCgroupDirectoryMetadata
	CgroupType       string
	Processes        string
	Controllers      string
	SubtreeControl   string
	ChildDirectories int
}

type workerdCgroupBackend interface {
	effectiveIDs() (uint32, uint32)
	inspectRoot(string) (workerdCgroupRootInspection, error)
	mkdirExclusive(int, string, uint32) error
	openChild(int, string) (int, workerdCgroupIdentity, error)
	writeControl(int, string, string) error
	readControl(int, string, int) (string, error)
	identityAt(int, string) (workerdCgroupIdentity, bool, error)
	removeChild(int, string) error
	closeFD(int) error
	wait(context.Context, time.Duration) error
}

type workerdCgroupController struct {
	authority sync.RWMutex
	mu        sync.Mutex

	config   workerdCgroupConfig
	backend  workerdCgroupBackend
	rootFD   int
	reserved int
	poisoned bool
	closed   bool
	closeErr error
}

type workerdCgroupDestroyOperation struct {
	done     chan struct{}
	finished bool
	err      error
}

type workerdCgroupLease struct {
	controller *workerdCgroupController
	name       string
	fd         int
	identity   workerdCgroupIdentity

	mu               sync.Mutex
	attachable       bool
	destroyed        bool
	terminalErr      error
	destroyOperation *workerdCgroupDestroyOperation
}

type linuxWorkerdCgroupBackend struct{}

func newWorkerdCgroupController(config workerdCgroupConfig) (*workerdCgroupController, error) {
	return newWorkerdCgroupControllerWithBackend(config, linuxWorkerdCgroupBackend{})
}

func newWorkerdCgroupControllerWithBackend(config workerdCgroupConfig, backend workerdCgroupBackend) (*workerdCgroupController, error) {
	if config.RootPath == "" || len(config.RootPath) > maximumWorkerdCgroupPathBytes || strings.IndexByte(config.RootPath, 0) >= 0 ||
		!filepath.IsAbs(config.RootPath) || filepath.Clean(config.RootPath) != config.RootPath || config.RootPath == string(filepath.Separator) ||
		config.MaximumShards < 1 || config.MaximumShards > maximumWorkerdCgroupShards ||
		config.DrainTimeout <= 0 || config.DrainTimeout > maximumWorkerdCgroupDrainTimeout ||
		config.MemoryMaxBytes < 1 || config.MemoryMaxBytes > maximumWorkerdCgroupMemoryBytes || config.SwapMaxBytes != 0 ||
		config.CPUCores < 1 || config.CPUCores > maximumWorkerdCgroupCPUCores ||
		config.PIDsMax < 1 || config.PIDsMax > maximumWorkerdCgroupPIDs {
		return nil, errInvalidWorkerdCgroupConfig
	}
	if backend == nil {
		return nil, fmt.Errorf("%w: backend is nil", errWorkerdCgroupContract)
	}
	inspection, err := backend.inspectRoot(config.RootPath)
	if err != nil {
		return nil, classifyWorkerdCgroupError("inspect delegated root", err)
	}
	var rootErr error
	if inspection.DirectoryFD < 0 || len(inspection.Components) < 2 {
		rootErr = fmt.Errorf("%w: incomplete delegated root inspection", errWorkerdCgroupContract)
	}
	if rootErr == nil {
		for _, component := range inspection.Components[:len(inspection.Components)-1] {
			if component.Mode&unix.S_IFMT != unix.S_IFDIR || component.UID != 0 || component.Mode&0o022 != 0 {
				rootErr = fmt.Errorf("%w: replaceable delegated root intermediate", errWorkerdCgroupContract)
				break
			}
		}
	}
	if rootErr == nil {
		effectiveUID, effectiveGID := backend.effectiveIDs()
		target := inspection.Components[len(inspection.Components)-1]
		if target.Mode&unix.S_IFMT != unix.S_IFDIR || target.Mode&0o7777 != 0o700 || target.UID != effectiveUID || target.GID != effectiveGID {
			rootErr = fmt.Errorf("%w: delegated root ownership or mode", errWorkerdCgroupContract)
		}
	}
	if rootErr == nil && inspection.FilesystemType != unix.CGROUP2_SUPER_MAGIC {
		rootErr = fmt.Errorf("%w: delegated root is not cgroup v2", errWorkerdCgroupContract)
	}
	if rootErr == nil && !exactCgroupControlValue(inspection.CgroupType, "domain") {
		rootErr = fmt.Errorf("%w: delegated root is not a domain cgroup", errWorkerdCgroupContract)
	}
	if rootErr == nil && (inspection.Processes != "" || inspection.ChildDirectories != 0) {
		rootErr = fmt.Errorf("%w: delegated root is not empty", errWorkerdCgroupContract)
	}
	if rootErr == nil {
		availableControllers := make(map[string]struct{})
		for _, controllerName := range strings.Fields(inspection.Controllers) {
			availableControllers[controllerName] = struct{}{}
		}
		enabledControllers := make(map[string]struct{})
		for _, controllerName := range strings.Fields(inspection.SubtreeControl) {
			enabledControllers[controllerName] = struct{}{}
		}
		for _, controllerName := range []string{"cpu", "memory", "pids"} {
			_, available := availableControllers[controllerName]
			_, enabled := enabledControllers[controllerName]
			if !available || !enabled {
				rootErr = fmt.Errorf("%w: required controller is not delegated", errWorkerdCgroupContract)
				break
			}
		}
	}
	if rootErr != nil {
		_ = backend.closeFD(inspection.DirectoryFD)
		return nil, rootErr
	}
	return &workerdCgroupController{
		config:  config,
		backend: backend,
		rootFD:  inspection.DirectoryFD,
	}, nil
}

func (controller *workerdCgroupController) evidence() workerdCgroupEvidence {
	return workerdCgroupEvidence{
		ReferenceOnly:      true,
		ProductionEligible: false,
		ConformanceClaimed: false,
		SecureRootWalk:     true,
		ExactLimitReadback: true,
		ScopedCgroupKill:   true,
		ReplacementFencing: true,
	}
}

func probeWorkerdCgroupAvailability(config workerdCgroupConfig) workerdCgroupAvailability {
	evidence := workerdCgroupEvidence{ReferenceOnly: true}
	controller, err := newWorkerdCgroupController(config)
	if err != nil {
		status := "FAILED"
		reason := "delegated cgroup root violates the required contract"
		if errors.Is(err, errWorkerdCgroupUnavailable) {
			status = "NOT_RUN"
			reason = "delegated cgroup v2 root is unavailable"
		}
		return workerdCgroupAvailability{Status: status, Reason: reason, Evidence: evidence}
	}
	evidence = controller.evidence()
	if err := controller.close(); err != nil {
		return workerdCgroupAvailability{Status: "FAILED", Reason: "delegated cgroup root descriptor could not be closed", Evidence: evidence}
	}
	return workerdCgroupAvailability{Status: "REFERENCE_ONLY", Available: true, Reason: "mechanical attachment is implemented but production cgroup authority isolation is not", Evidence: evidence}
}

func (controller *workerdCgroupController) prepare(ctx context.Context, shardID string, generation uint64) (resultLease *workerdCgroupLease, resultErr error) {
	if ctx == nil || shardID == "" || len(shardID) > maximumWorkerdCgroupShardIDBytes || strings.IndexByte(shardID, 0) >= 0 || generation == 0 {
		return nil, errInvalidWorkerdCgroupRequest
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	controller.mu.Lock()
	if controller.poisoned {
		controller.mu.Unlock()
		return nil, errWorkerdCgroupPoisoned
	}
	if controller.closed {
		controller.mu.Unlock()
		return nil, errWorkerdCgroupClosed
	}
	if controller.reserved >= controller.config.MaximumShards {
		controller.mu.Unlock()
		return nil, errWorkerdCgroupCapacity
	}
	controller.reserved++
	controller.mu.Unlock()

	name := workerdCgroupLeafName(shardID, generation)
	if err := controller.backend.mkdirExclusive(controller.rootFD, name, 0o700); err != nil {
		controller.mu.Lock()
		controller.reserved--
		controller.mu.Unlock()
		return nil, classifyWorkerdCgroupError("create shard cgroup", err)
	}
	fd, identity, err := controller.backend.openChild(controller.rootFD, name)
	if err != nil {
		controller.authority.Lock()
		controller.mu.Lock()
		controller.reserved--
		controller.poisoned = true
		controller.mu.Unlock()
		controller.authority.Unlock()
		return nil, errors.Join(classifyWorkerdCgroupError("open shard cgroup", err), errWorkerdCgroupPoisoned)
	}
	lease := &workerdCgroupLease{controller: controller, name: name, fd: fd, identity: identity}
	rollbackRequired := true
	defer func() {
		if !rollbackRequired || resultErr == nil {
			return
		}
		controller.authority.Lock()
		defer controller.authority.Unlock()
		controller.mu.Lock()
		currentIdentity, exists, identityErr := controller.backend.identityAt(controller.rootFD, name)
		if identityErr != nil {
			controller.mu.Unlock()
			resultLease = lease
			resultErr = errors.Join(resultErr, classifyWorkerdCgroupError("verify rollback cgroup identity", identityErr))
			return
		}
		if !exists || currentIdentity != identity {
			controller.reserved--
			controller.poisoned = true
			controller.mu.Unlock()
			closeErr := controller.backend.closeFD(fd)
			resultLease = nil
			resultErr = errors.Join(resultErr, errWorkerdCgroupPathReplaced, errWorkerdCgroupPoisoned)
			if closeErr != nil {
				resultErr = errors.Join(resultErr, classifyWorkerdCgroupError("close poisoned rollback cgroup", closeErr))
			}
			return
		}
		removeErr := controller.backend.removeChild(controller.rootFD, name)
		if removeErr != nil {
			controller.mu.Unlock()
			resultLease = lease
			resultErr = errors.Join(resultErr, classifyWorkerdCgroupError("rollback shard cgroup", removeErr))
			return
		}
		controller.reserved--
		controller.mu.Unlock()
		resultLease = nil
		if closeErr := controller.backend.closeFD(fd); closeErr != nil {
			resultErr = errors.Join(resultErr, classifyWorkerdCgroupError("close rolled back shard cgroup", closeErr))
		}
	}()
	leafControls := []struct {
		name     string
		expected string
	}{
		{name: "cgroup.type", expected: "domain"},
		{name: "cgroup.procs", expected: ""},
		{name: "cgroup.subtree_control", expected: ""},
	}
	for _, control := range leafControls {
		value, readErr := controller.backend.readControl(fd, control.name, maximumWorkerdCgroupControlBytes)
		if readErr != nil {
			return nil, classifyWorkerdCgroupError("read shard leaf state", readErr)
		}
		if !exactCgroupControlValue(value, control.expected) {
			return nil, fmt.Errorf("%w: shard is not an empty domain leaf", errWorkerdCgroupContract)
		}
	}
	stat, err := controller.backend.readControl(fd, "cgroup.stat", maximumWorkerdCgroupControlBytes)
	if err != nil {
		return nil, classifyWorkerdCgroupError("read shard descendant state", err)
	}
	foundDescendants := false
	foundDyingDescendants := false
	for _, line := range strings.Split(strings.TrimSuffix(stat, "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("%w: malformed cgroup.stat", errWorkerdCgroupContract)
		}
		value, parseErr := strconv.ParseUint(fields[1], 10, 64)
		if parseErr != nil {
			return nil, fmt.Errorf("%w: malformed cgroup.stat value", errWorkerdCgroupContract)
		}
		switch fields[0] {
		case "nr_descendants":
			if foundDescendants || value != 0 {
				return nil, fmt.Errorf("%w: shard has descendants", errWorkerdCgroupContract)
			}
			foundDescendants = true
		case "nr_dying_descendants":
			if foundDyingDescendants || value != 0 {
				return nil, fmt.Errorf("%w: shard has dying descendants", errWorkerdCgroupContract)
			}
			foundDyingDescendants = true
		}
	}
	if !foundDescendants || !foundDyingDescendants {
		return nil, fmt.Errorf("%w: incomplete cgroup.stat", errWorkerdCgroupContract)
	}
	limits := []struct {
		name  string
		value string
	}{
		{name: "cgroup.max.depth", value: "0"},
		{name: "cgroup.max.descendants", value: "0"},
		{name: "memory.max", value: fmt.Sprint(controller.config.MemoryMaxBytes)},
		{name: "memory.swap.max", value: "0"},
		{name: "cpu.max", value: fmt.Sprintf("%d %d", controller.config.CPUCores*workerdCgroupCPUPeriodMicros, workerdCgroupCPUPeriodMicros)},
		{name: "pids.max", value: fmt.Sprint(controller.config.PIDsMax)},
	}
	for _, limit := range limits {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := controller.backend.writeControl(fd, limit.name, limit.value); err != nil {
			return nil, classifyWorkerdCgroupError("write shard limit", err)
		}
		readback, err := controller.backend.readControl(fd, limit.name, maximumWorkerdCgroupControlBytes)
		if err != nil {
			return nil, classifyWorkerdCgroupError("read shard limit", err)
		}
		if !exactCgroupControlValue(readback, limit.value) {
			return nil, fmt.Errorf("%w: shard limit readback mismatch", errWorkerdCgroupContract)
		}
	}
	controller.mu.Lock()
	poisoned := controller.poisoned
	controller.mu.Unlock()
	if poisoned {
		return nil, errWorkerdCgroupPoisoned
	}
	lease.attachable = true
	rollbackRequired = false
	return lease, nil
}

func workerdCgroupLeafName(shardID string, generation uint64) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(workerdCgroupLeafDomain))
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(len(shardID)))
	_, _ = hash.Write(encoded[:])
	_, _ = hash.Write([]byte(shardID))
	binary.BigEndian.PutUint64(encoded[:], generation)
	_, _ = hash.Write(encoded[:])
	return "workerd-" + hex.EncodeToString(hash.Sum(nil))
}

func (lease *workerdCgroupLease) withDirectoryFD(use func(int) error) error {
	if lease == nil || lease.controller == nil || use == nil {
		return errInvalidWorkerdCgroupRequest
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	controller := lease.controller
	if !lease.attachable || lease.destroyed || lease.destroyOperation != nil {
		return errWorkerdCgroupLeaseUnavailable
	}
	controller.authority.RLock()
	defer controller.authority.RUnlock()
	controller.mu.Lock()
	unavailable := controller.poisoned || controller.closed
	controller.mu.Unlock()
	if unavailable {
		return errWorkerdCgroupLeaseUnavailable
	}
	return use(lease.fd)
}

func (lease *workerdCgroupLease) destroy(ctx context.Context) error {
	if lease == nil || lease.controller == nil || ctx == nil {
		return errInvalidWorkerdCgroupRequest
	}
	lease.mu.Lock()
	if lease.destroyed {
		err := lease.terminalErr
		lease.mu.Unlock()
		return err
	}
	if err := ctx.Err(); err != nil {
		lease.mu.Unlock()
		return err
	}
	if lease.destroyOperation != nil && !lease.destroyOperation.finished {
		existing := lease.destroyOperation
		lease.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-existing.done:
			return existing.err
		}
	}
	operation := &workerdCgroupDestroyOperation{done: make(chan struct{})}
	lease.destroyOperation = operation
	cleanupOnly := !lease.attachable
	lease.mu.Unlock()

	go func() {
		controller := lease.controller
		var cleanupErr error
		ownershipReleased := false
		if !cleanupOnly {
			if err := controller.backend.writeControl(lease.fd, "cgroup.kill", "1"); err != nil {
				cleanupErr = classifyWorkerdCgroupError("kill shard cgroup", err)
			}
		}
		if cleanupErr == nil && !cleanupOnly {
			drainContext, cancel := context.WithTimeout(context.Background(), controller.config.DrainTimeout)
			for cleanupErr == nil {
				if drainContext.Err() != nil {
					cleanupErr = errWorkerdCgroupDrainTimeout
					break
				}
				events, err := controller.backend.readControl(lease.fd, "cgroup.events", maximumWorkerdCgroupControlBytes)
				if err != nil {
					cleanupErr = classifyWorkerdCgroupError("read shard cgroup events", err)
					break
				}
				found := false
				populated := false
				for _, line := range strings.Split(strings.TrimSuffix(events, "\n"), "\n") {
					fields := strings.Fields(line)
					if len(fields) != 2 {
						cleanupErr = fmt.Errorf("%w: malformed cgroup.events", errWorkerdCgroupContract)
						break
					}
					if fields[0] != "populated" {
						continue
					}
					if found || (fields[1] != "0" && fields[1] != "1") {
						cleanupErr = fmt.Errorf("%w: malformed populated event", errWorkerdCgroupContract)
						break
					}
					found = true
					populated = fields[1] == "1"
				}
				if cleanupErr != nil {
					break
				}
				if !found {
					cleanupErr = fmt.Errorf("%w: missing populated event", errWorkerdCgroupContract)
					break
				}
				if !populated {
					break
				}
				if err := controller.backend.wait(drainContext, workerdCgroupDrainPollInterval); err != nil {
					if errors.Is(drainContext.Err(), context.DeadlineExceeded) {
						cleanupErr = errWorkerdCgroupDrainTimeout
					} else {
						cleanupErr = classifyWorkerdCgroupError("wait for shard cgroup drain", err)
					}
				}
			}
			cancel()
		}
		if cleanupErr == nil {
			controller.authority.Lock()
			controller.mu.Lock()
			identity, exists, err := controller.backend.identityAt(controller.rootFD, lease.name)
			if err != nil {
				controller.mu.Unlock()
				controller.authority.Unlock()
				cleanupErr = classifyWorkerdCgroupError("verify shard cgroup identity", err)
			} else if !exists || identity != lease.identity {
				controller.reserved--
				controller.poisoned = true
				ownershipReleased = true
				controller.mu.Unlock()
				closeErr := controller.backend.closeFD(lease.fd)
				controller.authority.Unlock()
				cleanupErr = errors.Join(errWorkerdCgroupPathReplaced, errWorkerdCgroupPoisoned)
				if closeErr != nil {
					cleanupErr = errors.Join(cleanupErr, classifyWorkerdCgroupError("close poisoned shard cgroup", closeErr))
				}
			} else if err := controller.backend.removeChild(controller.rootFD, lease.name); err != nil {
				controller.mu.Unlock()
				controller.authority.Unlock()
				cleanupErr = classifyWorkerdCgroupError("remove shard cgroup", err)
			} else {
				controller.reserved--
				ownershipReleased = true
				controller.mu.Unlock()
				if closeErr := controller.backend.closeFD(lease.fd); closeErr != nil {
					cleanupErr = classifyWorkerdCgroupError("close removed shard cgroup", closeErr)
				}
				controller.authority.Unlock()
			}
		}
		lease.mu.Lock()
		operation.err = cleanupErr
		operation.finished = true
		if cleanupErr == nil || ownershipReleased {
			lease.destroyed = true
			lease.fd = -1
			if cleanupErr != nil {
				lease.terminalErr = cleanupErr
			}
		}
		close(operation.done)
		lease.mu.Unlock()
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-operation.done:
		return operation.err
	}
}

func (lease *workerdCgroupLease) destroyedState() bool {
	if lease == nil {
		return false
	}
	lease.mu.Lock()
	destroyed := lease.destroyed
	lease.mu.Unlock()
	return destroyed
}

func (controller *workerdCgroupController) close() error {
	if controller == nil {
		return nil
	}
	controller.authority.Lock()
	defer controller.authority.Unlock()
	controller.mu.Lock()
	if controller.closed {
		err := controller.closeErr
		controller.mu.Unlock()
		return err
	}
	if controller.reserved != 0 {
		controller.mu.Unlock()
		return errWorkerdCgroupBusy
	}
	controller.closed = true
	rootFD := controller.rootFD
	controller.rootFD = -1
	var closeErr error
	if err := controller.backend.closeFD(rootFD); err != nil {
		closeErr = classifyWorkerdCgroupError("close delegated root", err)
	}
	if controller.poisoned {
		closeErr = errors.Join(errWorkerdCgroupPoisoned, closeErr)
	}
	controller.closeErr = closeErr
	controller.mu.Unlock()
	return closeErr
}

func exactCgroupControlValue(value string, expected string) bool {
	return value == expected || value == expected+"\n"
}

func classifyWorkerdCgroupError(operation string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, errInvalidWorkerdCgroupConfig) || errors.Is(err, errInvalidWorkerdCgroupRequest) ||
		errors.Is(err, errWorkerdCgroupUnavailable) || errors.Is(err, errWorkerdCgroupContract) ||
		errors.Is(err, errWorkerdCgroupCapacity) || errors.Is(err, errWorkerdCgroupClosed) ||
		errors.Is(err, errWorkerdCgroupBusy) || errors.Is(err, errWorkerdCgroupPathReplaced) ||
		errors.Is(err, errWorkerdCgroupDrainTimeout) || errors.Is(err, errWorkerdCgroupPoisoned) {
		return fmt.Errorf("%s: %w", operation, err)
	}
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EROFS) || errors.Is(err, unix.ENOSYS) {
		return fmt.Errorf("%s: %w", operation, errWorkerdCgroupUnavailable)
	}
	return fmt.Errorf("%s: %w", operation, errWorkerdCgroupContract)
}

func (linuxWorkerdCgroupBackend) effectiveIDs() (uint32, uint32) {
	return uint32(os.Geteuid()), uint32(os.Getegid())
}

func (backend linuxWorkerdCgroupBackend) inspectRoot(rootPath string) (workerdCgroupRootInspection, error) {
	currentFD, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return workerdCgroupRootInspection{}, err
	}
	components := make([]workerdCgroupDirectoryMetadata, 0, strings.Count(rootPath, string(filepath.Separator))+1)
	var rootStat unix.Stat_t
	if err := unix.Fstat(currentFD, &rootStat); err != nil {
		_ = unix.Close(currentFD)
		return workerdCgroupRootInspection{}, err
	}
	components = append(components, workerdCgroupDirectoryMetadata{
		Device: uint64(rootStat.Dev), Inode: rootStat.Ino, UID: rootStat.Uid, GID: rootStat.Gid, Mode: rootStat.Mode,
	})
	for _, component := range strings.Split(strings.TrimPrefix(rootPath, string(filepath.Separator)), string(filepath.Separator)) {
		nextFD, openErr := unix.Openat2(currentFD, component, &unix.OpenHow{
			Flags: uint64(unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC), Resolve: workerdCgroupSecureResolve,
		})
		_ = unix.Close(currentFD)
		if openErr != nil {
			return workerdCgroupRootInspection{}, openErr
		}
		currentFD = nextFD
		var componentStat unix.Stat_t
		if err := unix.Fstat(currentFD, &componentStat); err != nil {
			_ = unix.Close(currentFD)
			return workerdCgroupRootInspection{}, err
		}
		components = append(components, workerdCgroupDirectoryMetadata{
			Device: uint64(componentStat.Dev), Inode: componentStat.Ino, UID: componentStat.Uid, GID: componentStat.Gid, Mode: componentStat.Mode,
		})
	}
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(currentFD, &filesystem); err != nil {
		_ = unix.Close(currentFD)
		return workerdCgroupRootInspection{}, err
	}
	cgroupType, err := backend.readControl(currentFD, "cgroup.type", maximumWorkerdCgroupControlBytes)
	if err != nil {
		_ = unix.Close(currentFD)
		return workerdCgroupRootInspection{}, err
	}
	processes, err := backend.readControl(currentFD, "cgroup.procs", maximumWorkerdCgroupControlBytes)
	if err != nil {
		_ = unix.Close(currentFD)
		return workerdCgroupRootInspection{}, err
	}
	controllers, err := backend.readControl(currentFD, "cgroup.controllers", maximumWorkerdCgroupControlBytes)
	if err != nil {
		_ = unix.Close(currentFD)
		return workerdCgroupRootInspection{}, err
	}
	subtreeControl, err := backend.readControl(currentFD, "cgroup.subtree_control", maximumWorkerdCgroupControlBytes)
	if err != nil {
		_ = unix.Close(currentFD)
		return workerdCgroupRootInspection{}, err
	}
	directoryFD, err := unix.Openat2(currentFD, ".", &unix.OpenHow{
		Flags: uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC), Resolve: workerdCgroupSecureResolve,
	})
	if err != nil {
		_ = unix.Close(currentFD)
		return workerdCgroupRootInspection{}, err
	}
	directory := os.NewFile(uintptr(directoryFD), "workerd-cgroup-root")
	if directory == nil {
		_ = unix.Close(directoryFD)
		_ = unix.Close(currentFD)
		return workerdCgroupRootInspection{}, unix.EBADF
	}
	childDirectories := 0
	var scanErr error
	for inspected := 0; inspected <= maximumWorkerdCgroupShards+64; inspected++ {
		entries, readErr := directory.ReadDir(1)
		if len(entries) == 0 {
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				scanErr = readErr
			}
			break
		}
		info, infoErr := entries[0].Info()
		if infoErr != nil {
			scanErr = infoErr
			break
		}
		if info.IsDir() {
			childDirectories = 1
			break
		}
		if inspected == maximumWorkerdCgroupShards+64 {
			scanErr = unix.EOVERFLOW
		}
	}
	if closeErr := directory.Close(); scanErr == nil && closeErr != nil {
		scanErr = closeErr
	}
	if scanErr != nil {
		_ = unix.Close(currentFD)
		return workerdCgroupRootInspection{}, scanErr
	}
	return workerdCgroupRootInspection{
		DirectoryFD:      currentFD,
		FilesystemType:   filesystem.Type,
		Components:       components,
		CgroupType:       cgroupType,
		Processes:        processes,
		Controllers:      controllers,
		SubtreeControl:   subtreeControl,
		ChildDirectories: childDirectories,
	}, nil
}

func (linuxWorkerdCgroupBackend) mkdirExclusive(rootFD int, name string, mode uint32) error {
	return unix.Mkdirat(rootFD, name, mode)
}

func (linuxWorkerdCgroupBackend) openChild(rootFD int, name string) (int, workerdCgroupIdentity, error) {
	fd, err := unix.Openat2(rootFD, name, &unix.OpenHow{
		Flags: uint64(unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC), Resolve: workerdCgroupSecureResolve,
	})
	if err != nil {
		return -1, workerdCgroupIdentity{}, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return -1, workerdCgroupIdentity{}, err
	}
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(fd, &filesystem); err != nil {
		_ = unix.Close(fd)
		return -1, workerdCgroupIdentity{}, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o7777 != 0o700 || stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) || filesystem.Type != unix.CGROUP2_SUPER_MAGIC {
		_ = unix.Close(fd)
		return -1, workerdCgroupIdentity{}, fmt.Errorf("%w: created shard cgroup identity", errWorkerdCgroupContract)
	}
	return fd, workerdCgroupIdentity{Device: uint64(stat.Dev), Inode: stat.Ino}, nil
}

func (linuxWorkerdCgroupBackend) writeControl(directoryFD int, name string, value string) error {
	fd, err := unix.Openat2(directoryFD, name, &unix.OpenHow{
		Flags: uint64(unix.O_WRONLY | unix.O_CLOEXEC), Resolve: workerdCgroupSecureResolve,
	})
	if err != nil {
		return err
	}
	written, writeErr := unix.Write(fd, []byte(value))
	closeErr := unix.Close(fd)
	if writeErr != nil {
		return writeErr
	}
	if written != len(value) {
		return unix.EIO
	}
	return closeErr
}

func (linuxWorkerdCgroupBackend) readControl(directoryFD int, name string, limit int) (string, error) {
	if limit < 1 || limit > maximumWorkerdCgroupControlBytes {
		return "", errWorkerdCgroupContract
	}
	fd, err := unix.Openat2(directoryFD, name, &unix.OpenHow{
		Flags: uint64(unix.O_RDONLY | unix.O_CLOEXEC), Resolve: workerdCgroupSecureResolve,
	})
	if err != nil {
		return "", err
	}
	buffer := make([]byte, limit+1)
	offset := 0
	var readErr error
	for offset < len(buffer) {
		read, currentErr := unix.Read(fd, buffer[offset:])
		if currentErr != nil {
			if errors.Is(currentErr, unix.EINTR) {
				continue
			}
			readErr = currentErr
			break
		}
		if read == 0 {
			break
		}
		offset += read
	}
	closeErr := unix.Close(fd)
	if readErr != nil {
		return "", readErr
	}
	if offset > limit {
		return "", fmt.Errorf("%w: oversized cgroup control value", errWorkerdCgroupContract)
	}
	if closeErr != nil {
		return "", closeErr
	}
	return string(buffer[:offset]), nil
}

func (linuxWorkerdCgroupBackend) identityAt(rootFD int, name string) (workerdCgroupIdentity, bool, error) {
	fd, err := unix.Openat2(rootFD, name, &unix.OpenHow{
		Flags: uint64(unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC), Resolve: workerdCgroupSecureResolve,
	})
	if errors.Is(err, unix.ENOENT) {
		return workerdCgroupIdentity{}, false, nil
	}
	if err != nil {
		return workerdCgroupIdentity{}, false, err
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return workerdCgroupIdentity{}, false, err
	}
	return workerdCgroupIdentity{Device: uint64(stat.Dev), Inode: stat.Ino}, true, nil
}

func (linuxWorkerdCgroupBackend) removeChild(rootFD int, name string) error {
	return unix.Unlinkat(rootFD, name, unix.AT_REMOVEDIR)
}

func (linuxWorkerdCgroupBackend) closeFD(fd int) error {
	return unix.Close(fd)
}

func (linuxWorkerdCgroupBackend) wait(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
