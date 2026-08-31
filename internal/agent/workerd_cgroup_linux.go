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

	"github.com/hancomac/circulusd/internal/identity"
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
	minimumWorkerdCgroupCPUQuota     = uint64(1_000)
	maximumWorkerdCgroupCPUQuota     = uint64(1_000_000_000)
	minimumWorkerdCgroupCPUPeriod    = uint64(1_000)
	maximumWorkerdCgroupCPUPeriod    = uint64(1_000_000)
	maximumWorkerdCgroupPIDs         = uint64(1 << 20)
	maximumWorkerdCgroupPathBytes    = 4096
	maximumWorkerdCgroupShardIDBytes = 1024
	maximumWorkerdCgroupControlBytes = 4096
	maximumWorkerdCgroupScalarBytes  = 64
	maximumWorkerdCgroupCPUMaxBytes  = 64
	maximumWorkerdCgroupCounterBytes = maximumWorkerdCgroupControlBytes
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
	CPUMax         CPUMax
	PIDsMax        uint64
}

type workerdCgroupMemoryEvents struct {
	Low          uint64
	High         uint64
	Max          uint64
	OOM          uint64
	OOMKill      uint64
	OOMGroupKill uint64
}

type workerdCgroupCPUStat struct {
	UsageMicros      uint64
	UserMicros       uint64
	SystemMicros     uint64
	Periods          uint64
	ThrottledPeriods uint64
	ThrottledMicros  uint64
}

type workerdCgroupCounterBaseline struct {
	MemoryEvents workerdCgroupMemoryEvents
	CPUStat      workerdCgroupCPUStat
}

type workerdCgroupResourceSample struct {
	AgentInstanceID    identity.ID
	ShardID            string
	Generation         ShardGeneration
	Identity           workerdCgroupIdentity
	MemoryCurrentBytes uint64
	MemoryEvents       workerdCgroupMemoryEvents
	MemoryEventsDelta  workerdCgroupMemoryEvents
	CPUStat            workerdCgroupCPUStat
	CPUStatDelta       workerdCgroupCPUStat
	PIDsCurrent        uint64
	CPUMax             CPUMax
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
	// authority orders short borrow/writer registrations. Cgroup I/O runs only
	// after this mutex is released; the counters below retain logical ownership.
	authority sync.RWMutex
	mu        sync.Mutex

	config                  workerdCgroupConfig
	backend                 workerdCgroupBackend
	rootFD                  int
	reserved                int
	activeBorrows           int
	authorityWritersWaiting int
	authorityWriterActive   bool
	authorityChanged        chan struct{}
	poisoned                bool
	closed                  bool
	closeDone               chan struct{}
	closeErr                error
}

type workerdCgroupDestroyOperation struct {
	done     chan struct{}
	finished bool
	err      error
}

type workerdCgroupLease struct {
	controller      *workerdCgroupController
	name            string
	agentInstanceID identity.ID
	shardID         string
	generation      ShardGeneration
	fd              int
	identity        workerdCgroupIdentity
	baseline        workerdCgroupCounterBaseline

	mu               sync.Mutex
	attachable       bool
	destroyed        bool
	terminalErr      error
	destroyOperation *workerdCgroupDestroyOperation
	activeBorrows    int
	borrowQuiescent  chan struct{}
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
		config.CPUMax.QuotaMicros < minimumWorkerdCgroupCPUQuota || config.CPUMax.QuotaMicros > maximumWorkerdCgroupCPUQuota ||
		config.CPUMax.PeriodMicros < minimumWorkerdCgroupCPUPeriod || config.CPUMax.PeriodMicros > maximumWorkerdCgroupCPUPeriod ||
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
		config:           config,
		backend:          backend,
		rootFD:           inspection.DirectoryFD,
		authorityChanged: make(chan struct{}),
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

func (controller *workerdCgroupController) notifyAuthorityChangedLocked() {
	close(controller.authorityChanged)
	controller.authorityChanged = make(chan struct{})
}

func (controller *workerdCgroupController) beginAuthorityWrite() {
	announced := false
	for {
		controller.authority.Lock()
		controller.mu.Lock()
		if !announced {
			controller.authorityWritersWaiting++
			controller.notifyAuthorityChangedLocked()
			announced = true
		}
		if !controller.authorityWriterActive && controller.activeBorrows == 0 {
			controller.authorityWritersWaiting--
			controller.authorityWriterActive = true
			controller.notifyAuthorityChangedLocked()
			controller.mu.Unlock()
			controller.authority.Unlock()
			return
		}
		changed := controller.authorityChanged
		controller.mu.Unlock()
		controller.authority.Unlock()
		<-changed
	}
}

func (controller *workerdCgroupController) endAuthorityWrite() {
	controller.authority.Lock()
	controller.mu.Lock()
	controller.authorityWriterActive = false
	controller.notifyAuthorityChangedLocked()
	controller.mu.Unlock()
	controller.authority.Unlock()
}

func (controller *workerdCgroupController) prepare(ctx context.Context, agentInstanceID identity.ID, shardID string, generation ShardGeneration) (resultLease *workerdCgroupLease, resultErr error) {
	if ctx == nil || agentInstanceID.Kind() != identity.Process || shardID == "" || len(shardID) > maximumWorkerdCgroupShardIDBytes || strings.IndexByte(shardID, 0) >= 0 || generation == 0 {
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

	name := workerdCgroupLeafName(agentInstanceID, shardID, generation)
	if err := controller.backend.mkdirExclusive(controller.rootFD, name, 0o700); err != nil {
		controller.mu.Lock()
		controller.reserved--
		controller.mu.Unlock()
		return nil, classifyWorkerdCgroupError("create shard cgroup", err)
	}
	fd, identity, err := controller.backend.openChild(controller.rootFD, name)
	if err != nil {
		controller.mu.Lock()
		controller.reserved--
		controller.poisoned = true
		controller.notifyAuthorityChangedLocked()
		controller.mu.Unlock()
		return nil, errors.Join(classifyWorkerdCgroupError("open shard cgroup", err), errWorkerdCgroupPoisoned)
	}
	lease := &workerdCgroupLease{
		controller: controller, name: name, agentInstanceID: agentInstanceID,
		shardID: shardID, generation: generation, fd: fd, identity: identity,
	}
	rollbackRequired := true
	defer func() {
		if !rollbackRequired || resultErr == nil {
			return
		}
		controller.beginAuthorityWrite()
		defer controller.endAuthorityWrite()
		currentIdentity, exists, identityErr := controller.backend.identityAt(controller.rootFD, name)
		if identityErr != nil {
			resultLease = lease
			resultErr = errors.Join(resultErr, classifyWorkerdCgroupError("verify rollback cgroup identity", identityErr))
			return
		}
		if !exists || currentIdentity != identity {
			controller.mu.Lock()
			controller.reserved--
			controller.poisoned = true
			controller.notifyAuthorityChangedLocked()
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
			resultLease = lease
			resultErr = errors.Join(resultErr, classifyWorkerdCgroupError("rollback shard cgroup", removeErr))
			return
		}
		controller.mu.Lock()
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
		{name: "cpu.max", value: strconv.FormatUint(controller.config.CPUMax.QuotaMicros, 10) + " " + strconv.FormatUint(controller.config.CPUMax.PeriodMicros, 10)},
		{name: "pids.max", value: fmt.Sprint(controller.config.PIDsMax)},
	}
	for _, limit := range limits {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := controller.backend.writeControl(fd, limit.name, limit.value); err != nil {
			return nil, classifyWorkerdCgroupError("write shard limit", err)
		}
		readLimit := maximumWorkerdCgroupControlBytes
		if limit.name == "cpu.max" {
			readLimit = maximumWorkerdCgroupCPUMaxBytes
		}
		readback, err := controller.backend.readControl(fd, limit.name, readLimit)
		if err != nil {
			return nil, classifyWorkerdCgroupError("read shard limit", err)
		}
		if limit.name == "cpu.max" {
			cpuMax, parseErr := parseWorkerdCgroupCPUMax(readback)
			if parseErr != nil || cpuMax != controller.config.CPUMax {
				return nil, fmt.Errorf("%w: shard limit readback mismatch", errWorkerdCgroupContract)
			}
			continue
		}
		if !exactCgroupControlValue(readback, limit.value) {
			return nil, fmt.Errorf("%w: shard limit readback mismatch", errWorkerdCgroupContract)
		}
	}
	if err := lease.verifyPinnedIdentity("verify resource baseline cgroup identity"); err != nil {
		return nil, err
	}
	baseline, err := readWorkerdCgroupCumulativeCounters(ctx, controller.backend, fd)
	if err != nil {
		return nil, err
	}
	if err := lease.verifyPinnedIdentity("reverify resource baseline cgroup identity"); err != nil {
		return nil, err
	}
	lease.baseline = baseline
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

func workerdCgroupLeafName(agentInstanceID identity.ID, shardID string, generation ShardGeneration) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(workerdCgroupLeafDomain))
	var encoded [8]byte
	agentIdentity := agentInstanceID.String()
	binary.BigEndian.PutUint64(encoded[:], uint64(len(agentIdentity)))
	_, _ = hash.Write(encoded[:])
	_, _ = hash.Write([]byte(agentIdentity))
	binary.BigEndian.PutUint64(encoded[:], uint64(len(shardID)))
	_, _ = hash.Write(encoded[:])
	_, _ = hash.Write([]byte(shardID))
	binary.BigEndian.PutUint64(encoded[:], uint64(generation))
	_, _ = hash.Write(encoded[:])
	return "workerd-" + hex.EncodeToString(hash.Sum(nil))
}

func canonicalWorkerdCgroupPayload(value string, maximumBytes int) (string, error) {
	if value == "" || len(value) > maximumBytes || strings.IndexByte(value, 0) >= 0 {
		return "", fmt.Errorf("%w: malformed cgroup control value", errWorkerdCgroupContract)
	}
	if strings.HasSuffix(value, "\n") {
		value = strings.TrimSuffix(value, "\n")
	}
	if value == "" || strings.ContainsRune(value, '\r') {
		return "", fmt.Errorf("%w: malformed cgroup control value", errWorkerdCgroupContract)
	}
	return value, nil
}

func parseCanonicalWorkerdCgroupUint(value string) (uint64, error) {
	if value == "" {
		return 0, fmt.Errorf("%w: empty cgroup counter", errWorkerdCgroupContract)
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || strconv.FormatUint(parsed, 10) != value {
		return 0, fmt.Errorf("%w: noncanonical cgroup counter", errWorkerdCgroupContract)
	}
	return parsed, nil
}

func parseWorkerdCgroupScalar(value string) (uint64, error) {
	payload, err := canonicalWorkerdCgroupPayload(value, maximumWorkerdCgroupScalarBytes)
	if err != nil {
		return 0, err
	}
	return parseCanonicalWorkerdCgroupUint(payload)
}

func parseWorkerdCgroupCounters(value string) (map[string]uint64, error) {
	payload, err := canonicalWorkerdCgroupPayload(value, maximumWorkerdCgroupCounterBytes)
	if err != nil {
		return nil, err
	}
	counters := make(map[string]uint64)
	for _, line := range strings.Split(payload, "\n") {
		separator := strings.IndexByte(line, ' ')
		if separator <= 0 || separator == len(line)-1 || strings.IndexByte(line[separator+1:], ' ') >= 0 {
			return nil, fmt.Errorf("%w: malformed cgroup counter line", errWorkerdCgroupContract)
		}
		name := line[:separator]
		for _, character := range name {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' {
				return nil, fmt.Errorf("%w: malformed cgroup counter name", errWorkerdCgroupContract)
			}
		}
		if _, duplicate := counters[name]; duplicate {
			return nil, fmt.Errorf("%w: duplicate cgroup counter", errWorkerdCgroupContract)
		}
		parsed, parseErr := parseCanonicalWorkerdCgroupUint(line[separator+1:])
		if parseErr != nil {
			return nil, parseErr
		}
		counters[name] = parsed
	}
	return counters, nil
}

func parseWorkerdCgroupMemoryEvents(value string) (workerdCgroupMemoryEvents, error) {
	counters, err := parseWorkerdCgroupCounters(value)
	if err != nil {
		return workerdCgroupMemoryEvents{}, err
	}
	for _, required := range []string{"low", "high", "max", "oom", "oom_kill"} {
		if _, found := counters[required]; !found {
			return workerdCgroupMemoryEvents{}, fmt.Errorf("%w: incomplete memory.events", errWorkerdCgroupContract)
		}
	}
	return workerdCgroupMemoryEvents{
		Low:          counters["low"],
		High:         counters["high"],
		Max:          counters["max"],
		OOM:          counters["oom"],
		OOMKill:      counters["oom_kill"],
		OOMGroupKill: counters["oom_group_kill"],
	}, nil
}

func parseWorkerdCgroupCPUStat(value string) (workerdCgroupCPUStat, error) {
	counters, err := parseWorkerdCgroupCounters(value)
	if err != nil {
		return workerdCgroupCPUStat{}, err
	}
	for _, required := range []string{"usage_usec", "user_usec", "system_usec", "nr_periods", "nr_throttled", "throttled_usec"} {
		if _, found := counters[required]; !found {
			return workerdCgroupCPUStat{}, fmt.Errorf("%w: incomplete cpu.stat", errWorkerdCgroupContract)
		}
	}
	return workerdCgroupCPUStat{
		UsageMicros:      counters["usage_usec"],
		UserMicros:       counters["user_usec"],
		SystemMicros:     counters["system_usec"],
		Periods:          counters["nr_periods"],
		ThrottledPeriods: counters["nr_throttled"],
		ThrottledMicros:  counters["throttled_usec"],
	}, nil
}

func parseWorkerdCgroupCPUMax(value string) (CPUMax, error) {
	payload, err := canonicalWorkerdCgroupPayload(value, maximumWorkerdCgroupCPUMaxBytes)
	if err != nil {
		return CPUMax{}, err
	}
	separator := strings.IndexByte(payload, ' ')
	if separator <= 0 || separator == len(payload)-1 || strings.IndexByte(payload[separator+1:], ' ') >= 0 {
		return CPUMax{}, fmt.Errorf("%w: cpu.max must contain exactly two tokens", errWorkerdCgroupContract)
	}
	quota, err := parseCanonicalWorkerdCgroupUint(payload[:separator])
	if err != nil {
		return CPUMax{}, err
	}
	period, err := parseCanonicalWorkerdCgroupUint(payload[separator+1:])
	if err != nil {
		return CPUMax{}, err
	}
	if quota < minimumWorkerdCgroupCPUQuota || quota > maximumWorkerdCgroupCPUQuota ||
		period < minimumWorkerdCgroupCPUPeriod || period > maximumWorkerdCgroupCPUPeriod {
		return CPUMax{}, fmt.Errorf("%w: cpu.max is outside finite bounds", errWorkerdCgroupContract)
	}
	return CPUMax{QuotaMicros: quota, PeriodMicros: period}, nil
}

func readWorkerdCgroupCumulativeCounters(ctx context.Context, backend workerdCgroupBackend, directoryFD int) (workerdCgroupCounterBaseline, error) {
	if err := ctx.Err(); err != nil {
		return workerdCgroupCounterBaseline{}, err
	}
	memoryValue, err := backend.readControl(directoryFD, "memory.events", maximumWorkerdCgroupCounterBytes)
	if err != nil {
		return workerdCgroupCounterBaseline{}, classifyWorkerdCgroupError("read shard memory events", err)
	}
	memoryEvents, err := parseWorkerdCgroupMemoryEvents(memoryValue)
	if err != nil {
		return workerdCgroupCounterBaseline{}, err
	}
	if err := ctx.Err(); err != nil {
		return workerdCgroupCounterBaseline{}, err
	}
	cpuValue, err := backend.readControl(directoryFD, "cpu.stat", maximumWorkerdCgroupCounterBytes)
	if err != nil {
		return workerdCgroupCounterBaseline{}, classifyWorkerdCgroupError("read shard cpu stat", err)
	}
	cpuStat, err := parseWorkerdCgroupCPUStat(cpuValue)
	if err != nil {
		return workerdCgroupCounterBaseline{}, err
	}
	if err := ctx.Err(); err != nil {
		return workerdCgroupCounterBaseline{}, err
	}
	return workerdCgroupCounterBaseline{MemoryEvents: memoryEvents, CPUStat: cpuStat}, nil
}

func (lease *workerdCgroupLease) verifyPinnedIdentity(operation string) error {
	identity, exists, err := lease.controller.backend.identityAt(lease.controller.rootFD, lease.name)
	if err != nil {
		return classifyWorkerdCgroupError(operation, err)
	}
	if !exists || identity != lease.identity {
		lease.controller.mu.Lock()
		lease.controller.poisoned = true
		lease.controller.notifyAuthorityChangedLocked()
		lease.controller.mu.Unlock()
		return fmt.Errorf("%s: %w", operation, errors.Join(errWorkerdCgroupPathReplaced, errWorkerdCgroupPoisoned))
	}
	return nil
}

func (lease *workerdCgroupLease) sampleResources(ctx context.Context) (workerdCgroupResourceSample, error) {
	if lease == nil || lease.controller == nil || ctx == nil {
		return workerdCgroupResourceSample{}, errInvalidWorkerdCgroupRequest
	}
	if err := ctx.Err(); err != nil {
		return workerdCgroupResourceSample{}, err
	}
	var sample workerdCgroupResourceSample
	err := lease.withDirectoryFD(func(directoryFD int) error {
		if err := lease.verifyPinnedIdentity("verify resource sample cgroup identity"); err != nil {
			return err
		}
		memoryValue, err := lease.controller.backend.readControl(directoryFD, "memory.current", maximumWorkerdCgroupScalarBytes)
		if err != nil {
			return classifyWorkerdCgroupError("read shard memory current", err)
		}
		memoryCurrent, err := parseWorkerdCgroupScalar(memoryValue)
		if err != nil {
			return err
		}
		counters, err := readWorkerdCgroupCumulativeCounters(ctx, lease.controller.backend, directoryFD)
		if err != nil {
			return err
		}
		cpuMaxValue, err := lease.controller.backend.readControl(directoryFD, "cpu.max", maximumWorkerdCgroupCPUMaxBytes)
		if err != nil {
			return classifyWorkerdCgroupError("read shard cpu max", err)
		}
		cpuMax, err := parseWorkerdCgroupCPUMax(cpuMaxValue)
		if err != nil {
			return err
		}
		if cpuMax != lease.controller.config.CPUMax {
			return fmt.Errorf("%w: cpu.max changed after launch", errWorkerdCgroupContract)
		}
		pidsValue, err := lease.controller.backend.readControl(directoryFD, "pids.current", maximumWorkerdCgroupScalarBytes)
		if err != nil {
			return classifyWorkerdCgroupError("read shard pids current", err)
		}
		pidsCurrent, err := parseWorkerdCgroupScalar(pidsValue)
		if err != nil {
			return err
		}
		baselineMemory := lease.baseline.MemoryEvents
		currentMemory := counters.MemoryEvents
		if currentMemory.Low < baselineMemory.Low || currentMemory.High < baselineMemory.High || currentMemory.Max < baselineMemory.Max ||
			currentMemory.OOM < baselineMemory.OOM || currentMemory.OOMKill < baselineMemory.OOMKill || currentMemory.OOMGroupKill < baselineMemory.OOMGroupKill {
			return fmt.Errorf("%w: memory.events decreased from generation baseline", errWorkerdCgroupContract)
		}
		baselineCPU := lease.baseline.CPUStat
		currentCPU := counters.CPUStat
		if currentCPU.UsageMicros < baselineCPU.UsageMicros || currentCPU.UserMicros < baselineCPU.UserMicros || currentCPU.SystemMicros < baselineCPU.SystemMicros ||
			currentCPU.Periods < baselineCPU.Periods || currentCPU.ThrottledPeriods < baselineCPU.ThrottledPeriods || currentCPU.ThrottledMicros < baselineCPU.ThrottledMicros {
			return fmt.Errorf("%w: cpu.stat decreased from generation baseline", errWorkerdCgroupContract)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := lease.verifyPinnedIdentity("reverify resource sample cgroup identity"); err != nil {
			return err
		}
		sample = workerdCgroupResourceSample{
			AgentInstanceID:    lease.agentInstanceID,
			ShardID:            lease.shardID,
			Generation:         lease.generation,
			Identity:           lease.identity,
			MemoryCurrentBytes: memoryCurrent,
			MemoryEvents:       currentMemory,
			MemoryEventsDelta: workerdCgroupMemoryEvents{
				Low: currentMemory.Low - baselineMemory.Low, High: currentMemory.High - baselineMemory.High,
				Max: currentMemory.Max - baselineMemory.Max, OOM: currentMemory.OOM - baselineMemory.OOM,
				OOMKill: currentMemory.OOMKill - baselineMemory.OOMKill, OOMGroupKill: currentMemory.OOMGroupKill - baselineMemory.OOMGroupKill,
			},
			CPUStat: currentCPU,
			CPUStatDelta: workerdCgroupCPUStat{
				UsageMicros: currentCPU.UsageMicros - baselineCPU.UsageMicros, UserMicros: currentCPU.UserMicros - baselineCPU.UserMicros,
				SystemMicros: currentCPU.SystemMicros - baselineCPU.SystemMicros, Periods: currentCPU.Periods - baselineCPU.Periods,
				ThrottledPeriods: currentCPU.ThrottledPeriods - baselineCPU.ThrottledPeriods, ThrottledMicros: currentCPU.ThrottledMicros - baselineCPU.ThrottledMicros,
			},
			PIDsCurrent: pidsCurrent,
			CPUMax:      cpuMax,
		}
		return nil
	})
	if err != nil {
		return workerdCgroupResourceSample{}, err
	}
	return sample, nil
}

func (lease *workerdCgroupLease) withDirectoryFD(use func(int) error) error {
	if lease == nil || lease.controller == nil || use == nil {
		return errInvalidWorkerdCgroupRequest
	}
	controller := lease.controller
	for {
		controller.authority.RLock()
		controller.mu.Lock()
		if controller.poisoned || controller.closed {
			controller.mu.Unlock()
			controller.authority.RUnlock()
			return errWorkerdCgroupLeaseUnavailable
		}
		if controller.authorityWriterActive || controller.authorityWritersWaiting > 0 {
			changed := controller.authorityChanged
			controller.mu.Unlock()
			controller.authority.RUnlock()
			<-changed
			continue
		}
		controller.activeBorrows++
		controller.mu.Unlock()
		controller.authority.RUnlock()
		break
	}
	lease.mu.Lock()
	if !lease.attachable || lease.destroyed || lease.destroyOperation != nil {
		lease.mu.Unlock()
		controller.mu.Lock()
		controller.activeBorrows--
		controller.notifyAuthorityChangedLocked()
		controller.mu.Unlock()
		return errWorkerdCgroupLeaseUnavailable
	}
	if lease.activeBorrows == 0 {
		lease.borrowQuiescent = make(chan struct{})
	}
	lease.activeBorrows++
	directoryFD := lease.fd
	lease.mu.Unlock()
	defer func() {
		lease.mu.Lock()
		lease.activeBorrows--
		if lease.activeBorrows == 0 {
			close(lease.borrowQuiescent)
			lease.borrowQuiescent = nil
		}
		lease.mu.Unlock()
		controller.mu.Lock()
		controller.activeBorrows--
		controller.notifyAuthorityChangedLocked()
		controller.mu.Unlock()
	}()
	return use(directoryFD)
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
	borrowQuiescent := lease.borrowQuiescent
	lease.mu.Unlock()

	go func() {
		controller := lease.controller
		var cleanupErr error
		ownershipReleased := false
		if borrowQuiescent != nil {
			<-borrowQuiescent
		}
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
			controller.beginAuthorityWrite()
			identity, exists, err := controller.backend.identityAt(controller.rootFD, lease.name)
			if err != nil {
				cleanupErr = classifyWorkerdCgroupError("verify shard cgroup identity", err)
			} else if !exists || identity != lease.identity {
				controller.mu.Lock()
				controller.reserved--
				controller.poisoned = true
				controller.notifyAuthorityChangedLocked()
				ownershipReleased = true
				controller.mu.Unlock()
				closeErr := controller.backend.closeFD(lease.fd)
				cleanupErr = errors.Join(errWorkerdCgroupPathReplaced, errWorkerdCgroupPoisoned)
				if closeErr != nil {
					cleanupErr = errors.Join(cleanupErr, classifyWorkerdCgroupError("close poisoned shard cgroup", closeErr))
				}
			} else if err := controller.backend.removeChild(controller.rootFD, lease.name); err != nil {
				cleanupErr = classifyWorkerdCgroupError("remove shard cgroup", err)
			} else {
				controller.mu.Lock()
				controller.reserved--
				ownershipReleased = true
				controller.mu.Unlock()
				if closeErr := controller.backend.closeFD(lease.fd); closeErr != nil {
					cleanupErr = classifyWorkerdCgroupError("close removed shard cgroup", closeErr)
				}
			}
			controller.endAuthorityWrite()
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
	controller.mu.Lock()
	if controller.closed {
		done := controller.closeDone
		controller.mu.Unlock()
		<-done
		controller.mu.Lock()
		closeErr := controller.closeErr
		controller.mu.Unlock()
		return closeErr
	}
	if controller.reserved != 0 {
		controller.mu.Unlock()
		return errWorkerdCgroupBusy
	}
	controller.closed = true
	controller.closeDone = make(chan struct{})
	controller.notifyAuthorityChangedLocked()
	rootFD := controller.rootFD
	controller.rootFD = -1
	controller.mu.Unlock()

	controller.beginAuthorityWrite()
	var closeErr error
	if err := controller.backend.closeFD(rootFD); err != nil {
		closeErr = classifyWorkerdCgroupError("close delegated root", err)
	}
	controller.endAuthorityWrite()

	controller.mu.Lock()
	if controller.poisoned {
		closeErr = errors.Join(errWorkerdCgroupPoisoned, closeErr)
	}
	controller.closeErr = closeErr
	close(controller.closeDone)
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
