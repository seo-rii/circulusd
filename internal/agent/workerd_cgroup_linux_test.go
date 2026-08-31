//go:build linux

package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/identity"
	"golang.org/x/sys/unix"
)

func TestNewWorkerdCgroupControllerRejectsConfigurationOutsideClosedBounds(t *testing.T) {
	valid := workerdCgroupConfig{
		RootPath:       "/sys/fs/cgroup/circulusd-workerd",
		MaximumShards:  1,
		DrainTimeout:   time.Nanosecond,
		MemoryMaxBytes: 1,
		SwapMaxBytes:   0,
		CPUMax:         CPUMax{QuotaMicros: 1_000, PeriodMicros: 1_000},
		PIDsMax:        1,
	}
	tests := []struct {
		name   string
		mutate func(*workerdCgroupConfig)
	}{
		{name: "relative root", mutate: func(config *workerdCgroupConfig) { config.RootPath = "sys/fs/cgroup/workerd" }},
		{name: "filesystem root", mutate: func(config *workerdCgroupConfig) { config.RootPath = "/" }},
		{name: "noncanonical root", mutate: func(config *workerdCgroupConfig) { config.RootPath += "/../circulusd-workerd" }},
		{name: "zero capacity", mutate: func(config *workerdCgroupConfig) { config.MaximumShards = 0 }},
		{name: "excessive capacity", mutate: func(config *workerdCgroupConfig) { config.MaximumShards = 4097 }},
		{name: "zero drain", mutate: func(config *workerdCgroupConfig) { config.DrainTimeout = 0 }},
		{name: "excessive drain", mutate: func(config *workerdCgroupConfig) { config.DrainTimeout = 30*time.Second + time.Nanosecond }},
		{name: "zero memory", mutate: func(config *workerdCgroupConfig) { config.MemoryMaxBytes = 0 }},
		{name: "excessive memory", mutate: func(config *workerdCgroupConfig) { config.MemoryMaxBytes = (1 << 50) + 1 }},
		{name: "nonzero swap", mutate: func(config *workerdCgroupConfig) { config.SwapMaxBytes = 1 }},
		{name: "zero cpu quota", mutate: func(config *workerdCgroupConfig) { config.CPUMax.QuotaMicros = 0 }},
		{name: "cpu quota below minimum", mutate: func(config *workerdCgroupConfig) { config.CPUMax.QuotaMicros = 999 }},
		{name: "cpu quota above maximum", mutate: func(config *workerdCgroupConfig) { config.CPUMax.QuotaMicros = 1_000_000_001 }},
		{name: "zero cpu period", mutate: func(config *workerdCgroupConfig) { config.CPUMax.PeriodMicros = 0 }},
		{name: "cpu period below minimum", mutate: func(config *workerdCgroupConfig) { config.CPUMax.PeriodMicros = 999 }},
		{name: "cpu period above maximum", mutate: func(config *workerdCgroupConfig) { config.CPUMax.PeriodMicros = 1_000_001 }},
		{name: "zero pids", mutate: func(config *workerdCgroupConfig) { config.PIDsMax = 0 }},
		{name: "excessive pids", mutate: func(config *workerdCgroupConfig) { config.PIDsMax = (1 << 20) + 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.mutate(&config)
			controller, err := newWorkerdCgroupControllerWithBackend(config, nil)
			if controller != nil || !errors.Is(err, errInvalidWorkerdCgroupConfig) {
				t.Fatalf("newWorkerdCgroupControllerWithBackend() = %#v, %v, want nil, invalid config", controller, err)
			}
		})
	}
}

func TestNewWorkerdCgroupControllerAcceptsClosedConfigurationBounds(t *testing.T) {
	minimum := validWorkerdCgroupConfig()
	minimum.MaximumShards = 1
	minimum.DrainTimeout = time.Nanosecond
	minimum.MemoryMaxBytes = 1
	minimum.CPUMax = CPUMax{QuotaMicros: 1_000, PeriodMicros: 1_000}
	minimum.PIDsMax = 1
	maximum := validWorkerdCgroupConfig()
	maximum.MaximumShards = 4096
	maximum.DrainTimeout = 30 * time.Second
	maximum.MemoryMaxBytes = 1 << 50
	maximum.CPUMax = CPUMax{QuotaMicros: 1_000_000_000, PeriodMicros: 1_000_000}
	maximum.PIDsMax = 1 << 20
	for name, config := range map[string]workerdCgroupConfig{"minimum": minimum, "maximum": maximum} {
		t.Run(name, func(t *testing.T) {
			controller, err := newWorkerdCgroupControllerWithBackend(config, newFakeWorkerdCgroupBackend())
			if err != nil {
				t.Fatalf("newWorkerdCgroupControllerWithBackend() error = %v", err)
			}
			if err := controller.close(); err != nil {
				t.Fatalf("close() error = %v", err)
			}
		})
	}
}

func TestNewWorkerdCgroupControllerValidatesDelegatedRootFailClosed(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*fakeWorkerdCgroupBackend)
		wantErr error
	}{
		{name: "missing", mutate: func(backend *fakeWorkerdCgroupBackend) { backend.inspectErr = unix.ENOENT }, wantErr: errWorkerdCgroupUnavailable},
		{name: "permission", mutate: func(backend *fakeWorkerdCgroupBackend) { backend.inspectErr = unix.EACCES }, wantErr: errWorkerdCgroupUnavailable},
		{name: "readonly", mutate: func(backend *fakeWorkerdCgroupBackend) { backend.inspectErr = unix.EROFS }, wantErr: errWorkerdCgroupUnavailable},
		{name: "unsupported syscall", mutate: func(backend *fakeWorkerdCgroupBackend) { backend.inspectErr = unix.ENOSYS }, wantErr: errWorkerdCgroupUnavailable},
		{name: "symlink escape", mutate: func(backend *fakeWorkerdCgroupBackend) { backend.inspectErr = unix.EXDEV }, wantErr: errWorkerdCgroupContract},
		{name: "foreign intermediate", mutate: func(backend *fakeWorkerdCgroupBackend) { backend.inspection.Components[1].UID = 2001 }, wantErr: errWorkerdCgroupContract},
		{name: "daemon-owned replaceable intermediate", mutate: func(backend *fakeWorkerdCgroupBackend) {
			backend.inspection.Components[1].UID = backend.effectiveUID
			backend.inspection.Components[1].GID = backend.effectiveGID
			backend.inspection.Components[1].Mode = unix.S_IFDIR | 0o700
		}, wantErr: errWorkerdCgroupContract},
		{name: "replaceable intermediate", mutate: func(backend *fakeWorkerdCgroupBackend) { backend.inspection.Components[1].Mode = unix.S_IFDIR | 0o777 }, wantErr: errWorkerdCgroupContract},
		{name: "wrong filesystem", mutate: func(backend *fakeWorkerdCgroupBackend) { backend.inspection.FilesystemType = unix.TMPFS_MAGIC }, wantErr: errWorkerdCgroupContract},
		{name: "wrong owner", mutate: func(backend *fakeWorkerdCgroupBackend) { backend.inspection.Components[3].UID++ }, wantErr: errWorkerdCgroupContract},
		{name: "wrong group", mutate: func(backend *fakeWorkerdCgroupBackend) { backend.inspection.Components[3].GID++ }, wantErr: errWorkerdCgroupContract},
		{name: "nonprivate mode", mutate: func(backend *fakeWorkerdCgroupBackend) { backend.inspection.Components[3].Mode = unix.S_IFDIR | 0o750 }, wantErr: errWorkerdCgroupContract},
		{name: "threaded root", mutate: func(backend *fakeWorkerdCgroupBackend) { backend.inspection.CgroupType = "threaded\n" }, wantErr: errWorkerdCgroupContract},
		{name: "root process", mutate: func(backend *fakeWorkerdCgroupBackend) { backend.inspection.Processes = "123\n" }, wantErr: errWorkerdCgroupContract},
		{name: "missing cpu controller", mutate: func(backend *fakeWorkerdCgroupBackend) { backend.inspection.Controllers = "memory pids\n" }, wantErr: errWorkerdCgroupContract},
		{name: "missing delegated pids controller", mutate: func(backend *fakeWorkerdCgroupBackend) { backend.inspection.SubtreeControl = "cpu memory\n" }, wantErr: errWorkerdCgroupContract},
		{name: "existing child cgroup", mutate: func(backend *fakeWorkerdCgroupBackend) { backend.inspection.ChildDirectories = 1 }, wantErr: errWorkerdCgroupContract},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backend := newFakeWorkerdCgroupBackend()
			test.mutate(backend)
			controller, err := newWorkerdCgroupControllerWithBackend(validWorkerdCgroupConfig(), backend)
			if controller != nil || !errors.Is(err, test.wantErr) {
				t.Fatalf("newWorkerdCgroupControllerWithBackend() = %#v, %v, want nil, %v", controller, err, test.wantErr)
			}
			if backend.openFileDescriptors() != 0 {
				t.Fatalf("open file descriptors after rejected root = %d, want 0", backend.openFileDescriptors())
			}
		})
	}
}

func TestWorkerdCgroupPrepareWritesAndReadsBackExactControls(t *testing.T) {
	config, backend, controller := newWorkerdCgroupFixture(t)
	agentInstanceID := workerdTestAgentInstanceID(0)
	lease, err := controller.prepare(context.Background(), agentInstanceID, "shared-shard-a", 7)
	if err != nil {
		t.Fatalf("prepare() error = %v", err)
	}
	borrowedFD := -1
	if err := lease.withDirectoryFD(func(fd int) error {
		borrowedFD = fd
		return nil
	}); err != nil {
		t.Fatalf("withDirectoryFD() error = %v", err)
	}
	if borrowedFD < 0 {
		t.Fatalf("borrowed lease directory fd = %d, want a private held descriptor", borrowedFD)
	}
	wantWrites := []fakeWorkerdCgroupWrite{
		{Name: "cgroup.max.depth", Value: "0"},
		{Name: "cgroup.max.descendants", Value: "0"},
		{Name: "memory.max", Value: fmt.Sprint(config.MemoryMaxBytes)},
		{Name: "memory.swap.max", Value: "0"},
		{Name: "cpu.max", Value: "50000 100000"},
		{Name: "pids.max", Value: fmt.Sprint(config.PIDsMax)},
	}
	if writes := backend.limitWrites(); !reflect.DeepEqual(writes, wantWrites) {
		t.Fatalf("control writes = %#v, want %#v", writes, wantWrites)
	}
	if modes := backend.mkdirModesSeen(); !reflect.DeepEqual(modes, []uint32{0o700}) {
		t.Fatalf("mkdir modes = %#v, want exclusive private 0700", modes)
	}
	firstName := backend.onlyChildName(t)
	if firstName != workerdCgroupLeafName(agentInstanceID, "shared-shard-a", 7) {
		t.Fatalf("leaf name = %q, want deterministic domain-separated identity", firstName)
	}
	if firstName == workerdCgroupLeafName(agentInstanceID, "shared-shard-a", 8) {
		t.Fatal("leaf name does not bind shard generation")
	}
	evidence := controller.evidence()
	if !evidence.ReferenceOnly || evidence.ProductionEligible || evidence.ConformanceClaimed {
		t.Fatalf("evidence = %+v, want reference-only non-production evidence", evidence)
	}
	if err := lease.destroy(context.Background()); err != nil {
		t.Fatalf("destroy() error = %v", err)
	}
	if err := controller.close(); err != nil {
		t.Fatalf("close() error = %v", err)
	}
}

func TestWorkerdCgroupPrepareRejectsMissingOrWrongKindAgentIdentityBeforeAllocation(t *testing.T) {
	_, backend, controller := newWorkerdCgroupFixture(t)
	tenantID, err := identity.New(identity.Tenant)
	if err != nil {
		t.Fatalf("identity.New(tenant) error = %v", err)
	}
	for name, agentInstanceID := range map[string]identity.ID{
		"empty":      {},
		"wrong kind": tenantID,
	} {
		t.Run(name, func(t *testing.T) {
			lease, prepareErr := controller.prepare(context.Background(), agentInstanceID, "invalid-agent-identity", 1)
			if lease != nil || !errors.Is(prepareErr, errInvalidWorkerdCgroupRequest) {
				t.Fatalf("prepare() = %#v, %v, want nil/errInvalidWorkerdCgroupRequest", lease, prepareErr)
			}
		})
	}
	if children := backend.childCount(); children != 0 {
		t.Fatalf("invalid agent identities allocated %d cgroup(s)", children)
	}
	if err := controller.close(); err != nil {
		t.Fatalf("close() error = %v", err)
	}
}

func TestWorkerdCgroupSeparatesAgentBootsForSameShardGeneration(t *testing.T) {
	_, backend, controller := newWorkerdCgroupFixture(t)
	oldAgentInstanceID := workerdTestAgentInstanceID(0)
	newAgentInstanceID := workerdTestAgentInstanceID(1)
	oldLease, err := controller.prepare(context.Background(), oldAgentInstanceID, "cross-boot-shard", 7)
	if err != nil {
		t.Fatalf("prepare(old boot) error = %v", err)
	}
	newLease, err := controller.prepare(context.Background(), newAgentInstanceID, "cross-boot-shard", 7)
	if err != nil {
		t.Fatalf("prepare(new boot) error = %v", err)
	}
	if oldLease.name == newLease.name {
		t.Fatalf("cross-boot leaf names both = %q", oldLease.name)
	}
	if oldLease.agentInstanceID != oldAgentInstanceID || newLease.agentInstanceID != newAgentInstanceID {
		t.Fatalf("lease agent identities = %q/%q, want %q/%q", oldLease.agentInstanceID, newLease.agentInstanceID, oldAgentInstanceID, newAgentInstanceID)
	}
	if err := oldLease.destroy(context.Background()); err != nil {
		t.Fatalf("destroy(old boot) error = %v", err)
	}
	if children := backend.childCount(); children != 1 {
		t.Fatalf("children after old boot destroy = %d, want new boot leaf retained", children)
	}
	sample, err := newLease.sampleResources(context.Background())
	if err != nil {
		t.Fatalf("sampleResources(new boot) error = %v", err)
	}
	if sample.AgentInstanceID != newAgentInstanceID || sample.ShardID != "cross-boot-shard" || sample.Generation != 7 {
		t.Fatalf("new boot sample identity = %#v", sample)
	}
	if err := newLease.destroy(context.Background()); err != nil {
		t.Fatalf("destroy(new boot) error = %v", err)
	}
	if err := controller.close(); err != nil {
		t.Fatalf("close() error = %v", err)
	}
}

func TestWorkerdCgroupPrepareRejectsNonCanonicalCPUMaxReadback(t *testing.T) {
	for name, readback := range map[string]string{
		"unlimited quota":      "max 100000\n",
		"zero quota":           "0 100000\n",
		"quota below minimum":  "999 100000\n",
		"quota above maximum":  "1000000001 100000\n",
		"zero period":          "50000 0\n",
		"period below minimum": "50000 999\n",
		"period above maximum": "50000 1000001\n",
		"missing period":       "50000\n",
		"extra token":          "50000 100000 extra\n",
		"noncanonical decimal": "050000 100000\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, backend, controller := newWorkerdCgroupFixture(t)
			backend.corruptReadback["cpu.max"] = readback
			lease, err := controller.prepare(context.Background(), workerdTestAgentInstanceID(0), "strict-cpu-max", 1)
			if lease != nil || !errors.Is(err, errWorkerdCgroupContract) {
				t.Fatalf("prepare(cpu.max=%q) = %#v, %v, want nil, contract error", readback, lease, err)
			}
			if children := backend.childCount(); children != 0 {
				t.Fatalf("children after rejected cpu.max = %d, want 0", children)
			}
			if err := controller.close(); err != nil {
				t.Fatalf("close() error = %v", err)
			}
		})
	}
}

func TestParseWorkerdCgroupScalarRejectsNonCanonicalOrOversizedValues(t *testing.T) {
	for name, value := range map[string]string{
		"empty":               "",
		"negative":            "-1\n",
		"plus sign":           "+1\n",
		"leading zero":        "01\n",
		"leading whitespace":  " 1\n",
		"trailing whitespace": "1 \n",
		"extra token":         "1 2\n",
		"unlimited":           "max\n",
		"extra newline":       "1\n\n",
		"overflow":            "18446744073709551616\n",
		"oversized":           strings.Repeat("1", maximumWorkerdCgroupScalarBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if parsed, err := parseWorkerdCgroupScalar(value); parsed != 0 || !errors.Is(err, errWorkerdCgroupContract) {
				t.Fatalf("parseWorkerdCgroupScalar(%q) = %d, %v, want zero, contract error", value, parsed, err)
			}
		})
	}
	for name, value := range map[string]string{
		"zero":    "0\n",
		"decimal": "50000\n",
		"uint64":  "18446744073709551615\n",
	} {
		t.Run(name, func(t *testing.T) {
			parsed, err := parseWorkerdCgroupScalar(value)
			if err != nil {
				t.Fatalf("parseWorkerdCgroupScalar(%q) error = %v", value, err)
			}
			if strconv.FormatUint(parsed, 10)+"\n" != value {
				t.Fatalf("parsed scalar = %d, does not round-trip to %q", parsed, value)
			}
		})
	}
}

func TestParseWorkerdCgroupMemoryEventsRejectsMalformedCounters(t *testing.T) {
	valid := "low 1\nhigh 2\nmax 3\noom 4\noom_kill 5\noom_group_kill 6\n"
	parsed, err := parseWorkerdCgroupMemoryEvents(valid)
	if err != nil {
		t.Fatalf("parseWorkerdCgroupMemoryEvents(valid) error = %v", err)
	}
	if parsed != (workerdCgroupMemoryEvents{Low: 1, High: 2, Max: 3, OOM: 4, OOMKill: 5, OOMGroupKill: 6}) {
		t.Fatalf("memory events = %+v", parsed)
	}
	for name, value := range map[string]string{
		"empty":            "",
		"missing oom kill": "low 1\nhigh 2\nmax 3\noom 4\n",
		"duplicate":        valid + "oom 7\n",
		"negative":         strings.Replace(valid, "oom 4", "oom -1", 1),
		"plus sign":        strings.Replace(valid, "oom 4", "oom +4", 1),
		"leading zero":     strings.Replace(valid, "oom 4", "oom 04", 1),
		"whitespace":       strings.Replace(valid, "oom 4", "oom  4", 1),
		"extra token":      strings.Replace(valid, "oom 4", "oom 4 extra", 1),
		"overflow":         strings.Replace(valid, "oom 4", "oom 18446744073709551616", 1),
		"oversized":        strings.Repeat("x", maximumWorkerdCgroupCounterBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if got, parseErr := parseWorkerdCgroupMemoryEvents(value); got != (workerdCgroupMemoryEvents{}) || !errors.Is(parseErr, errWorkerdCgroupContract) {
				t.Fatalf("parseWorkerdCgroupMemoryEvents(%q) = %+v, %v, want zero, contract error", value, got, parseErr)
			}
		})
	}
}

func TestParseWorkerdCgroupCPUStatRejectsMalformedCounters(t *testing.T) {
	valid := "usage_usec 10\nuser_usec 4\nsystem_usec 6\nnr_periods 8\nnr_throttled 3\nthrottled_usec 2\n"
	parsed, err := parseWorkerdCgroupCPUStat(valid)
	if err != nil {
		t.Fatalf("parseWorkerdCgroupCPUStat(valid) error = %v", err)
	}
	if parsed != (workerdCgroupCPUStat{UsageMicros: 10, UserMicros: 4, SystemMicros: 6, Periods: 8, ThrottledPeriods: 3, ThrottledMicros: 2}) {
		t.Fatalf("cpu stat = %+v", parsed)
	}
	for name, value := range map[string]string{
		"empty":                "",
		"missing nr throttled": "usage_usec 10\nuser_usec 4\nsystem_usec 6\nnr_periods 8\nthrottled_usec 2\n",
		"duplicate":            valid + "usage_usec 11\n",
		"negative":             strings.Replace(valid, "usage_usec 10", "usage_usec -1", 1),
		"plus sign":            strings.Replace(valid, "usage_usec 10", "usage_usec +10", 1),
		"leading zero":         strings.Replace(valid, "usage_usec 10", "usage_usec 010", 1),
		"whitespace":           strings.Replace(valid, "usage_usec 10", "usage_usec\t10", 1),
		"extra token":          strings.Replace(valid, "usage_usec 10", "usage_usec 10 extra", 1),
		"overflow":             strings.Replace(valid, "usage_usec 10", "usage_usec 18446744073709551616", 1),
		"oversized":            strings.Repeat("x", maximumWorkerdCgroupCounterBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if got, parseErr := parseWorkerdCgroupCPUStat(value); got != (workerdCgroupCPUStat{}) || !errors.Is(parseErr, errWorkerdCgroupContract) {
				t.Fatalf("parseWorkerdCgroupCPUStat(%q) = %+v, %v, want zero, contract error", value, got, parseErr)
			}
		})
	}
}

func TestParseWorkerdCgroupCPUMaxRequiresExactFiniteTwoTokens(t *testing.T) {
	for name, value := range map[string]string{
		"minimum":   "1000 1000\n",
		"reference": "50000 100000\n",
		"maximum":   "1000000000 1000000\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseWorkerdCgroupCPUMax(value); err != nil {
				t.Fatalf("parseWorkerdCgroupCPUMax(%q) error = %v", value, err)
			}
		})
	}
	for name, value := range map[string]string{
		"empty":              "",
		"unlimited":          "max 100000\n",
		"zero quota":         "0 100000\n",
		"quota below range":  "999 100000\n",
		"quota above range":  "1000000001 100000\n",
		"zero period":        "50000 0\n",
		"period below range": "50000 999\n",
		"period above range": "50000 1000001\n",
		"leading zero":       "050000 100000\n",
		"whitespace":         "50000  100000\n",
		"missing period":     "50000\n",
		"extra token":        "50000 100000 extra\n",
		"overflow":           "18446744073709551616 100000\n",
		"oversized":          strings.Repeat("1", maximumWorkerdCgroupCPUMaxBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := parseWorkerdCgroupCPUMax(value); got != (CPUMax{}) || !errors.Is(err, errWorkerdCgroupContract) {
				t.Fatalf("parseWorkerdCgroupCPUMax(%q) = %+v, %v, want zero, contract error", value, got, err)
			}
		})
	}
}

func TestWorkerdCgroupResourceSampleUsesPinnedGenerationBaselineAndBoundedReads(t *testing.T) {
	baselineMemory := workerdCgroupMemoryEvents{Low: 1, High: 2, Max: 3, OOM: 4, OOMKill: 5, OOMGroupKill: 6}
	baselineCPU := workerdCgroupCPUStat{UsageMicros: 10, UserMicros: 4, SystemMicros: 6, Periods: 8, ThrottledPeriods: 3, ThrottledMicros: 2}
	backend := newFakeWorkerdCgroupBackend()
	backend.initialMemoryEvents = formatFakeWorkerdCgroupMemoryEvents(baselineMemory)
	backend.initialCPUStat = formatFakeWorkerdCgroupCPUStat(baselineCPU)
	config := validWorkerdCgroupConfig()
	controller, err := newWorkerdCgroupControllerWithBackend(config, backend)
	if err != nil {
		t.Fatalf("newWorkerdCgroupControllerWithBackend() error = %v", err)
	}
	lease, err := controller.prepare(context.Background(), workerdTestAgentInstanceID(0), "resource-baseline", 9)
	if err != nil {
		t.Fatalf("prepare() error = %v", err)
	}

	currentMemory := workerdCgroupMemoryEvents{Low: 3, High: 5, Max: 7, OOM: 8, OOMKill: 10, OOMGroupKill: 12}
	currentCPU := workerdCgroupCPUStat{UsageMicros: 30, UserMicros: 14, SystemMicros: 16, Periods: 18, ThrottledPeriods: 8, ThrottledMicros: 7}
	backend.setOnlyChildControl(t, "memory.current", "67108864\n")
	backend.setOnlyChildControl(t, "memory.events", formatFakeWorkerdCgroupMemoryEvents(currentMemory))
	backend.setOnlyChildControl(t, "cpu.stat", formatFakeWorkerdCgroupCPUStat(currentCPU))
	backend.setOnlyChildControl(t, "pids.current", "17\n")
	backend.resetControlReads()

	sample, err := lease.sampleResources(context.Background())
	if err != nil {
		t.Fatalf("sampleResources() error = %v", err)
	}
	want := workerdCgroupResourceSample{
		AgentInstanceID:    workerdTestAgentInstanceID(0),
		ShardID:            "resource-baseline",
		Generation:         9,
		Identity:           lease.identity,
		MemoryCurrentBytes: 67_108_864,
		MemoryEvents:       currentMemory,
		MemoryEventsDelta:  workerdCgroupMemoryEvents{Low: 2, High: 3, Max: 4, OOM: 4, OOMKill: 5, OOMGroupKill: 6},
		CPUStat:            currentCPU,
		CPUStatDelta:       workerdCgroupCPUStat{UsageMicros: 20, UserMicros: 10, SystemMicros: 10, Periods: 10, ThrottledPeriods: 5, ThrottledMicros: 5},
		PIDsCurrent:        17,
		CPUMax:             config.CPUMax,
	}
	if sample != want {
		t.Fatalf("sampleResources() = %+v, want %+v", sample, want)
	}
	wantReads := []fakeWorkerdCgroupRead{
		{Name: "memory.current", Limit: maximumWorkerdCgroupScalarBytes},
		{Name: "memory.events", Limit: maximumWorkerdCgroupCounterBytes},
		{Name: "cpu.stat", Limit: maximumWorkerdCgroupCounterBytes},
		{Name: "cpu.max", Limit: maximumWorkerdCgroupCPUMaxBytes},
		{Name: "pids.current", Limit: maximumWorkerdCgroupScalarBytes},
	}
	if reads := backend.controlReads(); !reflect.DeepEqual(reads, wantReads) {
		t.Fatalf("resource control reads = %#v, want %#v", reads, wantReads)
	}

	backend.setOnlyChildControl(t, "memory.current", "1\n")
	if sample.MemoryCurrentBytes != want.MemoryCurrentBytes || sample.MemoryEvents != want.MemoryEvents || sample.CPUStat != want.CPUStat {
		t.Fatalf("returned sample changed after backend mutation: %+v", sample)
	}
	if err := lease.destroy(context.Background()); err != nil {
		t.Fatalf("destroy() error = %v", err)
	}
	if err := controller.close(); err != nil {
		t.Fatalf("close() error = %v", err)
	}
}

func TestWorkerdCgroupResourceSampleRejectsCounterDecreaseFromGenerationBaseline(t *testing.T) {
	tests := []struct {
		name           string
		memoryBaseline workerdCgroupMemoryEvents
		memoryCurrent  workerdCgroupMemoryEvents
		cpuBaseline    workerdCgroupCPUStat
		cpuCurrent     workerdCgroupCPUStat
	}{
		{
			name:           "memory events",
			memoryBaseline: workerdCgroupMemoryEvents{Low: 1, High: 1, Max: 1, OOM: 9, OOMKill: 1},
			memoryCurrent:  workerdCgroupMemoryEvents{Low: 1, High: 1, Max: 1, OOM: 8, OOMKill: 1},
			cpuBaseline:    workerdCgroupCPUStat{UsageMicros: 10, UserMicros: 4, SystemMicros: 6, Periods: 8, ThrottledPeriods: 3, ThrottledMicros: 2},
			cpuCurrent:     workerdCgroupCPUStat{UsageMicros: 10, UserMicros: 4, SystemMicros: 6, Periods: 8, ThrottledPeriods: 3, ThrottledMicros: 2},
		},
		{
			name:           "cpu stat",
			memoryBaseline: workerdCgroupMemoryEvents{Low: 1, High: 1, Max: 1, OOM: 1, OOMKill: 1},
			memoryCurrent:  workerdCgroupMemoryEvents{Low: 1, High: 1, Max: 1, OOM: 1, OOMKill: 1},
			cpuBaseline:    workerdCgroupCPUStat{UsageMicros: 10, UserMicros: 4, SystemMicros: 6, Periods: 8, ThrottledPeriods: 3, ThrottledMicros: 2},
			cpuCurrent:     workerdCgroupCPUStat{UsageMicros: 9, UserMicros: 4, SystemMicros: 6, Periods: 8, ThrottledPeriods: 3, ThrottledMicros: 2},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backend := newFakeWorkerdCgroupBackend()
			backend.initialMemoryEvents = formatFakeWorkerdCgroupMemoryEvents(test.memoryBaseline)
			backend.initialCPUStat = formatFakeWorkerdCgroupCPUStat(test.cpuBaseline)
			controller, err := newWorkerdCgroupControllerWithBackend(validWorkerdCgroupConfig(), backend)
			if err != nil {
				t.Fatalf("new controller error = %v", err)
			}
			lease, err := controller.prepare(context.Background(), workerdTestAgentInstanceID(0), "counter-decrease", 1)
			if err != nil {
				t.Fatalf("prepare() error = %v", err)
			}
			backend.setOnlyChildControl(t, "memory.events", formatFakeWorkerdCgroupMemoryEvents(test.memoryCurrent))
			backend.setOnlyChildControl(t, "cpu.stat", formatFakeWorkerdCgroupCPUStat(test.cpuCurrent))
			if sample, sampleErr := lease.sampleResources(context.Background()); sample != (workerdCgroupResourceSample{}) || !errors.Is(sampleErr, errWorkerdCgroupContract) {
				t.Fatalf("sampleResources(counter decrease) = %+v, %v, want zero, contract error", sample, sampleErr)
			}
			if err := lease.destroy(context.Background()); err != nil {
				t.Fatalf("destroy() error = %v", err)
			}
			if err := controller.close(); err != nil {
				t.Fatalf("close() error = %v", err)
			}
		})
	}
}

func TestWorkerdCgroupResourceSampleRejectsOversizedControl(t *testing.T) {
	_, backend, controller := newWorkerdCgroupFixture(t)
	lease, err := controller.prepare(context.Background(), workerdTestAgentInstanceID(0), "oversized-resource", 1)
	if err != nil {
		t.Fatalf("prepare() error = %v", err)
	}
	backend.setOnlyChildControl(t, "memory.current", strings.Repeat("1", maximumWorkerdCgroupScalarBytes+1))
	if sample, sampleErr := lease.sampleResources(context.Background()); sample != (workerdCgroupResourceSample{}) || !errors.Is(sampleErr, errWorkerdCgroupContract) {
		t.Fatalf("sampleResources(oversized) = %+v, %v, want zero, contract error", sample, sampleErr)
	}
	if err := lease.destroy(context.Background()); err != nil {
		t.Fatalf("destroy() error = %v", err)
	}
	if err := controller.close(); err != nil {
		t.Fatalf("close() error = %v", err)
	}
}

func TestWorkerdCgroupResourceSampleRejectsPathReplacementDuringRead(t *testing.T) {
	_, backend, controller := newWorkerdCgroupFixture(t)
	lease, err := controller.prepare(context.Background(), workerdTestAgentInstanceID(0), "resource-replacement", 1)
	if err != nil {
		t.Fatalf("prepare() error = %v", err)
	}
	backend.replaceOnReadback = "memory.current"
	if sample, sampleErr := lease.sampleResources(context.Background()); sample != (workerdCgroupResourceSample{}) || !errors.Is(sampleErr, errWorkerdCgroupPathReplaced) || !errors.Is(sampleErr, errWorkerdCgroupPoisoned) {
		t.Fatalf("sampleResources(replacement) = %+v, %v, want zero, path replaced and poisoned", sample, sampleErr)
	}
	if next, prepareErr := controller.prepare(context.Background(), workerdTestAgentInstanceID(0), "must-not-observe-after-replacement", 1); next != nil || !errors.Is(prepareErr, errWorkerdCgroupPoisoned) {
		if next != nil {
			_ = next.destroy(context.Background())
		}
		t.Fatalf("prepare(after sample replacement) = %#v, %v, want poisoned", next, prepareErr)
	}
	if err := lease.destroy(context.Background()); !errors.Is(err, errWorkerdCgroupPathReplaced) || !errors.Is(err, errWorkerdCgroupPoisoned) {
		t.Fatalf("destroy(replaced lease) error = %v, want path replaced and poisoned", err)
	}
	if err := controller.close(); !errors.Is(err, errWorkerdCgroupPoisoned) {
		t.Fatalf("close(poisoned) error = %v, want poisoned", err)
	}
}

func TestWorkerdCgroupResourceSampleReleasesLocksAndExcludesDestroy(t *testing.T) {
	_, backend, controller := newWorkerdCgroupFixture(t)
	lease, err := controller.prepare(context.Background(), workerdTestAgentInstanceID(0), "sample-destroy-race", 1)
	if err != nil {
		t.Fatalf("prepare() error = %v", err)
	}
	readEntered := make(chan struct{}, 1)
	readGate := make(chan struct{})
	backend.readEnteredByControl["memory.current"] = readEntered
	backend.readGatesByControl["memory.current"] = readGate
	sampleResult := make(chan error, 1)
	go func() {
		_, sampleErr := lease.sampleResources(context.Background())
		sampleResult <- sampleErr
	}()
	select {
	case <-readEntered:
	case <-time.After(time.Second):
		t.Fatal("sample did not enter memory.current read")
	}
	closeResult := make(chan error, 1)
	go func() { closeResult <- controller.close() }()
	destroyResult := make(chan error, 1)
	go func() { destroyResult <- lease.destroy(context.Background()) }()
	destroyRegistered := make(chan struct{})
	go func() {
		for {
			lease.mu.Lock()
			registered := lease.destroyOperation != nil
			lease.mu.Unlock()
			if registered {
				close(destroyRegistered)
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	closeBlocked := false
	select {
	case err := <-closeResult:
		if !errors.Is(err, errWorkerdCgroupBusy) {
			t.Errorf("close() during sample error = %v, want busy", err)
		}
	case <-time.After(250 * time.Millisecond):
		closeBlocked = true
	}
	destroyRegistrationBlocked := false
	select {
	case <-destroyRegistered:
	case <-time.After(250 * time.Millisecond):
		destroyRegistrationBlocked = true
	}
	select {
	case err := <-destroyResult:
		t.Fatalf("destroy completed while sample held pinned lease: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(readGate)
	if err := <-sampleResult; err != nil {
		t.Fatalf("sampleResources() error = %v", err)
	}
	if err := <-destroyResult; err != nil {
		t.Fatalf("destroy() error = %v", err)
	}
	if closeBlocked {
		if err := <-closeResult; !errors.Is(err, errWorkerdCgroupBusy) {
			t.Errorf("delayed close() error = %v, want busy", err)
		}
		t.Error("controller close blocked behind resource sample I/O")
	}
	if destroyRegistrationBlocked {
		<-destroyRegistered
		t.Error("destroy epoch registration blocked behind resource sample I/O")
	}
	if sample, sampleErr := lease.sampleResources(context.Background()); sample != (workerdCgroupResourceSample{}) || !errors.Is(sampleErr, errWorkerdCgroupLeaseUnavailable) {
		t.Fatalf("sampleResources(after destroy) = %+v, %v, want zero, unavailable", sample, sampleErr)
	}
	if err := controller.close(); err != nil {
		t.Fatalf("close() error = %v", err)
	}
}

func TestWorkerdCgroupDirectoryFDBorrowExcludesDestroyAndCannotBeReused(t *testing.T) {
	_, backend, controller := newWorkerdCgroupFixture(t)
	lease, err := controller.prepare(context.Background(), workerdTestAgentInstanceID(0), "borrowed-directory-fd", 1)
	if err != nil {
		t.Fatalf("prepare() error = %v", err)
	}
	backend.killEntered = make(chan struct{}, 1)
	borrowEntered := make(chan struct{})
	releaseBorrow := make(chan struct{})
	borrowResult := make(chan error, 1)
	go func() {
		borrowResult <- lease.withDirectoryFD(func(fd int) error {
			if fd < 0 {
				return fmt.Errorf("borrowed fd = %d", fd)
			}
			close(borrowEntered)
			<-releaseBorrow
			return nil
		})
	}()
	<-borrowEntered
	destroyResult := make(chan error, 1)
	go func() {
		destroyResult <- lease.destroy(context.Background())
	}()
	select {
	case <-backend.killEntered:
		t.Fatal("cgroup destroy began while directory fd was borrowed")
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseBorrow)
	if err := <-borrowResult; err != nil {
		t.Fatalf("withDirectoryFD() error = %v", err)
	}
	if err := <-destroyResult; err != nil {
		t.Fatalf("destroy() error = %v", err)
	}
	if err := lease.withDirectoryFD(func(int) error { return nil }); !errors.Is(err, errWorkerdCgroupLeaseUnavailable) {
		t.Fatalf("withDirectoryFD(after destroy) error = %v, want unavailable", err)
	}
	if err := controller.close(); err != nil {
		t.Fatalf("close() error = %v", err)
	}
}

func TestWorkerdCgroupPrepareRejectsNonLeafCgroupState(t *testing.T) {
	tests := map[string]struct {
		control string
		value   string
	}{
		"non-domain type":       {control: "cgroup.type", value: "threaded\n"},
		"resident process":      {control: "cgroup.procs", value: "42\n"},
		"enabled subtree":       {control: "cgroup.subtree_control", value: "cpu\n"},
		"existing descendant":   {control: "cgroup.stat", value: "nr_descendants 1\nnr_dying_descendants 0\n"},
		"dying descendant":      {control: "cgroup.stat", value: "nr_descendants 0\nnr_dying_descendants 1\n"},
		"malformed descendant":  {control: "cgroup.stat", value: "nr_descendants zero\nnr_dying_descendants 0\n"},
		"duplicate descendants": {control: "cgroup.stat", value: "nr_descendants 0\nnr_descendants 0\nnr_dying_descendants 0\n"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, backend, controller := newWorkerdCgroupFixture(t)
			backend.corruptReadback[test.control] = test.value
			lease, err := controller.prepare(context.Background(), workerdTestAgentInstanceID(0), "invalid-leaf", 1)
			if lease != nil {
				if destroyErr := lease.destroy(context.Background()); destroyErr != nil {
					t.Fatalf("destroy(unexpected lease) error = %v", destroyErr)
				}
			}
			if !errors.Is(err, errWorkerdCgroupContract) {
				t.Fatalf("prepare(%s) error = %v, want contract error", test.control, err)
			}
			if children := backend.childCount(); children != 0 {
				t.Fatalf("children after rejected leaf = %d, want 0", children)
			}
			if err := controller.close(); err != nil {
				t.Fatalf("close() error = %v", err)
			}
		})
	}
}

func TestWorkerdCgroupPrepareRollsBackPartialLimitFailure(t *testing.T) {
	_, backend, controller := newWorkerdCgroupFixture(t)
	backend.corruptReadback["cpu.max"] = "99999 100000\n"
	lease, err := controller.prepare(context.Background(), workerdTestAgentInstanceID(0), "rollback-shard", 1)
	if lease != nil || !errors.Is(err, errWorkerdCgroupContract) {
		t.Fatalf("prepare(corrupt readback) = %#v, %v, want nil, contract error", lease, err)
	}
	if children := backend.childCount(); children != 0 {
		t.Fatalf("children after rollback = %d, want 0", children)
	}
	delete(backend.corruptReadback, "cpu.max")
	lease, err = controller.prepare(context.Background(), workerdTestAgentInstanceID(0), "after-rollback", 1)
	if err != nil {
		t.Fatalf("prepare(after rollback) error = %v", err)
	}
	if err := lease.destroy(context.Background()); err != nil {
		t.Fatalf("destroy() error = %v", err)
	}
	if err := controller.close(); err != nil {
		t.Fatalf("close() error = %v", err)
	}
}

func TestWorkerdCgroupPrepareReturnsCleanupLeaseWhenRollbackUnlinkFails(t *testing.T) {
	config := validWorkerdCgroupConfig()
	config.MaximumShards = 1
	backend := newFakeWorkerdCgroupBackend()
	backend.corruptReadback["cpu.max"] = "99999 100000\n"
	backend.removeFailures = 1
	controller, err := newWorkerdCgroupControllerWithBackend(config, backend)
	if err != nil {
		t.Fatalf("new controller error = %v", err)
	}
	lease, err := controller.prepare(context.Background(), workerdTestAgentInstanceID(0), "retryable-rollback", 1)
	if lease == nil || !errors.Is(err, errWorkerdCgroupContract) {
		t.Fatalf("prepare(rollback unlink failure) = %#v, %v, want cleanup lease and contract error", lease, err)
	}
	if descriptors := backend.openFileDescriptors(); descriptors != 2 {
		t.Fatalf("open descriptors while cleanup authority retained = %d, want root and lease", descriptors)
	}
	if children := backend.childCount(); children != 1 {
		t.Fatalf("children while cleanup authority retained = %d, want 1", children)
	}
	if err := lease.withDirectoryFD(func(int) error { return nil }); !errors.Is(err, errWorkerdCgroupLeaseUnavailable) {
		t.Fatalf("withDirectoryFD(cleanup-only lease) error = %v, want unavailable", err)
	}
	backend.writeFailures["cgroup.kill"] = 1
	delete(backend.corruptReadback, "cpu.max")
	if err := lease.destroy(context.Background()); err != nil {
		t.Fatalf("destroy(cleanup lease) error = %v", err)
	}
	if calls := backend.killCallCount(); calls != 0 {
		t.Fatalf("cgroup.kill calls for never-attached cleanup lease = %d, want 0", calls)
	}
	delete(backend.writeFailures, "cgroup.kill")
	replacement, err := controller.prepare(context.Background(), workerdTestAgentInstanceID(0), "after-retryable-rollback", 1)
	if err != nil {
		t.Fatalf("prepare(after cleanup retry) error = %v", err)
	}
	if err := replacement.destroy(context.Background()); err != nil {
		t.Fatalf("destroy(replacement) error = %v", err)
	}
	if err := controller.close(); err != nil {
		t.Fatalf("close() error = %v", err)
	}
}

func TestWorkerdCgroupPreparePoisonsControllerWhenCreatedChildCannotBeOpened(t *testing.T) {
	_, backend, controller := newWorkerdCgroupFixture(t)
	backend.openFailures = 1
	lease, err := controller.prepare(context.Background(), workerdTestAgentInstanceID(0), "unidentified-child", 1)
	if lease != nil || !errors.Is(err, errWorkerdCgroupPoisoned) {
		t.Fatalf("prepare(open failure) = %#v, %v, want nil and poisoned error", lease, err)
	}
	if next, prepareErr := controller.prepare(context.Background(), workerdTestAgentInstanceID(0), "must-not-admit", 1); next != nil || !errors.Is(prepareErr, errWorkerdCgroupPoisoned) {
		t.Fatalf("prepare(after poison) = %#v, %v, want poisoned error", next, prepareErr)
	}
	if calls := backend.mkdirCallCount(); calls != 1 {
		t.Fatalf("mkdir calls after poison = %d, want 1", calls)
	}
	if err := controller.close(); !errors.Is(err, errWorkerdCgroupPoisoned) {
		t.Fatalf("close(poisoned) error = %v, want poisoned error", err)
	}
	if descriptors := backend.openFileDescriptors(); descriptors != 0 {
		t.Fatalf("open descriptors after poisoned close = %d, want 0", descriptors)
	}
}

func TestWorkerdCgroupPoisonRevokesBorrowFromExistingLease(t *testing.T) {
	config := validWorkerdCgroupConfig()
	config.MaximumShards = 2
	backend := newFakeWorkerdCgroupBackend()
	controller, err := newWorkerdCgroupControllerWithBackend(config, backend)
	if err != nil {
		t.Fatalf("new controller error = %v", err)
	}
	existing, err := controller.prepare(context.Background(), workerdTestAgentInstanceID(0), "existing-before-poison", 1)
	if err != nil {
		t.Fatalf("prepare(existing) error = %v", err)
	}
	backend.openFailures = 1
	if unidentified, prepareErr := controller.prepare(context.Background(), workerdTestAgentInstanceID(0), "poisoning-child", 1); unidentified != nil || !errors.Is(prepareErr, errWorkerdCgroupPoisoned) {
		t.Fatalf("prepare(poisoning child) = %#v, %v, want poisoned error", unidentified, prepareErr)
	}
	if err := existing.withDirectoryFD(func(int) error { return nil }); !errors.Is(err, errWorkerdCgroupLeaseUnavailable) {
		t.Fatalf("withDirectoryFD(after controller poison) error = %v, want unavailable", err)
	}
	if err := existing.destroy(context.Background()); err != nil {
		t.Fatalf("destroy(existing) error = %v", err)
	}
	if err := controller.close(); !errors.Is(err, errWorkerdCgroupPoisoned) {
		t.Fatalf("close(poisoned) error = %v, want poisoned error", err)
	}
	if descriptors := backend.openFileDescriptors(); descriptors != 0 {
		t.Fatalf("open descriptors after poisoned close = %d, want 0", descriptors)
	}
}

func TestWorkerdCgroupPrepareRollbackNeverRemovesAReplacement(t *testing.T) {
	_, backend, controller := newWorkerdCgroupFixture(t)
	backend.corruptReadback["cpu.max"] = "99999 100000\n"
	backend.replaceOnReadback = "cpu.max"
	lease, err := controller.prepare(context.Background(), workerdTestAgentInstanceID(0), "rollback-replacement", 1)
	if lease != nil || !errors.Is(err, errWorkerdCgroupPathReplaced) || !errors.Is(err, errWorkerdCgroupPoisoned) {
		t.Fatalf("prepare(replaced during rollback) = %#v, %v, want nil, path replaced and poisoned", lease, err)
	}
	if calls := backend.removeCallCount(); calls != 0 {
		t.Fatalf("remove calls for rollback replacement = %d, want 0", calls)
	}
	if next, prepareErr := controller.prepare(context.Background(), workerdTestAgentInstanceID(0), "must-not-admit", 1); next != nil || !errors.Is(prepareErr, errWorkerdCgroupPoisoned) {
		t.Fatalf("prepare(after replacement poison) = %#v, %v, want poisoned error", next, prepareErr)
	}
	if err := controller.close(); !errors.Is(err, errWorkerdCgroupPoisoned) {
		t.Fatalf("close(poisoned) error = %v, want poisoned error", err)
	}
	if descriptors := backend.openFileDescriptors(); descriptors != 0 {
		t.Fatalf("open descriptors after poisoned close = %d, want 0", descriptors)
	}
}

func TestWorkerdCgroupPrepareReservesCapacityBeforeMkdir(t *testing.T) {
	config := validWorkerdCgroupConfig()
	config.MaximumShards = 1
	backend := newFakeWorkerdCgroupBackend()
	backend.mkdirEntered = make(chan struct{}, 1)
	mkdirGate := make(chan struct{})
	backend.mkdirGate = mkdirGate
	controller, err := newWorkerdCgroupControllerWithBackend(config, backend)
	if err != nil {
		t.Fatalf("new controller error = %v", err)
	}
	result := make(chan workerdCgroupPrepareResult, 1)
	go func() {
		lease, prepareErr := controller.prepare(context.Background(), workerdTestAgentInstanceID(0), "first", 1)
		result <- workerdCgroupPrepareResult{lease: lease, err: prepareErr}
	}()
	<-backend.mkdirEntered
	if lease, prepareErr := controller.prepare(context.Background(), workerdTestAgentInstanceID(0), "second", 1); lease != nil || !errors.Is(prepareErr, errWorkerdCgroupCapacity) {
		t.Fatalf("prepare(over cap) = %#v, %v, want nil, capacity", lease, prepareErr)
	}
	close(mkdirGate)
	first := <-result
	if first.err != nil {
		t.Fatalf("first prepare error = %v", first.err)
	}
	if calls := backend.mkdirCallCount(); calls != 1 {
		t.Fatalf("mkdir calls = %d, want 1", calls)
	}
	if err := first.lease.destroy(context.Background()); err != nil {
		t.Fatalf("destroy() error = %v", err)
	}
	if err := controller.close(); err != nil {
		t.Fatalf("close() error = %v", err)
	}
}

func TestWorkerdCgroupPrepareRunsDistinctShardsConcurrently(t *testing.T) {
	config := validWorkerdCgroupConfig()
	const shards = 32
	config.MaximumShards = shards
	backend := newFakeWorkerdCgroupBackend()
	controller, err := newWorkerdCgroupControllerWithBackend(config, backend)
	if err != nil {
		t.Fatalf("new controller error = %v", err)
	}
	results := make(chan workerdCgroupPrepareResult, shards)
	var wait sync.WaitGroup
	for index := range shards {
		wait.Add(1)
		go func() {
			defer wait.Done()
			lease, prepareErr := controller.prepare(context.Background(), workerdTestAgentInstanceID(0), fmt.Sprintf("concurrent-%d", index), 1)
			results <- workerdCgroupPrepareResult{lease: lease, err: prepareErr}
		}()
	}
	wait.Wait()
	close(results)
	leases := make([]*workerdCgroupLease, 0, shards)
	for result := range results {
		if result.err != nil {
			t.Fatalf("concurrent prepare error = %v", result.err)
		}
		leases = append(leases, result.lease)
	}
	for _, lease := range leases {
		if err := lease.destroy(context.Background()); err != nil {
			t.Fatalf("destroy() error = %v", err)
		}
	}
	if err := controller.close(); err != nil {
		t.Fatalf("close() error = %v", err)
	}
}

func TestWorkerdCgroupDestroyCoalescesConcurrentCallers(t *testing.T) {
	_, backend, controller := newWorkerdCgroupFixture(t)
	lease, err := controller.prepare(context.Background(), workerdTestAgentInstanceID(0), "coalesced-destroy", 1)
	if err != nil {
		t.Fatalf("prepare() error = %v", err)
	}
	backend.killEntered = make(chan struct{}, 1)
	killGate := make(chan struct{})
	backend.killGate = killGate
	const callers = 32
	errorsSeen := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errorsSeen <- lease.destroy(context.Background())
		}()
	}
	<-backend.killEntered
	if calls := backend.killCallCount(); calls != 1 {
		t.Fatalf("cgroup.kill calls while coalesced = %d, want 1", calls)
	}
	close(killGate)
	wait.Wait()
	close(errorsSeen)
	for destroyErr := range errorsSeen {
		if destroyErr != nil {
			t.Fatalf("destroy() error = %v", destroyErr)
		}
	}
	if err := lease.destroy(context.Background()); err != nil {
		t.Fatalf("idempotent destroy() error = %v", err)
	}
	if calls := backend.killCallCount(); calls != 1 {
		t.Fatalf("cgroup.kill calls after idempotent destroy = %d, want 1", calls)
	}
	if err := controller.close(); err != nil {
		t.Fatalf("close() error = %v", err)
	}
}

func TestWorkerdCgroupDestroyCallerCancellationDoesNotCancelSharedCleanup(t *testing.T) {
	_, backend, controller := newWorkerdCgroupFixture(t)
	lease, err := controller.prepare(context.Background(), workerdTestAgentInstanceID(0), "cancelled-destroy-waiter", 1)
	if err != nil {
		t.Fatalf("prepare() error = %v", err)
	}
	backend.killEntered = make(chan struct{}, 1)
	killGate := make(chan struct{})
	backend.killGate = killGate

	firstContext, cancelFirst := context.WithCancel(context.Background())
	firstResult := make(chan error, 1)
	go func() {
		firstResult <- lease.destroy(firstContext)
	}()
	<-backend.killEntered

	secondResult := make(chan error, 1)
	go func() {
		secondResult <- lease.destroy(context.Background())
	}()
	cancelFirst()
	var firstErr error
	select {
	case firstErr = <-firstResult:
	case <-time.After(100 * time.Millisecond):
		close(killGate)
		<-firstResult
		<-secondResult
		t.Fatal("destroy(cancelled waiter) did not return before shared cleanup completed")
	}
	if !errors.Is(firstErr, context.Canceled) {
		t.Fatalf("destroy(cancelled waiter) error = %v, want context canceled", firstErr)
	}
	close(killGate)
	if err := <-secondResult; err != nil {
		t.Fatalf("destroy(remaining waiter) error = %v", err)
	}
	if calls := backend.killCallCount(); calls != 1 {
		t.Fatalf("cgroup.kill calls = %d, want 1", calls)
	}
	if err := controller.close(); err != nil {
		t.Fatalf("close() error = %v", err)
	}
}

func TestWorkerdCgroupDestroyIsIdempotentAfterCallerCancellation(t *testing.T) {
	_, _, controller := newWorkerdCgroupFixture(t)
	lease, err := controller.prepare(context.Background(), workerdTestAgentInstanceID(0), "idempotent-cancelled-destroy", 1)
	if err != nil {
		t.Fatalf("prepare() error = %v", err)
	}
	if err := lease.destroy(context.Background()); err != nil {
		t.Fatalf("destroy() error = %v", err)
	}
	cancelledContext, cancel := context.WithCancel(context.Background())
	cancel()
	if err := lease.destroy(cancelledContext); err != nil {
		t.Fatalf("destroy(already destroyed, cancelled context) error = %v", err)
	}
	if err := controller.close(); err != nil {
		t.Fatalf("close() error = %v", err)
	}
}

func TestWorkerdCgroupDestroyRetriesAndRetainsCapacityUntilUnlink(t *testing.T) {
	config := validWorkerdCgroupConfig()
	config.MaximumShards = 1
	backend := newFakeWorkerdCgroupBackend()
	controller, err := newWorkerdCgroupControllerWithBackend(config, backend)
	if err != nil {
		t.Fatalf("new controller error = %v", err)
	}
	lease, err := controller.prepare(context.Background(), workerdTestAgentInstanceID(0), "retry-destroy", 1)
	if err != nil {
		t.Fatalf("prepare() error = %v", err)
	}
	backend.removeFailures = 1
	if err := lease.destroy(context.Background()); err == nil {
		t.Fatal("destroy(first) error = nil, want retryable failure")
	}
	if extra, prepareErr := controller.prepare(context.Background(), workerdTestAgentInstanceID(0), "must-remain-reserved", 1); extra != nil || !errors.Is(prepareErr, errWorkerdCgroupCapacity) {
		t.Fatalf("prepare(before successful unlink) = %#v, %v, want capacity", extra, prepareErr)
	}
	if err := lease.destroy(context.Background()); err != nil {
		t.Fatalf("destroy(retry) error = %v", err)
	}
	replacement, err := controller.prepare(context.Background(), workerdTestAgentInstanceID(0), "after-unlink", 1)
	if err != nil {
		t.Fatalf("prepare(after unlink) error = %v", err)
	}
	if err := replacement.destroy(context.Background()); err != nil {
		t.Fatalf("replacement destroy error = %v", err)
	}
	if err := controller.close(); err != nil {
		t.Fatalf("close() error = %v", err)
	}
}

func TestWorkerdCgroupDestroyNeverUnlinksAReplacement(t *testing.T) {
	_, backend, controller := newWorkerdCgroupFixture(t)
	lease, err := controller.prepare(context.Background(), workerdTestAgentInstanceID(0), "replacement-attack", 4)
	if err != nil {
		t.Fatalf("prepare() error = %v", err)
	}
	name := backend.onlyChildName(t)
	backend.replaceChild(name)
	if err := lease.destroy(context.Background()); !errors.Is(err, errWorkerdCgroupPathReplaced) || !errors.Is(err, errWorkerdCgroupPoisoned) {
		t.Fatalf("destroy(replaced path) error = %v, want path replaced and poisoned", err)
	}
	if calls := backend.removeCallCount(); calls != 0 {
		t.Fatalf("remove calls for replacement = %d, want 0", calls)
	}
	if err := lease.destroy(context.Background()); !errors.Is(err, errWorkerdCgroupPoisoned) {
		t.Fatalf("destroy(after terminal poison) error = %v, want poisoned error", err)
	}
	if next, prepareErr := controller.prepare(context.Background(), workerdTestAgentInstanceID(0), "must-not-admit", 1); next != nil || !errors.Is(prepareErr, errWorkerdCgroupPoisoned) {
		t.Fatalf("prepare(after destroy poison) = %#v, %v, want poisoned error", next, prepareErr)
	}
	if err := controller.close(); !errors.Is(err, errWorkerdCgroupPoisoned) {
		t.Fatalf("close(poisoned) error = %v, want poisoned error", err)
	}
	if descriptors := backend.openFileDescriptors(); descriptors != 0 {
		t.Fatalf("open descriptors after poisoned close = %d, want 0", descriptors)
	}
}

func TestWorkerdCgroupDestroyPollsUntilUnpopulated(t *testing.T) {
	_, backend, controller := newWorkerdCgroupFixture(t)
	lease, err := controller.prepare(context.Background(), workerdTestAgentInstanceID(0), "draining", 1)
	if err != nil {
		t.Fatalf("prepare() error = %v", err)
	}
	if err := lease.withDirectoryFD(func(fd int) error {
		backend.setEvents(fd, []string{
			"populated 1\nfrozen 0\n",
			"populated 1\nfrozen 0\n",
			"populated 0\nfrozen 0\n",
		})
		return nil
	}); err != nil {
		t.Fatalf("withDirectoryFD() error = %v", err)
	}
	if err := lease.destroy(context.Background()); err != nil {
		t.Fatalf("destroy() error = %v", err)
	}
	if waits := backend.waitCallCount(); waits != 2 {
		t.Fatalf("drain waits = %d, want 2", waits)
	}
	if err := controller.close(); err != nil {
		t.Fatalf("close() error = %v", err)
	}
}

func TestWorkerdCgroupDestroyDrainTimeoutIsRetryable(t *testing.T) {
	config := validWorkerdCgroupConfig()
	config.DrainTimeout = 5 * time.Millisecond
	backend := newFakeWorkerdCgroupBackend()
	controller, err := newWorkerdCgroupControllerWithBackend(config, backend)
	if err != nil {
		t.Fatalf("new controller error = %v", err)
	}
	lease, err := controller.prepare(context.Background(), workerdTestAgentInstanceID(0), "drain-timeout", 1)
	if err != nil {
		t.Fatalf("prepare() error = %v", err)
	}
	if err := lease.withDirectoryFD(func(fd int) error {
		backend.setEvents(fd, []string{"populated 1\nfrozen 0\n"})
		return nil
	}); err != nil {
		t.Fatalf("withDirectoryFD(populated) error = %v", err)
	}
	if err := lease.destroy(context.Background()); !errors.Is(err, errWorkerdCgroupDrainTimeout) {
		t.Fatalf("destroy(timeout) error = %v, want drain timeout", err)
	}
	if err := lease.withDirectoryFD(func(int) error { return nil }); !errors.Is(err, errWorkerdCgroupLeaseUnavailable) {
		t.Fatalf("withDirectoryFD(after kill attempt) error = %v, want unavailable", err)
	}
	backend.mu.Lock()
	for _, group := range backend.children {
		group.events = []string{"populated 0\nfrozen 0\n"}
	}
	backend.mu.Unlock()
	if err := lease.destroy(context.Background()); err != nil {
		t.Fatalf("destroy(retry) error = %v", err)
	}
	if err := controller.close(); err != nil {
		t.Fatalf("close() error = %v", err)
	}
}

func TestWorkerdCgroupControllerAndLeasesDoNotLeakFileDescriptors(t *testing.T) {
	config := validWorkerdCgroupConfig()
	config.MaximumShards = 1
	backend := newFakeWorkerdCgroupBackend()
	controller, err := newWorkerdCgroupControllerWithBackend(config, backend)
	if err != nil {
		t.Fatalf("new controller error = %v", err)
	}
	for generation := ShardGeneration(1); generation <= 100; generation++ {
		lease, prepareErr := controller.prepare(context.Background(), workerdTestAgentInstanceID(0), "fd-cycle", generation)
		if prepareErr != nil {
			t.Fatalf("prepare(%d) error = %v", generation, prepareErr)
		}
		if destroyErr := lease.destroy(context.Background()); destroyErr != nil {
			t.Fatalf("destroy(%d) error = %v", generation, destroyErr)
		}
	}
	if descriptors := backend.openFileDescriptors(); descriptors != 1 {
		t.Fatalf("open descriptors before controller close = %d, want root only", descriptors)
	}
	if err := controller.close(); err != nil {
		t.Fatalf("close() error = %v", err)
	}
	if descriptors := backend.openFileDescriptors(); descriptors != 0 {
		t.Fatalf("open descriptors after controller close = %d, want 0", descriptors)
	}
}

func TestWorkerdCgroupControllerCloseWaitsForTerminalLeaseFDClosure(t *testing.T) {
	backend := newFakeWorkerdCgroupBackend()
	controller, err := newWorkerdCgroupControllerWithBackend(validWorkerdCgroupConfig(), backend)
	if err != nil {
		t.Fatalf("newWorkerdCgroupControllerWithBackend() error = %v", err)
	}
	lease, err := controller.prepare(context.Background(), workerdTestAgentInstanceID(0), "close-waits-for-leaf-fd", 1)
	if err != nil {
		t.Fatalf("prepare() error = %v", err)
	}
	closeRelease := make(chan struct{})
	backend.closeEntered = make(chan int, 2)
	backend.closeGates[lease.fd] = closeRelease
	destroyResult := make(chan error, 1)
	go func() { destroyResult <- lease.destroy(context.Background()) }()
	if fd := <-backend.closeEntered; fd != lease.fd {
		t.Fatalf("first close fd = %d, want lease fd %d", fd, lease.fd)
	}
	controllerCloseResult := make(chan error, 1)
	go func() { controllerCloseResult <- controller.close() }()
	select {
	case closeErr := <-controllerCloseResult:
		t.Fatalf("controller.close() returned before leaf fd closure: %v", closeErr)
	case <-time.After(20 * time.Millisecond):
	}
	close(closeRelease)
	if err := <-destroyResult; err != nil {
		t.Fatalf("destroy() error = %v", err)
	}
	if err := <-controllerCloseResult; err != nil {
		t.Fatalf("controller.close() error = %v", err)
	}
}

func TestWorkerdCgroupLeaseLeafCloseFailureIsTerminalAndReplayable(t *testing.T) {
	backend := newFakeWorkerdCgroupBackend()
	controller, err := newWorkerdCgroupControllerWithBackend(validWorkerdCgroupConfig(), backend)
	if err != nil {
		t.Fatalf("newWorkerdCgroupControllerWithBackend() error = %v", err)
	}
	lease, err := controller.prepare(context.Background(), workerdTestAgentInstanceID(0), "terminal-leaf-close", 1)
	if err != nil {
		t.Fatalf("prepare() error = %v", err)
	}
	leaseFD := lease.fd
	backend.closeFailures[leaseFD] = 1
	firstErr := lease.destroy(context.Background())
	if !errors.Is(firstErr, errWorkerdCgroupContract) {
		t.Fatalf("destroy(close failure) error = %v, want cgroup contract error", firstErr)
	}
	if !lease.destroyedState() {
		t.Fatal("destroyedState() = false after terminal leaf close failure")
	}
	if replayErr := lease.destroy(context.Background()); !errors.Is(replayErr, errWorkerdCgroupContract) {
		t.Fatalf("destroy(replay) error = %v, want cached cgroup contract error", replayErr)
	}
	if calls := backend.closeCalls[leaseFD]; calls != 1 {
		t.Fatalf("leaf close calls = %d, want 1", calls)
	}
	if descriptors := backend.openFileDescriptors(); descriptors != 1 {
		t.Fatalf("descriptors after terminal leaf close = %d, want root only", descriptors)
	}
	if err := controller.close(); err != nil {
		t.Fatalf("controller.close() error = %v", err)
	}
}

func TestWorkerdCgroupControllerPoisonWriterWaitsForActiveBorrow(t *testing.T) {
	backend := newFakeWorkerdCgroupBackend()
	controller, err := newWorkerdCgroupControllerWithBackend(validWorkerdCgroupConfig(), backend)
	if err != nil {
		t.Fatalf("newWorkerdCgroupControllerWithBackend() error = %v", err)
	}
	borrowedLease, err := controller.prepare(context.Background(), workerdTestAgentInstanceID(0), "active-borrow", 1)
	if err != nil {
		t.Fatalf("prepare(active borrow) error = %v", err)
	}
	poisonedLease, err := controller.prepare(context.Background(), workerdTestAgentInstanceID(0), "poison-writer", 1)
	if err != nil {
		t.Fatalf("prepare(poison writer) error = %v", err)
	}
	queuedLease, err := controller.prepare(context.Background(), workerdTestAgentInstanceID(0), "queued-after-writer", 1)
	if err != nil {
		t.Fatalf("prepare(queued reader) error = %v", err)
	}
	borrowEntered := make(chan struct{})
	borrowRelease := make(chan struct{})
	borrowResult := make(chan error, 1)
	go func() {
		borrowResult <- borrowedLease.withDirectoryFD(func(int) error {
			close(borrowEntered)
			<-borrowRelease
			return nil
		})
	}()
	<-borrowEntered
	backend.replaceChild(poisonedLease.name)
	destroyResult := make(chan error, 1)
	go func() { destroyResult <- poisonedLease.destroy(context.Background()) }()
	writerDeadline := time.Now().Add(time.Second)
	for {
		controller.mu.Lock()
		writerQueued := controller.authorityWritersWaiting > 0
		controller.mu.Unlock()
		if writerQueued {
			break
		}
		if time.Now().After(writerDeadline) {
			t.Fatal("poison writer did not queue behind active borrow")
		}
		time.Sleep(time.Millisecond)
	}
	queuedCallbackEntered := make(chan struct{}, 1)
	queuedBorrowResult := make(chan error, 1)
	go func() {
		queuedBorrowResult <- queuedLease.withDirectoryFD(func(int) error {
			queuedCallbackEntered <- struct{}{}
			return nil
		})
	}()
	select {
	case destroyErr := <-destroyResult:
		t.Fatalf("poison writer completed during active borrow: %v", destroyErr)
	case <-time.After(20 * time.Millisecond):
	}
	select {
	case <-queuedCallbackEntered:
		t.Fatal("new borrow bypassed queued poison writer")
	case <-time.After(20 * time.Millisecond):
	}
	close(borrowRelease)
	if err := <-borrowResult; err != nil {
		t.Fatalf("active borrow error = %v", err)
	}
	if err := <-destroyResult; !errors.Is(err, errWorkerdCgroupPoisoned) {
		t.Fatalf("poisoning destroy error = %v, want poisoned", err)
	}
	if err := <-queuedBorrowResult; !errors.Is(err, errWorkerdCgroupLeaseUnavailable) {
		t.Fatalf("queued borrow error = %v, want unavailable after poison", err)
	}
	if err := borrowedLease.withDirectoryFD(func(int) error { return nil }); !errors.Is(err, errWorkerdCgroupLeaseUnavailable) {
		t.Fatalf("borrow after poison error = %v, want unavailable", err)
	}
	if err := borrowedLease.destroy(context.Background()); err != nil {
		t.Fatalf("destroy(active borrow lease) error = %v", err)
	}
	if err := queuedLease.destroy(context.Background()); err != nil {
		t.Fatalf("destroy(queued reader lease) error = %v", err)
	}
	if err := controller.close(); !errors.Is(err, errWorkerdCgroupPoisoned) {
		t.Fatalf("close() error = %v, want poisoned", err)
	}
}

func TestWorkerdCgroupAvailabilityIsNotRunWithoutMutatingHost(t *testing.T) {
	rootPath := fmt.Sprintf("/sys/fs/cgroup/circulusd-workerd-controller-not-installed-%d", os.Getpid())
	if _, err := os.Stat(rootPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("precondition stat(%q) error = %v, want absent", rootPath, err)
	}
	config := validWorkerdCgroupConfig()
	config.RootPath = rootPath
	availability := probeWorkerdCgroupAvailability(config)
	if availability.Status != "NOT_RUN" || availability.Available || !availability.Evidence.ReferenceOnly || availability.Evidence.ProductionEligible || availability.Evidence.ConformanceClaimed {
		t.Fatalf("availability = %+v, want reference-only NOT_RUN", availability)
	}
	if _, err := os.Stat(rootPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("post-probe stat(%q) error = %v, want absent", rootPath, err)
	}
}

type workerdCgroupPrepareResult struct {
	lease *workerdCgroupLease
	err   error
}

func validWorkerdCgroupConfig() workerdCgroupConfig {
	return workerdCgroupConfig{
		RootPath:       "/sys/fs/cgroup/circulusd-workerd",
		MaximumShards:  64,
		DrainTimeout:   time.Second,
		MemoryMaxBytes: 4 << 30,
		SwapMaxBytes:   0,
		CPUMax:         CPUMax{QuotaMicros: 50_000, PeriodMicros: 100_000},
		PIDsMax:        512,
	}
}

func formatFakeWorkerdCgroupMemoryEvents(events workerdCgroupMemoryEvents) string {
	return fmt.Sprintf(
		"low %d\nhigh %d\nmax %d\noom %d\noom_kill %d\noom_group_kill %d\n",
		events.Low, events.High, events.Max, events.OOM, events.OOMKill, events.OOMGroupKill,
	)
}

func formatFakeWorkerdCgroupCPUStat(stat workerdCgroupCPUStat) string {
	return fmt.Sprintf(
		"usage_usec %d\nuser_usec %d\nsystem_usec %d\nnr_periods %d\nnr_throttled %d\nthrottled_usec %d\n",
		stat.UsageMicros, stat.UserMicros, stat.SystemMicros, stat.Periods, stat.ThrottledPeriods, stat.ThrottledMicros,
	)
}

func newWorkerdCgroupFixture(t *testing.T) (workerdCgroupConfig, *fakeWorkerdCgroupBackend, *workerdCgroupController) {
	t.Helper()
	config := validWorkerdCgroupConfig()
	backend := newFakeWorkerdCgroupBackend()
	controller, err := newWorkerdCgroupControllerWithBackend(config, backend)
	if err != nil {
		t.Fatalf("newWorkerdCgroupControllerWithBackend() error = %v", err)
	}
	return config, backend, controller
}

type fakeWorkerdCgroupWrite struct {
	Name  string
	Value string
}

type fakeWorkerdCgroupRead struct {
	Name  string
	Limit int
}

type fakeWorkerdCgroup struct {
	identity workerdCgroupIdentity
	fd       int
	controls map[string]string
	events   []string
}

type fakeWorkerdCgroupBackend struct {
	mu sync.Mutex

	effectiveUID        uint32
	effectiveGID        uint32
	inspection          workerdCgroupRootInspection
	inspectErr          error
	nextFD              int
	openFDs             map[int]struct{}
	groupsByFD          map[int]*fakeWorkerdCgroup
	children            map[string]*fakeWorkerdCgroup
	writes              []fakeWorkerdCgroupWrite
	reads               []fakeWorkerdCgroupRead
	nextInode           uint64
	initialMemoryEvents string
	initialCPUStat      string

	corruptReadback      map[string]string
	replaceOnReadback    string
	writeFailures        map[string]int
	openFailures         int
	removeFailures       int
	mkdirCalls           int
	mkdirModes           []uint32
	removeCalls          int
	killCalls            int
	waitCalls            int
	mkdirEntered         chan struct{}
	mkdirGate            <-chan struct{}
	killEntered          chan struct{}
	killGate             <-chan struct{}
	killHook             func()
	killEnteredByFD      map[int]chan struct{}
	killGatesByFD        map[int]<-chan struct{}
	killHooksByFD        map[int]func()
	closeEntered         chan int
	closeGates           map[int]<-chan struct{}
	closeFailures        map[int]int
	closeCalls           map[int]int
	readEnteredByControl map[string]chan struct{}
	readGatesByControl   map[string]<-chan struct{}
}

func newFakeWorkerdCgroupBackend() *fakeWorkerdCgroupBackend {
	const uid = 1000
	const gid = 1000
	return &fakeWorkerdCgroupBackend{
		effectiveUID: uid,
		effectiveGID: gid,
		inspection: workerdCgroupRootInspection{
			DirectoryFD:    10,
			FilesystemType: unix.CGROUP2_SUPER_MAGIC,
			Components: []workerdCgroupDirectoryMetadata{
				{Device: 1, Inode: 1, UID: 0, GID: 0, Mode: unix.S_IFDIR | 0o755},
				{Device: 1, Inode: 2, UID: 0, GID: 0, Mode: unix.S_IFDIR | 0o755},
				{Device: 1, Inode: 3, UID: 0, GID: 0, Mode: unix.S_IFDIR | 0o755},
				{Device: 2, Inode: 4, UID: uid, GID: gid, Mode: unix.S_IFDIR | 0o700},
			},
			CgroupType:     "domain\n",
			Processes:      "",
			Controllers:    "cpu memory pids\n",
			SubtreeControl: "cpu memory pids\n",
		},
		nextFD:               11,
		openFDs:              map[int]struct{}{},
		groupsByFD:           map[int]*fakeWorkerdCgroup{},
		children:             map[string]*fakeWorkerdCgroup{},
		nextInode:            100,
		initialMemoryEvents:  "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n",
		initialCPUStat:       "usage_usec 0\nuser_usec 0\nsystem_usec 0\nnr_periods 0\nnr_throttled 0\nthrottled_usec 0\n",
		corruptReadback:      map[string]string{},
		writeFailures:        map[string]int{},
		killEnteredByFD:      map[int]chan struct{}{},
		killGatesByFD:        map[int]<-chan struct{}{},
		killHooksByFD:        map[int]func(){},
		closeGates:           map[int]<-chan struct{}{},
		closeFailures:        map[int]int{},
		closeCalls:           map[int]int{},
		readEnteredByControl: map[string]chan struct{}{},
		readGatesByControl:   map[string]<-chan struct{}{},
	}
}

func (backend *fakeWorkerdCgroupBackend) effectiveIDs() (uint32, uint32) {
	return backend.effectiveUID, backend.effectiveGID
}

func (backend *fakeWorkerdCgroupBackend) setOnlyChildControl(t *testing.T, name string, value string) {
	t.Helper()
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.children) != 1 {
		t.Fatalf("child count = %d, want one", len(backend.children))
	}
	for _, group := range backend.children {
		group.controls[name] = value
	}
}

func (backend *fakeWorkerdCgroupBackend) resetControlReads() {
	backend.mu.Lock()
	backend.reads = nil
	backend.mu.Unlock()
}

func (backend *fakeWorkerdCgroupBackend) controlReads() []fakeWorkerdCgroupRead {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	return append([]fakeWorkerdCgroupRead(nil), backend.reads...)
}

func (backend *fakeWorkerdCgroupBackend) inspectRoot(string) (workerdCgroupRootInspection, error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.inspectErr != nil {
		return workerdCgroupRootInspection{}, backend.inspectErr
	}
	inspection := backend.inspection
	inspection.Components = append([]workerdCgroupDirectoryMetadata(nil), backend.inspection.Components...)
	backend.openFDs[inspection.DirectoryFD] = struct{}{}
	return inspection, nil
}

func (backend *fakeWorkerdCgroupBackend) mkdirExclusive(_ int, name string, mode uint32) error {
	backend.mu.Lock()
	backend.mkdirCalls++
	backend.mkdirModes = append(backend.mkdirModes, mode)
	entered := backend.mkdirEntered
	gate := backend.mkdirGate
	backend.mu.Unlock()
	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}
	if gate != nil {
		<-gate
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if _, exists := backend.children[name]; exists {
		return unix.EEXIST
	}
	backend.nextInode++
	backend.children[name] = &fakeWorkerdCgroup{
		identity: workerdCgroupIdentity{Device: 2, Inode: backend.nextInode},
		controls: map[string]string{
			"cgroup.type":            "domain\n",
			"cgroup.procs":           "",
			"cgroup.subtree_control": "",
			"cgroup.stat":            "nr_descendants 0\nnr_dying_descendants 0\n",
			"memory.current":         "0\n",
			"memory.events":          backend.initialMemoryEvents,
			"cpu.stat":               backend.initialCPUStat,
			"pids.current":           "0\n",
		},
	}
	return nil
}

func (backend *fakeWorkerdCgroupBackend) openChild(_ int, name string) (int, workerdCgroupIdentity, error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.openFailures > 0 {
		backend.openFailures--
		return -1, workerdCgroupIdentity{}, unix.EIO
	}
	group, exists := backend.children[name]
	if !exists {
		return -1, workerdCgroupIdentity{}, unix.ENOENT
	}
	fd := backend.nextFD
	backend.nextFD++
	group.fd = fd
	backend.groupsByFD[fd] = group
	backend.openFDs[fd] = struct{}{}
	return fd, group.identity, nil
}

func (backend *fakeWorkerdCgroupBackend) writeControl(fd int, name string, value string) error {
	backend.mu.Lock()
	if remaining := backend.writeFailures[name]; remaining > 0 {
		backend.writeFailures[name] = remaining - 1
		backend.mu.Unlock()
		return unix.EIO
	}
	group := backend.groupsByFD[fd]
	if group == nil {
		backend.mu.Unlock()
		return unix.EBADF
	}
	if name == "cgroup.kill" {
		backend.killCalls++
		entered := backend.killEntered
		gate := backend.killGate
		hook := backend.killHook
		if specific := backend.killEnteredByFD[fd]; specific != nil {
			entered = specific
		}
		if specific := backend.killGatesByFD[fd]; specific != nil {
			gate = specific
		}
		if specific := backend.killHooksByFD[fd]; specific != nil {
			hook = specific
		}
		backend.mu.Unlock()
		if entered != nil {
			select {
			case entered <- struct{}{}:
			default:
			}
		}
		if gate != nil {
			<-gate
		}
		if hook != nil {
			hook()
		}
		return nil
	}
	group.controls[name] = value + "\n"
	backend.writes = append(backend.writes, fakeWorkerdCgroupWrite{Name: name, Value: value})
	backend.mu.Unlock()
	return nil
}

func (backend *fakeWorkerdCgroupBackend) readControl(fd int, name string, limit int) (string, error) {
	backend.mu.Lock()
	group := backend.groupsByFD[fd]
	if group == nil {
		backend.mu.Unlock()
		return "", unix.EBADF
	}
	backend.reads = append(backend.reads, fakeWorkerdCgroupRead{Name: name, Limit: limit})
	entered := backend.readEnteredByControl[name]
	gate := backend.readGatesByControl[name]
	backend.mu.Unlock()
	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}
	if gate != nil {
		<-gate
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.replaceOnReadback == name {
		for childName, child := range backend.children {
			if child == group {
				backend.nextInode++
				backend.children[childName] = &fakeWorkerdCgroup{
					identity: workerdCgroupIdentity{Device: 2, Inode: backend.nextInode},
					controls: map[string]string{},
				}
				break
			}
		}
		backend.replaceOnReadback = ""
	}
	if corrupted, exists := backend.corruptReadback[name]; exists {
		if len(corrupted) > limit {
			return "", errWorkerdCgroupContract
		}
		return corrupted, nil
	}
	if name == "cgroup.events" {
		if len(group.events) == 0 {
			value := "populated 0\nfrozen 0\n"
			if len(value) > limit {
				return "", errWorkerdCgroupContract
			}
			return value, nil
		}
		value := group.events[0]
		if len(group.events) > 1 {
			group.events = group.events[1:]
		}
		if len(value) > limit {
			return "", errWorkerdCgroupContract
		}
		return value, nil
	}
	value := group.controls[name]
	if len(value) > limit {
		return "", errWorkerdCgroupContract
	}
	return value, nil
}

func (backend *fakeWorkerdCgroupBackend) identityAt(_ int, name string) (workerdCgroupIdentity, bool, error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	group, exists := backend.children[name]
	if !exists {
		return workerdCgroupIdentity{}, false, nil
	}
	return group.identity, true, nil
}

func (backend *fakeWorkerdCgroupBackend) removeChild(_ int, name string) error {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.removeCalls++
	if backend.removeFailures > 0 {
		backend.removeFailures--
		return unix.EBUSY
	}
	if _, exists := backend.children[name]; !exists {
		return unix.ENOENT
	}
	delete(backend.children, name)
	return nil
}

func (backend *fakeWorkerdCgroupBackend) closeFD(fd int) error {
	backend.mu.Lock()
	entered := backend.closeEntered
	gate := backend.closeGates[fd]
	backend.mu.Unlock()
	if entered != nil {
		entered <- fd
	}
	if gate != nil {
		<-gate
	}
	backend.mu.Lock()
	backend.closeCalls[fd]++
	delete(backend.openFDs, fd)
	delete(backend.groupsByFD, fd)
	fail := backend.closeFailures[fd] > 0
	if fail {
		backend.closeFailures[fd]--
	}
	backend.mu.Unlock()
	if fail {
		return unix.EIO
	}
	return nil
}

func (backend *fakeWorkerdCgroupBackend) wait(ctx context.Context, _ time.Duration) error {
	backend.mu.Lock()
	backend.waitCalls++
	backend.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func (backend *fakeWorkerdCgroupBackend) onlyChildName(t *testing.T) string {
	t.Helper()
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.children) != 1 {
		t.Fatalf("children = %d, want 1", len(backend.children))
	}
	for name := range backend.children {
		return name
	}
	panic("unreachable")
}

func (backend *fakeWorkerdCgroupBackend) replaceChild(name string) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.nextInode++
	backend.children[name] = &fakeWorkerdCgroup{
		identity: workerdCgroupIdentity{Device: 2, Inode: backend.nextInode},
		controls: map[string]string{
			"cgroup.type":            "domain\n",
			"cgroup.procs":           "",
			"cgroup.subtree_control": "",
			"cgroup.stat":            "nr_descendants 0\nnr_dying_descendants 0\n",
		},
	}
}

func (backend *fakeWorkerdCgroupBackend) setEvents(fd int, events []string) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.groupsByFD[fd].events = append([]string(nil), events...)
}

func (backend *fakeWorkerdCgroupBackend) limitWrites() []fakeWorkerdCgroupWrite {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	return append([]fakeWorkerdCgroupWrite(nil), backend.writes...)
}

func (backend *fakeWorkerdCgroupBackend) openFileDescriptors() int {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	return len(backend.openFDs)
}

func (backend *fakeWorkerdCgroupBackend) childCount() int {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	return len(backend.children)
}

func (backend *fakeWorkerdCgroupBackend) mkdirCallCount() int {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	return backend.mkdirCalls
}

func (backend *fakeWorkerdCgroupBackend) mkdirModesSeen() []uint32 {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	return append([]uint32(nil), backend.mkdirModes...)
}

func (backend *fakeWorkerdCgroupBackend) removeCallCount() int {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	return backend.removeCalls
}

func (backend *fakeWorkerdCgroupBackend) killCallCount() int {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	return backend.killCalls
}

func (backend *fakeWorkerdCgroupBackend) waitCallCount() int {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	return backend.waitCalls
}
