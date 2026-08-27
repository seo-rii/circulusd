//go:build linux

package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestNewWorkerdCgroupControllerRejectsConfigurationOutsideClosedBounds(t *testing.T) {
	valid := workerdCgroupConfig{
		RootPath:       "/sys/fs/cgroup/circulusd-workerd",
		MaximumShards:  1,
		DrainTimeout:   time.Nanosecond,
		MemoryMaxBytes: 1,
		SwapMaxBytes:   0,
		CPUCores:       1,
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
		{name: "zero cpu", mutate: func(config *workerdCgroupConfig) { config.CPUCores = 0 }},
		{name: "excessive cpu", mutate: func(config *workerdCgroupConfig) { config.CPUCores = 1025 }},
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
	minimum.CPUCores = 1
	minimum.PIDsMax = 1
	maximum := validWorkerdCgroupConfig()
	maximum.MaximumShards = 4096
	maximum.DrainTimeout = 30 * time.Second
	maximum.MemoryMaxBytes = 1 << 50
	maximum.CPUCores = 1024
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
	lease, err := controller.prepare(context.Background(), "shared-shard-a", 7)
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
		{Name: "cpu.max", Value: fmt.Sprintf("%d 100000", config.CPUCores*100_000)},
		{Name: "pids.max", Value: fmt.Sprint(config.PIDsMax)},
	}
	if writes := backend.limitWrites(); !reflect.DeepEqual(writes, wantWrites) {
		t.Fatalf("control writes = %#v, want %#v", writes, wantWrites)
	}
	if modes := backend.mkdirModesSeen(); !reflect.DeepEqual(modes, []uint32{0o700}) {
		t.Fatalf("mkdir modes = %#v, want exclusive private 0700", modes)
	}
	firstName := backend.onlyChildName(t)
	if firstName != workerdCgroupLeafName("shared-shard-a", 7) {
		t.Fatalf("leaf name = %q, want deterministic domain-separated identity", firstName)
	}
	if firstName == workerdCgroupLeafName("shared-shard-a", 8) {
		t.Fatal("leaf name does not bind placement generation")
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

func TestWorkerdCgroupDirectoryFDBorrowExcludesDestroyAndCannotBeReused(t *testing.T) {
	_, backend, controller := newWorkerdCgroupFixture(t)
	lease, err := controller.prepare(context.Background(), "borrowed-directory-fd", 1)
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
			lease, err := controller.prepare(context.Background(), "invalid-leaf", 1)
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
	lease, err := controller.prepare(context.Background(), "rollback-shard", 1)
	if lease != nil || !errors.Is(err, errWorkerdCgroupContract) {
		t.Fatalf("prepare(corrupt readback) = %#v, %v, want nil, contract error", lease, err)
	}
	if children := backend.childCount(); children != 0 {
		t.Fatalf("children after rollback = %d, want 0", children)
	}
	delete(backend.corruptReadback, "cpu.max")
	lease, err = controller.prepare(context.Background(), "after-rollback", 1)
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
	lease, err := controller.prepare(context.Background(), "retryable-rollback", 1)
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
	replacement, err := controller.prepare(context.Background(), "after-retryable-rollback", 1)
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
	lease, err := controller.prepare(context.Background(), "unidentified-child", 1)
	if lease != nil || !errors.Is(err, errWorkerdCgroupPoisoned) {
		t.Fatalf("prepare(open failure) = %#v, %v, want nil and poisoned error", lease, err)
	}
	if next, prepareErr := controller.prepare(context.Background(), "must-not-admit", 1); next != nil || !errors.Is(prepareErr, errWorkerdCgroupPoisoned) {
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
	existing, err := controller.prepare(context.Background(), "existing-before-poison", 1)
	if err != nil {
		t.Fatalf("prepare(existing) error = %v", err)
	}
	backend.openFailures = 1
	if unidentified, prepareErr := controller.prepare(context.Background(), "poisoning-child", 1); unidentified != nil || !errors.Is(prepareErr, errWorkerdCgroupPoisoned) {
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
	lease, err := controller.prepare(context.Background(), "rollback-replacement", 1)
	if lease != nil || !errors.Is(err, errWorkerdCgroupPathReplaced) || !errors.Is(err, errWorkerdCgroupPoisoned) {
		t.Fatalf("prepare(replaced during rollback) = %#v, %v, want nil, path replaced and poisoned", lease, err)
	}
	if calls := backend.removeCallCount(); calls != 0 {
		t.Fatalf("remove calls for rollback replacement = %d, want 0", calls)
	}
	if next, prepareErr := controller.prepare(context.Background(), "must-not-admit", 1); next != nil || !errors.Is(prepareErr, errWorkerdCgroupPoisoned) {
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
		lease, prepareErr := controller.prepare(context.Background(), "first", 1)
		result <- workerdCgroupPrepareResult{lease: lease, err: prepareErr}
	}()
	<-backend.mkdirEntered
	if lease, prepareErr := controller.prepare(context.Background(), "second", 1); lease != nil || !errors.Is(prepareErr, errWorkerdCgroupCapacity) {
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
			lease, prepareErr := controller.prepare(context.Background(), fmt.Sprintf("concurrent-%d", index), 1)
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
	lease, err := controller.prepare(context.Background(), "coalesced-destroy", 1)
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
	lease, err := controller.prepare(context.Background(), "cancelled-destroy-waiter", 1)
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
	lease, err := controller.prepare(context.Background(), "idempotent-cancelled-destroy", 1)
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
	lease, err := controller.prepare(context.Background(), "retry-destroy", 1)
	if err != nil {
		t.Fatalf("prepare() error = %v", err)
	}
	backend.removeFailures = 1
	if err := lease.destroy(context.Background()); err == nil {
		t.Fatal("destroy(first) error = nil, want retryable failure")
	}
	if extra, prepareErr := controller.prepare(context.Background(), "must-remain-reserved", 1); extra != nil || !errors.Is(prepareErr, errWorkerdCgroupCapacity) {
		t.Fatalf("prepare(before successful unlink) = %#v, %v, want capacity", extra, prepareErr)
	}
	if err := lease.destroy(context.Background()); err != nil {
		t.Fatalf("destroy(retry) error = %v", err)
	}
	replacement, err := controller.prepare(context.Background(), "after-unlink", 1)
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
	lease, err := controller.prepare(context.Background(), "replacement-attack", 4)
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
	if next, prepareErr := controller.prepare(context.Background(), "must-not-admit", 1); next != nil || !errors.Is(prepareErr, errWorkerdCgroupPoisoned) {
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
	lease, err := controller.prepare(context.Background(), "draining", 1)
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
	lease, err := controller.prepare(context.Background(), "drain-timeout", 1)
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
	for generation := uint64(1); generation <= 100; generation++ {
		lease, prepareErr := controller.prepare(context.Background(), "fd-cycle", generation)
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
	lease, err := controller.prepare(context.Background(), "close-waits-for-leaf-fd", 1)
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
	lease, err := controller.prepare(context.Background(), "terminal-leaf-close", 1)
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
	borrowedLease, err := controller.prepare(context.Background(), "active-borrow", 1)
	if err != nil {
		t.Fatalf("prepare(active borrow) error = %v", err)
	}
	poisonedLease, err := controller.prepare(context.Background(), "poison-writer", 1)
	if err != nil {
		t.Fatalf("prepare(poison writer) error = %v", err)
	}
	queuedLease, err := controller.prepare(context.Background(), "queued-after-writer", 1)
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
	for controller.authority.TryRLock() {
		controller.authority.RUnlock()
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
		CPUCores:       4,
		PIDsMax:        512,
	}
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

type fakeWorkerdCgroup struct {
	identity workerdCgroupIdentity
	fd       int
	controls map[string]string
	events   []string
}

type fakeWorkerdCgroupBackend struct {
	mu sync.Mutex

	effectiveUID uint32
	effectiveGID uint32
	inspection   workerdCgroupRootInspection
	inspectErr   error
	nextFD       int
	openFDs      map[int]struct{}
	groupsByFD   map[int]*fakeWorkerdCgroup
	children     map[string]*fakeWorkerdCgroup
	writes       []fakeWorkerdCgroupWrite
	nextInode    uint64

	corruptReadback   map[string]string
	replaceOnReadback string
	writeFailures     map[string]int
	openFailures      int
	removeFailures    int
	mkdirCalls        int
	mkdirModes        []uint32
	removeCalls       int
	killCalls         int
	waitCalls         int
	mkdirEntered      chan struct{}
	mkdirGate         <-chan struct{}
	killEntered       chan struct{}
	killGate          <-chan struct{}
	killHook          func()
	killEnteredByFD   map[int]chan struct{}
	killGatesByFD     map[int]<-chan struct{}
	killHooksByFD     map[int]func()
	closeEntered      chan int
	closeGates        map[int]<-chan struct{}
	closeFailures     map[int]int
	closeCalls        map[int]int
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
		nextFD:          11,
		openFDs:         map[int]struct{}{},
		groupsByFD:      map[int]*fakeWorkerdCgroup{},
		children:        map[string]*fakeWorkerdCgroup{},
		nextInode:       100,
		corruptReadback: map[string]string{},
		writeFailures:   map[string]int{},
		killEnteredByFD: map[int]chan struct{}{},
		killGatesByFD:   map[int]<-chan struct{}{},
		killHooksByFD:   map[int]func(){},
		closeGates:      map[int]<-chan struct{}{},
		closeFailures:   map[int]int{},
		closeCalls:      map[int]int{},
	}
}

func (backend *fakeWorkerdCgroupBackend) effectiveIDs() (uint32, uint32) {
	return backend.effectiveUID, backend.effectiveGID
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

func (backend *fakeWorkerdCgroupBackend) readControl(fd int, name string, _ int) (string, error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	group := backend.groupsByFD[fd]
	if group == nil {
		return "", unix.EBADF
	}
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
		return corrupted, nil
	}
	if name == "cgroup.events" {
		if len(group.events) == 0 {
			return "populated 0\nfrozen 0\n", nil
		}
		value := group.events[0]
		if len(group.events) > 1 {
			group.events = group.events[1:]
		}
		return value, nil
	}
	return group.controls[name], nil
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
