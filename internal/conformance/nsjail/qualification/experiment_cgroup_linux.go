//go:build linux

package qualification

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type cgroupObservation struct {
	Device uint64            `json:"device"`
	Inode  uint64            `json:"inode"`
	Files  map[string]string `json:"files"`
}
type experimentCgroup interface {
	Snapshot() (cgroupObservation, error)
	Close() error
}
type pinnedExperimentCgroup struct {
	directory     *os.File
	files         map[string]*os.File
	device, inode uint64
}

var experimentCgroupFiles = []string{"cgroup.procs", "memory.max", "memory.swap.max", "pids.max", "cpu.max", "cpu.stat", "memory.events", "pids.events", "pids.current", "memory.current"}

// Open each pseudo-file before GO. Snapshots use these exact descriptors rather
// than re-opening a generation pathname after an OOM or a lifecycle transition.
func (s *liveQualificationSession) openExperimentCgroup() (experimentCgroup, error) {
	var leaf string
	err := walkQualificationDirectory(s.cgroupPath, 1024, 3, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		raw, err := readCgroupFilePath(filepath.Join(path, "cgroup.procs"))
		if err != nil {
			return err
		}
		if strings.TrimSpace(raw) == "" {
			return nil
		}
		if leaf != "" {
			return errors.New("experiment spans multiple active cgroups")
		}
		leaf = path
		return nil
	})
	if err != nil {
		return nil, err
	}
	if leaf == "" {
		return nil, errors.New("experiment has no active owned cgroup")
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, leaf, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, err
	}
	owned := &pinnedExperimentCgroup{directory: os.NewFile(uintptr(fd), "qualification-cgroup"), files: map[string]*os.File{}}
	failed := true
	defer func() {
		if failed {
			_ = owned.Close()
		}
	}()
	var stat unix.Stat_t
	var fs unix.Statfs_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	if err := unix.Fstatfs(fd, &fs); err != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return nil, errors.New("experiment target is not cgroup v2")
	}
	owned.device = uint64(stat.Dev)
	owned.inode = stat.Ino
	for _, name := range experimentCgroupFiles {
		fileFD, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return nil, err
		}
		owned.files[name] = os.NewFile(uintptr(fileFD), "qualification-"+name)
	}
	failed = false
	return owned, nil
}
func readCgroupFilePath(path string) (string, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(fd), "qualification-cgroup-read")
	defer file.Close()
	return readCgroupFile(file)
}
func readCgroupFile(file *os.File) (string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	raw, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(raw) > 4096 {
		return "", errors.New("cgroup observation unavailable or oversized")
	}
	return strings.TrimSpace(string(raw)), nil
}
func (c *pinnedExperimentCgroup) Snapshot() (cgroupObservation, error) {
	result := cgroupObservation{Device: c.device, Inode: c.inode, Files: map[string]string{}}
	if c.directory == nil {
		return result, errors.New("cgroup capture closed")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(c.directory.Fd()), &stat); err != nil || uint64(stat.Dev) != c.device || stat.Ino != c.inode {
		return result, errors.New("cgroup identity changed")
	}
	for _, name := range experimentCgroupFiles {
		file := c.files[name]
		if file == nil {
			return result, errors.New("missing cgroup observation descriptor")
		}
		raw, err := readCgroupFile(file)
		if err != nil {
			return result, err
		}
		result.Files[name] = raw
	}
	return result, nil
}
func (c *pinnedExperimentCgroup) Close() error {
	var err error
	for name, file := range c.files {
		err = errors.Join(err, file.Close())
		delete(c.files, name)
	}
	if c.directory != nil {
		err = errors.Join(err, c.directory.Close())
		c.directory = nil
	}
	return err
}

func parseKernelCounters(raw string) (map[string]uint64, error) {
	if raw == "" || len(raw) > 4096 {
		return nil, errors.New("invalid kernel counters")
	}
	result := map[string]uint64{}
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || len(result) >= 64 {
			return nil, errors.New("invalid kernel counter row")
		}
		if _, exists := result[fields[0]]; exists {
			return nil, errors.New("duplicate kernel counter")
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil || strconv.FormatUint(value, 10) != fields[1] {
			return nil, errors.New("noncanonical kernel counter")
		}
		result[fields[0]] = value
	}
	return result, nil
}
func fixedExperimentLimits(c cgroupObservation) bool {
	if len(c.Files) != len(experimentCgroupFiles) {
		return false
	}
	for _, key := range experimentCgroupFiles {
		if _, ok := c.Files[key]; !ok {
			return false
		}
	}
	for _, key := range []string{"memory.current", "pids.current"} {
		value, err := strconv.ParseUint(c.Files[key], 10, 64)
		if err != nil || strconv.FormatUint(value, 10) != c.Files[key] {
			return false
		}
	}
	for file, keys := range map[string][]string{"cpu.stat": {"usage_usec", "nr_throttled", "throttled_usec"}, "memory.events": {"oom", "oom_kill"}, "pids.events": {"max"}} {
		counters, err := parseKernelCounters(c.Files[file])
		if err != nil {
			return false
		}
		for _, key := range keys {
			if _, ok := counters[key]; !ok {
				return false
			}
		}
	}
	processes := strings.Fields(c.Files["cgroup.procs"])
	if len(processes) > 64 {
		return false
	}
	seen := map[uint64]bool{}
	for _, text := range processes {
		pid, err := strconv.ParseUint(text, 10, 32)
		if err != nil || pid == 0 || strconv.FormatUint(pid, 10) != text || seen[pid] {
			return false
		}
		seen[pid] = true
	}
	return c.Device != 0 && c.Inode != 0 && c.Files["memory.max"] == "536870912" && c.Files["memory.swap.max"] == "0" && c.Files["pids.max"] == "64" && validCPUQuota(c.Files["cpu.max"])
}
func counterDelta(before, after cgroupObservation, file, key string) (uint64, bool) {
	b, err := parseKernelCounters(before.Files[file])
	if err != nil {
		return 0, false
	}
	a, err := parseKernelCounters(after.Files[file])
	if err != nil {
		return 0, false
	}
	bv, bok := b[key]
	av, aok := a[key]
	if !bok || !aok || av < bv {
		return 0, false
	}
	return av - bv, true
}
