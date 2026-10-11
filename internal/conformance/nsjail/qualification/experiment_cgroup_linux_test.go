//go:build linux

package qualification

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPinnedCgroupSnapshotsUseOriginalDescriptorsAndCloseExactlyOnce(t *testing.T) {
	root := t.TempDir()
	directory, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(directory.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	capture := &pinnedExperimentCgroup{directory: directory, device: uint64(stat.Dev), inode: stat.Ino, files: map[string]*os.File{}}
	t.Cleanup(func() { _ = capture.Close() })
	raw := testExperiments(testHost().RunID)[0].Before
	var fds []int
	fds = append(fds, int(directory.Fd()))
	for key, value := range raw.Files {
		path := filepath.Join(root, key)
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		capture.files[key] = file
		fds = append(fds, int(file.Fd()))
	}
	if before, err := capture.Snapshot(); err != nil || !fixedExperimentLimits(before) {
		t.Fatalf("first snapshot: %v", err)
	}
	path := filepath.Join(root, "memory.max")
	if err := os.Rename(path, path+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("max"), 0600); err != nil {
		t.Fatal(err)
	}
	after, err := capture.Snapshot()
	if err != nil || after.Files["memory.max"] != "536870912" {
		t.Fatal("snapshot reopened a replaced pathname")
	}
	if err := capture.Close(); err != nil {
		t.Fatal(err)
	}
	for _, fd := range fds {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != unix.EBADF {
			t.Fatal("capture leaked a descriptor")
		}
	}
	if err := capture.Close(); err != nil {
		t.Fatal("capture double closed resources")
	}
	if _, err := capture.Snapshot(); err == nil {
		t.Fatal("closed snapshot succeeded")
	}
}

func TestCgroupCaptureRefusesRegularFilesAndMalformedCounters(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "cgroup.procs"), []byte("111"), 0600); err != nil {
		t.Fatal(err)
	}
	s := &liveQualificationSession{cgroupPath: root}
	if capture, err := s.openExperimentCgroup(); err == nil {
		_ = capture.Close()
		t.Fatal("ordinary files became kernel evidence")
	}
	for _, raw := range []string{"", "max", "max -1", "max 01", "max 1\nmax 2", "max 18446744073709551616", strings.Repeat("x", 4097)} {
		if _, err := parseKernelCounters(raw); err == nil {
			t.Fatalf("invalid counter accepted %q", raw)
		}
	}
	o := testExperiments(testHost().RunID)[0]
	delete(o.Before.Files, "memory.current")
	if fixedExperimentLimits(o.Before) {
		t.Fatal("missing raw cgroup file accepted")
	}
}
