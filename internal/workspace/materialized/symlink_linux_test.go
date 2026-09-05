//go:build linux

package materialized_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/hancomac/circulusd/internal/workspace/manifest"
	"github.com/hancomac/circulusd/internal/workspace/materialized"
	"golang.org/x/sys/unix"
)

func TestSymlinkScanMaterializePreservesTraversal(t *testing.T) {
	for _, test := range []struct {
		name, target string
		want         symlinkObservation
	}{
		{"symlink_before_parent", "link/../file", symlinkObservation{kind: unix.S_IFREG, content: "nested file"}},
		{"missing_before_parent", "missing/../file", symlinkObservation{errno: unix.ENOENT}},
		{"file_before_parent", "file/../file", symlinkObservation{errno: unix.ENOTDIR}},
		{"file_before_dot", "file/.", symlinkObservation{errno: unix.ENOTDIR}},
		{"file_trailing_slash", "file/", symlinkObservation{errno: unix.ENOTDIR}},
		{"directory_trailing_slash", "link/", symlinkObservation{kind: unix.S_IFDIR}},
		{"repeated_slash", "dir//nested/../file", symlinkObservation{kind: unix.S_IFREG, content: "nested file"}},
		{"leading_dot", "./file", symlinkObservation{kind: unix.S_IFREG, content: "root file"}},
		{"leading_dot_repeated_slash", ".//file", symlinkObservation{kind: unix.S_IFREG, content: "root file"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			observed := checkSymlinkRoundTrip(t, []string{"dir/nested"}, map[string][]byte{
				"file": []byte("root file"), "dir/file": []byte("nested file"),
			}, map[string]string{"link": "dir/nested", "alias": test.target}, true)
			if observed["alias"] != test.want {
				t.Fatalf("source fixture resolved as %+v, want %+v", observed["alias"], test.want)
			}
		})
	}
}

func TestSymlinkScanRejectsEscapeThroughAnotherLink(t *testing.T) {
	observed := checkSymlinkRoundTrip(t, []string{"dir"}, map[string][]byte{"file": []byte("inside")},
		map[string]string{"dir/up": "..", "escape": "dir/up/../file"}, false)
	if observed != nil {
		t.Fatal("Scan accepted a link that escapes after expanding an intermediate symlink")
	}
}

type symlinkObservation struct {
	kind    uint32
	errno   syscall.Errno
	content string
}

// The kernel is the independent path-resolution oracle. RESOLVE_BENEATH
// prevents even a generated escaping link from accessing the host filesystem.
func observeSymlink(t *testing.T, rootFD int, name string) symlinkObservation {
	t.Helper()
	fd, err := unix.Openat2(rootFD, name, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_NOCTTY,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		var errno syscall.Errno
		if !errors.As(err, &errno) {
			t.Fatal(err)
		}
		switch errno {
		case unix.ENOENT, unix.ENOTDIR, unix.ELOOP, unix.EXDEV:
			return symlinkObservation{errno: errno}
		default:
			t.Fatalf("unexpected path lookup error for %q: %v", name, err)
		}
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		t.Fatal(err)
	}
	observed := symlinkObservation{kind: stat.Mode & unix.S_IFMT}
	if observed.kind == unix.S_IFREG {
		content, err := io.ReadAll(io.LimitReader(file, 1025))
		if err != nil || len(content) > 1024 {
			t.Fatalf("generated file read exceeded its boundary: bytes=%d err=%v", len(content), err)
		}
		observed.content = string(content)
	}
	return observed
}

// Known-safe generated trees must be accepted. For arbitrary graphs, rejection
// is permitted; every accepted graph must preserve resolution and containment.
func checkSymlinkRoundTrip(
	t *testing.T,
	directories []string,
	files map[string][]byte,
	links map[string]string,
	mustAccept bool,
) map[string]symlinkObservation {
	t.Helper()
	parent := t.TempDir()
	original, restored := filepath.Join(parent, "original"), filepath.Join(parent, "restored")
	if err := os.Mkdir(original, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, directory := range directories {
		if err := os.MkdirAll(filepath.Join(original, directory), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	source := &memorySource{objects: make(map[string][]byte)}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(original, name), content, 0o644); err != nil {
			t.Fatal(err)
		}
		source.objects[digest(content)] = content
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(original, name)); err != nil {
			t.Fatal(err)
		}
	}
	limits := materialized.Limits{MaxEntries: 64, MaxFileBytes: 1024, MaxTotalBytes: 8192}
	scanned, err := materialized.Scan(context.Background(), original, limits)
	if err != nil {
		if mustAccept || !errors.Is(err, manifest.ErrInvalidEntry) {
			t.Fatalf("Scan rejected generated tree: links=%q err=%v", links, err)
		}
		return nil
	}
	originalFD, err := unix.Open(original, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(originalFD)
	before := make(map[string]symlinkObservation, len(links))
	for name := range links {
		before[name] = observeSymlink(t, originalFD, name)
		if before[name].errno == unix.EXDEV {
			t.Fatalf("Scan accepted escaping link %q: targets=%q", name, links)
		}
	}
	if err := materialized.Materialize(context.Background(), restored, materialized.Snapshot{
		RootDigest: scanned.RootDigest(), Entries: scanned.Entries(),
	}, source, limits, testOwnership()); err != nil {
		t.Fatal(err)
	}
	restoredFD, err := unix.Open(restored, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(restoredFD)
	for name := range links {
		after := observeSymlink(t, restoredFD, name)
		if after != before[name] {
			t.Fatalf("symlink %q changed resolution: before=%+v after=%+v targets=%q", name, before[name], after, links)
		}
	}
	again, err := materialized.Scan(context.Background(), restored, limits)
	if err != nil || again.RootDigest() != scanned.RootDigest() {
		t.Fatal(fmt.Errorf("round-trip snapshot is not canonical: digest=%q want=%q err=%v", again.RootDigest(), scanned.RootDigest(), err))
	}
	return before
}
