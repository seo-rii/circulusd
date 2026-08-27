//go:build linux

package materialized_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/hancomac/circulusd/internal/workspace/manifest"
	"github.com/hancomac/circulusd/internal/workspace/materialized"
	"golang.org/x/sys/unix"
)

func TestMaterializeAndScanRoundTrip(t *testing.T) {
	t.Parallel()

	plain := []byte("hello, workspace\n")
	executable := []byte("#!/bin/sh\necho ok\n")
	entries := []manifest.Entry{
		{Path: "src/cafe\u0301.txt", Type: manifest.File, Mode: 0o600, Size: int64(len(plain)), ContentDigest: digest(plain)},
		{Path: "src", Type: manifest.Directory, Mode: 0o700},
		{Path: "run", Type: manifest.File, Mode: 0o711, Size: int64(len(executable)), ContentDigest: digest(executable)},
		{Path: "latest", Type: manifest.Symlink, Mode: 0o700, SymlinkTarget: "src/caf\u00e9.txt"},
	}
	wantEntries, err := manifest.Canonicalize(entries)
	if err != nil {
		t.Fatalf("Canonicalize() error = %v", err)
	}
	wantDigest, err := manifest.RootDigest(entries)
	if err != nil {
		t.Fatalf("RootDigest() error = %v", err)
	}

	parent := t.TempDir()
	target := filepath.Join(parent, "workspace")
	source := &memorySource{objects: map[string][]byte{
		digest(plain):      plain,
		digest(executable): executable,
	}}
	limits := materialized.Limits{MaxEntries: 16, MaxFileBytes: 1 << 20, MaxTotalBytes: 2 << 20}
	if err := materialized.Materialize(context.Background(), target, materialized.Snapshot{
		RootDigest: wantDigest,
		Entries:    entries,
	}, source, limits, testOwnership()); err != nil {
		t.Fatalf("Materialize() error = %v", err)
	}

	content, err := os.ReadFile(filepath.Join(target, "src", "caf\u00e9.txt"))
	if err != nil {
		t.Fatalf("ReadFile(materialized file) error = %v", err)
	}
	if !bytes.Equal(content, plain) {
		t.Fatalf("materialized content = %q, want %q", content, plain)
	}
	information, err := os.Stat(filepath.Join(target, "run"))
	if err != nil {
		t.Fatalf("Stat(executable) error = %v", err)
	}
	if information.Mode().Perm() != 0o755 {
		t.Fatalf("executable mode = %#o, want 0755", information.Mode().Perm())
	}
	assertOwner(t, target, testOwnership())
	assertOwner(t, filepath.Join(target, "run"), testOwnership())
	assertOwner(t, filepath.Join(target, "src"), testOwnership())
	assertOwner(t, filepath.Join(target, "latest"), testOwnership())
	targetValue, err := os.Readlink(filepath.Join(target, "latest"))
	if err != nil {
		t.Fatalf("Readlink() error = %v", err)
	}
	if targetValue != "src/caf\u00e9.txt" {
		t.Fatalf("symlink target = %q", targetValue)
	}

	result, err := materialized.Scan(context.Background(), target, limits)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if result.RootDigest() != wantDigest {
		t.Fatalf("Scan().RootDigest() = %q, want %q", result.RootDigest(), wantDigest)
	}
	if !reflect.DeepEqual(result.Entries(), wantEntries) {
		t.Fatalf("Scan().Entries() = %#v, want %#v", result.Entries(), wantEntries)
	}
	if result.TotalBytes() != int64(len(plain)+len(executable)) {
		t.Fatalf("Scan().TotalBytes() = %d", result.TotalBytes())
	}

	returned := result.Entries()
	returned[0].Path = "tampered"
	if result.Entries()[0].Path == "tampered" {
		t.Fatal("ScanResult aliases caller-owned entries")
	}
}

func TestMaterializeRejectsCorruptSnapshotAndCleansStaging(t *testing.T) {
	t.Parallel()

	content := []byte("expected")
	entry := manifest.Entry{Path: "file", Type: manifest.File, Mode: 0o644, Size: int64(len(content)), ContentDigest: digest(content)}
	rootDigest, err := manifest.RootDigest([]manifest.Entry{entry})
	if err != nil {
		t.Fatalf("RootDigest() error = %v", err)
	}
	tests := []struct {
		name     string
		snapshot materialized.Snapshot
		source   *memorySource
		want     error
	}{
		{
			name:     "declared root digest mismatch",
			snapshot: materialized.Snapshot{RootDigest: strings.Repeat("0", len(rootDigest)), Entries: []manifest.Entry{entry}},
			source:   &memorySource{objects: map[string][]byte{entry.ContentDigest: content}},
			want:     materialized.ErrSnapshotMismatch,
		},
		{
			name:     "blob digest mismatch",
			snapshot: materialized.Snapshot{RootDigest: rootDigest, Entries: []manifest.Entry{entry}},
			source:   &memorySource{objects: map[string][]byte{entry.ContentDigest: []byte("corrupt!")}},
			want:     materialized.ErrCorruptBlob,
		},
		{
			name:     "blob size mismatch",
			snapshot: materialized.Snapshot{RootDigest: rootDigest, Entries: []manifest.Entry{entry}},
			source:   &memorySource{objects: map[string][]byte{entry.ContentDigest: append(content, '!')}},
			want:     materialized.ErrCorruptBlob,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			parent := t.TempDir()
			target := filepath.Join(parent, "workspace")
			err := materialized.Materialize(context.Background(), target, test.snapshot, test.source, materialized.Limits{
				MaxEntries: 4, MaxFileBytes: 1024, MaxTotalBytes: 1024,
			}, testOwnership())
			if !errors.Is(err, test.want) {
				t.Fatalf("Materialize() error = %v, want %v", err, test.want)
			}
			if _, statErr := os.Lstat(target); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("failed materialization published target: %v", statErr)
			}
			assertNoStagingDirectories(t, parent)
		})
	}
}

func TestMaterializeRequiresSourceForZeroByteFile(t *testing.T) {
	t.Parallel()

	entry := manifest.Entry{Path: "empty", Type: manifest.File, Mode: 0o644, ContentDigest: digest(nil)}
	rootDigest, err := manifest.RootDigest([]manifest.Entry{entry})
	if err != nil {
		t.Fatalf("RootDigest() error = %v", err)
	}
	target := filepath.Join(t.TempDir(), "workspace")
	err = materialized.Materialize(context.Background(), target, materialized.Snapshot{
		RootDigest: rootDigest,
		Entries:    []manifest.Entry{entry},
	}, nil, materialized.Limits{MaxEntries: 1, MaxFileBytes: 1024, MaxTotalBytes: 1024}, testOwnership())
	if !errors.Is(err, materialized.ErrCorruptBlob) {
		t.Fatalf("Materialize(nil source) error = %v, want ErrCorruptBlob", err)
	}
	if _, statErr := os.Lstat(target); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("nil-source materialization published target: %v", statErr)
	}
}

func TestMaterializeRejectsUnsafePathsAndLimitsBeforeOpeningBlobs(t *testing.T) {
	t.Parallel()

	content := []byte("content")
	validEntry := manifest.Entry{Path: "file", Type: manifest.File, Size: int64(len(content)), ContentDigest: digest(content)}
	tests := []struct {
		name    string
		entries []manifest.Entry
		limits  materialized.Limits
		want    error
	}{
		{
			name:    "path traversal",
			entries: []manifest.Entry{{Path: "../escape", Type: manifest.File, Size: int64(len(content)), ContentDigest: digest(content)}},
			limits:  materialized.Limits{MaxEntries: 2, MaxFileBytes: 1024, MaxTotalBytes: 1024},
			want:    manifest.ErrInvalidPath,
		},
		{
			name:    "absolute symlink",
			entries: []manifest.Entry{{Path: "escape", Type: manifest.Symlink, SymlinkTarget: "/etc/passwd"}},
			limits:  materialized.Limits{MaxEntries: 2, MaxFileBytes: 1024, MaxTotalBytes: 1024},
			want:    manifest.ErrInvalidEntry,
		},
		{
			name:    "entry count",
			entries: []manifest.Entry{validEntry},
			limits:  materialized.Limits{MaxEntries: 0, MaxFileBytes: 1024, MaxTotalBytes: 1024},
			want:    materialized.ErrInvalidLimits,
		},
		{
			name:    "file size",
			entries: []manifest.Entry{validEntry},
			limits:  materialized.Limits{MaxEntries: 1, MaxFileBytes: 1, MaxTotalBytes: 1024},
			want:    materialized.ErrLimitExceeded,
		},
		{
			name:    "total size",
			entries: []manifest.Entry{validEntry},
			limits:  materialized.Limits{MaxEntries: 1, MaxFileBytes: 1024, MaxTotalBytes: 1},
			want:    materialized.ErrLimitExceeded,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			parent := t.TempDir()
			target := filepath.Join(parent, "workspace")
			rootDigest, _ := manifest.RootDigest(test.entries)
			source := &memorySource{objects: map[string][]byte{digest(content): content}}
			err := materialized.Materialize(context.Background(), target, materialized.Snapshot{
				RootDigest: rootDigest,
				Entries:    test.entries,
			}, source, test.limits, testOwnership())
			if !errors.Is(err, test.want) {
				t.Fatalf("Materialize() error = %v, want %v", err, test.want)
			}
			if source.openCount() != 0 {
				t.Fatalf("source opens = %d, want 0", source.openCount())
			}
			if _, statErr := os.Lstat(target); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("invalid snapshot published target: %v", statErr)
			}
		})
	}
}

func TestMaterializePublishesExactlyOnceUnderConcurrency(t *testing.T) {
	t.Parallel()

	content := []byte("immutable")
	entry := manifest.Entry{Path: "file", Type: manifest.File, Size: int64(len(content)), ContentDigest: digest(content)}
	rootDigest, err := manifest.RootDigest([]manifest.Entry{entry})
	if err != nil {
		t.Fatalf("RootDigest() error = %v", err)
	}
	parent := t.TempDir()
	target := filepath.Join(parent, "workspace")
	source := &memorySource{objects: map[string][]byte{entry.ContentDigest: content}}
	limits := materialized.Limits{MaxEntries: 2, MaxFileBytes: 1024, MaxTotalBytes: 1024}

	const callers = 32
	start := make(chan struct{})
	results := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			results <- materialized.Materialize(context.Background(), target, materialized.Snapshot{
				RootDigest: rootDigest,
				Entries:    []manifest.Entry{entry},
			}, source, limits, testOwnership())
		}()
	}
	close(start)
	wait.Wait()
	close(results)

	successes := 0
	conflicts := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, materialized.ErrDestinationExists):
			conflicts++
		default:
			t.Fatalf("concurrent Materialize() error = %v", err)
		}
	}
	if successes != 1 || conflicts != callers-1 {
		t.Fatalf("successes/conflicts = %d/%d, want 1/%d", successes, conflicts, callers-1)
	}
	got, err := os.ReadFile(filepath.Join(target, "file"))
	if err != nil {
		t.Fatalf("ReadFile(published file) error = %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("published content = %q", got)
	}
	assertNoStagingDirectories(t, parent)
}

func TestMaterializeDoesNotReplaceExistingDestination(t *testing.T) {
	t.Parallel()

	parent := t.TempDir()
	target := filepath.Join(parent, "workspace")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("Mkdir(target) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(target, "sentinel"), []byte("keep"), 0o600); err != nil {
		t.Fatalf("WriteFile(sentinel) error = %v", err)
	}
	rootDigest, err := manifest.RootDigest(nil)
	if err != nil {
		t.Fatalf("RootDigest(empty) error = %v", err)
	}
	err = materialized.Materialize(context.Background(), target, materialized.Snapshot{RootDigest: rootDigest}, &memorySource{}, materialized.Limits{
		MaxEntries: 1, MaxFileBytes: 1, MaxTotalBytes: 1,
	}, testOwnership())
	if !errors.Is(err, materialized.ErrDestinationExists) {
		t.Fatalf("Materialize(existing) error = %v, want ErrDestinationExists", err)
	}
	got, err := os.ReadFile(filepath.Join(target, "sentinel"))
	if err != nil || string(got) != "keep" {
		t.Fatalf("existing destination changed: content=%q err=%v", got, err)
	}
	assertNoStagingDirectories(t, parent)
}

func TestMaterializeAndScanRejectNonCanonicalOrSymlinkRoots(t *testing.T) {
	t.Parallel()

	limits := materialized.Limits{MaxEntries: 2, MaxFileBytes: 1024, MaxTotalBytes: 1024}
	rootDigest, err := manifest.RootDigest(nil)
	if err != nil {
		t.Fatalf("RootDigest(empty) error = %v", err)
	}
	parent := t.TempDir()
	realParent := filepath.Join(parent, "real")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatalf("Mkdir(real parent) error = %v", err)
	}
	linkedParent := filepath.Join(parent, "linked")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Fatalf("Symlink(parent) error = %v", err)
	}

	for name, target := range map[string]string{
		"relative target":         "workspace",
		"unclean target":          parent + "/real/../workspace",
		"symlinked target parent": filepath.Join(linkedParent, "workspace"),
	} {
		t.Run(name, func(t *testing.T) {
			err := materialized.Materialize(context.Background(), target, materialized.Snapshot{RootDigest: rootDigest}, &memorySource{}, limits, testOwnership())
			if !errors.Is(err, materialized.ErrInvalidRoot) {
				t.Fatalf("Materialize(%q) error = %v, want ErrInvalidRoot", target, err)
			}
		})
	}

	realRoot := filepath.Join(parent, "scan-root")
	if err := os.Mkdir(realRoot, 0o700); err != nil {
		t.Fatalf("Mkdir(scan root) error = %v", err)
	}
	linkedRoot := filepath.Join(parent, "scan-link")
	if err := os.Symlink(realRoot, linkedRoot); err != nil {
		t.Fatalf("Symlink(scan root) error = %v", err)
	}
	if _, err := materialized.Scan(context.Background(), linkedRoot, limits); !errors.Is(err, materialized.ErrInvalidRoot) {
		t.Fatalf("Scan(symlink root) error = %v, want ErrInvalidRoot", err)
	}

	insecureParent := filepath.Join(parent, "insecure")
	if err := os.Mkdir(insecureParent, 0o777); err != nil {
		t.Fatalf("Mkdir(insecure parent) error = %v", err)
	}
	if err := os.Chmod(insecureParent, 0o777); err != nil {
		t.Fatalf("Chmod(insecure parent) error = %v", err)
	}
	insecureTarget := filepath.Join(insecureParent, "workspace")
	if err := materialized.Materialize(
		context.Background(),
		insecureTarget,
		materialized.Snapshot{RootDigest: rootDigest},
		&memorySource{},
		limits,
		testOwnership(),
	); !errors.Is(err, materialized.ErrInvalidRoot) {
		t.Fatalf("Materialize(world-writable parent) error = %v, want ErrInvalidRoot", err)
	}
	if err := os.Mkdir(insecureTarget, 0o755); err != nil {
		t.Fatalf("Mkdir(insecure scan root) error = %v", err)
	}
	if _, err := materialized.Scan(context.Background(), insecureTarget, limits); !errors.Is(err, materialized.ErrInvalidRoot) {
		t.Fatalf("Scan(world-writable parent) error = %v, want ErrInvalidRoot", err)
	}
}

func TestScanRejectsUnsupportedOrUnsafeFilesystemState(t *testing.T) {
	t.Parallel()

	limits := materialized.Limits{MaxEntries: 8, MaxFileBytes: 1024, MaxTotalBytes: 4096}
	tests := []struct {
		name  string
		setup func(t *testing.T, root string)
		want  error
	}{
		{
			name: "absolute symlink",
			setup: func(t *testing.T, root string) {
				t.Helper()
				if err := os.Symlink("/etc/passwd", filepath.Join(root, "escape")); err != nil {
					t.Fatalf("Symlink() error = %v", err)
				}
			},
			want: manifest.ErrInvalidEntry,
		},
		{
			name: "escaping relative symlink",
			setup: func(t *testing.T, root string) {
				t.Helper()
				if err := os.Symlink("../outside", filepath.Join(root, "escape")); err != nil {
					t.Fatalf("Symlink() error = %v", err)
				}
			},
			want: manifest.ErrInvalidEntry,
		},
		{
			name: "fifo",
			setup: func(t *testing.T, root string) {
				t.Helper()
				if err := unix.Mkfifo(filepath.Join(root, "pipe"), 0o600); err != nil {
					t.Fatalf("Mkfifo() error = %v", err)
				}
			},
			want: materialized.ErrUnsupportedFileType,
		},
		{
			name: "hard link",
			setup: func(t *testing.T, root string) {
				t.Helper()
				first := filepath.Join(root, "first")
				if err := os.WriteFile(first, []byte("same inode"), 0o600); err != nil {
					t.Fatalf("WriteFile() error = %v", err)
				}
				if err := os.Link(first, filepath.Join(root, "second")); err != nil {
					t.Fatalf("Link() error = %v", err)
				}
			},
			want: materialized.ErrUnsupportedFileType,
		},
		{
			name: "invalid utf8 name",
			setup: func(t *testing.T, root string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(root, string([]byte{'x', 0xff})), nil, 0o600); err != nil {
					t.Fatalf("WriteFile(invalid UTF-8) error = %v", err)
				}
			},
			want: manifest.ErrInvalidPath,
		},
		{
			name: "NFC collision",
			setup: func(t *testing.T, root string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(root, "caf\u00e9"), nil, 0o600); err != nil {
					t.Fatalf("WriteFile(NFC) error = %v", err)
				}
				if err := os.WriteFile(filepath.Join(root, "cafe\u0301"), nil, 0o600); err != nil {
					t.Fatalf("WriteFile(NFD) error = %v", err)
				}
			},
			want: manifest.ErrPathCollision,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			root := filepath.Join(t.TempDir(), "workspace")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatalf("Mkdir(root) error = %v", err)
			}
			test.setup(t, root)
			_, err := materialized.Scan(context.Background(), root, limits)
			if !errors.Is(err, test.want) {
				t.Fatalf("Scan() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestScanEnforcesCountAndContentLimits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		limits materialized.Limits
	}{
		{name: "entry count", limits: materialized.Limits{MaxEntries: 1, MaxFileBytes: 1024, MaxTotalBytes: 1024}},
		{name: "file size", limits: materialized.Limits{MaxEntries: 4, MaxFileBytes: 2, MaxTotalBytes: 1024}},
		{name: "total size", limits: materialized.Limits{MaxEntries: 4, MaxFileBytes: 1024, MaxTotalBytes: 5}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			root := filepath.Join(t.TempDir(), "workspace")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatalf("Mkdir(root) error = %v", err)
			}
			if err := os.WriteFile(filepath.Join(root, "one"), []byte("abc"), 0o600); err != nil {
				t.Fatalf("WriteFile(one) error = %v", err)
			}
			if err := os.WriteFile(filepath.Join(root, "two"), []byte("def"), 0o600); err != nil {
				t.Fatalf("WriteFile(two) error = %v", err)
			}
			_, err := materialized.Scan(context.Background(), root, test.limits)
			if !errors.Is(err, materialized.ErrLimitExceeded) {
				t.Fatalf("Scan() error = %v, want ErrLimitExceeded", err)
			}
		})
	}
}

func TestScanIsDeterministicForConcurrentReaders(t *testing.T) {
	t.Parallel()

	root := filepath.Join(t.TempDir(), "workspace")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("Mkdir(root) error = %v", err)
	}
	for index := range 64 {
		name := fmt.Sprintf("file-%03d", 63-index)
		if err := os.WriteFile(filepath.Join(root, name), []byte(name), 0o600); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", name, err)
		}
	}
	limits := materialized.Limits{MaxEntries: 128, MaxFileBytes: 1024, MaxTotalBytes: 1 << 20}

	const readers = 32
	results := make(chan string, readers)
	errorsSeen := make(chan error, readers)
	var wait sync.WaitGroup
	for range readers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := materialized.Scan(context.Background(), root, limits)
			if err == nil {
				paths := make([]string, 0, len(result.Entries()))
				for _, entry := range result.Entries() {
					paths = append(paths, entry.Path)
				}
				if !sort.StringsAreSorted(paths) {
					err = fmt.Errorf("paths are not sorted: %v", paths)
				} else {
					results <- result.RootDigest()
				}
			}
			errorsSeen <- err
		}()
	}
	wait.Wait()
	close(results)
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatalf("concurrent Scan() error = %v", err)
		}
	}
	var first string
	for result := range results {
		if first == "" {
			first = result
		} else if result != first {
			t.Fatalf("concurrent digest = %q, want %q", result, first)
		}
	}
}

func TestOperationsHonorCanceledContextWithoutPublishing(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	limits := materialized.Limits{MaxEntries: 2, MaxFileBytes: 1024, MaxTotalBytes: 1024}
	rootDigest, err := manifest.RootDigest(nil)
	if err != nil {
		t.Fatalf("RootDigest(empty) error = %v", err)
	}
	target := filepath.Join(t.TempDir(), "workspace")
	if err := materialized.Materialize(ctx, target, materialized.Snapshot{RootDigest: rootDigest}, &memorySource{}, limits, testOwnership()); !errors.Is(err, context.Canceled) {
		t.Fatalf("Materialize(canceled) error = %v", err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled materialization published target: %v", err)
	}
	root := filepath.Join(t.TempDir(), "scan")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("Mkdir(scan root) error = %v", err)
	}
	if _, err := materialized.Scan(ctx, root, limits); !errors.Is(err, context.Canceled) {
		t.Fatalf("Scan(canceled) error = %v", err)
	}
}

func TestOperationsRejectNilContextWithoutFilesystemMutation(t *testing.T) {
	t.Parallel()

	limits := materialized.Limits{MaxEntries: 2, MaxFileBytes: 1024, MaxTotalBytes: 1024}
	rootDigest, err := manifest.RootDigest(nil)
	if err != nil {
		t.Fatalf("RootDigest(empty) error = %v", err)
	}
	target := filepath.Join(t.TempDir(), "workspace")
	if err := materialized.Materialize(
		nil,
		target,
		materialized.Snapshot{RootDigest: rootDigest},
		&memorySource{},
		limits,
		testOwnership(),
	); err == nil {
		t.Fatal("Materialize(nil context) error = nil")
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("nil-context materialization mutated target: %v", err)
	}
	root := filepath.Join(t.TempDir(), "scan")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("Mkdir(scan root) error = %v", err)
	}
	if _, err := materialized.Scan(nil, root, limits); err == nil {
		t.Fatal("Scan(nil context) error = nil")
	}
}

func TestMaterializeRejectsReservedOwnershipWithoutFilesystemMutation(t *testing.T) {
	t.Parallel()

	limits := materialized.Limits{MaxEntries: 1, MaxFileBytes: 1, MaxTotalBytes: 1}
	rootDigest, err := manifest.RootDigest(nil)
	if err != nil {
		t.Fatalf("RootDigest(empty) error = %v", err)
	}
	for name, ownership := range map[string]materialized.Ownership{
		"reserved uid": {UID: ^uint32(0), GID: uint32(os.Getegid())},
		"reserved gid": {UID: uint32(os.Geteuid()), GID: ^uint32(0)},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			target := filepath.Join(t.TempDir(), "workspace")
			err := materialized.Materialize(
				context.Background(),
				target,
				materialized.Snapshot{RootDigest: rootDigest},
				&memorySource{},
				limits,
				ownership,
			)
			if err == nil {
				t.Fatal("Materialize(reserved ownership) error = nil")
			}
			if _, statErr := os.Lstat(target); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("reserved ownership mutated target: %v", statErr)
			}
		})
	}
}

func TestMaterializePreservesCancellationFromBlobRead(t *testing.T) {
	t.Parallel()

	content := []byte("content")
	entry := manifest.Entry{Path: "file", Type: manifest.File, Size: int64(len(content)), ContentDigest: digest(content)}
	rootDigest, err := manifest.RootDigest([]manifest.Entry{entry})
	if err != nil {
		t.Fatalf("RootDigest() error = %v", err)
	}
	target := filepath.Join(t.TempDir(), "workspace")
	err = materialized.Materialize(context.Background(), target, materialized.Snapshot{
		RootDigest: rootDigest,
		Entries:    []manifest.Entry{entry},
	}, cancelingSource{}, materialized.Limits{MaxEntries: 1, MaxFileBytes: 1024, MaxTotalBytes: 1024}, testOwnership())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Materialize(canceled read) error = %v, want context.Canceled", err)
	}
	if _, statErr := os.Lstat(target); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("canceled blob read published target: %v", statErr)
	}
}

type memorySource struct {
	mu      sync.Mutex
	opens   int
	objects map[string][]byte
}

type cancelingSource struct{}

func (cancelingSource) Open(context.Context, string) (io.ReadCloser, error) {
	return io.NopCloser(cancelingReader{}), nil
}

type cancelingReader struct{}

func (cancelingReader) Read([]byte) (int, error) { return 0, context.Canceled }

func (source *memorySource) Open(_ context.Context, contentDigest string) (io.ReadCloser, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.opens++
	content, found := source.objects[contentDigest]
	if !found {
		return nil, os.ErrNotExist
	}
	return io.NopCloser(bytes.NewReader(append([]byte(nil), content...))), nil
}

func (source *memorySource) openCount() int {
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.opens
}

func digest(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func assertNoStagingDirectories(t *testing.T, parent string) {
	t.Helper()
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatalf("ReadDir(parent) error = %v", err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".stage-") {
			t.Fatalf("staging directory was not cleaned: %q", entry.Name())
		}
	}
}

func testOwnership() materialized.Ownership {
	return materialized.Ownership{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
}

func assertOwner(t *testing.T, path string, want materialized.Ownership) {
	t.Helper()
	var status unix.Stat_t
	if err := unix.Lstat(path, &status); err != nil {
		t.Fatalf("Lstat(%s) error = %v", path, err)
	}
	if status.Uid != want.UID || status.Gid != want.GID {
		t.Fatalf("owner(%s) = %d:%d, want %d:%d", path, status.Uid, status.Gid, want.UID, want.GID)
	}
}
