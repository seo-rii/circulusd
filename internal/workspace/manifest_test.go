package workspace

import (
	"errors"
	"strings"
	"sync"
	"testing"
)

const (
	emptyDigest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	textDigest  = "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
)

func TestBuildManifestCanonicalizesPathsModesAndOrdering(t *testing.T) {
	t.Parallel()
	input := []Entry{
		{Path: "src/e\u0301.txt", Type: EntryFile, Mode: 0o600, Size: 5, ContentDigest: textDigest},
		{Path: "src", Type: EntryDirectory, Mode: 0o700},
		{Path: "run", Type: EntryFile, Mode: 0o711, ContentDigest: emptyDigest},
		{Path: "latest", Type: EntrySymlink, Mode: 0o700, SymlinkTarget: "src/é.txt"},
	}

	manifest, err := BuildManifest(input, Limits{})
	if err != nil {
		t.Fatalf("BuildManifest() error = %v", err)
	}
	wantPaths := []string{"latest", "run", "src", "src/é.txt"}
	entries := manifest.Entries()
	if len(entries) != len(wantPaths) {
		t.Fatalf("entry count = %d, want %d", len(entries), len(wantPaths))
	}
	for index, want := range wantPaths {
		if entries[index].Path != want {
			t.Fatalf("entry[%d].Path = %q, want %q", index, entries[index].Path, want)
		}
	}
	if entries[1].Mode != 0o755 || entries[2].Mode != 0o755 || entries[3].Mode != 0o644 || entries[0].Mode != 0o777 {
		t.Fatalf("canonical modes = %#v", entries)
	}
	if !strings.HasPrefix(manifest.RootDigest(), "sha256:") || len(manifest.RootDigest()) != 71 {
		t.Fatalf("root digest = %q", manifest.RootDigest())
	}

	input[0].Path = "mutated"
	entries[0].Path = "also-mutated"
	if manifest.Entries()[0].Path != "latest" {
		t.Fatal("manifest aliases caller-owned entry slices")
	}
}

func TestBuildManifestDigestIsIndependentOfInputOrder(t *testing.T) {
	t.Parallel()
	left, err := BuildManifest([]Entry{
		{Path: "dir/file", Type: EntryFile, Size: 5, ContentDigest: textDigest},
		{Path: "dir", Type: EntryDirectory},
	}, Limits{})
	if err != nil {
		t.Fatalf("BuildManifest(left) error = %v", err)
	}
	right, err := BuildManifest([]Entry{
		{Path: "dir", Type: EntryDirectory},
		{Path: "dir/file", Type: EntryFile, Size: 5, ContentDigest: textDigest},
	}, Limits{})
	if err != nil {
		t.Fatalf("BuildManifest(right) error = %v", err)
	}
	if left.RootDigest() != right.RootDigest() {
		t.Fatalf("root digests differ: %q != %q", left.RootDigest(), right.RootDigest())
	}
}

func TestBuildManifestRejectsUnsafeOrAmbiguousPaths(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		path string
	}{
		{name: "empty", path: ""},
		{name: "absolute", path: "/etc/passwd"},
		{name: "dot", path: "a/./b"},
		{name: "parent", path: "a/../b"},
		{name: "empty component", path: "a//b"},
		{name: "nul", path: "a\x00b"},
		{name: "component too long", path: strings.Repeat("a", 256)},
		{name: "path too long", path: strings.Repeat("a/", 2048) + "a"},
		{name: "invalid utf8", path: string([]byte{0xff})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := BuildManifest([]Entry{{Path: test.path, Type: EntryFile, ContentDigest: emptyDigest}}, Limits{})
			if !errors.Is(err, ErrInvalidPath) {
				t.Fatalf("BuildManifest(%q) error = %v, want ErrInvalidPath", test.path, err)
			}
		})
	}

	_, err := BuildManifest([]Entry{
		{Path: "é", Type: EntryFile, ContentDigest: emptyDigest},
		{Path: "e\u0301", Type: EntryFile, ContentDigest: emptyDigest},
	}, Limits{})
	if !errors.Is(err, ErrPathCollision) {
		t.Fatalf("NFC collision error = %v, want ErrPathCollision", err)
	}
}

func TestBuildManifestRejectsInvalidHierarchyAndEntryShapes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		entries []Entry
		want    error
	}{
		{name: "missing parent", entries: []Entry{{Path: "dir/file", Type: EntryFile, ContentDigest: emptyDigest}}, want: ErrInvalidHierarchy},
		{name: "file parent", entries: []Entry{{Path: "dir", Type: EntryFile, ContentDigest: emptyDigest}, {Path: "dir/file", Type: EntryFile, ContentDigest: emptyDigest}}, want: ErrInvalidHierarchy},
		{name: "unknown type", entries: []Entry{{Path: "x", Type: EntryType("fifo")}}, want: ErrInvalidEntry},
		{name: "file missing digest", entries: []Entry{{Path: "x", Type: EntryFile}}, want: ErrInvalidEntry},
		{name: "file target", entries: []Entry{{Path: "x", Type: EntryFile, ContentDigest: emptyDigest, SymlinkTarget: "y"}}, want: ErrInvalidEntry},
		{name: "directory payload", entries: []Entry{{Path: "x", Type: EntryDirectory, ContentDigest: emptyDigest}}, want: ErrInvalidEntry},
		{name: "symlink missing target", entries: []Entry{{Path: "x", Type: EntrySymlink}}, want: ErrInvalidSymlink},
		{name: "absolute symlink", entries: []Entry{{Path: "x", Type: EntrySymlink, SymlinkTarget: "/etc"}}, want: ErrInvalidSymlink},
		{name: "escaping symlink", entries: []Entry{{Path: "dir", Type: EntryDirectory}, {Path: "dir/x", Type: EntrySymlink, SymlinkTarget: "../../etc"}}, want: ErrInvalidSymlink},
		{name: "special mode", entries: []Entry{{Path: "x", Type: EntryFile, Mode: 0o100644, ContentDigest: emptyDigest}}, want: ErrInvalidEntry},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := BuildManifest(test.entries, Limits{})
			if !errors.Is(err, test.want) {
				t.Fatalf("BuildManifest() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestBuildManifestEnforcesEntryAndMetadataQuotas(t *testing.T) {
	t.Parallel()
	entries := []Entry{
		{Path: "a", Type: EntryFile, ContentDigest: emptyDigest},
		{Path: "b", Type: EntryFile, ContentDigest: emptyDigest},
	}
	if _, err := BuildManifest(entries, Limits{MaxEntries: 1, MaxMetadataBytes: 4096}); !errors.Is(err, ErrManifestTooLarge) {
		t.Fatalf("entry quota error = %v, want ErrManifestTooLarge", err)
	}
	if _, err := BuildManifest(entries, Limits{MaxEntries: 2, MaxMetadataBytes: 8}); !errors.Is(err, ErrManifestTooLarge) {
		t.Fatalf("metadata quota error = %v, want ErrManifestTooLarge", err)
	}
}

func TestDiffProducesCanonicalDeleteCreateAndUpdateMutations(t *testing.T) {
	t.Parallel()
	base, err := BuildManifest([]Entry{
		{Path: "old", Type: EntryFile, Size: 5, ContentDigest: textDigest},
		{Path: "same", Type: EntryFile, ContentDigest: emptyDigest},
		{Path: "updated", Type: EntryFile, ContentDigest: emptyDigest},
	}, Limits{})
	if err != nil {
		t.Fatalf("BuildManifest(base) error = %v", err)
	}
	next, err := BuildManifest([]Entry{
		{Path: "new", Type: EntryFile, Size: 5, ContentDigest: textDigest},
		{Path: "same", Type: EntryFile, ContentDigest: emptyDigest},
		{Path: "updated", Type: EntryFile, Mode: 0o755, ContentDigest: emptyDigest},
	}, Limits{})
	if err != nil {
		t.Fatalf("BuildManifest(next) error = %v", err)
	}

	mutations := Diff(base, next)
	if len(mutations) != 3 {
		t.Fatalf("Diff() = %#v, want 3 mutations", mutations)
	}
	if mutations[0].Kind != MutationCreate || mutations[0].Path != "new" || mutations[0].After == nil {
		t.Fatalf("mutation[0] = %#v", mutations[0])
	}
	if mutations[1].Kind != MutationDelete || mutations[1].Path != "old" || mutations[1].Before == nil {
		t.Fatalf("mutation[1] = %#v", mutations[1])
	}
	if mutations[2].Kind != MutationUpdate || mutations[2].Path != "updated" || mutations[2].Before == nil || mutations[2].After == nil {
		t.Fatalf("mutation[2] = %#v", mutations[2])
	}
	mutations[0].After.Path = "tampered"
	if Diff(base, next)[0].After.Path != "new" {
		t.Fatal("Diff result aliases a manifest entry")
	}
}

func TestBuildManifestIsSafeForConcurrentCallers(t *testing.T) {
	t.Parallel()
	entries := []Entry{{Path: "x", Type: EntryFile, ContentDigest: emptyDigest}}
	const callers = 64
	results := make(chan string, callers)
	errorsSeen := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			manifest, err := BuildManifest(entries, Limits{})
			if err == nil {
				results <- manifest.RootDigest()
			}
			errorsSeen <- err
		}()
	}
	wait.Wait()
	close(results)
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatalf("concurrent BuildManifest() error = %v", err)
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
