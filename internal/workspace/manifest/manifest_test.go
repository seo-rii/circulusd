package manifest_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/hancomac/circulusd/internal/workspace/manifest"
)

const (
	emptySHA256 = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	abcSHA256   = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
)

func TestCanonicalizeNormalizesSortsAndDoesNotMutateInput(t *testing.T) {
	t.Parallel()

	input := []manifest.Entry{
		{
			Path:          "docs/cafe\u0301.txt",
			Type:          manifest.File,
			Mode:          0o644,
			Size:          0,
			ContentDigest: emptySHA256,
		},
		{Path: "docs", Type: manifest.Directory, Mode: 0o755},
		{
			Path:          "docs/latest",
			Type:          manifest.Symlink,
			Mode:          0o777,
			SymlinkTarget: "./cafe\u0301.txt",
		},
	}

	got, err := manifest.Canonicalize(input)
	if err != nil {
		t.Fatalf("Canonicalize() error = %v", err)
	}

	want := []manifest.Entry{
		{Path: "docs", Type: manifest.Directory, Mode: 0o755},
		{
			Path:          "docs/caf\u00e9.txt",
			Type:          manifest.File,
			Mode:          0o644,
			Size:          0,
			ContentDigest: emptySHA256,
		},
		{
			Path:          "docs/latest",
			Type:          manifest.Symlink,
			Mode:          0o777,
			SymlinkTarget: "caf\u00e9.txt",
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Canonicalize() = %#v, want %#v", got, want)
	}

	if input[0].Path != "docs/cafe\u0301.txt" {
		t.Fatalf("Canonicalize() mutated input path to %q", input[0].Path)
	}
	if input[2].SymlinkTarget != "./cafe\u0301.txt" {
		t.Fatalf("Canonicalize() mutated input symlink target to %q", input[2].SymlinkTarget)
	}
}

func TestCanonicalizeRejectsInvalidPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
	}{
		{name: "empty", path: ""},
		{name: "absolute", path: "/etc/passwd"},
		{name: "dot", path: "."},
		{name: "dot component", path: "a/./b"},
		{name: "dotdot", path: ".."},
		{name: "dotdot component", path: "a/../b"},
		{name: "empty component", path: "a//b"},
		{name: "trailing slash", path: "a/"},
		{name: "nul", path: "a\x00b"},
		{name: "invalid utf8", path: string([]byte{'a', 0xff})},
		{name: "component too long", path: strings.Repeat("a", manifest.MaxComponentBytes+1)},
		{
			name: "component too long after NFC",
			path: strings.Repeat("e\u0301", 128),
		},
		{
			name: "path too long",
			path: strings.Repeat(strings.Repeat("a", 255)+"/", 16) + "a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := manifest.Canonicalize([]manifest.Entry{
				{Path: tt.path, Type: manifest.Directory, Mode: 0o755},
			})
			if !errors.Is(err, manifest.ErrInvalidPath) {
				t.Fatalf("Canonicalize() error = %v, want ErrInvalidPath", err)
			}
		})
	}
}

func TestCanonicalizeRejectsPostNormalizationCollision(t *testing.T) {
	t.Parallel()

	_, err := manifest.Canonicalize([]manifest.Entry{
		{Path: "caf\u00e9", Type: manifest.Directory, Mode: 0o755},
		{Path: "cafe\u0301", Type: manifest.Directory, Mode: 0o755},
	})
	if !errors.Is(err, manifest.ErrPathCollision) {
		t.Fatalf("Canonicalize() error = %v, want ErrPathCollision", err)
	}
}

func TestCanonicalizeIsCaseSensitive(t *testing.T) {
	t.Parallel()

	got, err := manifest.Canonicalize([]manifest.Entry{
		{Path: "Readme", Type: manifest.File, Mode: 0o644, Size: 0, ContentDigest: emptySHA256},
		{Path: "README", Type: manifest.File, Mode: 0o644, Size: 0, ContentDigest: emptySHA256},
	})
	if err != nil {
		t.Fatalf("Canonicalize() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("Canonicalize() returned %d entries, want 2", len(got))
	}
}

func TestCanonicalizeValidatesEntryMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		entry manifest.Entry
	}{
		{
			name:  "unsupported type",
			entry: manifest.Entry{Path: "x", Type: manifest.EntryType("device"), Mode: 0o600},
		},
		{
			name:  "mode contains setuid",
			entry: manifest.Entry{Path: "x", Type: manifest.File, Mode: 0o4755, Size: 0, ContentDigest: emptySHA256},
		},
		{
			name:  "file negative size",
			entry: manifest.Entry{Path: "x", Type: manifest.File, Mode: 0o644, Size: -1, ContentDigest: emptySHA256},
		},
		{
			name:  "file missing digest",
			entry: manifest.Entry{Path: "x", Type: manifest.File, Mode: 0o644, Size: 0},
		},
		{
			name:  "file uppercase digest",
			entry: manifest.Entry{Path: "x", Type: manifest.File, Mode: 0o644, Size: 0, ContentDigest: "sha256:E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"},
		},
		{
			name:  "file malformed digest",
			entry: manifest.Entry{Path: "x", Type: manifest.File, Mode: 0o644, Size: 0, ContentDigest: "sha256:not-a-digest"},
		},
		{
			name: "file has symlink target",
			entry: manifest.Entry{
				Path: "x", Type: manifest.File, Mode: 0o644, Size: 0,
				ContentDigest: emptySHA256, SymlinkTarget: "y",
			},
		},
		{
			name:  "directory has size",
			entry: manifest.Entry{Path: "x", Type: manifest.Directory, Mode: 0o755, Size: 1},
		},
		{
			name:  "directory has digest",
			entry: manifest.Entry{Path: "x", Type: manifest.Directory, Mode: 0o755, ContentDigest: emptySHA256},
		},
		{
			name:  "directory has symlink target",
			entry: manifest.Entry{Path: "x", Type: manifest.Directory, Mode: 0o755, SymlinkTarget: "y"},
		},
		{
			name:  "symlink has size",
			entry: manifest.Entry{Path: "x", Type: manifest.Symlink, Mode: 0o777, Size: 1, SymlinkTarget: "y"},
		},
		{
			name:  "symlink has digest",
			entry: manifest.Entry{Path: "x", Type: manifest.Symlink, Mode: 0o777, ContentDigest: emptySHA256, SymlinkTarget: "y"},
		},
		{
			name:  "symlink missing target",
			entry: manifest.Entry{Path: "x", Type: manifest.Symlink, Mode: 0o777},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := manifest.Canonicalize([]manifest.Entry{tt.entry})
			if !errors.Is(err, manifest.ErrInvalidEntry) {
				t.Fatalf("Canonicalize() error = %v, want ErrInvalidEntry", err)
			}
		})
	}
}

func TestCanonicalizeNormalizesPortableModes(t *testing.T) {
	t.Parallel()

	got, err := manifest.Canonicalize([]manifest.Entry{
		{Path: "data", Type: manifest.Directory, Mode: 0o700},
		{Path: "data/plain", Type: manifest.File, Mode: 0o600, Size: 0, ContentDigest: emptySHA256},
		{Path: "data/run", Type: manifest.File, Mode: 0o710, Size: 0, ContentDigest: emptySHA256},
		{Path: "data/link", Type: manifest.Symlink, Mode: 0o700, SymlinkTarget: "plain"},
	})
	if err != nil {
		t.Fatalf("Canonicalize() error = %v", err)
	}
	modes := map[string]uint32{}
	for _, entry := range got {
		modes[entry.Path] = entry.Mode
	}
	if modes["data"] != 0o755 || modes["data/plain"] != 0o644 ||
		modes["data/run"] != 0o755 || modes["data/link"] != 0o777 {
		t.Fatalf("canonical modes = %#v", modes)
	}
}

func TestCanonicalizeValidatesFlatTreeSemantics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		entries []manifest.Entry
	}{
		{
			name: "missing parent directory",
			entries: []manifest.Entry{
				{Path: "a/file", Type: manifest.File, Mode: 0o644, Size: 0, ContentDigest: emptySHA256},
			},
		},
		{
			name: "file parent",
			entries: []manifest.Entry{
				{Path: "a", Type: manifest.File, Mode: 0o644, Size: 0, ContentDigest: emptySHA256},
				{Path: "a/file", Type: manifest.File, Mode: 0o644, Size: 0, ContentDigest: emptySHA256},
			},
		},
		{
			name: "symlink parent",
			entries: []manifest.Entry{
				{Path: "a", Type: manifest.Symlink, Mode: 0o777, SymlinkTarget: "target"},
				{Path: "a/file", Type: manifest.File, Mode: 0o644, Size: 0, ContentDigest: emptySHA256},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := manifest.Canonicalize(tt.entries)
			if !errors.Is(err, manifest.ErrInvalidTree) {
				t.Fatalf("Canonicalize() error = %v, want ErrInvalidTree", err)
			}
		})
	}

	valid := []manifest.Entry{
		{Path: "a/b/file", Type: manifest.File, Mode: 0o644, Size: 3, ContentDigest: abcSHA256},
		{Path: "a", Type: manifest.Directory, Mode: 0o755},
		{Path: "a/b", Type: manifest.Directory, Mode: 0o755},
	}
	if err := manifest.Validate(valid); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if err := manifest.Validate(nil); err != nil {
		t.Fatalf("Validate(empty) error = %v", err)
	}
}

func TestCanonicalizeValidatesSafeRelativeSymlinks(t *testing.T) {
	t.Parallel()

	valid := []manifest.Entry{
		{Path: "target", Type: manifest.File, Mode: 0o644, Size: 0, ContentDigest: emptySHA256},
		{Path: "dir", Type: manifest.Directory, Mode: 0o755},
		{Path: "dir/deep", Type: manifest.Directory, Mode: 0o755},
		{Path: "dir/deep/link", Type: manifest.Symlink, Mode: 0o777, SymlinkTarget: "../../target"},
	}
	got, err := manifest.Canonicalize(valid)
	if err != nil {
		t.Fatalf("Canonicalize(valid symlink) error = %v", err)
	}
	if got[2].Path != "dir/deep/link" || got[2].SymlinkTarget != "../../target" {
		t.Fatalf("Canonicalize(valid symlink) = %#v", got[2])
	}

	tests := []struct {
		name   string
		path   string
		target string
	}{
		{name: "absolute", path: "link", target: "/etc/passwd"},
		{name: "escapes top level", path: "link", target: "../outside"},
		{name: "escapes nested directory", path: "dir/link", target: "../../outside"},
		{name: "empty", path: "link", target: ""},
		{name: "nul", path: "link", target: "a\x00b"},
		{name: "invalid utf8", path: "link", target: string([]byte{'a', 0xff})},
		{
			name:   "oversized before cleaning",
			path:   "link",
			target: strings.Repeat("a/../", manifest.MaxPathBytes/5+1) + "target",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			entries := []manifest.Entry{
				{Path: tt.path, Type: manifest.Symlink, Mode: 0o777, SymlinkTarget: tt.target},
			}
			if strings.Contains(tt.path, "/") {
				entries = append(entries, manifest.Entry{Path: "dir", Type: manifest.Directory, Mode: 0o755})
			}
			_, err := manifest.Canonicalize(entries)
			if !errors.Is(err, manifest.ErrInvalidEntry) {
				t.Fatalf("Canonicalize() error = %v, want ErrInvalidEntry", err)
			}
		})
	}
}

func TestMarshalCanonicalIsDeterministicRFC8949CBOR(t *testing.T) {
	t.Parallel()

	forward := []manifest.Entry{
		{Path: "bin", Type: manifest.Directory, Mode: 0o755},
		{Path: "bin/run", Type: manifest.File, Mode: 0o755, Size: 3, ContentDigest: abcSHA256},
	}
	reverse := []manifest.Entry{forward[1], forward[0]}

	gotForward, err := manifest.MarshalCanonical(forward)
	if err != nil {
		t.Fatalf("MarshalCanonical(forward) error = %v", err)
	}
	gotReverse, err := manifest.MarshalCanonical(reverse)
	if err != nil {
		t.Fatalf("MarshalCanonical(reverse) error = %v", err)
	}
	if !bytes.Equal(gotForward, gotReverse) {
		t.Fatalf("MarshalCanonical() depends on input order:\nforward %x\nreverse %x", gotForward, gotReverse)
	}

	// Schema v1 is [version, entries]. Each entry is
	// [path, type-code, mode, size-or-null, content-digest-or-null,
	// symlink-target-or-null]. Integers and lengths use shortest-form CBOR.
	wantHex := "820182" +
		"866362696e011901edf6f6f6" +
		"866762696e2f72756e001901ed03" +
		"7847" + "7368613235363a62613738313662663866303163666561343134313430646535646165323232336230303336316133393631373761396362343130666636316632303031356164" +
		"f6"
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatalf("decode CBOR golden: %v", err)
	}
	if !bytes.Equal(gotForward, want) {
		t.Fatalf("MarshalCanonical() = %x, want %x", gotForward, want)
	}
}

func TestRootDigestUsesDomainSeparatedSHA256(t *testing.T) {
	t.Parallel()

	entries := []manifest.Entry{
		{Path: "bin", Type: manifest.Directory, Mode: 0o755},
		{Path: "bin/run", Type: manifest.File, Mode: 0o755, Size: 3, ContentDigest: abcSHA256},
	}

	got, err := manifest.RootDigest(entries)
	if err != nil {
		t.Fatalf("RootDigest() error = %v", err)
	}
	// This golden is independently generated by the TypeScript RFC 8949
	// implementation from the common ADR-006 structured hash envelope.
	const want = "sha256:124c2e2b4ea7d7aa7c1ac7d422d2775bd221eb4bf98b3de7d16987f61d3295bd"
	if got != want {
		t.Fatalf("RootDigest() = %q, want %q", got, want)
	}

	changed := append([]manifest.Entry(nil), entries...)
	changed[1].Mode = 0o644
	changedDigest, err := manifest.RootDigest(changed)
	if err != nil {
		t.Fatalf("RootDigest(changed) error = %v", err)
	}
	if changedDigest == got {
		t.Fatal("RootDigest() did not change when canonical metadata changed")
	}
}

func TestCanonicalOperationsAreSafeForConcurrentUse(t *testing.T) {
	entries := []manifest.Entry{
		{Path: "data", Type: manifest.Directory, Mode: 0o755},
		{Path: "data/file", Type: manifest.File, Mode: 0o644, Size: 0, ContentDigest: emptySHA256},
	}

	const workers = 32
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := manifest.MarshalCanonical(entries); err != nil {
				errs <- err
				return
			}
			if _, err := manifest.RootDigest(entries); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent canonical operation error = %v", err)
	}
}
