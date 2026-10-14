package workspace

import (
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"

	"github.com/hancomac/circulusd/internal/canonical"
	wiremanifest "github.com/hancomac/circulusd/internal/workspace/manifest"
)

// buildManifestByComposition is the previous BuildManifest body. It
// canonicalized the input three times (Canonicalize, MarshalCanonical and
// RootDigest) and is kept as the oracle for the single-pass build.
func buildManifestByComposition(input []Entry, limits Limits) (Manifest, error) {
	if limits.MaxEntries < 0 || limits.MaxMetadataBytes < 0 {
		return Manifest{}, fmt.Errorf("%w: limits cannot be negative", ErrManifestTooLarge)
	}
	if limits.MaxEntries == 0 {
		limits.MaxEntries = defaultMaximumEntries
	}
	if limits.MaxMetadataBytes == 0 {
		limits.MaxMetadataBytes = defaultMaximumMetadataBytes
	}
	if len(input) > limits.MaxEntries {
		return Manifest{}, fmt.Errorf("%w: got %d entries, limit %d", ErrManifestTooLarge, len(input), limits.MaxEntries)
	}
	entries, err := wiremanifest.Canonicalize(input)
	if err != nil {
		return Manifest{}, err
	}
	encoded, err := wiremanifest.MarshalCanonical(entries)
	if err != nil {
		if errors.Is(err, canonical.ErrLimitExceeded) {
			return Manifest{}, fmt.Errorf("%w: metadata limit %d bytes", ErrManifestTooLarge, limits.MaxMetadataBytes)
		}
		return Manifest{}, fmt.Errorf("encode workspace manifest: %w", err)
	}
	if len(encoded) > limits.MaxMetadataBytes {
		return Manifest{}, fmt.Errorf("%w: metadata is %d bytes; limit %d", ErrManifestTooLarge, len(encoded), limits.MaxMetadataBytes)
	}
	rootDigest, err := wiremanifest.RootDigest(entries)
	if err != nil {
		return Manifest{}, fmt.Errorf("digest workspace manifest: %w", err)
	}
	return Manifest{entries: entries, rootDigest: rootDigest, metadataBytes: len(encoded)}, nil
}

func TestBuildManifestMatchesComposedCanonicalization(t *testing.T) {
	t.Parallel()
	type buildCase struct {
		name    string
		entries []Entry
		limits  Limits
	}
	cases := []buildCase{
		{name: "empty"},
		{name: "nfc and modes", entries: []Entry{
			{Path: "src/é.txt", Type: EntryFile, Mode: 0o600, Size: 5, ContentDigest: textDigest},
			{Path: "src", Type: EntryDirectory, Mode: 0o700},
			{Path: "run", Type: EntryFile, Mode: 0o711, ContentDigest: emptyDigest},
			{Path: "latest", Type: EntrySymlink, Mode: 0o700, SymlinkTarget: "src/é.txt"},
		}},
		{name: "path collision", entries: []Entry{
			{Path: "é", Type: EntryFile, ContentDigest: emptyDigest},
			{Path: "é", Type: EntryFile, ContentDigest: emptyDigest},
		}},
		{name: "missing parent", entries: []Entry{{Path: "a/b", Type: EntryFile, ContentDigest: emptyDigest}}},
		{name: "escaping symlink", entries: []Entry{{Path: "up", Type: EntrySymlink, SymlinkTarget: "../outside"}}},
		{name: "entry quota", entries: []Entry{
			{Path: "a", Type: EntryFile, ContentDigest: emptyDigest},
			{Path: "b", Type: EntryFile, ContentDigest: emptyDigest},
		}, limits: Limits{MaxEntries: 1}},
		{name: "metadata quota", entries: []Entry{
			{Path: "a", Type: EntryFile, ContentDigest: emptyDigest},
		}, limits: Limits{MaxMetadataBytes: 8}},
		{name: "negative limit", limits: Limits{MaxEntries: -1}},
	}
	random := rand.New(rand.NewSource(1))
	for index := range 500 {
		entries := randomManifestEntries(random)
		limits := Limits{}
		if index%7 == 0 {
			limits.MaxMetadataBytes = 64 + random.Intn(512)
		}
		cases = append(cases, buildCase{name: fmt.Sprintf("random-%d", index), entries: entries, limits: limits})
	}

	outcomes := make(map[bool]int)
	for _, test := range cases {
		want, wantErr := buildManifestByComposition(test.entries, test.limits)
		got, gotErr := BuildManifest(test.entries, test.limits)
		outcomes[gotErr == nil]++
		if (gotErr == nil) != (wantErr == nil) || (gotErr != nil && gotErr.Error() != wantErr.Error()) {
			t.Fatalf("%s: BuildManifest() error = %v, want %v", test.name, gotErr, wantErr)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: BuildManifest() = %#v, want %#v", test.name, got, want)
		}
	}
	if outcomes[true] < 50 || outcomes[false] < 50 {
		t.Fatalf("cases exercised %d successes and %d failures, want both", outcomes[true], outcomes[false])
	}
}

// randomManifestEntries builds a small tree of directories, files and
// symlinks in random order. Some trees contain a defect so both success and
// failure paths are compared.
func randomManifestEntries(random *rand.Rand) []Entry {
	directories := []string{""}
	var entries []Entry
	names := []string{"a", "b", "é", "é", "src", "lib", "x.txt"}
	for range 1 + random.Intn(24) {
		parent := directories[random.Intn(len(directories))]
		name := names[random.Intn(len(names))] + fmt.Sprint(random.Intn(4))
		path := name
		if parent != "" {
			path = parent + "/" + name
		}
		switch random.Intn(4) {
		case 0:
			entries = append(entries, Entry{Path: path, Type: EntryDirectory, Mode: uint32(random.Intn(0o1000))})
			directories = append(directories, path)
		case 1, 2:
			entries = append(entries, Entry{Path: path, Type: EntryFile, Mode: uint32(random.Intn(0o1000)), Size: int64(random.Intn(1 << 20)), ContentDigest: textDigest})
		default:
			targets := []string{"a0", "../a0", "src1/x.txt2", "..", "missing", strings.Repeat("../", random.Intn(3)) + "b1"}
			entries = append(entries, Entry{Path: path, Type: EntrySymlink, SymlinkTarget: targets[random.Intn(len(targets))]})
		}
	}
	switch random.Intn(6) {
	case 0:
		entries = append(entries, Entry{Path: "orphan/child", Type: EntryFile, ContentDigest: emptyDigest})
	case 1:
		entries = append(entries, Entry{Path: "bad\x01name", Type: EntryFile, ContentDigest: emptyDigest})
	}
	random.Shuffle(len(entries), func(left, right int) { entries[left], entries[right] = entries[right], entries[left] })
	return entries
}

func BenchmarkBuildManifest(b *testing.B) {
	entries := make([]Entry, 0, 20_000)
	for directory := range 1_000 {
		parent := fmt.Sprintf("dir-%04d", directory)
		entries = append(entries, Entry{Path: parent, Type: EntryDirectory})
		for file := range 18 {
			entries = append(entries, Entry{Path: fmt.Sprintf("%s/file-%02d.txt", parent, file), Type: EntryFile, Size: 5, ContentDigest: textDigest})
		}
		entries = append(entries, Entry{Path: parent + "/link", Type: EntrySymlink, SymlinkTarget: "file-00.txt"})
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := BuildManifest(entries, Limits{}); err != nil {
			b.Fatal(err)
		}
	}
}
