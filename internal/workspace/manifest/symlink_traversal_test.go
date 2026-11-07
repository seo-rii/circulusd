package manifest

import (
	"fmt"
	"math/rand"
	"path"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// legacyValidateSymlinkTraversal is the per-link expansion walk that the
// memoized resolver replaced, kept (minus comments) as the differential oracle.
func legacyValidateSymlinkTraversal(entry Entry, kinds map[string]EntryType, symlinks map[string]string) error {
	directory := path.Dir(entry.Path)
	if directory == "." {
		directory = ""
	}
	pending := strings.Split(entry.SymlinkTarget, "/")
	expansions := 1
	for len(pending) > 0 {
		component := pending[0]
		pending = pending[1:]
		switch component {
		case "", ".":
			continue
		case "..":
			if directory == "" {
				return fmt.Errorf("%w: symlink %q target escapes through symlink traversal", ErrInvalidEntry, entry.Path)
			}
			if separator := strings.LastIndexByte(directory, '/'); separator >= 0 {
				directory = directory[:separator]
			} else {
				directory = ""
			}
			continue
		}
		candidate := component
		if directory != "" {
			candidate = directory + "/" + component
		}
		switch kinds[candidate] {
		case Symlink:
			expansions++
			if expansions > maxSymlinkExpansions {
				return fmt.Errorf("%w: symlink %q exceeds %d link expansions", ErrInvalidEntry, entry.Path, maxSymlinkExpansions)
			}
			pending = append(strings.Split(symlinks[candidate], "/"), pending...)
		case Directory:
			directory = candidate
		default:
			return nil
		}
	}
	return nil
}

func legacyValidateSymlinks(entries []Entry) error {
	kinds := make(map[string]EntryType, len(entries))
	symlinks := make(map[string]string)
	for _, entry := range entries {
		kinds[entry.Path] = entry.Type
		if entry.Type == Symlink {
			symlinks[entry.Path] = entry.SymlinkTarget
		}
	}
	for _, entry := range entries {
		if entry.Type == Symlink {
			if err := legacyValidateSymlinkTraversal(entry, kinds, symlinks); err != nil {
				return err
			}
		}
	}
	return nil
}

// randomTraversalManifest returns a canonical manifest (sorted, normalized,
// explicit parents) whose link targets all pass the per-entry checks
// unchanged, so the traversal stage alone decides whether it is accepted.
// Absolute, leading "./", and lexically escaping targets are rejected or
// rewritten before that stage and are covered by the per-entry tests.
func randomTraversalManifest(random *rand.Rand) []Entry {
	entries := []Entry{}
	var grow func(parent string, depth int)
	grow = func(parent string, depth int) {
		if parent != "" && random.Intn(2) == 0 {
			entries = append(entries, Entry{Path: parent + "/u", Type: Symlink, Mode: 0o777, SymlinkTarget: ".."})
		}
		for _, name := range []string{"a", "b", "c"} {
			entryPath := name
			if parent != "" {
				entryPath = parent + "/" + name
			}
			switch kind := random.Intn(8); {
			case kind == 0:
			case kind <= 3 && depth < 3:
				entries = append(entries, Entry{Path: entryPath, Type: Directory, Mode: 0o755})
				grow(entryPath, depth+1)
			case kind <= 5:
				entries = append(entries, Entry{Path: entryPath, Type: File, Mode: 0o644, ContentDigest: traversalEmptySHA256})
			default:
				entries = append(entries, Entry{Path: entryPath, Type: Symlink, Mode: 0o777})
			}
		}
	}
	grow("", 0)

	// A root-level chain long enough to straddle the expansion limit. Interior
	// dots and trailing slashes carry chained directories forward, and the last
	// link ends in a directory, a dangling name, or an escape through k/up.
	parts := []string{"a", "b", "c", "u", "..", ".", ""}
	if random.Intn(3) == 0 {
		entries = append(entries,
			Entry{Path: "k", Type: Directory, Mode: 0o755},
			Entry{Path: "k/up", Type: Symlink, Mode: 0o777, SymlinkTarget: ".."},
		)
		length := 34 + random.Intn(10)
		for index := 0; index < length; index++ {
			next := fmt.Sprintf("k%02d", index+1)
			target := []string{next, next + "/.", next + "/", "k/../" + next}[random.Intn(4)]
			if index+1 == length {
				target = []string{"k/up/..", "k/up/./..", "k/up", "k/up/k", "missing", ""}[random.Intn(6)]
			} else if random.Intn(16) == 0 {
				target = ""
			}
			entries = append(entries, Entry{Path: fmt.Sprintf("k%02d", index), Type: Symlink, Mode: 0o777, SymlinkTarget: target})
		}
		parts = append(parts, "k", "up", "k00", fmt.Sprintf("k%02d", random.Intn(length)), fmt.Sprintf("k%02d", random.Intn(length)))
	}

	for index := range entries {
		entry := &entries[index]
		if entry.Type != Symlink || entry.SymlinkTarget != "" {
			continue
		}
		for {
			components := make([]string, 1+random.Intn(6))
			for component := range components {
				components[component] = parts[random.Intn(len(parts))]
			}
			target := strings.Join(components, "/")
			resolved := path.Clean(path.Join(path.Dir(entry.Path), target))
			if target != "" && !strings.HasPrefix(target, "/") && !strings.HasPrefix(target, "./") &&
				resolved != ".." && !strings.HasPrefix(resolved, "../") {
				entry.SymlinkTarget = target
				break
			}
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries
}

const traversalEmptySHA256 = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func TestSymlinkTraversalMatchesLegacyExpansion(t *testing.T) {
	t.Parallel()

	outcomes := map[string]int{}
	for seed := int64(0); seed < 4_000; seed++ {
		random := rand.New(rand.NewSource(seed))
		entries := randomTraversalManifest(random)

		// Every link individually, resolved in a random order: memoized results
		// must not depend on which traversal reached a link first.
		kinds := make(map[string]EntryType, len(entries))
		symlinks := make(map[string]string)
		for _, entry := range entries {
			kinds[entry.Path] = entry.Type
			if entry.Type == Symlink {
				symlinks[entry.Path] = entry.SymlinkTarget
			}
		}
		traversal := newSymlinkTraversal(entries)
		for _, index := range random.Perm(len(entries)) {
			entry := entries[index]
			if entry.Type != Symlink {
				continue
			}
			want := "accepted"
			if err := legacyValidateSymlinkTraversal(entry, kinds, symlinks); err != nil && strings.Contains(err.Error(), "escapes") {
				want = "escape"
			} else if err != nil {
				want = "expansion limit"
			}
			got := map[linkState]string{
				linkDirectory: "accepted", linkTerminal: "accepted", linkEscapes: "escape", linkExceeds: "expansion limit",
			}[traversal.resolve(index+1)]
			if got != want {
				t.Fatalf("seed %d: link %q resolved as %q, legacy %q\nentries: %#v", seed, entry.Path, got, want, entries)
			}
			outcomes[want]++
			if traversal.nodes[index+1].expansions == maxSymlinkExpansions && want != "expansion limit" {
				outcomes[want+" at the limit"]++
			}
		}

		// The whole manifest: same first error, or the same canonical output.
		want := legacyValidateSymlinks(entries)
		canonical, err := Canonicalize(entries)
		if fmt.Sprint(err) != fmt.Sprint(want) {
			t.Fatalf("seed %d: Canonicalize() error = %v, legacy = %v\nentries: %#v", seed, err, want, entries)
		}
		if err == nil && !reflect.DeepEqual(canonical, entries) {
			t.Fatalf("seed %d: Canonicalize() changed a canonical manifest", seed)
		}
	}
	t.Logf("per-link outcomes: %v", outcomes)
	for _, outcome := range []string{"accepted", "escape", "expansion limit", "accepted at the limit", "escape at the limit"} {
		if outcomes[outcome] < 10 {
			t.Fatalf("differential corpus is unbalanced: %v", outcomes)
		}
	}
}

// TestSymlinkTraversalWorkIsLinear covers manifests for which the legacy walk
// was super-linear: every link re-expanded (and prepend-copied) a long shared
// chain, and every component lookup rebuilt a long directory path. The
// resolver fails closed once it reads more target components than the
// manifest contains, so acceptance proves each component was read at most
// once.
func TestSymlinkTraversalWorkIsLinear(t *testing.T) {
	t.Parallel()

	const chain = 38
	padding := strings.Repeat("/.", 2000)
	shared := make([]Entry, 0, chain+20_000)
	for index := 0; index < chain; index++ {
		shared = append(shared, Entry{
			Path: fmt.Sprintf("c%02d", index), Type: Symlink, SymlinkTarget: fmt.Sprintf("c%02d%s", index+1, padding),
		})
	}
	for index := 0; index < 20_000; index++ {
		shared = append(shared, Entry{Path: fmt.Sprintf("e%05d", index), Type: Symlink, SymlinkTarget: "c00"})
	}

	deep := strings.TrimPrefix(strings.Repeat("/"+strings.Repeat("d", 250), 15), "/")
	long := []Entry{{Path: deep + "/x", Type: Directory}}
	for depth := len(deep); depth > 0; depth = strings.LastIndexByte(deep[:depth], '/') {
		long = append(long, Entry{Path: deep[:depth], Type: Directory})
	}
	bounce := strings.Repeat("x/../", (MaxPathBytes-1)/len("x/../")) + "x"
	for index := 0; index < 1_000; index++ {
		long = append(long, Entry{Path: fmt.Sprintf("%s/l%04d", deep, index), Type: Symlink, SymlinkTarget: bounce})
	}

	for name, entries := range map[string][]Entry{"shared chain": shared, "long directory": long} {
		if _, err := Canonicalize(entries); err != nil {
			t.Fatalf("%s: Canonicalize() error = %v", name, err)
		}
	}
}
