package manifest

import (
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// FuzzCanonicalizePathSafety feeds arbitrary newline-separated paths through
// Canonicalize and asserts its security guarantee directly: whatever it accepts,
// every output path is traversal-safe — relative, NUL-free, NFC-normalized,
// within bounds, and free of "", ".", and ".." components. It also asserts the
// output is bytewise path-sorted and that canonicalization is idempotent.
func FuzzCanonicalizePathSafety(f *testing.F) {
	seeds := []string{
		"a",
		"a\na/b",
		"dir\ndir/child",
		"café",
		"a\na/b\na/b/c",
		"/abs",
		"a/../b",
		"a//b",
		".",
		"..",
		"a/.",
		"a/..",
		"nul\x00path",
		strings.Repeat("x", 300),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		lines := strings.Split(raw, "\n")
		entries := make([]Entry, 0, len(lines))
		for _, candidate := range lines {
			entries = append(entries, Entry{Path: candidate, Type: Directory, Mode: 0o755})
		}

		out, err := Canonicalize(entries)
		if err != nil {
			return // rejection is always acceptable; the contract is "never panic".
		}
		for _, entry := range out {
			path := entry.Path
			if !utf8.ValidString(path) || path == "" || strings.HasPrefix(path, "/") ||
				strings.IndexByte(path, 0) >= 0 || len(path) > MaxPathBytes || norm.NFC.String(path) != path {
				t.Fatalf("Canonicalize produced an unsafe path: %q", path)
			}
			for _, component := range strings.Split(path, "/") {
				if component == "" || component == "." || component == ".." || len(component) > MaxComponentBytes {
					t.Fatalf("Canonicalize produced path %q with a forbidden component %q", path, component)
				}
			}
		}
		for i := 1; i < len(out); i++ {
			if out[i-1].Path > out[i].Path {
				t.Fatalf("Canonicalize output is not bytewise-sorted: %q before %q", out[i-1].Path, out[i].Path)
			}
		}
		again, err := Canonicalize(out)
		if err != nil {
			t.Fatalf("re-Canonicalize of a canonical manifest failed: %v", err)
		}
		if !reflect.DeepEqual(again, out) {
			t.Fatalf("Canonicalize is not idempotent:\n first: %#v\nsecond: %#v", out, again)
		}
	})
}
