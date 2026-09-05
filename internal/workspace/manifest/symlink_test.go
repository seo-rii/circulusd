package manifest_test

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/hancomac/circulusd/internal/workspace/manifest"
)

func TestCanonicalizePreservesSymlinkTargetComponents(t *testing.T) {
	for _, target := range []string{"link/../file", "missing/../file", "file/.", "file/", "file/../file", "dir//nested/../file"} {
		t.Run(target, func(t *testing.T) {
			entries := []manifest.Entry{
				{Path: "dir", Type: manifest.Directory},
				{Path: "dir/nested", Type: manifest.Directory},
				{Path: "file", Type: manifest.File, ContentDigest: emptySHA256},
				{Path: "dir/file", Type: manifest.File, ContentDigest: emptySHA256},
				{Path: "link", Type: manifest.Symlink, SymlinkTarget: "dir/nested"},
				{Path: "alias", Type: manifest.Symlink, SymlinkTarget: target},
			}
			canonical, err := manifest.Canonicalize(entries)
			if err != nil {
				t.Fatal(err)
			}
			if canonical[0].Path != "alias" || canonical[0].SymlinkTarget != target {
				t.Fatalf("target components changed: %q, want %q", canonical[0].SymlinkTarget, target)
			}
			again, err := manifest.Canonicalize(canonical)
			if err != nil || !reflect.DeepEqual(again, canonical) {
				t.Fatalf("symlink canonicalization is not idempotent: %v", err)
			}
		})
	}
}

func TestCanonicalizeRejectsIndirectSymlinkEscape(t *testing.T) {
	for _, target := range []string{"dir/up/../outside", "other/../outside"} {
		entries := []manifest.Entry{
			{Path: "dir", Type: manifest.Directory},
			{Path: "dir/up", Type: manifest.Symlink, SymlinkTarget: ".."},
			{Path: "other", Type: manifest.Symlink, SymlinkTarget: "dir/up"},
			{Path: "escape", Type: manifest.Symlink, SymlinkTarget: target},
		}
		if _, err := manifest.Canonicalize(entries); !errors.Is(err, manifest.ErrInvalidEntry) {
			t.Fatalf("accepted indirect escape %q: %v", target, err)
		}
	}
}

func TestCanonicalizeBoundsSymlinkExpansion(t *testing.T) {
	for _, count := range []int{40, 41} {
		entries := []manifest.Entry{{Path: "file", Type: manifest.File, ContentDigest: emptySHA256}}
		for index := 0; index < count; index++ {
			target := "file"
			if index+1 < count {
				target = fmt.Sprintf("link%02d", index+1)
			}
			entries = append(entries, manifest.Entry{
				Path: fmt.Sprintf("link%02d", index), Type: manifest.Symlink, SymlinkTarget: target,
			})
		}
		_, err := manifest.Canonicalize(entries)
		if count == 40 && err != nil {
			t.Fatalf("bounded link chain was rejected: %v", err)
		}
		if count == 41 && !errors.Is(err, manifest.ErrInvalidEntry) {
			t.Fatalf("unbounded link chain was accepted: %v", err)
		}
	}
	if _, err := manifest.Canonicalize([]manifest.Entry{
		{Path: "a", Type: manifest.Symlink, SymlinkTarget: "b"},
		{Path: "b", Type: manifest.Symlink, SymlinkTarget: "a"},
	}); !errors.Is(err, manifest.ErrInvalidEntry) {
		t.Fatalf("symlink cycle was accepted: %v", err)
	}
}
