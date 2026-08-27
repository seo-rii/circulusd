package workspace_test

import (
	"errors"
	"testing"

	"github.com/hancomac/circulusd/internal/workspace"
	wiremanifest "github.com/hancomac/circulusd/internal/workspace/manifest"
)

const compatibilityDigest = "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

func TestWorkspaceManifestFacadesShareCanonicalDigest(t *testing.T) {
	t.Parallel()

	entries := []workspace.Entry{
		{Path: "src", Type: workspace.EntryDirectory},
		{Path: "src/e\u0301.txt", Type: workspace.EntryFile, Mode: 0o600, Size: 5, ContentDigest: compatibilityDigest},
		{Path: "latest", Type: workspace.EntrySymlink, SymlinkTarget: "src/é.txt"},
	}
	rootManifest, err := workspace.BuildManifest(entries, workspace.Limits{})
	if err != nil {
		t.Fatalf("workspace.BuildManifest() error = %v", err)
	}
	wireDigest, err := wiremanifest.RootDigest([]wiremanifest.Entry{
		{Path: "src", Type: wiremanifest.Directory},
		{Path: "src/e\u0301.txt", Type: wiremanifest.File, Mode: 0o600, Size: 5, ContentDigest: compatibilityDigest},
		{Path: "latest", Type: wiremanifest.Symlink, SymlinkTarget: "src/é.txt"},
	})
	if err != nil {
		t.Fatalf("wiremanifest.RootDigest() error = %v", err)
	}
	if rootManifest.RootDigest() != wireDigest {
		t.Fatalf("root digest = %q, wire digest = %q", rootManifest.RootDigest(), wireDigest)
	}
}

func TestWireManifestRejectsControlCharactersLikeWorkspaceFacade(t *testing.T) {
	t.Parallel()

	_, err := wiremanifest.Canonicalize([]wiremanifest.Entry{{
		Path:          "line\nbreak",
		Type:          wiremanifest.File,
		ContentDigest: compatibilityDigest,
	}})
	if !errors.Is(err, wiremanifest.ErrInvalidPath) {
		t.Fatalf("Canonicalize(control path) error = %v, want ErrInvalidPath", err)
	}
}
