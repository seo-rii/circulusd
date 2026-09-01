package workerd

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newShortResourceFixtureDirectory(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("", "q-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if len(directory) > maximumResourceQualificationFixtureDirectoryBytes {
		t.Skipf("temporary directory %q exceeds the fixed argv bound", directory)
	}
	return directory
}

func TestMaterializeResourceQualificationFixtureBindsDigestsAndSocket(t *testing.T) {
	t.Parallel()
	directory := newShortResourceFixtureDirectory(t)
	rendering, err := materializeResourceQualificationFixture(directory, "workerd 1.20260825.1")
	if err != nil {
		t.Fatalf("materializeResourceQualificationFixture() error = %v", err)
	}
	if rendering.Directory != directory ||
		rendering.SocketPath != filepath.Join(directory, "qualification.sock") ||
		rendering.ConfigPath != filepath.Join(directory, "phase0-resource.capnp") {
		t.Fatalf("rendering paths = %+v, want directory-derived socket and configuration", rendering)
	}

	hostTemplate, err := resourceFixtureFiles.ReadFile("fixture/session-host-resource.mjs")
	if err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("sha256:%x", sha256.Sum256(hostTemplate)); rendering.ArtifactDigest != want {
		t.Fatalf("artifact digest = %q, want the unrendered SessionHost source digest %q", rendering.ArtifactDigest, want)
	}
	renderedConfig, err := os.ReadFile(rendering.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("sha256:%x", sha256.Sum256(renderedConfig)); rendering.ConfigDigest != want {
		t.Fatalf("config digest = %q, want the rendered configuration digest %q", rendering.ConfigDigest, want)
	}
	if !bytes.Contains(renderedConfig, []byte("unix:"+rendering.SocketPath)) {
		t.Fatalf("rendered configuration does not bind the private socket %q", rendering.SocketPath)
	}
	if !bytes.Contains(renderedConfig, []byte(`compatibilityDate = "`+resourceQualificationCompatibilityDate+`"`)) {
		t.Fatal("rendered configuration does not pin the compiled compatibility date")
	}

	renderedHost, err := os.ReadFile(filepath.Join(directory, "session-host-resource.mjs"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte(`artifactDigest: "` + rendering.ArtifactDigest + `"`),
		[]byte(`configDigest: "` + rendering.ConfigDigest + `"`),
		[]byte(`workerdRelease: "workerd 1.20260825.1"`),
	} {
		if !bytes.Contains(renderedHost, required) {
			t.Errorf("rendered session host does not contain %q", required)
		}
	}
	for _, name := range []string{"phase0-resource-entry.mjs", "pi-worker.mjs"} {
		contents, readErr := os.ReadFile(filepath.Join(directory, name))
		if readErr != nil {
			t.Fatalf("materialized %s: %v", name, readErr)
		}
		if bytes.Contains(contents, []byte("@COMPATIBILITY_")) {
			t.Fatalf("%s carries an unexpected placeholder", name)
		}
	}
	worker, err := fixtureFiles.ReadFile("fixture/pi-worker.mjs")
	if err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("sha256:%x", sha256.Sum256(worker)); rendering.WorkerDigest != want {
		t.Fatalf("worker digest = %q, want pinned bundle digest %q", rendering.WorkerDigest, want)
	}
}

func TestMaterializeResourceQualificationFixtureRejectsInvalidInputs(t *testing.T) {
	t.Parallel()
	directory := newShortResourceFixtureDirectory(t)
	for name, request := range map[string]struct {
		directory string
		release   string
		wantErr   error
	}{
		"relative directory": {directory: "relative", release: "workerd 1.20260825.1", wantErr: errInvalidResourceQualificationFixture},
		"oversized directory": {
			directory: "/" + strings.Repeat("d", maximumResourceQualificationFixtureDirectoryBytes),
			release:   "workerd 1.20260825.1",
			wantErr:   errInvalidResourceQualificationFixture,
		},
		"empty release":     {directory: directory, release: "", wantErr: errResourceFixtureMaterialization},
		"multiline release": {directory: directory, release: "workerd\n1", wantErr: errResourceFixtureMaterialization},
		"quoting release":   {directory: directory, release: `workerd"1`, wantErr: errResourceFixtureMaterialization},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := materializeResourceQualificationFixture(request.directory, request.release); !errors.Is(err, request.wantErr) {
				t.Fatalf("materializeResourceQualificationFixture(%s) error = %v, want %v", name, err, request.wantErr)
			}
		})
	}
}

func TestResourceFixtureCarriesBoundedProbeSurfaceOnly(t *testing.T) {
	t.Parallel()
	host, err := resourceFixtureFiles.ReadFile("fixture/session-host-resource.mjs")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte("const NONCE_PATTERN = /^[0-9a-f]{32}$/"),
		[]byte("const WORKER_PATTERN = "),
		[]byte(`path === "/ready"`),
		[]byte(`path === "/worker/spin"`),
		[]byte(`path === "/worker/state-load"`),
		[]byte(`path === "/allocate"`),
		[]byte("export default"),
		[]byte(`mainModule: "phase0-resource-entry.js"`),
	} {
		if !bytes.Contains(host, required) {
			t.Errorf("resource session host does not contain %q", required)
		}
	}
	if bytes.Contains(host, []byte("export const")) {
		t.Error("resource session host exposes workerd-test entrypoints; it must stay serve-only")
	}
	entry, err := resourceFixtureFiles.ReadFile("fixture/phase0-resource-entry.mjs")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte(`import worker from "./pi-worker.js"`),
		[]byte("let initializationInstance = null"),
		[]byte("if (initializationInstance === null)"),
		[]byte("for (;;)"),
		[]byte(`path === "/state-init"`),
		[]byte(`path === "/state-load"`),
	} {
		if !bytes.Contains(entry, required) {
			t.Errorf("resource worker entry does not contain %q", required)
		}
	}
	if count := bytes.Count(entry, []byte("crypto.getRandomValues")); count != 1 {
		t.Errorf("resource worker entry draws entropy %d times, want exactly one module-local draw", count)
	}
	testHost, err := fixtureFiles.ReadFile("fixture/session-host.mjs")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{[]byte(`"/spin"`), []byte(`"/allocate"`)} {
		if bytes.Contains(testHost, forbidden) {
			t.Errorf("workerd-test session host gained the unbounded qualification route %q", forbidden)
		}
	}
}
