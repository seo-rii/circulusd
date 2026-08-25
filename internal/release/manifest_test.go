package release

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestRepositoryManifestIsValid(t *testing.T) {
	t.Parallel()

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test file")
	}

	manifest, err := Load(filepath.Join(filepath.Dir(currentFile), "..", "..", "deploy", "airgap", "release-manifest.json"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if err := manifest.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestManifestRejectsMalformedArtifactDigest(t *testing.T) {
	t.Parallel()

	manifest := Manifest{
		SchemaVersion: 1,
		Release:       Release{Version: "0.3.0", Status: "development", Architectures: []string{"x86_64"}},
		Components: []Component{{
			Name:          "workerd",
			Version:       "1",
			Commit:        "0123456789abcdef0123456789abcdef01234567",
			License:       "Apache-2.0",
			Source:        "https://example.invalid/workerd",
			Qualification: "test",
			Artifacts: []Artifact{{
				Architecture: "x86_64",
				Name:         "workerd.gz",
				SHA256:       "not-a-digest",
			}},
		}},
	}

	if err := manifest.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want malformed digest error")
	}
}

func TestManifestRejectsDuplicateComponent(t *testing.T) {
	t.Parallel()

	component := Component{
		Name:          "celld",
		Version:       "0.3.0",
		Commit:        "0123456789abcdef0123456789abcdef01234567",
		License:       "Apache-2.0",
		Source:        "https://example.invalid/celld",
		Qualification: "test",
	}
	manifest := Manifest{
		SchemaVersion: 1,
		Release:       Release{Version: "0.3.0", Status: "development", Architectures: []string{"x86_64"}},
		Components:    []Component{component, component},
	}

	if err := manifest.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want duplicate component error")
	}
}
