package release

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

func TestLoadRejectsManifestLargerThanLimitEvenWhenOverflowIsWhitespace(t *testing.T) {
	t.Parallel()

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test file")
	}
	contents, err := os.ReadFile(filepath.Join(filepath.Dir(currentFile), "..", "..", "deploy", "airgap", "release-manifest.json"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	contents = append(contents, bytes.Repeat([]byte{' '}, maxManifestBytes+1-len(contents))...)
	path := filepath.Join(t.TempDir(), "oversized.json")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load(oversized) error = nil")
	}
}

func TestManifestRejectsMalformedArtifactDigest(t *testing.T) {
	t.Parallel()

	manifest := Manifest{
		SchemaVersion: 1,
		Release:       Release{Version: "0.3.0", Status: "development", Architectures: []string{"x86_64"}},
		Toolchains:    developmentToolchains(),
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

	if err := manifest.Validate(); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("Validate() error = %v, want malformed digest error", err)
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
		Toolchains:    developmentToolchains(),
		Components:    []Component{component, component},
	}

	if err := manifest.Validate(); err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("Validate() error = %v, want duplicate component error", err)
	}
}

func TestCandidateAndProductionRequireCompleteSignedArtifacts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Manifest)
	}{
		{name: "missing signatures", mutate: func(manifest *Manifest) { manifest.Signatures = nil }},
		{name: "missing generator toolchain", mutate: func(manifest *Manifest) {
			delete(manifest.Toolchains, "protocGenGo")
		}},
		{name: "unresolved artifact", mutate: func(manifest *Manifest) {
			manifest.UnresolvedArtifacts = []string{"sandboxd binary"}
		}},
		{name: "missing protocol pair", mutate: func(manifest *Manifest) {
			manifest.ProtocolCompatibility = manifest.ProtocolCompatibility[:4]
		}},
		{name: "duplicate protocol pair", mutate: func(manifest *Manifest) {
			manifest.ProtocolCompatibility[4].Pair = manifest.ProtocolCompatibility[0].Pair
		}},
		{name: "missing core component", mutate: func(manifest *Manifest) {
			manifest.Components = manifest.Components[1:]
		}},
		{name: "artifactless component", mutate: func(manifest *Manifest) {
			manifest.Components[0].Artifacts = nil
		}},
		{name: "unsigned artifact", mutate: func(manifest *Manifest) {
			manifest.Components[0].Artifacts[0].Signature = nil
		}},
		{name: "missing artifact size", mutate: func(manifest *Manifest) {
			manifest.Components[0].Artifacts[0].SizeBytes = nil
		}},
		{name: "protocol range reversed", mutate: func(manifest *Manifest) {
			manifest.ProtocolCompatibility[0].Minimum = ProtocolVersion{Major: 2}
		}},
		{name: "invalid descriptor digest", mutate: func(manifest *Manifest) {
			manifest.ProtocolCompatibility[0].DescriptorSHA256 = "no"
		}},
		{name: "invalid manifest signature", mutate: func(manifest *Manifest) {
			manifest.Signatures[0].Value = "AA=="
		}},
		{name: "unsafe artifact size", mutate: func(manifest *Manifest) {
			size := uint64(9_007_199_254_740_992)
			manifest.Components[0].Artifacts[0].SizeBytes = &size
		}},
		{name: "unsafe protocol version", mutate: func(manifest *Manifest) {
			manifest.ProtocolCompatibility[0].Minimum = ProtocolVersion{Major: 9_007_199_254_740_992}
			manifest.ProtocolCompatibility[0].Maximum = ProtocolVersion{Major: 9_007_199_254_740_992}
		}},
		{name: "unsafe feature bitmap", mutate: func(manifest *Manifest) {
			manifest.ProtocolCompatibility[0].FeatureBitmap = 9_007_199_254_740_992
		}},
		{name: "oversized component version", mutate: func(manifest *Manifest) {
			manifest.Components[0].Version = strings.Repeat("v", 129)
		}},
		{name: "oversized artifact name", mutate: func(manifest *Manifest) {
			manifest.Components[0].Artifacts[0].Name = strings.Repeat("a", 256)
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			for _, status := range []string{"candidate", "production"} {
				manifest := completeRelease(status)
				test.mutate(&manifest)
				if err := manifest.Validate(); err == nil {
					t.Fatalf("Validate(%s) error = nil", status)
				}
			}
		})
	}
}

func TestCandidateAndProductionRequireTrustedWorkerComponents(t *testing.T) {
	t.Parallel()

	tests := []struct {
		status        string
		componentName string
	}{
		{status: "candidate", componentName: "session-host"},
		{status: "candidate", componentName: "pi-runtime"},
		{status: "candidate", componentName: "state-app"},
		{status: "production", componentName: "session-host"},
		{status: "production", componentName: "pi-runtime"},
		{status: "production", componentName: "state-app"},
	}

	for _, test := range tests {
		t.Run(test.status+"/"+test.componentName, func(t *testing.T) {
			t.Parallel()

			manifest := completeRelease(test.status)
			for index, component := range manifest.Components {
				if component.Name == test.componentName {
					manifest.Components = append(manifest.Components[:index], manifest.Components[index+1:]...)
					break
				}
			}

			err := manifest.Validate()
			if err == nil || !strings.Contains(err.Error(), `missing component "`+test.componentName+`"`) {
				t.Fatalf("Validate() error = %v, want missing %q component error", err, test.componentName)
			}
		})
	}
}

func TestCompleteCandidateAndProductionShapeIsValid(t *testing.T) {
	t.Parallel()

	for _, status := range []string{"candidate", "production"} {
		manifest := completeRelease(status)
		if err := manifest.Validate(); err != nil {
			t.Fatalf("Validate(%s) error = %v", status, err)
		}
	}
}

func completeRelease(status string) Manifest {
	signature := Signature{
		Algorithm: "ed25519",
		KeyID:     "release-root-1",
		Value:     base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
	}
	components := make([]Component, 0, len(requiredProductionComponents))
	for _, name := range requiredProductionComponents {
		size := uint64(12)
		components = append(components, Component{
			Name:          name,
			Version:       "0.3.0",
			Commit:        "0123456789abcdef0123456789abcdef01234567",
			License:       "Apache-2.0",
			Source:        "https://example.invalid/" + name,
			Qualification: "conformance-pass",
			Artifacts: []Artifact{{
				Architecture: "any",
				Name:         name + ".tar.zst",
				SHA256:       "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				SizeBytes:    &size,
				Signature:    &signature,
			}},
		})
	}

	pairs := make([]ProtocolCompatibility, 0, len(requiredProtocolPairs))
	for _, pair := range requiredProtocolPairs {
		pairs = append(pairs, ProtocolCompatibility{
			Pair:             pair,
			Minimum:          ProtocolVersion{Major: 1},
			Maximum:          ProtocolVersion{Major: 1},
			DescriptorSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		})
	}

	return Manifest{
		SchemaVersion: 1,
		Release: Release{
			Version:       "0.3.0",
			Status:        status,
			Architectures: []string{"x86_64", "aarch64"},
		},
		Toolchains:            developmentToolchains(),
		Components:            components,
		ProtocolCompatibility: pairs,
		Signatures:            []Signature{signature},
	}
}

func developmentToolchains() map[string]string {
	return map[string]string{
		"go":                 "1.25.3",
		"node":               "24.1.0",
		"pnpm":               "10.30.0",
		"protoc":             "3.21.12",
		"protocGenGo":        "1.36.10",
		"protocGenConnectGo": "1.19.1",
	}
}
