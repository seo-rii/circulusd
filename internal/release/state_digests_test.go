package release

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestTrustStoreDerivesAuthenticatedProductionStateArtifactDigests(t *testing.T) {
	t.Parallel()

	for _, status := range []string{"candidate", "production"} {
		status := status
		t.Run(status, func(t *testing.T) {
			t.Parallel()

			manifest, _, publicKey := signedArtifactManifest(t)
			manifest.Release.Status = status
			manifest.Release.Architectures = []string{"x86_64"}
			for componentIndex := range manifest.Components {
				if manifest.Components[componentIndex].Name == "celld" {
					manifest.Components[componentIndex].Artifacts[0].Architecture = "x86_64"
					break
				}
			}
			for left, right := 0, len(manifest.Components)-1; left < right; left, right = left+1, right-1 {
				manifest.Components[left], manifest.Components[right] = manifest.Components[right], manifest.Components[left]
			}
			resignArtifactManifest(t, &manifest)
			store, err := NewTrustStore(map[string]ed25519.PublicKey{"release-root-1": publicKey})
			if err != nil {
				t.Fatalf("NewTrustStore() error = %v", err)
			}

			verified, err := store.DeriveProductionStateArtifactDigests(manifest, "x86_64")
			if err != nil {
				t.Fatalf("DeriveProductionStateArtifactDigests() error = %v", err)
			}
			wantBuild := "sha256:" + componentArtifactSHA256(t, manifest, "celld")
			wantApplication := "sha256:" + componentArtifactSHA256(t, manifest, "state-app")
			if verified.CelldBuildDigest() != wantBuild || verified.StateAppApplicationDigest() != wantApplication {
				t.Fatalf("state artifacts = %q/%q, want %q/%q", verified.CelldBuildDigest(), verified.StateAppApplicationDigest(), wantBuild, wantApplication)
			}

			manifest.Components[0].Artifacts[0].SHA256 = strings.Repeat("f", 64)
			if verified.CelldBuildDigest() != wantBuild || verified.StateAppApplicationDigest() != wantApplication {
				t.Fatal("derived state artifacts alias the caller manifest")
			}
		})
	}
}

func TestTrustStoreRejectsAmbiguousProductionStateArtifactDigests(t *testing.T) {
	t.Parallel()

	for _, componentName := range []string{"celld", "state-app"} {
		componentName := componentName
		t.Run(componentName, func(t *testing.T) {
			t.Parallel()

			manifest, _, publicKey := signedArtifactManifest(t)
			for componentIndex := range manifest.Components {
				component := &manifest.Components[componentIndex]
				if component.Name != componentName {
					continue
				}
				size := uint64(17)
				component.Artifacts = append(component.Artifacts, Artifact{
					Architecture: "x86_64",
					Name:         componentName + "-second.tar.zst",
					SHA256:       strings.Repeat("a", 64),
					SizeBytes:    &size,
				})
				break
			}
			resignArtifactManifest(t, &manifest)
			store, err := NewTrustStore(map[string]ed25519.PublicKey{"release-root-1": publicKey})
			if err != nil {
				t.Fatalf("NewTrustStore() error = %v", err)
			}
			if err := store.VerifyPromotion(manifest); err != nil {
				t.Fatalf("VerifyPromotion(ambiguous but signed manifest) error = %v", err)
			}

			verified, err := store.DeriveProductionStateArtifactDigests(manifest, "x86_64")
			if !errors.Is(err, ErrArtifactVerification) {
				t.Fatalf("DeriveProductionStateArtifactDigests() error = %v, want ErrArtifactVerification", err)
			}
			if verified.CelldBuildDigest() != "" || verified.StateAppApplicationDigest() != "" {
				t.Fatalf("ambiguous derivation returned partial state artifacts: %#v", verified)
			}
		})
	}
}

func TestTrustStoreProductionStateArtifactDerivationFailsClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		architecture string
		mutate       func(*testing.T, *Manifest)
		nilStore     bool
	}{
		{name: "development release", architecture: "x86_64", mutate: func(t *testing.T, manifest *Manifest) {
			manifest.Release.Status = "development"
			resignArtifactManifest(t, manifest)
		}},
		{name: "unsupported architecture alias", architecture: "amd64"},
		{name: "architecture outside release", architecture: "aarch64", mutate: func(t *testing.T, manifest *Manifest) {
			manifest.Release.Architectures = []string{"x86_64"}
			resignArtifactManifest(t, manifest)
		}},
		{name: "tampered artifact digest", architecture: "x86_64", mutate: func(_ *testing.T, manifest *Manifest) {
			manifest.Components[0].Artifacts[0].SHA256 = strings.Repeat("b", 64)
		}},
		{name: "nil trust store", architecture: "x86_64", nilStore: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			manifest, _, publicKey := signedArtifactManifest(t)
			if test.mutate != nil {
				test.mutate(t, &manifest)
			}
			var store *TrustStore
			if !test.nilStore {
				var err error
				store, err = NewTrustStore(map[string]ed25519.PublicKey{"release-root-1": publicKey})
				if err != nil {
					t.Fatalf("NewTrustStore() error = %v", err)
				}
			}

			verified, err := store.DeriveProductionStateArtifactDigests(manifest, test.architecture)
			if !errors.Is(err, ErrArtifactVerification) {
				t.Fatalf("DeriveProductionStateArtifactDigests() error = %v, want ErrArtifactVerification", err)
			}
			if verified.CelldBuildDigest() != "" || verified.StateAppApplicationDigest() != "" {
				t.Fatalf("failed derivation returned partial state artifacts: %#v", verified)
			}
		})
	}
}

func TestCloneManifestBreaksEveryMutableAlias(t *testing.T) {
	t.Parallel()

	manifest, _, _ := signedArtifactManifest(t)
	manifest.UnresolvedArtifacts = []string{"test-only"}
	snapshot := cloneManifest(manifest)
	want := cloneManifest(snapshot)

	manifest.Release.Architectures[0] = "changed"
	manifest.Toolchains["go"] = "changed"
	manifest.Components[0].Name = "changed"
	manifest.Components[1].Artifacts[0].Name = "changed"
	*manifest.Components[2].Artifacts[0].SizeBytes = 999
	manifest.Components[3].Artifacts[0].Signature.KeyID = "changed"
	manifest.ProtocolCompatibility[0].Pair = "changed"
	manifest.Signatures[0].KeyID = "changed"
	manifest.UnresolvedArtifacts[0] = "changed"

	if !reflect.DeepEqual(snapshot, want) {
		t.Fatalf("manifest snapshot changed through caller aliases:\n got: %#v\nwant: %#v", snapshot, want)
	}
}

func TestTrustStoreDerivesProductionStateArtifactDigestsConcurrently(t *testing.T) {
	t.Parallel()

	manifest, _, publicKey := signedArtifactManifest(t)
	store, err := NewTrustStore(map[string]ed25519.PublicKey{"release-root-1": publicKey})
	if err != nil {
		t.Fatalf("NewTrustStore() error = %v", err)
	}
	wantBuild := "sha256:" + componentArtifactSHA256(t, manifest, "celld")
	wantApplication := "sha256:" + componentArtifactSHA256(t, manifest, "state-app")

	const workers = 64
	start := make(chan struct{})
	results := make(chan AuthenticatedStateArtifactDigests, workers)
	errors := make(chan error, workers)
	var wait sync.WaitGroup
	wait.Add(workers)
	for range workers {
		go func() {
			defer wait.Done()
			<-start
			verified, err := store.DeriveProductionStateArtifactDigests(manifest, "x86_64")
			results <- verified
			errors <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("concurrent DeriveProductionStateArtifactDigests() error = %v", err)
		}
	}
	for verified := range results {
		if verified.CelldBuildDigest() != wantBuild || verified.StateAppApplicationDigest() != wantApplication {
			t.Fatalf("concurrent state artifacts = %#v", verified)
		}
	}
}

func resignArtifactManifest(t *testing.T, manifest *Manifest) {
	t.Helper()

	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	for componentIndex := range manifest.Components {
		component := &manifest.Components[componentIndex]
		for artifactIndex := range component.Artifacts {
			artifact := &component.Artifacts[artifactIndex]
			artifact.Signature = nil
			digest, err := ArtifactSigningDigest(manifest.Release, *component, *artifact)
			if err != nil {
				t.Fatalf("ArtifactSigningDigest() error = %v", err)
			}
			artifact.Signature = &Signature{
				Algorithm: "ed25519",
				KeyID:     "release-root-1",
				Value:     base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(digest))),
			}
		}
	}
	manifest.Signatures = nil
	digest, err := ManifestSigningDigest(*manifest)
	if err != nil {
		t.Fatalf("ManifestSigningDigest() error = %v", err)
	}
	manifest.Signatures = []Signature{{
		Algorithm: "ed25519",
		KeyID:     "release-root-1",
		Value:     base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(digest))),
	}}
}

func componentArtifactSHA256(t *testing.T, manifest Manifest, componentName string) string {
	t.Helper()

	for _, component := range manifest.Components {
		if component.Name == componentName {
			if len(component.Artifacts) != 1 {
				t.Fatalf("component %q artifacts = %d, want 1", componentName, len(component.Artifacts))
			}
			return component.Artifacts[0].SHA256
		}
	}
	t.Fatalf("component %q is missing", componentName)
	return ""
}
