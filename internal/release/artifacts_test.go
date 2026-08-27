package release

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
)

type memoryArtifactSource struct {
	mu       sync.Mutex
	contents map[string][]byte
	opens    []string
}

func (source *memoryArtifactSource) OpenArtifact(
	ctx context.Context,
	componentName string,
	architecture string,
	artifactName string,
) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key := componentName + "\x00" + architecture + "\x00" + artifactName
	source.mu.Lock()
	source.opens = append(source.opens, key)
	content, found := source.contents[key]
	source.mu.Unlock()
	if !found {
		return nil, fmt.Errorf("test artifact %q is missing", key)
	}
	return io.NopCloser(bytes.NewReader(append([]byte(nil), content...))), nil
}

func (source *memoryArtifactSource) opened() []string {
	source.mu.Lock()
	defer source.mu.Unlock()
	return append([]string(nil), source.opens...)
}

func TestTrustStoreVerifiesSelectedArtifactBytes(t *testing.T) {
	t.Parallel()

	manifest, contents, publicKey := signedArtifactManifest(t)
	store, err := NewTrustStore(map[string]ed25519.PublicKey{"release-root-1": publicKey})
	if err != nil {
		t.Fatalf("NewTrustStore() error = %v", err)
	}
	source := &memoryArtifactSource{contents: contents}

	verified, err := store.VerifyArtifacts(context.Background(), manifest, "x86_64", source)
	if err != nil {
		t.Fatalf("VerifyArtifacts() error = %v", err)
	}
	if len(verified) != len(manifest.Components) {
		t.Fatalf("VerifyArtifacts() returned %d artifacts, want %d", len(verified), len(manifest.Components))
	}
	for index, artifact := range verified {
		if index > 0 && verified[index-1].ComponentName >= artifact.ComponentName {
			t.Fatalf("verified artifacts are not canonically ordered: %#v", verified)
		}
		key := artifact.ComponentName + "\x00" + artifact.Architecture + "\x00" + artifact.ArtifactName
		content, found := contents[key]
		if !found || artifact.Architecture != "any" || artifact.SizeBytes != uint64(len(content)) {
			t.Fatalf("verified artifact = %#v", artifact)
		}
		digest := fmt.Sprintf("%x", sha256.Sum256(content))
		if artifact.SHA256 != digest {
			t.Fatalf("verified digest = %q, want %q", artifact.SHA256, digest)
		}
	}
	if len(source.opened()) != len(manifest.Components) {
		t.Fatalf("artifact source opens = %#v", source.opened())
	}
}

func TestTrustStoreRejectsMissingTruncatedExtendedAndCorruptArtifacts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(map[string][]byte, string)
	}{
		{name: "missing", mutate: func(contents map[string][]byte, key string) { delete(contents, key) }},
		{name: "truncated", mutate: func(contents map[string][]byte, key string) {
			contents[key] = contents[key][:len(contents[key])-1]
		}},
		{name: "extended", mutate: func(contents map[string][]byte, key string) {
			contents[key] = append(contents[key], 'x')
		}},
		{name: "digest mismatch", mutate: func(contents map[string][]byte, key string) {
			contents[key] = bytes.Repeat([]byte{'x'}, len(contents[key]))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			manifest, contents, publicKey := signedArtifactManifest(t)
			key := manifest.Components[0].Name + "\x00" + manifest.Components[0].Artifacts[0].Architecture + "\x00" + manifest.Components[0].Artifacts[0].Name
			test.mutate(contents, key)
			store, err := NewTrustStore(map[string]ed25519.PublicKey{"release-root-1": publicKey})
			if err != nil {
				t.Fatalf("NewTrustStore() error = %v", err)
			}

			if _, err := store.VerifyArtifacts(
				context.Background(),
				manifest,
				"x86_64",
				&memoryArtifactSource{contents: contents},
			); !errors.Is(err, ErrArtifactVerification) {
				t.Fatalf("VerifyArtifacts() error = %v, want ErrArtifactVerification", err)
			}
		})
	}
}

func TestTrustStoreArtifactVerificationFailsClosedOnInvalidInputs(t *testing.T) {
	t.Parallel()

	manifest, contents, publicKey := signedArtifactManifest(t)
	store, err := NewTrustStore(map[string]ed25519.PublicKey{"release-root-1": publicKey})
	if err != nil {
		t.Fatalf("NewTrustStore() error = %v", err)
	}
	var nilSource *memoryArtifactSource
	if _, err := store.VerifyArtifacts(context.Background(), manifest, "x86_64", nilSource); !errors.Is(err, ErrArtifactVerification) {
		t.Fatalf("VerifyArtifacts(typed nil source) error = %v", err)
	}
	if _, err := store.VerifyArtifacts(context.Background(), manifest, "amd64", &memoryArtifactSource{contents: contents}); !errors.Is(err, ErrArtifactVerification) {
		t.Fatalf("VerifyArtifacts(unsupported architecture) error = %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	source := &memoryArtifactSource{contents: contents}
	if _, err := store.VerifyArtifacts(canceled, manifest, "x86_64", source); !errors.Is(err, context.Canceled) {
		t.Fatalf("VerifyArtifacts(canceled) error = %v", err)
	}
	if len(source.opened()) != 0 {
		t.Fatalf("canceled verification opened artifacts: %#v", source.opened())
	}
}

func signedArtifactManifest(t *testing.T) (Manifest, map[string][]byte, ed25519.PublicKey) {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	manifest := completeRelease("candidate")
	contents := make(map[string][]byte, len(manifest.Components))
	for componentIndex := range manifest.Components {
		component := &manifest.Components[componentIndex]
		for artifactIndex := range component.Artifacts {
			artifact := &component.Artifacts[artifactIndex]
			content := []byte("artifact:" + component.Name + ":" + artifact.Name)
			digest := sha256.Sum256(content)
			size := uint64(len(content))
			artifact.SHA256 = fmt.Sprintf("%x", digest)
			artifact.SizeBytes = &size
			artifact.Signature = nil
			signingDigest, err := ArtifactSigningDigest(manifest.Release, *component, *artifact)
			if err != nil {
				t.Fatalf("ArtifactSigningDigest() error = %v", err)
			}
			artifact.Signature = &Signature{
				Algorithm: "ed25519",
				KeyID:     "release-root-1",
				Value: base64.StdEncoding.EncodeToString(
					ed25519.Sign(privateKey, []byte(signingDigest)),
				),
			}
			contents[component.Name+"\x00"+artifact.Architecture+"\x00"+artifact.Name] = content
		}
	}
	manifest.Signatures = nil
	digest, err := ManifestSigningDigest(manifest)
	if err != nil {
		t.Fatalf("ManifestSigningDigest() error = %v", err)
	}
	manifest.Signatures = []Signature{{
		Algorithm: "ed25519",
		KeyID:     "release-root-1",
		Value: base64.StdEncoding.EncodeToString(
			ed25519.Sign(privateKey, []byte(digest)),
		),
	}}
	return manifest, contents, privateKey.Public().(ed25519.PublicKey)
}
