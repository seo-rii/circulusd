package release

import (
	"crypto/ed25519"
	"encoding/base64"
	"sync"
	"testing"
)

func TestTrustStoreVerifiesSignedPromotionManifest(t *testing.T) {
	t.Parallel()

	manifest, publicKey := signedPromotion(t, "candidate")
	store, err := NewTrustStore(map[string]ed25519.PublicKey{"release-root-1": publicKey})
	if err != nil {
		t.Fatalf("NewTrustStore() error = %v", err)
	}
	if err := store.VerifyPromotion(manifest); err != nil {
		t.Fatalf("VerifyPromotion() error = %v", err)
	}
}

func TestTrustStoreRejectsTamperingAndUntrustedKeys(t *testing.T) {
	t.Parallel()

	manifest, publicKey := signedPromotion(t, "production")
	store, err := NewTrustStore(map[string]ed25519.PublicKey{"release-root-1": publicKey})
	if err != nil {
		t.Fatalf("NewTrustStore() error = %v", err)
	}

	tamperedArtifact := manifest
	tamperedArtifact.Components = append([]Component(nil), manifest.Components...)
	tamperedArtifact.Components[0].Artifacts = append(
		[]Artifact(nil),
		manifest.Components[0].Artifacts...,
	)
	tamperedArtifact.Components[0].Artifacts[0].SHA256 =
		"1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if err := store.VerifyPromotion(tamperedArtifact); err == nil {
		t.Fatal("VerifyPromotion(tampered artifact) error = nil")
	}

	tamperedManifest := manifest
	tamperedManifest.Release.Version = "0.3.1"
	if err := store.VerifyPromotion(tamperedManifest); err == nil {
		t.Fatal("VerifyPromotion(tampered manifest) error = nil")
	}

	untrusted, err := NewTrustStore(map[string]ed25519.PublicKey{
		"other-root": ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey),
	})
	if err != nil {
		t.Fatalf("NewTrustStore(untrusted) error = %v", err)
	}
	if err := untrusted.VerifyPromotion(manifest); err == nil {
		t.Fatal("VerifyPromotion(untrusted) error = nil")
	}
}

func TestTrustStoreRejectsDevelopmentAndInvalidRoots(t *testing.T) {
	t.Parallel()

	if _, err := NewTrustStore(nil); err == nil {
		t.Fatal("NewTrustStore(nil) error = nil")
	}
	if _, err := NewTrustStore(map[string]ed25519.PublicKey{"bad key": make([]byte, 1)}); err == nil {
		t.Fatal("NewTrustStore(invalid key) error = nil")
	}

	manifest, publicKey := signedPromotion(t, "candidate")
	manifest.Release.Status = "development"
	store, err := NewTrustStore(map[string]ed25519.PublicKey{"release-root-1": publicKey})
	if err != nil {
		t.Fatalf("NewTrustStore() error = %v", err)
	}
	if err := store.VerifyPromotion(manifest); err == nil {
		t.Fatal("VerifyPromotion(development) error = nil")
	}
}

func TestSigningDigestIsDeterministicAcrossToolchainMapOrder(t *testing.T) {
	t.Parallel()

	manifest := completeRelease("candidate")
	manifest.Toolchains = map[string]string{
		"protocGenConnectGo": "1.19.1",
		"pnpm":               "10.30.0",
		"go":                 "1.25.3",
		"protoc":             "3.21.12",
		"node":               "24.1.0",
		"protocGenGo":        "1.36.10",
	}
	first, err := ManifestSigningDigest(manifest)
	if err != nil {
		t.Fatalf("ManifestSigningDigest(first) error = %v", err)
	}
	manifest.Toolchains = developmentToolchains()
	second, err := ManifestSigningDigest(manifest)
	if err != nil {
		t.Fatalf("ManifestSigningDigest(second) error = %v", err)
	}
	if first != second {
		t.Fatalf("ManifestSigningDigest() = %q and %q", first, second)
	}
}

func TestTrustStoreSupportsConcurrentVerification(t *testing.T) {
	t.Parallel()

	manifest, publicKey := signedPromotion(t, "candidate")
	store, err := NewTrustStore(map[string]ed25519.PublicKey{"release-root-1": publicKey})
	if err != nil {
		t.Fatalf("NewTrustStore() error = %v", err)
	}

	const callers = 64
	start := make(chan struct{})
	errors := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			errors <- store.VerifyPromotion(manifest)
		}()
	}
	close(start)
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("VerifyPromotion() error = %v", err)
		}
	}
}

func TestTrustStoreCopiesRootKeys(t *testing.T) {
	t.Parallel()

	manifest, publicKey := signedPromotion(t, "candidate")
	store, err := NewTrustStore(map[string]ed25519.PublicKey{"release-root-1": publicKey})
	if err != nil {
		t.Fatalf("NewTrustStore() error = %v", err)
	}
	for index := range publicKey {
		publicKey[index] ^= 0xff
	}
	if err := store.VerifyPromotion(manifest); err != nil {
		t.Fatalf("VerifyPromotion() after caller key mutation error = %v", err)
	}
}

func TestManifestSignatureCoversArtifactSignatures(t *testing.T) {
	t.Parallel()

	manifest, publicKey := signedPromotion(t, "candidate")
	secondSeed := make([]byte, ed25519.SeedSize)
	for index := range secondSeed {
		secondSeed[index] = 1
	}
	secondPrivateKey := ed25519.NewKeyFromSeed(secondSeed)
	artifact := &manifest.Components[0].Artifacts[0]
	digest, err := ArtifactSigningDigest(manifest.Release, manifest.Components[0], *artifact)
	if err != nil {
		t.Fatalf("ArtifactSigningDigest() error = %v", err)
	}
	artifact.Signature = &Signature{
		Algorithm: "ed25519",
		KeyID:     "release-root-2",
		Value: base64.StdEncoding.EncodeToString(
			ed25519.Sign(secondPrivateKey, []byte(digest)),
		),
	}

	store, err := NewTrustStore(map[string]ed25519.PublicKey{
		"release-root-1": publicKey,
		"release-root-2": secondPrivateKey.Public().(ed25519.PublicKey),
	})
	if err != nil {
		t.Fatalf("NewTrustStore() error = %v", err)
	}
	if err := store.VerifyPromotion(manifest); err == nil {
		t.Fatal("VerifyPromotion(re-signed artifact without manifest re-signing) error = nil")
	}
}

func signedPromotion(t *testing.T, status string) (Manifest, ed25519.PublicKey) {
	t.Helper()

	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	manifest := completeRelease(status)
	for componentIndex := range manifest.Components {
		for artifactIndex := range manifest.Components[componentIndex].Artifacts {
			artifact := &manifest.Components[componentIndex].Artifacts[artifactIndex]
			digest, err := ArtifactSigningDigest(
				manifest.Release,
				manifest.Components[componentIndex],
				*artifact,
			)
			if err != nil {
				t.Fatalf("ArtifactSigningDigest() error = %v", err)
			}
			artifact.Signature = &Signature{
				Algorithm: "ed25519",
				KeyID:     "release-root-1",
				Value: base64.StdEncoding.EncodeToString(
					ed25519.Sign(privateKey, []byte(digest)),
				),
			}
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
	return manifest, privateKey.Public().(ed25519.PublicKey)
}
