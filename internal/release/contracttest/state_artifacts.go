// Package contracttest provides signed release fixtures for production-boundary
// tests in packages that cannot manufacture opaque release results directly.
package contracttest

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/hancomac/circulusd/internal/release"
)

// StateArtifactDigests builds a complete signed candidate manifest and returns
// its opaque state digest pair for cross-package production-boundary tests.
func StateArtifactDigests(
	t testing.TB,
	buildDigest string,
	applicationDigest string,
) release.AuthenticatedStateArtifactDigests {
	t.Helper()

	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	components := []string{
		"platformd", "agentd", "executord", "sandboxd", "workerd", "celld",
		"session-host", "pi-runtime", "state-app",
	}
	manifest := release.Manifest{
		SchemaVersion: 1,
		Release: release.Release{
			Version:       "0.3.0",
			Status:        "candidate",
			Architectures: []string{"x86_64"},
		},
		Toolchains: map[string]string{
			"go": "1", "node": "1", "pnpm": "1", "protoc": "1",
			"protocGenGo": "1", "protocGenConnectGo": "1",
		},
	}
	for _, name := range components {
		digest := strings.Repeat("a", 64)
		if name == "celld" {
			digest = strings.TrimPrefix(buildDigest, "sha256:")
		} else if name == "state-app" {
			digest = strings.TrimPrefix(applicationDigest, "sha256:")
		}
		size := uint64(1)
		component := release.Component{
			Name: name, Version: "0.3.0", Commit: strings.Repeat("1", 40), License: "Apache-2.0",
			Source: "https://example.invalid/" + name, Qualification: "test",
			Artifacts: []release.Artifact{{
				Architecture: "any", Name: name + ".tar.zst", SHA256: digest, SizeBytes: &size,
			}},
		}
		signingDigest, err := release.ArtifactSigningDigest(manifest.Release, component, component.Artifacts[0])
		if err != nil {
			t.Fatalf("ArtifactSigningDigest() error = %v", err)
		}
		component.Artifacts[0].Signature = &release.Signature{
			Algorithm: "ed25519", KeyID: "release-root-1",
			Value: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(signingDigest))),
		}
		manifest.Components = append(manifest.Components, component)
	}
	for _, pair := range []string{
		"platformd-agentd", "platformd-executord", "session-host-dynamic-worker",
		"executord-sandboxd", "state-app-schema",
	} {
		manifest.ProtocolCompatibility = append(manifest.ProtocolCompatibility, release.ProtocolCompatibility{
			Pair: pair, Minimum: release.ProtocolVersion{Major: 1}, Maximum: release.ProtocolVersion{Major: 1},
			DescriptorSHA256: strings.Repeat("b", 64),
		})
	}
	manifestDigest, err := release.ManifestSigningDigest(manifest)
	if err != nil {
		t.Fatalf("ManifestSigningDigest() error = %v", err)
	}
	manifest.Signatures = []release.Signature{{
		Algorithm: "ed25519", KeyID: "release-root-1",
		Value: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(manifestDigest))),
	}}
	store, err := release.NewTrustStore(map[string]ed25519.PublicKey{
		"release-root-1": privateKey.Public().(ed25519.PublicKey),
	})
	if err != nil {
		t.Fatalf("release.NewTrustStore() error = %v", err)
	}
	artifacts, err := store.DeriveProductionStateArtifactDigests(manifest, "x86_64")
	if err != nil {
		t.Fatalf("DeriveProductionStateArtifactDigests() error = %v", err)
	}
	return artifacts
}
