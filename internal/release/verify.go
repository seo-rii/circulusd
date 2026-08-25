package release

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"

	"github.com/hancomac/circulusd/internal/canonical"
)

const (
	artifactSignatureDomain = "circulusd.release.artifact-signature"
	manifestSignatureDomain = "circulusd.release.manifest-signature"
)

type TrustStore struct {
	roots map[string]ed25519.PublicKey
}

func NewTrustStore(roots map[string]ed25519.PublicKey) (*TrustStore, error) {
	if len(roots) == 0 {
		return nil, fmt.Errorf("release trust store must contain at least one root")
	}

	copied := make(map[string]ed25519.PublicKey, len(roots))
	for keyID, publicKey := range roots {
		if !signingKeyPattern.MatchString(keyID) {
			return nil, fmt.Errorf("release trust root %q has an invalid key ID", keyID)
		}
		if len(publicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("release trust root %q has an invalid Ed25519 public key", keyID)
		}
		copied[keyID] = append(ed25519.PublicKey(nil), publicKey...)
	}

	return &TrustStore{roots: copied}, nil
}

func ArtifactSigningDigest(release Release, component Component, artifact Artifact) (string, error) {
	var size canonical.Value
	if artifact.SizeBytes != nil {
		size = *artifact.SizeBytes
	}

	return canonical.StructuredDigest(
		artifactSignatureDomain,
		1,
		canonical.Map{
			"releaseVersion": release.Version,
			"component": canonical.Map{
				"name":    component.Name,
				"version": component.Version,
				"commit":  component.Commit,
			},
			"artifact": canonical.Map{
				"architecture": artifact.Architecture,
				"name":         artifact.Name,
				"sha256":       artifact.SHA256,
				"sizeBytes":    size,
			},
		},
	)
}

// ManifestSigningDigest covers the complete manifest except for its root
// signatures. Artifact signatures remain covered so that they cannot be
// detached, replaced, or moved between otherwise valid manifests.
func ManifestSigningDigest(manifest Manifest) (string, error) {
	toolchains := make(canonical.Map, len(manifest.Toolchains))
	for name, version := range manifest.Toolchains {
		toolchains[name] = version
	}

	architectures := make(canonical.Array, len(manifest.Release.Architectures))
	for index, architecture := range manifest.Release.Architectures {
		architectures[index] = architecture
	}

	components := make(canonical.Array, len(manifest.Components))
	for componentIndex, component := range manifest.Components {
		artifacts := make(canonical.Array, len(component.Artifacts))
		for artifactIndex, artifact := range component.Artifacts {
			var size canonical.Value
			if artifact.SizeBytes != nil {
				size = *artifact.SizeBytes
			}

			var signature canonical.Value
			if artifact.Signature != nil {
				signature = canonical.Map{
					"algorithm": artifact.Signature.Algorithm,
					"keyId":     artifact.Signature.KeyID,
					"value":     artifact.Signature.Value,
				}
			}

			artifacts[artifactIndex] = canonical.Map{
				"architecture": artifact.Architecture,
				"name":         artifact.Name,
				"sha256":       artifact.SHA256,
				"sizeBytes":    size,
				"signature":    signature,
			}
		}

		components[componentIndex] = canonical.Map{
			"name":          component.Name,
			"version":       component.Version,
			"commit":        component.Commit,
			"license":       component.License,
			"source":        component.Source,
			"qualification": component.Qualification,
			"artifacts":     artifacts,
		}
	}

	compatibility := make(canonical.Array, len(manifest.ProtocolCompatibility))
	for index, protocol := range manifest.ProtocolCompatibility {
		compatibility[index] = canonical.Map{
			"pair": protocol.Pair,
			"minimum": canonical.Map{
				"major": protocol.Minimum.Major,
				"minor": protocol.Minimum.Minor,
			},
			"maximum": canonical.Map{
				"major": protocol.Maximum.Major,
				"minor": protocol.Maximum.Minor,
			},
			"descriptorSha256": protocol.DescriptorSHA256,
			"featureBitmap":    protocol.FeatureBitmap,
		}
	}

	unresolved := make(canonical.Array, len(manifest.UnresolvedArtifacts))
	for index, artifact := range manifest.UnresolvedArtifacts {
		unresolved[index] = artifact
	}

	return canonical.StructuredDigest(
		manifestSignatureDomain,
		1,
		canonical.Map{
			"schemaVersion": uint64(manifest.SchemaVersion),
			"release": canonical.Map{
				"version":       manifest.Release.Version,
				"status":        manifest.Release.Status,
				"architectures": architectures,
			},
			"toolchains":            toolchains,
			"components":            components,
			"protocolCompatibility": compatibility,
			"unresolvedArtifacts":   unresolved,
		},
	)
}

func (store *TrustStore) VerifyPromotion(manifest Manifest) error {
	if store == nil || len(store.roots) == 0 {
		return fmt.Errorf("release trust store is not configured")
	}
	if manifest.Release.Status != "candidate" && manifest.Release.Status != "production" {
		return fmt.Errorf("release status %q is not promotable", manifest.Release.Status)
	}
	if err := manifest.Validate(); err != nil {
		return fmt.Errorf("validate promotion manifest: %w", err)
	}

	for componentIndex, component := range manifest.Components {
		for artifactIndex, artifact := range component.Artifacts {
			signature := artifact.Signature
			publicKey, trusted := store.roots[signature.KeyID]
			if !trusted {
				return fmt.Errorf(
					"component[%d] artifact[%d] signature key %q is not trusted",
					componentIndex,
					artifactIndex,
					signature.KeyID,
				)
			}
			encodedSignature, err := base64.StdEncoding.Strict().DecodeString(signature.Value)
			if err != nil {
				return fmt.Errorf("decode component[%d] artifact[%d] signature: %w", componentIndex, artifactIndex, err)
			}
			digest, err := ArtifactSigningDigest(manifest.Release, component, artifact)
			if err != nil {
				return fmt.Errorf("hash component[%d] artifact[%d]: %w", componentIndex, artifactIndex, err)
			}
			if !ed25519.Verify(publicKey, []byte(digest), encodedSignature) {
				return fmt.Errorf("component[%d] artifact[%d] signature verification failed", componentIndex, artifactIndex)
			}
		}
	}

	digest, err := ManifestSigningDigest(manifest)
	if err != nil {
		return fmt.Errorf("hash promotion manifest: %w", err)
	}
	for _, signature := range manifest.Signatures {
		publicKey, trusted := store.roots[signature.KeyID]
		if !trusted {
			continue
		}
		encodedSignature, err := base64.StdEncoding.Strict().DecodeString(signature.Value)
		if err != nil {
			continue
		}
		if ed25519.Verify(publicKey, []byte(digest), encodedSignature) {
			return nil
		}
	}

	return fmt.Errorf("promotion manifest has no valid signature from a trusted release root")
}
