package release

import "fmt"

// AuthenticatedStateArtifactDigests is an immutable pair of expected state
// identities authenticated from one signed release-manifest snapshot. It is
// metadata-only: it does not hash installed or runtime bytes and, by itself,
// never establishes readiness. Production dependency requirements must consume
// this value as one unit so callers cannot inject independently sourced digest
// strings.
type AuthenticatedStateArtifactDigests struct {
	celldBuildDigest          string
	stateAppApplicationDigest string
}

func (artifacts AuthenticatedStateArtifactDigests) CelldBuildDigest() string {
	return artifacts.celldBuildDigest
}

func (artifacts AuthenticatedStateArtifactDigests) StateAppApplicationDigest() string {
	return artifacts.stateAppApplicationDigest
}

// DeriveProductionStateArtifactDigests authenticates one promotable manifest
// and derives both expected state identities from that same immutable snapshot.
// The current schema has no artifact-purpose field, so each role must have
// exactly one artifact applicable to the requested release architecture.
func (store *TrustStore) DeriveProductionStateArtifactDigests(
	manifest Manifest,
	architecture string,
) (AuthenticatedStateArtifactDigests, error) {
	snapshot := cloneManifest(manifest)
	if err := store.verifyPromotionSnapshot(snapshot); err != nil {
		return AuthenticatedStateArtifactDigests{}, fmt.Errorf("%w: authenticate state release: %w", ErrArtifactVerification, err)
	}
	if architecture != "x86_64" && architecture != "aarch64" {
		return AuthenticatedStateArtifactDigests{}, fmt.Errorf("%w: architecture %q is unsupported", ErrArtifactVerification, architecture)
	}
	releasedArchitecture := false
	for _, released := range snapshot.Release.Architectures {
		if released == architecture {
			releasedArchitecture = true
			break
		}
	}
	if !releasedArchitecture {
		return AuthenticatedStateArtifactDigests{}, fmt.Errorf("%w: architecture %q is not present in the release", ErrArtifactVerification, architecture)
	}

	var celldDigests []string
	var stateAppDigests []string
	for _, component := range snapshot.Components {
		if component.Name != "celld" && component.Name != "state-app" {
			continue
		}
		for _, artifact := range component.Artifacts {
			if artifact.Architecture != "any" && artifact.Architecture != architecture {
				continue
			}
			digest := "sha256:" + artifact.SHA256
			if component.Name == "celld" {
				celldDigests = append(celldDigests, digest)
			} else {
				stateAppDigests = append(stateAppDigests, digest)
			}
		}
	}
	if len(celldDigests) != 1 || len(stateAppDigests) != 1 {
		return AuthenticatedStateArtifactDigests{}, fmt.Errorf(
			"%w: state artifact selection is ambiguous or incomplete",
			ErrArtifactVerification,
		)
	}
	return AuthenticatedStateArtifactDigests{
		celldBuildDigest:          celldDigests[0],
		stateAppApplicationDigest: stateAppDigests[0],
	}, nil
}

func cloneManifest(manifest Manifest) Manifest {
	cloned := manifest
	cloned.Release.Architectures = append([]string(nil), manifest.Release.Architectures...)
	if manifest.Toolchains != nil {
		cloned.Toolchains = make(map[string]string, len(manifest.Toolchains))
		for name, version := range manifest.Toolchains {
			cloned.Toolchains[name] = version
		}
	}
	cloned.Components = make([]Component, len(manifest.Components))
	for componentIndex, component := range manifest.Components {
		cloned.Components[componentIndex] = component
		cloned.Components[componentIndex].Artifacts = make([]Artifact, len(component.Artifacts))
		for artifactIndex, artifact := range component.Artifacts {
			cloned.Components[componentIndex].Artifacts[artifactIndex] = artifact
			if artifact.SizeBytes != nil {
				size := *artifact.SizeBytes
				cloned.Components[componentIndex].Artifacts[artifactIndex].SizeBytes = &size
			}
			if artifact.Signature != nil {
				signature := *artifact.Signature
				cloned.Components[componentIndex].Artifacts[artifactIndex].Signature = &signature
			}
		}
	}
	cloned.ProtocolCompatibility = append([]ProtocolCompatibility(nil), manifest.ProtocolCompatibility...)
	cloned.Signatures = append([]Signature(nil), manifest.Signatures...)
	cloned.UnresolvedArtifacts = append([]string(nil), manifest.UnresolvedArtifacts...)
	return cloned
}
