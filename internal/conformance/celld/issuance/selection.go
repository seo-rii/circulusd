package issuance

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"regexp"
	"time"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/dependency"
)

// StorageSelection is an independent, storage-only selected local release.
// It does not manufacture AuthenticatedStateArtifactDigests or promote the
// complete nine-component platform release. That bootstrap remains closed.
type StorageSelection struct {
	SchemaVersion        uint32 `json:"schemaVersion"`
	ReleaseVersion       string `json:"releaseVersion"`
	Architecture         string `json:"architecture"`
	CelldCommit          string `json:"celldCommit"`
	ArtifactName         string `json:"artifactName"`
	ArtifactSizeBytes    uint64 `json:"artifactSizeBytes"`
	ExtractionRecipe     string `json:"extractionRecipe"`
	BuildDigest          string `json:"buildDigest"`
	ApplicationSizeBytes uint64 `json:"applicationSizeBytes"`
	ApplicationDigest    string `json:"applicationDigest"`
	KeyID                string `json:"keyId"`
	Algorithm            string `json:"algorithm"`
	Signature            string `json:"signature"`
}

var version = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$`)
var artifact = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$`)

func SelectionSigningDigest(s StorageSelection) (string, error) {
	if s.SchemaVersion != 1 || !version.MatchString(s.ReleaseVersion) || (s.Architecture != "x86_64" && s.Architecture != "aarch64") ||
		!commit.MatchString(s.CelldCommit) || !artifact.MatchString(s.ArtifactName) || s.ArtifactSizeBytes == 0 ||
		s.ArtifactSizeBytes > 1<<30 || s.ApplicationSizeBytes == 0 || s.ApplicationSizeBytes > 32<<20 ||
		s.ExtractionRecipe != "raw-executable-v1" || !digest.MatchString(s.BuildDigest) || !digest.MatchString(s.ApplicationDigest) ||
		!identifier.MatchString(s.KeyID) || s.Algorithm != "ed25519" {
		return "", ErrInvalidConfiguration
	}
	return canonical.StructuredDigest("circulusd.native-storage-release-selection", 1, canonical.Map{
		"schemaVersion": uint64(s.SchemaVersion), "releaseVersion": s.ReleaseVersion, "architecture": s.Architecture,
		"celldCommit": s.CelldCommit, "artifactName": s.ArtifactName, "artifactSizeBytes": s.ArtifactSizeBytes,
		"extractionRecipe": s.ExtractionRecipe, "buildDigest": s.BuildDigest, "applicationSizeBytes": s.ApplicationSizeBytes,
		"applicationDigest": s.ApplicationDigest, "keyId": s.KeyID, "algorithm": s.Algorithm,
	})
}

func VerifySelection(s StorageSelection, roots map[string]ed25519.PublicKey) error {
	d, err := SelectionSigningDigest(s)
	key, ok := roots[s.KeyID]
	sig, sigErr := base64.StdEncoding.Strict().DecodeString(s.Signature)
	if err != nil || sigErr != nil || !ok || len(key) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize ||
		base64.StdEncoding.EncodeToString(sig) != s.Signature || !ed25519.Verify(key, []byte(d), sig) {
		return ErrInvalidConfiguration
	}
	return nil
}

func separateReleaseRoots(c Config) error {
	if len(c.ReleaseRoots) == 0 || len(c.ReleaseRoots) > 64 {
		return ErrInvalidConfiguration
	}
	conformance := c.ConformancePrivateKey.Public().(ed25519.PublicKey)
	for id, key := range c.ReleaseRoots {
		if !identifier.MatchString(id) || len(key) != ed25519.PublicKeySize || id == c.ConformanceKeyID || id == c.RuntimeKeyID ||
			bytes.Equal(key, conformance) || bytes.Equal(key, c.RuntimePublicKey) {
			return ErrInvalidConfiguration
		}
		for observerID, observer := range c.ObserverRoots {
			if id == observerID || bytes.Equal(key, observer) {
				return ErrInvalidConfiguration
			}
		}
		if _, err := dependency.NewVerifier(dependency.VerifierConfig{
			ConformanceRoots: map[string]ed25519.PublicKey{id: key}, RuntimeRoots: map[string]ed25519.PublicKey{c.RuntimeKeyID: c.RuntimePublicKey},
			Clock: func() time.Time { return c.Now }, Entropy: bytes.NewReader(make([]byte, 32)),
		}); err != nil {
			return ErrInvalidConfiguration
		}
	}
	return nil
}
