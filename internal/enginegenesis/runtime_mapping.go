package enginegenesis

import (
	"crypto/ed25519"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/ed25519key"
)

const (
	RuntimeMappingDomain               = "circulusd.pi.genesis-runtime-mapping"
	RuntimeMappingCelldCommit          = "89e4ffc53a14ecb496d2ca5014ff9d19b0061ad9"
	MaximumRuntimeMappingDocumentBytes = 4096
	maximumRuntimeMappingTrustRoots    = 64
)

// RuntimeMappingClaims binds the immutable Pi artifact identity to one exact
// runtime revision. This document does not qualify a native runtime, grant
// production authority, or replace an independent live dependency proof.
type RuntimeMappingClaims struct {
	SchemaVersion           uint32 `json:"schemaVersion"`
	CelldCommit             string `json:"celldCommit"`
	AdapterABIVersion       uint32 `json:"adapterAbiVersion"`
	CheckpointSchemaVersion uint32 `json:"checkpointSchemaVersion"`
	RuntimeRevisionDigest   string `json:"runtimeRevisionDigest"`
	ArtifactDigest          string `json:"artifactDigest"`
	KeyID                   string `json:"keyId"`
}

// RuntimeMappingTrustRoot must be provisioned independently of the document.
// Verification snapshots its public key and never retains caller-owned bytes.
type RuntimeMappingTrustRoot struct {
	KeyID     string
	PublicKey ed25519.PublicKey
}

// RuntimeMappingBinding is a verified immutable mapping. Its zero value is
// unverified. The signing digest must also have been pinned independently by
// the caller; a trusted signer alone cannot select a different mapping.
type RuntimeMappingBinding struct {
	claims   RuntimeMappingClaims
	digest   string
	verified bool
}

func (binding RuntimeMappingBinding) Claims() RuntimeMappingClaims {
	if !binding.verified {
		return RuntimeMappingClaims{}
	}
	return binding.claims
}

func (binding RuntimeMappingBinding) MappingDigest() string {
	if !binding.verified {
		return ""
	}
	return binding.digest
}

func runtimeMappingOptions() canonical.Options {
	return canonical.Options{MaxBytes: MaximumRuntimeMappingDocumentBytes, MaxDepth: 16, MaxItems: 64}
}

func runtimeMappingClaimsValue(claims RuntimeMappingClaims) (canonical.Map, error) {
	if claims.SchemaVersion != 1 || claims.CelldCommit != RuntimeMappingCelldCommit ||
		claims.AdapterABIVersion != 2 || claims.CheckpointSchemaVersion != 2 ||
		!digestPattern.MatchString(claims.RuntimeRevisionDigest) ||
		!digestPattern.MatchString(claims.ArtifactDigest) || !keyPattern.MatchString(claims.KeyID) {
		return nil, ErrInvalidConfig
	}
	return canonical.Map{
		"schemaVersion": int64(claims.SchemaVersion), "celldCommit": claims.CelldCommit,
		"adapterAbiVersion":       int64(claims.AdapterABIVersion),
		"checkpointSchemaVersion": int64(claims.CheckpointSchemaVersion),
		"runtimeRevisionDigest":   claims.RuntimeRevisionDigest,
		"artifactDigest":          claims.ArtifactDigest, "keyId": claims.KeyID,
	}, nil
}

// RuntimeMappingSigningDigest prepares the digest for an independent offline
// Ed25519 signer. The signer signs the ASCII bytes of this 71-byte sha256 digest,
// rather than raw CBOR or a hex-decoded digest. No private key is accepted here.
func RuntimeMappingSigningDigest(claims RuntimeMappingClaims) (string, error) {
	value, err := runtimeMappingClaimsValue(claims)
	if err != nil {
		return "", ErrInvalidConfig
	}
	if _, err := canonical.Encode(value, runtimeMappingOptions()); err != nil {
		return "", ErrInvalidConfig
	}
	digest, err := canonical.StructuredDigest(RuntimeMappingDomain, 1, value)
	if err != nil {
		return "", ErrInvalidConfig
	}
	return digest, nil
}

// EncodeSignedRuntimeMapping packages a signature produced by an independent
// offline signer. Packaging does not verify that signature or confer authority.
func EncodeSignedRuntimeMapping(claims RuntimeMappingClaims, signature []byte) ([]byte, error) {
	value, err := runtimeMappingClaimsValue(claims)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, ErrInvalidConfig
	}
	encoded, err := canonical.Encode(canonical.Map{
		"claims": value, "algorithm": "ed25519",
		"signature": canonical.Bytes(append([]byte(nil), signature...)),
	}, runtimeMappingOptions())
	if err != nil {
		return nil, ErrInvalidConfig
	}
	return encoded, nil
}

// VerifySignedRuntimeMapping verifies a bounded canonical document against a
// pinned claims digest and independently provisioned signing roots. There is no
// expiry: immutable mappings must remain usable for existing-session replay.
// Native eligibility and current artifact bytes require separate verification.
func VerifySignedRuntimeMapping(document []byte, expectedMappingDigest string, roots []RuntimeMappingTrustRoot) (RuntimeMappingBinding, error) {
	if !digestPattern.MatchString(expectedMappingDigest) || len(roots) < 1 || len(roots) > maximumRuntimeMappingTrustRoots {
		return RuntimeMappingBinding{}, ErrInvalidConfig
	}
	trusted := make(map[string]ed25519.PublicKey, len(roots))
	materials := make(map[[ed25519.PublicKeySize]byte]struct{}, len(roots))
	for _, root := range roots {
		material, valid := runtimeMappingPublicKey(root.PublicKey)
		if !keyPattern.MatchString(root.KeyID) || !valid {
			return RuntimeMappingBinding{}, ErrInvalidConfig
		}
		if _, duplicate := trusted[root.KeyID]; duplicate {
			return RuntimeMappingBinding{}, ErrInvalidConfig
		}
		if _, duplicate := materials[material]; duplicate {
			return RuntimeMappingBinding{}, ErrInvalidConfig
		}
		materials[material] = struct{}{}
		trusted[root.KeyID] = append(ed25519.PublicKey(nil), material[:]...)
	}
	decoded, err := canonical.Decode(document, runtimeMappingOptions())
	if err != nil {
		return RuntimeMappingBinding{}, ErrInvalidResponse
	}
	value, ok := decoded.(canonical.Map)
	if !ok || len(value) != 3 || value["algorithm"] != "ed25519" {
		return RuntimeMappingBinding{}, ErrInvalidResponse
	}
	claimsValue, ok := value["claims"].(canonical.Map)
	if !ok || len(claimsValue) != 7 {
		return RuntimeMappingBinding{}, ErrInvalidResponse
	}
	if claimsValue["schemaVersion"] != int64(1) || claimsValue["celldCommit"] != RuntimeMappingCelldCommit ||
		claimsValue["adapterAbiVersion"] != int64(2) || claimsValue["checkpointSchemaVersion"] != int64(2) {
		return RuntimeMappingBinding{}, ErrInvalidResponse
	}
	claims := RuntimeMappingClaims{SchemaVersion: 1, CelldCommit: RuntimeMappingCelldCommit, AdapterABIVersion: 2, CheckpointSchemaVersion: 2}
	claims.RuntimeRevisionDigest, _ = claimsValue["runtimeRevisionDigest"].(string)
	claims.ArtifactDigest, _ = claimsValue["artifactDigest"].(string)
	claims.KeyID, _ = claimsValue["keyId"].(string)
	digest, err := RuntimeMappingSigningDigest(claims)
	if err != nil || digest != expectedMappingDigest {
		return RuntimeMappingBinding{}, ErrInvalidResponse
	}
	signature, ok := value["signature"].(canonical.Bytes)
	publicKey, trustedKey := trusted[claims.KeyID]
	if !ok || len(signature) != ed25519.SignatureSize || !trustedKey || !ed25519.Verify(publicKey, []byte(digest), signature) {
		return RuntimeMappingBinding{}, ErrInvalidResponse
	}
	return RuntimeMappingBinding{claims: claims, digest: digest, verified: true}, nil
}

// A non-identity canonical prime-order key prevents alternate point encodings
// and small-order or mixed-order roots from becoming signing authorities.
func runtimeMappingPublicKey(publicKey ed25519.PublicKey) ([ed25519.PublicKeySize]byte, bool) {
	var material [ed25519.PublicKeySize]byte
	if !ed25519key.IsCanonicalPrimeOrder(publicKey) {
		return material, false
	}
	copy(material[:], publicKey)
	return material, true
}
