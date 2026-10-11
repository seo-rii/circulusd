package enginegenesis

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/edwards25519"
	"github.com/hancomac/circulusd/internal/canonical"
)

type runtimeMappingFixture struct {
	TestOnly             bool                       `json:"testOnly"`
	Description          string                     `json:"description"`
	Domain               string                     `json:"domain"`
	SchemaVersion        int                        `json:"schemaVersion"`
	MaximumDocumentBytes int                        `json:"maximumDocumentBytes"`
	MaximumDepth         int                        `json:"maximumDepth"`
	MaximumItems         int                        `json:"maximumItems"`
	Claims               RuntimeMappingClaims       `json:"claims"`
	PublicKeyHex         string                     `json:"publicKeyHex"`
	ClaimsCBORHex        string                     `json:"claimsCBORHex"`
	SigningDigest        string                     `json:"signingDigest"`
	SignatureHex         string                     `json:"signatureHex"`
	DocumentCBORHex      string                     `json:"documentCBORHex"`
	InvalidPublicKeys    []runtimeMappingInvalidKey `json:"invalidPublicKeys"`
}

type runtimeMappingInvalidKey struct {
	Name         string `json:"name"`
	PublicKeyHex string `json:"publicKeyHex"`
}

func runtimeMappingInvalidKeys(t *testing.T, publicKey ed25519.PublicKey) []runtimeMappingInvalidKey {
	t.Helper()
	identity := make(ed25519.PublicKey, 32)
	identity[0] = 1
	nonCanonical := append(ed25519.PublicKey(nil), identity...)
	nonCanonical[31] = 0x80
	orderTwo := bytes.Repeat([]byte{0xff}, 32)
	orderTwo[0], orderTwo[31] = 0xec, 0x7f
	validPoint, err := new(edwards25519.Point).SetBytes(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	torsion, err := new(edwards25519.Point).SetBytes(orderTwo)
	if err != nil {
		t.Fatal(err)
	}
	return []runtimeMappingInvalidKey{
		{Name: "identity", PublicKeyHex: hex.EncodeToString(identity)},
		{Name: "noncanonical identity", PublicKeyHex: hex.EncodeToString(nonCanonical)},
		{Name: "order two", PublicKeyHex: hex.EncodeToString(orderTwo)},
		{Name: "order four", PublicKeyHex: hex.EncodeToString(make([]byte, 32))},
		{Name: "mixed order", PublicKeyHex: hex.EncodeToString(new(edwards25519.Point).Add(validPoint, torsion).Bytes())},
	}
}

func runtimeMappingFixtureKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func runtimeMappingFixtureClaims() RuntimeMappingClaims {
	return RuntimeMappingClaims{
		SchemaVersion: 1, CelldCommit: RuntimeMappingCelldCommit,
		AdapterABIVersion: 2, CheckpointSchemaVersion: 2,
		RuntimeRevisionDigest: "sha256:" + strings.Repeat("11", 32),
		ArtifactDigest:        "sha256:" + strings.Repeat("22", 32),
		KeyID:                 "pi-genesis-mapping-fixture-1",
	}
}

func runtimeMappingFixtureDocument(t *testing.T) ([]byte, string, []RuntimeMappingTrustRoot) {
	t.Helper()
	claims := runtimeMappingFixtureClaims()
	digest, err := RuntimeMappingSigningDigest(claims)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := runtimeMappingFixtureKey()
	document, err := EncodeSignedRuntimeMapping(claims, ed25519.Sign(privateKey, []byte(digest)))
	if err != nil {
		t.Fatal(err)
	}
	return document, digest, []RuntimeMappingTrustRoot{{KeyID: claims.KeyID, PublicKey: privateKey.Public().(ed25519.PublicKey)}}
}

func TestRuntimeMappingGoldenFixture(t *testing.T) {
	claims := runtimeMappingFixtureClaims()
	claimsValue, err := runtimeMappingClaimsValue(claims)
	if err != nil {
		t.Fatal(err)
	}
	claimsBytes, err := canonical.Encode(claimsValue, runtimeMappingOptions())
	if err != nil {
		t.Fatal(err)
	}
	document, digest, roots := runtimeMappingFixtureDocument(t)
	fixture := runtimeMappingFixture{
		TestOnly:    true,
		Description: "Public deterministic Ed25519 mapping example from test-only seed 00..1f; not deployment trust, native eligibility, or artifact qualification evidence.",
		Domain:      RuntimeMappingDomain, SchemaVersion: 1,
		MaximumDocumentBytes: MaximumRuntimeMappingDocumentBytes, MaximumDepth: 16, MaximumItems: 64,
		Claims: claims, PublicKeyHex: hex.EncodeToString(roots[0].PublicKey),
		ClaimsCBORHex: hex.EncodeToString(claimsBytes), SigningDigest: digest,
		SignatureHex:      hex.EncodeToString(ed25519.Sign(runtimeMappingFixtureKey(), []byte(digest))),
		DocumentCBORHex:   hex.EncodeToString(document),
		InvalidPublicKeys: runtimeMappingInvalidKeys(t, roots[0].PublicKey),
	}
	expected, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	expected = append(expected, '\n')
	path := filepath.Join("..", "..", "packages", "protocol-types", "fixtures", "pi-genesis-runtime-mapping-v1alpha1.json")
	if os.Getenv("CIRCULUSD_UPDATE_PI_GENESIS_MAPPING_FIXTURE") == "1" {
		if err := os.WriteFile(path, expected, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	actual, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatal("signed Pi genesis runtime mapping fixture differs from canonical Go contract")
	}
	binding, err := VerifySignedRuntimeMapping(document, digest, roots)
	if err != nil || binding.Claims() != claims || binding.MappingDigest() != digest {
		t.Fatalf("binding claims/digest/error = %#v/%q/%v", binding.Claims(), binding.MappingDigest(), err)
	}
	if len(digest) != 71 || len(claimsBytes) >= MaximumRuntimeMappingDocumentBytes || len(document) >= MaximumRuntimeMappingDocumentBytes {
		t.Fatal("mapping fixture violates explicit wire limits")
	}
}

func TestRuntimeMappingBindingOwnsVerifiedSnapshot(t *testing.T) {
	t.Parallel()
	document, digest, roots := runtimeMappingFixtureDocument(t)
	binding, err := VerifySignedRuntimeMapping(document, digest, roots)
	if err != nil {
		t.Fatal(err)
	}
	for index := range document {
		document[index] = 0
	}
	for index := range roots[0].PublicKey {
		roots[0].PublicKey[index] = 0
	}
	roots[0].KeyID = "another-root"
	copy := binding.Claims()
	copy.ArtifactDigest = "sha256:" + strings.Repeat("33", 32)
	if binding.Claims() != runtimeMappingFixtureClaims() || binding.MappingDigest() != digest {
		t.Fatal("binding retained caller-owned document, root bytes, or returned claims")
	}
	if (RuntimeMappingBinding{}).Claims() != (RuntimeMappingClaims{}) || (RuntimeMappingBinding{}).MappingDigest() != "" {
		t.Fatal("zero binding disclosed a verified mapping")
	}
}

func TestRuntimeMappingRejectsTamperedOrAmbiguousDocuments(t *testing.T) {
	t.Parallel()
	document, digest, roots := runtimeMappingFixtureDocument(t)
	decoded, err := canonical.Decode(document, runtimeMappingOptions())
	if err != nil {
		t.Fatal(err)
	}
	encode := func(value canonical.Value) []byte {
		encoded, err := canonical.Encode(value, canonical.DefaultOptions())
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	clone := func() canonical.Map {
		value, err := canonical.Decode(document, runtimeMappingOptions())
		if err != nil {
			t.Fatal(err)
		}
		return value.(canonical.Map)
	}
	cases := []struct {
		name     string
		document []byte
		digest   string
	}{
		{"empty", nil, digest},
		{"truncated", document[:len(document)-1], digest},
		{"trailing", append(append([]byte(nil), document...), 0xf6), digest},
		{"too large", make([]byte, MaximumRuntimeMappingDocumentBytes+1), digest},
		{"not map", encode(canonical.Array{decoded}), digest},
		{"wrong pinned mapping", document, "sha256:" + strings.Repeat("33", 32)},
	}
	for _, mutation := range []struct {
		name   string
		mutate func(canonical.Map)
	}{
		{"tampered signature", func(value canonical.Map) { value["signature"].(canonical.Bytes)[0] ^= 1 }},
		{"short signature", func(value canonical.Map) { value["signature"] = canonical.Bytes(make([]byte, 63)) }},
		{"text signature", func(value canonical.Map) { value["signature"] = "not signature bytes" }},
		{"unknown document field", func(value canonical.Map) { value["extra"] = "hidden claim" }},
		{"missing document field", func(value canonical.Map) { delete(value, "algorithm") }},
		{"wrong algorithm", func(value canonical.Map) { value["algorithm"] = "Ed25519" }},
		{"claims array", func(value canonical.Map) { value["claims"] = canonical.Array{} }},
		{"tampered claims", func(value canonical.Map) {
			value["claims"].(canonical.Map)["artifactDigest"] = "sha256:" + strings.Repeat("44", 32)
		}},
		{"unknown claims field", func(value canonical.Map) { value["claims"].(canonical.Map)["productionEligible"] = true }},
		{"missing claims field", func(value canonical.Map) { delete(value["claims"].(canonical.Map), "artifactDigest") }},
		{"claim key mismatch", func(value canonical.Map) { value["claims"].(canonical.Map)["keyId"] = "untrusted-root" }},
	} {
		value := clone()
		mutation.mutate(value)
		cases = append(cases, struct {
			name     string
			document []byte
			digest   string
		}{mutation.name, encode(value), digest})
	}
	// Repeat the first canonical key to exercise duplicate decoding directly;
	// canonical encoders cannot construct duplicate maps.
	claimsEntry := append(encode("claims"), encode(decoded.(canonical.Map)["claims"])...)
	duplicate := append([]byte{0xa4}, claimsEntry...)
	duplicate = append(duplicate, document[1:]...)
	cases = append(cases, struct {
		name     string
		document []byte
		digest   string
	}{"duplicate key", duplicate, digest})
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			binding, err := VerifySignedRuntimeMapping(test.document, test.digest, roots)
			if !errors.Is(err, ErrInvalidResponse) || binding != (RuntimeMappingBinding{}) {
				t.Fatalf("binding/error = %#v/%v, want empty/sanitized invalid response", binding, err)
			}
		})
	}
	for _, test := range []struct {
		name   string
		mutate func(canonical.Map)
	}{
		{"wrong celld commit", func(value canonical.Map) { value["celldCommit"] = strings.Repeat("0", 40) }},
		{"wrong mapping schema", func(value canonical.Map) { value["schemaVersion"] = int64(2) }},
		{"wrong ABI", func(value canonical.Map) { value["adapterAbiVersion"] = int64(1) }},
		{"wrong checkpoint schema", func(value canonical.Map) { value["checkpointSchemaVersion"] = int64(1) }},
		{"text ABI", func(value canonical.Map) { value["adapterAbiVersion"] = "2" }},
		{"invalid runtime digest", func(value canonical.Map) { value["runtimeRevisionDigest"] = "sha256:" + strings.Repeat("AA", 32) }},
		{"invalid artifact digest", func(value canonical.Map) { value["artifactDigest"] = "sha256:1234" }},
		{"invalid key id", func(value canonical.Map) { value["keyId"] = "Invalid-Key" }},
	} {
		t.Run("signed "+test.name, func(t *testing.T) {
			value := clone()
			claims := value["claims"].(canonical.Map)
			test.mutate(claims)
			invalidDigest, err := canonical.StructuredDigest(RuntimeMappingDomain, 1, claims)
			if err != nil {
				t.Fatal(err)
			}
			value["signature"] = canonical.Bytes(ed25519.Sign(runtimeMappingFixtureKey(), []byte(invalidDigest)))
			binding, err := VerifySignedRuntimeMapping(encode(value), invalidDigest, roots)
			if !errors.Is(err, ErrInvalidResponse) || binding != (RuntimeMappingBinding{}) {
				t.Fatalf("valid signature bypassed mapping semantics: %#v/%v", binding, err)
			}
		})
	}
}

func TestRuntimeMappingRejectsInvalidIndependentTrust(t *testing.T) {
	t.Parallel()
	document, digest, roots := runtimeMappingFixtureDocument(t)
	publicKey := append(ed25519.PublicKey(nil), roots[0].PublicKey...)
	tooMany := make([]RuntimeMappingTrustRoot, 65)
	cases := []struct {
		name   string
		digest string
		roots  []RuntimeMappingTrustRoot
	}{
		{"missing pin", "", roots},
		{"invalid pin", "sha256:1", roots},
		{"missing roots", digest, nil},
		{"too many roots", digest, tooMany},
		{"duplicate key id", digest, append(append([]RuntimeMappingTrustRoot(nil), roots...), roots[0])},
		{"duplicate public material", digest, append(append([]RuntimeMappingTrustRoot(nil), roots...), RuntimeMappingTrustRoot{KeyID: "second-root", PublicKey: publicKey})},
		{"bad key id", digest, []RuntimeMappingTrustRoot{{KeyID: "BAD", PublicKey: publicKey}}},
		{"short public key", digest, []RuntimeMappingTrustRoot{{KeyID: roots[0].KeyID, PublicKey: publicKey[:31]}}},
	}
	for _, weak := range runtimeMappingInvalidKeys(t, publicKey) {
		material, err := hex.DecodeString(weak.PublicKeyHex)
		if err != nil {
			t.Fatal(err)
		}
		cases = append(cases, struct {
			name   string
			digest string
			roots  []RuntimeMappingTrustRoot
		}{
			weak.Name + " public key", digest, []RuntimeMappingTrustRoot{{KeyID: roots[0].KeyID, PublicKey: ed25519.PublicKey(material)}},
		})
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			binding, err := VerifySignedRuntimeMapping(document, test.digest, test.roots)
			if !errors.Is(err, ErrInvalidConfig) || binding != (RuntimeMappingBinding{}) {
				t.Fatalf("binding/error = %#v/%v, want empty/sanitized invalid config", binding, err)
			}
		})
	}
	wrongRoots := []RuntimeMappingTrustRoot{{KeyID: "other-root", PublicKey: publicKey}}
	if binding, err := VerifySignedRuntimeMapping(document, digest, wrongRoots); !errors.Is(err, ErrInvalidResponse) || binding != (RuntimeMappingBinding{}) {
		t.Fatalf("untrusted claims key id = %#v/%v", binding, err)
	}
	otherSeed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	wrongRoots[0] = RuntimeMappingTrustRoot{KeyID: roots[0].KeyID, PublicKey: ed25519.NewKeyFromSeed(otherSeed).Public().(ed25519.PublicKey)}
	if binding, err := VerifySignedRuntimeMapping(document, digest, wrongRoots); !errors.Is(err, ErrInvalidResponse) || binding != (RuntimeMappingBinding{}) {
		t.Fatalf("untrusted public key = %#v/%v", binding, err)
	}
}

func TestRuntimeMappingAcceptsMaximumIndependentRoots(t *testing.T) {
	t.Parallel()
	document, digest, roots := runtimeMappingFixtureDocument(t)
	for index := 1; index < maximumRuntimeMappingTrustRoots; index++ {
		seed := make([]byte, ed25519.SeedSize)
		for offset := range seed {
			seed[offset] = byte(offset)
		}
		seed[0] = byte(index)
		roots = append(roots, RuntimeMappingTrustRoot{
			KeyID:     fmt.Sprintf("mapping-root-%d", index),
			PublicKey: ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey),
		})
	}
	binding, err := VerifySignedRuntimeMapping(document, digest, roots)
	if err != nil || binding.Claims() != runtimeMappingFixtureClaims() || binding.MappingDigest() != digest {
		t.Fatalf("64 independent roots failed: %#v/%v", binding, err)
	}
}

func TestRuntimeMappingRequiresExactSigningDomainAndASCIIDigest(t *testing.T) {
	t.Parallel()
	claims := runtimeMappingFixtureClaims()
	value, err := runtimeMappingClaimsValue(claims)
	if err != nil {
		t.Fatal(err)
	}
	_, digest, roots := runtimeMappingFixtureDocument(t)
	wrongDomain, err := canonical.StructuredDigest("circulusd.production-dependency-evidence", 1, value)
	if err != nil {
		t.Fatal(err)
	}
	rawDigest, err := hex.DecodeString(strings.TrimPrefix(digest, "sha256:"))
	if err != nil {
		t.Fatal(err)
	}
	claimsBytes, err := canonical.Encode(value, runtimeMappingOptions())
	if err != nil {
		t.Fatal(err)
	}
	for _, message := range [][]byte{[]byte(wrongDomain), rawDigest, claimsBytes} {
		document, err := EncodeSignedRuntimeMapping(claims, ed25519.Sign(runtimeMappingFixtureKey(), message))
		if err != nil {
			t.Fatal(err)
		}
		if binding, err := VerifySignedRuntimeMapping(document, digest, roots); err != ErrInvalidResponse || binding != (RuntimeMappingBinding{}) {
			t.Fatalf("wrong signing message accepted: %#v/%v", binding, err)
		}
	}
}

func TestRuntimeMappingOfflinePreparationRejectsInvalidClaimsAndSignature(t *testing.T) {
	t.Parallel()
	claims := runtimeMappingFixtureClaims()
	for _, mutate := range []func(*RuntimeMappingClaims){
		func(value *RuntimeMappingClaims) { value.SchemaVersion = 2 },
		func(value *RuntimeMappingClaims) { value.CelldCommit = "other" },
		func(value *RuntimeMappingClaims) { value.AdapterABIVersion = 1 },
		func(value *RuntimeMappingClaims) { value.CheckpointSchemaVersion = 1 },
		func(value *RuntimeMappingClaims) { value.RuntimeRevisionDigest = "wrong" },
		func(value *RuntimeMappingClaims) { value.ArtifactDigest = "wrong" },
		func(value *RuntimeMappingClaims) { value.KeyID = strings.Repeat("k", 65) },
	} {
		invalid := claims
		mutate(&invalid)
		if digest, err := RuntimeMappingSigningDigest(invalid); digest != "" || !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("invalid signing claims accepted: %q/%v", digest, err)
		}
		if document, err := EncodeSignedRuntimeMapping(invalid, make([]byte, 64)); document != nil || !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("invalid packaged claims accepted: %x/%v", document, err)
		}
	}
	for _, size := range []int{0, 63, 65} {
		if document, err := EncodeSignedRuntimeMapping(claims, make([]byte, size)); document != nil || !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("invalid signature size accepted: %x/%v", document, err)
		}
	}
	// Packaging a correctly-sized signature is deliberately not verification.
	document, err := EncodeSignedRuntimeMapping(claims, make([]byte, 64))
	if err != nil {
		t.Fatal(err)
	}
	_, digest, roots := runtimeMappingFixtureDocument(t)
	if binding, err := VerifySignedRuntimeMapping(document, digest, roots); !errors.Is(err, ErrInvalidResponse) || binding != (RuntimeMappingBinding{}) {
		t.Fatalf("signature packaging conferred authority: %#v/%v", binding, err)
	}
}
