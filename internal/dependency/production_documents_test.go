package dependency

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
)

func TestDecodeEvidenceReturnsValidatedDetachedDocument(t *testing.T) {
	t.Parallel()

	fixture := newVerificationFixture(t, "state-domain-a")
	encoded := encodeEvidenceDocument(t, fixture.evidence, nil)
	originalDocument := append([]byte(nil), encoded...)
	loaded, err := DecodeEvidence(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("DecodeEvidence() error = %v", err)
	}
	if !equalDescriptor(loaded.Descriptor, fixture.evidence.Descriptor) ||
		loaded.IssuedAtUnix != fixture.evidence.IssuedAtUnix ||
		loaded.ExpiresAtUnix != fixture.evidence.ExpiresAtUnix ||
		loaded.KeyID != fixture.evidence.KeyID ||
		!bytes.Equal(loaded.Signature, fixture.evidence.Signature) {
		t.Fatalf("DecodeEvidence() = %#v, want signed fixture", loaded)
	}
	for index := range encoded {
		encoded[index] ^= 0xff
	}
	if !bytes.Equal(loaded.Signature, fixture.evidence.Signature) ||
		!equalDescriptor(loaded.Descriptor, fixture.evidence.Descriptor) {
		t.Fatal("DecodeEvidence() result was aliased with the encoded input")
	}
	loaded.Signature[0] ^= 0xff
	loaded.Descriptor.AtomicGroups[0] = "mutated"
	again, err := DecodeEvidence(bytes.NewReader(originalDocument))
	if err != nil {
		t.Fatalf("DecodeEvidence(second) error = %v", err)
	}
	if !bytes.Equal(again.Signature, fixture.evidence.Signature) ||
		!equalDescriptor(again.Descriptor, fixture.evidence.Descriptor) {
		t.Fatal("DecodeEvidence() returned state aliased with input or a prior result")
	}
	withWhitespace := append(encodeEvidenceDocument(t, fixture.evidence, nil), []byte(" \n\t")...)
	if _, err := DecodeEvidence(bytes.NewReader(withWhitespace)); err != nil {
		t.Fatalf("DecodeEvidence(trailing whitespace) error = %v", err)
	}
}

func TestDecodeEvidenceLeavesProductionAdmissionToVerifyDependency(t *testing.T) {
	t.Parallel()

	fixture := newVerificationFixture(t, "state-domain-a")
	document := encodeEvidenceDocument(t, fixture.evidence, func(document *evidenceDocumentFixture) {
		document.Descriptor.BackendKind = BackendReferenceMemory
		document.Descriptor.DurabilityClass = DurabilityProcessLocal
		document.Descriptor.ProductionEligible = false
	})
	loaded, err := DecodeEvidence(bytes.NewReader(document))
	if err != nil {
		t.Fatalf("DecodeEvidence(reference descriptor) error = %v", err)
	}
	if loaded.Descriptor.BackendKind != BackendReferenceMemory || loaded.Descriptor.ProductionEligible {
		t.Fatalf("DecodeEvidence(reference descriptor) = %#v", loaded.Descriptor)
	}
}

func TestDecodeEvidenceRejectsAmbiguousUnboundedOrInvalidDocuments(t *testing.T) {
	t.Parallel()

	fixture := newVerificationFixture(t, "state-domain-a")
	valid := encodeEvidenceDocument(t, fixture.evidence, nil)
	unknownRoot := append([]byte(nil), valid[:len(valid)-1]...)
	unknownRoot = append(unknownRoot, []byte(`,"extra":true}`)...)
	duplicateRoot := bytes.Replace(valid, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1,"schemaVersion":1`), 1)
	unknownDescriptor := bytes.Replace(valid, []byte(`"backendKind":"celld"`), []byte(`"backendKind":"celld","extra":true`), 1)
	duplicateDescriptor := bytes.Replace(valid, []byte(`"backendKind":"celld"`), []byte(`"backendKind":"celld","backendKind":"celld"`), 1)
	trailing := append(append([]byte(nil), valid...), []byte(` {}`)...)
	deep := []byte(`{"schemaVersion":1,"descriptor":` + strings.Repeat("[", 40) + `0` + strings.Repeat("]", 40) + `}`)
	manyTokens := []byte(`{"extra":[` + strings.Repeat("0,", 5_000) + `0]}`)
	caseAlias := bytes.Replace(valid, []byte(`"backendKind"`), []byte(`"BackendKind"`), 1)
	dualCaseAlias := bytes.Replace(valid, []byte(`"backendKind":"celld"`), []byte(`"backendKind":"celld","BackendKind":"reference-memory"`), 1)
	referenceDocument := encodeEvidenceDocument(t, fixture.evidence, func(document *evidenceDocumentFixture) {
		document.Descriptor.BackendKind = BackendReferenceMemory
		document.Descriptor.DurabilityClass = DurabilityProcessLocal
		document.Descriptor.ProductionEligible = false
	})
	missingFalseField := bytes.Replace(referenceDocument, []byte(`,"productionEligible":false`), nil, 1)
	nullFalseField := bytes.Replace(referenceDocument, []byte(`"productionEligible":false`), []byte(`"productionEligible":null`), 1)
	invalidUTF8 := bytes.Replace(valid, []byte(`"keyId":"conformance-root"`), []byte{'"', 'k', 'e', 'y', 'I', 'd', '"', ':', '"', 0xff, '"'}, 1)
	bom := append([]byte{0xef, 0xbb, 0xbf}, valid...)
	maximumAtomicGroups := encodeEvidenceDocument(t, fixture.evidence, func(document *evidenceDocumentFixture) {
		document.Descriptor.AtomicGroups = make([]AtomicGroup, 64)
		for index := range document.Descriptor.AtomicGroups {
			document.Descriptor.AtomicGroups[index] = AtomicGroup(fmt.Sprintf("group-%02d", index))
		}
	})
	if _, err := DecodeEvidence(bytes.NewReader(maximumAtomicGroups)); err != nil {
		t.Fatalf("DecodeEvidence(64 atomic groups) error = %v", err)
	}
	tests := []struct {
		name     string
		document []byte
		want     error
	}{
		{name: "empty", document: nil, want: ErrInvalidEvidenceDocument},
		{name: "whitespace", document: []byte(" \n\t"), want: ErrInvalidEvidenceDocument},
		{name: "unknown root member", document: unknownRoot, want: ErrInvalidEvidenceDocument},
		{name: "duplicate root member", document: duplicateRoot, want: ErrInvalidEvidenceDocument},
		{name: "unknown descriptor member", document: unknownDescriptor, want: ErrInvalidEvidenceDocument},
		{name: "duplicate descriptor member", document: duplicateDescriptor, want: ErrInvalidEvidenceDocument},
		{name: "trailing value", document: trailing, want: ErrInvalidEvidenceDocument},
		{name: "non-object", document: []byte(`[]`), want: ErrInvalidEvidenceDocument},
		{name: "null document", document: []byte(`null`), want: ErrInvalidEvidenceDocument},
		{name: "case alias", document: caseAlias, want: ErrInvalidEvidenceDocument},
		{name: "dual case alias", document: dualCaseAlias, want: ErrInvalidEvidenceDocument},
		{name: "missing required false field", document: missingFalseField, want: ErrInvalidEvidenceDocument},
		{name: "null required false field", document: nullFalseField, want: ErrInvalidEvidenceDocument},
		{name: "invalid UTF-8", document: invalidUTF8, want: ErrInvalidEvidenceDocument},
		{name: "UTF-8 BOM", document: bom, want: ErrInvalidEvidenceDocument},
		{name: "excessive depth", document: deep, want: ErrInvalidEvidenceDocument},
		{name: "excessive tokens", document: manyTokens, want: ErrInvalidEvidenceDocument},
		{name: "oversized", document: bytes.Repeat([]byte{' '}, 65_537), want: ErrEvidenceDocumentTooLarge},
		{name: "unsupported envelope", document: encodeEvidenceDocument(t, fixture.evidence, func(document *evidenceDocumentFixture) {
			document.SchemaVersion = 2
		}), want: ErrInvalidEvidenceDocument},
		{name: "wrong algorithm", document: encodeEvidenceDocument(t, fixture.evidence, func(document *evidenceDocumentFixture) {
			document.Algorithm = "rsa"
		}), want: ErrInvalidEvidenceDocument},
		{name: "malformed signature", document: encodeEvidenceDocument(t, fixture.evidence, func(document *evidenceDocumentFixture) {
			document.Signature = "not-base64"
		}), want: ErrInvalidEvidenceDocument},
		{name: "short signature", document: encodeEvidenceDocument(t, fixture.evidence, func(document *evidenceDocumentFixture) {
			document.Signature = base64.StdEncoding.EncodeToString([]byte{1})
		}), want: ErrInvalidEvidenceDocument},
		{name: "noncanonical signature", document: encodeEvidenceDocument(t, fixture.evidence, func(document *evidenceDocumentFixture) {
			document.Signature = document.Signature[:4] + "\n" + document.Signature[4:]
		}), want: ErrInvalidEvidenceDocument},
		{name: "missing signature padding", document: encodeEvidenceDocument(t, fixture.evidence, func(document *evidenceDocumentFixture) {
			document.Signature = strings.TrimRight(document.Signature, "=")
		}), want: ErrInvalidEvidenceDocument},
		{name: "extra signature padding", document: encodeEvidenceDocument(t, fixture.evidence, func(document *evidenceDocumentFixture) {
			document.Signature += "="
		}), want: ErrInvalidEvidenceDocument},
		{name: "invalid descriptor", document: encodeEvidenceDocument(t, fixture.evidence, func(document *evidenceDocumentFixture) {
			document.Descriptor.ProductionEligible = false
		}), want: ErrInvalidEvidenceDocument},
		{name: "zero probe epoch", document: encodeEvidenceDocument(t, fixture.evidence, func(document *evidenceDocumentFixture) {
			document.Descriptor.ProbeEpoch = 0
		}), want: ErrInvalidEvidenceDocument},
		{name: "unsorted atomic groups", document: encodeEvidenceDocument(t, fixture.evidence, func(document *evidenceDocumentFixture) {
			document.Descriptor.AtomicGroups = []AtomicGroup{AtomicEffectLifecycle, AtomicCommandReceipt}
		}), want: ErrInvalidEvidenceDocument},
		{name: "duplicate atomic groups", document: encodeEvidenceDocument(t, fixture.evidence, func(document *evidenceDocumentFixture) {
			document.Descriptor.AtomicGroups = []AtomicGroup{AtomicCommandReceipt, AtomicCommandReceipt}
		}), want: ErrInvalidEvidenceDocument},
		{name: "too many atomic groups", document: encodeEvidenceDocument(t, fixture.evidence, func(document *evidenceDocumentFixture) {
			document.Descriptor.AtomicGroups = make([]AtomicGroup, 65)
			for index := range document.Descriptor.AtomicGroups {
				document.Descriptor.AtomicGroups[index] = AtomicGroup(fmt.Sprintf("group-%02d", index))
			}
		}), want: ErrInvalidEvidenceDocument},
		{name: "invalid evidence key ID", document: encodeEvidenceDocument(t, fixture.evidence, func(document *evidenceDocumentFixture) {
			document.KeyID = " invalid"
		}), want: ErrInvalidEvidenceDocument},
		{name: "zero issue time", document: encodeEvidenceDocument(t, fixture.evidence, func(document *evidenceDocumentFixture) {
			document.IssuedAtUnix = 0
		}), want: ErrInvalidEvidenceDocument},
		{name: "nonincreasing expiry", document: encodeEvidenceDocument(t, fixture.evidence, func(document *evidenceDocumentFixture) {
			document.ExpiresAtUnix = document.IssuedAtUnix
		}), want: ErrInvalidEvidenceDocument},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			loaded, err := DecodeEvidence(bytes.NewReader(test.document))
			if !errors.Is(err, test.want) || loaded.Descriptor.SchemaVersion != 0 ||
				loaded.IssuedAtUnix != 0 || loaded.ExpiresAtUnix != 0 || loaded.KeyID != "" || loaded.Signature != nil {
				t.Fatalf("DecodeEvidence() evidence/error = %#v/%v, want zero/%v", loaded, err, test.want)
			}
			if len(test.document) > 0 && strings.Contains(err.Error(), string(test.document)) {
				t.Fatal("DecodeEvidence() disclosed the complete rejected document")
			}
		})
	}
	var nilReader *bytes.Reader
	if _, err := DecodeEvidence(nilReader); !errors.Is(err, ErrInvalidEvidenceDocument) {
		t.Fatalf("DecodeEvidence(typed nil) error = %v", err)
	}
	if _, err := DecodeEvidence(failingProductionDocumentReader{}); !errors.Is(err, ErrInvalidEvidenceDocument) {
		t.Fatalf("DecodeEvidence(read failure) error = %v", err)
	}
}

func TestDecodeTrustRootsRequiresTheExpectedRoleAndReturnsCopies(t *testing.T) {
	t.Parallel()

	first := deterministicTestPublicKey(0x11)
	second := deterministicTestPublicKey(0x22)
	roots := []trustRootDocumentFixture{
		{KeyID: "conformance-root-1", Algorithm: "ed25519", PublicKey: base64.StdEncoding.EncodeToString(first)},
		{KeyID: "conformance-root-2", Algorithm: "ed25519", PublicKey: base64.StdEncoding.EncodeToString(second)},
	}
	encoded := encodeTrustRootsDocument(t, TrustDomainConformanceEvidence, roots, nil)
	originalDocument := append([]byte(nil), encoded...)
	loaded, err := DecodeTrustRoots(bytes.NewReader(encoded), TrustDomainConformanceEvidence)
	if err != nil {
		t.Fatalf("DecodeTrustRoots() error = %v", err)
	}
	if len(loaded) != 2 || !bytes.Equal(loaded[roots[0].KeyID], first) || !bytes.Equal(loaded[roots[1].KeyID], second) {
		t.Fatalf("DecodeTrustRoots() = %#v", loaded)
	}
	for index := range encoded {
		encoded[index] ^= 0xff
	}
	if !bytes.Equal(loaded[roots[0].KeyID], first) || !bytes.Equal(loaded[roots[1].KeyID], second) {
		t.Fatal("DecodeTrustRoots() result was aliased with the encoded input")
	}
	loaded[roots[0].KeyID][0] ^= 0xff
	again, err := DecodeTrustRoots(
		bytes.NewReader(originalDocument),
		TrustDomainConformanceEvidence,
	)
	if err != nil {
		t.Fatalf("DecodeTrustRoots(second) error = %v", err)
	}
	if !bytes.Equal(again[roots[0].KeyID], first) {
		t.Fatal("DecodeTrustRoots() returned key material aliased with input or a prior result")
	}

	runtimeDocument := encodeTrustRootsDocument(t, TrustDomainRuntimeProbe, []trustRootDocumentFixture{{
		KeyID: "runtime-root-1", Algorithm: "ed25519", PublicKey: base64.StdEncoding.EncodeToString(first),
	}}, nil)
	if _, err := DecodeTrustRoots(bytes.NewReader(runtimeDocument), TrustDomainConformanceEvidence); !errors.Is(err, ErrInvalidTrustRootsDocument) {
		t.Fatalf("DecodeTrustRoots(wrong role) error = %v", err)
	}
	if _, err := DecodeTrustRoots(bytes.NewReader(runtimeDocument), TrustDomainRuntimeProbe); err != nil {
		t.Fatalf("DecodeTrustRoots(runtime role) error = %v", err)
	}
}

func TestDecodeTrustRootsRejectsAmbiguousUnboundedOrInvalidDocuments(t *testing.T) {
	t.Parallel()

	validRoot := trustRootDocumentFixture{
		KeyID: "conformance-root-1", Algorithm: "ed25519",
		PublicKey: base64.StdEncoding.EncodeToString(deterministicTestPublicKey(0x31)),
	}
	identity := make(ed25519.PublicKey, ed25519.PublicKeySize)
	identity[0] = 1
	nonCanonicalIdentity := append(ed25519.PublicKey(nil), identity...)
	nonCanonicalIdentity[ed25519.PublicKeySize-1] = 0x80
	orderTwo := make(ed25519.PublicKey, ed25519.PublicKeySize)
	for index := range orderTwo {
		orderTwo[index] = 0xff
	}
	orderTwo[0] = 0xec
	orderTwo[ed25519.PublicKeySize-1] = 0x7f
	valid := encodeTrustRootsDocument(t, TrustDomainConformanceEvidence, []trustRootDocumentFixture{validRoot}, nil)
	unknownRoot := append([]byte(nil), valid[:len(valid)-1]...)
	unknownRoot = append(unknownRoot, []byte(`,"extra":true}`)...)
	duplicateRoot := bytes.Replace(valid, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1,"schemaVersion":1`), 1)
	unknownEntry := bytes.Replace(valid, []byte(`"algorithm":"ed25519"`), []byte(`"algorithm":"ed25519","extra":true`), 1)
	duplicateEntry := bytes.Replace(valid, []byte(`"algorithm":"ed25519"`), []byte(`"algorithm":"ed25519","algorithm":"ed25519"`), 1)
	trailing := append(append([]byte(nil), valid...), []byte(` {}`)...)
	deep := []byte(`{"schemaVersion":1,"trustDomain":"conformance-evidence","roots":` + strings.Repeat("[", 40) + `0` + strings.Repeat("]", 40) + `}`)
	manyTokens := []byte(`{"roots":[` + strings.Repeat("0,", 5_000) + `0]}`)
	caseAlias := bytes.Replace(valid, []byte(`"keyId"`), []byte(`"KeyID"`), 1)
	dualCaseAlias := bytes.Replace(valid, []byte(`"keyId":"conformance-root-1"`), []byte(`"keyId":"conformance-root-1","KeyID":"runtime-root"`), 1)
	missingPublicKey := bytes.Replace(valid, []byte(`,"publicKey":"`+validRoot.PublicKey+`"`), nil, 1)
	nullPublicKey := bytes.Replace(valid, []byte(`"publicKey":"`+validRoot.PublicKey+`"`), []byte(`"publicKey":null`), 1)
	maximumRoots := make([]trustRootDocumentFixture, 64)
	for index := range maximumRoots {
		maximumRoots[index] = trustRootDocumentFixture{
			KeyID:     fmt.Sprintf("conformance-root-%02d", index),
			Algorithm: "ed25519",
			PublicKey: base64.StdEncoding.EncodeToString(deterministicTestPublicKey(byte(index))),
		}
	}
	if roots, err := DecodeTrustRoots(
		bytes.NewReader(encodeTrustRootsDocument(t, TrustDomainConformanceEvidence, maximumRoots, nil)),
		TrustDomainConformanceEvidence,
	); err != nil || len(roots) != 64 {
		t.Fatalf("DecodeTrustRoots(64 roots) len/error = %d/%v", len(roots), err)
	}
	tooManyRoots := append(append([]trustRootDocumentFixture(nil), maximumRoots...), trustRootDocumentFixture{
		KeyID: "conformance-root-overflow", Algorithm: "ed25519", PublicKey: validRoot.PublicKey,
	})
	tests := []struct {
		name     string
		document []byte
		want     error
	}{
		{name: "empty", document: nil, want: ErrInvalidTrustRootsDocument},
		{name: "whitespace", document: []byte(" \n\t"), want: ErrInvalidTrustRootsDocument},
		{name: "unknown root member", document: unknownRoot, want: ErrInvalidTrustRootsDocument},
		{name: "duplicate root member", document: duplicateRoot, want: ErrInvalidTrustRootsDocument},
		{name: "unknown root entry member", document: unknownEntry, want: ErrInvalidTrustRootsDocument},
		{name: "duplicate root entry member", document: duplicateEntry, want: ErrInvalidTrustRootsDocument},
		{name: "trailing value", document: trailing, want: ErrInvalidTrustRootsDocument},
		{name: "non-object", document: []byte(`[]`), want: ErrInvalidTrustRootsDocument},
		{name: "null document", document: []byte(`null`), want: ErrInvalidTrustRootsDocument},
		{name: "case alias", document: caseAlias, want: ErrInvalidTrustRootsDocument},
		{name: "dual case alias", document: dualCaseAlias, want: ErrInvalidTrustRootsDocument},
		{name: "missing required member", document: missingPublicKey, want: ErrInvalidTrustRootsDocument},
		{name: "null required member", document: nullPublicKey, want: ErrInvalidTrustRootsDocument},
		{name: "excessive depth", document: deep, want: ErrInvalidTrustRootsDocument},
		{name: "excessive tokens", document: manyTokens, want: ErrInvalidTrustRootsDocument},
		{name: "oversized", document: bytes.Repeat([]byte{' '}, 1_048_577), want: ErrTrustRootsDocumentTooLarge},
		{name: "unsupported envelope", document: encodeTrustRootsDocument(t, TrustDomainConformanceEvidence, []trustRootDocumentFixture{validRoot}, func(document *trustRootsDocumentFixture) {
			document.SchemaVersion = 2
		}), want: ErrInvalidTrustRootsDocument},
		{name: "empty roots", document: encodeTrustRootsDocument(t, TrustDomainConformanceEvidence, nil, nil), want: ErrInvalidTrustRootsDocument},
		{name: "too many roots", document: encodeTrustRootsDocument(t, TrustDomainConformanceEvidence, tooManyRoots, nil), want: ErrInvalidTrustRootsDocument},
		{name: "duplicate key ID", document: encodeTrustRootsDocument(t, TrustDomainConformanceEvidence, []trustRootDocumentFixture{validRoot, validRoot}, nil), want: ErrInvalidTrustRootsDocument},
		{name: "duplicate key material", document: encodeTrustRootsDocument(t, TrustDomainConformanceEvidence, []trustRootDocumentFixture{validRoot, {
			KeyID: "conformance-root-2", Algorithm: "ed25519", PublicKey: validRoot.PublicKey,
		}}, nil), want: ErrInvalidTrustRootsDocument},
		{name: "invalid key ID", document: encodeTrustRootsDocument(t, TrustDomainConformanceEvidence, []trustRootDocumentFixture{{
			KeyID: " invalid", Algorithm: "ed25519", PublicKey: validRoot.PublicKey,
		}}, nil), want: ErrInvalidTrustRootsDocument},
		{name: "wrong algorithm", document: encodeTrustRootsDocument(t, TrustDomainConformanceEvidence, []trustRootDocumentFixture{{
			KeyID: validRoot.KeyID, Algorithm: "rsa", PublicKey: validRoot.PublicKey,
		}}, nil), want: ErrInvalidTrustRootsDocument},
		{name: "malformed public key", document: encodeTrustRootsDocument(t, TrustDomainConformanceEvidence, []trustRootDocumentFixture{{
			KeyID: validRoot.KeyID, Algorithm: "ed25519", PublicKey: "not-base64",
		}}, nil), want: ErrInvalidTrustRootsDocument},
		{name: "short public key", document: encodeTrustRootsDocument(t, TrustDomainConformanceEvidence, []trustRootDocumentFixture{{
			KeyID: validRoot.KeyID, Algorithm: "ed25519", PublicKey: base64.StdEncoding.EncodeToString([]byte{1}),
		}}, nil), want: ErrInvalidTrustRootsDocument},
		{name: "noncanonical public key", document: encodeTrustRootsDocument(t, TrustDomainConformanceEvidence, []trustRootDocumentFixture{{
			KeyID: validRoot.KeyID, Algorithm: "ed25519", PublicKey: validRoot.PublicKey[:4] + "\n" + validRoot.PublicKey[4:],
		}}, nil), want: ErrInvalidTrustRootsDocument},
		{name: "missing public key padding", document: encodeTrustRootsDocument(t, TrustDomainConformanceEvidence, []trustRootDocumentFixture{{
			KeyID: validRoot.KeyID, Algorithm: "ed25519", PublicKey: strings.TrimRight(validRoot.PublicKey, "="),
		}}, nil), want: ErrInvalidTrustRootsDocument},
		{name: "extra public key padding", document: encodeTrustRootsDocument(t, TrustDomainConformanceEvidence, []trustRootDocumentFixture{{
			KeyID: validRoot.KeyID, Algorithm: "ed25519", PublicKey: validRoot.PublicKey + "=",
		}}, nil), want: ErrInvalidTrustRootsDocument},
		{name: "URL public key alphabet", document: encodeTrustRootsDocument(t, TrustDomainConformanceEvidence, []trustRootDocumentFixture{{
			KeyID: validRoot.KeyID, Algorithm: "ed25519",
			PublicKey: base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, ed25519.PublicKeySize)),
		}}, nil), want: ErrInvalidTrustRootsDocument},
		{name: "identity public key", document: encodeTrustRootsDocument(t, TrustDomainConformanceEvidence, []trustRootDocumentFixture{{
			KeyID: validRoot.KeyID, Algorithm: "ed25519", PublicKey: base64.StdEncoding.EncodeToString(identity),
		}}, nil), want: ErrInvalidTrustRootsDocument},
		{name: "noncanonical identity public key", document: encodeTrustRootsDocument(t, TrustDomainConformanceEvidence, []trustRootDocumentFixture{{
			KeyID: validRoot.KeyID, Algorithm: "ed25519", PublicKey: base64.StdEncoding.EncodeToString(nonCanonicalIdentity),
		}}, nil), want: ErrInvalidTrustRootsDocument},
		{name: "order two public key", document: encodeTrustRootsDocument(t, TrustDomainConformanceEvidence, []trustRootDocumentFixture{{
			KeyID: validRoot.KeyID, Algorithm: "ed25519", PublicKey: base64.StdEncoding.EncodeToString(orderTwo),
		}}, nil), want: ErrInvalidTrustRootsDocument},
		{name: "order four public key", document: encodeTrustRootsDocument(t, TrustDomainConformanceEvidence, []trustRootDocumentFixture{{
			KeyID: validRoot.KeyID, Algorithm: "ed25519", PublicKey: base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)),
		}}, nil), want: ErrInvalidTrustRootsDocument},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			roots, err := DecodeTrustRoots(bytes.NewReader(test.document), TrustDomainConformanceEvidence)
			if !errors.Is(err, test.want) || roots != nil {
				t.Fatalf("DecodeTrustRoots() roots/error = %#v/%v, want nil/%v", roots, err, test.want)
			}
			if len(test.document) > 0 && strings.Contains(err.Error(), string(test.document)) {
				t.Fatal("DecodeTrustRoots() disclosed the complete rejected document")
			}
		})
	}
	for _, domain := range []TrustDomain{"", "release", "conformance_evidence"} {
		if _, err := DecodeTrustRoots(bytes.NewReader(valid), domain); !errors.Is(err, ErrInvalidTrustRootsDocument) {
			t.Fatalf("DecodeTrustRoots(domain %q) error = %v", domain, err)
		}
	}
	var nilReader *bytes.Reader
	if _, err := DecodeTrustRoots(nilReader, TrustDomainConformanceEvidence); !errors.Is(err, ErrInvalidTrustRootsDocument) {
		t.Fatalf("DecodeTrustRoots(typed nil) error = %v", err)
	}
	if _, err := DecodeTrustRoots(failingProductionDocumentReader{}, TrustDomainConformanceEvidence); !errors.Is(err, ErrInvalidTrustRootsDocument) {
		t.Fatalf("DecodeTrustRoots(read failure) error = %v", err)
	}
}

func TestProductionJSONScannerEnforcesDepthAndTokenBoundaries(t *testing.T) {
	t.Parallel()

	exactDepth := []byte(strings.Repeat("[", maximumProductionJSONDepth) + "0" + strings.Repeat("]", maximumProductionJSONDepth))
	excessiveDepth := []byte(strings.Repeat("[", maximumProductionJSONDepth+1) + "0" + strings.Repeat("]", maximumProductionJSONDepth+1))
	exactTokenCount := []byte("[" + strings.Repeat("0,", maximumProductionJSONTokens-3) + "0]")
	excessiveTokenCount := []byte("[" + strings.Repeat("0,", maximumProductionJSONTokens-2) + "0]")
	tests := []struct {
		name     string
		document []byte
		want     bool
	}{
		{name: "exact depth", document: exactDepth, want: true},
		{name: "excessive depth", document: excessiveDepth, want: false},
		{name: "exact token count", document: exactTokenCount, want: true},
		{name: "excessive token count", document: excessiveTokenCount, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := scanProductionJSON(test.document); got != test.want {
				t.Fatalf("scanProductionJSON() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestProductionDocumentDecodersAreSafeForConcurrentReaders(t *testing.T) {
	t.Parallel()

	fixture := newVerificationFixture(t, "state-domain-a")
	evidenceDocument := encodeEvidenceDocument(t, fixture.evidence, nil)
	rootDocument := encodeTrustRootsDocument(t, TrustDomainConformanceEvidence, []trustRootDocumentFixture{{
		KeyID: fixture.evidence.KeyID, Algorithm: "ed25519",
		PublicKey: base64.StdEncoding.EncodeToString(fixture.conformancePublicKey),
	}}, nil)
	const readers = 64
	start := make(chan struct{})
	errorsSeen := make(chan error, readers)
	var ready sync.WaitGroup
	ready.Add(readers)
	for range readers {
		go func() {
			ready.Done()
			<-start
			loadedEvidence, err := DecodeEvidence(bytes.NewReader(evidenceDocument))
			if err == nil && !bytes.Equal(loadedEvidence.Signature, fixture.evidence.Signature) {
				err = errors.New("concurrent evidence decode returned the wrong signature")
			}
			if err == nil {
				roots, rootErr := DecodeTrustRoots(bytes.NewReader(rootDocument), TrustDomainConformanceEvidence)
				err = rootErr
				if err == nil && !bytes.Equal(roots[fixture.evidence.KeyID], fixture.conformancePublicKey) {
					err = errors.New("concurrent root decode returned the wrong key")
				}
			}
			errorsSeen <- err
		}()
	}
	ready.Wait()
	close(start)
	for range readers {
		if err := <-errorsSeen; err != nil {
			t.Fatalf("concurrent production document decode error = %v", err)
		}
	}
}

func deterministicTestPublicKey(seedByte byte) ed25519.PublicKey {
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seedByte}, ed25519.SeedSize))
	return append(ed25519.PublicKey(nil), privateKey[ed25519.SeedSize:]...)
}

type descriptorDocumentFixture struct {
	SchemaVersion       uint32        `json:"schemaVersion"`
	BackendKind         string        `json:"backendKind"`
	BuildDigest         string        `json:"buildDigest"`
	ApplicationDigest   string        `json:"applicationDigest"`
	InstanceID          string        `json:"instanceId"`
	TransactionDomainID string        `json:"transactionDomainId"`
	DurabilityClass     string        `json:"durabilityClass"`
	ConformanceRunID    string        `json:"conformanceRunId"`
	ConformanceDigest   string        `json:"conformanceDigest"`
	RuntimeKeyID        string        `json:"runtimeKeyId"`
	ProbeEpoch          uint64        `json:"probeEpoch"`
	ProductionEligible  bool          `json:"productionEligible"`
	AtomicGroups        []AtomicGroup `json:"atomicGroups"`
}

type evidenceDocumentFixture struct {
	SchemaVersion uint32                    `json:"schemaVersion"`
	Descriptor    descriptorDocumentFixture `json:"descriptor"`
	IssuedAtUnix  int64                     `json:"issuedAtUnix"`
	ExpiresAtUnix int64                     `json:"expiresAtUnix"`
	KeyID         string                    `json:"keyId"`
	Algorithm     string                    `json:"algorithm"`
	Signature     string                    `json:"signature"`
}

type trustRootsDocumentFixture struct {
	SchemaVersion uint32                     `json:"schemaVersion"`
	TrustDomain   TrustDomain                `json:"trustDomain"`
	Roots         []trustRootDocumentFixture `json:"roots"`
}

type trustRootDocumentFixture struct {
	KeyID     string `json:"keyId"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"publicKey"`
}

func encodeEvidenceDocument(t *testing.T, evidence Evidence, edit func(*evidenceDocumentFixture)) []byte {
	t.Helper()
	descriptor := evidence.Descriptor
	document := evidenceDocumentFixture{
		SchemaVersion: 1,
		Descriptor: descriptorDocumentFixture{
			SchemaVersion: descriptor.SchemaVersion, BackendKind: descriptor.BackendKind,
			BuildDigest: descriptor.BuildDigest, ApplicationDigest: descriptor.ApplicationDigest,
			InstanceID: descriptor.InstanceID, TransactionDomainID: descriptor.TransactionDomainID,
			DurabilityClass: descriptor.DurabilityClass, ConformanceRunID: descriptor.ConformanceRunID,
			ConformanceDigest: descriptor.ConformanceDigest, RuntimeKeyID: descriptor.RuntimeKeyID,
			ProbeEpoch: descriptor.ProbeEpoch, ProductionEligible: descriptor.ProductionEligible,
			AtomicGroups: append([]AtomicGroup(nil), descriptor.AtomicGroups...),
		},
		IssuedAtUnix: evidence.IssuedAtUnix, ExpiresAtUnix: evidence.ExpiresAtUnix,
		KeyID: evidence.KeyID, Algorithm: "ed25519",
		Signature: base64.StdEncoding.EncodeToString(evidence.Signature),
	}
	if edit != nil {
		edit(&document)
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("Marshal(evidence document) error = %v", err)
	}
	return encoded
}

func encodeTrustRootsDocument(
	t *testing.T,
	domain TrustDomain,
	roots []trustRootDocumentFixture,
	edit func(*trustRootsDocumentFixture),
) []byte {
	t.Helper()
	document := trustRootsDocumentFixture{
		SchemaVersion: 1,
		TrustDomain:   domain,
		Roots:         append([]trustRootDocumentFixture(nil), roots...),
	}
	if edit != nil {
		edit(&document)
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("Marshal(trust roots document) error = %v", err)
	}
	return encoded
}

type failingProductionDocumentReader struct{}

func (failingProductionDocumentReader) Read([]byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}
