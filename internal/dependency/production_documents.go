package dependency

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

const (
	maximumEvidenceDocumentBytes   = 64 << 10
	maximumTrustRootsDocumentBytes = 1 << 20
	maximumProductionJSONDepth     = 32
	maximumProductionJSONTokens    = 4_096
	maximumProductionTrustRoots    = 64
	maximumEvidenceAtomicGroups    = 64
)

var (
	ErrInvalidEvidenceDocument    = errors.New("dependency: invalid production evidence document")
	ErrEvidenceDocumentTooLarge   = errors.New("dependency: production evidence document is too large")
	ErrInvalidTrustRootsDocument  = errors.New("dependency: invalid production trust-roots document")
	ErrTrustRootsDocumentTooLarge = errors.New("dependency: production trust-roots document is too large")
)

type TrustDomain string

const (
	TrustDomainConformanceEvidence TrustDomain = "conformance-evidence"
	TrustDomainRuntimeProbe        TrustDomain = "runtime-probe"
)

type productionJSONContainer struct {
	kind         json.Delim
	keys         map[string]struct{}
	expectingKey bool
}

// DecodeEvidence performs bounded document and descriptor validation. It does
// not establish signer trust, freshness, deployment requirements, or liveness;
// callers must still pass its result to VerifyDependency.
func DecodeEvidence(reader io.Reader) (Evidence, error) {
	encoded, err := readProductionDocument(
		reader,
		maximumEvidenceDocumentBytes,
		ErrInvalidEvidenceDocument,
		ErrEvidenceDocumentTooLarge,
	)
	if err != nil {
		return Evidence{}, err
	}
	if !scanProductionJSON(encoded) {
		return Evidence{}, ErrInvalidEvidenceDocument
	}
	document, ok := decodeJSONObject(encoded)
	if !ok || !hasExactMembers(document, []string{
		"schemaVersion", "descriptor", "issuedAtUnix", "expiresAtUnix", "keyId", "algorithm", "signature",
	}) {
		return Evidence{}, ErrInvalidEvidenceDocument
	}
	var envelopeSchemaVersion uint32
	var issuedAtUnix int64
	var expiresAtUnix int64
	var keyID string
	var algorithm string
	var encodedSignature string
	if !decodeJSONMember(document, "schemaVersion", &envelopeSchemaVersion) || envelopeSchemaVersion != 1 ||
		!decodeJSONMember(document, "issuedAtUnix", &issuedAtUnix) ||
		!decodeJSONMember(document, "expiresAtUnix", &expiresAtUnix) ||
		!decodeJSONMember(document, "keyId", &keyID) ||
		!decodeJSONMember(document, "algorithm", &algorithm) || algorithm != "ed25519" ||
		!decodeJSONMember(document, "signature", &encodedSignature) {
		return Evidence{}, ErrInvalidEvidenceDocument
	}
	descriptorDocument, ok := decodeRawJSONObject(document["descriptor"])
	if !ok || !hasExactMembers(descriptorDocument, []string{
		"schemaVersion", "backendKind", "buildDigest", "applicationDigest", "instanceId",
		"transactionDomainId", "durabilityClass", "conformanceRunId", "conformanceDigest",
		"runtimeKeyId", "probeEpoch", "productionEligible", "atomicGroups",
	}) {
		return Evidence{}, ErrInvalidEvidenceDocument
	}
	var descriptor Descriptor
	if !decodeJSONMember(descriptorDocument, "schemaVersion", &descriptor.SchemaVersion) ||
		!decodeJSONMember(descriptorDocument, "backendKind", &descriptor.BackendKind) ||
		!decodeJSONMember(descriptorDocument, "buildDigest", &descriptor.BuildDigest) ||
		!decodeJSONMember(descriptorDocument, "applicationDigest", &descriptor.ApplicationDigest) ||
		!decodeJSONMember(descriptorDocument, "instanceId", &descriptor.InstanceID) ||
		!decodeJSONMember(descriptorDocument, "transactionDomainId", &descriptor.TransactionDomainID) ||
		!decodeJSONMember(descriptorDocument, "durabilityClass", &descriptor.DurabilityClass) ||
		!decodeJSONMember(descriptorDocument, "conformanceRunId", &descriptor.ConformanceRunID) ||
		!decodeJSONMember(descriptorDocument, "conformanceDigest", &descriptor.ConformanceDigest) ||
		!decodeJSONMember(descriptorDocument, "runtimeKeyId", &descriptor.RuntimeKeyID) ||
		!decodeJSONMember(descriptorDocument, "probeEpoch", &descriptor.ProbeEpoch) ||
		!decodeJSONMember(descriptorDocument, "productionEligible", &descriptor.ProductionEligible) ||
		!decodeJSONMember(descriptorDocument, "atomicGroups", &descriptor.AtomicGroups) ||
		len(descriptor.AtomicGroups) > maximumEvidenceAtomicGroups {
		return Evidence{}, ErrInvalidEvidenceDocument
	}
	signature, ok := decodeCanonicalBase64(encodedSignature, ed25519.SignatureSize)
	if !ok {
		return Evidence{}, ErrInvalidEvidenceDocument
	}
	evidence := Evidence{
		Descriptor:    descriptor,
		IssuedAtUnix:  issuedAtUnix,
		ExpiresAtUnix: expiresAtUnix,
		KeyID:         keyID,
		Signature:     signature,
	}
	if _, err := EvidenceSigningDigest(evidence); err != nil {
		return Evidence{}, ErrInvalidEvidenceDocument
	}
	return evidence, nil
}

// DecodeTrustRoots validates a role-tagged, bounded Ed25519 trust-root
// document and returns detached key material for NewVerifier.
func DecodeTrustRoots(reader io.Reader, expectedDomain TrustDomain) (map[string]ed25519.PublicKey, error) {
	if expectedDomain != TrustDomainConformanceEvidence && expectedDomain != TrustDomainRuntimeProbe {
		return nil, ErrInvalidTrustRootsDocument
	}
	encoded, err := readProductionDocument(
		reader,
		maximumTrustRootsDocumentBytes,
		ErrInvalidTrustRootsDocument,
		ErrTrustRootsDocumentTooLarge,
	)
	if err != nil {
		return nil, err
	}
	if !scanProductionJSON(encoded) {
		return nil, ErrInvalidTrustRootsDocument
	}
	document, ok := decodeJSONObject(encoded)
	if !ok || !hasExactMembers(document, []string{"schemaVersion", "trustDomain", "roots"}) {
		return nil, ErrInvalidTrustRootsDocument
	}
	var schemaVersion uint32
	var trustDomain TrustDomain
	var rootDocuments []json.RawMessage
	if !decodeJSONMember(document, "schemaVersion", &schemaVersion) || schemaVersion != 1 ||
		!decodeJSONMember(document, "trustDomain", &trustDomain) || trustDomain != expectedDomain ||
		!decodeJSONMember(document, "roots", &rootDocuments) ||
		len(rootDocuments) == 0 || len(rootDocuments) > maximumProductionTrustRoots {
		return nil, ErrInvalidTrustRootsDocument
	}
	roots := make(map[string]ed25519.PublicKey, len(rootDocuments))
	materials := make(map[[ed25519.PublicKeySize]byte]struct{}, len(rootDocuments))
	for _, encodedRoot := range rootDocuments {
		rootDocument, ok := decodeRawJSONObject(encodedRoot)
		if !ok || !hasExactMembers(rootDocument, []string{"keyId", "algorithm", "publicKey"}) {
			return nil, ErrInvalidTrustRootsDocument
		}
		var keyID string
		var algorithm string
		var encodedPublicKey string
		if !decodeJSONMember(rootDocument, "keyId", &keyID) || !identifierPattern.MatchString(keyID) ||
			!decodeJSONMember(rootDocument, "algorithm", &algorithm) || algorithm != "ed25519" ||
			!decodeJSONMember(rootDocument, "publicKey", &encodedPublicKey) {
			return nil, ErrInvalidTrustRootsDocument
		}
		publicKey, ok := decodeCanonicalBase64(encodedPublicKey, ed25519.PublicKeySize)
		if !ok {
			return nil, ErrInvalidTrustRootsDocument
		}
		material, valid := canonicalPrimeOrderEd25519Key(publicKey)
		if !valid {
			return nil, ErrInvalidTrustRootsDocument
		}
		if _, duplicate := roots[keyID]; duplicate {
			return nil, ErrInvalidTrustRootsDocument
		}
		if _, duplicate := materials[material]; duplicate {
			return nil, ErrInvalidTrustRootsDocument
		}
		materials[material] = struct{}{}
		roots[keyID] = append(ed25519.PublicKey(nil), material[:]...)
	}
	return roots, nil
}

func readProductionDocument(reader io.Reader, maximumBytes int64, invalidError, tooLargeError error) ([]byte, error) {
	if interfaceNil(reader) {
		return nil, invalidError
	}
	encoded, err := io.ReadAll(io.LimitReader(reader, maximumBytes+1))
	if int64(len(encoded)) > maximumBytes {
		return nil, errors.Join(invalidError, tooLargeError)
	}
	if err != nil || len(encoded) == 0 || !utf8.Valid(encoded) {
		return nil, invalidError
	}
	return encoded, nil
}

func scanProductionJSON(encoded []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	containers := make([]productionJSONContainer, 0, 8)
	rootValues := 0
	tokens := 0
	completeValue := func() {
		if len(containers) == 0 {
			rootValues++
			return
		}
		current := &containers[len(containers)-1]
		if current.kind == '{' && !current.expectingKey {
			current.expectingKey = true
		}
	}
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return false
		}
		tokens++
		if tokens > maximumProductionJSONTokens {
			return false
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{':
				if len(containers) >= maximumProductionJSONDepth {
					return false
				}
				containers = append(containers, productionJSONContainer{
					kind: delimiter, keys: make(map[string]struct{}), expectingKey: true,
				})
			case '[':
				if len(containers) >= maximumProductionJSONDepth {
					return false
				}
				containers = append(containers, productionJSONContainer{kind: delimiter})
			case '}', ']':
				if len(containers) == 0 || containers[len(containers)-1].kind+2 != delimiter {
					return false
				}
				containers = containers[:len(containers)-1]
				completeValue()
			default:
				return false
			}
			continue
		}
		if len(containers) > 0 {
			current := &containers[len(containers)-1]
			if current.kind == '{' && current.expectingKey {
				key, ok := token.(string)
				if !ok {
					return false
				}
				if _, duplicate := current.keys[key]; duplicate {
					return false
				}
				current.keys[key] = struct{}{}
				current.expectingKey = false
				continue
			}
		}
		completeValue()
	}
	return len(containers) == 0 && rootValues == 1
}

func decodeJSONObject(encoded []byte) (map[string]json.RawMessage, bool) {
	var document map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	if err := decoder.Decode(&document); err != nil || document == nil {
		return nil, false
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, false
	}
	return document, true
}

func decodeRawJSONObject(encoded json.RawMessage) (map[string]json.RawMessage, bool) {
	if bytes.Equal(bytes.TrimSpace(encoded), []byte("null")) {
		return nil, false
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &document); err != nil || document == nil {
		return nil, false
	}
	return document, true
}

func hasExactMembers(document map[string]json.RawMessage, required []string) bool {
	if len(document) != len(required) {
		return false
	}
	for _, name := range required {
		encoded, present := document[name]
		if !present || bytes.Equal(bytes.TrimSpace(encoded), []byte("null")) {
			return false
		}
	}
	return true
}

func decodeJSONMember(document map[string]json.RawMessage, name string, destination any) bool {
	encoded, present := document[name]
	if !present || bytes.Equal(bytes.TrimSpace(encoded), []byte("null")) {
		return false
	}
	return json.Unmarshal(encoded, destination) == nil
}

func decodeCanonicalBase64(encoded string, expectedBytes int) ([]byte, bool) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) != expectedBytes || base64.StdEncoding.EncodeToString(decoded) != encoded {
		clear(decoded)
		return nil, false
	}
	return decoded, true
}
