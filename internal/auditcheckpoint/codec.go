package auditcheckpoint

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"regexp"

	"github.com/hancomac/circulusd/internal/authstate"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/dependency"
	"github.com/hancomac/circulusd/internal/ed25519key"
	"github.com/hancomac/circulusd/internal/identity"
)

const (
	MaximumCheckpointBytes  = 8192
	maximumAuditStateBytes  = 16 << 20
	maximumAuditSequence    = 65_536
	checkpointProtocol      = "circulus.audit-checkpoint.v1"
	checkpointSigningDomain = "circulusd.auth.audit-checkpoint"
	zeroHeadDigest          = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)

// SigningDigest validates canonical claims and derives their domain-separated
// digest. Native Signer implementations sign these exact 32 bytes with the
// independently pinned checkpoint key, not arbitrary application log content.
func SigningDigest(canonicalClaims []byte) ([32]byte, error) {
	claims, err := decodeClaims(canonicalClaims)
	if err != nil {
		return [32]byte{}, err
	}
	_, digest, err := signingPayload(claims)
	return digest, err
}

func signingPayload(claims Claims) ([]byte, [32]byte, error) {
	if !validClaims(claims) {
		return nil, [32]byte{}, ErrInvalidCheckpoint
	}
	value := claimsValue(claims)
	body, err := canonical.Encode(value, checkpointOptions())
	if err != nil {
		return nil, [32]byte{}, ErrInvalidCheckpoint
	}
	frame, err := canonical.Encode(canonical.Array{"circulusd.hash", int64(1), checkpointSigningDomain, int64(1), value}, checkpointOptions())
	if err != nil {
		return nil, [32]byte{}, ErrInvalidCheckpoint
	}
	return body, sha256.Sum256(frame), nil
}

func Verify(checkpoint Checkpoint, publicKey ed25519.PublicKey) error {
	if !ed25519key.IsCanonicalPrimeOrder(publicKey) || len(checkpoint.Signature) != ed25519.SignatureSize {
		return ErrInvalidCheckpoint
	}
	_, digest, err := signingPayload(checkpoint.Claims)
	if err != nil || digest != checkpoint.SigningDigest || !ed25519.Verify(publicKey, digest[:], checkpoint.Signature) {
		return ErrInvalidCheckpoint
	}
	return nil
}

func Encode(checkpoint Checkpoint) ([]byte, error) {
	claims, digest, err := signingPayload(checkpoint.Claims)
	if err != nil || digest != checkpoint.SigningDigest || len(checkpoint.Signature) != ed25519.SignatureSize {
		return nil, ErrInvalidCheckpoint
	}
	encoded, err := canonical.Encode(canonical.Map{"protocol": checkpointProtocol, "version": int64(1),
		"claims": canonical.Bytes(claims), "signingDigest": canonical.Bytes(digest[:]),
		"signature": canonical.Bytes(checkpoint.Signature)}, checkpointOptions())
	if err != nil {
		return nil, ErrInvalidCheckpoint
	}
	return encoded, nil
}

// Decode accepts only a bounded canonical frame and a genuine signature under
// the caller's pinned public key. A decoded checkpoint attests its historical
// snapshot; it never proves that a later live head or credential is unchanged.
func Decode(encoded []byte, publicKey ed25519.PublicKey) (Checkpoint, error) {
	value, err := canonical.Decode(encoded, checkpointOptions())
	if err != nil {
		return Checkpoint{}, ErrInvalidCheckpoint
	}
	m, ok := value.(canonical.Map)
	if !ok || len(m) != 5 || m["protocol"] != checkpointProtocol || m["version"] != int64(1) {
		return Checkpoint{}, ErrInvalidCheckpoint
	}
	body, bodyOK := m["claims"].(canonical.Bytes)
	digest, digestOK := m["signingDigest"].(canonical.Bytes)
	signature, signatureOK := m["signature"].(canonical.Bytes)
	if !bodyOK || !digestOK || len(digest) != 32 || !signatureOK || len(signature) != ed25519.SignatureSize {
		return Checkpoint{}, ErrInvalidCheckpoint
	}
	claims, err := decodeClaims(body)
	if err != nil {
		return Checkpoint{}, err
	}
	checkpoint := Checkpoint{Claims: claims, Signature: bytes.Clone(signature)}
	copy(checkpoint.SigningDigest[:], digest)
	if err := Verify(checkpoint, publicKey); err != nil {
		return Checkpoint{}, err
	}
	return checkpoint, nil
}

func claimsValue(c Claims) canonical.Map {
	return canonical.Map{"auditGroup": c.AuditGroup, "tenantId": c.TenantID, "objectId": c.ObjectID, "sourceInstanceId": c.SourceInstanceID,
		"transactionDomainId": c.TransactionDomainID, "sourceBuildDigest": c.SourceBuildDigest,
		"sourceApplicationDigest": c.SourceApplicationDigest, "headSequence": c.HeadSequence,
		"headDigest": c.HeadDigest, "stateDigest": canonical.Bytes(c.StateDigest[:]), "signerKeyId": c.SignerKeyID,
		"signerInstanceId": c.SignerInstanceID, "signerTransactionDomainId": c.SignerTransactionDomainID,
		"signerBuildDigest": c.SignerBuildDigest, "signerApplicationDigest": c.SignerApplicationDigest}
}

func decodeClaims(encoded []byte) (Claims, error) {
	value, err := canonical.Decode(encoded, checkpointOptions())
	if err != nil {
		return Claims{}, ErrInvalidCheckpoint
	}
	m, ok := value.(canonical.Map)
	if !ok || len(m) != 15 {
		return Claims{}, ErrInvalidCheckpoint
	}
	var c Claims
	for key, target := range map[string]*string{"auditGroup": &c.AuditGroup, "tenantId": &c.TenantID, "objectId": &c.ObjectID,
		"sourceInstanceId": &c.SourceInstanceID, "transactionDomainId": &c.TransactionDomainID,
		"sourceBuildDigest": &c.SourceBuildDigest, "sourceApplicationDigest": &c.SourceApplicationDigest,
		"headDigest": &c.HeadDigest, "signerKeyId": &c.SignerKeyID, "signerInstanceId": &c.SignerInstanceID,
		"signerTransactionDomainId": &c.SignerTransactionDomainID,
		"signerBuildDigest":         &c.SignerBuildDigest, "signerApplicationDigest": &c.SignerApplicationDigest} {
		text, ok := m[key].(string)
		if !ok {
			return Claims{}, ErrInvalidCheckpoint
		}
		*target = text
	}
	sequence, ok := m["headSequence"].(int64)
	digest, digestOK := m["stateDigest"].(canonical.Bytes)
	if !ok || sequence < 0 || !digestOK || len(digest) != 32 {
		return Claims{}, ErrInvalidCheckpoint
	}
	c.HeadSequence = uint64(sequence)
	copy(c.StateDigest[:], digest)
	if !validClaims(c) {
		return Claims{}, ErrInvalidCheckpoint
	}
	return c, nil
}

func validClaims(c Claims) bool {
	group := dependency.AtomicGroup(c.AuditGroup)
	if group != authstate.AtomicCredentialAudit && group != authstate.AtomicAccountAudit {
		return false
	}
	if _, err := identity.Parse(identity.Tenant, c.TenantID); err != nil || c.ObjectID != auditObjectID(group, c.TenantID) ||
		c.HeadSequence > maximumAuditSequence || !validDigest(c.HeadDigest) ||
		(c.HeadSequence == 0) != (c.HeadDigest == zeroHeadDigest) || c.StateDigest == ([32]byte{}) {
		return false
	}
	for _, value := range []string{c.SourceInstanceID, c.TransactionDomainID, c.SignerKeyID, c.SignerInstanceID, c.SignerTransactionDomainID} {
		if !validIdentifier(value) {
			return false
		}
	}
	for _, value := range []string{c.SourceBuildDigest, c.SourceApplicationDigest, c.SignerBuildDigest, c.SignerApplicationDigest} {
		if !validDigest(value) || value == zeroHeadDigest {
			return false
		}
	}
	return true
}

func validIdentifier(text string) bool { return identifierPattern.MatchString(text) }

func validDigest(text string) bool {
	if len(text) != 71 || text[:7] != "sha256:" {
		return false
	}
	decoded, err := hex.DecodeString(text[7:])
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == text[7:]
}

func checkpointOptions() canonical.Options {
	return canonical.Options{MaxBytes: MaximumCheckpointBytes, MaxDepth: 4, MaxItems: 128}
}

func matchesHead(state []byte, c Claims) bool {
	if len(state) == 0 {
		return c.HeadSequence == 0 && c.HeadDigest == zeroHeadDigest
	}
	value, err := canonical.Decode(state, canonical.Options{MaxBytes: maximumAuditStateBytes, MaxDepth: 12, MaxItems: 1_000_000})
	if err != nil {
		return false
	}
	m, ok := value.(canonical.Map)
	if !ok || m["version"] != int64(1) || m["tenantId"] != c.TenantID ||
		m["headSequence"] != int64(c.HeadSequence) || m["headDigest"] != c.HeadDigest {
		return false
	}
	audit, ok := m["audit"].(canonical.Array)
	if !ok || uint64(len(audit)) != c.HeadSequence {
		return false
	}
	if dependency.AtomicGroup(c.AuditGroup) == authstate.AtomicCredentialAudit {
		_, recordsOK := m["records"].(canonical.Array)
		return len(m) == 6 && recordsOK
	}
	_, accountsOK := m["accounts"].(canonical.Array)
	_, policyOK := m["policy"].(canonical.Map)
	return len(m) == 7 && accountsOK && policyOK
}
