package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strings"
	"time"
)

const (
	TokenEntropyBytes  = 32
	maximumPATLifetime = 366 * 24 * time.Hour
	maximumScopes      = 128
)

var (
	ErrInvalidCredential = errors.New("invalid credential")
	ErrCredentialExpired = errors.New("credential expired")
	ErrCredentialRevoked = errors.New("credential revoked")
	ErrInsufficientScope = errors.New("insufficient credential scope")
)

type PATRecord struct {
	ID         string
	TenantID   string
	UserID     string
	Digest     string
	Scopes     []string
	IssuedAt   time.Time
	ExpiresAt  time.Time
	RevokedAt  *time.Time
	LastUsedAt time.Time
	UseCount   uint64
	Version    uint64
}

func issuePAT(
	entropy io.Reader,
	tenantID string,
	userID string,
	scopes []string,
	issuedAt time.Time,
	expiresAt time.Time,
) (string, PATRecord, error) {
	if err := validateBoundedText(tenantID); err != nil {
		return "", PATRecord{}, fmt.Errorf("tenant ID: %w", err)
	}
	if err := validateBoundedText(userID); err != nil {
		return "", PATRecord{}, fmt.Errorf("user ID: %w", err)
	}
	if issuedAt.IsZero() || !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > maximumPATLifetime {
		return "", PATRecord{}, errors.New("PAT expiry is outside the supported range")
	}
	if len(scopes) == 0 || len(scopes) > maximumScopes {
		return "", PATRecord{}, errors.New("PAT must contain a bounded non-empty scope set")
	}
	canonicalScopes := append([]string(nil), scopes...)
	for _, scope := range canonicalScopes {
		if err := validateBoundedText(scope); err != nil {
			return "", PATRecord{}, fmt.Errorf("PAT scope: %w", err)
		}
	}
	slices.Sort(canonicalScopes)
	for index := 1; index < len(canonicalScopes); index++ {
		if canonicalScopes[index] == canonicalScopes[index-1] {
			return "", PATRecord{}, errors.New("PAT scopes must be unique")
		}
	}
	if entropy == nil {
		entropy = rand.Reader
	}
	secret := make([]byte, TokenEntropyBytes)
	if _, err := io.ReadFull(entropy, secret); err != nil {
		return "", PATRecord{}, fmt.Errorf("read PAT entropy: %w", err)
	}
	plaintext := "pat_" + base64.RawURLEncoding.EncodeToString(secret)
	digest, err := parsePATPlaintext(plaintext)
	if err != nil {
		return "", PATRecord{}, err
	}
	return plaintext, PATRecord{
		ID:        "patid_" + hex.EncodeToString(digest[:16]),
		TenantID:  tenantID,
		UserID:    userID,
		Digest:    "sha256:" + hex.EncodeToString(digest[:]),
		Scopes:    canonicalScopes,
		IssuedAt:  issuedAt.UTC(),
		ExpiresAt: expiresAt.UTC(),
		Version:   1,
	}, nil
}

func verifyPATSnapshot(plaintext string, record PATRecord, requiredScope string, now time.Time) error {
	actual, err := parsePATPlaintext(plaintext)
	if err != nil {
		return ErrInvalidCredential
	}
	if err := validatePATRecord(record); err != nil {
		return err
	}
	if err := validateBoundedText(requiredScope); err != nil {
		return ErrInsufficientScope
	}
	expected, err := parsePATDigest(record.Digest)
	if err != nil {
		return ErrInvalidCredential
	}
	if subtle.ConstantTimeCompare(actual[:], expected) != 1 {
		return ErrInvalidCredential
	}
	if record.RevokedAt != nil {
		return ErrCredentialRevoked
	}
	if now.IsZero() || now.Before(record.IssuedAt) {
		return ErrInvalidCredential
	}
	if !record.LastUsedAt.IsZero() && now.Before(record.LastUsedAt) {
		return ErrInvalidCredential
	}
	if !now.Before(record.ExpiresAt) {
		return ErrCredentialExpired
	}
	if _, found := slices.BinarySearch(record.Scopes, requiredScope); !found {
		return ErrInsufficientScope
	}
	return nil
}

func applyPATRevocation(record PATRecord, revokedAt time.Time) (PATRecord, error) {
	if err := validatePATRecord(record); err != nil {
		return PATRecord{}, err
	}
	if record.RevokedAt != nil {
		return clonePATRecord(record), nil
	}
	if revokedAt.IsZero() {
		return PATRecord{}, errors.New("PAT revocation time is invalid")
	}
	if record.Version == math.MaxUint64 {
		return PATRecord{}, errors.New("PAT version cannot advance")
	}
	next := clonePATRecord(record)
	timestamp := revokedAt.UTC()
	if record.LastUsedAt.After(timestamp) {
		timestamp = record.LastUsedAt.UTC()
	}
	if timestamp.Before(record.IssuedAt) {
		return PATRecord{}, errors.New("PAT revocation time is invalid")
	}
	next.RevokedAt = &timestamp
	next.Version++
	return next, nil
}

func validatePATRecord(record PATRecord) error {
	if err := validateBoundedText(record.ID); err != nil {
		return fmt.Errorf("PAT ID: %w", err)
	}
	if err := validateBoundedText(record.TenantID); err != nil {
		return fmt.Errorf("PAT tenant ID: %w", err)
	}
	if err := validateBoundedText(record.UserID); err != nil {
		return fmt.Errorf("PAT user ID: %w", err)
	}
	if record.Version == 0 ||
		record.IssuedAt.IsZero() ||
		!record.ExpiresAt.After(record.IssuedAt) ||
		record.ExpiresAt.Sub(record.IssuedAt) > maximumPATLifetime {
		return ErrInvalidCredential
	}
	digest, err := parsePATDigest(record.Digest)
	if err != nil || record.ID != "patid_"+hex.EncodeToString(digest[:16]) {
		return ErrInvalidCredential
	}
	if len(record.Scopes) == 0 || len(record.Scopes) > maximumScopes || !slices.IsSorted(record.Scopes) {
		return ErrInvalidCredential
	}
	for index, scope := range record.Scopes {
		if err := validateBoundedText(scope); err != nil {
			return ErrInvalidCredential
		}
		if index > 0 && scope == record.Scopes[index-1] {
			return ErrInvalidCredential
		}
	}
	if record.RevokedAt != nil {
		if record.RevokedAt.Before(record.IssuedAt) ||
			(!record.LastUsedAt.IsZero() && record.RevokedAt.Before(record.LastUsedAt)) {
			return ErrInvalidCredential
		}
	}
	if record.UseCount == 0 {
		if !record.LastUsedAt.IsZero() {
			return ErrInvalidCredential
		}
	} else if record.LastUsedAt.Before(record.IssuedAt) || !record.LastUsedAt.Before(record.ExpiresAt) {
		return ErrInvalidCredential
	}
	expectedVersion := uint64(1) + record.UseCount
	if record.RevokedAt != nil {
		if expectedVersion == math.MaxUint64 {
			return ErrInvalidCredential
		}
		expectedVersion++
	}
	if record.Version != expectedVersion {
		return ErrInvalidCredential
	}
	return nil
}

func parsePATPlaintext(plaintext string) ([sha256.Size]byte, error) {
	encodedSecret, found := strings.CutPrefix(plaintext, "pat_")
	if !found || len(plaintext) > 128 {
		return [sha256.Size]byte{}, ErrInvalidCredential
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(encodedSecret)
	if err != nil || len(secret) != TokenEntropyBytes || base64.RawURLEncoding.EncodeToString(secret) != encodedSecret {
		return [sha256.Size]byte{}, ErrInvalidCredential
	}
	return sha256.Sum256([]byte(plaintext)), nil
}

func parsePATDigest(encoded string) ([]byte, error) {
	hexDigest, found := strings.CutPrefix(encoded, "sha256:")
	if !found {
		return nil, ErrInvalidCredential
	}
	digest, err := hex.DecodeString(hexDigest)
	if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != hexDigest {
		return nil, ErrInvalidCredential
	}
	return digest, nil
}

func clonePATRecord(record PATRecord) PATRecord {
	clone := record
	clone.Scopes = append([]string(nil), record.Scopes...)
	if record.RevokedAt != nil {
		timestamp := *record.RevokedAt
		clone.RevokedAt = &timestamp
	}
	return clone
}
