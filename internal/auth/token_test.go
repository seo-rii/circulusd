package auth

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestPATStoresOnlyDigestAndEnforcesScopeExpiryAndRevocation(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 26, 9, 0, 0, 0, time.UTC)
	plaintext, record, err := issuePAT(
		bytes.NewReader(bytes.Repeat([]byte{0x33}, TokenEntropyBytes)),
		"tenant-a",
		"user-a",
		[]string{"workspace:read", "session:write"},
		now,
		now.Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("issuePAT() error = %v", err)
	}
	if !strings.HasPrefix(plaintext, "pat_") || strings.Contains(record.Digest, plaintext) {
		t.Fatalf("plaintext or digest shape is invalid: token=%q record=%+v", plaintext, record)
	}
	if got, want := record.Scopes, []string{"session:write", "workspace:read"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Scopes = %v, want %v", got, want)
	}
	if err := verifyPATSnapshot(plaintext, record, "workspace:read", now.Add(time.Minute)); err != nil {
		t.Fatalf("verifyPATSnapshot() error = %v", err)
	}
	if err := verifyPATSnapshot(plaintext, record, "artifact:delete", now); !errors.Is(err, ErrInsufficientScope) {
		t.Fatalf("verifyPATSnapshot(scope) error = %v, want ErrInsufficientScope", err)
	}
	if err := verifyPATSnapshot(plaintext+"x", record, "workspace:read", now); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("verifyPATSnapshot(wrong) error = %v", err)
	}
	if err := verifyPATSnapshot(plaintext, record, "workspace:read", record.ExpiresAt); !errors.Is(err, ErrCredentialExpired) {
		t.Fatalf("verifyPATSnapshot(expired) error = %v", err)
	}
	if err := verifyPATSnapshot(plaintext, record, "workspace:read", record.IssuedAt.Add(-time.Nanosecond)); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("verifyPATSnapshot(before issue) error = %v, want ErrInvalidCredential", err)
	}

	malformedPlaintext := "pat_short"
	malformedDigest := sha256.Sum256([]byte(malformedPlaintext))
	malformedRecord := record
	malformedRecord.Digest = "sha256:" + hex.EncodeToString(malformedDigest[:])
	malformedRecord.ID = "patid_" + hex.EncodeToString(malformedDigest[:16])
	if err := verifyPATSnapshot(malformedPlaintext, malformedRecord, "workspace:read", now); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("verifyPATSnapshot(malformed shape) error = %v, want ErrInvalidCredential", err)
	}

	revoked, err := applyPATRevocation(record, now.Add(10*time.Minute))
	if err != nil {
		t.Fatalf("RevokePAT() error = %v", err)
	}
	if revoked.Version != record.Version+1 || revoked.RevokedAt == nil {
		t.Fatalf("RevokePAT() = %+v", revoked)
	}
	if err := verifyPATSnapshot(plaintext, revoked, "workspace:read", now.Add(11*time.Minute)); !errors.Is(err, ErrCredentialRevoked) {
		t.Fatalf("verifyPATSnapshot(revoked) error = %v", err)
	}
	if replay, err := applyPATRevocation(revoked, now.Add(12*time.Minute)); err != nil || !reflect.DeepEqual(replay, revoked) {
		t.Fatalf("RevokePAT(replay) = (%+v, %v)", replay, err)
	}
	overflow := record
	overflow.Version = math.MaxUint64
	if _, err := applyPATRevocation(overflow, now.Add(12*time.Minute)); err == nil {
		t.Fatal("RevokePAT(version overflow) error = nil")
	}
	corrupt := record
	corrupt.Digest = "sha256:not-a-digest"
	if _, err := applyPATRevocation(corrupt, now.Add(12*time.Minute)); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("RevokePAT(corrupt digest) error = %v, want ErrInvalidCredential", err)
	}
	overlong := record
	overlong.ExpiresAt = overlong.IssuedAt.Add(maximumPATLifetime + time.Nanosecond)
	if err := verifyPATSnapshot(plaintext, overlong, "workspace:read", now); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("VerifyPAT(overlong record) error = %v, want ErrInvalidCredential", err)
	}
}

func TestPATRejectsUnboundedOrNonCanonicalClaimsBeforeEntropyUse(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	reader := &countingReader{}
	tests := []struct {
		name     string
		tenantID string
		userID   string
		scopes   []string
		expires  time.Time
	}{
		{name: "empty tenant", userID: "u", scopes: []string{"read"}, expires: now.Add(time.Hour)},
		{name: "empty user", tenantID: "t", scopes: []string{"read"}, expires: now.Add(time.Hour)},
		{name: "duplicate after normalization", tenantID: "t", userID: "u", scopes: []string{"read", "read"}, expires: now.Add(time.Hour)},
		{name: "empty scope", tenantID: "t", userID: "u", scopes: []string{""}, expires: now.Add(time.Hour)},
		{name: "no expiry", tenantID: "t", userID: "u", scopes: []string{"read"}, expires: now},
	}
	for _, test := range tests {
		if _, _, err := issuePAT(reader, test.tenantID, test.userID, test.scopes, now, test.expires); err == nil {
			t.Fatalf("IssuePAT(%s) error = nil", test.name)
		}
	}
	if reader.calls != 0 {
		t.Fatalf("entropy reader calls = %d, want 0", reader.calls)
	}
}

type countingReader struct {
	calls int
}

func (reader *countingReader) Read(buffer []byte) (int, error) {
	reader.calls++
	for index := range buffer {
		buffer[index] = 1
	}
	return len(buffer), nil
}
