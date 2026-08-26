package auth

import (
	"bytes"
	"strings"
	"testing"
)

func TestArgon2idPasswordHashRoundTripAndRehashSignal(t *testing.T) {
	t.Parallel()

	params := Argon2idParams{
		MemoryKiB:   8 * 1024,
		Iterations:  1,
		Parallelism: 1,
		SaltBytes:   16,
		KeyBytes:    32,
	}
	encoded, err := HashPassword("correct horse battery staple", params, bytes.NewReader(bytes.Repeat([]byte{0x5a}, 16)))
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if !strings.HasPrefix(encoded, "$argon2id$v=19$m=8192,t=1,p=1$") {
		t.Fatalf("HashPassword() = %q", encoded)
	}

	verification, err := VerifyPassword(encoded, "correct horse battery staple", params)
	if err != nil {
		t.Fatalf("VerifyPassword() error = %v", err)
	}
	if !verification.Valid || verification.NeedsRehash {
		t.Fatalf("VerifyPassword() = %+v", verification)
	}
	wrong, err := VerifyPassword(encoded, "wrong", params)
	if err != nil {
		t.Fatalf("VerifyPassword(wrong) error = %v", err)
	}
	if wrong.Valid {
		t.Fatal("VerifyPassword(wrong).Valid = true")
	}

	stronger := params
	stronger.Iterations = 2
	rehash, err := VerifyPassword(encoded, "correct horse battery staple", stronger)
	if err != nil {
		t.Fatalf("VerifyPassword(rehash) error = %v", err)
	}
	if !rehash.Valid || !rehash.NeedsRehash {
		t.Fatalf("VerifyPassword(rehash) = %+v", rehash)
	}
}

func TestArgon2idPasswordHashFailsClosedOnHostileInputs(t *testing.T) {
	t.Parallel()

	params := Argon2idParams{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1, SaltBytes: 16, KeyBytes: 32}
	if _, err := HashPassword(strings.Repeat("x", MaxPasswordBytes+1), params, bytes.NewReader(make([]byte, 16))); err == nil {
		t.Fatal("HashPassword(oversized) error = nil")
	}

	for _, encoded := range []string{
		"not-a-phc-string",
		"$argon2i$v=19$m=8192,t=1,p=1$WlpaWlpaWlpaWlpaWlpaWg$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=19$m=1073741824,t=1,p=1$WlpaWlpaWlpaWlpaWlpaWg$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=19$m=8192,t=1,p=1$***$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=19$m=0008192,t=01,p=01$WlpaWlpaWlpaWlpaWlpaWg$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	} {
		if _, err := VerifyPassword(encoded, "password", params); err == nil {
			t.Fatalf("VerifyPassword(%q) error = nil", encoded)
		}
	}
	tooExpensive := "$argon2id$v=19$m=262145,t=1,p=1$WlpaWlpaWlpaWlpaWlpaWg$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if _, _, _, err := parseArgon2idHash(tooExpensive); err == nil {
		t.Fatal("parseArgon2idHash(too expensive) error = nil")
	}
}
