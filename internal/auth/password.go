package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	MaxPasswordBytes = 1024

	minimumMemoryKiB   = 8 * 1024
	maximumMemoryKiB   = 256 * 1024
	maximumIterations  = 5
	maximumParallelism = 4
	minimumSaltBytes   = 16
	maximumSaltBytes   = 64
	minimumKeyBytes    = 16
	maximumKeyBytes    = 64
	maximumPHCBytes    = 512
)

var ErrInvalidPasswordHash = errors.New("invalid password hash")

type Argon2idParams struct {
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
	SaltBytes   uint32
	KeyBytes    uint32
}

var DefaultArgon2idParams = Argon2idParams{
	MemoryKiB:   64 * 1024,
	Iterations:  3,
	Parallelism: 1,
	SaltBytes:   16,
	KeyBytes:    32,
}

type PasswordVerification struct {
	Valid       bool
	NeedsRehash bool
}

func HashPassword(password string, params Argon2idParams, entropy io.Reader) (string, error) {
	if err := validatePassword(password); err != nil {
		return "", err
	}
	if err := validateArgon2idParams(params); err != nil {
		return "", err
	}
	if entropy == nil {
		entropy = rand.Reader
	}
	salt := make([]byte, params.SaltBytes)
	if _, err := io.ReadFull(entropy, salt); err != nil {
		return "", fmt.Errorf("read password salt: %w", err)
	}
	key := argon2.IDKey(
		[]byte(password),
		salt,
		params.Iterations,
		params.MemoryKiB,
		params.Parallelism,
		params.KeyBytes,
	)
	defer clear(key)
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		params.MemoryKiB,
		params.Iterations,
		params.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

func VerifyPassword(
	encoded string,
	password string,
	current Argon2idParams,
) (PasswordVerification, error) {
	if err := validatePassword(password); err != nil {
		return PasswordVerification{}, err
	}
	if err := validateArgon2idParams(current); err != nil {
		return PasswordVerification{}, fmt.Errorf("current password parameters: %w", err)
	}
	stored, salt, expected, err := parseArgon2idHash(encoded)
	if err != nil {
		return PasswordVerification{}, err
	}
	actual := argon2.IDKey(
		[]byte(password),
		salt,
		stored.Iterations,
		stored.MemoryKiB,
		stored.Parallelism,
		stored.KeyBytes,
	)
	defer clear(actual)
	valid := subtle.ConstantTimeCompare(actual, expected) == 1
	return PasswordVerification{
		Valid: valid,
		NeedsRehash: valid && (stored.MemoryKiB != current.MemoryKiB ||
			stored.Iterations != current.Iterations ||
			stored.Parallelism != current.Parallelism ||
			stored.SaltBytes != current.SaltBytes ||
			stored.KeyBytes != current.KeyBytes),
	}, nil
}

func parseArgon2idHash(encoded string) (Argon2idParams, []byte, []byte, error) {
	if len(encoded) == 0 || len(encoded) > maximumPHCBytes {
		return Argon2idParams{}, nil, nil, ErrInvalidPasswordHash
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return Argon2idParams{}, nil, nil, ErrInvalidPasswordHash
	}
	parameterParts := strings.Split(parts[3], ",")
	if len(parameterParts) != 3 {
		return Argon2idParams{}, nil, nil, ErrInvalidPasswordHash
	}
	values := make([]uint64, 3)
	for index, prefix := range []string{"m=", "t=", "p="} {
		if !strings.HasPrefix(parameterParts[index], prefix) {
			return Argon2idParams{}, nil, nil, ErrInvalidPasswordHash
		}
		encodedValue := strings.TrimPrefix(parameterParts[index], prefix)
		parsed, err := strconv.ParseUint(encodedValue, 10, 32)
		if err != nil || strconv.FormatUint(parsed, 10) != encodedValue {
			return Argon2idParams{}, nil, nil, ErrInvalidPasswordHash
		}
		values[index] = parsed
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil {
		return Argon2idParams{}, nil, nil, ErrInvalidPasswordHash
	}
	expected, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil {
		return Argon2idParams{}, nil, nil, ErrInvalidPasswordHash
	}
	if values[2] > 255 {
		return Argon2idParams{}, nil, nil, ErrInvalidPasswordHash
	}
	params := Argon2idParams{
		MemoryKiB:   uint32(values[0]),
		Iterations:  uint32(values[1]),
		Parallelism: uint8(values[2]),
		SaltBytes:   uint32(len(salt)),
		KeyBytes:    uint32(len(expected)),
	}
	if err := validateArgon2idParams(params); err != nil {
		return Argon2idParams{}, nil, nil, ErrInvalidPasswordHash
	}
	return params, salt, expected, nil
}

func validatePassword(password string) error {
	if password == "" || !utf8.ValidString(password) || len(password) > MaxPasswordBytes {
		return errors.New("password must be non-empty valid UTF-8 within the byte limit")
	}
	return nil
}

func validateArgon2idParams(params Argon2idParams) error {
	if params.MemoryKiB < minimumMemoryKiB || params.MemoryKiB > maximumMemoryKiB {
		return errors.New("argon2id memory is outside the supported range")
	}
	if params.Iterations == 0 || params.Iterations > maximumIterations {
		return errors.New("argon2id iterations are outside the supported range")
	}
	if params.Parallelism == 0 || params.Parallelism > maximumParallelism {
		return errors.New("argon2id parallelism is outside the supported range")
	}
	if params.MemoryKiB < 8*uint32(params.Parallelism) {
		return errors.New("argon2id memory is too small for its parallelism")
	}
	if params.SaltBytes < minimumSaltBytes || params.SaltBytes > maximumSaltBytes {
		return errors.New("argon2id salt length is outside the supported range")
	}
	if params.KeyBytes < minimumKeyBytes || params.KeyBytes > maximumKeyBytes {
		return errors.New("argon2id key length is outside the supported range")
	}
	return nil
}
