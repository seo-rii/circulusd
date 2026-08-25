package canonical

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestTypeScriptGoldenVectors(t *testing.T) {
	t.Parallel()

	encodedFixture, err := os.ReadFile("../../packages/protocol-types/fixtures/v1alpha-golden.json")
	if err != nil {
		t.Fatalf("ReadFile(golden) error = %v", err)
	}
	var fixture struct {
		Vectors []struct {
			Name           string `json:"name"`
			Domain         string `json:"domain"`
			SchemaVersion  uint64 `json:"schemaVersion"`
			PayloadCBORHex string `json:"payloadCborHex"`
			Digest         string `json:"digest"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(encodedFixture, &fixture); err != nil {
		t.Fatalf("Unmarshal(golden) error = %v", err)
	}

	for _, vector := range fixture.Vectors {
		vector := vector
		t.Run(vector.Name, func(t *testing.T) {
			t.Parallel()
			var payload Value
			switch vector.Name {
			case "null":
				payload = nil
			case "canonical-map-key-order":
				payload = Map{"aa": int64(1), "b": int64(2)}
			case "nfc-text":
				payload = "e\u0301"
			case "opaque-bytes":
				payload = Bytes{0, 1, 255}
			default:
				t.Fatalf("unhandled golden vector %q", vector.Name)
			}

			encoded, err := Encode(payload, Options{})
			if err != nil {
				t.Fatalf("Encode() error = %v", err)
			}
			if got := hex.EncodeToString(encoded); got != vector.PayloadCBORHex {
				t.Fatalf("Encode() = %s, want %s", got, vector.PayloadCBORHex)
			}
			digest, err := StructuredDigest(vector.Domain, vector.SchemaVersion, payload)
			if err != nil {
				t.Fatalf("StructuredDigest() error = %v", err)
			}
			if digest != vector.Digest {
				t.Fatalf("StructuredDigest() = %q, want %q", digest, vector.Digest)
			}
		})
	}
}

func TestEncodeNormalizesTextAndSortsMapKeys(t *testing.T) {
	t.Parallel()

	encoded, err := Encode(Map{"z": int64(0), "aa": int64(1), "b": int64(2)}, Options{})
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if got, want := hex.EncodeToString(encoded), "a3616202617a0062616101"; got != want {
		t.Fatalf("Encode() = %s, want %s", got, want)
	}
	encoded, err = Encode("e\u0301", Options{})
	if err != nil {
		t.Fatalf("Encode(NFC) error = %v", err)
	}
	if got, want := hex.EncodeToString(encoded), "62c3a9"; got != want {
		t.Fatalf("Encode(NFC) = %s, want %s", got, want)
	}
}

func TestEncodeRejectsAmbiguousValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value Value
	}{
		{name: "float", value: 1.5},
		{name: "negative zero", value: -0.0},
		{name: "unsafe positive integer", value: uint64(maxSafeInteger + 1)},
		{name: "unsafe negative integer", value: -int64(maxSafeInteger) - 1},
		{name: "invalid UTF-8", value: string([]byte{0xff})},
		{name: "unsupported struct", value: struct{ Value int }{Value: 1}},
		{name: "unsupported native slice", value: []string{"a"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := Encode(test.value, Options{}); !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("Encode(%T) error = %v, want ErrInvalidValue", test.value, err)
			}
		})
	}
}

func TestEncodeRejectsDuplicateNormalizedKeys(t *testing.T) {
	t.Parallel()

	_, err := Encode(Map{"é": int64(1), "e\u0301": int64(2)}, Options{})
	if !errors.Is(err, ErrDuplicateKey) {
		t.Fatalf("Encode() error = %v, want ErrDuplicateKey", err)
	}
}

func TestEncodeEnforcesDepthAndSizeLimits(t *testing.T) {
	t.Parallel()

	if _, err := Encode(Array{Array{int64(0)}}, Options{MaxDepth: 1}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("Encode(depth) error = %v, want ErrLimitExceeded", err)
	}
	if _, err := Encode("abcd", Options{MaxBytes: 4}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("Encode(size) error = %v, want ErrLimitExceeded", err)
	}
	if _, err := Encode(nil, Options{MaxDepth: -1}); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("Encode(invalid option) error = %v, want ErrInvalidOption", err)
	}
}

func TestNormalizeStringSetUsesUTF8ByteOrderAndRejectsDuplicates(t *testing.T) {
	t.Parallel()

	got, err := NormalizeStringSet([]string{"z", "é", "a", "e\u0301x"})
	if err != nil {
		t.Fatalf("NormalizeStringSet() error = %v", err)
	}
	want := []string{"a", "z", "é", "éx"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("NormalizeStringSet() = %#v, want %#v", got, want)
	}
	if _, err := NormalizeStringSet([]string{"é", "e\u0301"}); !errors.Is(err, ErrDuplicateKey) {
		t.Fatalf("NormalizeStringSet(duplicate) error = %v, want ErrDuplicateKey", err)
	}
}
