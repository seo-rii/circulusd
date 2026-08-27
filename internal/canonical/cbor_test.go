package canonical

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"runtime"
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

			encoded, err := Encode(payload, DefaultOptions())
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

	encoded, err := Encode(Map{"z": int64(0), "aa": int64(1), "b": int64(2)}, DefaultOptions())
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if got, want := hex.EncodeToString(encoded), "a3616202617a0062616101"; got != want {
		t.Fatalf("Encode() = %s, want %s", got, want)
	}
	encoded, err = Encode("e\u0301", DefaultOptions())
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
			if _, err := Encode(test.value, DefaultOptions()); !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("Encode(%T) error = %v, want ErrInvalidValue", test.value, err)
			}
		})
	}
}

func TestEncodeRejectsDuplicateNormalizedKeys(t *testing.T) {
	t.Parallel()

	_, err := Encode(Map{"é": int64(1), "e\u0301": int64(2)}, DefaultOptions())
	if !errors.Is(err, ErrDuplicateKey) {
		t.Fatalf("Encode() error = %v, want ErrDuplicateKey", err)
	}
}

func TestEncodeEnforcesDepthAndSizeLimits(t *testing.T) {
	t.Parallel()

	if _, err := Encode(Array{Array{int64(0)}}, Options{MaxDepth: 1, MaxBytes: defaultMaxBytes, MaxItems: defaultMaxItems}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("Encode(depth) error = %v, want ErrLimitExceeded", err)
	}
	if _, err := Encode("abcd", Options{MaxDepth: defaultMaxDepth, MaxBytes: 4, MaxItems: defaultMaxItems}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("Encode(size) error = %v, want ErrLimitExceeded", err)
	}
	if _, err := Encode(nil, Options{MaxDepth: -1}); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("Encode(invalid option) error = %v, want ErrInvalidOption", err)
	}
	if _, err := Encode(Array{nil, nil}, Options{MaxDepth: defaultMaxDepth, MaxBytes: defaultMaxBytes, MaxItems: 2}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("Encode(items) error = %v, want ErrLimitExceeded", err)
	}
	if _, err := Encode(Array{nil, nil}, Options{MaxDepth: defaultMaxDepth, MaxBytes: defaultMaxBytes, MaxItems: 3}); err != nil {
		t.Fatalf("Encode(items within limit) error = %v", err)
	}
}

func TestEncodeIntegerAliasesConsumeOneItem(t *testing.T) {
	t.Parallel()

	for name, value := range map[string]Value{
		"int": int(0), "int8": int8(0), "int16": int16(0), "int32": int32(0),
		"uint": uint(0), "uint8": uint8(0), "uint16": uint16(0), "uint32": uint32(0),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			encoded, err := Encode(value, Options{MaxDepth: 1, MaxBytes: 1, MaxItems: 1})
			if err != nil {
				t.Fatalf("Encode(%T) error = %v", value, err)
			}
			if !bytes.Equal(encoded, []byte{0}) {
				t.Fatalf("Encode(%T) = %x, want 00", value, encoded)
			}
		})
	}
}

func TestExplicitZeroLimitsFailClosedLikeTypeScript(t *testing.T) {
	t.Parallel()

	if _, err := Encode(nil, Options{MaxDepth: 1, MaxBytes: 1, MaxItems: 0}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("Encode(MaxItems: 0) error = %v, want ErrLimitExceeded", err)
	}
	if _, err := Encode(nil, Options{MaxDepth: 1, MaxBytes: 0, MaxItems: 1}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("Encode(MaxBytes: 0) error = %v, want ErrLimitExceeded", err)
	}
	if _, err := Encode(Array{nil}, Options{MaxDepth: 0, MaxBytes: 2, MaxItems: 2}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("Encode(MaxDepth: 0) error = %v, want ErrLimitExceeded", err)
	}
	if _, err := Decode([]byte{0xf6}, Options{MaxDepth: 1, MaxBytes: 1, MaxItems: 0}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("Decode(MaxItems: 0) error = %v, want ErrLimitExceeded", err)
	}
	if _, err := Decode([]byte{0xf6}, Options{MaxDepth: 1, MaxBytes: 0, MaxItems: 1}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("Decode(MaxBytes: 0) error = %v, want ErrLimitExceeded", err)
	}
	if _, err := Decode([]byte{0x81, 0xf6}, Options{MaxDepth: 0, MaxBytes: 2, MaxItems: 2}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("Decode(MaxDepth: 0) error = %v, want ErrLimitExceeded", err)
	}
}

func TestDecodeRoundTripsSupportedCanonicalValuesWithoutByteAliases(t *testing.T) {
	t.Parallel()

	want := Map{
		"array":      Array{nil, false, true, int64(0), int64(23), int64(24), int64(-1), int64(-24), int64(-25)},
		"bytes":      Bytes{0, 1, 0xfe, 0xff},
		"emptyBytes": Bytes{},
		"integerBounds": Array{
			-int64(maxSafeInteger),
			int64(maxSafeInteger),
		},
		"text": "é\uFEFF",
	}
	encoded, err := Encode(want, DefaultOptions())
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	decoded, err := Decode(encoded, DefaultOptions())
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if !reflect.DeepEqual(decoded, want) {
		t.Fatalf("Decode() = %#v, want %#v", decoded, want)
	}
	reencoded, err := Encode(decoded, DefaultOptions())
	if err != nil {
		t.Fatalf("Encode(decoded) error = %v", err)
	}
	if !bytes.Equal(reencoded, encoded) {
		t.Fatalf("Encode(Decode(encoded)) = %x, want %x", reencoded, encoded)
	}

	decodedBytes := decoded.(Map)["bytes"].(Bytes)
	byteStringOffset := bytes.IndexByte(encoded, 0x44) + 1
	encoded[byteStringOffset] = 0xaa
	if !bytes.Equal(decodedBytes, Bytes{0, 1, 0xfe, 0xff}) {
		t.Fatalf("decoded bytes alias encoded input: %x", decodedBytes)
	}
	decodedBytes[0] = 0xbb
	if encoded[byteStringOffset] != 0xaa {
		t.Fatalf("encoded input aliases decoded bytes: %x", encoded)
	}
}

func TestDecodeRejectsNonMinimalArguments(t *testing.T) {
	t.Parallel()

	for _, encodedHex := range []string{
		"1817", "1900ff", "1a0000ffff", "1b00000000ffffffff",
		"3817", "5800", "7800", "9800", "b800",
	} {
		encodedHex := encodedHex
		t.Run(encodedHex, func(t *testing.T) {
			t.Parallel()
			encoded, err := hex.DecodeString(encodedHex)
			if err != nil {
				t.Fatalf("DecodeString() error = %v", err)
			}
			if _, err := Decode(encoded, DefaultOptions()); !errors.Is(err, ErrInvalidEncoding) {
				t.Fatalf("Decode(%s) error = %v, want ErrInvalidEncoding", encodedHex, err)
			}
		})
	}
}

func TestDecodeRejectsUnsafeIntegersAndUnsupportedForms(t *testing.T) {
	t.Parallel()

	for _, encodedHex := range []string{
		"1b0020000000000000", "3b001fffffffffffff",
		"f7", "f800", "f90000", "fa00000000", "fb0000000000000000",
		"c0f6", "9f00ff", "5f40ff", "1c",
	} {
		encodedHex := encodedHex
		t.Run(encodedHex, func(t *testing.T) {
			t.Parallel()
			encoded, err := hex.DecodeString(encodedHex)
			if err != nil {
				t.Fatalf("DecodeString() error = %v", err)
			}
			if _, err := Decode(encoded, DefaultOptions()); !errors.Is(err, ErrInvalidEncoding) {
				t.Fatalf("Decode(%s) error = %v, want ErrInvalidEncoding", encodedHex, err)
			}
		})
	}
}

func TestDecodeRejectsNonCanonicalTextAndMapKeys(t *testing.T) {
	t.Parallel()

	for name, encodedHex := range map[string]string{
		"invalid UTF-8":        "61ff",
		"non-NFC text":         "6365cc81",
		"non-text key":         "a10000",
		"duplicate key":        "a2616100616101",
		"bytewise key order":   "a2616200616101",
		"length-first order":   "a262616100616201",
		"normalized duplicate": "a262c3a9006365cc8101",
	} {
		name, encodedHex := name, encodedHex
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			encoded, err := hex.DecodeString(encodedHex)
			if err != nil {
				t.Fatalf("DecodeString() error = %v", err)
			}
			if _, err := Decode(encoded, DefaultOptions()); !errors.Is(err, ErrInvalidEncoding) {
				t.Fatalf("Decode(%s) error = %v, want ErrInvalidEncoding", encodedHex, err)
			}
		})
	}
}

func TestDecodeRejectsTrailingTruncatedAndImpossibleLengths(t *testing.T) {
	t.Parallel()

	for _, encodedHex := range []string{
		"", "00f6", "1a0000", "5b0020000000000000", "9b0020000000000000",
	} {
		encodedHex := encodedHex
		t.Run(encodedHex, func(t *testing.T) {
			t.Parallel()
			encoded, err := hex.DecodeString(encodedHex)
			if err != nil {
				t.Fatalf("DecodeString() error = %v", err)
			}
			if _, err := Decode(encoded, DefaultOptions()); !errors.Is(err, ErrInvalidEncoding) {
				t.Fatalf("Decode(%s) error = %v, want ErrInvalidEncoding", encodedHex, err)
			}
		})
	}
}

func TestDecodeEnforcesByteDepthAndAggregateItemLimits(t *testing.T) {
	t.Parallel()

	nested, err := Encode(Array{Array{Array{int64(0)}}}, DefaultOptions())
	if err != nil {
		t.Fatalf("Encode(nested) error = %v", err)
	}
	if _, err := Decode(nested, Options{MaxDepth: 1, MaxBytes: defaultMaxBytes, MaxItems: defaultMaxItems}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("Decode(depth) error = %v, want ErrLimitExceeded", err)
	}
	if _, err := Decode(nested, Options{MaxDepth: defaultMaxDepth, MaxBytes: len(nested) - 1, MaxItems: defaultMaxItems}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("Decode(bytes) error = %v, want ErrLimitExceeded", err)
	}
	threeItems, err := hex.DecodeString("83010203")
	if err != nil {
		t.Fatalf("DecodeString(items) error = %v", err)
	}
	if _, err := Decode(threeItems, Options{MaxDepth: defaultMaxDepth, MaxBytes: defaultMaxBytes, MaxItems: 3}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("Decode(items) error = %v, want ErrLimitExceeded", err)
	}
	if _, err := Decode([]byte{0xf6}, Options{MaxItems: -1}); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("Decode(invalid items option) error = %v, want ErrInvalidOption", err)
	}
}

func TestDecodeDoesNotPreallocateAttackerDeclaredContainers(t *testing.T) {
	encoded := make([]byte, 1_000_003)
	copy(encoded, []byte{0xba, 0x00, 0x07, 0xa1, 0x1f, 0x00})
	options := Options{MaxDepth: 64, MaxBytes: len(encoded), MaxItems: 1_000_000}

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	if _, err := Decode(encoded, options); !errors.Is(err, ErrInvalidEncoding) {
		t.Fatalf("Decode(oversized declared map) error = %v, want ErrInvalidEncoding", err)
	}
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 4<<20 {
		t.Fatalf("Decode(oversized declared map) allocated %d bytes before rejection", allocated)
	}
}

func TestEncodeChecksContainerItemBudgetBeforeAuxiliaryAllocation(t *testing.T) {
	value := make(Map, 100_000)
	for index := range 100_000 {
		value[string(rune(index+1))] = nil
	}

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	if _, err := Encode(value, Options{MaxDepth: 64, MaxBytes: defaultMaxBytes, MaxItems: 1}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("Encode(oversized map) error = %v, want ErrLimitExceeded", err)
	}
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 1<<20 {
		t.Fatalf("Encode(oversized map) allocated %d bytes before item-budget rejection", allocated)
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
