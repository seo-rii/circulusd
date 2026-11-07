package canonical

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"

	"golang.org/x/text/unicode/norm"
)

type canonicalTextFixture struct {
	UnicodeVersion         string `json:"unicodeVersion"`
	UnassignedRangesSHA256 string `json:"unassignedRangesSha256"`
	Text                   []struct {
		Name         string `json:"name"`
		InputHex     string `json:"inputHex"`
		CanonicalHex string `json:"canonicalHex"`
		Decode       string `json:"decode"`
	} `json:"text"`
	Maps []struct {
		Name    string   `json:"name"`
		KeysHex []string `json:"keysHex"`
		CBORHex *string  `json:"cborHex"`
	} `json:"maps"`
}

func loadCanonicalTextFixture(t *testing.T) canonicalTextFixture {
	t.Helper()
	encoded, err := os.ReadFile("../../packages/protocol-types/fixtures/canonical-text-nfc-v1.json")
	if err != nil {
		t.Fatalf("ReadFile(canonical text fixture) error = %v", err)
	}
	var fixture canonicalTextFixture
	if err := json.Unmarshal(encoded, &fixture); err != nil {
		t.Fatalf("Unmarshal(canonical text fixture) error = %v", err)
	}
	if fixture.UnicodeVersion != "15.0.0" || len(fixture.Text) == 0 || len(fixture.Maps) == 0 {
		t.Fatalf("canonical text fixture is incomplete: %+v", fixture)
	}
	return fixture
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("DecodeString(%q) error = %v", value, err)
	}
	return decoded
}

func textHead(length int) []byte {
	output := &writer{maxBytes: 9, maxItems: 1}
	if err := output.appendHead(3, uint64(length)); err != nil {
		panic(err)
	}
	return output.encoded
}

func TestCanonicalTextGoldenVectorsEncodeAndDecode(t *testing.T) {
	t.Parallel()

	fixture := loadCanonicalTextFixture(t)
	for _, vector := range fixture.Text {
		input := mustDecodeHex(t, vector.InputHex)
		canonicalText := mustDecodeHex(t, vector.CanonicalHex)
		want := append(textHead(len(canonicalText)), canonicalText...)
		encoded, err := Encode(string(input), DefaultOptions())
		if err != nil || !bytes.Equal(encoded, want) {
			t.Errorf("%s: Encode() = %x, %v; want %x", vector.Name, encoded, err, want)
		}
		decoded, err := Decode(append(textHead(len(input)), input...), DefaultOptions())
		switch vector.Decode {
		case "accept":
			if err != nil || decoded != string(input) {
				t.Errorf("%s: Decode() = %q, %v; want the input accepted", vector.Name, decoded, err)
			}
		case "reject":
			if !errors.Is(err, ErrInvalidEncoding) {
				t.Errorf("%s: Decode() error = %v, want ErrInvalidEncoding", vector.Name, err)
			}
		default:
			t.Fatalf("%s: unknown decode expectation %q", vector.Name, vector.Decode)
		}
	}
	for _, vector := range fixture.Maps {
		value := Map{}
		for index, keyHex := range vector.KeysHex {
			value[string(mustDecodeHex(t, keyHex))] = int64(index)
		}
		encoded, err := Encode(value, DefaultOptions())
		if vector.CBORHex == nil {
			if !errors.Is(err, ErrDuplicateKey) {
				t.Errorf("%s: Encode() error = %v, want ErrDuplicateKey", vector.Name, err)
			}
			continue
		}
		if err != nil || hex.EncodeToString(encoded) != *vector.CBORHex {
			t.Errorf("%s: Encode() = %x, %v; want %s", vector.Name, encoded, err, *vector.CBORHex)
		}
	}
}

func TestNormalizeTextGoldenVectorsAndPinnedTable(t *testing.T) {
	t.Parallel()

	fixture := loadCanonicalTextFixture(t)
	var table strings.Builder
	previousLast := rune(-1)
	for _, bounds := range unicode15UnassignedRanges {
		if bounds[0] <= previousLast || bounds[1] < bounds[0] || bounds[1] > 0x10ffff {
			t.Fatalf("unassigned range %X..%X is not ascending and disjoint", bounds[0], bounds[1])
		}
		previousLast = bounds[1]
		fmt.Fprintf(&table, "%04X..%04X\n", bounds[0], bounds[1])
	}
	if digest := sha256.Sum256([]byte(table.String())); hex.EncodeToString(digest[:]) != fixture.UnassignedRangesSHA256 {
		t.Fatalf("unassigned range table digest = %x, want %s", digest, fixture.UnassignedRangesSHA256)
	}
	for _, vector := range fixture.Text {
		input := string(mustDecodeHex(t, vector.InputHex))
		if got := hex.EncodeToString([]byte(NormalizeText(input))); got != vector.CanonicalHex {
			t.Errorf("%s: NormalizeText() = %s, want %s", vector.Name, got, vector.CanonicalHex)
		}
		if got := hex.EncodeToString([]byte(normalizeUnicode15Segments(input))); got != vector.CanonicalHex {
			t.Errorf("%s: normalizeUnicode15Segments() = %s, want %s", vector.Name, got, vector.CanonicalHex)
		}
		if got := IsNormalizedText(input); got != (vector.Decode == "accept") {
			t.Errorf("%s: IsNormalizedText() = %v, want %v", vector.Name, got, vector.Decode == "accept")
		}
	}
	got, err := NormalizeStringSet([]string{"\U000105D2\u0307", "\U000105C9"})
	if err != nil || len(got) != 2 {
		t.Fatalf("NormalizeStringSet(post-15.0 forms) = %q, %v; want two distinct values", got, err)
	}
}

func TestUnicode15SegmentsMatchUnicode15Tables(t *testing.T) {
	t.Parallel()

	if norm.Version != "15.0.0" {
		t.Skipf("the x/text tables are Unicode %s; this oracle needs Unicode 15.0.0", norm.Version)
	}
	// With Unicode 15.0.0 tables the runtime normalizer is the contract itself,
	// so the segment path used with newer tables must never change its result.
	pool := []rune{
		'a', 'e', 0x1100, 0x1161, 0x11a8, 0xac00, 0x0300, 0x0301, 0x0323, 0x0345, 0x0958, 0x093c,
		0x212b, 0x0f73, 0x10efd, 0x0378, 0x0897, 0x1acf, 0x05c8, 0x105c9, 0x105d2, 0x0307,
		0x16d67, 0x11382, 0x113c9, 0x1611e, 0x1fae9, 0x50000, 0xe000, 0xfffe,
	}
	random := rand.New(rand.NewSource(20261014))
	for iteration := 0; iteration < 20_000; iteration++ {
		runes := make([]rune, 1+random.Intn(12))
		for index := range runes {
			runes[index] = pool[random.Intn(len(pool))]
		}
		input := string(runes)
		if got, want := normalizeUnicode15Segments(input), norm.NFC.String(input); got != want {
			t.Fatalf("normalizeUnicode15Segments(%+q) = %+q, want %+q", input, got, want)
		}
	}
}

func TestRuntimeNormalizationTablesStayPinned(t *testing.T) {
	t.Parallel()

	// U+10EFD (ccc 220) is new in Unicode 15.0.0; older tables would not reorder it.
	if got := norm.NFC.String("\u0300\U00010EFD"); got != "\U00010EFD\u0300" {
		t.Fatalf("x/text normalization tables predate Unicode 15.0.0 (version %s)", norm.Version)
	}
	// Other packages still call golang.org/x/text/unicode/norm directly. Their
	// results equal NormalizeText only while the tables are exactly 15.0.0
	// (go1.27 switches x/text to Unicode 17.0.0), so move them to NormalizeText
	// and IsNormalizedText before changing the toolchain or x/text.
	if norm.Version != "15.0.0" {
		t.Fatalf("x/text normalization tables are Unicode %s; migrate direct norm callers first", norm.Version)
	}
}
