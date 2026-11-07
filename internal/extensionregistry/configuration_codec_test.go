package extensionregistry

import (
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hancomac/circulusd/internal/canonical"
)

func TestExtensionJSONMatchesCrossLanguageGolden(t *testing.T) {
	t.Parallel()
	contents, err := os.ReadFile(filepath.Join("..", "..", "packages", "extension-manifest", "fixtures", "configuration-json-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Domain string `json:"domain"`
		Cases  []struct {
			Name              string `json:"name"`
			JSON              string `json:"json"`
			SchemaVersion     int    `json:"schemaVersion"`
			Digest            string `json:"digest"`
			EncodedPayloadHex string `json:"encodedPayloadHex"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(contents, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, entry := range fixture.Cases {
		t.Run(entry.Name, func(t *testing.T) {
			var value any
			if err := json.Unmarshal([]byte(entry.JSON), &value); err != nil {
				t.Fatal(err)
			}
			normalized, version2, err := normalizeExtensionJSON(value)
			if err != nil || version2 != (entry.SchemaVersion == 2) {
				t.Fatalf("normalize JSON version=%t, error=%v", version2, err)
			}
			encoded, err := extensionJSONDigestPayload(normalized, version2)
			if err != nil || hex.EncodeToString(encoded) != entry.EncodedPayloadHex {
				t.Fatalf("encoded payload differs from TS golden; error=%v", err)
			}
			digest, err := extensionJSONDigest(fixture.Domain, normalized, version2)
			if err != nil || digest != entry.Digest {
				t.Fatalf("digest = %q, error=%v, want %q", digest, err, entry.Digest)
			}
		})
	}
}

func TestExtensionJSONPreservesIntegerDigestWithoutRelaxingControlCBOR(t *testing.T) {
	t.Parallel()
	value := canonical.Map{"scale": int64(1), "prefix": ""}
	normalized, version2, err := normalizeExtensionJSON(value)
	if err != nil || version2 {
		t.Fatalf("integer normalization error=%v, v2=%t", err, version2)
	}
	want, _ := canonical.StructuredDigest("test.configuration", 1, value)
	got, err := extensionJSONDigest("test.configuration", normalized, version2)
	if err != nil || got != want {
		t.Fatalf("legacy digest changed: %q != %q, error=%v", got, want, err)
	}
	if _, err := canonical.Encode(canonical.Map{"scale": 0.5}, canonical.DefaultOptions()); err == nil {
		t.Fatal("control-plane CBOR accepted a float")
	}
}

func TestExtensionJSONRejectsNonFiniteAndLossyNativeNumbers(t *testing.T) {
	t.Parallel()
	for _, value := range []any{math.NaN(), math.Inf(1), math.Inf(-1), json.Number("1e309"), int64(maxSafeInteger + 1), uint64(maxSafeInteger + 1)} {
		if _, _, err := normalizeExtensionJSON(canonical.Map{"value": value}); err == nil {
			t.Fatalf("accepted out-of-range JSON number %T", value)
		}
	}
	if _, _, err := normalizeExtensionJSON(canonical.Map{"é": int64(1), "é": int64(2)}); err == nil {
		t.Fatal("accepted duplicate normalized keys")
	}
	if _, _, err := normalizeExtensionJSON(canonical.Map{"__proto__": canonical.Map{"polluted": true}}); err == nil {
		t.Fatal("accepted dangerous object keys")
	}
}

func TestExtensionJSONRejectsTextThatXTextNormalizesIncorrectly(t *testing.T) {
	t.Parallel()
	for _, value := range []canonical.Map{
		{"value": "\u00e1" + strings.Repeat("\u0301", 30)},
		{"\U00010041" + strings.Repeat("\u0301", 31): int64(1)},
		{"value": canonical.Array{"\u00e1" + strings.Repeat("\u0301", 30)}},
		{"value": "a" + strings.Repeat("\u0301", 31)},
	} {
		if normalized, _, err := normalizeExtensionJSON(value); err == nil {
			t.Fatalf("normalizeExtensionJSON(%+q) = %+q, want an error", value, normalized)
		}
	}
}
