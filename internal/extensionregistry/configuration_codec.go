package extensionregistry

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"unicode/utf8"

	"github.com/hancomac/circulusd/internal/canonical"
	"golang.org/x/text/unicode/norm"
)

// Extension JSON is a separate, versioned representation. It never relaxes the
// integer-only control-plane CBOR codec. Safe-integer payloads retain v1 digests;
// other finite binary64 numbers use a fully tagged, collision-free v2 tree.
func normalizeExtensionJSON(value any) (canonical.Value, bool, error) {
	items, textBytes := 0, 0
	version2 := false
	text := func(value string, maximum int) (string, error) {
		if !utf8.ValidString(value) {
			return "", fmt.Errorf("JSON text must contain Unicode scalar values")
		}
		value = norm.NFC.String(value)
		textBytes += len(value)
		if len(value) > maximum || textBytes > 1<<20 {
			return "", fmt.Errorf("extension JSON text exceeds its byte limit")
		}
		return value, nil
	}
	var visit func(any, int) (canonical.Value, error)
	visit = func(value any, depth int) (canonical.Value, error) {
		items++
		if items > 10_000 || depth > 64 {
			return nil, fmt.Errorf("extension JSON exceeds its item or depth limit")
		}
		switch number := value.(type) {
		case int:
			value = int64(number)
		case int8:
			value = int64(number)
		case int16:
			value = int64(number)
		case int32:
			value = int64(number)
		case uint:
			value = uint64(number)
		case uint8:
			value = uint64(number)
		case uint16:
			value = uint64(number)
		case uint32:
			value = uint64(number)
		case float32:
			value = float64(number)
		case json.Number:
			parsed, err := number.Float64()
			if err != nil {
				return nil, fmt.Errorf("JSON number exceeds binary64 range")
			}
			value = parsed
		case []any:
			value = canonical.Array(number)
		case map[string]any:
			value = canonical.Map(number)
		}
		switch current := value.(type) {
		case nil, bool:
			return current, nil
		case string:
			return text(current, 65_536)
		case int64:
			if current < -int64(maxSafeInteger) || current > int64(maxSafeInteger) {
				return nil, fmt.Errorf("native JSON integer exceeds the shared safe-integer range")
			}
			return current, nil
		case uint64:
			if current > maxSafeInteger {
				return nil, fmt.Errorf("native JSON integer exceeds the shared safe-integer range")
			}
			return int64(current), nil
		case float64:
			if math.IsNaN(current) || math.IsInf(current, 0) {
				return nil, fmt.Errorf("extension JSON numbers must be finite binary64 values")
			}
			if math.Trunc(current) == current && math.Abs(current) <= float64(maxSafeInteger) {
				return int64(current), nil // also canonicalizes -0 to +0
			}
			version2 = true
			return current, nil
		case canonical.Array:
			if len(current) > 10_000 {
				return nil, fmt.Errorf("extension JSON exceeds its item limit")
			}
			output := make(canonical.Array, len(current))
			for index, item := range current {
				var err error
				output[index], err = visit(item, depth+1)
				if err != nil {
					return nil, err
				}
			}
			return output, nil
		case canonical.Map:
			output := make(canonical.Map, len(current))
			for key, item := range current {
				normalizedKey, err := text(key, 256)
				if err != nil {
					return nil, err
				}
				if normalizedKey == "__proto__" || normalizedKey == "constructor" || normalizedKey == "prototype" {
					return nil, fmt.Errorf("dangerous extension JSON object key is not allowed")
				}
				if _, found := output[normalizedKey]; found {
					return nil, fmt.Errorf("extension JSON has duplicate normalized keys")
				}
				output[normalizedKey], err = visit(item, depth+1)
				if err != nil {
					return nil, err
				}
			}
			return output, nil
		default:
			return nil, fmt.Errorf("unsupported extension JSON value %T", value)
		}
	}
	result, err := visit(value, 0)
	return result, version2, err
}

func extensionJSONTagged(value canonical.Value) canonical.Value {
	switch current := value.(type) {
	case nil:
		return canonical.Array{"null"}
	case bool:
		return canonical.Array{"boolean", current}
	case string:
		return canonical.Array{"string", current}
	case int64:
		return extensionJSONTagged(float64(current))
	case float64:
		var bytes [8]byte
		binary.BigEndian.PutUint64(bytes[:], math.Float64bits(current))
		return canonical.Array{"number", hex.EncodeToString(bytes[:])}
	case canonical.Array:
		output := make(canonical.Array, len(current))
		for index, item := range current {
			output[index] = extensionJSONTagged(item)
		}
		return canonical.Array{"array", output}
	case canonical.Map:
		output := make(canonical.Map, len(current))
		for key, item := range current {
			output[key] = extensionJSONTagged(item)
		}
		return canonical.Array{"object", output}
	default:
		panic("extension JSON was not normalized")
	}
}

func extensionJSONDigest(domain string, normalized canonical.Value, version2 bool) (string, error) {
	if !version2 {
		if domain == "" || !utf8.ValidString(domain) || norm.NFC.String(domain) != domain {
			return "", fmt.Errorf("JSON digest domain must be non-empty NFC UTF-8")
		}
		// This is the unchanged v1 hash envelope, with the same 72-level
		// scoped limit as TS digestStructuredValue rather than control CBOR's
		// shorter default. No bytes change for previously accepted values.
		encoded, err := canonical.Encode(canonical.Array{"circulusd.hash", int64(1), domain, int64(1), normalized}, canonical.Options{MaxDepth: 72, MaxBytes: 16 << 20, MaxItems: 100_000})
		if err != nil {
			return "", err
		}
		digest := sha256.Sum256(encoded)
		return "sha256:" + hex.EncodeToString(digest[:]), nil
	}
	encoded, err := extensionJSONDigestPayload(normalized, version2)
	if err != nil {
		return "", err
	}
	return canonical.StructuredDigest(domain, 2, canonical.Bytes(encoded))
}

func extensionJSONDigestPayload(normalized canonical.Value, version2 bool) ([]byte, error) {
	if !version2 {
		return canonical.Encode(normalized, canonical.DefaultOptions())
	}
	return canonical.Encode(canonical.Array{"circulusd.extension-json", int64(2), extensionJSONTagged(normalized)}, canonical.Options{MaxDepth: 140, MaxBytes: 16 << 20, MaxItems: 100_000})
}
