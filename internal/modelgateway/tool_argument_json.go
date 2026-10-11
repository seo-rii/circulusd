package modelgateway

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"unicode/utf8"

	"github.com/hancomac/circulusd/internal/canonical"
	"golang.org/x/text/unicode/norm"
)

const piNumberWrapperKey = "$pi.number.v1"

func decodeToolArgumentJSON(encoded []byte) (canonical.Value, error) {
	if len(encoded) == 0 || len(encoded) > hardMaxEventBytes {
		return nil, ErrInvalidRequest
	}
	options := canonical.DefaultOptions()
	options.MaxBytes = hardMaxEventBytes
	value, err := canonical.Decode(encoded, options)
	if err != nil {
		return nil, fmt.Errorf("%w: tool arguments are not canonical CBOR", ErrInvalidRequest)
	}
	return transformToolArgumentJSON(value, true)
}

func transformToolArgumentJSON(value canonical.Value, decode bool) (canonical.Value, error) {
	options := canonical.DefaultOptions()
	walker := toolArgumentJSONWalker{
		decode: decode, maximumDepth: options.MaxDepth,
		remainingItems: options.MaxItems, remainingBytes: hardMaxEventBytes,
	}
	return walker.value(value, 0)
}

// The prewalk bounds allocation before constructing a normalized tree. Its byte
// budget is a lower bound; the final canonical encoder enforces the exact budget,
// including number wrappers and CBOR length headers. The depth bound also stops
// cyclic Go maps/slices without traversing an unbounded graph.
type toolArgumentJSONWalker struct {
	decode         bool
	maximumDepth   int
	remainingItems int
	remainingBytes int
}

func (walker *toolArgumentJSONWalker) value(value canonical.Value, depth int) (canonical.Value, error) {
	if depth > walker.maximumDepth || walker.remainingItems < 1 || walker.remainingBytes < 1 {
		return nil, fmt.Errorf("%w: tool JSON exceeds its structural bounds", ErrInvalidRequest)
	}
	walker.remainingItems--
	walker.remainingBytes--
	switch value := value.(type) {
	case nil, bool:
		return value, nil
	case string:
		if !utf8.ValidString(value) {
			return nil, ErrInvalidRequest
		}
		value = norm.NFC.String(value)
		if len(value) > walker.remainingBytes {
			return nil, ErrInvalidRequest
		}
		walker.remainingBytes -= len(value)
		return value, nil
	case int:
		return walker.integer(int64(value))
	case int8:
		return walker.integer(int64(value))
	case int16:
		return walker.integer(int64(value))
	case int32:
		return walker.integer(int64(value))
	case int64:
		return walker.integer(value)
	case uint:
		return walker.unsigned(uint64(value))
	case uint8:
		return walker.unsigned(uint64(value))
	case uint16:
		return walker.unsigned(uint64(value))
	case uint32:
		return walker.unsigned(uint64(value))
	case uint64:
		return walker.unsigned(value)
	case float32:
		return walker.number(float64(value))
	case float64:
		return walker.number(value)
	case []any:
		return walker.array(canonical.Array(value), depth)
	case canonical.Array:
		return walker.array(value, depth)
	case map[string]any:
		return walker.object(canonical.Map(value), depth)
	case canonical.Map:
		return walker.object(value, depth)
	default:
		// Byte strings, pointers, custom marshalers, and all other non-JSON
		// types must never be silently coerced into provider arguments.
		return nil, fmt.Errorf("%w: tool arguments must contain only JSON values", ErrInvalidRequest)
	}
}

func (*toolArgumentJSONWalker) integer(value int64) (canonical.Value, error) {
	if value < -int64(maxCanonicalInteger) || value > int64(maxCanonicalInteger) {
		return nil, ErrInvalidRequest
	}
	return value, nil
}

func (*toolArgumentJSONWalker) unsigned(value uint64) (canonical.Value, error) {
	if value > maxCanonicalInteger {
		return nil, ErrInvalidRequest
	}
	return int64(value), nil
}

func (walker *toolArgumentJSONWalker) number(value float64) (canonical.Value, error) {
	if walker.decode || math.IsInf(value, 0) || math.IsNaN(value) || value == 0 && math.Signbit(value) {
		return nil, ErrInvalidRequest
	}
	if math.Trunc(value) == value && math.Abs(value) <= float64(maxCanonicalInteger) {
		return int64(value), nil
	}
	decimal, err := piNumberDecimal(value)
	if err != nil {
		return nil, err
	}
	// Account for the generated key and decimal before allocating the wrapper,
	// so a dense fractional array cannot expand far past the event budget during
	// the prewalk. The map itself was already charged by value().
	additionalBytes := len(piNumberWrapperKey) + len(decimal) + 2
	if walker.remainingItems < 2 || walker.remainingBytes < additionalBytes {
		return nil, ErrInvalidRequest
	}
	walker.remainingItems -= 2
	walker.remainingBytes -= additionalBytes
	return canonical.Map{piNumberWrapperKey: decimal}, nil
}

// Go's binary64 JSON encoder uses ECMAScript's shortest round-tripping decimal,
// fixed notation for [1e-6, 1e21), and unpadded exponents. In particular plain
// strconv.FormatFloat(value, 'g', -1, 64) uses different notation cutoffs.
func piNumberDecimal(value float64) (string, error) {
	if math.IsInf(value, 0) || math.IsNaN(value) || value == 0 && math.Signbit(value) {
		return "", ErrInvalidRequest
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", ErrInvalidRequest
	}
	return string(encoded), nil
}

func (walker *toolArgumentJSONWalker) array(value canonical.Array, depth int) (canonical.Value, error) {
	if len(value) > walker.remainingItems || len(value) > walker.remainingBytes {
		return nil, ErrInvalidRequest
	}
	result := make(canonical.Array, len(value))
	for index, entry := range value {
		converted, err := walker.value(entry, depth+1)
		if err != nil {
			return nil, err
		}
		result[index] = converted
	}
	return result, nil
}

func (walker *toolArgumentJSONWalker) object(value canonical.Map, depth int) (canonical.Value, error) {
	if wrapped, present := value[piNumberWrapperKey]; present {
		decimal, ok := wrapped.(string)
		if !walker.decode || len(value) != 1 || !ok || len(decimal) > 32 {
			return nil, fmt.Errorf("%w: reserved Pi number wrapper is invalid", ErrInvalidRequest)
		}
		number, err := strconv.ParseFloat(decimal, 64)
		canonicalDecimal, decimalErr := piNumberDecimal(number)
		if err != nil || decimalErr != nil || decimal != canonicalDecimal ||
			math.Trunc(number) == number && math.Abs(number) <= float64(maxCanonicalInteger) {
			return nil, fmt.Errorf("%w: Pi number wrapper is not canonical", ErrInvalidRequest)
		}
		return number, nil
	}
	if len(value) > walker.remainingItems/2 || len(value) > walker.remainingBytes/2 {
		return nil, ErrInvalidRequest
	}
	result := make(canonical.Map, len(value))
	for key, entry := range value {
		normalized, err := walker.value(key, depth+1)
		if err != nil {
			return nil, err
		}
		key = normalized.(string)
		if _, duplicate := result[key]; duplicate {
			return nil, fmt.Errorf("%w: duplicate normalized tool JSON key", ErrInvalidRequest)
		}
		converted, err := walker.value(entry, depth+1)
		if err != nil {
			return nil, err
		}
		result[key] = converted
	}
	return result, nil
}
