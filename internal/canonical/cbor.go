package canonical

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const (
	defaultMaxDepth = 64
	defaultMaxBytes = 16 << 20
	defaultMaxItems = 1_000_000
	maxSafeInteger  = uint64(9_007_199_254_740_991)
)

var (
	ErrInvalidValue    = errors.New("invalid canonical value")
	ErrInvalidEncoding = errors.New("invalid canonical encoding")
	ErrDuplicateKey    = errors.New("duplicate normalized key")
	ErrLimitExceeded   = errors.New("canonical encoding limit exceeded")
	ErrInvalidOption   = errors.New("invalid canonical encoding option")
)

type Value = any

type Array []Value

type Map map[string]Value

type Bytes []byte

type Options struct {
	MaxDepth int
	MaxBytes int
	MaxItems int
}

type writer struct {
	encoded  []byte
	maxBytes int
	items    int
	maxItems int
}

func Encode(value Value, options Options) ([]byte, error) {
	if options.MaxDepth < 0 || options.MaxBytes < 0 || options.MaxItems < 0 {
		return nil, ErrInvalidOption
	}
	maxDepth := options.MaxDepth
	if maxDepth == 0 {
		maxDepth = defaultMaxDepth
	}
	maxBytes := options.MaxBytes
	if maxBytes == 0 {
		maxBytes = defaultMaxBytes
	}
	maxItems := options.MaxItems
	if maxItems == 0 {
		maxItems = defaultMaxItems
	}
	output := &writer{
		encoded: make([]byte, 0, 256), maxBytes: maxBytes, maxItems: maxItems,
	}
	if err := encode(output, value, 0, maxDepth); err != nil {
		return nil, err
	}
	return append([]byte(nil), output.encoded...), nil
}

func Decode(encoded []byte, options Options) (Value, error) {
	if options.MaxDepth < 0 || options.MaxBytes < 0 || options.MaxItems < 0 {
		return nil, ErrInvalidOption
	}
	maxDepth := options.MaxDepth
	if maxDepth == 0 {
		maxDepth = defaultMaxDepth
	}
	maxBytes := options.MaxBytes
	if maxBytes == 0 {
		maxBytes = defaultMaxBytes
	}
	maxItems := options.MaxItems
	if maxItems == 0 {
		maxItems = defaultMaxItems
	}
	if len(encoded) > maxBytes {
		return nil, fmt.Errorf("%w: encoded size exceeds %d bytes", ErrLimitExceeded, maxBytes)
	}
	input := &decoder{encoded: encoded, maxDepth: maxDepth, maxItems: maxItems}
	value, err := input.readValue(0)
	if err != nil {
		return nil, err
	}
	if input.offset != len(input.encoded) {
		return nil, fmt.Errorf("%w: trailing bytes after the value", ErrInvalidEncoding)
	}
	return value, nil
}

func StructuredDigest(domain string, schemaVersion uint64, payload Value) (string, error) {
	if domain == "" || !utf8.ValidString(domain) || norm.NFC.String(domain) != domain {
		return "", fmt.Errorf("%w: digest domain must be non-empty NFC UTF-8", ErrInvalidValue)
	}
	if schemaVersion == 0 || schemaVersion > maxSafeInteger {
		return "", fmt.Errorf("%w: schema version is outside the shared integer range", ErrInvalidValue)
	}
	encoded, err := Encode(
		Array{"circulusd.hash", int64(1), domain, int64(schemaVersion), payload},
		Options{},
	)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func NormalizeStringSet(values []string) ([]string, error) {
	normalized := make([]string, len(values))
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		if !utf8.ValidString(value) {
			return nil, fmt.Errorf("%w: set value %d is not UTF-8", ErrInvalidValue, index)
		}
		value = norm.NFC.String(value)
		if _, duplicate := seen[value]; duplicate {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateKey, value)
		}
		seen[value] = struct{}{}
		normalized[index] = value
	}
	sort.Slice(normalized, func(left, right int) bool {
		return bytes.Compare([]byte(normalized[left]), []byte(normalized[right])) < 0
	})
	return normalized, nil
}

func encode(output *writer, value Value, depth int, maxDepth int) error {
	if depth > maxDepth {
		return fmt.Errorf("%w: maximum depth %d", ErrLimitExceeded, maxDepth)
	}
	if output.items >= output.maxItems {
		return fmt.Errorf("%w: encoded item limit %d exceeded", ErrLimitExceeded, output.maxItems)
	}
	output.items++
	switch value := value.(type) {
	case nil:
		return output.appendBytes([]byte{0xf6})
	case bool:
		if value {
			return output.appendBytes([]byte{0xf5})
		}
		return output.appendBytes([]byte{0xf4})
	case string:
		if !utf8.ValidString(value) {
			return fmt.Errorf("%w: text is not UTF-8", ErrInvalidValue)
		}
		value = norm.NFC.String(value)
		if err := output.appendHead(3, uint64(len(value))); err != nil {
			return err
		}
		return output.appendBytes([]byte(value))
	case Bytes:
		if err := output.appendHead(2, uint64(len(value))); err != nil {
			return err
		}
		return output.appendBytes(value)
	case int:
		return encode(output, int64(value), depth, maxDepth)
	case int8:
		return encode(output, int64(value), depth, maxDepth)
	case int16:
		return encode(output, int64(value), depth, maxDepth)
	case int32:
		return encode(output, int64(value), depth, maxDepth)
	case int64:
		if value >= 0 {
			if uint64(value) > maxSafeInteger {
				return fmt.Errorf("%w: integer exceeds the shared safe range", ErrInvalidValue)
			}
			return output.appendHead(0, uint64(value))
		}
		if value < -int64(maxSafeInteger) {
			return fmt.Errorf("%w: integer exceeds the shared safe range", ErrInvalidValue)
		}
		return output.appendHead(1, uint64(-1-value))
	case uint:
		return encode(output, uint64(value), depth, maxDepth)
	case uint8:
		return encode(output, uint64(value), depth, maxDepth)
	case uint16:
		return encode(output, uint64(value), depth, maxDepth)
	case uint32:
		return encode(output, uint64(value), depth, maxDepth)
	case uint64:
		if value > maxSafeInteger {
			return fmt.Errorf("%w: integer exceeds the shared safe range", ErrInvalidValue)
		}
		return output.appendHead(0, value)
	case Array:
		if err := output.appendHead(4, uint64(len(value))); err != nil {
			return err
		}
		for _, item := range value {
			if err := encode(output, item, depth+1, maxDepth); err != nil {
				return err
			}
		}
		return nil
	case Map:
		type entry struct {
			encoded []byte
			value   Value
		}
		entries := make([]entry, 0, len(value))
		seen := make(map[string]struct{}, len(value))
		for key, item := range value {
			if !utf8.ValidString(key) {
				return fmt.Errorf("%w: map key is not UTF-8", ErrInvalidValue)
			}
			key = norm.NFC.String(key)
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("%w: %q", ErrDuplicateKey, key)
			}
			seen[key] = struct{}{}
			keyWriter := &writer{
				encoded: make([]byte, 0, len(key)+9), maxBytes: len(key) + 9, maxItems: 1,
			}
			if err := encode(keyWriter, key, depth+1, maxDepth); err != nil {
				return err
			}
			entries = append(entries, entry{encoded: keyWriter.encoded, value: item})
		}
		sort.Slice(entries, func(left, right int) bool {
			if len(entries[left].encoded) != len(entries[right].encoded) {
				return len(entries[left].encoded) < len(entries[right].encoded)
			}
			return bytes.Compare(entries[left].encoded, entries[right].encoded) < 0
		})
		if err := output.appendHead(5, uint64(len(entries))); err != nil {
			return err
		}
		for _, entry := range entries {
			if output.items >= output.maxItems {
				return fmt.Errorf("%w: encoded item limit %d exceeded", ErrLimitExceeded, output.maxItems)
			}
			output.items++
			if err := output.appendBytes(entry.encoded); err != nil {
				return err
			}
			if err := encode(output, entry.value, depth+1, maxDepth); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("%w: unsupported type %T", ErrInvalidValue, value)
	}
}

type decoder struct {
	encoded  []byte
	maxDepth int
	maxItems int
	items    int
	offset   int
}

func (input *decoder) readValue(depth int) (Value, error) {
	if depth > input.maxDepth {
		return nil, fmt.Errorf("%w: maximum depth %d", ErrLimitExceeded, input.maxDepth)
	}
	if input.items >= input.maxItems {
		return nil, fmt.Errorf("%w: decoded item limit %d exceeded", ErrLimitExceeded, input.maxItems)
	}
	input.items++
	if input.offset >= len(input.encoded) {
		return nil, fmt.Errorf("%w: truncated input", ErrInvalidEncoding)
	}
	initial := input.encoded[input.offset]
	input.offset++
	major, additional := initial>>5, initial&0x1f
	if major == 7 {
		switch initial {
		case 0xf4:
			return false, nil
		case 0xf5:
			return true, nil
		case 0xf6:
			return nil, nil
		default:
			return nil, fmt.Errorf("%w: unsupported simple, floating-point, or break value", ErrInvalidEncoding)
		}
	}
	if major == 6 {
		return nil, fmt.Errorf("%w: tags are unsupported", ErrInvalidEncoding)
	}

	var argument uint64
	switch {
	case additional < 24:
		argument = uint64(additional)
	case additional >= 24 && additional <= 27:
		width := 1 << (additional - 24)
		if len(input.encoded)-input.offset < int(width) {
			return nil, fmt.Errorf("%w: truncated argument", ErrInvalidEncoding)
		}
		for index := 0; index < width; index++ {
			argument = argument<<8 | uint64(input.encoded[input.offset])
			input.offset++
		}
		minimum := uint64(24)
		switch width {
		case 2:
			minimum = 0x100
		case 4:
			minimum = 0x1_0000
		case 8:
			minimum = 0x1_0000_0000
		}
		if argument < minimum {
			return nil, fmt.Errorf("%w: non-minimal argument", ErrInvalidEncoding)
		}
	case additional == 31:
		return nil, fmt.Errorf("%w: indefinite-length values are unsupported", ErrInvalidEncoding)
	default:
		return nil, fmt.Errorf("%w: reserved additional information", ErrInvalidEncoding)
	}

	switch major {
	case 0:
		if argument > maxSafeInteger {
			return nil, fmt.Errorf("%w: integer exceeds the shared safe range", ErrInvalidEncoding)
		}
		return int64(argument), nil
	case 1:
		if argument >= maxSafeInteger {
			return nil, fmt.Errorf("%w: integer exceeds the shared safe range", ErrInvalidEncoding)
		}
		return -1 - int64(argument), nil
	case 2, 3:
		remaining := len(input.encoded) - input.offset
		if argument > uint64(remaining) {
			return nil, fmt.Errorf("%w: declared string length exceeds remaining input", ErrInvalidEncoding)
		}
		length := int(argument)
		value := input.encoded[input.offset : input.offset+length]
		input.offset += length
		if major == 2 {
			copied := make(Bytes, len(value))
			copy(copied, value)
			return copied, nil
		}
		if !utf8.Valid(value) {
			return nil, fmt.Errorf("%w: text is not UTF-8", ErrInvalidEncoding)
		}
		text := string(value)
		if norm.NFC.String(text) != text {
			return nil, fmt.Errorf("%w: text is not NFC-normalized", ErrInvalidEncoding)
		}
		return text, nil
	case 4:
		remaining := len(input.encoded) - input.offset
		if argument > uint64(remaining) {
			return nil, fmt.Errorf("%w: declared array length exceeds remaining input", ErrInvalidEncoding)
		}
		availableItems := input.maxItems - input.items
		if argument > uint64(availableItems) {
			return nil, fmt.Errorf("%w: decoded item limit %d exceeded", ErrLimitExceeded, input.maxItems)
		}
		result := make(Array, int(argument))
		for index := range result {
			value, err := input.readValue(depth + 1)
			if err != nil {
				return nil, err
			}
			result[index] = value
		}
		return result, nil
	case 5:
		remaining := len(input.encoded) - input.offset
		if argument > uint64(remaining/2) {
			return nil, fmt.Errorf("%w: declared map length exceeds remaining input", ErrInvalidEncoding)
		}
		availableItems := input.maxItems - input.items
		if argument > uint64(availableItems/2) {
			return nil, fmt.Errorf("%w: decoded item limit %d exceeded", ErrLimitExceeded, input.maxItems)
		}
		result := make(Map, int(argument))
		previousKeyStart, previousKeyEnd := -1, -1
		for index := uint64(0); index < argument; index++ {
			keyStart := input.offset
			if keyStart >= len(input.encoded) || input.encoded[keyStart]>>5 != 3 {
				return nil, fmt.Errorf("%w: map keys must be text", ErrInvalidEncoding)
			}
			keyValue, err := input.readValue(depth + 1)
			if err != nil {
				return nil, err
			}
			key, ok := keyValue.(string)
			if !ok {
				return nil, fmt.Errorf("%w: map keys must be text", ErrInvalidEncoding)
			}
			keyEnd := input.offset
			if _, duplicate := result[key]; duplicate {
				return nil, fmt.Errorf("%w: duplicate map key", ErrInvalidEncoding)
			}
			if previousKeyStart >= 0 {
				previousKey := input.encoded[previousKeyStart:previousKeyEnd]
				currentKey := input.encoded[keyStart:keyEnd]
				if len(previousKey) > len(currentKey) ||
					(len(previousKey) == len(currentKey) && bytes.Compare(previousKey, currentKey) >= 0) {
					return nil, fmt.Errorf("%w: map keys are not in deterministic order", ErrInvalidEncoding)
				}
			}
			previousKeyStart, previousKeyEnd = keyStart, keyEnd
			item, err := input.readValue(depth + 1)
			if err != nil {
				return nil, err
			}
			result[key] = item
		}
		return result, nil
	default:
		return nil, fmt.Errorf("%w: unsupported major type %d", ErrInvalidEncoding, major)
	}
}

func (output *writer) appendHead(major byte, value uint64) error {
	var header [9]byte
	length := 1
	switch {
	case value < 24:
		header[0] = major<<5 | byte(value)
	case value <= 0xff:
		header[0], header[1], length = major<<5|24, byte(value), 2
	case value <= 0xffff:
		header[0], length = major<<5|25, 3
		binary.BigEndian.PutUint16(header[1:3], uint16(value))
	case value <= 0xffffffff:
		header[0], length = major<<5|26, 5
		binary.BigEndian.PutUint32(header[1:5], uint32(value))
	default:
		header[0], length = major<<5|27, 9
		binary.BigEndian.PutUint64(header[1:9], value)
	}
	return output.appendBytes(header[:length])
}

func (output *writer) appendBytes(value []byte) error {
	if len(value) > output.maxBytes-len(output.encoded) {
		return fmt.Errorf("%w: encoded size exceeds %d bytes", ErrLimitExceeded, output.maxBytes)
	}
	output.encoded = append(output.encoded, value...)
	return nil
}
