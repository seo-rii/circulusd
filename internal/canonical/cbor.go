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
	maxSafeInteger  = uint64(9_007_199_254_740_991)
)

var (
	ErrInvalidValue  = errors.New("invalid canonical value")
	ErrDuplicateKey  = errors.New("duplicate normalized key")
	ErrLimitExceeded = errors.New("canonical encoding limit exceeded")
	ErrInvalidOption = errors.New("invalid canonical encoding option")
)

type Value = any

type Array []Value

type Map map[string]Value

type Bytes []byte

type Options struct {
	MaxDepth int
	MaxBytes int
}

type writer struct {
	encoded  []byte
	maxBytes int
}

func Encode(value Value, options Options) ([]byte, error) {
	if options.MaxDepth < 0 || options.MaxBytes < 0 {
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
	output := &writer{encoded: make([]byte, 0, 256), maxBytes: maxBytes}
	if err := encode(output, value, 0, maxDepth); err != nil {
		return nil, err
	}
	return append([]byte(nil), output.encoded...), nil
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
			keyWriter := &writer{encoded: make([]byte, 0, len(key)+9), maxBytes: len(key) + 9}
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
