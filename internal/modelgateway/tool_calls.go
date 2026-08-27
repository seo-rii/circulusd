package modelgateway

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"sort"
	"unicode/utf8"

	"github.com/hancomac/circulusd/internal/canonical"
	"golang.org/x/text/unicode/norm"
)

const maxCanonicalInteger = uint64(9_007_199_254_740_991)

// CanonicalToolArguments contains canonical CBOR from the shared protocol
// encoder. The byte storage is private so provider adapters cannot construct a
// value without passing canonical validation.
type CanonicalToolArguments struct {
	encoded []byte
}

// NewCanonicalToolArguments converts a provider's structured arguments into
// the canonical protocol representation.
func NewCanonicalToolArguments(value canonical.Value) (CanonicalToolArguments, error) {
	options := canonical.DefaultOptions()
	options.MaxBytes = hardMaxEventBytes
	encoded, err := canonical.Encode(value, options)
	if err != nil {
		return CanonicalToolArguments{}, fmt.Errorf("%w: canonical tool arguments: %v", ErrInvalidRequest, err)
	}
	return ParseCanonicalToolArguments(encoded)
}

// ParseCanonicalToolArguments validates and defensively copies canonical CBOR.
// It is intended for durable adapters restoring a previously encoded response.
func ParseCanonicalToolArguments(encoded []byte) (CanonicalToolArguments, error) {
	if len(encoded) == 0 || len(encoded) > hardMaxEventBytes {
		return CanonicalToolArguments{}, fmt.Errorf("%w: canonical tool arguments are empty or oversized", ErrInvalidRequest)
	}
	validator := canonicalCBORValidator{encoded: encoded}
	if err := validator.value(0); err != nil || validator.offset != len(encoded) {
		return CanonicalToolArguments{}, fmt.Errorf("%w: tool arguments are not canonical CBOR", ErrInvalidRequest)
	}
	return CanonicalToolArguments{encoded: append([]byte(nil), encoded...)}, nil
}

func (arguments CanonicalToolArguments) Bytes() []byte {
	return append([]byte(nil), arguments.encoded...)
}

func (arguments CanonicalToolArguments) MarshalBinary() ([]byte, error) {
	if err := validateCanonicalToolArguments(arguments); err != nil {
		return nil, err
	}
	return arguments.Bytes(), nil
}

func (arguments *CanonicalToolArguments) UnmarshalBinary(encoded []byte) error {
	if arguments == nil {
		return fmt.Errorf("%w: nil canonical tool arguments receiver", ErrInvalidRequest)
	}
	parsed, err := ParseCanonicalToolArguments(encoded)
	if err != nil {
		return err
	}
	*arguments = parsed
	return nil
}

func (arguments CanonicalToolArguments) String() string {
	return fmt.Sprintf("model-tool-arguments<canonical-cbor:%d-bytes>", len(arguments.encoded))
}

func (arguments CanonicalToolArguments) GoString() string { return arguments.String() }

func validateCanonicalToolArguments(arguments CanonicalToolArguments) error {
	if len(arguments.encoded) == 0 || len(arguments.encoded) > hardMaxEventBytes {
		return ErrInvalidRequest
	}
	validator := canonicalCBORValidator{encoded: arguments.encoded}
	if err := validator.value(0); err != nil || validator.offset != len(arguments.encoded) {
		return ErrInvalidRequest
	}
	return nil
}

func normalizeToolCalls(calls []ToolCall) ([]ToolCall, uint64, error) {
	if len(calls) == 0 {
		return nil, 0, nil
	}
	if len(calls) > hardMaxEvents {
		return nil, 0, ErrEventLimit
	}
	declaredOrder := calls[0].Order.Declared
	seenIDs := make(map[string]struct{}, len(calls))
	normalized := make([]ToolCall, len(calls))
	var totalBytes uint64
	for index, call := range calls {
		if !identifierPattern.MatchString(call.ID) || len(call.ID) > hardMaxProviderRequestIDBytes ||
			!identifierPattern.MatchString(call.Name) || len(call.Name) > hardMaxIdentifierBytes ||
			call.Order.Declared != declaredOrder || (!call.Order.Declared && call.Order.Index != 0) ||
			(call.Order.Declared && call.Order.Index != uint32(index)) {
			return nil, 0, ErrInvalidRequest
		}
		if _, duplicate := seenIDs[call.ID]; duplicate {
			return nil, 0, ErrInvalidRequest
		}
		seenIDs[call.ID] = struct{}{}
		if err := validateCanonicalToolArguments(call.Arguments); err != nil {
			return nil, 0, err
		}
		callBytes := uint64(len(call.ID)) + uint64(len(call.Name)) + uint64(len(call.Arguments.encoded)) + 9
		if callBytes > math.MaxUint64-totalBytes {
			return nil, 0, ErrEventLimit
		}
		totalBytes += callBytes
		normalized[index] = call
		normalized[index].Arguments.encoded = append([]byte(nil), call.Arguments.encoded...)
	}
	if !declaredOrder {
		sort.SliceStable(normalized, func(left, right int) bool {
			if normalized[left].ID != normalized[right].ID {
				return normalized[left].ID < normalized[right].ID
			}
			if normalized[left].Name != normalized[right].Name {
				return normalized[left].Name < normalized[right].Name
			}
			return bytes.Compare(normalized[left].Arguments.encoded, normalized[right].Arguments.encoded) < 0
		})
	}
	return normalized, totalBytes, nil
}

func equalToolCalls(left []ToolCall, right []ToolCall) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].ID != right[index].ID || left[index].Name != right[index].Name || left[index].Order != right[index].Order ||
			!bytes.Equal(left[index].Arguments.encoded, right[index].Arguments.encoded) {
			return false
		}
	}
	return true
}

type canonicalCBORValidator struct {
	encoded []byte
	offset  int
}

func (validator *canonicalCBORValidator) value(depth int) error {
	if depth > 64 || validator.offset >= len(validator.encoded) {
		return ErrInvalidRequest
	}
	start := validator.offset
	major, additional, value, err := validator.head()
	if err != nil {
		return err
	}
	switch major {
	case 0:
		if value > maxCanonicalInteger {
			return ErrInvalidRequest
		}
	case 1:
		if value >= maxCanonicalInteger {
			return ErrInvalidRequest
		}
	case 2:
		if err := validator.skip(value); err != nil {
			return err
		}
	case 3:
		textStart := validator.offset
		if err := validator.skip(value); err != nil {
			return err
		}
		text := string(validator.encoded[textStart:validator.offset])
		if !utf8.ValidString(text) || norm.NFC.String(text) != text {
			return ErrInvalidRequest
		}
	case 4:
		for range value {
			if err := validator.value(depth + 1); err != nil {
				return err
			}
		}
	case 5:
		var previousKey []byte
		for range value {
			keyStart := validator.offset
			if validator.offset >= len(validator.encoded) || validator.encoded[validator.offset]>>5 != 3 {
				return ErrInvalidRequest
			}
			if err := validator.value(depth + 1); err != nil {
				return err
			}
			key := validator.encoded[keyStart:validator.offset]
			if previousKey != nil && (len(previousKey) > len(key) || (len(previousKey) == len(key) && bytes.Compare(previousKey, key) >= 0)) {
				return ErrInvalidRequest
			}
			previousKey = key
			if err := validator.value(depth + 1); err != nil {
				return err
			}
		}
	case 7:
		if additional != 20 && additional != 21 && additional != 22 {
			return ErrInvalidRequest
		}
	default:
		return ErrInvalidRequest
	}
	if validator.offset <= start {
		return ErrInvalidRequest
	}
	return nil
}

func (validator *canonicalCBORValidator) head() (byte, byte, uint64, error) {
	initial := validator.encoded[validator.offset]
	validator.offset++
	major, additional := initial>>5, initial&0x1f
	switch {
	case additional < 24:
		return major, additional, uint64(additional), nil
	case additional == 24:
		encoded, err := validator.read(1)
		if err != nil || encoded[0] < 24 {
			return 0, 0, 0, ErrInvalidRequest
		}
		return major, additional, uint64(encoded[0]), nil
	case additional == 25:
		encoded, err := validator.read(2)
		if err != nil || binary.BigEndian.Uint16(encoded) <= math.MaxUint8 {
			return 0, 0, 0, ErrInvalidRequest
		}
		return major, additional, uint64(binary.BigEndian.Uint16(encoded)), nil
	case additional == 26:
		encoded, err := validator.read(4)
		if err != nil || binary.BigEndian.Uint32(encoded) <= math.MaxUint16 {
			return 0, 0, 0, ErrInvalidRequest
		}
		return major, additional, uint64(binary.BigEndian.Uint32(encoded)), nil
	case additional == 27:
		encoded, err := validator.read(8)
		if err != nil || binary.BigEndian.Uint64(encoded) <= math.MaxUint32 {
			return 0, 0, 0, ErrInvalidRequest
		}
		return major, additional, binary.BigEndian.Uint64(encoded), nil
	default:
		return 0, 0, 0, ErrInvalidRequest
	}
}

func (validator *canonicalCBORValidator) read(size int) ([]byte, error) {
	if size < 0 || size > len(validator.encoded)-validator.offset {
		return nil, ErrInvalidRequest
	}
	value := validator.encoded[validator.offset : validator.offset+size]
	validator.offset += size
	return value, nil
}

func (validator *canonicalCBORValidator) skip(size uint64) error {
	if size > uint64(len(validator.encoded)-validator.offset) {
		return ErrInvalidRequest
	}
	validator.offset += int(size)
	return nil
}
