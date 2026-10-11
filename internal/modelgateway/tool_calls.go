package modelgateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"

	"github.com/hancomac/circulusd/internal/canonical"
)

const maxCanonicalInteger = uint64(9_007_199_254_740_991)

// CanonicalToolArguments contains canonical CBOR from the shared protocol
// encoder. The byte storage is private so provider adapters cannot construct a
// value without passing canonical validation.
type CanonicalToolArguments struct {
	encoded []byte
}

// NewCanonicalToolArguments converts a provider's JSON arguments into the
// canonical protocol representation, wrapping non-safe-integer binary64 numbers
// with the versioned Pi JSON number codec. Raw reserved wrapper keys are rejected.
func NewCanonicalToolArguments(value canonical.Value) (CanonicalToolArguments, error) {
	value, err := transformToolArgumentJSON(value, false)
	if err != nil {
		return CanonicalToolArguments{}, err
	}
	options := canonical.DefaultOptions()
	options.MaxBytes = hardMaxEventBytes
	encoded, err := canonical.Encode(value, options)
	if err != nil {
		return CanonicalToolArguments{}, fmt.Errorf("%w: canonical tool arguments: %v", ErrInvalidRequest, err)
	}
	return ParseCanonicalToolArguments(encoded)
}

// ParseCanonicalToolArguments validates and defensively copies canonical CBOR,
// including the stored Pi JSON number wrappers. It is intended for durable
// adapters restoring a previously encoded response.
func ParseCanonicalToolArguments(encoded []byte) (CanonicalToolArguments, error) {
	if len(encoded) == 0 || len(encoded) > hardMaxEventBytes {
		return CanonicalToolArguments{}, fmt.Errorf("%w: canonical tool arguments are empty or oversized", ErrInvalidRequest)
	}
	if _, err := decodeToolArgumentJSON(encoded); err != nil {
		return CanonicalToolArguments{}, err
	}
	return CanonicalToolArguments{encoded: append([]byte(nil), encoded...)}, nil
}

func (arguments CanonicalToolArguments) Bytes() []byte {
	return append([]byte(nil), arguments.encoded...)
}

// ProviderJSON restores actual JSON numbers before a provider or external tool
// consumes the arguments. Bytes returns the durable integer-only representation;
// it must not be forwarded as provider JSON without this decoding boundary.
func (arguments CanonicalToolArguments) ProviderJSON() (json.RawMessage, error) {
	value, err := decodeToolArgumentJSON(arguments.encoded)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot encode provider tool JSON", ErrInvalidRequest)
	}
	return json.RawMessage(encoded), nil
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
	_, err := decodeToolArgumentJSON(arguments.encoded)
	return err
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
