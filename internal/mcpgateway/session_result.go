package mcpgateway

import (
	"bytes"

	"github.com/hancomac/circulusd/internal/canonical"
)

const maximumSessionPiResultBytes = 1 << 20

// ValidateSessionPiResultBounds validates the immutable MCP policy used when
// reading terminal observations. It performs no provider or ledger operation.
func ValidateSessionPiResultBounds(bounds Bounds) error { return validateBounds(bounds) }

// ValidateSessionPiResult accepts a retained MCP observation only when Output
// already contains the exact Pi tool-result v1 body. Generic JSON, plaintext or
// MCP protocol output cannot supply missing toolCallId/toolName/timestamp and
// is rejected instead of being wrapped with invented metadata.
//
// The caller must authenticate the terminal records, verify TerminalCommitted
// and exact effect/invocation/request/result identity, and qualify the durable
// reader. This pure codec grants no settlement authority or production evidence.
// Pi checks the tool identity and image capability against its durable call.
func ValidateSessionPiResult(encodedLedgerResult, normalizedCBOR []byte, bounds Bounds) ([]byte, error) {
	if len(normalizedCBOR) == 0 || len(normalizedCBOR) > maximumSessionPiResultBytes ||
		len(encodedLedgerResult) == 0 || len(encodedLedgerResult) > maximumSessionPiResultBytes+hardMaxExternalCommitIDBytes+sessionDispatchEnvelopeBytes {
		return nil, ErrInvalidRequest
	}
	facts, err := DecodeSessionDispatchResult(encodedLedgerResult, bounds)
	if err != nil || !bytes.Equal(facts.Output, normalizedCBOR) {
		return nil, ErrInvalidRequest
	}
	value, err := canonical.Decode(normalizedCBOR, canonical.Options{MaxBytes: maximumSessionPiResultBytes, MaxDepth: 64, MaxItems: 1_000_000})
	if err != nil {
		return nil, ErrInvalidRequest
	}
	result, ok := sessionPiRecord(value,
		[]string{"version", "toolCallId", "toolName", "content", "isError", "timestamp"}, []string{"details"})
	if !ok || result["version"] != int64(1) {
		return nil, ErrInvalidRequest
	}
	for _, key := range []string{"toolCallId", "toolName"} {
		if text, ok := result[key].(string); !ok || text == "" || (key == "toolName" && len(text) > 256) {
			return nil, ErrInvalidRequest
		}
	}
	if _, ok := result["isError"].(bool); !ok {
		return nil, ErrInvalidRequest
	}
	if timestamp, ok := result["timestamp"].(int64); !ok || timestamp < 0 {
		return nil, ErrInvalidRequest
	}
	content, ok := result["content"].(canonical.Array)
	if !ok {
		return nil, ErrInvalidRequest
	}
	for _, value := range content {
		block, ok := value.(canonical.Map)
		if !ok {
			return nil, ErrInvalidRequest
		}
		var fields []string
		switch block["type"] {
		case "text":
			block, ok = sessionPiRecord(block, []string{"type", "text"}, []string{"textSignature"})
			fields = []string{"text", "textSignature"}
		case "image":
			block, ok = sessionPiRecord(block, []string{"type", "data", "mimeType"}, nil)
			fields = []string{"data", "mimeType"}
		default:
			return nil, ErrInvalidRequest
		}
		if !ok {
			return nil, ErrInvalidRequest
		}
		for _, key := range fields {
			if value, present := block[key]; present {
				if _, ok := value.(string); !ok {
					return nil, ErrInvalidRequest
				}
			}
		}
	}
	return bytes.Clone(normalizedCBOR), nil
}

func sessionPiRecord(value canonical.Value, required, optional []string) (canonical.Map, bool) {
	object, ok := value.(canonical.Map)
	if !ok || len(object) < len(required) || len(object) > len(required)+len(optional) {
		return nil, false
	}
	allowed := make(map[string]bool, len(required)+len(optional))
	for _, key := range required {
		if _, present := object[key]; !present {
			return nil, false
		}
		allowed[key] = true
	}
	for _, key := range optional {
		allowed[key] = true
	}
	for key := range object {
		if !allowed[key] {
			return nil, false
		}
	}
	return object, true
}
