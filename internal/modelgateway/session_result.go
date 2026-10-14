package modelgateway

import (
	"bytes"
	"math"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/hancomac/circulusd/internal/canonical"
)

const maximumSessionPiResultBytes = 1 << 20

// ValidateSessionPiResult checks an independently retained Pi v2 model body
// against the immutable Session model terminal observation. It returns a copy
// of the original canonical bytes, preserving decimal costs and fractional
// tool arguments. The observation does not contain enough information to
// synthesize api/provider/model, timestamps, cache usage, or costs.
//
// The caller must authenticate both records, verify TerminalCommitted and their
// exact effect/invocation/request/result identity, and qualify their durable
// reader. This pure codec supplies neither settlement authority nor evidence of
// production qualification. Pi still checks model and tool configuration when
// consuming the settlement.
func ValidateSessionPiResult(encodedLedgerResult, normalizedCBOR []byte) ([]byte, error) {
	if len(encodedLedgerResult) == 0 || len(encodedLedgerResult) > 6*maximumSessionPiResultBytes+sessionDispatchResultEnvelopeBytes ||
		len(normalizedCBOR) == 0 || len(normalizedCBOR) > maximumSessionPiResultBytes {
		return nil, ErrInvalidRequest
	}
	facts, err := DecodeSessionDispatchResult(encodedLedgerResult)
	if err != nil || facts.State != StateCompleted || facts.Outcome != OutcomeCompleted || facts.PartialOutput != (facts.StreamBytes > 0) ||
		facts.FailureReason != "" || facts.ProviderRequestID == "" || facts.Response == nil ||
		facts.Revision != uint64(facts.EventCount)+1 || facts.EventCount > hardMaxEvents ||
		facts.EventBytes > uint64(facts.EventCount)*hardMaxEventBytes || facts.StreamBytes > hardMaxStreamBytes ||
		facts.Attempt > hardMaxPreDispatchRetries+1 || len(facts.ProviderRequestID) > hardMaxProviderRequestIDBytes ||
		!utf8.ValidString(facts.ProviderRequestID) || strings.IndexFunc(facts.ProviderRequestID, unicode.IsControl) >= 0 {
		return nil, ErrInvalidRequest
	}
	value, err := canonical.Decode(normalizedCBOR, canonical.Options{MaxBytes: maximumSessionPiResultBytes, MaxDepth: 64, MaxItems: 1_000_000})
	if err != nil {
		return nil, ErrInvalidRequest
	}
	result, ok := sessionPiRecord(value, []string{"version", "message"}, nil)
	if !ok || result["version"] != int64(2) {
		return nil, ErrInvalidRequest
	}
	message, ok := sessionPiRecord(result["message"],
		[]string{"role", "content", "api", "provider", "model", "usage", "stopReason", "timestamp"},
		[]string{"responseModel", "responseId", "errorMessage", "rawStopReason", "endTurn"})
	if !ok || message["role"] != "assistant" || !sessionPiSafeUint(message["timestamp"]) {
		return nil, ErrInvalidRequest
	}
	for _, key := range []string{"api", "provider", "model"} {
		if text, ok := message[key].(string); !ok || text == "" {
			return nil, ErrInvalidRequest
		}
	}
	for _, key := range []string{"responseModel", "responseId", "errorMessage", "rawStopReason"} {
		if value, present := message[key]; present {
			if _, ok := value.(string); !ok {
				return nil, ErrInvalidRequest
			}
		}
	}
	if value, present := message["endTurn"]; present {
		if _, ok := value.(bool); !ok {
			return nil, ErrInvalidRequest
		}
	}
	usage, ok := sessionPiRecord(message["usage"],
		[]string{"input", "output", "cacheRead", "cacheWrite", "totalTokens", "cost"}, []string{"cacheWrite1h", "reasoning"})
	if !ok {
		return nil, ErrInvalidRequest
	}
	for key, value := range usage {
		if key != "cost" && !sessionPiSafeUint(value) {
			return nil, ErrInvalidRequest
		}
	}
	// These are the provider's Pi usage counters. Gateway Usage is normalized
	// quota accounting, so equating the two would silently rewrite real usage.
	cost, ok := sessionPiRecord(usage["cost"], []string{"encoding", "input", "output", "cacheRead", "cacheWrite", "total"}, nil)
	if !ok || cost["encoding"] != "pi-cost-decimal-v1" {
		return nil, ErrInvalidRequest
	}
	for key, value := range cost {
		if key == "encoding" {
			continue
		}
		decimal, ok := value.(string)
		if !ok || len(decimal) > 32 {
			return nil, ErrInvalidRequest
		}
		number, parseErr := strconv.ParseFloat(decimal, 64)
		encoded, encodeErr := piNumberDecimal(number)
		if parseErr != nil || encodeErr != nil || math.Signbit(number) || encoded != decimal {
			return nil, ErrInvalidRequest
		}
	}
	stop, ok := message["stopReason"].(string)
	if want, settleable := sessionPiStopReason(facts.Response); !ok || !settleable || stop != want {
		return nil, ErrInvalidRequest
	}
	content, ok := message["content"].(canonical.Array)
	if !ok {
		return nil, ErrInvalidRequest
	}
	var text strings.Builder
	var calls []ToolCall
	for _, value := range content {
		block, ok := value.(canonical.Map)
		if !ok {
			return nil, ErrInvalidRequest
		}
		switch block["type"] {
		case "text":
			block, ok = sessionPiRecord(block, []string{"type", "text"}, []string{"textSignature"})
			if !ok || !sessionPiStrings(block, "text", "textSignature") {
				return nil, ErrInvalidRequest
			}
			text.WriteString(block["text"].(string))
		case "thinking":
			block, ok = sessionPiRecord(block, []string{"type", "thinking"}, []string{"thinkingSignature", "redacted"})
			if !ok || !sessionPiStrings(block, "thinking", "thinkingSignature") {
				return nil, ErrInvalidRequest
			}
			if value, present := block["redacted"]; present {
				if _, ok := value.(bool); !ok {
					return nil, ErrInvalidRequest
				}
			}
		case "toolCall":
			block, ok = sessionPiRecord(block, []string{"type", "id", "name", "arguments"}, []string{"thoughtSignature", "namespace"})
			if !ok || !sessionPiStrings(block, "id", "name", "thoughtSignature", "namespace") {
				return nil, ErrInvalidRequest
			}
			arguments, ok := block["arguments"].(canonical.Map)
			if !ok {
				return nil, ErrInvalidRequest
			}
			if _, reserved := arguments[piNumberWrapperKey]; reserved {
				return nil, ErrInvalidRequest
			}
			argumentBytes, err := canonical.Encode(arguments, canonical.Options{MaxBytes: maximumSessionPiResultBytes, MaxDepth: 64, MaxItems: 1_000_000})
			if err != nil {
				return nil, ErrInvalidRequest
			}
			parsed, err := ParseCanonicalToolArguments(argumentBytes)
			if err != nil || len(calls) >= len(facts.Response.ToolCalls) {
				return nil, ErrInvalidRequest
			}
			calls = append(calls, ToolCall{ID: block["id"].(string), Name: block["name"].(string), Arguments: parsed,
				Order: facts.Response.ToolCalls[len(calls)].Order})
		default:
			return nil, ErrInvalidRequest
		}
	}
	normalizedCalls, toolBytes, err := normalizeToolCalls(facts.Response.ToolCalls)
	if err != nil || !equalToolCalls(normalizedCalls, facts.Response.ToolCalls) ||
		!equalToolCalls(calls, facts.Response.ToolCalls) || text.String() != facts.Response.Text ||
		(stop == "toolUse") != (len(calls) > 0) ||
		facts.StreamBytes+uint64(len(facts.ProviderRequestID)+len(facts.Response.Text)+len(facts.Response.FinishReason))+toolBytes > facts.EventBytes {
		return nil, ErrInvalidRequest
	}
	// Decode rejects non-canonical encodings; retain precisely those bytes rather
	// than rebuilding a provider message or rounding its decimal fields.
	return bytes.Clone(normalizedCBOR), nil
}

// sessionPiStopReason returns the Pi v2 stop reason for a completed response.
// Pi has no stop reason for content filtering, cancellation or unrecognized
// provider reasons, and reports toolUse exactly when tool calls are present,
// so any other response can never be settled as a Session model result.
func sessionPiStopReason(response *ModelResponse) (string, bool) {
	if response == nil {
		return "", false
	}
	var stop string
	switch response.FinishReason {
	case FinishReasonStop:
		stop = "stop"
	case FinishReasonLength:
		stop = "length"
	case FinishReasonToolCalls:
		stop = "toolUse"
	default:
		return "", false
	}
	if (stop == "toolUse") != (len(response.ToolCalls) > 0) {
		return "", false
	}
	return stop, true
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

func sessionPiSafeUint(value canonical.Value) bool {
	number, ok := value.(int64)
	return ok && number >= 0 && uint64(number) <= maxCanonicalInteger
}

func sessionPiStrings(object canonical.Map, keys ...string) bool {
	for _, key := range keys {
		if value, present := object[key]; present {
			if _, ok := value.(string); !ok {
				return false
			}
		}
	}
	return true
}
