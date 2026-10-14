package modelgateway

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/effectledger"
)

func TestSessionPiModelResultMatchesActualSessionDispatchTerminalEncoder(t *testing.T) {
	for _, name := range []string{"model_tool_call", "model_final"} {
		t.Run(name, func(t *testing.T) {
			body := sessionPiModelFixture(t, name)
			wire := sessionPiModelFacts(t, body)
			response := &ProviderResponse{Text: wire.Response.Text, FinishReason: string(wire.Response.FinishReason), Usage: wire.Response.Usage}
			for _, call := range wire.Response.ToolCalls {
				arguments, err := ParseCanonicalToolArguments(call.Arguments)
				if err != nil {
					t.Fatal(err)
				}
				response.ToolCalls = append(response.ToolCalls, ToolCall{ID: call.ID, Name: call.Name, Arguments: arguments, Order: call.Order})
			}
			fixture := newSessionDispatchTest(t, &scriptedSessionProviderStream{events: []ProviderEvent{{Kind: ProviderEventResponseCompleted, Response: response}}}, nil, true)
			// The shared reference fixture intentionally has a 32-byte event
			// budget; this real fractional tool response needs a larger budget.
			gateway := *fixture.gateway
			gateway.bounds.MaxEventBytes = 1024
			gateway.bounds.MaxResponseBytes = 1024
			fixture.gateway = &gateway
			starter, err := NewReferenceSessionDispatchStarter(&gateway, fixture.ledger, fixture.starter.RouteDigest())
			if err != nil {
				t.Fatal(err)
			}
			fixture.starter = starter
			digest, err := fixture.starter.Prepare(context.Background(), fixture.dispatch, fixture.transition)
			if err != nil {
				t.Fatal(err)
			}
			consumer, _ := fixture.consumer(t, digest)
			if _, err := consumer.StartExactAttempt(context.Background(), fixture.startRequest(digest)); err != nil {
				t.Fatal(err)
			}
			facts, err := fixture.ledger.Inspect(context.Background(), sessionLookup(fixture.dispatch))
			if err != nil || facts.Terminal.Status != effectledger.TerminalCommitted {
				t.Fatalf("fixture did not commit an actual terminal observation: %v", err)
			}
			if got, err := ValidateSessionPiResult(facts.Terminal.Result, body); err != nil || !bytes.Equal(got, body) {
				t.Fatalf("actual Session terminal encoder did not retain matching Pi facts: %v", err)
			}
		})
	}
}

func TestSessionDispatchDoesNotCommitCompletionsPiCannotSettle(t *testing.T) {
	arguments, err := NewCanonicalToolArguments(canonical.Map{"ok": true})
	if err != nil {
		t.Fatal(err)
	}
	call := ToolCall{ID: "call-a", Name: "lookup", Arguments: arguments, Order: ToolCallOrder{Declared: true}}
	for _, test := range []struct {
		name     string
		response ProviderResponse
		want     effectledger.TerminalStatus
	}{
		{"stop", ProviderResponse{FinishReason: "stop"}, effectledger.TerminalCommitted},
		{"tool use", ProviderResponse{FinishReason: "tool_calls", ToolCalls: []ToolCall{call}}, effectledger.TerminalCommitted},
		{"content filter", ProviderResponse{FinishReason: "content_filter"}, effectledger.TerminalUnknown},
		{"cancelled", ProviderResponse{FinishReason: "cancelled"}, effectledger.TerminalUnknown},
		{"unrecognized reason", ProviderResponse{FinishReason: "provider_specific"}, effectledger.TerminalUnknown},
		{"tool use without calls", ProviderResponse{FinishReason: "tool_calls"}, effectledger.TerminalUnknown},
		{"stop with calls", ProviderResponse{FinishReason: "stop", ToolCalls: []ToolCall{call}}, effectledger.TerminalUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := test.response
			response.Text, response.Usage = "done", Usage{InputTokens: 11, OutputTokens: 3}
			fixture := newSessionDispatchTest(t, &scriptedSessionProviderStream{events: []ProviderEvent{
				{Kind: ProviderEventResponseCompleted, Response: &response},
			}}, nil, true)
			gateway := *fixture.gateway
			gateway.bounds.MaxEventBytes = 1024
			gateway.bounds.MaxResponseBytes = 1024
			starter, err := NewReferenceSessionDispatchStarter(&gateway, fixture.ledger, fixture.starter.RouteDigest())
			if err != nil {
				t.Fatal(err)
			}
			fixture.starter = starter
			digest, err := fixture.starter.Prepare(context.Background(), fixture.dispatch, fixture.transition)
			if err != nil {
				t.Fatal(err)
			}
			consumer, _ := fixture.consumer(t, digest)
			if _, err := consumer.StartExactAttempt(context.Background(), fixture.startRequest(digest)); err != nil {
				t.Fatal(err)
			}
			facts, err := fixture.ledger.Inspect(context.Background(), sessionLookup(fixture.dispatch))
			if err != nil || facts.Terminal.Status != test.want {
				t.Fatalf("terminal status = %q, %v; want %q", facts.Terminal.Status, err, test.want)
			}
			result, err := DecodeSessionDispatchResult(facts.Terminal.Result)
			if err != nil || (result.State == StateCompleted) != (test.want == effectledger.TerminalCommitted) {
				t.Fatalf("terminal result = %#v, %v", result, err)
			}
		})
	}
}

func TestSessionPiModelResultPreservesActualColdEngineFixture(t *testing.T) {
	for _, name := range []string{"model_tool_call", "model_final"} {
		t.Run(name, func(t *testing.T) {
			body := sessionPiModelFixture(t, name)
			wire := sessionPiModelFacts(t, body)
			ledger := sessionPiModelJSON(t, wire)
			result, err := ValidateSessionPiResult(ledger, body)
			if err != nil || !bytes.Equal(result, body) {
				t.Fatalf("actual Pi canonical body changed: %v", err)
			}
			result[0] ^= 0xff
			again, err := ValidateSessionPiResult(ledger, body)
			if err != nil || !bytes.Equal(again, body) {
				t.Fatal("returned bytes alias caller input")
			}
			// Costs and true provider usage survive even when gateway accounting
			// charged a larger admitted reservation to the same invocation.
			wire.Response.Usage = Usage{InputTokens: 1000, OutputTokens: 2000}
			if got, err := ValidateSessionPiResult(sessionPiModelJSON(t, wire), body); err != nil || !bytes.Equal(got, body) {
				t.Fatalf("quota accounting rewrote Pi cost/usage: %v", err)
			}
			// PartialOutput records that deltas were streamed, even after a
			// successful final response. Completion, not that historical flag,
			// distinguishes a usable terminal body from an interrupted stream.
			wire.PartialOutput = true
			wire.StreamBytes = 4
			wire.EventBytes += 4
			wire.EventCount++
			wire.Revision++
			if got, err := ValidateSessionPiResult(sessionPiModelJSON(t, wire), body); err != nil || !bytes.Equal(got, body) {
				t.Fatalf("completed streamed response rejected: %v", err)
			}
		})
	}
}

func TestSessionPiModelResultRejectsMissingOrUnsupportedBodies(t *testing.T) {
	base := sessionPiModelFixture(t, "model_tool_call")
	for _, test := range []struct {
		name string
		edit func(canonical.Map)
	}{
		{"missing model", func(m canonical.Map) { delete(m["message"].(canonical.Map), "model") }},
		{"fabricated field", func(m canonical.Map) { m["message"].(canonical.Map)["invented"] = "value" }},
		{"wrong role", func(m canonical.Map) { m["message"].(canonical.Map)["role"] = "user" }},
		{"negative time", func(m canonical.Map) { m["message"].(canonical.Map)["timestamp"] = int64(-1) }},
		{"invalid metadata", func(m canonical.Map) { m["message"].(canonical.Map)["responseId"] = canonical.Map{} }},
		{"missing cost", func(m canonical.Map) { delete(m["message"].(canonical.Map)["usage"].(canonical.Map), "cost") }},
		{"legacy version", func(m canonical.Map) { m["version"] = int64(1) }},
		{"numeric cost", func(m canonical.Map) { piModelCost(m)["input"] = int64(0) }},
		{"negative cost", func(m canonical.Map) { piModelCost(m)["input"] = "-1" }},
		{"negative zero cost", func(m canonical.Map) { piModelCost(m)["input"] = "-0" }},
		{"noncanonical cost", func(m canonical.Map) { piModelCost(m)["input"] = "0.000001250" }},
		{"infinite cost", func(m canonical.Map) { piModelCost(m)["input"] = "Infinity" }},
		{"unsafe counter", func(m canonical.Map) { m["message"].(canonical.Map)["usage"].(canonical.Map)["input"] = "1" }},
		{"wrong stop", func(m canonical.Map) { m["message"].(canonical.Map)["stopReason"] = "stop" }},
		{"wrong tool identity", func(m canonical.Map) { piModelFirstBlock(m)["id"] = "different-call" }},
		{"wrong tool args", func(m canonical.Map) { piModelFirstBlock(m)["arguments"] = canonical.Map{"value": int64(2)} }},
		{"noncanonical wrapper", func(m canonical.Map) {
			piModelFirstBlock(m)["arguments"] = canonical.Map{"value": canonical.Map{piNumberWrapperKey: "1.250"}}
		}},
		{"scalar arguments", func(m canonical.Map) { piModelFirstBlock(m)["arguments"] = int64(1) }},
		{"unsupported content", func(m canonical.Map) { piModelFirstBlock(m)["type"] = "image" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := sessionPiModelDecode(t, base)
			test.edit(value)
			body, err := canonical.Encode(value, canonical.DefaultOptions())
			if err != nil {
				t.Fatal(err)
			}
			ledger := sessionPiModelJSON(t, sessionPiModelFacts(t, base))
			if got, err := ValidateSessionPiResult(ledger, body); got != nil || !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("invalid body accepted: %v", err)
			}
		})
	}
	for _, body := range [][]byte{nil, []byte(`{"version":2}`), append(bytes.Clone(base), 0), bytes.Repeat([]byte{0}, maximumSessionPiResultBytes+1)} {
		if got, err := ValidateSessionPiResult(sessionPiModelJSON(t, sessionPiModelFacts(t, base)), body); got != nil || !errors.Is(err, ErrInvalidRequest) {
			t.Fatal("malformed, generic, trailing or oversized body accepted")
		}
	}
}

func TestSessionPiModelResultRejectsIncompleteOrContradictoryFacts(t *testing.T) {
	body := sessionPiModelFixture(t, "model_final")
	for _, test := range []struct {
		name string
		edit func(*sessionDispatchResultWire)
	}{
		{"failed", func(w *sessionDispatchResultWire) { w.State = StateFailed }},
		{"unknown", func(w *sessionDispatchResultWire) { w.Outcome = OutcomeUncertain }},
		{"incomplete stream", func(w *sessionDispatchResultWire) { w.State = StateStreaming }},
		{"inconsistent stream flag", func(w *sessionDispatchResultWire) { w.PartialOutput = true }},
		{"failure reason", func(w *sessionDispatchResultWire) { w.FailureReason = "failed" }},
		{"unaccepted", func(w *sessionDispatchResultWire) { w.ProviderRequestID = "" }},
		{"no response", func(w *sessionDispatchResultWire) { w.Response = nil }},
		{"wrong text", func(w *sessionDispatchResultWire) { w.Response.Text = "changed" }},
		{"unknown finish", func(w *sessionDispatchResultWire) { w.Response.FinishReason = FinishReasonOther }},
		{"wrong revision", func(w *sessionDispatchResultWire) { w.Revision++ }},
		{"missing event bytes", func(w *sessionDispatchResultWire) { w.EventBytes = 0 }},
		{"oversized history", func(w *sessionDispatchResultWire) { w.EventBytes = uint64(w.EventCount)*hardMaxEventBytes + 1 }},
		{"invalid request ID", func(w *sessionDispatchResultWire) { w.ProviderRequestID = "request\n" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			wire := sessionPiModelFacts(t, body)
			test.edit(&wire)
			if got, err := ValidateSessionPiResult(sessionPiModelJSON(t, wire), body); got != nil || !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("invalid observation accepted: %v", err)
			}
		})
	}
}

func TestSessionPiModelResultRequiresOriginalToolOrder(t *testing.T) {
	body := sessionPiModelFixture(t, "model_tool_call")
	value := sessionPiModelDecode(t, body)
	message := value["message"].(canonical.Map)
	first := piModelFirstBlock(value)
	second := canonical.Map{"type": "toolCall", "id": "call_second", "name": first["name"], "arguments": first["arguments"]}
	message["content"] = canonical.Array{first, second}
	body, err := canonical.Encode(value, canonical.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	wire := sessionPiModelFacts(t, body)
	if _, err := ValidateSessionPiResult(sessionPiModelJSON(t, wire), body); err != nil {
		t.Fatalf("original declared order rejected: %v", err)
	}
	message["content"] = canonical.Array{second, first}
	changed, err := canonical.Encode(value, canonical.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ValidateSessionPiResult(sessionPiModelJSON(t, wire), changed); got != nil || !errors.Is(err, ErrInvalidRequest) {
		t.Fatal("changed tool order accepted")
	}
	wire.Response.ToolCalls[1].Order.Index = 0
	if got, err := ValidateSessionPiResult(sessionPiModelJSON(t, wire), body); got != nil || !errors.Is(err, ErrInvalidRequest) {
		t.Fatal("invalid ledger order accepted")
	}
}

func piModelCost(m canonical.Map) canonical.Map {
	return m["message"].(canonical.Map)["usage"].(canonical.Map)["cost"].(canonical.Map)
}
func piModelFirstBlock(m canonical.Map) canonical.Map {
	return m["message"].(canonical.Map)["content"].(canonical.Array)[0].(canonical.Map)
}
func sessionPiModelDecode(t *testing.T, body []byte) canonical.Map {
	t.Helper()
	value, err := canonical.Decode(body, canonical.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	return value.(canonical.Map)
}
func sessionPiModelJSON(t *testing.T, wire sessionDispatchResultWire) []byte {
	t.Helper()
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
func sessionPiModelFacts(t *testing.T, body []byte) sessionDispatchResultWire {
	t.Helper()
	message := sessionPiModelDecode(t, body)["message"].(canonical.Map)
	response := &sessionModelResponseWire{Usage: Usage{InputTokens: 1, OutputTokens: 2}, ToolCalls: []sessionToolCallWire{}}
	var text strings.Builder
	for _, value := range message["content"].(canonical.Array) {
		block := value.(canonical.Map)
		switch block["type"] {
		case "text":
			text.WriteString(block["text"].(string))
		case "toolCall":
			arguments, err := canonical.Encode(block["arguments"], canonical.DefaultOptions())
			if err != nil {
				t.Fatal(err)
			}
			response.ToolCalls = append(response.ToolCalls, sessionToolCallWire{ID: block["id"].(string), Name: block["name"].(string),
				Arguments: arguments, Order: ToolCallOrder{Declared: true, Index: uint32(len(response.ToolCalls))}})
		}
	}
	response.Text = text.String()
	switch message["stopReason"] {
	case "stop":
		response.FinishReason = FinishReasonStop
	case "toolUse":
		response.FinishReason = FinishReasonToolCalls
	}
	const requestID = "pi-fixture-request"
	eventBytes := uint64(len(requestID) + len(response.Text) + len(response.FinishReason))
	for _, call := range response.ToolCalls {
		eventBytes += uint64(len(call.ID) + len(call.Name) + len(call.Arguments) + 9)
	}
	return sessionDispatchResultWire{Version: sessionDispatchResultVersion, State: StateCompleted, Outcome: OutcomeCompleted,
		Revision: 4, Attempt: 1, EventCount: 3, EventBytes: eventBytes, ProviderRequestID: requestID, Response: response}
}
func sessionPiModelFixture(t *testing.T, name string) []byte {
	t.Helper()
	encoded, err := os.ReadFile("../../packages/protocol-types/fixtures/stateapp-pi-codec-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Version     int
		Settlements []struct{ Name, PayloadHex string }
	}
	if err := json.Unmarshal(encoded, &fixture); err != nil || fixture.Version != 1 {
		t.Fatalf("invalid actual Pi fixture: %v", err)
	}
	for _, item := range fixture.Settlements {
		if item.Name == name {
			body, err := hex.DecodeString(item.PayloadHex)
			if err != nil {
				t.Fatal(err)
			}
			return body
		}
	}
	t.Fatalf("fixture %s missing", name)
	return nil
}
