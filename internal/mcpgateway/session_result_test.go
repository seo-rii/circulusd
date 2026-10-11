package mcpgateway

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/hancomac/circulusd/internal/canonical"
)

func TestSessionPiToolResultPreservesActualColdEngineFixture(t *testing.T) {
	body := sessionPiToolFixture(t)
	ledger := sessionPiToolLedger(t, body)
	result, err := ValidateSessionPiResult(ledger, body, testBounds())
	if err != nil || !bytes.Equal(result, body) {
		t.Fatalf("actual Pi canonical tool body changed: %v", err)
	}
	result[0] ^= 0xff
	if got, err := ValidateSessionPiResult(ledger, body, testBounds()); err != nil || !bytes.Equal(got, body) {
		t.Fatal("returned bytes alias caller storage")
	}
}

func TestSessionPiToolResultRejectsInventedOrGenericOutput(t *testing.T) {
	body := sessionPiToolFixture(t)
	for _, invalid := range [][]byte{nil, []byte("done"), []byte(`{"ok":true}`), append(bytes.Clone(body), 0), bytes.Repeat([]byte{0}, maximumSessionPiResultBytes+1)} {
		ledger := sessionPiToolLedger(t, invalid)
		if got, err := ValidateSessionPiResult(ledger, invalid, testBounds()); got != nil || !errors.Is(err, ErrInvalidRequest) {
			t.Fatal("generic, malformed or oversized tool output accepted")
		}
	}
	if got, err := ValidateSessionPiResult(sessionPiToolLedger(t, []byte(`{"ok":true}`)), body, testBounds()); got != nil || !errors.Is(err, ErrInvalidRequest) {
		t.Fatal("unretained Pi envelope substituted for generic tool output")
	}
	if got, err := ValidateSessionPiResult(sessionPiToolLedger(t, body), body, Bounds{}); got != nil || !errors.Is(err, ErrInvalidRequest) {
		t.Fatal("invalid bounds accepted")
	}
}

func TestSessionPiToolResultValidatesOriginalEnvelope(t *testing.T) {
	body := sessionPiToolFixture(t)
	for _, test := range []struct {
		name string
		edit func(canonical.Map)
	}{
		{"missing timestamp", func(m canonical.Map) { delete(m, "timestamp") }},
		{"missing name", func(m canonical.Map) { delete(m, "toolName") }},
		{"empty identity", func(m canonical.Map) { m["toolCallId"] = "" }},
		{"future version", func(m canonical.Map) { m["version"] = int64(2) }},
		{"invalid error flag", func(m canonical.Map) { m["isError"] = "false" }},
		{"negative time", func(m canonical.Map) { m["timestamp"] = int64(-1) }},
		{"unexpected field", func(m canonical.Map) { m["newField"] = "value" }},
		{"invalid content", func(m canonical.Map) { m["content"] = "done" }},
		{"invalid text", func(m canonical.Map) { m["content"] = canonical.Array{canonical.Map{"type": "text", "text": int64(1)}} }},
		{"unknown block field", func(m canonical.Map) {
			m["content"] = canonical.Array{canonical.Map{"type": "text", "text": "done", "unknown": true}}
		}},
		{"unknown block kind", func(m canonical.Map) { m["content"] = canonical.Array{canonical.Map{"type": "audio"}} }},
		{"invalid signature", func(m canonical.Map) {
			m["content"] = canonical.Array{canonical.Map{"type": "text", "text": "done", "textSignature": int64(1)}}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			value, err := canonical.Decode(body, canonical.DefaultOptions())
			if err != nil {
				t.Fatal(err)
			}
			test.edit(value.(canonical.Map))
			changed, err := canonical.Encode(value, canonical.DefaultOptions())
			if err != nil {
				t.Fatal(err)
			}
			if got, err := ValidateSessionPiResult(sessionPiToolLedger(t, changed), changed, testBounds()); got != nil || !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("invalid tool envelope accepted: %v", err)
			}
		})
	}
}

func TestSessionPiToolResultPreservesCommittedToolErrorAndDetails(t *testing.T) {
	value, err := canonical.Decode(sessionPiToolFixture(t), canonical.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	object := value.(canonical.Map)
	object["isError"] = true
	object["details"] = canonical.Map{"original": canonical.Bytes{1, 2, 3}, "nested": canonical.Array{nil, false}}
	object["content"] = canonical.Array{
		canonical.Map{"type": "text", "text": "tool error", "textSignature": "signature"},
		canonical.Map{"type": "image", "data": "AQID", "mimeType": "image/png"},
	}
	body, err := canonical.Encode(object, canonical.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ValidateSessionPiResult(sessionPiToolLedger(t, body), body, testBounds()); err != nil || !bytes.Equal(got, body) {
		t.Fatalf("committed tool error/details altered: %v", err)
	}
}

func sessionPiToolLedger(t *testing.T, body []byte) []byte {
	t.Helper()
	encoded, err := encodeSessionDispatchResult(SessionDispatchResult{Output: body, ExternalCommitID: "pi-fixture-commit"}, Bounds{
		MaxOutputBytes: maximumSessionPiResultBytes + 1, MaxExternalCommitIDBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func sessionPiToolFixture(t *testing.T) []byte {
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
		if item.Name == "tool_result" {
			body, err := hex.DecodeString(item.PayloadHex)
			if err != nil {
				t.Fatal(err)
			}
			return body
		}
	}
	t.Fatal("actual Pi tool fixture missing")
	return nil
}
