package mcpgateway

import (
	"bytes"
	"errors"
	"github.com/hancomac/circulusd/internal/canonical"
	"testing"
)

func TestSessionPiMarkedToolDetails(t *testing.T) {
	for _, details := range []canonical.Value{nil, true, "", int64(1), canonical.Map{"scale": canonical.Map{"$pi.number.v1": "0.5"}, "nested": canonical.Array{nil, canonical.Map{"$pi.number.v1": "1e-7"}, canonical.Map{"$pi.number.v1": "1e+21"}}}} {
		value, err := canonical.Decode(sessionPiToolFixture(t), canonical.DefaultOptions())
		if err != nil {
			t.Fatal(err)
		}
		body := value.(canonical.Map)
		body["detailsEncoding"] = "pi-tool-details-json-v1"
		body["details"] = details
		encoded, err := canonical.Encode(body, canonical.DefaultOptions())
		if err != nil {
			t.Fatal(err)
		}
		got, err := ValidateSessionPiResult(sessionPiToolLedger(t, encoded), encoded, testBounds())
		if err != nil || !bytes.Equal(got, encoded) {
			t.Fatalf("marked details changed or rejected: %v", err)
		}
	}
}
func TestSessionPiRejectsMalformedMarkedToolDetails(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(canonical.Map)
	}{
		{"missing details", func(m canonical.Map) { delete(m, "details") }},
		{"unknown codec", func(m canonical.Map) { m["detailsEncoding"] = "future" }},
		{"wrong codec type", func(m canonical.Map) { m["detailsEncoding"] = int64(1) }},
		{"binary", func(m canonical.Map) { m["details"] = canonical.Bytes{1} }},
		{"integer wrapper", func(m canonical.Map) { m["details"] = canonical.Map{"$pi.number.v1": "1"} }},
		{"negative zero", func(m canonical.Map) { m["details"] = canonical.Map{"$pi.number.v1": "-0"} }},
		{"infinity", func(m canonical.Map) { m["details"] = canonical.Map{"$pi.number.v1": "Infinity"} }},
		{"noncanonical decimal", func(m canonical.Map) { m["details"] = canonical.Map{"$pi.number.v1": "0.50"} }},
		{"mixed wrapper", func(m canonical.Map) { m["details"] = canonical.Map{"$pi.number.v1": "0.5", "extra": true} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			value, err := canonical.Decode(sessionPiToolFixture(t), canonical.DefaultOptions())
			if err != nil {
				t.Fatal(err)
			}
			body := value.(canonical.Map)
			body["detailsEncoding"] = "pi-tool-details-json-v1"
			body["details"] = nil
			test.edit(body)
			encoded, err := canonical.Encode(body, canonical.DefaultOptions())
			if err != nil {
				t.Fatal(err)
			}
			if got, err := ValidateSessionPiResult(sessionPiToolLedger(t, encoded), encoded, testBounds()); got != nil || !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("malformed details accepted: %v", err)
			}
		})
	}
}
func TestSessionPiUnmarkedDetailsRemainOpaque(t *testing.T) {
	for _, details := range []canonical.Value{canonical.Map{"$pi.number.v1": "opaque"}, canonical.Bytes{1, 2, 3}, canonical.Map{"nested": canonical.Array{canonical.Bytes{4}, nil}}} {
		value, err := canonical.Decode(sessionPiToolFixture(t), canonical.DefaultOptions())
		if err != nil {
			t.Fatal(err)
		}
		body := value.(canonical.Map)
		body["details"] = details
		encoded, err := canonical.Encode(body, canonical.DefaultOptions())
		if err != nil {
			t.Fatal(err)
		}
		if got, err := ValidateSessionPiResult(sessionPiToolLedger(t, encoded), encoded, testBounds()); err != nil || !bytes.Equal(got, encoded) {
			t.Fatalf("opaque details changed: %v", err)
		}
	}
}
