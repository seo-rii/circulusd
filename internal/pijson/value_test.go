package pijson

import (
	"errors"
	"strings"
	"testing"

	"github.com/hancomac/circulusd/internal/canonical"
)

func TestDecodeValueUsesCallerBounds(t *testing.T) {
	value := canonical.Map{"payload": strings.Repeat("x", (1<<20)+1), "scale": canonical.Map{NumberWrapperKey: "1.25"}}
	options := canonical.DefaultOptions()
	decoded, err := DecodeValue(value, options)
	if err != nil || decoded.(canonical.Map)["scale"] != float64(1.25) {
		t.Fatalf("MCP-sized arguments: %v", err)
	}
	options.MaxBytes = 1 << 20
	if _, err := DecodeValue(value, options); err == nil {
		t.Fatal("caller byte limit was ignored")
	}
}

func TestValueNormalizationRejectsNonEquivalentText(t *testing.T) {
	for _, transform := range []func(canonical.Value, canonical.Options) (canonical.Value, error){EncodeValue, DecodeValue} {
		text := "a" + strings.Repeat("\u0301", 31)
		for _, value := range []canonical.Value{text, canonical.Map{text: "value"}} {
			if _, err := transform(value, canonical.DefaultOptions()); !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("non-equivalent normalization accepted: %v", err)
			}
		}
		got, err := transform("e\u0301", canonical.DefaultOptions())
		if err != nil || got != "é" {
			t.Fatalf("ordinary NFC = %v, %v", got, err)
		}
	}
}
