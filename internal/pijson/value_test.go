package pijson

import (
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
