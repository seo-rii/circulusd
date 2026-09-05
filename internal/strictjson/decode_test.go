package strictjson_test

import (
	"strings"
	"testing"

	"github.com/hancomac/circulusd/internal/strictjson"
)

func TestDecodeValidatesNestedSchemaAndKeepsMapKeys(t *testing.T) {
	type entry struct {
		Name string `json:"name,omitempty"`
	}
	type document struct {
		Entries []*entry          `json:"entries"`
		Labels  map[string]*entry `json:"labels"`
		Exact   string
		Ignored string `json:"-"`
	}
	for name, input := range map[string]string{
		"slice field":    `{"entries":[{"Name":"x"}]}`,
		"map value":      `{"labels":{"free-key":{"NAME":"x"}}}`,
		"duplicate":      `{"entries":[],"entries":[]}`,
		"escaped repeat": `{"entries":[],"entr\u0069es":[]}`,
		"ignored":        `{"Ignored":"x"}`,
		"untagged alias": `{"exact":"x"}`,
		"wrong shape":    `{"entries":{}}`,
		"trailing":       `{} {}`,
		"malformed":      `{"entries":[}`,
	} {
		t.Run(name, func(t *testing.T) {
			var target document
			if err := strictjson.Decode([]byte(input), &target); err == nil {
				t.Fatal("accepted invalid document")
			}
		})
	}
	var target document
	if err := strictjson.Decode([]byte(`{"entr\u0069es":[null,{"name":"x"}],"labels":{"a":{"name":"lower"},"A":{"name":"upper"}},"Exact":"ok"}`), &target); err != nil {
		t.Fatal(err)
	}
	if len(target.Entries) != 2 || target.Entries[0] != nil || target.Entries[1].Name != "x" ||
		target.Labels["a"].Name != "lower" || target.Labels["A"].Name != "upper" || target.Exact != "ok" {
		t.Fatalf("decoded fields were changed: %#v", target)
	}
}

func TestDecodeBoundsDepthAndRequiresDestination(t *testing.T) {
	var target any
	if err := strictjson.Decode([]byte(strings.Repeat("[", 65)+"0"+strings.Repeat("]", 65)), &target); err == nil {
		t.Fatal("accepted excess depth")
	}
	for _, destination := range []any{nil, (*string)(nil), "not a pointer"} {
		if err := strictjson.Decode([]byte(`"value"`), destination); err == nil {
			t.Fatal("accepted invalid destination")
		}
	}
}
