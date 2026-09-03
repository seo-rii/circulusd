package release

import (
	"encoding/json"
	"testing"
)

// FuzzDecodeStrictJSON checks the hand-rolled strict JSON walker against
// arbitrary input:
//
//   - it never panics.
//   - it is strictly more restrictive than encoding/json: it additionally
//     rejects duplicate object members, unknown fields, and trailing data. So
//     anything it accepts, a plain json.Unmarshal into the same type must accept
//     too. A counterexample means the token walk accepted malformed JSON the
//     real decoder would reject — a parser-confusion hole for release manifests.
func FuzzDecodeStrictJSON(f *testing.F) {
	seeds := []string{
		`{}`,
		`[]`,
		`{"a":1}`,
		`{"a":{"b":[1,2,3]}}`,
		`[1,"two",true,null]`,
		`{"a":1,"a":2}`,
		`{} trailing`,
		`{`,
		`[1,2,`,
		`{"a":1} {"b":2}`,
		`123`,
		`"x"`,
		`true`,
		`null`,
		`{"schemaVersion":1,"release":{"version":"0.0.0","status":"development","architectures":[]},"components":[]}`,
	}
	for _, seed := range seeds {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var strict Manifest
		if err := decodeStrictJSON(data, "fuzz", &strict); err != nil {
			return // rejection is always acceptable; the contract is "never panic".
		}
		var standard Manifest
		if err := json.Unmarshal(data, &standard); err != nil {
			t.Fatalf("decodeStrictJSON accepted input that json.Unmarshal rejects: %v\ninput: %q", err, data)
		}
	})
}
