package release

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
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
		if !reflect.DeepEqual(strict, standard) {
			t.Fatalf("strict and standard decoders disagree on an accepted manifest")
		}
	})
}

// FuzzStrictJSONFieldNames constructs schema-valid documents, then independently
// requires rejection of case aliases, unknown members and duplicate members.
// It therefore detects overly permissive decoding as well as false rejections.
func FuzzStrictJSONFieldNames(f *testing.F) {
	for index := byte(0); index < 7; index++ {
		f.Add(index, uint64(1), "field value")
		f.Add(index, ^uint64(0), "한글\u0000e\u0301")
	}
	f.Fuzz(func(t *testing.T, selector byte, mask uint64, text string) {
		if len(text) > 1024 {
			t.Skip()
		}
		quoted, err := json.Marshal(text)
		if err != nil {
			t.Fatal(err)
		}
		targets := []struct{ prefix, key, value, suffix string }{
			{`{`, "schemaVersion", "1", `}`},
			{`{"release":{`, "version", string(quoted), `}}`},
			{`{"components":[{`, "name", string(quoted), `}]}`},
			{`{"components":[{"artifacts":[{`, "sha256", string(quoted), `}]}]}`},
			{`{"components":[{"artifacts":[{"signature":{`, "keyId", string(quoted), `}}]}]}`},
			{`{"protocolCompatibility":[{"minimum":{`, "major", "1", `}}]}`},
			{`{"signatures":[{`, "algorithm", string(quoted), `}]}`},
		}
		target := targets[int(selector)%len(targets)]
		decode := func(members string) error {
			var manifest Manifest
			return decodeStrictJSON([]byte(target.prefix+members+target.suffix), "fuzz", &manifest)
		}
		member := `"` + target.key + `":` + target.value
		if err := decode(member); err != nil {
			t.Fatalf("rejected canonical field %q: %v", target.key, err)
		}
		alias := []byte(target.key)
		for index, character := range alias {
			if mask&(uint64(1)<<uint(index)) != 0 &&
				(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z') {
				alias[index] ^= 0x20
			}
		}
		if string(alias) == target.key {
			alias[0] ^= 0x20
		}
		escaped := fmt.Sprintf(`"\u%04x%s":%s`, target.key[0], target.key[1:], target.value)
		if err := decode(escaped); err != nil {
			t.Fatalf("rejected a canonical escaped field: %v", err)
		}
		for _, members := range []string{
			`"` + string(alias) + `":` + target.value,
			member + `,"` + string(alias) + `":` + target.value,
			member + "," + member,
			member + "," + escaped,
			strings.Replace(member, target.key, "unknown_"+target.key, 1),
		} {
			if err := decode(members); err == nil {
				t.Fatalf("accepted noncanonical members: %s", members)
			}
		}
	})
}
