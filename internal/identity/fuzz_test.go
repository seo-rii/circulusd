package identity

import (
	"bytes"
	"testing"
)

func identityFuzzSeeds(tb testing.TB) [][]byte {
	tb.Helper()
	seeds := make([][]byte, 0, len(declaredKinds)+9)
	generator := Generator{Random: bytes.NewReader(bytes.Repeat([]byte{0xA5}, entropyBytes*(len(declaredKinds)+1)))}
	for _, kind := range declaredKinds {
		id, err := generator.New(kind)
		if err != nil {
			tb.Fatalf("seed New(%q) error = %v", kind, err)
		}
		seeds = append(seeds, []byte(id.String()))
	}
	seeds = append(seeds,
		[]byte(""),
		[]byte("_"),
		[]byte("sess_"),
		[]byte("sess"),
		[]byte("sess__"),
		[]byte("unknown_AAAAAAAAAAAAAAAAAAAAAAAAAA"),   // undeclared kind, 26-char tail
		[]byte("sess_AAAAAAAAAAAAAAAAAAAAAAAAA1"),      // non-canonical base32 tail
		[]byte("sess_aaaaaaaaaaaaaaaaaaaaaaaaaa"),      // lowercase tail (encoder emits uppercase)
		[]byte("sess_AAAAAAAAAAAAAAAAAAAAAAAAAAAA"),    // over-long tail
	)
	return seeds
}

// FuzzParseIdentity asserts the security-relevant properties of identity
// parsing against arbitrary bytes:
//
//   - parsing never panics; malformed identities are rejected.
//   - an accepted identity is stored verbatim — no silent normalization that
//     would let two distinct byte strings denote the same identity.
//   - parsing is idempotent and Parse binds the kind: the matching kind accepts
//     and every other declared kind rejects the same text.
func FuzzParseIdentity(f *testing.F) {
	for _, seed := range identityFuzzSeeds(f) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var id ID
		if err := id.UnmarshalText(data); err != nil {
			return // rejection is always acceptable; the contract is "never panic".
		}
		if id.String() != string(data) {
			t.Fatalf("parsed identity mutated its text: got %q, want %q", id.String(), string(data))
		}
		if !isDeclaredKind(id.Kind()) {
			t.Fatalf("parsed identity has an undeclared kind %q", id.Kind())
		}
		var again ID
		if err := again.UnmarshalText([]byte(id.String())); err != nil {
			t.Fatalf("re-parse of %q failed: %v", id.String(), err)
		}
		if again != id {
			t.Fatalf("re-parse produced a different identity: %+v vs %+v", again, id)
		}
		if parsed, err := Parse(id.Kind(), id.String()); err != nil || parsed != id {
			t.Fatalf("Parse(%q, %q) = (%+v, %v), want the original identity", id.Kind(), id.String(), parsed, err)
		}
		for _, other := range declaredKinds {
			if other == id.Kind() {
				continue
			}
			if _, err := Parse(other, id.String()); err == nil {
				t.Fatalf("Parse(%q, %q) accepted a mismatched kind", other, id.String())
			}
		}
	})
}
