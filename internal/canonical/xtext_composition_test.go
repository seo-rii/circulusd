package canonical

import "testing"

// x/text before v0.42.0 looked canonical composition pairs up by the low 16
// bits of each rune and composed a leading non-starter, so NFC turned these
// already-normalized strings into unrelated characters (golang/go#81028, fixed
// by CL 822082). Encoding must keep each of them unchanged.
func TestEncodeKeepsTextThatTruncatedCompositionRewrote(t *testing.T) {
	t.Parallel()

	for _, text := range []string{
		"\U00010041\u0301", // was U+00C1
		"\U00020041\u0301", // was U+00C1
		"\u1099\U000110BA", // was U+1109A
		"\U00011F41\u0301", // was U+1F45
		"\u05D2\u0307",     // was U+105C9
		"\u05DA\u0307",     // was U+105E4
	} {
		for _, value := range []Value{text, Map{text: int64(1)}} {
			encoded, err := Encode(value, DefaultOptions())
			if err != nil {
				t.Fatalf("Encode(%+q) error = %v", value, err)
			}
			decoded, err := Decode(encoded, DefaultOptions())
			if err != nil {
				t.Fatalf("Decode(Encode(%+q)) error = %v", value, err)
			}
			if got, ok := decoded.(string); ok && got != text {
				t.Fatalf("Encode(%+q) round trip = %+q, want the text unchanged", text, got)
			}
			if got, ok := decoded.(Map); ok {
				if _, found := got[text]; !found || len(got) != 1 {
					t.Fatalf("Encode(map key %+q) round trip = %+q, want the key unchanged", text, got)
				}
			}
		}
	}
}
