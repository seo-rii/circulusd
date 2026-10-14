package canonical

import (
	"fmt"
	"strings"

	"golang.org/x/text/unicode/norm"
)

// NormalizeNFC returns text in NFC. It fails closed with ErrInvalidValue when
// the result of golang.org/x/text NFC is not canonically equivalent to text.
//
// x/text inserts U+034F after 30 consecutive non-starters (the stream-safe
// text format), which Unicode NFC and the TypeScript side do not, so the two
// sides would encode the same text differently. x/text NFD inserts U+034F the
// same way, so this case is detected by counting U+034F. The NFD comparison
// rejects any other result that is not canonically equivalent; x/text before
// v0.42.0 produced such results by looking composition pairs up with
// truncated 16-bit keys (golang/go#81028), and the check keeps a regression
// from silently changing persisted text. Both checks run only when NFC
// changed the text. Text that x/text NFC leaves unchanged is NFC
// (TestXTextComposesEveryPrimaryComposite checks that no composition pair is
// lost).
//
// The rejected text includes text that is already NFC, such as U+00E1
// followed by 30 U+0301. Go rejects it both when encoding and when decoding
// bytes that another implementation produced. NormalizeNFC does not validate
// UTF-8.
func NormalizeNFC(text string) (string, error) {
	normalized := norm.NFC.String(text)
	if normalized == text {
		return text, nil
	}
	if strings.Count(normalized, norm.GraphemeJoiner) != strings.Count(text, norm.GraphemeJoiner) ||
		norm.NFD.String(normalized) != norm.NFD.String(text) {
		return "", fmt.Errorf("%w: x/text NFC result is not canonically equivalent to the text", ErrInvalidValue)
	}
	return normalized, nil
}

// isNFC reports whether NormalizeNFC accepts text unchanged. It is false for
// text that NormalizeNFC rejects, so checks reject that text, never rewrite it.
func isNFC(text string) bool {
	normalized, err := NormalizeNFC(text)
	return err == nil && normalized == text
}
