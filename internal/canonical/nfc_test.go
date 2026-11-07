package canonical

import (
	"errors"
	"math/rand/v2"
	"strings"
	"testing"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// xtextNonEquivalentNFC lists text that golang.org/x/text NFC rewrites into
// text that is not canonically equivalent to it: x/text inserts U+034F after
// 30 consecutive non-starters (the stream-safe text format). Each input is
// already NFC by the Unicode algorithm, so TypeScript keeps it unchanged.
var xtextNonEquivalentNFC = map[string]string{
	"31 combining marks":                      "\u00e1" + strings.Repeat("\u0301", 30),
	"31 combining marks after a plane 1 base": "\U00010041" + strings.Repeat("\u0301", 31),
}

func TestEncodeRejectsTextThatXTextNormalizesIncorrectly(t *testing.T) {
	t.Parallel()

	inputs := map[string]string{"decomposed 31 combining marks": "a" + strings.Repeat("\u0301", 31)}
	for name, text := range xtextNonEquivalentNFC {
		inputs[name] = text
	}
	for name, text := range inputs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if encoded, err := Encode(text, DefaultOptions()); !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("Encode(text) = %x, %v, want ErrInvalidValue", encoded, err)
			}
			if encoded, err := Encode(Map{text: int64(1)}, DefaultOptions()); !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("Encode(map key) = %x, %v, want ErrInvalidValue", encoded, err)
			}
			if digest, err := StructuredDigest("circulusd.test", 1, Array{text}); !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("StructuredDigest() = %q, %v, want ErrInvalidValue", digest, err)
			}
			if set, err := NormalizeStringSet([]string{text}); !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("NormalizeStringSet() = %+q, %v, want ErrInvalidValue", set, err)
			}
		})
	}
}

func TestDecodeRejectsNFCTextThatXTextCannotVerify(t *testing.T) {
	t.Parallel()

	for name, text := range xtextNonEquivalentNFC {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			// The bytes TypeScript produces for the text.
			encoded := []byte{0x60 | byte(len(text))}
			if len(text) >= 24 {
				encoded = []byte{0x78, byte(len(text))}
			}
			encoded = append(encoded, text...)
			if value, err := Decode(encoded, DefaultOptions()); !errors.Is(err, ErrInvalidEncoding) ||
				!strings.Contains(err.Error(), "NFC") {
				t.Fatalf("Decode(text) = %+q, %v, want an NFC ErrInvalidEncoding", value, err)
			}
			if _, err := StructuredDigest(text, 1, nil); !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("StructuredDigest(domain) error = %v, want ErrInvalidValue", err)
			}
		})
	}
}

func TestNormalizeNFCRejectsNonEquivalentResults(t *testing.T) {
	t.Parallel()

	for name, text := range xtextNonEquivalentNFC {
		if normalized, err := NormalizeNFC(text); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("NormalizeNFC(%s) = %+q, %v, want ErrInvalidValue", name, normalized, err)
		}
	}
}

func TestNormalizeNFCKeepsOrdinaryNormalization(t *testing.T) {
	t.Parallel()

	for _, test := range []struct{ input, want string }{
		{input: "", want: ""},
		{input: "circulusd.hash", want: "circulusd.hash"},
		{input: "e\u0301", want: "\u00e9"},
		{input: "\u00e9", want: "\u00e9"},
		{input: "\u212b", want: "\u00c5"},
		{input: "a\u0301\u0316", want: "\u00e1\u0316"},
		{input: "u\u0308\u0304", want: "\u01d6"},
		{input: "\u1100\u1161\u11a8", want: "\uac01"},
		{input: "\uac00\u11a8", want: "\uac01"},
		{input: "\ud55c\uad6d\uc5b4", want: "\ud55c\uad6d\uc5b4"},
		{input: "\U00011099\U000110ba", want: "\U0001109a"},
		{input: "\U0001d15e", want: "\U0001d157\U0001d165"},
		{input: "\U00010041", want: "\U00010041"},
		{input: "a" + strings.Repeat("\u0301", 30), want: "\u00e1" + strings.Repeat("\u0301", 29)},
		{input: "a" + strings.Repeat("\u0301", 30) + "\u034f\u0301", want: "\u00e1" + strings.Repeat("\u0301", 29) + "\u034f\u0301"},
		// x/text before v0.42.0 composed these into unrelated characters
		// (golang/go#81028). They are NFC and must stay unchanged.
		{input: "\U00010041\u0301", want: "\U00010041\u0301"},
		{input: "\U00020041\u0301", want: "\U00020041\u0301"},
		{input: "\u1099\U000110ba", want: "\u1099\U000110ba"},
		{input: "\U00011f41\u0301", want: "\U00011f41\u0301"},
		{input: "\u05d2\u0307", want: "\u05d2\u0307"},
	} {
		got, err := NormalizeNFC(test.input)
		if err != nil || got != test.want {
			t.Errorf("NormalizeNFC(%+q) = %+q, %v, want %+q", test.input, got, err, test.want)
		}
		if !isNFC(test.want) {
			t.Errorf("isNFC(%+q) = false, want true", test.want)
		}
	}
}

// TestNormalizeNFCAcceptsExactlyCanonicallyEquivalentResults compares
// NormalizeNFC against a reference NFD that decomposes rune by rune and sorts
// combining classes without inserting U+034F.
func TestNormalizeNFCAcceptsExactlyCanonicallyEquivalentResults(t *testing.T) {
	t.Parallel()

	referenceNFD := func(text string) string {
		var decomposed []rune
		for _, character := range text {
			decomposed = append(decomposed, []rune(norm.NFD.String(string(character)))...)
		}
		combiningClass := func(character rune) uint8 { return norm.NFD.PropertiesString(string(character)).CCC() }
		for index := 1; index < len(decomposed); index++ {
			for next := index; next > 0; next-- {
				class := combiningClass(decomposed[next])
				if class == 0 || combiningClass(decomposed[next-1]) <= class {
					break
				}
				decomposed[next], decomposed[next-1] = decomposed[next-1], decomposed[next]
			}
		}
		return string(decomposed)
	}
	pool := []rune{
		'a', 'e', 'o', 'u', 'A', 'O', 0xe9, 0x1f41, 0x3bf, 0x1099, 0x11099, 0x1109a, 0x11131, 0x11347,
		0x10041, 0x20041, 0x10065, 0x1006f, 0x203bf, 0x11f41, 0x1d15e, 0x1100, 0x1161, 0x11a8, 0xac00, 0x034f,
	}
	marks := []rune{0x0301, 0x0308, 0x0314, 0x0316, 0x0327, 0x0334, 0x0345, 0x05b0, 0x110ba, 0x11127, 0x1133e, 0x1d165}
	random := rand.New(rand.NewPCG(24, 41))
	accepted, changed, rejected := 0, 0, 0
	for iteration := 0; iteration < 20_000; iteration++ {
		var builder strings.Builder
		for tokens := 1 + random.IntN(8); tokens > 0; tokens-- {
			switch choice := random.IntN(20); {
			case choice < 9:
				builder.WriteRune(pool[random.IntN(len(pool))])
			case choice < 17:
				builder.WriteRune(marks[random.IntN(len(marks))])
			case choice < 19:
				character := rune(random.IntN(0x110000 - 0x800))
				if character >= 0xd800 {
					character += 0x800
				}
				builder.WriteRune(character)
			default:
				mark := string(marks[random.IntN(len(marks))])
				builder.WriteString(strings.Repeat(mark, 25+random.IntN(10)))
			}
		}
		input := builder.String()
		normalized, err := NormalizeNFC(input)
		equivalent := referenceNFD(norm.NFC.String(input)) == referenceNFD(input)
		if err != nil {
			rejected++
			if equivalent {
				t.Fatalf("NormalizeNFC(%+q) rejected an equivalent x/text result", input)
			}
			continue
		}
		accepted++
		if normalized != input {
			changed++
		}
		if !equivalent || referenceNFD(normalized) != referenceNFD(input) {
			t.Fatalf("NormalizeNFC(%+q) = %+q, which is not canonically equivalent", input, normalized)
		}
		if again, err := NormalizeNFC(normalized); err != nil || again != normalized {
			t.Fatalf("NormalizeNFC(%+q) = %+q, %v, want it unchanged", normalized, again, err)
		}
	}
	t.Logf("accepted %d (changed %d), rejected %d", accepted, changed, rejected)
	if rejected == 0 || changed == 0 || accepted == changed {
		t.Fatal("random strings did not cover accepted, changed and rejected text")
	}
}

// TestXTextComposesEveryPrimaryComposite backs the NormalizeNFC fast path:
// x/text must not lose a composition pair, or text that x/text leaves
// unchanged could still be non-NFC.
func TestXTextComposesEveryPrimaryComposite(t *testing.T) {
	t.Parallel()

	for character := rune(0); character <= unicode.MaxRune; character++ {
		if 0xd800 <= character && character <= 0xdfff {
			continue
		}
		text := string(character)
		decomposed := norm.NFD.String(text)
		if decomposed == text || norm.NFC.String(text) != text {
			continue
		}
		if composed := norm.NFC.String(decomposed); composed != text {
			t.Errorf("NFC(NFD(%U)) = %+q, want %+q", character, composed, text)
		}
	}
}
