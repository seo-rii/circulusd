package canonical

import (
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// NormalizeText returns valid UTF-8 text in canonical form: NFC as defined by
// Unicode 15.0.0, whatever Unicode version the x/text tables carry.
func NormalizeText(text string) string {
	if norm.Version == "15.0.0" {
		return norm.NFC.String(text)
	}
	return normalizeUnicode15Segments(text)
}

// IsNormalizedText reports whether valid UTF-8 text is already in the
// canonical form produced by NormalizeText.
func IsNormalizedText(text string) bool {
	return NormalizeText(text) == text
}

// normalizeUnicode15Segments computes Unicode 15.0.0 NFC with tables of any
// later version. A code point unassigned in Unicode 15.0.0 has combining class
// 0, no decomposition and no composition there, so it is a normalization
// boundary. Normalizing the text between those code points with the newer
// tables gives the 15.0.0 result, because that text holds only characters
// assigned in 15.0.0, whose normalization the Unicode Normalization Stability
// Policy freezes. TypeScript applies the same rule (protocol-types text.ts).
func normalizeUnicode15Segments(text string) string {
	var normalized []byte
	segmentStart := 0
	for index := 0; index < len(text); {
		character, size := rune(text[index]), 1
		if character >= utf8.RuneSelf {
			character, size = utf8.DecodeRuneInString(text[index:])
		}
		if unassignedInUnicode15(character) {
			if normalized == nil {
				normalized = make([]byte, 0, len(text))
			}
			normalized = norm.NFC.AppendString(normalized, text[segmentStart:index])
			normalized = append(normalized, text[index:index+size]...)
			segmentStart = index + size
		}
		index += size
	}
	if normalized == nil {
		return norm.NFC.String(text)
	}
	return string(norm.NFC.AppendString(normalized, text[segmentStart:]))
}

func unassignedInUnicode15(character rune) bool {
	if character < unicode15UnassignedRanges[0][0] {
		return false
	}
	low, high := 0, len(unicode15UnassignedRanges)
	for low < high {
		middle := int(uint(low+high) >> 1)
		if unicode15UnassignedRanges[middle][1] < character {
			low = middle + 1
		} else {
			high = middle
		}
	}
	return low < len(unicode15UnassignedRanges) && unicode15UnassignedRanges[low][0] <= character
}
