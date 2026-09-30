package main

import "unicode/utf8"

// trimIncompleteRune drops a trailing partial UTF-8 sequence, so that text cut
// at an arbitrary byte does not end in a torn character. Complete sequences,
// valid or not, are left alone: only an encoding that stops short is removed.
func trimIncompleteRune(data []byte) []byte {
	start := len(data)
	for start > 0 && len(data)-start < utf8.UTFMax && !utf8.RuneStart(data[start-1]) {
		start--
	}
	if start == 0 {
		return data
	}
	start-- // the lead byte of the last sequence
	if utf8.RuneStart(data[start]) && !utf8.FullRune(data[start:]) {
		return data[:start]
	}
	return data
}
