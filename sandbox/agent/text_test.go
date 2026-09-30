package main

import (
	"bytes"
	"testing"
)

func TestTrimIncompleteRune(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"ascii", "hello", "hello"},
		{"complete two byte", "café", "café"},
		{"complete four byte", "ok \U0001F600", "ok \U0001F600"},
		{"torn two byte", "caf\xc3", "caf"},
		{"torn three byte", "a\xe4\xbd", "a"},
		{"torn four byte", "x\xf0\x9f\x98", "x"},
		{"torn after complete multibyte", "éé\xe4\xbd", "éé"},
		{"stray continuation bytes stay", "\x80\x80", "\x80\x80"},
		{"invalid but complete stays", "a\xff", "a\xff"},
		{"empty", "", ""},
	}
	for _, c := range cases {
		got := trimIncompleteRune([]byte(c.in))
		if !bytes.Equal(got, []byte(c.want)) {
			t.Errorf("%s: trimIncompleteRune(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}
