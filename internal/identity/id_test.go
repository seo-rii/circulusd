package identity

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
)

func TestGeneratorUsesOnlyKindAndRandomBytes(t *testing.T) {
	t.Parallel()

	generator := Generator{Random: bytes.NewReader(make([]byte, entropyBytes))}
	id, err := generator.New(Session)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got, want := id.String(), "sess_"+strings.Repeat("A", 26); got != want {
		t.Fatalf("New() = %q, want %q", got, want)
	}
	if id.Kind() != Session {
		t.Fatalf("Kind() = %q, want %q", id.Kind(), Session)
	}
}

func TestParseRejectsMalformedOrMismatchedIDs(t *testing.T) {
	t.Parallel()

	valid := "turn_" + strings.Repeat("A", 26)
	tests := []struct {
		name  string
		kind  Kind
		value string
	}{
		{name: "unknown expected kind", kind: Kind("admin"), value: valid},
		{name: "wrong kind", kind: Session, value: valid},
		{name: "lowercase entropy", kind: Turn, value: "turn_" + strings.Repeat("a", 26)},
		{name: "padding", kind: Turn, value: valid + "="},
		{name: "too short", kind: Turn, value: "turn_A"},
		{name: "ambiguous alphabet", kind: Turn, value: "turn_" + strings.Repeat("0", 26)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := Parse(test.kind, test.value); err == nil {
				t.Fatalf("Parse(%q, %q) error = nil", test.kind, test.value)
			}
		})
	}

	id, err := Parse(Turn, valid)
	if err != nil {
		t.Fatalf("Parse(valid) error = %v", err)
	}
	if id.String() != valid {
		t.Fatalf("Parse(valid).String() = %q, want %q", id.String(), valid)
	}
}

func TestGeneratorFailsClosedOnEntropyFailure(t *testing.T) {
	t.Parallel()

	generator := Generator{Random: errorReader{}}
	if _, err := generator.New(Invocation); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("New() error = %v, want io.ErrUnexpectedEOF", err)
	}
	if _, err := generator.New(Kind("tenant-input")); err == nil {
		t.Fatal("New(unknown kind) error = nil")
	}
}

func TestDefaultGeneratorProducesUniqueConcurrentIDs(t *testing.T) {
	t.Parallel()

	const count = 256
	ids := make(chan ID, count)
	errors := make(chan error, count)
	var wait sync.WaitGroup
	for range count {
		wait.Add(1)
		go func() {
			defer wait.Done()
			id, err := New(Effect)
			ids <- id
			errors <- err
		}()
	}
	wait.Wait()
	close(ids)
	close(errors)

	for err := range errors {
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
	}
	seen := make(map[ID]struct{}, count)
	for id := range ids {
		if _, duplicate := seen[id]; duplicate {
			t.Fatalf("duplicate ID %q", id)
		}
		seen[id] = struct{}{}
		if _, err := Parse(Effect, id.String()); err != nil {
			t.Fatalf("Parse(%q) error = %v", id, err)
		}
	}
}

func TestEveryDeclaredKindRoundTrips(t *testing.T) {
	t.Parallel()

	for _, kind := range AllKinds() {
		kind := kind
		t.Run(string(kind), func(t *testing.T) {
			t.Parallel()
			generator := Generator{Random: bytes.NewReader(bytes.Repeat([]byte{0x5a}, entropyBytes))}
			id, err := generator.New(kind)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if _, err := Parse(kind, id.String()); err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
		})
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}
