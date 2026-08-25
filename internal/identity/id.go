package identity

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"io"
	"strings"
)

const entropyBytes = 16

var idEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

type Kind string

const (
	Tenant              Kind = "tenant"
	Subject             Kind = "subject"
	Session             Kind = "sess"
	Turn                Kind = "turn"
	Effect              Kind = "effect"
	Invocation          Kind = "inv"
	Workspace           Kind = "ws"
	Sandbox             Kind = "sandbox"
	Process             Kind = "proc"
	Lease               Kind = "lease"
	Commit              Kind = "commit"
	Operation           Kind = "op"
	Request             Kind = "req"
	Artifact            Kind = "artifact"
	RuntimeRevision     Kind = "runtime"
	EnvironmentRevision Kind = "env"
	PolicyRevision      Kind = "policy"
)

var declaredKinds = []Kind{
	Tenant,
	Subject,
	Session,
	Turn,
	Effect,
	Invocation,
	Workspace,
	Sandbox,
	Process,
	Lease,
	Commit,
	Operation,
	Request,
	Artifact,
	RuntimeRevision,
	EnvironmentRevision,
	PolicyRevision,
}

type ID struct {
	kind  Kind
	value string
}

type Generator struct {
	Random io.Reader
}

func New(kind Kind) (ID, error) {
	return (Generator{Random: rand.Reader}).New(kind)
}

func (generator Generator) New(kind Kind) (ID, error) {
	if !isDeclaredKind(kind) {
		return ID{}, fmt.Errorf("identity kind %q is not declared", kind)
	}

	random := generator.Random
	if random == nil {
		random = rand.Reader
	}
	entropy := make([]byte, entropyBytes)
	if _, err := io.ReadFull(random, entropy); err != nil {
		return ID{}, fmt.Errorf("generate %s identity: %w", kind, err)
	}
	value := string(kind) + "_" + idEncoding.EncodeToString(entropy)
	return ID{kind: kind, value: value}, nil
}

func Parse(expected Kind, value string) (ID, error) {
	if !isDeclaredKind(expected) {
		return ID{}, fmt.Errorf("identity kind %q is not declared", expected)
	}

	id, err := parseID(value)
	if err != nil {
		return ID{}, err
	}
	if id.kind != expected {
		return ID{}, fmt.Errorf("identity %q has kind %q, want %q", value, id.kind, expected)
	}
	return id, nil
}

func AllKinds() []Kind {
	return append([]Kind(nil), declaredKinds...)
}

func (id ID) Kind() Kind {
	return id.kind
}

func (id ID) String() string {
	return id.value
}

func (id ID) MarshalText() ([]byte, error) {
	if id.value == "" {
		return nil, fmt.Errorf("cannot marshal an empty identity")
	}
	return []byte(id.value), nil
}

func (id *ID) UnmarshalText(text []byte) error {
	parsed, err := parseID(string(text))
	if err != nil {
		return err
	}
	*id = parsed
	return nil
}

func parseID(value string) (ID, error) {
	prefix, encoded, found := strings.Cut(value, "_")
	if !found || prefix == "" || len(encoded) != 26 {
		return ID{}, fmt.Errorf("identity %q has an invalid shape", value)
	}

	kind := Kind(prefix)
	if !isDeclaredKind(kind) {
		return ID{}, fmt.Errorf("identity %q has undeclared kind %q", value, kind)
	}

	decoded, err := idEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != entropyBytes || idEncoding.EncodeToString(decoded) != encoded {
		return ID{}, fmt.Errorf("identity %q has invalid entropy encoding", value)
	}
	return ID{kind: kind, value: value}, nil
}

func isDeclaredKind(kind Kind) bool {
	for _, declared := range declaredKinds {
		if kind == declared {
			return true
		}
	}
	return false
}
