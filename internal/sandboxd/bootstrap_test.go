//go:build linux

package sandboxd

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestLoadCommandManifestReturnsCanonicalAllowlist(t *testing.T) {
	t.Parallel()

	path := writeCommandManifest(t, `{
  "schemaVersion": 1,
  "commands": [
    {"name": "echo", "path": "/usr/bin/echo"},
    {"name": "python3", "path": "/usr/bin/python3"}
  ]
}`)
	commands, err := LoadCommandManifest(path, uint32(os.Geteuid()))
	if err != nil {
		t.Fatalf("LoadCommandManifest() error = %v", err)
	}
	if len(commands) != 2 || commands["echo"] != "/usr/bin/echo" || commands["python3"] != "/usr/bin/python3" {
		t.Fatalf("LoadCommandManifest() = %#v", commands)
	}

	commands["echo"] = "/tmp/changed"
	again, err := LoadCommandManifest(path, uint32(os.Geteuid()))
	if err != nil {
		t.Fatalf("second LoadCommandManifest() error = %v", err)
	}
	if again["echo"] != "/usr/bin/echo" {
		t.Fatalf("second LoadCommandManifest() shared mutable state: %#v", again)
	}
}

func TestLoadCommandManifestRejectsAmbiguousOrUnsafeDocuments(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		document string
	}{
		{name: "duplicate root field", document: `{"schemaVersion":1,"schemaVersion":1,"commands":[]}`},
		{name: "unknown root field", document: `{"schemaVersion":1,"commands":[],"extra":true}`},
		{name: "unsupported schema", document: `{"schemaVersion":2,"commands":[]}`},
		{name: "empty commands", document: `{"schemaVersion":1,"commands":[]}`},
		{name: "duplicate command", document: `{"schemaVersion":1,"commands":[{"name":"echo","path":"/bin/echo"},{"name":"echo","path":"/usr/bin/echo"}]}`},
		{name: "unsorted commands", document: `{"schemaVersion":1,"commands":[{"name":"python3","path":"/usr/bin/python3"},{"name":"echo","path":"/bin/echo"}]}`},
		{name: "relative executable", document: `{"schemaVersion":1,"commands":[{"name":"echo","path":"bin/echo"}]}`},
		{name: "noncanonical executable", document: `{"schemaVersion":1,"commands":[{"name":"echo","path":"/usr/../bin/echo"}]}`},
		{name: "mutable executable", document: `{"schemaVersion":1,"commands":[{"name":"tool","path":"/workspace/tool"}]}`},
		{name: "raw command path", document: `{"schemaVersion":1,"commands":[{"name":"/bin/sh","path":"/bin/sh"}]}`},
		{name: "unknown command field", document: `{"schemaVersion":1,"commands":[{"name":"echo","path":"/bin/echo","args":[]}]}`},
		{name: "trailing document", document: `{"schemaVersion":1,"commands":[{"name":"echo","path":"/bin/echo"}]} {}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := LoadCommandManifest(writeCommandManifest(t, test.document), uint32(os.Geteuid()))
			if !errors.Is(err, ErrInvalidCommandManifest) {
				t.Fatalf("LoadCommandManifest() error = %v, want ErrInvalidCommandManifest", err)
			}
		})
	}
}

func TestLoadCommandManifestRejectsUnsafeFilesystemObjects(t *testing.T) {
	t.Parallel()

	document := `{"schemaVersion":1,"commands":[{"name":"echo","path":"/bin/echo"}]}`
	t.Run("symbolic link", func(t *testing.T) {
		t.Parallel()

		target := writeCommandManifest(t, document)
		link := filepath.Join(t.TempDir(), "commands.json")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadCommandManifest(link, uint32(os.Geteuid())); !errors.Is(err, ErrInvalidCommandManifest) {
			t.Fatalf("LoadCommandManifest(symlink) error = %v", err)
		}
	})
	t.Run("group writable", func(t *testing.T) {
		t.Parallel()

		path := writeCommandManifest(t, document)
		if err := os.Chmod(path, 0o660); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadCommandManifest(path, uint32(os.Geteuid())); !errors.Is(err, ErrInvalidCommandManifest) {
			t.Fatalf("LoadCommandManifest(writable) error = %v", err)
		}
	})
	t.Run("directory", func(t *testing.T) {
		t.Parallel()

		if _, err := LoadCommandManifest(t.TempDir(), uint32(os.Geteuid())); !errors.Is(err, ErrInvalidCommandManifest) {
			t.Fatalf("LoadCommandManifest(directory) error = %v", err)
		}
	})
}

func TestLoadCommandManifestIsSafeForConcurrentReaders(t *testing.T) {
	t.Parallel()

	path := writeCommandManifest(t, `{"schemaVersion":1,"commands":[{"name":"echo","path":"/bin/echo"}]}`)
	const readers = 32
	start := make(chan struct{})
	errorsSeen := make(chan error, readers)
	var ready sync.WaitGroup
	ready.Add(readers)
	for range readers {
		go func() {
			ready.Done()
			<-start
			commands, err := LoadCommandManifest(path, uint32(os.Geteuid()))
			if err == nil && commands["echo"] != "/bin/echo" {
				err = errors.New("unexpected concurrent allowlist")
			}
			errorsSeen <- err
		}()
	}
	ready.Wait()
	close(start)
	for range readers {
		if err := <-errorsSeen; err != nil {
			t.Fatalf("concurrent LoadCommandManifest() error = %v", err)
		}
	}
}

func TestLoadCommandManifestRejectsUnexpectedOwner(t *testing.T) {
	t.Parallel()

	path := writeCommandManifest(t, `{"schemaVersion":1,"commands":[{"name":"echo","path":"/bin/echo"}]}`)
	unexpectedOwner := uint32(os.Geteuid()) ^ 1
	if _, err := LoadCommandManifest(path, unexpectedOwner); !errors.Is(err, ErrInvalidCommandManifest) {
		t.Fatalf("LoadCommandManifest(unexpected owner %d) error = %v", unexpectedOwner, err)
	}
}

func writeCommandManifest(t *testing.T, document string) string {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "commands.json")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
