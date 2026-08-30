//go:build linux

package stateappclient

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestNewFromCredentialFilesLoadsDistinctCredentialsOnce(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	readKey := bytes.Repeat([]byte{0x31}, 32)
	dispatchKey := bytes.Repeat([]byte{0x91}, 64)
	readPath := writeRootKeyFile(t, directory, "read.key", readKey, 0o400)
	dispatchPath := writeRootKeyFile(t, directory, "dispatch.key", dispatchKey, 0o600)

	client, err := NewFromCredentialFiles(CredentialFileConfig{
		Endpoint:                 "http://127.0.0.1:1",
		KeyID:                    "state-read-current-1",
		RootKeyFile:              readPath,
		DispatchStartKeyID:       "state-dispatch-current-1",
		DispatchStartRootKeyFile: dispatchPath,
		Timeout:                  time.Second,
	})
	if err != nil {
		t.Fatalf("NewFromCredentialFiles() error = %v", err)
	}
	t.Cleanup(client.Close)

	wantReadRequestKey := keyedDigest(readKey, []byte(requestKeyDomain))
	wantReadResponseKey := keyedDigest(readKey, []byte(responseKeyDomain))
	wantDispatchRequestKey := keyedDigest(dispatchKey, []byte(requestKeyDomain))
	wantDispatchResponseKey := keyedDigest(dispatchKey, []byte(responseKeyDomain))
	if client.requestKey != wantReadRequestKey || client.responseKey != wantReadResponseKey ||
		client.dispatchStartRequestKey != wantDispatchRequestKey ||
		client.dispatchStartResponseKey != wantDispatchResponseKey {
		t.Fatal("NewFromCredentialFiles() did not derive the expected operation-scoped keys")
	}

	if err := os.Remove(readPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(dispatchPath); err != nil {
		t.Fatal(err)
	}
	if client.requestKey != wantReadRequestKey || client.dispatchStartRequestKey != wantDispatchRequestKey {
		t.Fatal("client keys changed after the one-shot credential files were removed")
	}
}

func TestLoadRootKeyFileAcceptsInclusiveKeyLengthAndModeBoundaries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		size int
		mode os.FileMode
	}{
		{name: "minimum read-only", size: 32, mode: 0o400},
		{name: "minimum owner-writable", size: 32, mode: 0o600},
		{name: "maximum read-only", size: 256, mode: 0o400},
		{name: "maximum owner-writable", size: 256, mode: 0o600},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			want := bytes.Repeat([]byte{byte(test.size)}, test.size)
			path := writeRootKeyFile(t, t.TempDir(), "root.key", want, test.mode)
			got, err := loadRootKeyFile(path, uint32(os.Geteuid()))
			if err != nil {
				t.Fatalf("loadRootKeyFile() error = %v", err)
			}
			defer clear(got)
			if !bytes.Equal(got, want) {
				t.Fatalf("loadRootKeyFile() length = %d, want %d", len(got), len(want))
			}
		})
	}
}

func TestLoadRootKeyFileRejectsNonCanonicalKeyEncodingWithoutDisclosure(t *testing.T) {
	t.Parallel()

	valid := strings.Repeat("31", 32)
	tests := map[string][]byte{
		"empty":                  {},
		"below minimum":          []byte(strings.Repeat("31", 31)),
		"above maximum":          []byte(strings.Repeat("31", 257)),
		"uppercase":              []byte(strings.Repeat("AB", 32)),
		"trailing newline":       []byte(valid + "\n"),
		"leading whitespace":     []byte(" " + valid),
		"odd length":             []byte(valid + "1"),
		"non hexadecimal":        []byte(strings.Repeat("zz", 32)),
		"raw binary":             bytes.Repeat([]byte{0x31}, 32),
		"secret-like diagnostic": []byte(strings.Repeat("secret-must-not-appear", 4)),
	}
	for name, contents := range tests {
		name, contents := name, contents
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "root.key")
			if err := os.WriteFile(path, contents, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := loadRootKeyFile(path, uint32(os.Geteuid()))
			if !errors.Is(err, ErrInvalidCredentialFile) {
				t.Fatalf("loadRootKeyFile() error = %v, want ErrInvalidCredentialFile", err)
			}
			if len(contents) != 0 && strings.Contains(err.Error(), string(contents)) {
				t.Fatal("loadRootKeyFile() disclosed credential file contents in its error")
			}
		})
	}
}

func TestLoadRootKeyFileRejectsUnsafeFilesystemObjects(t *testing.T) {
	t.Parallel()

	ownerUID := uint32(os.Geteuid())
	t.Run("final symbolic link", func(t *testing.T) {
		t.Parallel()

		directory := t.TempDir()
		target := writeRootKeyFile(t, directory, "target.key", bytes.Repeat([]byte{1}, 32), 0o600)
		link := filepath.Join(directory, "link.key")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := loadRootKeyFile(link, ownerUID); !errors.Is(err, ErrInvalidCredentialFile) {
			t.Fatalf("loadRootKeyFile(symlink) error = %v", err)
		}
	})
	t.Run("parent symbolic link", func(t *testing.T) {
		t.Parallel()

		directory := t.TempDir()
		targetDirectory := filepath.Join(directory, "target")
		if err := os.Mkdir(targetDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		writeRootKeyFile(t, targetDirectory, "root.key", bytes.Repeat([]byte{2}, 32), 0o600)
		linkDirectory := filepath.Join(directory, "linked")
		if err := os.Symlink(targetDirectory, linkDirectory); err != nil {
			t.Fatal(err)
		}
		if _, err := loadRootKeyFile(filepath.Join(linkDirectory, "root.key"), ownerUID); !errors.Is(err, ErrInvalidCredentialFile) {
			t.Fatalf("loadRootKeyFile(parent symlink) error = %v", err)
		}
	})
	t.Run("proc magic link", func(t *testing.T) {
		t.Parallel()

		path := writeRootKeyFile(t, t.TempDir(), "root.key", bytes.Repeat([]byte{7}, 32), 0o600)
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		magicPath := filepath.Join("/proc/self/fd", strconv.Itoa(int(file.Fd())))
		if _, err := loadRootKeyFile(magicPath, ownerUID); !errors.Is(err, ErrInvalidCredentialFile) {
			t.Fatalf("loadRootKeyFile(proc magic link) error = %v", err)
		}
	})
	t.Run("hard link", func(t *testing.T) {
		t.Parallel()

		directory := t.TempDir()
		path := writeRootKeyFile(t, directory, "root.key", bytes.Repeat([]byte{3}, 32), 0o600)
		if err := os.Link(path, filepath.Join(directory, "alias.key")); err != nil {
			t.Fatal(err)
		}
		if _, err := loadRootKeyFile(path, ownerUID); !errors.Is(err, ErrInvalidCredentialFile) {
			t.Fatalf("loadRootKeyFile(hard link) error = %v", err)
		}
	})
	t.Run("directory", func(t *testing.T) {
		t.Parallel()

		if _, err := loadRootKeyFile(t.TempDir(), ownerUID); !errors.Is(err, ErrInvalidCredentialFile) {
			t.Fatalf("loadRootKeyFile(directory) error = %v", err)
		}
	})
	t.Run("named pipe", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "root.key")
		if err := unix.Mkfifo(path, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadRootKeyFile(path, ownerUID); !errors.Is(err, ErrInvalidCredentialFile) {
			t.Fatalf("loadRootKeyFile(named pipe) error = %v", err)
		}
	})
	t.Run("unsafe parent mode", func(t *testing.T) {
		t.Parallel()

		parent := filepath.Join(t.TempDir(), "writable")
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		path := writeRootKeyFile(t, parent, "root.key", bytes.Repeat([]byte{6}, 32), 0o600)
		if err := os.Chmod(parent, 0o777); err != nil {
			t.Fatal(err)
		}
		if _, err := loadRootKeyFile(path, ownerUID); !errors.Is(err, ErrInvalidCredentialFile) {
			t.Fatalf("loadRootKeyFile(unsafe parent) error = %v", err)
		}
	})
}

func TestLoadRootKeyFileRejectsUnexpectedOwnerAndMode(t *testing.T) {
	t.Parallel()

	path := writeRootKeyFile(t, t.TempDir(), "owner.key", bytes.Repeat([]byte{4}, 32), 0o600)
	if _, err := loadRootKeyFile(path, uint32(os.Geteuid())^1); !errors.Is(err, ErrInvalidCredentialFile) {
		t.Fatalf("loadRootKeyFile(unexpected owner) error = %v", err)
	}

	for _, mode := range []os.FileMode{0, 0o200, 0o440, 0o640, 0o700, os.ModeSetuid | 0o600} {
		mode := mode
		t.Run(mode.String(), func(t *testing.T) {
			t.Parallel()

			path := writeRootKeyFile(t, t.TempDir(), "mode.key", bytes.Repeat([]byte{5}, 32), mode)
			if _, err := loadRootKeyFile(path, uint32(os.Geteuid())); !errors.Is(err, ErrInvalidCredentialFile) {
				t.Fatalf("loadRootKeyFile(mode %04o) error = %v", mode, err)
			}
		})
	}
}

func TestLoadRootKeyFileRejectsInvalidPaths(t *testing.T) {
	t.Parallel()

	for name, path := range map[string]string{
		"empty":        "",
		"relative":     "root.key",
		"noncanonical": t.TempDir() + string(filepath.Separator) + "sub" + string(filepath.Separator) + ".." + string(filepath.Separator) + "root.key",
		"root":         string(filepath.Separator),
		"nul":          filepath.Join(t.TempDir(), "root\x00.key"),
		"newline":      filepath.Join(t.TempDir(), "root\n.key"),
		"oversized":    string(filepath.Separator) + strings.Repeat("a", 4096),
	} {
		name, path := name, path
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := loadRootKeyFile(path, uint32(os.Geteuid())); !errors.Is(err, ErrInvalidCredentialFile) {
				t.Fatalf("loadRootKeyFile(%q) error = %v", path, err)
			}
		})
	}
}

func TestNewFromCredentialFilesRejectsSharedAuthority(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	key := bytes.Repeat([]byte{0x61}, 32)
	readPath := writeRootKeyFile(t, directory, "read.key", key, 0o600)
	dispatchPath := writeRootKeyFile(t, directory, "dispatch.key", key, 0o600)
	base := CredentialFileConfig{
		Endpoint:                 "http://127.0.0.1:1",
		KeyID:                    "state-read-current-1",
		RootKeyFile:              readPath,
		DispatchStartKeyID:       "state-dispatch-current-1",
		DispatchStartRootKeyFile: dispatchPath,
		Timeout:                  time.Second,
	}
	if _, err := NewFromCredentialFiles(base); !errors.Is(err, ErrInvalidCredentialFile) {
		t.Fatalf("NewFromCredentialFiles(equal keys) error = %v", err)
	}
	base.DispatchStartRootKeyFile = base.RootKeyFile
	if _, err := NewFromCredentialFiles(base); !errors.Is(err, ErrInvalidCredentialFile) {
		t.Fatalf("NewFromCredentialFiles(shared path) error = %v", err)
	}
}

func TestNewFromCredentialFilesClearsDecodedBuffersWhenConstructionFails(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	readKey := bytes.Repeat([]byte{0x71}, 32)
	dispatchKey := bytes.Repeat([]byte{0x72}, 32)
	config := CredentialFileConfig{
		Endpoint:                 "http://127.0.0.1:1",
		KeyID:                    "state-read-current-1",
		RootKeyFile:              writeRootKeyFile(t, directory, "read.key", readKey, 0o600),
		DispatchStartKeyID:       "state-dispatch-current-1",
		DispatchStartRootKeyFile: writeRootKeyFile(t, directory, "dispatch.key", dispatchKey, 0o600),
		Timeout:                  time.Second,
	}
	constructorError := errors.New("injected constructor failure")
	var observedReadBuffer []byte
	var observedDispatchBuffer []byte
	client, err := newFromCredentialFiles(config, func(candidate Config) (*Client, error) {
		observedReadBuffer = candidate.RootKey
		observedDispatchBuffer = candidate.DispatchStartRootKey
		if !bytes.Equal(observedReadBuffer, readKey) || !bytes.Equal(observedDispatchBuffer, dispatchKey) {
			t.Fatal("constructor did not receive the decoded credential snapshots")
		}
		return nil, constructorError
	})
	if client != nil || !errors.Is(err, constructorError) {
		t.Fatalf("newFromCredentialFiles() client/error = %v/%v", client, err)
	}
	for _, value := range observedReadBuffer {
		if value != 0 {
			t.Fatal("read credential loader buffer was not cleared after constructor failure")
		}
	}
	for _, value := range observedDispatchBuffer {
		if value != 0 {
			t.Fatal("dispatch-start credential loader buffer was not cleared after constructor failure")
		}
	}
}

func TestPinnedRootKeyFileSurvivesPathReplacementButRejectsInodeMutation(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	originalKey := bytes.Repeat([]byte{0x81}, 32)
	originalPath := writeRootKeyFile(t, directory, "root.key", originalKey, 0o600)
	pinned, err := openRootKeyFile(originalPath, uint32(os.Geteuid()))
	if err != nil {
		t.Fatalf("openRootKeyFile() error = %v", err)
	}
	defer pinned.file.Close()

	replacementPath := writeRootKeyFile(t, directory, "replacement.key", bytes.Repeat([]byte{0x82}, 32), 0o600)
	if err := os.Rename(originalPath, filepath.Join(directory, "original.key")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacementPath, originalPath); err != nil {
		t.Fatal(err)
	}
	got, err := readPinnedRootKey(pinned)
	if err != nil {
		t.Fatalf("readPinnedRootKey(path replacement) error = %v", err)
	}
	defer clear(got)
	if !bytes.Equal(got, originalKey) {
		t.Fatal("readPinnedRootKey() followed a replacement path instead of its pinned descriptor")
	}

	mutablePath := writeRootKeyFile(t, directory, "mutable.key", bytes.Repeat([]byte{0x83}, 32), 0o600)
	mutable, err := openRootKeyFile(mutablePath, uint32(os.Geteuid()))
	if err != nil {
		t.Fatalf("openRootKeyFile(mutable) error = %v", err)
	}
	defer mutable.file.Close()
	writeRootKeyFile(t, directory, "mutable.key", bytes.Repeat([]byte{0x84}, 32), 0o600)
	changedAt := time.Now().Add(time.Hour)
	if err := os.Chtimes(mutablePath, changedAt, changedAt); err != nil {
		t.Fatal(err)
	}
	if changed, err := readPinnedRootKey(mutable); !errors.Is(err, ErrInvalidCredentialFile) {
		clear(changed)
		t.Fatalf("readPinnedRootKey(mutated inode) error = %v, want ErrInvalidCredentialFile", err)
	}
}

func TestLoadRootKeyFileIsSafeForConcurrentReaders(t *testing.T) {
	t.Parallel()

	want := bytes.Repeat([]byte{0xa7}, 256)
	path := writeRootKeyFile(t, t.TempDir(), "root.key", want, 0o400)
	const readers = 64
	start := make(chan struct{})
	errorsSeen := make(chan error, readers)
	var ready sync.WaitGroup
	ready.Add(readers)
	for range readers {
		go func() {
			ready.Done()
			<-start
			got, err := loadRootKeyFile(path, uint32(os.Geteuid()))
			if err == nil && !bytes.Equal(got, want) {
				err = errors.New("concurrent reader returned the wrong key")
			}
			clear(got)
			errorsSeen <- err
		}()
	}
	ready.Wait()
	close(start)
	for range readers {
		if err := <-errorsSeen; err != nil {
			t.Fatalf("concurrent loadRootKeyFile() error = %v", err)
		}
	}
}

func TestNewFromCredentialFilesIsSafeForConcurrentConstruction(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	readKey := bytes.Repeat([]byte{0xb1}, 32)
	dispatchKey := bytes.Repeat([]byte{0xb2}, 32)
	config := CredentialFileConfig{
		Endpoint:                 "http://127.0.0.1:1",
		KeyID:                    "state-read-current-1",
		RootKeyFile:              writeRootKeyFile(t, directory, "read.key", readKey, 0o400),
		DispatchStartKeyID:       "state-dispatch-current-1",
		DispatchStartRootKeyFile: writeRootKeyFile(t, directory, "dispatch.key", dispatchKey, 0o400),
		Timeout:                  time.Second,
	}
	wantReadRequestKey := keyedDigest(readKey, []byte(requestKeyDomain))
	wantDispatchRequestKey := keyedDigest(dispatchKey, []byte(requestKeyDomain))
	const constructors = 64
	start := make(chan struct{})
	errorsSeen := make(chan error, constructors)
	var ready sync.WaitGroup
	ready.Add(constructors)
	for range constructors {
		go func() {
			ready.Done()
			<-start
			client, err := NewFromCredentialFiles(config)
			if err == nil {
				if client.requestKey != wantReadRequestKey || client.dispatchStartRequestKey != wantDispatchRequestKey {
					err = errors.New("concurrent constructor derived the wrong keys")
				}
				client.Close()
			}
			errorsSeen <- err
		}()
	}
	ready.Wait()
	close(start)
	for range constructors {
		if err := <-errorsSeen; err != nil {
			t.Fatalf("concurrent NewFromCredentialFiles() error = %v", err)
		}
	}
}

func writeRootKeyFile(t *testing.T, directory, name string, key []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(directory, name)
	encoded := make([]byte, hex.EncodedLen(len(key)))
	hex.Encode(encoded, key)
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	clear(encoded)
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}
