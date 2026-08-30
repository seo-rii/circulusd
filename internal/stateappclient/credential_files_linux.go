//go:build linux

package stateappclient

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const (
	minimumEncodedRootKeyBytes = 64
	maximumEncodedRootKeyBytes = 512
	maximumCredentialPathBytes = 4096
)

type pinnedRootKeyFile struct {
	file   *os.File
	status unix.Stat_t
}

func loadRootKeyPair(readPath, dispatchStartPath string) ([]byte, []byte, error) {
	expectedOwnerUID := uint32(os.Geteuid())
	readFile, err := openRootKeyFile(readPath, expectedOwnerUID)
	if err != nil {
		return nil, nil, err
	}
	defer readFile.file.Close()
	dispatchStartFile, err := openRootKeyFile(dispatchStartPath, expectedOwnerUID)
	if err != nil {
		return nil, nil, err
	}
	defer dispatchStartFile.file.Close()
	if readFile.status.Dev == dispatchStartFile.status.Dev &&
		readFile.status.Ino == dispatchStartFile.status.Ino {
		return nil, nil, fmt.Errorf("%w: read and dispatch-start paths resolve to the same file", ErrInvalidCredentialFile)
	}

	readRootKey, err := readPinnedRootKey(readFile)
	if err != nil {
		return nil, nil, err
	}
	dispatchStartRootKey, err := readPinnedRootKey(dispatchStartFile)
	if err != nil {
		clear(readRootKey)
		return nil, nil, err
	}
	return readRootKey, dispatchStartRootKey, nil
}

func loadRootKeyFile(path string, expectedOwnerUID uint32) ([]byte, error) {
	pinned, err := openRootKeyFile(path, expectedOwnerUID)
	if err != nil {
		return nil, err
	}
	defer pinned.file.Close()
	return readPinnedRootKey(pinned)
}

func openRootKeyFile(path string, expectedOwnerUID uint32) (*pinnedRootKeyFile, error) {
	if !validCredentialPath(path) {
		return nil, fmt.Errorf("%w: path must be canonical and absolute", ErrInvalidCredentialFile)
	}
	rootDescriptor, err := unix.Open(
		string(filepath.Separator),
		unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: open filesystem root: %v", ErrInvalidCredentialFile, err)
	}
	currentDescriptor := rootDescriptor
	components := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	for index, component := range components {
		final := index == len(components)-1
		flags := uint64(unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW)
		if final {
			flags = uint64(unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK)
		}
		nextDescriptor, openErr := unix.Openat2(currentDescriptor, component, &unix.OpenHow{
			Flags: flags,
			Resolve: uint64(
				unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
			),
		})
		_ = unix.Close(currentDescriptor)
		if openErr != nil {
			return nil, fmt.Errorf("%w: open credential path: %v", ErrInvalidCredentialFile, openErr)
		}
		currentDescriptor = nextDescriptor

		var status unix.Stat_t
		if statErr := unix.Fstat(currentDescriptor, &status); statErr != nil {
			_ = unix.Close(currentDescriptor)
			return nil, fmt.Errorf("%w: inspect credential path: %v", ErrInvalidCredentialFile, statErr)
		}
		if !final {
			if !trustedCredentialDirectory(status, expectedOwnerUID) {
				_ = unix.Close(currentDescriptor)
				return nil, fmt.Errorf("%w: credential parent owner or mode is unsafe", ErrInvalidCredentialFile)
			}
			continue
		}
		if !trustedRootKeyFile(status, expectedOwnerUID) {
			_ = unix.Close(currentDescriptor)
			return nil, fmt.Errorf("%w: credential file type, owner, mode, link count, or size is unsafe", ErrInvalidCredentialFile)
		}
		file := os.NewFile(uintptr(currentDescriptor), "state-app-root-key")
		if file == nil {
			_ = unix.Close(currentDescriptor)
			return nil, fmt.Errorf("%w: credential file descriptor is unavailable", ErrInvalidCredentialFile)
		}
		return &pinnedRootKeyFile{file: file, status: status}, nil
	}
	_ = unix.Close(currentDescriptor)
	return nil, fmt.Errorf("%w: credential path has no file component", ErrInvalidCredentialFile)
}

func readPinnedRootKey(pinned *pinnedRootKeyFile) ([]byte, error) {
	if pinned == nil || pinned.file == nil {
		return nil, fmt.Errorf("%w: credential file is unavailable", ErrInvalidCredentialFile)
	}
	encoded := make([]byte, int(pinned.status.Size))
	defer clear(encoded)
	if _, err := io.ReadFull(pinned.file, encoded); err != nil {
		return nil, fmt.Errorf("%w: read credential file: %v", ErrInvalidCredentialFile, err)
	}
	var trailing [1]byte
	if count, err := pinned.file.Read(trailing[:]); count != 0 || err != io.EOF {
		clear(trailing[:])
		return nil, fmt.Errorf("%w: credential file changed while it was read", ErrInvalidCredentialFile)
	}
	clear(trailing[:])

	var after unix.Stat_t
	if err := unix.Fstat(int(pinned.file.Fd()), &after); err != nil || !sameCredentialFileStatus(pinned.status, after) {
		return nil, fmt.Errorf("%w: credential file changed while it was read", ErrInvalidCredentialFile)
	}
	for _, character := range encoded {
		if character != byte(unicode.ToLower(rune(character))) ||
			(character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return nil, fmt.Errorf("%w: credential must be canonical lowercase hexadecimal", ErrInvalidCredentialFile)
		}
	}
	decoded := make([]byte, hex.DecodedLen(len(encoded)))
	if _, err := hex.Decode(decoded, encoded); err != nil {
		clear(decoded)
		return nil, fmt.Errorf("%w: credential must be canonical lowercase hexadecimal", ErrInvalidCredentialFile)
	}
	return decoded, nil
}

func validCredentialPath(path string) bool {
	if path == "" || len(path) > maximumCredentialPathBytes || !utf8.ValidString(path) ||
		!filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return false
	}
	for _, character := range path {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func trustedCredentialDirectory(status unix.Stat_t, expectedOwnerUID uint32) bool {
	if status.Mode&unix.S_IFMT != unix.S_IFDIR || status.Uid != 0 && status.Uid != expectedOwnerUID {
		return false
	}
	if status.Mode&0o022 == 0 {
		return true
	}
	return status.Uid == 0 && status.Mode&unix.S_ISVTX != 0
}

func trustedRootKeyFile(status unix.Stat_t, expectedOwnerUID uint32) bool {
	permissions := status.Mode & 0o7777
	return status.Mode&unix.S_IFMT == unix.S_IFREG && status.Nlink == 1 &&
		status.Uid == expectedOwnerUID && (permissions == 0o400 || permissions == 0o600) &&
		status.Size >= minimumEncodedRootKeyBytes && status.Size <= maximumEncodedRootKeyBytes &&
		status.Size%2 == 0
}

func sameCredentialFileStatus(before, after unix.Stat_t) bool {
	return before.Dev == after.Dev && before.Ino == after.Ino && before.Mode == after.Mode &&
		before.Nlink == after.Nlink && before.Uid == after.Uid && before.Gid == after.Gid &&
		before.Size == after.Size && before.Mtim == after.Mtim && before.Ctim == after.Ctim
}
