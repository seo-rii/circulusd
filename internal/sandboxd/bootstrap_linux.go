//go:build linux

package sandboxd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/hancomac/circulusd/internal/strictjson"
	"golang.org/x/sys/unix"
)

const (
	maximumCommandManifestBytes = 1 << 20
	maximumCommandCount         = 1024
)

var ErrInvalidCommandManifest = errors.New("sandboxd: invalid command manifest")

// LoadCommandManifest reads the immutable environment allowlist used to
// resolve logical command names. The manifest itself is trusted packaging
// input, but it is still parsed fail-closed before becoming launch authority.
func LoadCommandManifest(path string, expectedOwnerUID uint32) (map[string]string, error) {
	if path == "" || len(path) > 4096 || !utf8.ValidString(path) ||
		strings.IndexByte(path, 0) >= 0 || !filepath.IsAbs(path) ||
		filepath.Clean(path) != path || path == string(filepath.Separator) {
		return nil, fmt.Errorf("%w: path must be canonical and absolute", ErrInvalidCommandManifest)
	}
	fileDescriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: open: %v", ErrInvalidCommandManifest, err)
	}
	file := os.NewFile(uintptr(fileDescriptor), "sandboxd-command-manifest")
	if file == nil {
		_ = unix.Close(fileDescriptor)
		return nil, fmt.Errorf("%w: file descriptor is unavailable", ErrInvalidCommandManifest)
	}
	defer file.Close()

	var before unix.Stat_t
	if err := unix.Fstat(fileDescriptor, &before); err != nil {
		return nil, fmt.Errorf("%w: inspect: %v", ErrInvalidCommandManifest, err)
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 ||
		before.Uid != expectedOwnerUID || before.Mode&0o022 != 0 ||
		before.Size <= 0 || before.Size > maximumCommandManifestBytes {
		return nil, fmt.Errorf("%w: file type, owner, mode, link count, or size is unsafe", ErrInvalidCommandManifest)
	}
	document, err := io.ReadAll(io.LimitReader(file, maximumCommandManifestBytes+1))
	if err != nil || len(document) == 0 || len(document) > maximumCommandManifestBytes {
		return nil, fmt.Errorf("%w: read failed or exceeded the size bound", ErrInvalidCommandManifest)
	}
	var after unix.Stat_t
	if err := unix.Fstat(fileDescriptor, &after); err != nil ||
		before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size ||
		before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return nil, fmt.Errorf("%w: file changed while it was read", ErrInvalidCommandManifest)
	}

	type commandRecord struct {
		Name string `json:"name"`
		Path string `json:"path"`
	}
	type manifestDocument struct {
		SchemaVersion int             `json:"schemaVersion"`
		Commands      []commandRecord `json:"commands"`
	}
	// encoding/json alone would bind case variants such as "PATH" to "path",
	// letting a second spelling silently replace the reviewed executable.
	var manifest manifestDocument
	if err := strictjson.Decode(document, &manifest); err != nil {
		return nil, fmt.Errorf("%w: decode: %v", ErrInvalidCommandManifest, err)
	}
	if manifest.SchemaVersion != 1 || len(manifest.Commands) == 0 ||
		len(manifest.Commands) > maximumCommandCount {
		return nil, fmt.Errorf("%w: unsupported schema or command count", ErrInvalidCommandManifest)
	}

	commands := make(map[string]string, len(manifest.Commands))
	previousName := ""
	for index, record := range manifest.Commands {
		name, err := ParseCommandName(record.Name)
		if err != nil || name.String() != record.Name ||
			(index > 0 && record.Name <= previousName) {
			return nil, fmt.Errorf("%w: command names must be unique and sorted", ErrInvalidCommandManifest)
		}
		if record.Path == "" || len(record.Path) > 4096 || !utf8.ValidString(record.Path) ||
			strings.IndexByte(record.Path, 0) >= 0 || !filepath.IsAbs(record.Path) ||
			filepath.Clean(record.Path) != record.Path || record.Path == string(filepath.Separator) {
			return nil, fmt.Errorf("%w: command %q path is not canonical", ErrInvalidCommandManifest, record.Name)
		}
		for _, mutableRoot := range []string{
			"/workspace", "/scratch", "/tmp", "/run", "/proc", "/dev", "/sys",
		} {
			if record.Path == mutableRoot || strings.HasPrefix(record.Path, mutableRoot+string(filepath.Separator)) {
				return nil, fmt.Errorf("%w: command %q resolves from a mutable path", ErrInvalidCommandManifest, record.Name)
			}
		}
		commands[record.Name] = record.Path
		previousName = record.Name
	}
	return commands, nil
}
