// Package manifest validates and canonically encodes the logical workspace
// filesystem described by SPEC.md section 17.4.
package manifest

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/hancomac/circulusd/internal/canonical"
	"golang.org/x/text/unicode/norm"
)

const (
	// MaxComponentBytes is the maximum UTF-8 byte length of a canonical path
	// component.
	MaxComponentBytes = 255

	// MaxPathBytes is the maximum UTF-8 byte length of a canonical workspace
	// path.
	MaxPathBytes = 4096

	// MaxFileSize is the largest exact integer shared by the Go and TypeScript
	// deterministic-CBOR implementations.
	MaxFileSize int64 = 9_007_199_254_740_991

	rootDigestDomain = "circulusd.workspace.manifest.root"
)

var (
	// ErrInvalidPath identifies a malformed or out-of-bounds workspace path.
	ErrInvalidPath = errors.New("invalid workspace path")

	// ErrPathCollision identifies entries whose paths are identical after NFC
	// normalization.
	ErrPathCollision = errors.New("canonical workspace path collision")

	// ErrInvalidEntry identifies invalid type-specific metadata or an unsafe
	// symlink target.
	ErrInvalidEntry = errors.New("invalid workspace entry")

	// ErrInvalidTree identifies a missing or non-directory parent entry.
	ErrInvalidTree = errors.New("invalid workspace tree")
)

// EntryType is a durable workspace entry kind.
type EntryType string

const (
	File      EntryType = "file"
	Directory EntryType = "directory"
	Symlink   EntryType = "symlink"
)

// Entry is one entry in the expanded flat logical representation. The root is
// implicit and therefore is not represented by an empty Path entry.
//
// File entries require a non-negative Size and a canonical lowercase
// sha256:<hex> ContentDigest. Directory and symlink entries require Size zero
// and no ContentDigest. Only the low nine POSIX permission bits are accepted;
// they are normalized to portable file, directory, and symlink modes.
type Entry struct {
	Path          string
	Type          EntryType
	Mode          uint32
	Size          int64
	ContentDigest string
	SymlinkTarget string
}

// Canonicalize returns a validated, NFC-normalized, bytewise path-sorted copy
// of entries. It also validates that every non-root entry has an explicitly
// represented directory parent. The input slice and its entries are not
// modified.
func Canonicalize(entries []Entry) ([]Entry, error) {
	canonical := make([]Entry, len(entries))
	kinds := make(map[string]EntryType, len(entries))

	for i, entry := range entries {
		if !utf8.ValidString(entry.Path) {
			return nil, fmt.Errorf("%w: entry %d is not valid UTF-8", ErrInvalidPath, i)
		}

		entry.Path = norm.NFC.String(entry.Path)
		if entry.Path == "" {
			return nil, fmt.Errorf("%w: entry %d is empty", ErrInvalidPath, i)
		}
		if strings.HasPrefix(entry.Path, "/") {
			return nil, fmt.Errorf("%w: %q is absolute", ErrInvalidPath, entry.Path)
		}
		if strings.IndexByte(entry.Path, 0) >= 0 {
			return nil, fmt.Errorf("%w: %q contains NUL", ErrInvalidPath, entry.Path)
		}
		if len(entry.Path) > MaxPathBytes {
			return nil, fmt.Errorf(
				"%w: %q is %d bytes; maximum is %d",
				ErrInvalidPath,
				entry.Path,
				len(entry.Path),
				MaxPathBytes,
			)
		}

		for _, component := range strings.Split(entry.Path, "/") {
			if component == "" || component == "." || component == ".." {
				return nil, fmt.Errorf(
					"%w: %q contains forbidden component %q",
					ErrInvalidPath,
					entry.Path,
					component,
				)
			}
			if len(component) > MaxComponentBytes {
				return nil, fmt.Errorf(
					"%w: component %q is %d bytes; maximum is %d",
					ErrInvalidPath,
					component,
					len(component),
					MaxComponentBytes,
				)
			}
		}

		if _, exists := kinds[entry.Path]; exists {
			return nil, fmt.Errorf("%w: %q", ErrPathCollision, entry.Path)
		}
		if entry.Mode&^uint32(0o777) != 0 {
			return nil, fmt.Errorf(
				"%w: %q mode %#o contains unsupported bits",
				ErrInvalidEntry,
				entry.Path,
				entry.Mode,
			)
		}

		switch entry.Type {
		case File:
			if entry.Size < 0 || entry.Size > MaxFileSize {
				return nil, fmt.Errorf(
					"%w: file %q size %d is outside 0..%d",
					ErrInvalidEntry,
					entry.Path,
					entry.Size,
					MaxFileSize,
				)
			}
			if entry.SymlinkTarget != "" {
				return nil, fmt.Errorf("%w: file %q has a symlink target", ErrInvalidEntry, entry.Path)
			}
			if len(entry.ContentDigest) != len("sha256:")+sha256.Size*2 ||
				!strings.HasPrefix(entry.ContentDigest, "sha256:") ||
				entry.ContentDigest != strings.ToLower(entry.ContentDigest) {
				return nil, fmt.Errorf(
					"%w: file %q has a non-canonical SHA-256 digest",
					ErrInvalidEntry,
					entry.Path,
				)
			}
			digestBytes, err := hex.DecodeString(strings.TrimPrefix(entry.ContentDigest, "sha256:"))
			if err != nil || len(digestBytes) != sha256.Size {
				return nil, fmt.Errorf(
					"%w: file %q has a malformed SHA-256 digest",
					ErrInvalidEntry,
					entry.Path,
				)
			}
			if entry.Mode&0o111 == 0 {
				entry.Mode = 0o644
			} else {
				entry.Mode = 0o755
			}

		case Directory:
			if entry.Size != 0 || entry.ContentDigest != "" || entry.SymlinkTarget != "" {
				return nil, fmt.Errorf(
					"%w: directory %q contains file or symlink metadata",
					ErrInvalidEntry,
					entry.Path,
				)
			}
			entry.Mode = 0o755

		case Symlink:
			if entry.Size != 0 || entry.ContentDigest != "" {
				return nil, fmt.Errorf(
					"%w: symlink %q contains file metadata",
					ErrInvalidEntry,
					entry.Path,
				)
			}
			if !utf8.ValidString(entry.SymlinkTarget) {
				return nil, fmt.Errorf(
					"%w: symlink %q target is not valid UTF-8",
					ErrInvalidEntry,
					entry.Path,
				)
			}

			entry.SymlinkTarget = norm.NFC.String(entry.SymlinkTarget)
			if entry.SymlinkTarget == "" ||
				strings.IndexByte(entry.SymlinkTarget, 0) >= 0 ||
				path.IsAbs(entry.SymlinkTarget) {
				return nil, fmt.Errorf(
					"%w: symlink %q target %q is not a safe relative path",
					ErrInvalidEntry,
					entry.Path,
					entry.SymlinkTarget,
				)
			}
			if len(entry.SymlinkTarget) > MaxPathBytes {
				return nil, fmt.Errorf(
					"%w: symlink %q target is longer than %d bytes",
					ErrInvalidEntry,
					entry.Path,
					MaxPathBytes,
				)
			}
			for _, component := range strings.Split(entry.SymlinkTarget, "/") {
				if component != "." && component != ".." && len(component) > MaxComponentBytes {
					return nil, fmt.Errorf(
						"%w: symlink %q target component %q is longer than %d bytes",
						ErrInvalidEntry,
						entry.Path,
						component,
						MaxComponentBytes,
					)
				}
			}

			entry.SymlinkTarget = path.Clean(entry.SymlinkTarget)

			resolvedTarget := path.Clean(path.Join(path.Dir(entry.Path), entry.SymlinkTarget))
			if resolvedTarget == ".." || strings.HasPrefix(resolvedTarget, "../") {
				return nil, fmt.Errorf(
					"%w: symlink %q target %q escapes the workspace",
					ErrInvalidEntry,
					entry.Path,
					entry.SymlinkTarget,
				)
			}
			entry.Mode = 0o777

		default:
			return nil, fmt.Errorf(
				"%w: %q has unsupported type %q",
				ErrInvalidEntry,
				entry.Path,
				entry.Type,
			)
		}

		kinds[entry.Path] = entry.Type
		canonical[i] = entry
	}

	sort.Slice(canonical, func(i, j int) bool {
		return canonical[i].Path < canonical[j].Path
	})

	for _, entry := range canonical {
		separator := strings.LastIndexByte(entry.Path, '/')
		if separator < 0 {
			continue
		}

		parent := entry.Path[:separator]
		parentType, exists := kinds[parent]
		if !exists {
			return nil, fmt.Errorf(
				"%w: %q is missing parent directory %q",
				ErrInvalidTree,
				entry.Path,
				parent,
			)
		}
		if parentType != Directory {
			return nil, fmt.Errorf(
				"%w: parent %q of %q is %q, not a directory",
				ErrInvalidTree,
				parent,
				entry.Path,
				parentType,
			)
		}
	}

	return canonical, nil
}

// Validate checks the expanded flat representation and its logical tree
// semantics without returning the normalized copy.
func Validate(entries []Entry) error {
	_, err := Canonicalize(entries)
	return err
}

// MarshalCanonical encodes the canonical expanded representation as
// deterministic CBOR. The version-1 schema is a two-element array containing
// the unsigned schema version and an array of entries. Every entry is encoded
// as [path, type-code, mode, size-or-null, digest-or-null, target-or-null].
//
// The schema contains no maps, floating-point values, or indefinite-length
// items. Array/text lengths and unsigned integers use the shortest RFC 8949
// representation.
func MarshalCanonical(entries []Entry) ([]byte, error) {
	canonicalEntries, err := Canonicalize(entries)
	if err != nil {
		return nil, err
	}
	return canonical.Encode(manifestValue(canonicalEntries), canonical.Options{})
}

// RootDigest returns the ADR-006 structured SHA-256 digest of the deterministic
// CBOR representation. Its textual form is sha256:<lowercase hex>.
func RootDigest(entries []Entry) (string, error) {
	canonicalEntries, err := Canonicalize(entries)
	if err != nil {
		return "", err
	}
	return canonical.StructuredDigest(rootDigestDomain, 1, manifestValue(canonicalEntries))
}

func manifestValue(entries []Entry) canonical.Array {
	encodedEntries := make(canonical.Array, 0, len(entries))
	for _, entry := range entries {
		var typeCode int64
		switch entry.Type {
		case File:
			typeCode = 0
		case Directory:
			typeCode = 1
		case Symlink:
			typeCode = 2
		}

		var size canonical.Value
		if entry.Type == File {
			size = entry.Size
		}
		var digest canonical.Value
		if entry.ContentDigest == "" {
			digest = nil
		} else {
			digest = entry.ContentDigest
		}
		var target canonical.Value
		if entry.SymlinkTarget == "" {
			target = nil
		} else {
			target = entry.SymlinkTarget
		}
		encodedEntries = append(encodedEntries, canonical.Array{
			entry.Path,
			typeCode,
			int64(entry.Mode),
			size,
			digest,
			target,
		})
	}
	return canonical.Array{int64(1), encodedEntries}
}
