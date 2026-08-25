// Package workspace defines the canonical, backend-independent workspace
// projection format. Sandbox scans are untrusted input until BuildManifest has
// validated and normalized them.
package workspace

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/hancomac/circulusd/internal/canonical"
	"golang.org/x/text/unicode/norm"
)

const (
	defaultMaximumEntries       = 50_000
	defaultMaximumMetadataBytes = 8 << 20
	maximumPathBytes            = 4096
	maximumPathComponentBytes   = 255
)

var (
	ErrInvalidPath      = errors.New("workspace: invalid canonical path")
	ErrPathCollision    = errors.New("workspace: normalized path collision")
	ErrInvalidEntry     = errors.New("workspace: invalid manifest entry")
	ErrInvalidHierarchy = errors.New("workspace: invalid manifest hierarchy")
	ErrInvalidSymlink   = errors.New("workspace: invalid symlink target")
	ErrManifestTooLarge = errors.New("workspace: manifest exceeds configured quota")
)

type EntryType string

const (
	EntryFile      EntryType = "file"
	EntryDirectory EntryType = "directory"
	EntrySymlink   EntryType = "symlink"
)

// Entry is the portable subset retained by an authoritative workspace
// revision. Mode contains permission bits only and is normalized to the
// canonical sandbox user: regular files retain only executable/non-executable
// semantics, directories are 0755, and symlinks are 0777.
type Entry struct {
	Path          string
	Type          EntryType
	Mode          uint32
	Size          uint64
	ContentDigest string
	SymlinkTarget string
}

type Limits struct {
	MaxEntries       int
	MaxMetadataBytes int
}

// Manifest has no exported mutable storage. Entries always returns a copy so
// one validated snapshot can safely be shared among concurrent projections.
type Manifest struct {
	entries       []Entry
	rootDigest    string
	metadataBytes int
}

func (manifest Manifest) Entries() []Entry {
	entries := make([]Entry, len(manifest.entries))
	for index, entry := range manifest.entries {
		entries[index] = cloneEntry(entry)
	}
	return entries
}

func (manifest Manifest) RootDigest() string { return manifest.rootDigest }

func (manifest Manifest) MetadataBytes() int { return manifest.metadataBytes }

// BuildManifest normalizes an exact sandbox scan into a deterministic tree.
// It rejects ambiguous paths and unsupported filesystem objects before any
// blob reference is eligible for a Workspace DO commit.
func BuildManifest(input []Entry, limits Limits) (Manifest, error) {
	if limits.MaxEntries < 0 || limits.MaxMetadataBytes < 0 {
		return Manifest{}, fmt.Errorf("%w: limits cannot be negative", ErrManifestTooLarge)
	}
	if limits.MaxEntries == 0 {
		limits.MaxEntries = defaultMaximumEntries
	}
	if limits.MaxMetadataBytes == 0 {
		limits.MaxMetadataBytes = defaultMaximumMetadataBytes
	}
	if len(input) > limits.MaxEntries {
		return Manifest{}, fmt.Errorf("%w: got %d entries, limit %d", ErrManifestTooLarge, len(input), limits.MaxEntries)
	}

	entries := make([]Entry, len(input))
	seen := make(map[string]struct{}, len(input))
	for index, candidate := range input {
		if !utf8.ValidString(candidate.Path) || candidate.Path == "" || strings.HasPrefix(candidate.Path, "/") {
			return Manifest{}, fmt.Errorf("%w: entry %d", ErrInvalidPath, index)
		}
		normalizedPath := norm.NFC.String(candidate.Path)
		if len(normalizedPath) > maximumPathBytes {
			return Manifest{}, fmt.Errorf("%w: %q exceeds %d bytes", ErrInvalidPath, normalizedPath, maximumPathBytes)
		}
		components := strings.Split(normalizedPath, "/")
		for _, component := range components {
			if component == "" || component == "." || component == ".." || len(component) > maximumPathComponentBytes {
				return Manifest{}, fmt.Errorf("%w: %q", ErrInvalidPath, normalizedPath)
			}
			for _, character := range component {
				if unicode.IsControl(character) {
					return Manifest{}, fmt.Errorf("%w: %q contains a control character", ErrInvalidPath, normalizedPath)
				}
			}
		}
		if _, duplicate := seen[normalizedPath]; duplicate {
			return Manifest{}, fmt.Errorf("%w: %q", ErrPathCollision, normalizedPath)
		}
		seen[normalizedPath] = struct{}{}

		entry := candidate
		entry.Path = normalizedPath
		if entry.Mode&^uint32(0o777) != 0 {
			return Manifest{}, fmt.Errorf("%w: %q has non-permission mode bits", ErrInvalidEntry, normalizedPath)
		}
		switch entry.Type {
		case EntryFile:
			if entry.ContentDigest == "" || entry.SymlinkTarget != "" || len(entry.ContentDigest) != 71 || !strings.HasPrefix(entry.ContentDigest, "sha256:") || strings.ToLower(entry.ContentDigest) != entry.ContentDigest {
				return Manifest{}, fmt.Errorf("%w: file %q has invalid fields", ErrInvalidEntry, normalizedPath)
			}
			decodedDigest, err := hex.DecodeString(strings.TrimPrefix(entry.ContentDigest, "sha256:"))
			if err != nil || len(decodedDigest) != 32 {
				return Manifest{}, fmt.Errorf("%w: file %q has invalid digest", ErrInvalidEntry, normalizedPath)
			}
			if entry.Mode&0o111 != 0 {
				entry.Mode = 0o755
			} else {
				entry.Mode = 0o644
			}
		case EntryDirectory:
			if entry.Size != 0 || entry.ContentDigest != "" || entry.SymlinkTarget != "" {
				return Manifest{}, fmt.Errorf("%w: directory %q carries file data", ErrInvalidEntry, normalizedPath)
			}
			entry.Mode = 0o755
		case EntrySymlink:
			if entry.Size != 0 || entry.ContentDigest != "" || entry.SymlinkTarget == "" || !utf8.ValidString(entry.SymlinkTarget) || strings.HasPrefix(entry.SymlinkTarget, "/") {
				return Manifest{}, fmt.Errorf("%w: %q", ErrInvalidSymlink, normalizedPath)
			}
			entry.SymlinkTarget = norm.NFC.String(entry.SymlinkTarget)
			if len(entry.SymlinkTarget) > maximumPathBytes {
				return Manifest{}, fmt.Errorf("%w: %q target is too long", ErrInvalidSymlink, normalizedPath)
			}
			baseDepth := len(components) - 1
			resolvedDepth := baseDepth
			for _, component := range strings.Split(entry.SymlinkTarget, "/") {
				if component == "" || component == "." || len(component) > maximumPathComponentBytes {
					return Manifest{}, fmt.Errorf("%w: %q", ErrInvalidSymlink, normalizedPath)
				}
				if component == ".." {
					resolvedDepth--
					if resolvedDepth < 0 {
						return Manifest{}, fmt.Errorf("%w: %q escapes the workspace", ErrInvalidSymlink, normalizedPath)
					}
					continue
				}
				for _, character := range component {
					if unicode.IsControl(character) {
						return Manifest{}, fmt.Errorf("%w: %q contains a control character", ErrInvalidSymlink, normalizedPath)
					}
				}
				resolvedDepth++
			}
			entry.Mode = 0o777
		default:
			return Manifest{}, fmt.Errorf("%w: %q has unsupported type %q", ErrInvalidEntry, normalizedPath, entry.Type)
		}
		entries[index] = entry
	}

	sort.Slice(entries, func(left, right int) bool {
		return bytes.Compare([]byte(entries[left].Path), []byte(entries[right].Path)) < 0
	})
	entryByPath := make(map[string]Entry, len(entries))
	for _, entry := range entries {
		if separator := strings.LastIndexByte(entry.Path, '/'); separator >= 0 {
			parent, exists := entryByPath[entry.Path[:separator]]
			if !exists || parent.Type != EntryDirectory {
				return Manifest{}, fmt.Errorf("%w: parent of %q is not a directory", ErrInvalidHierarchy, entry.Path)
			}
		}
		entryByPath[entry.Path] = entry
	}

	payload := make(canonical.Array, len(entries))
	for index, entry := range entries {
		switch entry.Type {
		case EntryFile:
			payload[index] = canonical.Array{string(entry.Type), entry.Path, uint64(entry.Mode), entry.Size, entry.ContentDigest}
		case EntryDirectory:
			payload[index] = canonical.Array{string(entry.Type), entry.Path, uint64(entry.Mode)}
		case EntrySymlink:
			payload[index] = canonical.Array{string(entry.Type), entry.Path, uint64(entry.Mode), entry.SymlinkTarget}
		}
	}
	encoded, err := canonical.Encode(payload, canonical.Options{MaxBytes: limits.MaxMetadataBytes})
	if err != nil {
		if errors.Is(err, canonical.ErrLimitExceeded) {
			return Manifest{}, fmt.Errorf("%w: metadata limit %d bytes", ErrManifestTooLarge, limits.MaxMetadataBytes)
		}
		return Manifest{}, fmt.Errorf("encode workspace manifest: %w", err)
	}
	rootDigest, err := canonical.StructuredDigest("workspace.manifest", 1, payload)
	if err != nil {
		return Manifest{}, fmt.Errorf("digest workspace manifest: %w", err)
	}
	return Manifest{entries: entries, rootDigest: rootDigest, metadataBytes: len(encoded)}, nil
}

type MutationKind string

const (
	MutationCreate MutationKind = "create"
	MutationUpdate MutationKind = "update"
	MutationDelete MutationKind = "delete"
)

type Mutation struct {
	Kind   MutationKind
	Path   string
	Before *Entry
	After  *Entry
}

// Diff compares complete canonical scans. It deliberately has no rename
// primitive: a rename is represented as one delete and one create, matching
// both full-scan and overlayfs semantics.
func Diff(base Manifest, next Manifest) []Mutation {
	mutations := make([]Mutation, 0)
	left, right := 0, 0
	for left < len(base.entries) || right < len(next.entries) {
		switch {
		case left == len(base.entries):
			after := cloneEntry(next.entries[right])
			mutations = append(mutations, Mutation{Kind: MutationCreate, Path: after.Path, After: &after})
			right++
		case right == len(next.entries):
			before := cloneEntry(base.entries[left])
			mutations = append(mutations, Mutation{Kind: MutationDelete, Path: before.Path, Before: &before})
			left++
		case base.entries[left].Path < next.entries[right].Path:
			before := cloneEntry(base.entries[left])
			mutations = append(mutations, Mutation{Kind: MutationDelete, Path: before.Path, Before: &before})
			left++
		case next.entries[right].Path < base.entries[left].Path:
			after := cloneEntry(next.entries[right])
			mutations = append(mutations, Mutation{Kind: MutationCreate, Path: after.Path, After: &after})
			right++
		default:
			if base.entries[left] != next.entries[right] {
				before := cloneEntry(base.entries[left])
				after := cloneEntry(next.entries[right])
				mutations = append(mutations, Mutation{Kind: MutationUpdate, Path: before.Path, Before: &before, After: &after})
			}
			left++
			right++
		}
	}
	return mutations
}

func cloneEntry(entry Entry) Entry { return entry }
