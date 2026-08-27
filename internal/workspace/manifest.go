// Package workspace exposes the canonical, backend-independent workspace
// projection format. Sandbox scans are untrusted input until BuildManifest has
// validated and normalized them.
package workspace

import (
	"errors"
	"fmt"

	"github.com/hancomac/circulusd/internal/canonical"
	wiremanifest "github.com/hancomac/circulusd/internal/workspace/manifest"
)

const (
	defaultMaximumEntries       = 50_000
	defaultMaximumMetadataBytes = 8 << 20
)

var (
	// These aliases keep the facade and wire packages on one validation
	// contract. Callers can use errors.Is across either package boundary.
	ErrInvalidPath      = wiremanifest.ErrInvalidPath
	ErrPathCollision    = wiremanifest.ErrPathCollision
	ErrInvalidEntry     = wiremanifest.ErrInvalidEntry
	ErrInvalidHierarchy = wiremanifest.ErrInvalidTree
	ErrInvalidSymlink   = wiremanifest.ErrInvalidEntry
	ErrManifestTooLarge = errors.New("workspace: manifest exceeds configured quota")
)

type EntryType = wiremanifest.EntryType

const (
	EntryFile      = wiremanifest.File
	EntryDirectory = wiremanifest.Directory
	EntrySymlink   = wiremanifest.Symlink
)

// Entry is the portable subset retained by an authoritative workspace
// revision. It is an alias of the deterministic wire entry so storage,
// projection, and diff code cannot silently disagree about canonical bytes.
type Entry = wiremanifest.Entry

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

// BuildManifest applies quota policy around the shared canonical wire format.
// RootDigest therefore has exactly one schema and domain across durable state,
// sandbox materialization, and post-execution scans.
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

	entries, err := wiremanifest.Canonicalize(input)
	if err != nil {
		return Manifest{}, err
	}
	encoded, err := wiremanifest.MarshalCanonical(entries)
	if err != nil {
		if errors.Is(err, canonical.ErrLimitExceeded) {
			return Manifest{}, fmt.Errorf("%w: metadata limit %d bytes", ErrManifestTooLarge, limits.MaxMetadataBytes)
		}
		return Manifest{}, fmt.Errorf("encode workspace manifest: %w", err)
	}
	if len(encoded) > limits.MaxMetadataBytes {
		return Manifest{}, fmt.Errorf("%w: metadata is %d bytes; limit %d", ErrManifestTooLarge, len(encoded), limits.MaxMetadataBytes)
	}
	rootDigest, err := wiremanifest.RootDigest(entries)
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
