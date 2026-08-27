//go:build linux

// Package materialized implements the materialized-manifest projection from
// SPEC.md sections 17.4 and 17.5. It turns a verified logical snapshot into a
// private filesystem tree and reconstructs the authoritative post-execution
// manifest with a full scan.
package materialized

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/hancomac/circulusd/internal/workspace/manifest"
	"golang.org/x/sys/unix"
)

var (
	// ErrInvalidLimits identifies missing or nonsensical caller-supplied
	// workspace quota limits. This package deliberately has no implicit size
	// defaults because deployment quotas are policy, not format invariants.
	ErrInvalidLimits = errors.New("materialized workspace: invalid limits")

	// ErrInvalidRoot identifies a relative, non-canonical, or symlink-resolved
	// host projection path.
	ErrInvalidRoot = errors.New("materialized workspace: invalid root")

	// ErrDestinationExists means an atomic materialization lost the publish
	// race or was asked to overwrite an existing tree.
	ErrDestinationExists = errors.New("materialized workspace: destination exists")

	// ErrSnapshotMismatch means the entries do not match the snapshot's
	// declared canonical root digest.
	ErrSnapshotMismatch = errors.New("materialized workspace: snapshot digest mismatch")

	// ErrCorruptBlob means content returned for a digest has the wrong size or
	// SHA-256 value, or could not be read completely.
	ErrCorruptBlob = errors.New("materialized workspace: corrupt blob")

	// ErrLimitExceeded identifies a scan or materialization that exceeds the
	// caller's entry, per-file, or aggregate content quota.
	ErrLimitExceeded = errors.New("materialized workspace: limit exceeded")

	// ErrUnsupportedFileType identifies a durable tree object outside the v0.3
	// subset, including devices, FIFOs, sockets, hard links, and special modes.
	ErrUnsupportedFileType = errors.New("materialized workspace: unsupported filesystem object")

	// ErrConcurrentMutation means a scanned object changed while it was being
	// inspected. Callers must stop all sandbox processes before retrying.
	ErrConcurrentMutation = errors.New("materialized workspace: concurrent mutation")

	// ErrInvalidContext identifies a nil context. Public operations reject it
	// before touching the filesystem instead of panicking while checking
	// cancellation.
	ErrInvalidContext = errors.New("materialized workspace: nil context")
)

// Limits are mandatory invocation-scoped quota limits. MaxEntries includes
// files, directories, and symlinks but not the implicit root directory.
type Limits struct {
	MaxEntries    int
	MaxFileBytes  int64
	MaxTotalBytes int64
}

// Ownership is the sandbox identity that owns the published workspace tree.
// Linux reserves the all-ones uid and gid as the "do not change" sentinel, so
// those values are never valid publication identities.
type Ownership struct {
	UID uint32
	GID uint32
}

// Snapshot is the flat small-workspace representation from SPEC.md section
// 17.4. RootDigest is verified before any blob is opened or staging directory
// is created.
type Snapshot struct {
	RootDigest string
	Entries    []manifest.Entry
}

// BlobSource resolves an already-authorized content digest. Implementations
// must scope authorization to the workspace/invocation; Materialize still
// verifies the exact size and digest before publishing the tree.
type BlobSource interface {
	Open(context.Context, string) (io.ReadCloser, error)
}

// ScanResult is immutable from the caller's perspective.
type ScanResult struct {
	entries    []manifest.Entry
	rootDigest string
	totalBytes int64
}

// Entries returns a copy of the canonical path-sorted manifest entries.
func (result ScanResult) Entries() []manifest.Entry {
	return append([]manifest.Entry(nil), result.entries...)
}

// RootDigest returns the deterministic canonical manifest digest.
func (result ScanResult) RootDigest() string { return result.rootDigest }

// TotalBytes returns the aggregate size of all regular files.
func (result ScanResult) TotalBytes() int64 { return result.totalBytes }

// Materialize constructs snapshot in a private sibling staging directory and
// publishes it with renameat2(RENAME_NOREPLACE). A target is therefore either
// absent or a complete verified tree; concurrent callers can never overwrite
// the winner.
func Materialize(ctx context.Context, target string, snapshot Snapshot, source BlobSource, limits Limits, ownership Ownership) (returnErr error) {
	if ctx == nil {
		return ErrInvalidContext
	}
	if err := validateLimits(limits); err != nil {
		return err
	}
	if ownership.UID == ^uint32(0) || ownership.GID == ^uint32(0) {
		return fmt.Errorf("invalid workspace ownership %d:%d", ownership.UID, ownership.GID)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	canonicalEntries, err := manifest.Canonicalize(snapshot.Entries)
	if err != nil {
		return fmt.Errorf("canonicalize snapshot: %w", err)
	}
	if len(canonicalEntries) > limits.MaxEntries {
		return fmt.Errorf("%w: %d entries exceed maximum %d", ErrLimitExceeded, len(canonicalEntries), limits.MaxEntries)
	}
	var totalBytes int64
	hasFiles := false
	for _, entry := range canonicalEntries {
		if entry.Type != manifest.File {
			continue
		}
		hasFiles = true
		if entry.Size > limits.MaxFileBytes {
			return fmt.Errorf("%w: file %q is %d bytes; maximum is %d", ErrLimitExceeded, entry.Path, entry.Size, limits.MaxFileBytes)
		}
		if entry.Size > limits.MaxTotalBytes-totalBytes {
			return fmt.Errorf("%w: total content exceeds %d bytes", ErrLimitExceeded, limits.MaxTotalBytes)
		}
		totalBytes += entry.Size
	}
	actualRootDigest, err := manifest.RootDigest(canonicalEntries)
	if err != nil {
		return fmt.Errorf("digest snapshot: %w", err)
	}
	if snapshot.RootDigest != actualRootDigest {
		return fmt.Errorf("%w: declared %q, actual %q", ErrSnapshotMismatch, snapshot.RootDigest, actualRootDigest)
	}
	if source == nil && hasFiles {
		return fmt.Errorf("%w: blob source is required", ErrCorruptBlob)
	}

	parentPath, targetName, err := splitCanonicalRoot(target)
	if err != nil {
		return err
	}
	parentFD, err := openAbsoluteDirectory(parentPath)
	if err != nil {
		return fmt.Errorf("%w: open target parent: %v", ErrInvalidRoot, err)
	}
	defer unix.Close(parentFD)

	var existing unix.Stat_t
	if err := unix.Fstatat(parentFD, targetName, &existing, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		return ErrDestinationExists
	} else if !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("inspect materialization target: %w", err)
	}

	var randomSuffix [16]byte
	stageName := ""
	for range 8 {
		if _, err := rand.Read(randomSuffix[:]); err != nil {
			return fmt.Errorf("create staging name: %w", err)
		}
		candidate := fmt.Sprintf(".workspace-stage-%x", randomSuffix[:])
		if err := unix.Mkdirat(parentFD, candidate, 0o700); err == nil {
			stageName = candidate
			break
		} else if !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("create staging directory: %w", err)
		}
	}
	if stageName == "" {
		return errors.New("create staging directory: repeated random-name collision")
	}
	stageFD, err := openDirectoryAt(parentFD, stageName)
	if err != nil {
		_ = unix.Unlinkat(parentFD, stageName, unix.AT_REMOVEDIR)
		return fmt.Errorf("open staging directory: %w", err)
	}
	published := false
	defer func() {
		_ = unix.Close(stageFD)
		if published {
			return
		}
		if cleanupErr := removeTreeAt(parentFD, stageName); cleanupErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("clean staging directory: %w", cleanupErr))
		}
	}()

	directories := make([]string, 0)
	for _, entry := range canonicalEntries {
		if err := ctx.Err(); err != nil {
			return err
		}
		parentRelative := path.Dir(entry.Path)
		entryName := path.Base(entry.Path)
		entryParentFD, err := openDirectoryAt(stageFD, parentRelative)
		if err != nil {
			return fmt.Errorf("open parent of %q: %w", entry.Path, err)
		}

		switch entry.Type {
		case manifest.Directory:
			err = unix.Mkdirat(entryParentFD, entryName, 0o700)
			if err == nil {
				directoryFD := -1
				directoryFD, err = openDirectoryAt(entryParentFD, entryName)
				if err == nil {
					err = unix.Fchown(directoryFD, int(ownership.UID), int(ownership.GID))
				}
				if directoryFD >= 0 {
					closeDirectoryErr := unix.Close(directoryFD)
					if err == nil {
						err = closeDirectoryErr
					}
				}
				if err == nil {
					directories = append(directories, entry.Path)
				}
			}

		case manifest.Symlink:
			err = unix.Symlinkat(entry.SymlinkTarget, entryParentFD, entryName)
			if err == nil {
				err = unix.Fchownat(entryParentFD, entryName, int(ownership.UID), int(ownership.GID), unix.AT_SYMLINK_NOFOLLOW)
			}

		case manifest.File:
			var reader io.ReadCloser
			reader, err = source.Open(ctx, entry.ContentDigest)
			if err != nil {
				err = fmt.Errorf("%w: open %q: %w", ErrCorruptBlob, entry.Path, err)
				break
			}
			if reader == nil {
				err = fmt.Errorf("%w: source returned a nil reader for %q", ErrCorruptBlob, entry.Path)
				break
			}

			fileFD, openErr := unix.Openat(entryParentFD, entryName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
			if openErr != nil {
				_ = reader.Close()
				err = openErr
				break
			}
			file := os.NewFile(uintptr(fileFD), entry.Path)
			if file == nil {
				_ = unix.Close(fileFD)
				_ = reader.Close()
				err = errors.New("invalid materialized file descriptor")
				break
			}
			hasher := sha256.New()
			written, copyErr := io.Copy(io.MultiWriter(file, hasher), io.LimitReader(&contextReader{ctx: ctx, reader: reader}, entry.Size+1))
			readerCloseErr := reader.Close()
			if copyErr == nil && readerCloseErr != nil {
				copyErr = readerCloseErr
			}
			if copyErr == nil && written != entry.Size {
				copyErr = fmt.Errorf("size is %d bytes, expected %d", written, entry.Size)
			}
			actualDigest := "sha256:" + hex.EncodeToString(hasher.Sum(nil))
			if copyErr == nil && actualDigest != entry.ContentDigest {
				copyErr = fmt.Errorf("digest is %s, expected %s", actualDigest, entry.ContentDigest)
			}
			if copyErr == nil {
				copyErr = file.Chown(int(ownership.UID), int(ownership.GID))
			}
			if copyErr == nil {
				copyErr = file.Chmod(os.FileMode(entry.Mode))
			}
			if copyErr == nil {
				copyErr = file.Sync()
			}
			fileCloseErr := file.Close()
			if copyErr == nil && fileCloseErr != nil {
				copyErr = fileCloseErr
			}
			if copyErr != nil {
				err = fmt.Errorf("%w: verify %q: %w", ErrCorruptBlob, entry.Path, copyErr)
			}
		}
		closeErr := unix.Close(entryParentFD)
		if err != nil {
			return fmt.Errorf("materialize %q: %w", entry.Path, err)
		}
		if closeErr != nil {
			return fmt.Errorf("close parent of %q: %w", entry.Path, closeErr)
		}
	}

	for index := len(directories) - 1; index >= 0; index-- {
		directoryFD, err := openDirectoryAt(stageFD, directories[index])
		if err != nil {
			return fmt.Errorf("open completed directory %q: %w", directories[index], err)
		}
		if err := unix.Fchmod(directoryFD, 0o755); err != nil {
			_ = unix.Close(directoryFD)
			return fmt.Errorf("seal directory %q: %w", directories[index], err)
		}
		if err := unix.Fsync(directoryFD); err != nil {
			_ = unix.Close(directoryFD)
			return fmt.Errorf("sync directory %q: %w", directories[index], err)
		}
		if err := unix.Close(directoryFD); err != nil {
			return fmt.Errorf("close directory %q: %w", directories[index], err)
		}
	}
	if err := unix.Fchown(stageFD, int(ownership.UID), int(ownership.GID)); err != nil {
		return fmt.Errorf("set staging root ownership: %w", err)
	}
	if err := unix.Fchmod(stageFD, 0o755); err != nil {
		return fmt.Errorf("seal staging root: %w", err)
	}
	if err := unix.Fsync(stageFD); err != nil {
		return fmt.Errorf("sync staging root: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := unix.Renameat2(parentFD, stageName, parentFD, targetName, unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, unix.EEXIST) || errors.Is(err, unix.ENOTEMPTY) {
			return ErrDestinationExists
		}
		return fmt.Errorf("publish materialized workspace: %w", err)
	}
	published = true
	if err := unix.Fsync(parentFD); err != nil {
		return fmt.Errorf("sync materialized workspace parent: %w", err)
	}
	return nil
}

// Scan performs the correctness-reference full filesystem scan. It never
// follows workspace symlinks, rejects hard links and special objects, hashes
// file descriptors opened beneath the pinned root, and validates the result
// through the shared canonical manifest schema.
func Scan(ctx context.Context, root string, limits Limits) (ScanResult, error) {
	if ctx == nil {
		return ScanResult{}, ErrInvalidContext
	}
	if err := validateLimits(limits); err != nil {
		return ScanResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return ScanResult{}, err
	}
	rootPath, rootName, err := splitCanonicalRoot(root)
	if err != nil {
		return ScanResult{}, err
	}
	parentFD, err := openAbsoluteDirectory(rootPath)
	if err != nil {
		return ScanResult{}, fmt.Errorf("%w: open scan parent: %v", ErrInvalidRoot, err)
	}
	defer unix.Close(parentFD)
	rootFD, err := openDirectoryAt(parentFD, rootName)
	if err != nil {
		return ScanResult{}, fmt.Errorf("%w: open scan root: %v", ErrInvalidRoot, err)
	}
	defer unix.Close(rootFD)

	state := scanState{limits: limits, entries: make([]manifest.Entry, 0)}
	var rootBefore unix.Stat_t
	if err := unix.Fstat(rootFD, &rootBefore); err != nil {
		return ScanResult{}, fmt.Errorf("stat scan root: %w", err)
	}
	if err := state.scanDirectory(ctx, rootFD, ""); err != nil {
		return ScanResult{}, err
	}
	var rootAfter unix.Stat_t
	if err := unix.Fstat(rootFD, &rootAfter); err != nil {
		return ScanResult{}, fmt.Errorf("restat scan root: %w", err)
	}
	if rootBefore.Dev != rootAfter.Dev || rootBefore.Ino != rootAfter.Ino || rootBefore.Mode != rootAfter.Mode ||
		rootBefore.Mtim != rootAfter.Mtim || rootBefore.Ctim != rootAfter.Ctim {
		return ScanResult{}, fmt.Errorf("%w: root changed during scan", ErrConcurrentMutation)
	}

	canonicalEntries, err := manifest.Canonicalize(state.entries)
	if err != nil {
		return ScanResult{}, fmt.Errorf("canonicalize full scan: %w", err)
	}
	rootDigest, err := manifest.RootDigest(canonicalEntries)
	if err != nil {
		return ScanResult{}, fmt.Errorf("digest full scan: %w", err)
	}
	return ScanResult{entries: canonicalEntries, rootDigest: rootDigest, totalBytes: state.totalBytes}, nil
}

type scanState struct {
	limits     Limits
	entries    []manifest.Entry
	totalBytes int64
}

func (state *scanState) scanDirectory(ctx context.Context, directoryFD int, prefix string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	duplicateFD, err := duplicateCloseOnExec(directoryFD)
	if err != nil {
		return fmt.Errorf("duplicate directory descriptor: %w", err)
	}
	directory := os.NewFile(uintptr(duplicateFD), prefix)
	if directory == nil {
		_ = unix.Close(duplicateFD)
		return errors.New("invalid directory descriptor")
	}
	directoryEntries := make([]os.DirEntry, 0)
	var readErr error
	for {
		var batch []os.DirEntry
		batch, readErr = directory.ReadDir(128)
		if len(directoryEntries)+len(batch) > state.limits.MaxEntries-len(state.entries) {
			_ = directory.Close()
			return fmt.Errorf("%w: entry count exceeds %d", ErrLimitExceeded, state.limits.MaxEntries)
		}
		directoryEntries = append(directoryEntries, batch...)
		if errors.Is(readErr, io.EOF) {
			readErr = nil
			break
		}
		if readErr != nil {
			break
		}
	}
	closeErr := directory.Close()
	if readErr != nil {
		return fmt.Errorf("read directory %q: %w", prefix, readErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close directory %q: %w", prefix, closeErr)
	}
	sort.Slice(directoryEntries, func(left, right int) bool {
		return directoryEntries[left].Name() < directoryEntries[right].Name()
	})

	for _, directoryEntry := range directoryEntries {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := directoryEntry.Name()
		entryPath := name
		if prefix != "" {
			entryPath = prefix + "/" + name
		}
		if !utf8.ValidString(entryPath) || strings.IndexByte(entryPath, 0) >= 0 || len(entryPath) > manifest.MaxPathBytes {
			return fmt.Errorf("%w: scanned path %q", manifest.ErrInvalidPath, entryPath)
		}
		for _, component := range strings.Split(entryPath, "/") {
			if component == "" || component == "." || component == ".." || len(component) > manifest.MaxComponentBytes {
				return fmt.Errorf("%w: scanned path %q", manifest.ErrInvalidPath, entryPath)
			}
		}
		if len(state.entries) >= state.limits.MaxEntries {
			return fmt.Errorf("%w: entry count exceeds %d", ErrLimitExceeded, state.limits.MaxEntries)
		}

		var before unix.Stat_t
		if err := unix.Fstatat(directoryFD, name, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return fmt.Errorf("stat %q: %w", entryPath, err)
		}
		if before.Mode&(unix.S_ISUID|unix.S_ISGID|unix.S_ISVTX) != 0 {
			return fmt.Errorf("%w: %q has special mode bits", ErrUnsupportedFileType, entryPath)
		}

		switch before.Mode & unix.S_IFMT {
		case unix.S_IFREG:
			if before.Nlink != 1 {
				return fmt.Errorf("%w: regular file %q has %d links", ErrUnsupportedFileType, entryPath, before.Nlink)
			}
			if before.Size < 0 || before.Size > state.limits.MaxFileBytes {
				return fmt.Errorf("%w: file %q is %d bytes; maximum is %d", ErrLimitExceeded, entryPath, before.Size, state.limits.MaxFileBytes)
			}
			if before.Size > state.limits.MaxTotalBytes-state.totalBytes {
				return fmt.Errorf("%w: total content exceeds %d bytes", ErrLimitExceeded, state.limits.MaxTotalBytes)
			}
			fileFD, err := unix.Openat2(directoryFD, name, &unix.OpenHow{
				Flags:   uint64(unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW),
				Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV,
			})
			if err != nil {
				if errors.Is(err, unix.EXDEV) {
					return fmt.Errorf("%w: file %q crosses a mount boundary", ErrUnsupportedFileType, entryPath)
				}
				return fmt.Errorf("open file %q: %w", entryPath, err)
			}
			file := os.NewFile(uintptr(fileFD), entryPath)
			if file == nil {
				_ = unix.Close(fileFD)
				return fmt.Errorf("open file %q: invalid descriptor", entryPath)
			}
			var opened unix.Stat_t
			if err := unix.Fstat(fileFD, &opened); err != nil {
				_ = file.Close()
				return fmt.Errorf("stat opened file %q: %w", entryPath, err)
			}
			if before.Dev != opened.Dev || before.Ino != opened.Ino || before.Mode != opened.Mode ||
				before.Nlink != opened.Nlink || before.Size != opened.Size || before.Mtim != opened.Mtim || before.Ctim != opened.Ctim {
				_ = file.Close()
				return fmt.Errorf("%w: file %q changed before open", ErrConcurrentMutation, entryPath)
			}
			xattrBytes, xattrErr := unix.Flistxattr(fileFD, nil)
			if xattrErr != nil && !errors.Is(xattrErr, unix.ENOTSUP) && !errors.Is(xattrErr, unix.EOPNOTSUPP) {
				_ = file.Close()
				return fmt.Errorf("list attributes for %q: %w", entryPath, xattrErr)
			}
			if xattrBytes > 0 {
				_ = file.Close()
				return fmt.Errorf("%w: file %q has extended attributes", ErrUnsupportedFileType, entryPath)
			}
			hasher := sha256.New()
			readBytes, readErr := io.Copy(hasher, io.LimitReader(&contextReader{ctx: ctx, reader: file}, state.limits.MaxFileBytes+1))
			var after unix.Stat_t
			statErr := unix.Fstat(fileFD, &after)
			fileCloseErr := file.Close()
			if readErr != nil {
				return fmt.Errorf("hash file %q: %w", entryPath, readErr)
			}
			if statErr != nil {
				return fmt.Errorf("restat file %q: %w", entryPath, statErr)
			}
			if fileCloseErr != nil {
				return fmt.Errorf("close file %q: %w", entryPath, fileCloseErr)
			}
			if readBytes != before.Size || before.Dev != after.Dev || before.Ino != after.Ino || before.Mode != after.Mode ||
				before.Nlink != after.Nlink || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
				return fmt.Errorf("%w: file %q changed while hashing", ErrConcurrentMutation, entryPath)
			}
			state.totalBytes += readBytes
			state.entries = append(state.entries, manifest.Entry{
				Path:          entryPath,
				Type:          manifest.File,
				Mode:          uint32(before.Mode & 0o777),
				Size:          readBytes,
				ContentDigest: "sha256:" + hex.EncodeToString(hasher.Sum(nil)),
			})

		case unix.S_IFDIR:
			subdirectoryFD, err := unix.Openat2(directoryFD, name, &unix.OpenHow{
				Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW),
				Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV,
			})
			if err != nil {
				if errors.Is(err, unix.EXDEV) {
					return fmt.Errorf("%w: directory %q crosses a mount boundary", ErrUnsupportedFileType, entryPath)
				}
				return fmt.Errorf("open directory %q: %w", entryPath, err)
			}
			var opened unix.Stat_t
			if err := unix.Fstat(subdirectoryFD, &opened); err != nil {
				_ = unix.Close(subdirectoryFD)
				return fmt.Errorf("stat opened directory %q: %w", entryPath, err)
			}
			if before.Dev != opened.Dev || before.Ino != opened.Ino || before.Mode != opened.Mode ||
				before.Mtim != opened.Mtim || before.Ctim != opened.Ctim {
				_ = unix.Close(subdirectoryFD)
				return fmt.Errorf("%w: directory %q changed before open", ErrConcurrentMutation, entryPath)
			}
			xattrBytes, xattrErr := unix.Flistxattr(subdirectoryFD, nil)
			if xattrErr != nil && !errors.Is(xattrErr, unix.ENOTSUP) && !errors.Is(xattrErr, unix.EOPNOTSUPP) {
				_ = unix.Close(subdirectoryFD)
				return fmt.Errorf("list attributes for directory %q: %w", entryPath, xattrErr)
			}
			if xattrBytes > 0 {
				_ = unix.Close(subdirectoryFD)
				return fmt.Errorf("%w: directory %q has extended attributes", ErrUnsupportedFileType, entryPath)
			}
			state.entries = append(state.entries, manifest.Entry{Path: entryPath, Type: manifest.Directory, Mode: uint32(before.Mode & 0o777)})
			if err := state.scanDirectory(ctx, subdirectoryFD, entryPath); err != nil {
				_ = unix.Close(subdirectoryFD)
				return err
			}
			var after unix.Stat_t
			statErr := unix.Fstat(subdirectoryFD, &after)
			closeErr := unix.Close(subdirectoryFD)
			if statErr != nil {
				return fmt.Errorf("restat directory %q: %w", entryPath, statErr)
			}
			if closeErr != nil {
				return fmt.Errorf("close directory %q: %w", entryPath, closeErr)
			}
			if before.Dev != after.Dev || before.Ino != after.Ino || before.Mode != after.Mode ||
				before.Mtim != after.Mtim || before.Ctim != after.Ctim {
				return fmt.Errorf("%w: directory %q changed during scan", ErrConcurrentMutation, entryPath)
			}

		case unix.S_IFLNK:
			if before.Nlink != 1 {
				return fmt.Errorf("%w: symlink %q has %d links", ErrUnsupportedFileType, entryPath, before.Nlink)
			}
			targetBuffer := make([]byte, manifest.MaxPathBytes+1)
			targetBytes, err := unix.Readlinkat(directoryFD, name, targetBuffer)
			if err != nil {
				return fmt.Errorf("read symlink %q: %w", entryPath, err)
			}
			if targetBytes == len(targetBuffer) {
				return fmt.Errorf("%w: symlink %q target exceeds %d bytes", manifest.ErrInvalidEntry, entryPath, manifest.MaxPathBytes)
			}
			var after unix.Stat_t
			if err := unix.Fstatat(directoryFD, name, &after, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return fmt.Errorf("restat symlink %q: %w", entryPath, err)
			}
			if before.Dev != after.Dev || before.Ino != after.Ino || before.Mode != after.Mode ||
				before.Nlink != after.Nlink || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
				return fmt.Errorf("%w: symlink %q changed during scan", ErrConcurrentMutation, entryPath)
			}
			state.entries = append(state.entries, manifest.Entry{
				Path:          entryPath,
				Type:          manifest.Symlink,
				Mode:          uint32(before.Mode & 0o777),
				SymlinkTarget: string(targetBuffer[:targetBytes]),
			})

		default:
			return fmt.Errorf("%w: %q has mode %#o", ErrUnsupportedFileType, entryPath, before.Mode)
		}
	}
	return nil
}

func validateLimits(limits Limits) error {
	if limits.MaxEntries <= 0 || limits.MaxFileBytes <= 0 || limits.MaxTotalBytes <= 0 || limits.MaxFileBytes > manifest.MaxFileSize || limits.MaxTotalBytes > manifest.MaxFileSize {
		return fmt.Errorf("%w: entries=%d fileBytes=%d totalBytes=%d", ErrInvalidLimits, limits.MaxEntries, limits.MaxFileBytes, limits.MaxTotalBytes)
	}
	return nil
}

func splitCanonicalRoot(root string) (string, string, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root || strings.IndexByte(root, 0) >= 0 || root == string(filepath.Separator) {
		return "", "", fmt.Errorf("%w: %q must be an absolute canonical non-root path", ErrInvalidRoot, root)
	}
	parent := filepath.Dir(root)
	name := filepath.Base(root)
	if name == "." || name == string(filepath.Separator) || name == "" {
		return "", "", fmt.Errorf("%w: %q has no final component", ErrInvalidRoot, root)
	}
	return parent, name, nil
}

func openAbsoluteDirectory(directory string) (int, error) {
	rootFD, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	currentFD := rootFD
	components := strings.Split(strings.TrimPrefix(directory, "/"), "/")
	if directory == "/" {
		components = nil
	}
	for componentIndex := -1; componentIndex < len(components); componentIndex++ {
		var status unix.Stat_t
		if err := unix.Fstat(currentFD, &status); err != nil {
			_ = unix.Close(currentFD)
			return -1, err
		}
		if status.Mode&unix.S_IFMT != unix.S_IFDIR {
			_ = unix.Close(currentFD)
			return -1, unix.ENOTDIR
		}
		trustedOwner := status.Uid == 0 || status.Uid == uint32(os.Geteuid())
		writableByOthers := status.Mode&0o022 != 0
		rootOwnedSticky := status.Uid == 0 && status.Mode&unix.S_ISVTX != 0
		if !trustedOwner || writableByOthers && !rootOwnedSticky {
			_ = unix.Close(currentFD)
			return -1, fmt.Errorf("untrusted directory owner or mode %d:%#o", status.Uid, status.Mode&0o7777)
		}
		if componentIndex+1 == len(components) {
			return currentFD, nil
		}
		nextFD, err := unix.Openat2(currentFD, components[componentIndex+1], &unix.OpenHow{
			Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW),
			Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
		})
		_ = unix.Close(currentFD)
		if err != nil {
			return -1, err
		}
		currentFD = nextFD
	}
	return -1, unix.ENOENT
}

func openDirectoryAt(rootFD int, relative string) (int, error) {
	if relative == "." || relative == "" {
		return duplicateCloseOnExec(rootFD)
	}
	return unix.Openat2(rootFD, relative, &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
	})
}

func removeTreeAt(parentFD int, name string) error {
	childFD, err := openDirectoryAt(parentFD, name)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	duplicateFD, err := duplicateCloseOnExec(childFD)
	if err != nil {
		_ = unix.Close(childFD)
		return err
	}
	directory := os.NewFile(uintptr(duplicateFD), name)
	if directory == nil {
		_ = unix.Close(duplicateFD)
		_ = unix.Close(childFD)
		return errors.New("invalid cleanup directory descriptor")
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil {
		_ = unix.Close(childFD)
		return readErr
	}
	if closeErr != nil {
		_ = unix.Close(childFD)
		return closeErr
	}
	for _, entry := range entries {
		var information unix.Stat_t
		if err := unix.Fstatat(childFD, entry.Name(), &information, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			_ = unix.Close(childFD)
			return err
		}
		if information.Mode&unix.S_IFMT == unix.S_IFDIR {
			if err := removeTreeAt(childFD, entry.Name()); err != nil {
				_ = unix.Close(childFD)
				return err
			}
		} else if err := unix.Unlinkat(childFD, entry.Name(), 0); err != nil {
			_ = unix.Close(childFD)
			return err
		}
	}
	if err := unix.Close(childFD); err != nil {
		return err
	}
	return unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR)
}

func duplicateCloseOnExec(fileDescriptor int) (int, error) {
	return unix.FcntlInt(uintptr(fileDescriptor), unix.F_DUPFD_CLOEXEC, 0)
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *contextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}
