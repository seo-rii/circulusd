package objectstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const (
	defaultMaximumObjectBytes = int64(64 << 20)
	maximumKeyBytes           = 1024
	lockDirectory             = ".locks"
)

// FileStore is the durable single-node object store. All filesystem access is
// performed through an *os.Root opened once at construction, so every path is
// resolved relative to the held root directory descriptor (openat semantics).
// This confines operations to the original root even if the root path is later
// renamed or replaced by a symlink, and it refuses any component symlink that
// would escape the root — neither guarantee holds for a captured path string.
type FileStore struct {
	root               *os.Root
	maximumObjectBytes int64
}

func NewFileStore(root string, options FileStoreOptions) (*FileStore, error) {
	if root == "" {
		return nil, fmt.Errorf("%w: storage root is empty", ErrUnsafePath)
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve object-store root: %w", err)
	}
	if filepath.Clean(absolute) == string(filepath.Separator) {
		return nil, fmt.Errorf("%w: filesystem root cannot be an object-store root", ErrUnsafePath)
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return nil, fmt.Errorf("create object-store root: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return nil, fmt.Errorf("resolve object-store root symlinks: %w", err)
	}
	information, err := os.Stat(resolved)
	if err != nil {
		return nil, fmt.Errorf("stat object-store root: %w", err)
	}
	if !information.IsDir() {
		return nil, fmt.Errorf("%w: storage root is not a directory", ErrUnsafePath)
	}
	maximum := options.MaximumObjectBytes
	if maximum == 0 {
		maximum = defaultMaximumObjectBytes
	}
	if maximum < 0 {
		return nil, fmt.Errorf("%w: negative maximum object size", ErrObjectTooLarge)
	}
	rooted, err := os.OpenRoot(resolved)
	if err != nil {
		return nil, fmt.Errorf("open object-store root: %w", err)
	}
	store := &FileStore{root: rooted, maximumObjectBytes: maximum}
	if err := store.ensureLockDirectory(); err != nil {
		_ = rooted.Close()
		return nil, err
	}
	return store, nil
}

// Close releases the root directory descriptor. A FileStore is normally held for
// the lifetime of the process; Close exists so tests and transient stores do not
// leak the descriptor.
func (store *FileStore) Close() error {
	return store.root.Close()
}

func (store *FileStore) ensureLockDirectory() error {
	if err := store.root.Mkdir(lockDirectory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create object-store lock directory: %w", err)
	}
	information, err := store.root.Lstat(lockDirectory)
	if err != nil || !information.IsDir() || information.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: lock path is not a private directory", ErrUnsafePath)
	}
	return nil
}

func ETagFor(data []byte) ETag {
	digest := sha256.Sum256(data)
	return ETag("sha256:" + hex.EncodeToString(digest[:]))
}

func (store *FileStore) Get(ctx context.Context, bucket Bucket, key string) (Object, error) {
	if err := ctx.Err(); err != nil {
		return Object{}, err
	}
	objectPath, err := store.objectRelPath(bucket, key)
	if err != nil {
		return Object{}, err
	}
	data, etag, err := store.readExisting(objectPath)
	if err != nil {
		return Object{}, err
	}
	return Object{Data: data, ETag: etag}, nil
}

func (store *FileStore) PutIfAbsent(ctx context.Context, bucket Bucket, key string, data []byte) (ETag, error) {
	if int64(len(data)) > store.maximumObjectBytes {
		return "", ErrObjectTooLarge
	}
	objectPath, err := store.objectRelPath(bucket, key)
	if err != nil {
		return "", err
	}
	var result ETag
	err = store.withKeyLock(ctx, bucket, key, func() error {
		if err := store.ensureParentDirectories(path.Dir(objectPath)); err != nil {
			return err
		}
		information, err := store.root.Lstat(objectPath)
		switch {
		case err == nil && information.Mode().IsRegular():
			return ErrPreconditionFailed
		case err == nil:
			return ErrUnsafePath
		case !errors.Is(err, os.ErrNotExist):
			return fmt.Errorf("inspect conditional-create target: %w", err)
		}
		if err := store.writeAtomic(objectPath, data); err != nil {
			return err
		}
		result = ETagFor(data)
		return nil
	})
	return result, err
}

func (store *FileStore) CompareAndSwap(ctx context.Context, bucket Bucket, key string, expected ETag, data []byte) (ETag, error) {
	if !validETag(expected) {
		return "", ErrInvalidETag
	}
	if int64(len(data)) > store.maximumObjectBytes {
		return "", ErrObjectTooLarge
	}
	objectPath, err := store.objectRelPath(bucket, key)
	if err != nil {
		return "", err
	}
	var result ETag
	err = store.withKeyLock(ctx, bucket, key, func() error {
		_, current, err := store.readExisting(objectPath)
		if err != nil {
			return err
		}
		if current != expected {
			return ErrPreconditionFailed
		}
		if err := store.writeAtomic(objectPath, data); err != nil {
			return err
		}
		result = ETagFor(data)
		return nil
	})
	return result, err
}

func (store *FileStore) DeleteIfMatch(ctx context.Context, bucket Bucket, key string, expected ETag) error {
	if !validETag(expected) {
		return ErrInvalidETag
	}
	objectPath, err := store.objectRelPath(bucket, key)
	if err != nil {
		return err
	}
	return store.withKeyLock(ctx, bucket, key, func() error {
		_, current, err := store.readExisting(objectPath)
		if err != nil {
			return err
		}
		if current != expected {
			return ErrPreconditionFailed
		}
		if err := store.root.Remove(objectPath); err != nil {
			return fmt.Errorf("delete conditional object: %w", err)
		}
		if err := store.syncDirectory(path.Dir(objectPath)); err != nil {
			return fmt.Errorf("persist conditional delete: %w", err)
		}
		return nil
	})
}

// objectRelPath validates the bucket and key and returns the slash-separated path
// of the object relative to the store root. The store is Linux-only (advisory
// flock), so the slash separator is the OS separator and no conversion is needed.
func (store *FileStore) objectRelPath(bucket Bucket, key string) (string, error) {
	switch bucket {
	case BucketCelldState, BucketWorkspaceBlobs, BucketArtifacts, BucketExtensionBundles, BucketRuntimeBundles, BucketExecutionEnvironments, BucketBackups:
	default:
		return "", ErrInvalidBucket
	}
	if key == "" || !utf8.ValidString(key) || norm.NFC.String(key) != key || len([]byte(key)) > maximumKeyBytes || strings.ContainsRune(key, '\\') || path.IsAbs(key) || path.Clean(key) != key {
		return "", ErrInvalidKey
	}
	for _, component := range strings.Split(key, "/") {
		if component == "" || component == "." || component == ".." || len([]byte(component)) > 255 {
			return "", ErrInvalidKey
		}
		for _, character := range component {
			if character < 0x20 || character == 0x7f {
				return "", ErrInvalidKey
			}
		}
	}
	return string(bucket) + "/" + key, nil
}

func (store *FileStore) withKeyLock(ctx context.Context, bucket Bucket, key string, operation func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	lockDigest := sha256.Sum256([]byte(string(bucket) + "\x00" + key))
	lockPath := lockDirectory + "/" + hex.EncodeToString(lockDigest[:]) + ".lock"
	file, err := store.root.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open object lock: %w", err)
	}
	defer file.Close()
	if err := acquireExclusiveLock(ctx, file); err != nil {
		return err
	}
	defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	if err := ctx.Err(); err != nil {
		return err
	}
	return operation()
}

// acquireExclusiveLock takes an exclusive advisory lock on file while honoring
// the caller's context. flock(2) blocks on a conflicting lock unless LOCK_NB is
// set, so a blocking LOCK_EX would ignore ctx for the entire wait — a request
// deadline could not interrupt a contended key. Instead poll with a
// non-blocking flock and wait for the lock or ctx between attempts.
func acquireExclusiveLock(ctx context.Context, file *os.File) error {
	const pollInterval = 2 * time.Millisecond
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			return fmt.Errorf("lock object: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}

// ensureParentDirectories creates each missing directory in the object's parent
// chain, rejecting any component that is not a real directory (a symlink component
// yields ErrUnsafePath). It walks one component at a time so a component symlink is
// observed as a symlink rather than silently traversed.
func (store *FileStore) ensureParentDirectories(relativeParent string) error {
	current := ""
	for _, component := range strings.Split(relativeParent, "/") {
		if component == "." || component == "" {
			continue
		}
		if current == "" {
			current = component
		} else {
			current = current + "/" + component
		}
		information, err := store.root.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			created := false
			if err := store.root.Mkdir(current, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
				return fmt.Errorf("create object parent: %w", err)
			} else if err == nil {
				created = true
			}
			if created {
				if err := store.syncDirectory(path.Dir(current)); err != nil {
					return fmt.Errorf("persist object parent: %w", err)
				}
			}
			information, err = store.root.Lstat(current)
		}
		if err != nil {
			return fmt.Errorf("inspect object parent: %w", err)
		}
		if !information.IsDir() || information.Mode()&os.ModeSymlink != 0 {
			return ErrUnsafePath
		}
	}
	return nil
}

func (store *FileStore) readExisting(objectPath string) ([]byte, ETag, error) {
	if err := store.validateExistingParents(path.Dir(objectPath)); err != nil {
		return nil, "", err
	}
	information, err := store.root.Lstat(objectPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, "", ErrNotFound
	}
	if err != nil {
		return nil, "", fmt.Errorf("inspect object: %w", err)
	}
	if !information.Mode().IsRegular() || information.Mode()&os.ModeSymlink != 0 {
		return nil, "", ErrUnsafePath
	}
	if information.Size() > store.maximumObjectBytes {
		return nil, "", ErrObjectTooLarge
	}
	file, err := store.root.Open(objectPath)
	if err != nil {
		return nil, "", fmt.Errorf("open object: %w", err)
	}
	defer file.Close()
	// Read one byte past the limit to detect a file that grew beyond the maximum
	// between the size check above and this read. Guard the +1 against overflow:
	// when the maximum is math.MaxInt64, maximumObjectBytes+1 wraps negative and
	// io.LimitReader would return EOF immediately, silently yielding empty data.
	readLimit := store.maximumObjectBytes
	if readLimit < math.MaxInt64 {
		readLimit++
	}
	data, err := io.ReadAll(io.LimitReader(file, readLimit))
	if err != nil {
		return nil, "", fmt.Errorf("read object: %w", err)
	}
	if int64(len(data)) > store.maximumObjectBytes {
		return nil, "", ErrObjectTooLarge
	}
	return data, ETagFor(data), nil
}

// validateExistingParents walks the object's parent chain for a read, requiring
// each component to be a real directory. A missing component yields ErrNotFound; a
// symlink component yields ErrUnsafePath.
func (store *FileStore) validateExistingParents(relativeParent string) error {
	current := ""
	for _, component := range strings.Split(relativeParent, "/") {
		if component == "." || component == "" {
			continue
		}
		if current == "" {
			current = component
		} else {
			current = current + "/" + component
		}
		information, err := store.root.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("inspect object parent: %w", err)
		}
		if !information.IsDir() || information.Mode()&os.ModeSymlink != 0 {
			return ErrUnsafePath
		}
	}
	return nil
}

func (store *FileStore) writeAtomic(objectPath string, data []byte) error {
	parent := path.Dir(objectPath)
	if err := store.ensureParentDirectories(parent); err != nil {
		return err
	}
	file, temporary, err := store.createTemporary(parent)
	if err != nil {
		return err
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = store.root.Remove(temporary)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return fmt.Errorf("set object permissions: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return fmt.Errorf("write object temporary: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("persist object temporary: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close object temporary: %w", err)
	}
	if err := store.root.Rename(temporary, objectPath); err != nil {
		return fmt.Errorf("publish object: %w", err)
	}
	removeTemporary = false
	if err := store.syncDirectory(parent); err != nil {
		return fmt.Errorf("persist object publication: %w", err)
	}
	return nil
}

// createTemporary creates a fresh temporary file in relativeParent through the
// root, returning the open file and its relative path. It is the confined
// equivalent of os.CreateTemp: os.Root has no CreateTemp, so a random O_EXCL name
// is used.
func (store *FileStore) createTemporary(relativeParent string) (*os.File, string, error) {
	for attempt := 0; attempt < 10_000; attempt++ {
		var randomBytes [16]byte
		if _, err := rand.Read(randomBytes[:]); err != nil {
			return nil, "", fmt.Errorf("generate object temporary name: %w", err)
		}
		name := ".circulusd-object-" + hex.EncodeToString(randomBytes[:])
		relativePath := path.Join(relativeParent, name)
		file, err := store.root.OpenFile(relativePath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err == nil {
			return file, relativePath, nil
		}
		if errors.Is(err, os.ErrExist) {
			continue
		}
		return nil, "", fmt.Errorf("create object temporary: %w", err)
	}
	return nil, "", fmt.Errorf("create object temporary: exhausted unique names")
}

// syncDirectory fsyncs a directory through the root so a create, rename, or delete
// is durable. An empty or "." relativePath names the root directory itself.
func (store *FileStore) syncDirectory(relativePath string) error {
	if relativePath == "" {
		relativePath = "."
	}
	file, err := store.root.Open(relativePath)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func validETag(etag ETag) bool {
	value := string(etag)
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && value == strings.ToLower(value)
}
