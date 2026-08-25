package objectstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const (
	defaultMaximumObjectBytes = int64(64 << 20)
	maximumKeyBytes           = 1024
)

type FileStore struct {
	root               string
	lockRoot           string
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
	lockRoot := filepath.Join(resolved, ".locks")
	if err := os.Mkdir(lockRoot, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("create object-store lock directory: %w", err)
	}
	lockInformation, err := os.Lstat(lockRoot)
	if err != nil || !lockInformation.IsDir() || lockInformation.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: lock path is not a private directory", ErrUnsafePath)
	}
	return &FileStore{root: resolved, lockRoot: lockRoot, maximumObjectBytes: maximum}, nil
}

func ETagFor(data []byte) ETag {
	digest := sha256.Sum256(data)
	return ETag("sha256:" + hex.EncodeToString(digest[:]))
}

func (store *FileStore) Get(ctx context.Context, bucket Bucket, key string) (Object, error) {
	if err := ctx.Err(); err != nil {
		return Object{}, err
	}
	objectPath, err := store.objectPath(bucket, key)
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
	objectPath, err := store.objectPath(bucket, key)
	if err != nil {
		return "", err
	}
	var result ETag
	err = store.withKeyLock(ctx, bucket, key, func() error {
		if err := store.ensureParentDirectories(filepath.Dir(objectPath)); err != nil {
			return err
		}
		information, err := os.Lstat(objectPath)
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
	objectPath, err := store.objectPath(bucket, key)
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
	objectPath, err := store.objectPath(bucket, key)
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
		if err := os.Remove(objectPath); err != nil {
			return fmt.Errorf("delete conditional object: %w", err)
		}
		if err := syncDirectory(filepath.Dir(objectPath)); err != nil {
			return fmt.Errorf("persist conditional delete: %w", err)
		}
		return nil
	})
}

func (store *FileStore) objectPath(bucket Bucket, key string) (string, error) {
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
	return filepath.Join(store.root, string(bucket), filepath.FromSlash(key)), nil
}

func (store *FileStore) withKeyLock(ctx context.Context, bucket Bucket, key string, operation func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	lockDigest := sha256.Sum256([]byte(string(bucket) + "\x00" + key))
	lockPath := filepath.Join(store.lockRoot, hex.EncodeToString(lockDigest[:])+".lock")
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open object lock: %w", err)
	}
	defer file.Close()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("lock object: %w", err)
	}
	defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	if err := ctx.Err(); err != nil {
		return err
	}
	return operation()
}

func (store *FileStore) ensureParentDirectories(parent string) error {
	relative, err := filepath.Rel(store.root, parent)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return ErrUnsafePath
	}
	current := store.root
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "." || component == "" {
			continue
		}
		current = filepath.Join(current, component)
		information, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			created := false
			if err := os.Mkdir(current, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
				return fmt.Errorf("create object parent: %w", err)
			} else if err == nil {
				created = true
			}
			if created {
				if err := syncDirectory(filepath.Dir(current)); err != nil {
					return fmt.Errorf("persist object parent: %w", err)
				}
			}
			information, err = os.Lstat(current)
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
	parent := filepath.Dir(objectPath)
	relative, err := filepath.Rel(store.root, parent)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, "", ErrUnsafePath
	}
	current := store.root
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "." || component == "" {
			continue
		}
		current = filepath.Join(current, component)
		information, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil, "", ErrNotFound
		}
		if err != nil {
			return nil, "", fmt.Errorf("inspect object parent: %w", err)
		}
		if !information.IsDir() || information.Mode()&os.ModeSymlink != 0 {
			return nil, "", ErrUnsafePath
		}
	}
	information, err := os.Lstat(objectPath)
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
	file, err := os.Open(objectPath)
	if err != nil {
		return nil, "", fmt.Errorf("open object: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, store.maximumObjectBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("read object: %w", err)
	}
	if int64(len(data)) > store.maximumObjectBytes {
		return nil, "", ErrObjectTooLarge
	}
	return data, ETagFor(data), nil
}

func (store *FileStore) writeAtomic(objectPath string, data []byte) error {
	parent := filepath.Dir(objectPath)
	if err := store.ensureParentDirectories(parent); err != nil {
		return err
	}
	file, err := os.CreateTemp(parent, ".circulusd-object-*")
	if err != nil {
		return fmt.Errorf("create object temporary: %w", err)
	}
	temporary := file.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporary)
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
	if err := os.Rename(temporary, objectPath); err != nil {
		return fmt.Errorf("publish object: %w", err)
	}
	removeTemporary = false
	if err := syncDirectory(parent); err != nil {
		return fmt.Errorf("persist object publication: %w", err)
	}
	return nil
}

func syncDirectory(directory string) error {
	file, err := os.Open(directory)
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
