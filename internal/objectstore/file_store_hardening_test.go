package objectstore

import (
	"bytes"
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestFileStoreMaxInt64ObjectSizeReadsFullData reproduces R6: with the maximum
// object size at math.MaxInt64 the read limit maximumObjectBytes+1 overflowed to a
// negative value, so io.LimitReader returned EOF immediately and Get silently
// yielded empty data for a file that was written correctly.
func TestFileStoreMaxInt64ObjectSizeReadsFullData(t *testing.T) {
	t.Parallel()
	store, err := NewFileStore(t.TempDir(), FileStoreOptions{MaximumObjectBytes: math.MaxInt64})
	if err != nil {
		t.Fatalf("NewFileStore() error = %v", err)
	}
	defer store.Close()

	if _, err := store.PutIfAbsent(context.Background(), BucketArtifacts, "abc", []byte("abc")); err != nil {
		t.Fatalf("PutIfAbsent() error = %v", err)
	}
	object, err := store.Get(context.Background(), BucketArtifacts, "abc")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !bytes.Equal(object.Data, []byte("abc")) {
		t.Fatalf("Get() data = %q, want %q (overflowed read limit silently truncated the object)", object.Data, "abc")
	}
	if object.ETag != ETagFor([]byte("abc")) {
		t.Fatalf("Get() ETag = %q, want the content ETag", object.ETag)
	}
}

// TestFileStoreLockWaitHonorsContextCancellation reproduces R4: a blocking
// flock(LOCK_EX) ignored the caller's context for the whole wait, so a request
// deadline could not interrupt an operation contending for a held key lock. It
// also checks that a different key is not blocked by the held lock.
func TestFileStoreLockWaitHonorsContextCancellation(t *testing.T) {
	t.Parallel()
	store := newTestFileStore(t)

	held := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = store.withKeyLock(context.Background(), BucketCelldState, "contended", func() error {
			close(held)
			<-release
			return nil
		})
	}()
	<-held
	defer func() {
		close(release)
		<-done
	}()

	deadlineCtx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := store.PutIfAbsent(deadlineCtx, BucketCelldState, "contended", []byte("x"))
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("PutIfAbsent under a held lock = %v, want context.DeadlineExceeded", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("PutIfAbsent waited %v before honoring a 30ms deadline", elapsed)
	}

	// A different key must not be blocked by the held lock.
	otherCtx, otherCancel := context.WithTimeout(context.Background(), time.Second)
	defer otherCancel()
	if _, err := store.PutIfAbsent(otherCtx, BucketCelldState, "free", []byte("y")); err != nil {
		t.Fatalf("PutIfAbsent on an uncontended key error = %v", err)
	}
}

// TestFileStoreConfinesToOriginalRootAfterSwap reproduces R5: the store captured
// the root as a path string, so renaming the root directory and replacing it with
// a symlink to an attacker-controlled directory caused reads to escape the
// original root. Operating through a held *os.Root keeps every access relative to
// the original root directory descriptor.
func TestFileStoreConfinesToOriginalRootAfterSwap(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	root := filepath.Join(base, "store")
	store, err := NewFileStore(root, FileStoreOptions{MaximumObjectBytes: 1 << 20})
	if err != nil {
		t.Fatalf("NewFileStore() error = %v", err)
	}
	defer store.Close()

	if _, err := store.PutIfAbsent(context.Background(), BucketArtifacts, "k", []byte("INSIDE")); err != nil {
		t.Fatalf("PutIfAbsent() error = %v", err)
	}

	// Plant an outside directory shaped like the store, then swap the root path for
	// a symlink pointing at it.
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(filepath.Join(outside, string(BucketArtifacts)), 0o700); err != nil {
		t.Fatalf("MkdirAll(outside) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(outside, string(BucketArtifacts), "k"), []byte("OUTSIDE"), 0o600); err != nil {
		t.Fatalf("WriteFile(outside) error = %v", err)
	}
	if err := os.Rename(root, filepath.Join(base, "moved")); err != nil {
		t.Fatalf("Rename(root) error = %v", err)
	}
	if err := os.Symlink(outside, root); err != nil {
		t.Fatalf("Symlink(root) error = %v", err)
	}

	object, err := store.Get(context.Background(), BucketArtifacts, "k")
	if err != nil {
		t.Fatalf("Get(after swap) error = %v", err)
	}
	if bytes.Equal(object.Data, []byte("OUTSIDE")) {
		t.Fatalf("Get(after swap) escaped the original root and read the swapped-in data")
	}
	if !bytes.Equal(object.Data, []byte("INSIDE")) {
		t.Fatalf("Get(after swap) data = %q, want the original %q", object.Data, "INSIDE")
	}
}

// TestFileStoreKeysThatArePathPrefixesFailClosed covers keys such as "a" and
// "a/b": the file layout cannot hold both, so the second key must be rejected
// as a key error, and reads of it must report a missing object rather than an
// unsafe path.
func TestFileStoreKeysThatArePathPrefixesFailClosed(t *testing.T) {
	t.Parallel()
	store := newTestFileStore(t)
	defer store.Close()
	ctx := context.Background()
	missing := ETagFor([]byte("missing"))

	shortETag, err := store.PutIfAbsent(ctx, BucketArtifacts, "short", []byte("short"))
	if err != nil {
		t.Fatalf("PutIfAbsent(short) error = %v", err)
	}
	if _, err := store.PutIfAbsent(ctx, BucketArtifacts, "short/nested", []byte("nested")); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("PutIfAbsent(below an object) error = %v, want ErrInvalidKey", err)
	}
	if _, err := store.Get(ctx, BucketArtifacts, "short/nested"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get(below an object) error = %v, want ErrNotFound", err)
	}
	if _, err := store.CompareAndSwap(ctx, BucketArtifacts, "short/nested", missing, []byte("x")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("CompareAndSwap(below an object) error = %v, want ErrNotFound", err)
	}
	if err := store.DeleteIfMatch(ctx, BucketArtifacts, "short/nested", missing); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteIfMatch(below an object) error = %v, want ErrNotFound", err)
	}
	if object, err := store.Get(ctx, BucketArtifacts, "short"); err != nil || string(object.Data) != "short" || object.ETag != shortETag {
		t.Fatalf("Get(short) = %q/%q, %v; want the original object", object.Data, object.ETag, err)
	}

	if _, err := store.PutIfAbsent(ctx, BucketArtifacts, "parent/child", []byte("child")); err != nil {
		t.Fatalf("PutIfAbsent(parent/child) error = %v", err)
	}
	if _, err := store.PutIfAbsent(ctx, BucketArtifacts, "parent", []byte("parent")); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("PutIfAbsent(prefix of an object) error = %v, want ErrInvalidKey", err)
	}
	if _, err := store.Get(ctx, BucketArtifacts, "parent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get(prefix of an object) error = %v, want ErrNotFound", err)
	}
	if _, err := store.CompareAndSwap(ctx, BucketArtifacts, "parent", missing, []byte("x")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("CompareAndSwap(prefix of an object) error = %v, want ErrNotFound", err)
	}
	if err := store.DeleteIfMatch(ctx, BucketArtifacts, "parent", missing); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteIfMatch(prefix of an object) error = %v, want ErrNotFound", err)
	}
	if object, err := store.Get(ctx, BucketArtifacts, "parent/child"); err != nil || string(object.Data) != "child" {
		t.Fatalf("Get(parent/child) = %q, %v; want the original object", object.Data, err)
	}

	// Keys must not alias the store's own temporary files, which live next to
	// objects and can be left behind by a crash.
	for _, key := range []string{".circulusd-object-0123", "dir/.circulusd-object-0123", ".circulusd-object-/x"} {
		if _, err := store.PutIfAbsent(ctx, BucketArtifacts, key, []byte("x")); !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("PutIfAbsent(%q) error = %v, want ErrInvalidKey", key, err)
		}
		if _, err := store.Get(ctx, BucketArtifacts, key); !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("Get(%q) error = %v, want ErrInvalidKey", key, err)
		}
	}
}

// TestFileStoreGetRacingDeleteReportsNotFound checks that a Get that observes
// an object and then loses it to a concurrent delete reports ErrNotFound, not
// a generic open error. Get takes no key lock, so the race is real.
func TestFileStoreGetRacingDeleteReportsNotFound(t *testing.T) {
	t.Parallel()
	store := newTestFileStore(t)
	defer store.Close()
	ctx := context.Background()

	stop := make(chan struct{})
	writer := make(chan error, 1)
	go func() {
		for {
			select {
			case <-stop:
				writer <- nil
				return
			default:
			}
			etag, err := store.PutIfAbsent(ctx, BucketArtifacts, "raced", []byte("raced"))
			if err != nil {
				writer <- err
				return
			}
			if err := store.DeleteIfMatch(ctx, BucketArtifacts, "raced", etag); err != nil {
				writer <- err
				return
			}
		}
	}()
	var raceErr error
	for deadline := time.Now().Add(500 * time.Millisecond); time.Now().Before(deadline) && raceErr == nil; {
		if _, err := store.Get(ctx, BucketArtifacts, "raced"); err != nil && !errors.Is(err, ErrNotFound) {
			raceErr = err
		}
	}
	close(stop)
	if err := <-writer; err != nil {
		t.Fatalf("writer error = %v", err)
	}
	if raceErr != nil {
		t.Fatalf("Get(racing delete) error = %v, want nil or ErrNotFound", raceErr)
	}
}
