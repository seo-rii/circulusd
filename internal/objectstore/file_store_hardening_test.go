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
