package objectstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestFileStoreConditionalWriteAndReadAfterWrite(t *testing.T) {
	t.Parallel()
	store := newTestFileStore(t)
	ctx := context.Background()

	firstETag, err := store.PutIfAbsent(ctx, BucketCelldState, "sessions/sess-1", []byte("version-1"))
	if err != nil {
		t.Fatalf("PutIfAbsent() error = %v", err)
	}
	if firstETag != ETagFor([]byte("version-1")) {
		t.Fatalf("PutIfAbsent() ETag = %q, want content ETag", firstETag)
	}
	object, err := store.Get(ctx, BucketCelldState, "sessions/sess-1")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !bytes.Equal(object.Data, []byte("version-1")) || object.ETag != firstETag {
		t.Fatalf("Get() = %#v, want version-1/%s", object, firstETag)
	}

	if _, err := store.PutIfAbsent(ctx, BucketCelldState, "sessions/sess-1", []byte("other")); !errors.Is(err, ErrPreconditionFailed) {
		t.Fatalf("duplicate PutIfAbsent() error = %v, want ErrPreconditionFailed", err)
	}
	if _, err := store.CompareAndSwap(ctx, BucketCelldState, "sessions/sess-1", ETagFor([]byte("wrong")), []byte("corrupt")); !errors.Is(err, ErrPreconditionFailed) {
		t.Fatalf("wrong CompareAndSwap() error = %v, want ErrPreconditionFailed", err)
	}
	secondETag, err := store.CompareAndSwap(ctx, BucketCelldState, "sessions/sess-1", firstETag, []byte("version-2"))
	if err != nil {
		t.Fatalf("CompareAndSwap() error = %v", err)
	}
	object, err = store.Get(ctx, BucketCelldState, "sessions/sess-1")
	if err != nil {
		t.Fatalf("Get(after CAS) error = %v", err)
	}
	if !bytes.Equal(object.Data, []byte("version-2")) || object.ETag != secondETag {
		t.Fatalf("Get(after CAS) = %#v", object)
	}
}

func TestFileStoreConcurrentCASHasExactlyOneWinner(t *testing.T) {
	t.Parallel()
	store := newTestFileStore(t)
	ctx := context.Background()
	initial, err := store.PutIfAbsent(ctx, BucketCelldState, "ownership/object-1", []byte("owner-0"))
	if err != nil {
		t.Fatalf("PutIfAbsent() error = %v", err)
	}

	const contenders = 64
	var wait sync.WaitGroup
	results := make(chan error, contenders)
	for contender := range contenders {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := store.CompareAndSwap(ctx, BucketCelldState, "ownership/object-1", initial, []byte(fmt.Sprintf("owner-%d", contender+1)))
			results <- err
		}()
	}
	wait.Wait()
	close(results)
	winners := 0
	losers := 0
	for err := range results {
		switch {
		case err == nil:
			winners++
		case errors.Is(err, ErrPreconditionFailed):
			losers++
		default:
			t.Fatalf("CompareAndSwap() error = %v", err)
		}
	}
	if winners != 1 || losers != contenders-1 {
		t.Fatalf("CAS results = %d winners/%d losers, want 1/%d", winners, losers, contenders-1)
	}
}

func TestFileStorePersistsAcrossRestartAndFencesDelete(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	first, err := NewFileStore(root, FileStoreOptions{MaximumObjectBytes: 1 << 20})
	if err != nil {
		t.Fatalf("NewFileStore(first) error = %v", err)
	}
	etag, err := first.PutIfAbsent(context.Background(), BucketWorkspaceBlobs, "tenant-a/sha256/ab/cd/blob", []byte("blob"))
	if err != nil {
		t.Fatalf("PutIfAbsent() error = %v", err)
	}

	restarted, err := NewFileStore(root, FileStoreOptions{MaximumObjectBytes: 1 << 20})
	if err != nil {
		t.Fatalf("NewFileStore(restarted) error = %v", err)
	}
	object, err := restarted.Get(context.Background(), BucketWorkspaceBlobs, "tenant-a/sha256/ab/cd/blob")
	if err != nil || !bytes.Equal(object.Data, []byte("blob")) || object.ETag != etag {
		t.Fatalf("Get(after restart) = %#v, %v", object, err)
	}
	if err := restarted.DeleteIfMatch(context.Background(), BucketWorkspaceBlobs, "tenant-a/sha256/ab/cd/blob", ETagFor([]byte("other"))); !errors.Is(err, ErrPreconditionFailed) {
		t.Fatalf("DeleteIfMatch(wrong) error = %v, want ErrPreconditionFailed", err)
	}
	if err := restarted.DeleteIfMatch(context.Background(), BucketWorkspaceBlobs, "tenant-a/sha256/ab/cd/blob", etag); err != nil {
		t.Fatalf("DeleteIfMatch() error = %v", err)
	}
	if _, err := restarted.Get(context.Background(), BucketWorkspaceBlobs, "tenant-a/sha256/ab/cd/blob"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get(deleted) error = %v, want ErrNotFound", err)
	}
}

func TestFileStoreRejectsTraversalSymlinksInvalidBucketsAndOversizeWrites(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	store, err := NewFileStore(root, FileStoreOptions{MaximumObjectBytes: 4})
	if err != nil {
		t.Fatalf("NewFileStore() error = %v", err)
	}
	ctx := context.Background()

	for _, key := range []string{"", "/absolute", "../escape", "a/../../escape", "a//b", "a/./b", "e\u0301"} {
		if _, err := store.PutIfAbsent(ctx, BucketArtifacts, key, []byte("ok")); !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("PutIfAbsent(key %q) error = %v, want ErrInvalidKey", key, err)
		}
	}
	if _, err := store.PutIfAbsent(ctx, Bucket("user-bucket"), "safe", []byte("ok")); !errors.Is(err, ErrInvalidBucket) {
		t.Fatalf("PutIfAbsent(invalid bucket) error = %v, want ErrInvalidBucket", err)
	}
	if _, err := store.PutIfAbsent(ctx, BucketArtifacts, "too-large", []byte("12345")); !errors.Is(err, ErrObjectTooLarge) {
		t.Fatalf("PutIfAbsent(oversize) error = %v, want ErrObjectTooLarge", err)
	}

	bucketRoot := filepath.Join(root, string(BucketArtifacts))
	if err := os.MkdirAll(bucketRoot, 0o700); err != nil {
		t.Fatalf("MkdirAll(bucket) error = %v", err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(bucketRoot, "linked")); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	if _, err := store.PutIfAbsent(ctx, BucketArtifacts, "linked/escape", []byte("ok")); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("PutIfAbsent(symlink parent) error = %v, want ErrUnsafePath", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "escape")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("outside path was touched, Stat() error = %v", err)
	}
}

func TestFileStoreHonorsCancellationAndReturnsCopies(t *testing.T) {
	t.Parallel()
	store := newTestFileStore(t)
	data := []byte("original")
	if _, err := store.PutIfAbsent(context.Background(), BucketRuntimeBundles, "runtime/one", data); err != nil {
		t.Fatalf("PutIfAbsent() error = %v", err)
	}
	data[0] = 'X'
	object, err := store.Get(context.Background(), BucketRuntimeBundles, "runtime/one")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	object.Data[0] = 'Y'
	again, err := store.Get(context.Background(), BucketRuntimeBundles, "runtime/one")
	if err != nil || string(again.Data) != "original" {
		t.Fatalf("Get(copy) = %q, %v", again.Data, err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Get(cancelled, BucketRuntimeBundles, "runtime/one"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Get(cancelled) error = %v, want context.Canceled", err)
	}
}

func newTestFileStore(t *testing.T) *FileStore {
	t.Helper()
	store, err := NewFileStore(t.TempDir(), FileStoreOptions{MaximumObjectBytes: 1 << 20})
	if err != nil {
		t.Fatalf("NewFileStore() error = %v", err)
	}
	return store
}
