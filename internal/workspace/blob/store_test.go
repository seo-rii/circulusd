package blob

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/identity"
	"github.com/hancomac/circulusd/internal/objectstore"
)

func TestContentStoreUploadsDeduplicatesAndReadsTenantScopedBytes(t *testing.T) {
	t.Parallel()
	content, objects := newTestContentStore(t)
	tenant := blobTenant(t, "A")
	createdAt := time.Unix(1_900_000_000, 0).UTC()

	first, err := content.Upload(context.Background(), tenant, []byte("workspace bytes"), createdAt)
	if err != nil {
		t.Fatalf("Upload() error = %v", err)
	}
	second, err := content.Upload(context.Background(), tenant, []byte("workspace bytes"), createdAt.Add(time.Hour))
	if err != nil {
		t.Fatalf("Upload(dedup) error = %v", err)
	}
	if first != second || first.Size != uint64(len("workspace bytes")) {
		t.Fatalf("dedup references = %#v and %#v", first, second)
	}
	data, err := content.Read(context.Background(), tenant, first)
	if err != nil || string(data) != "workspace bytes" {
		t.Fatalf("Read() = %q, %v", data, err)
	}
	data[0] = 'X'
	again, err := content.Read(context.Background(), tenant, first)
	if err != nil || string(again) != "workspace bytes" {
		t.Fatalf("Read(copy) = %q, %v", again, err)
	}

	stored, err := objects.Get(context.Background(), objectstore.BucketWorkspaceBlobs, first.ObjectKey())
	if err != nil || string(stored.Data) != "workspace bytes" || string(stored.ETag) != first.Digest {
		t.Fatalf("underlying content object = %#v, %v", stored, err)
	}
}

func TestContentStoreNeverCrossesTenantScope(t *testing.T) {
	t.Parallel()
	content, _ := newTestContentStore(t)
	owner := blobTenant(t, "B")
	other := blobTenant(t, "C")
	reference, err := content.Upload(context.Background(), owner, []byte("private"), time.Unix(1_900_000_100, 0).UTC())
	if err != nil {
		t.Fatalf("Upload() error = %v", err)
	}
	if _, err := content.Read(context.Background(), other, reference); !errors.Is(err, ErrTenantMismatch) {
		t.Fatalf("Read(other tenant) error = %v, want ErrTenantMismatch", err)
	}
	if _, err := content.Protect(context.Background(), other, reference, "permit-cross-tenant"); !errors.Is(err, ErrTenantMismatch) {
		t.Fatalf("Protect(other tenant) error = %v, want ErrTenantMismatch", err)
	}
}

func TestContentStoreRejectsAnObjectWhoseBytesDoNotMatchItsAddress(t *testing.T) {
	t.Parallel()
	content, objects := newTestContentStore(t)
	tenant := blobTenant(t, "D")
	reference := ReferenceFor(tenant, []byte("expected"))
	if _, err := objects.PutIfAbsent(context.Background(), objectstore.BucketWorkspaceBlobs, reference.ObjectKey(), []byte("tampered")); err != nil {
		t.Fatalf("PutIfAbsent(tampered fixture) error = %v", err)
	}

	if _, err := content.Upload(context.Background(), tenant, []byte("expected"), time.Unix(1_900_000_200, 0).UTC()); !errors.Is(err, ErrCorruptObject) {
		t.Fatalf("Upload(corrupt existing) error = %v, want ErrCorruptObject", err)
	}
	if _, err := content.Read(context.Background(), tenant, reference); !errors.Is(err, ErrCorruptObject) {
		t.Fatalf("Read(corrupt existing) error = %v, want ErrCorruptObject", err)
	}
}

func TestConcurrentContentUploadConvergesOnOneObjectAndGuard(t *testing.T) {
	t.Parallel()
	content, _ := newTestContentStore(t)
	tenant := blobTenant(t, "E")
	createdAt := time.Unix(1_900_000_300, 0).UTC()

	const workers = 64
	results := make(chan Reference, workers)
	errorsChannel := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			reference, err := content.Upload(context.Background(), tenant, []byte("same bytes"), createdAt)
			results <- reference
			errorsChannel <- err
		}()
	}
	wait.Wait()
	close(results)
	close(errorsChannel)
	for err := range errorsChannel {
		if err != nil {
			t.Fatalf("Upload() error = %v", err)
		}
	}
	var first Reference
	for result := range results {
		if first == (Reference{}) {
			first = result
		}
		if result != first {
			t.Fatalf("Upload() = %#v, want stable %#v", result, first)
		}
	}
	snapshot := content.guards.Snapshot(Key{TenantID: tenant.String(), Digest: first.Digest})
	if !snapshot.Found || snapshot.State != Live || snapshot.Incarnation != 1 {
		t.Fatalf("guard snapshot = %#v", snapshot)
	}
}

func TestContentDeletionIsPhysicallyDurableAndIdempotent(t *testing.T) {
	t.Parallel()
	content, objects := newTestContentStore(t)
	tenant := blobTenant(t, "F")
	start := time.Unix(1_900_000_400, 0).UTC()
	reference, err := content.Upload(context.Background(), tenant, []byte("delete me"), start)
	if err != nil {
		t.Fatalf("Upload() error = %v", err)
	}
	permit, err := content.Protect(context.Background(), tenant, reference, "permit-before-reference")
	if err != nil {
		t.Fatalf("Protect() error = %v", err)
	}
	if permit.Key.Digest != reference.Digest || permit.Key.TenantID != tenant.String() {
		t.Fatalf("Protect() = %#v", permit)
	}
	if err := content.guards.Finalize(permit.ID); err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}
	if _, err := content.guards.Sweep(1, true, nil, start); err != nil {
		t.Fatalf("Sweep(candidate) error = %v", err)
	}
	deletions, err := content.guards.Sweep(2, true, nil, start)
	if err != nil || len(deletions) != 1 {
		t.Fatalf("Sweep(deleting) = %#v, %v", deletions, err)
	}
	if err := content.Delete(context.Background(), deletions[0]); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if err := content.Delete(context.Background(), deletions[0]); err != nil {
		t.Fatalf("Delete(idempotent retry) error = %v", err)
	}
	if _, err := objects.Get(context.Background(), objectstore.BucketWorkspaceBlobs, reference.ObjectKey()); !errors.Is(err, objectstore.ErrNotFound) {
		t.Fatalf("Get(deleted) error = %v, want ErrNotFound", err)
	}
	if snapshot := content.guards.Snapshot(deletions[0].Key); snapshot.State != Deleted {
		t.Fatalf("guard after delete = %#v", snapshot)
	}
}

func TestStaleDeletionClaimCannotDeleteLiveContent(t *testing.T) {
	t.Parallel()
	content, _ := newTestContentStore(t)
	tenant := blobTenant(t, "G")
	reference, err := content.Upload(
		context.Background(),
		tenant,
		[]byte("must remain live"),
		time.Unix(1_900_000_500, 0).UTC(),
	)
	if err != nil {
		t.Fatalf("Upload() error = %v", err)
	}
	key := Key{TenantID: tenant.String(), Digest: reference.Digest}
	snapshot := content.guards.Snapshot(key)
	forged := Deletion{Key: key, GuardGeneration: snapshot.Generation, Epoch: 1}
	if err := content.Delete(context.Background(), forged); !errors.Is(err, ErrStaleDeletion) {
		t.Fatalf("Delete(forged) error = %v, want ErrStaleDeletion", err)
	}
	data, err := content.Read(context.Background(), tenant, reference)
	if err != nil || string(data) != "must remain live" {
		t.Fatalf("Read(after forged deletion) = %q, %v", data, err)
	}
}

func newTestContentStore(t *testing.T) (*ContentStore, *objectstore.FileStore) {
	t.Helper()
	objects, err := objectstore.NewFileStore(t.TempDir(), objectstore.FileStoreOptions{MaximumObjectBytes: 1 << 20})
	if err != nil {
		t.Fatalf("NewFileStore() error = %v", err)
	}
	content, err := NewContentStore(objects, NewGuardTable(0))
	if err != nil {
		t.Fatalf("NewContentStore() error = %v", err)
	}
	return content, objects
}

func blobTenant(t *testing.T, fill string) identity.ID {
	t.Helper()
	id, err := (identity.Generator{Random: bytes.NewReader(bytes.Repeat([]byte(fill), 16))}).New(identity.Tenant)
	if err != nil {
		t.Fatalf("New(tenant) error = %v", err)
	}
	return id
}
