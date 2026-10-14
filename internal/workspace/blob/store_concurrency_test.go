package blob

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/objectstore"
)

func TestContentStoreFencesPhysicalDeletionAcrossSharedInstances(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	first, objects := newTestContentStore(t)
	paused := &pausedDeletionStore{Store: objects, entered: make(chan struct{}), release: make(chan struct{})}
	first.objects = paused
	second, err := NewContentStore(paused, first.guards)
	if err != nil {
		t.Fatal(err)
	}
	tenant := blobTenant(t, "R")
	now := time.Unix(1_900_000_000, 0)
	content := []byte("protected reupload")
	reference, err := first.Upload(ctx, tenant, content, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.guards.Sweep(1, true, nil, now); err != nil {
		t.Fatal(err)
	}
	claims, err := first.guards.Sweep(2, true, nil, now)
	if err != nil || len(claims) != 1 {
		t.Fatalf("Sweep() = %v, %v", claims, err)
	}
	var release sync.Once
	unpause := func() { release.Do(func() { close(paused.release) }) }
	deleted := make(chan error, 1)
	var finish sync.Once
	var deletionErr error
	finishDeletion := func() error {
		finish.Do(func() {
			unpause()
			deletionErr = <-deleted
		})
		return deletionErr
	}
	defer finishDeletion()
	go func() { deleted <- first.Delete(ctx, claims[0]) }()
	<-paused.entered
	for _, operation := range []struct {
		name string
		run  func(context.Context) error
	}{
		{"duplicate delete", func(ctx context.Context) error { return second.Delete(ctx, claims[0]) }},
		{"reupload", func(ctx context.Context) error {
			_, err := second.Upload(ctx, tenant, content, now.Add(time.Hour))
			return err
		}},
		{"protect", func(ctx context.Context) error {
			_, err := second.Protect(ctx, tenant, reference, "queued-permit")
			return err
		}},
	} {
		t.Run(operation.name, func(t *testing.T) {
			bounded, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
			defer cancel()
			if err := operation.run(bounded); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("operation during physical deletion = %v, want canceled wait", err)
			}
		})
	}
	// A held deletion fence belongs only to this digest.
	independent, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if _, err := second.Upload(independent, tenant, []byte("independent digest"), now); err != nil {
		t.Fatalf("independent upload blocked by another blob: %v", err)
	}
	if _, err := first.guards.Protect(claims[0].Key, "raw-permit"); !errors.Is(err, ErrObjectDeleting) {
		t.Fatalf("raw Protect during deletion = %v, want object deleting", err)
	}
	if _, err := first.guards.Sweep(3, true, nil, now); err != nil {
		t.Fatal(err)
	}
	if err := finishDeletion(); err != nil {
		t.Fatal(err)
	}
	reuploaded, err := second.Upload(ctx, tenant, content, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	permit, err := second.Protect(ctx, tenant, reuploaded, "new-incarnation-permit")
	if err != nil || permit.ObjectIncarnation != 2 {
		t.Fatalf("new protection = %+v, %v", permit, err)
	}
	if err := first.Delete(ctx, claims[0]); !errors.Is(err, ErrStaleDeletion) {
		t.Fatalf("old deletion after protected reupload = %v, want stale claim", err)
	}
	if _, err := first.Read(ctx, tenant, reuploaded); err != nil {
		t.Fatalf("new protected object was deleted: %v", err)
	}
	first.guards.storageMu.Lock()
	defer first.guards.storageMu.Unlock()
	if len(first.guards.storageGates) != 0 {
		t.Fatalf("completed/canceled operations retained %d storage gates", len(first.guards.storageGates))
	}
}

func TestGuardMetadataCannotResurrectDuringPhysicalDeletion(t *testing.T) {
	t.Parallel()
	content, objects := newTestContentStore(t)
	paused := &pausedDeletionStore{Store: objects, entered: make(chan struct{}), release: make(chan struct{})}
	content.objects = paused
	ctx := context.Background()
	now := time.Unix(1_900_000_000, 0)
	_, err := content.Upload(ctx, blobTenant(t, "M"), []byte("metadata fence"), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := content.guards.Sweep(1, true, nil, now); err != nil {
		t.Fatal(err)
	}
	claims, err := content.guards.Sweep(2, true, nil, now)
	if err != nil || len(claims) != 1 {
		t.Fatalf("Sweep() = %v, %v", claims, err)
	}
	var release sync.Once
	unpause := func() { release.Do(func() { close(paused.release) }) }
	defer unpause()
	deleted := make(chan error, 1)
	go func() { deleted <- content.Delete(ctx, claims[0]) }()
	<-paused.entered
	completed := make(chan error, 1)
	go func() { completed <- content.guards.CompleteDeletion(claims[0]) }()
	registered := make(chan error, 1)
	go func() { registered <- content.guards.Register(claims[0].Key, now.Add(time.Hour)) }()

	// Observe both callers queued behind the actual storage operation, rather
	// than relying on a sleep to assume their goroutines have run.
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for {
		content.guards.storageMu.Lock()
		gate := content.guards.storageGates[claims[0].Key]
		queued := gate != nil && gate.users == 3
		content.guards.storageMu.Unlock()
		if queued {
			break
		}
		select {
		case err := <-completed:
			t.Fatalf("CompleteDeletion bypassed active physical deletion: %v", err)
		case err := <-registered:
			t.Fatalf("Register bypassed active physical deletion: %v", err)
		case <-deadline.C:
			t.Fatal("metadata callers did not reach the storage fence")
		default:
			runtime.Gosched()
		}
	}
	snapshot := content.guards.Snapshot(claims[0].Key)
	if snapshot.State != Deleting || snapshot.Incarnation != 1 {
		t.Fatalf("metadata advanced during physical deletion: %+v", snapshot)
	}
	unpause()
	if err := <-deleted; err != nil {
		t.Fatal(err)
	}
	if err := <-registered; err != nil {
		t.Fatal(err)
	}
	// Register and CompleteDeletion can acquire in either order after Delete.
	if err := <-completed; err != nil && !errors.Is(err, ErrStaleDeletion) {
		t.Fatal(err)
	}
	if snapshot := content.guards.Snapshot(claims[0].Key); snapshot.Incarnation != 2 || snapshot.State != Live {
		t.Fatalf("metadata did not advance after physical deletion: %+v", snapshot)
	}
}

func TestDeduplicatedUploadCannotRegisterBytesDeletedAfterItsRead(t *testing.T) {
	t.Parallel()
	first, objects := newTestContentStore(t)
	paused := &pausedReadStore{Store: objects, entered: make(chan struct{}), release: make(chan struct{})}
	first.objects = paused
	second, err := NewContentStore(paused, first.guards)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tenant := blobTenant(t, "D")
	now := time.Unix(1_900_000_000, 0)
	data := []byte("deduplicated bytes")
	if _, err := first.Upload(ctx, tenant, data, now); err != nil {
		t.Fatal(err)
	}
	uploaded := make(chan error, 1)
	var finish sync.Once
	var uploadErr error
	finishUpload := func() error {
		finish.Do(func() {
			close(paused.release)
			uploadErr = <-uploaded
		})
		return uploadErr
	}
	defer finishUpload()
	go func() {
		_, err := first.Upload(ctx, tenant, data, now)
		uploaded <- err
	}()
	<-paused.entered
	if _, err := first.guards.Sweep(1, true, nil, now); err != nil {
		t.Fatal(err)
	}
	claims, err := first.guards.Sweep(2, true, nil, now)
	if err != nil || len(claims) != 1 {
		t.Fatalf("Sweep() = %v, %v", claims, err)
	}
	bounded, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if err := second.Delete(bounded, claims[0]); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Delete during deduplication = %v, want canceled wait", err)
	}
	if err := finishUpload(); !errors.Is(err, ErrObjectDeleting) {
		t.Fatalf("upload after GC claimed the object = %v, want object deleting", err)
	}
	if err := second.Delete(ctx, claims[0]); err != nil {
		t.Fatal(err)
	}
	reuploaded, err := second.Upload(ctx, tenant, data, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.Protect(ctx, tenant, reuploaded, "dedup-reupload"); err != nil {
		t.Fatalf("successfully reuploaded bytes cannot be protected: %v", err)
	}
}

func TestFailedPhysicalDeletionReleasesClaim(t *testing.T) {
	t.Parallel()
	// removed=true models a delete whose durability step fails after the
	// object is already gone, so the physical outcome is unknown.
	for _, removed := range []bool{false, true} {
		t.Run(fmt.Sprintf("removed=%t", removed), func(t *testing.T) {
			t.Parallel()
			content, objects := newTestContentStore(t)
			content.objects = &failingDeletionStore{Store: objects, remove: removed, failures: 1}
			ctx := context.Background()
			tenant := blobTenant(t, "F")
			now := time.Unix(1_900_000_000, 0)
			data := []byte("deletion fails")
			reference, err := content.Upload(ctx, tenant, data, now)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := content.guards.Sweep(1, true, nil, now); err != nil {
				t.Fatal(err)
			}
			claims, err := content.guards.Sweep(2, true, nil, now)
			if err != nil || len(claims) != 1 {
				t.Fatalf("Sweep() = %v, %v", claims, err)
			}
			if err := content.Delete(ctx, claims[0]); !errors.Is(err, errInjectedDeletion) {
				t.Fatalf("Delete() = %v, want injected failure", err)
			}
			if snapshot := content.guards.Snapshot(claims[0].Key); snapshot.State != Candidate || snapshot.Incarnation != 2 {
				t.Fatalf("guard after failed deletion = %+v, want released candidate with a new incarnation", snapshot)
			}
			if err := content.Delete(ctx, claims[0]); !errors.Is(err, ErrStaleDeletion) {
				t.Fatalf("Delete(released claim) = %v, want stale claim", err)
			}
			// Protection rechecks the bytes, so a deletion with an unknown
			// outcome is never reported as protected.
			permit, err := content.Protect(ctx, tenant, reference, "before-reupload")
			if removed {
				if !errors.Is(err, objectstore.ErrNotFound) {
					t.Fatalf("Protect(removed bytes) = %+v, %v, want not found", permit, err)
				}
			} else if err != nil || permit.ObjectIncarnation != 2 {
				t.Fatalf("Protect(kept bytes) = %+v, %v", permit, err)
			}
			reuploaded, err := content.Upload(ctx, tenant, data, now.Add(time.Hour))
			if err != nil {
				t.Fatalf("re-upload after failed deletion = %v", err)
			}
			if _, err := content.Protect(ctx, tenant, reuploaded, "after-reupload"); err != nil {
				t.Fatalf("Protect(re-uploaded) = %v", err)
			}
			if got, err := content.Read(ctx, tenant, reuploaded); err != nil || !bytes.Equal(got, data) {
				t.Fatalf("Read(re-uploaded) = %q, %v", got, err)
			}
		})
	}
}

func TestReleasedDeletionIsClaimedAgainBySweep(t *testing.T) {
	t.Parallel()
	content, objects := newTestContentStore(t)
	content.objects = &failingDeletionStore{Store: objects, failures: 1}
	ctx := context.Background()
	tenant := blobTenant(t, "S")
	now := time.Unix(1_900_000_000, 0)
	data := []byte("deleted on retry")
	reference, err := content.Upload(ctx, tenant, data, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := content.guards.Sweep(1, true, nil, now); err != nil {
		t.Fatal(err)
	}
	claims, err := content.guards.Sweep(2, true, nil, now)
	if err != nil || len(claims) != 1 {
		t.Fatalf("Sweep() = %v, %v", claims, err)
	}
	if err := content.Delete(ctx, claims[0]); !errors.Is(err, errInjectedDeletion) {
		t.Fatalf("Delete() = %v, want injected failure", err)
	}
	retry, err := content.guards.Sweep(3, true, nil, now)
	if err != nil || len(retry) != 1 || retry[0].GuardGeneration <= claims[0].GuardGeneration {
		t.Fatalf("Sweep(after failure) = %v, %v, want a newer claim than %v", retry, err, claims)
	}
	if err := content.Delete(ctx, retry[0]); err != nil {
		t.Fatalf("Delete(retry) = %v", err)
	}
	if _, err := content.Read(ctx, tenant, reference); !errors.Is(err, objectstore.ErrNotFound) {
		t.Fatalf("Read(after retried deletion) = %v, want not found", err)
	}
	if _, err := content.Upload(ctx, tenant, data, now.Add(time.Hour)); err != nil {
		t.Fatalf("Upload(after retried deletion) = %v", err)
	}
}

func TestProtectRacingFailedDeletionKeepsProtectedBytes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Unix(1_900_000_000, 0)
	data := []byte("racing protection")
	for iteration := range 100 {
		content, objects := newTestContentStore(t)
		content.objects = &failingDeletionStore{Store: objects, remove: iteration%2 == 1, failures: 1}
		tenant := blobTenant(t, "P")
		reference, err := content.Upload(ctx, tenant, data, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := content.guards.Sweep(1, true, nil, now); err != nil {
			t.Fatal(err)
		}
		claims, err := content.guards.Sweep(2, true, nil, now)
		if err != nil || len(claims) != 1 {
			t.Fatalf("iteration %d Sweep() = %v, %v", iteration, claims, err)
		}

		ready := make(chan struct{})
		var wait sync.WaitGroup
		var deleteErr, protectErr, uploadErr error
		var permit Permit
		wait.Add(3)
		go func() {
			defer wait.Done()
			<-ready
			deleteErr = content.Delete(ctx, claims[0])
		}()
		go func() {
			defer wait.Done()
			<-ready
			permit, protectErr = content.Protect(ctx, tenant, reference, "racing-permit")
		}()
		go func() {
			defer wait.Done()
			<-ready
			_, uploadErr = content.Upload(ctx, tenant, data, now.Add(time.Hour))
		}()
		close(ready)
		wait.Wait()

		if !errors.Is(deleteErr, errInjectedDeletion) {
			t.Fatalf("iteration %d Delete() = %v, want injected failure", iteration, deleteErr)
		}
		if uploadErr != nil && !errors.Is(uploadErr, ErrObjectDeleting) {
			t.Fatalf("iteration %d Upload() = %v", iteration, uploadErr)
		}
		if protectErr != nil {
			if !errors.Is(protectErr, ErrObjectDeleting) && !errors.Is(protectErr, objectstore.ErrNotFound) {
				t.Fatalf("iteration %d Protect() = %v", iteration, protectErr)
			}
		} else {
			// A granted permit must name the current incarnation and its bytes,
			// and the failed claim must not be able to remove them later.
			snapshot := content.guards.Snapshot(claims[0].Key)
			if snapshot.State != Live || snapshot.PendingPermits != 1 || snapshot.Incarnation != permit.ObjectIncarnation {
				t.Fatalf("iteration %d permit %+v with guard %+v", iteration, permit, snapshot)
			}
			if err := content.Delete(ctx, claims[0]); !errors.Is(err, ErrStaleDeletion) {
				t.Fatalf("iteration %d Delete(after protection) = %v, want stale claim", iteration, err)
			}
			if got, err := content.Read(ctx, tenant, reference); err != nil || !bytes.Equal(got, data) {
				t.Fatalf("iteration %d protected bytes = %q, %v", iteration, got, err)
			}
		}
		if _, err := content.Upload(ctx, tenant, data, now.Add(2*time.Hour)); err != nil {
			t.Fatalf("iteration %d Upload(after failed deletion) = %v", iteration, err)
		}
		if _, err := content.Protect(ctx, tenant, reference, "recovered-permit"); err != nil {
			t.Fatalf("iteration %d Protect(after re-upload) = %v", iteration, err)
		}
	}
}

var errInjectedDeletion = errors.New("injected deletion failure")

// failingDeletionStore fails the first failures conditional deletes. With
// remove set it removes the object before failing, like a delete whose
// durability step fails after the object is gone.
type failingDeletionStore struct {
	objectstore.Store
	remove   bool
	mu       sync.Mutex
	failures int
}

func (store *failingDeletionStore) DeleteIfMatch(ctx context.Context, bucket objectstore.Bucket, key string, expected objectstore.ETag) error {
	store.mu.Lock()
	fail := store.failures > 0
	if fail {
		store.failures--
	}
	store.mu.Unlock()
	if !fail {
		return store.Store.DeleteIfMatch(ctx, bucket, key, expected)
	}
	if store.remove {
		if err := store.Store.DeleteIfMatch(ctx, bucket, key, expected); err != nil {
			return err
		}
	}
	return errInjectedDeletion
}

type pausedReadStore struct {
	objectstore.Store
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (store *pausedReadStore) Get(ctx context.Context, bucket objectstore.Bucket, key string) (objectstore.Object, error) {
	object, err := store.Store.Get(ctx, bucket, key)
	if err != nil {
		return object, err
	}
	store.once.Do(func() {
		close(store.entered)
		select {
		case <-store.release:
		case <-ctx.Done():
			err = ctx.Err()
		}
	})
	return object, err
}

type pausedDeletionStore struct {
	objectstore.Store
	mu      sync.Mutex
	count   int
	entered chan struct{}
	release chan struct{}
}

func (store *pausedDeletionStore) DeleteIfMatch(ctx context.Context, bucket objectstore.Bucket, key string, expected objectstore.ETag) error {
	store.mu.Lock()
	store.count++
	first := store.count == 1
	store.mu.Unlock()
	if first {
		close(store.entered)
		select {
		case <-store.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return store.Store.DeleteIfMatch(ctx, bucket, key, expected)
}
