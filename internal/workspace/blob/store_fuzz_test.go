package blob

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/objectstore"
)

// FuzzContentStoreIncarnationOrders varies real storage/GC/protection operation
// orders around a paused physical delete. The first seed is the original ABA:
// duplicate delete, reupload identical bytes, protect, finish the old delete.
// Every pending permit must continue to reference readable, unchanged bytes.
func FuzzContentStoreIncarnationOrders(f *testing.F) {
	f.Add([]byte{0, 1, 2, 5, 0}, []byte("same bytes, new incarnation"))
	f.Add([]byte{5, 1, 2, 3, 0}, []byte("protected"))
	f.Add([]byte{5, 1, 2, 6, 3, 3, 9, 1, 2, 0}, []byte{})
	f.Add([]byte{4, 3, 5, 1, 2, 7, 3, 3, 9}, []byte("abandoned"))
	f.Fuzz(func(t *testing.T, program, data []byte) {
		if len(program) > 24 || len(data) > 128 {
			t.Skip()
		}
		ctx := context.Background()
		first, objects := newTestContentStore(t)
		paused := &pausedDeletionStore{Store: objects, entered: make(chan struct{}), release: make(chan struct{})}
		first.objects = paused
		second, err := NewContentStore(paused, first.guards)
		if err != nil {
			t.Fatal(err)
		}
		tenant := blobTenant(t, "Z")
		now := time.Unix(1_900_000_000, 0)
		reference, err := first.Upload(ctx, tenant, data, now)
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
		deleted := make(chan error, 1)
		go func() { deleted <- first.Delete(ctx, claims[0]) }()
		<-paused.entered
		var finish sync.Once
		finished := false
		finishDeletion := func() {
			finish.Do(func() {
				close(paused.release)
				if err := <-deleted; err != nil {
					t.Errorf("initial fenced delete failed: %v; operations %v", err, program)
				}
				finished = true
			})
		}
		defer finishDeletion()
		pending := make(map[string]Permit)
		var permits []Permit
		epoch := uint64(2)
		assertProtected := func() {
			if len(pending) == 0 {
				return
			}
			got, err := second.Read(ctx, tenant, reference)
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("%d pending permits lost their blob: got %q, %v; operations %v", len(pending), got, err, program)
			}
			snapshot := first.guards.Snapshot(claims[0].Key)
			for _, permit := range pending {
				if permit.ObjectIncarnation != snapshot.Incarnation || snapshot.State != Live {
					t.Fatalf("pending permit %+v invalidated by %+v; operations %v", permit, snapshot, program)
				}
			}
		}
		for index, instruction := range program {
			// Only operations issued while the old delete is paused need a
			// deadline. This bounds the queue without depending on scheduler
			// ordering, and also exercises retirement of canceled waiters.
			operationCtx := ctx
			cancel := func() {}
			if !finished {
				operationCtx, cancel = context.WithTimeout(ctx, time.Millisecond)
			}
			var operationErr error
			switch instruction % 9 {
			case 0:
				operationErr = second.Delete(operationCtx, claims[int(instruction)/9%len(claims)])
			case 1:
				_, operationErr = second.Upload(operationCtx, tenant, data, now.Add(time.Duration(index+1)*time.Hour))
			case 2:
				permit, err := second.Protect(operationCtx, tenant, reference, fmt.Sprintf("permit-%d", index))
				operationErr = err
				if err == nil {
					pending[permit.ID] = permit
					permits = append(permits, permit)
				}
			case 3:
				epoch++
				next, err := first.guards.Sweep(epoch, true, nil, now.Add(time.Duration(index+1)*time.Hour))
				if err != nil {
					t.Fatal(err)
				}
				claims = append(claims, next...)
			case 4:
				_, operationErr = second.Upload(operationCtx, tenant, append(append([]byte(nil), data...), 0xff), now)
			case 5:
				finishDeletion()
			case 6, 7:
				if len(permits) > 0 {
					permit := permits[int(instruction)/9%len(permits)]
					var err error
					if instruction%9 == 6 {
						err = first.guards.Finalize(permit.ID)
					} else {
						err = first.guards.Abandon(permit.ID)
					}
					if err == nil {
						delete(pending, permit.ID)
					}
					operationErr = err
				}
			case 8:
				_, operationErr = second.Read(operationCtx, tenant, reference)
			}
			cancel()
			if operationErr != nil &&
				!errors.Is(operationErr, context.DeadlineExceeded) &&
				!errors.Is(operationErr, objectstore.ErrNotFound) &&
				!errors.Is(operationErr, ErrObjectDeleting) &&
				!errors.Is(operationErr, ErrStaleDeletion) &&
				!errors.Is(operationErr, ErrStalePermit) {
				t.Fatalf("operation %d at %d: %v; operations %v", instruction%9, index, operationErr, program)
			}
			assertProtected()
		}
		finishDeletion()
		assertProtected()
		first.guards.storageMu.Lock()
		defer first.guards.storageMu.Unlock()
		if len(first.guards.storageGates) != 0 {
			t.Fatalf("idle storage gates retained after operations %v", program)
		}
	})
}
