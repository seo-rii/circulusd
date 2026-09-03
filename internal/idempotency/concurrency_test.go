package idempotency

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// TestCreationRegistrySingleReservationUnderConcurrency proves the security
// invariant that guards against duplicate resource creation: when many callers
// race to Reserve the same (scope, key) with DISTINCT proposed resource IDs,
// exactly one reservation is created and every caller observes that one
// committed resource ID. Run under -race it also proves the map access is
// correctly synchronized.
func TestCreationRegistrySingleReservationUnderConcurrency(t *testing.T) {
	t.Parallel()
	registry := NewCreationRegistry()
	scope := Scope{
		TenantID:      "tenant-1",
		SubjectID:     "subject-1",
		Method:        "POST",
		RouteTemplate: "/v1/things",
		TargetID:      "target-1",
	}
	keyDigest, err := DigestKey(bytes.Repeat([]byte{0x2c}, 32), "the-idempotency-key")
	if err != nil {
		t.Fatalf("DigestKey() error = %v", err)
	}
	requestDigest := "sha256:" + strings.Repeat("ab", 32)

	const workers = 64
	var (
		waitGroup sync.WaitGroup
		creators  atomic.Int64
		start     = make(chan struct{})
		records   = make([]CreationRecord, workers)
		errs      = make([]error, workers)
	)
	for worker := 0; worker < workers; worker++ {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			<-start
			record, existed, err := registry.Reserve(
				scope, keyDigest, requestDigest, fmt.Sprintf("resource-%d", index),
			)
			records[index], errs[index] = record, err
			if err == nil && !existed {
				creators.Add(1)
			}
		}(worker)
	}
	close(start)
	waitGroup.Wait()

	if got := creators.Load(); got != 1 {
		t.Fatalf("expected exactly one reservation to win, got %d", got)
	}
	committed := ""
	for index := 0; index < workers; index++ {
		if errs[index] != nil {
			t.Fatalf("worker %d Reserve() error = %v", index, errs[index])
		}
		if committed == "" {
			committed = records[index].ResourceID
		}
		if records[index].ResourceID != committed {
			t.Fatalf("workers observed divergent resource IDs: %q vs %q", records[index].ResourceID, committed)
		}
		if records[index].Phase != Reserved {
			t.Fatalf("worker %d observed phase %q, want %q", index, records[index].Phase, Reserved)
		}
	}
	looked, found, err := registry.Lookup(scope, keyDigest)
	if err != nil || !found {
		t.Fatalf("Lookup() = (%+v, %v, %v), want the committed record", looked, found, err)
	}
	if looked.ResourceID != committed {
		t.Fatalf("Lookup resource ID %q != committed %q", looked.ResourceID, committed)
	}
}
