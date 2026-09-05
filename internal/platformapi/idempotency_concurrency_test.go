package platformapi_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/hancomac/circulusd/internal/platformapi"
)

// TestConcurrentDistinctAndDuplicateKeysCreateExactlyOneTurnPerKey is the
// §53.16 idempotency concurrency invariant at its strongest shape: many
// distinct Idempotency-Keys and many duplicates of each race the create-turn
// path at once. Exactly one durable turn exists per key, every duplicate of a
// key converges on that key's single turn ID, distinct keys never collide on a
// turn ID, and the number of creators equals the number of distinct keys.
func TestConcurrentDistinctAndDuplicateKeysCreateExactlyOneTurnPerKey(t *testing.T) {
	ctx := context.Background()
	store := platformapi.NewMemoryStore()
	registerAPISession(t, store)
	service := newAPIService(t, store, &scopedAuthorizer{})

	const (
		keys             = 16
		duplicatesPerKey = 8
		workers          = keys * duplicatesPerKey
	)
	type outcome struct {
		key     int
		turnID  string
		created bool
		err     error
	}
	start := make(chan struct{})
	results := make(chan outcome, workers)
	var launched sync.WaitGroup
	for key := range keys {
		for range duplicatesPerKey {
			launched.Add(1)
			go func(key int) {
				defer launched.Done()
				// Every duplicate of a key sends an identical body so the key
				// deduplicates rather than conflicts; distinct keys carry
				// distinct bodies.
				request := platformapi.CreateTurnRequest{
					Principal:      platformapi.Principal{TenantID: apiTenantID, SubjectID: apiSubjectID},
					SessionID:      apiSessionID,
					IdempotencyKey: fmt.Sprintf("client-key-%d", key),
					Messages: []platformapi.Message{{
						Role: "user", Content: fmt.Sprintf("request for key %d", key),
					}},
				}
				<-start
				value, err := service.CreateTurn(ctx, request)
				results <- outcome{
					key: key, turnID: value.Turn.ID, created: !value.Deduplicated, err: err,
				}
			}(key)
		}
	}
	close(start)
	go func() {
		launched.Wait()
		close(results)
	}()

	turnIDByKey := make(map[int]string)
	createdByKey := make(map[int]int)
	turnIDOwner := make(map[string]int)
	for result := range results {
		if result.err != nil {
			t.Fatalf("CreateTurn(key %d) error = %v", result.key, result.err)
		}
		if existing, seen := turnIDByKey[result.key]; seen && existing != result.turnID {
			t.Fatalf("key %d observed divergent turn IDs %q and %q", result.key, existing, result.turnID)
		}
		turnIDByKey[result.key] = result.turnID
		if owner, taken := turnIDOwner[result.turnID]; taken && owner != result.key {
			t.Fatalf("turn ID %q shared across keys %d and %d", result.turnID, owner, result.key)
		}
		turnIDOwner[result.turnID] = result.key
		if result.created {
			createdByKey[result.key]++
		}
	}

	if len(turnIDByKey) != keys {
		t.Fatalf("distinct keys with a turn = %d, want %d", len(turnIDByKey), keys)
	}
	for key, created := range createdByKey {
		if created != 1 {
			t.Fatalf("key %d had %d creators, want exactly 1", key, created)
		}
	}
	if len(createdByKey) != keys {
		t.Fatalf("keys with a creator = %d, want %d", len(createdByKey), keys)
	}
	if count := store.TurnCount(apiTenantID, apiSessionID); count != keys {
		t.Fatalf("TurnCount() = %d, want %d durable turns", count, keys)
	}
}

// TestConcurrentSameKeyDifferentBodyYieldsSingleTurnAndConflicts proves the
// §53.16 conflict half under concurrency: when two distinct request bodies race
// under one Idempotency-Key, exactly one body wins the single durable turn and
// every caller sending the losing body is rejected with ErrIdempotencyConflict.
// The winner is racy, so the assertion is over invariants, not which body wins.
func TestConcurrentSameKeyDifferentBodyYieldsSingleTurnAndConflicts(t *testing.T) {
	ctx := context.Background()
	store := platformapi.NewMemoryStore()
	registerAPISession(t, store)
	service := newAPIService(t, store, &scopedAuthorizer{})

	const workersPerBody = 32
	bodies := [2]string{"body alpha", "body beta"}
	newRequest := func(body string) platformapi.CreateTurnRequest {
		return platformapi.CreateTurnRequest{
			Principal: platformapi.Principal{TenantID: apiTenantID, SubjectID: apiSubjectID},
			SessionID: apiSessionID, IdempotencyKey: "contended-key",
			Messages: []platformapi.Message{{Role: "user", Content: body}},
		}
	}

	type outcome struct {
		body   int
		result platformapi.CreateTurnResult
		err    error
	}
	start := make(chan struct{})
	results := make(chan outcome, len(bodies)*workersPerBody)
	var launched sync.WaitGroup
	for body := range bodies {
		for range workersPerBody {
			launched.Add(1)
			go func(body int) {
				defer launched.Done()
				request := newRequest(bodies[body])
				<-start
				result, err := service.CreateTurn(ctx, request)
				results <- outcome{body: body, result: result, err: err}
			}(body)
		}
	}
	close(start)
	go func() {
		launched.Wait()
		close(results)
	}()

	created := 0
	conflicts := 0
	winners := make(map[string]struct{})
	winningTurnID := ""
	for result := range results {
		switch {
		case result.err == nil:
			winners[result.result.Turn.ID] = struct{}{}
			winningTurnID = result.result.Turn.ID
			if !result.result.Deduplicated {
				created++
			}
		case errors.Is(result.err, platformapi.ErrIdempotencyConflict):
			conflicts++
		default:
			t.Fatalf("CreateTurn(body %d) error = %v", result.body, result.err)
		}
	}

	if created != 1 {
		t.Fatalf("creators = %d, want exactly 1", created)
	}
	if len(winners) != 1 {
		t.Fatalf("distinct winning turn IDs = %d, want 1", len(winners))
	}
	if conflicts != workersPerBody {
		t.Fatalf("conflicts = %d, want %d (every caller of the losing body)", conflicts, workersPerBody)
	}
	if count := store.TurnCount(apiTenantID, apiSessionID); count != 1 {
		t.Fatalf("TurnCount() = %d, want 1", count)
	}
	if _, ok := winners[winningTurnID]; !ok {
		t.Fatalf("winning turn ID %q not recorded", winningTurnID)
	}
}
