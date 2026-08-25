package idempotency

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

const requestDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestDigestKeyUsesServerSecretAndNeverReturnsRawKey(t *testing.T) {
	t.Parallel()

	raw := "client-visible-key"
	first, err := DigestKey([]byte(strings.Repeat("a", 32)), raw)
	if err != nil {
		t.Fatalf("DigestKey() error = %v", err)
	}
	second, err := DigestKey([]byte(strings.Repeat("b", 32)), raw)
	if err != nil {
		t.Fatalf("DigestKey(second secret) error = %v", err)
	}
	if first == second {
		t.Fatal("DigestKey() did not bind the server secret")
	}
	if strings.Contains(first, raw) || !strings.HasPrefix(first, "hmac-sha256:") {
		t.Fatalf("DigestKey() = %q, want opaque HMAC digest", first)
	}
	if _, err := DigestKey([]byte("short"), raw); err == nil {
		t.Fatal("DigestKey(short secret) error = nil")
	}
	if _, err := DigestKey([]byte(strings.Repeat("a", 32)), ""); err == nil {
		t.Fatal("DigestKey(empty key) error = nil")
	}
}

func TestConcurrentReservationConvergesOnOneResource(t *testing.T) {
	t.Parallel()

	registry := NewCreationRegistry()
	scope := validScope()
	keyDigest := validKeyDigest("1")

	const workers = 128
	type outcome struct {
		record       CreationRecord
		deduplicated bool
		err          error
	}
	outcomes := make(chan outcome, workers)
	var wait sync.WaitGroup
	for index := range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			record, deduplicated, err := registry.Reserve(
				scope,
				keyDigest,
				requestDigest,
				fmt.Sprintf("sess_candidate_%03d", index),
			)
			outcomes <- outcome{record: record, deduplicated: deduplicated, err: err}
		}()
	}
	wait.Wait()
	close(outcomes)

	resourceIDs := map[string]struct{}{}
	deduplicated := 0
	for outcome := range outcomes {
		if outcome.err != nil {
			t.Fatalf("Reserve() error = %v", outcome.err)
		}
		resourceIDs[outcome.record.ResourceID] = struct{}{}
		if outcome.deduplicated {
			deduplicated++
		}
	}
	if len(resourceIDs) != 1 || deduplicated != workers-1 {
		t.Fatalf("resources=%v deduplicated=%d, want one resource and %d replays", resourceIDs, deduplicated, workers-1)
	}
}

func TestSameKeyDifferentRequestFailsWithoutOverwriting(t *testing.T) {
	t.Parallel()

	registry := NewCreationRegistry()
	scope := validScope()
	keyDigest := validKeyDigest("2")
	first, _, err := registry.Reserve(scope, keyDigest, requestDigest, "sess_first")
	if err != nil {
		t.Fatalf("Reserve(first) error = %v", err)
	}
	different := "sha256:" + strings.Repeat("b", 64)
	if _, _, err := registry.Reserve(scope, keyDigest, different, "sess_second"); !errors.Is(err, ErrKeyReused) {
		t.Fatalf("Reserve(conflict) error = %v, want ErrKeyReused", err)
	}
	stored, found, err := registry.Lookup(scope, keyDigest)
	if err != nil || !found {
		t.Fatalf("Lookup() = %#v, %t, %v", stored, found, err)
	}
	if stored != first {
		t.Fatalf("stored record = %#v, want %#v", stored, first)
	}
}

func TestScopeSeparatesAuthenticatedOperations(t *testing.T) {
	t.Parallel()

	registry := NewCreationRegistry()
	keyDigest := validKeyDigest("3")
	base := validScope()
	scopes := []Scope{
		base,
		{TenantID: "tenant-b", SubjectID: base.SubjectID, Method: base.Method, RouteTemplate: base.RouteTemplate},
		{TenantID: base.TenantID, SubjectID: "subject-b", Method: base.Method, RouteTemplate: base.RouteTemplate},
		{TenantID: base.TenantID, SubjectID: base.SubjectID, Method: "PUT", RouteTemplate: base.RouteTemplate},
		{TenantID: base.TenantID, SubjectID: base.SubjectID, Method: base.Method, RouteTemplate: "/v1/workspaces"},
		{TenantID: base.TenantID, SubjectID: base.SubjectID, Method: base.Method, RouteTemplate: base.RouteTemplate, TargetID: "target-a"},
	}
	for index, scope := range scopes {
		record, deduplicated, err := registry.Reserve(scope, keyDigest, requestDigest, fmt.Sprintf("resource_%d", index))
		if err != nil || deduplicated {
			t.Fatalf("Reserve(scope %d) = %#v, %t, %v", index, record, deduplicated, err)
		}
	}
}

func TestCreationSagaTransitionsAreIdempotentAndFenced(t *testing.T) {
	t.Parallel()

	registry := NewCreationRegistry()
	scope := validScope()
	keyDigest := validKeyDigest("4")
	reserved, _, err := registry.Reserve(scope, keyDigest, requestDigest, "sess_stable")
	if err != nil {
		t.Fatalf("Reserve() error = %v", err)
	}
	if reserved.Phase != Reserved {
		t.Fatalf("Reserve().Phase = %q, want %q", reserved.Phase, Reserved)
	}

	initialized, err := registry.MarkTargetInitialized(
		scope,
		keyDigest,
		requestDigest,
		"sess_stable",
		"op_target_result",
	)
	if err != nil {
		t.Fatalf("MarkTargetInitialized() error = %v", err)
	}
	replayed, err := registry.MarkTargetInitialized(
		scope,
		keyDigest,
		requestDigest,
		"sess_stable",
		"op_target_result",
	)
	if err != nil || replayed != initialized {
		t.Fatalf("MarkTargetInitialized(replay) = %#v, %v, want %#v", replayed, err, initialized)
	}
	if _, err := registry.MarkTargetInitialized(
		scope,
		keyDigest,
		requestDigest,
		"sess_other",
		"op_target_result",
	); !errors.Is(err, ErrSagaConflict) {
		t.Fatalf("MarkTargetInitialized(stale resource) error = %v, want ErrSagaConflict", err)
	}

	finalized, err := registry.Finalize(scope, keyDigest, requestDigest, "sess_stable")
	if err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}
	if finalized.Phase != Finalized || finalized.ResultRef != "op_target_result" {
		t.Fatalf("Finalize() = %#v", finalized)
	}
	replayedFinal, err := registry.Finalize(scope, keyDigest, requestDigest, "sess_stable")
	if err != nil || replayedFinal != finalized {
		t.Fatalf("Finalize(replay) = %#v, %v, want %#v", replayedFinal, err, finalized)
	}
}

func TestFinalizeRequiresCompletedTargetInitialization(t *testing.T) {
	t.Parallel()

	registry := NewCreationRegistry()
	scope := validScope()
	keyDigest := validKeyDigest("5")
	if _, _, err := registry.Reserve(scope, keyDigest, requestDigest, "sess_pending"); err != nil {
		t.Fatalf("Reserve() error = %v", err)
	}
	if _, err := registry.Finalize(scope, keyDigest, requestDigest, "sess_pending"); !errors.Is(err, ErrInvalidSagaPhase) {
		t.Fatalf("Finalize(reserved) error = %v, want ErrInvalidSagaPhase", err)
	}
}

func validScope() Scope {
	return Scope{
		TenantID:      "tenant-a",
		SubjectID:     "subject-a",
		Method:        "POST",
		RouteTemplate: "/v1/sessions",
	}
}

func validKeyDigest(nibble string) string {
	return "hmac-sha256:" + strings.Repeat(nibble, 64)
}
