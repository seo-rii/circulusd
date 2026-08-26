package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestPATServiceUsesCurrentRecordAndAtomicAuditOutbox(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 26, 11, 0, 0, 0, time.UTC)
	store := newTestPATStore()
	service, err := NewPATService(PATServiceConfig{
		Store:             store,
		Entropy:           bytes.NewReader(bytes.Repeat([]byte{0x42}, TokenEntropyBytes)),
		Now:               func() time.Time { return now },
		MaximumCASRetries: 16,
	})
	if err != nil {
		t.Fatalf("NewPATService() error = %v", err)
	}
	plaintext, issued, err := service.Issue(
		context.Background(),
		"tenant-a",
		"user-a",
		[]string{"session:write"},
		time.Hour,
	)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	issuedAt := now
	now = issuedAt.Add(10 * time.Minute)
	principal, err := service.Authenticate(
		context.Background(),
		plaintext,
		"session:write",
	)
	if err != nil || principal.TenantID != "tenant-a" || principal.UserID != "user-a" {
		t.Fatalf("Authenticate() = (%+v, %v)", principal, err)
	}
	used, err := store.LoadPATByID(context.Background(), issued.ID)
	if err != nil {
		t.Fatalf("LoadPATByID() error = %v", err)
	}
	if used.UseCount != 1 || used.Version != 2 || !used.LastUsedAt.Equal(now) {
		t.Fatalf("used PAT = %+v", used)
	}
	now = issuedAt.Add(5 * time.Minute)
	if _, err := service.Authenticate(context.Background(), plaintext, "session:write"); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("Authenticate(clock regression) error = %v, want ErrInvalidCredential", err)
	}
	afterRegression, err := store.LoadPATByID(context.Background(), issued.ID)
	if err != nil || afterRegression.Version != used.Version || afterRegression.UseCount != used.UseCount {
		t.Fatalf("PAT after clock regression = (%+v, %v)", afterRegression, err)
	}
	now = issuedAt.Add(5 * time.Minute)
	revoked, err := service.Revoke(context.Background(), used.ID, used.Version)
	if err != nil || revoked.Version != 3 || revoked.RevokedAt == nil {
		t.Fatalf("Revoke() = (%+v, %v)", revoked, err)
	}
	if !revoked.RevokedAt.Equal(used.LastUsedAt) {
		t.Errorf("RevokedAt = %s, want high-water %s", revoked.RevokedAt, used.LastUsedAt)
	}
	if _, err := service.Authenticate(context.Background(), plaintext, "session:write"); !errors.Is(err, ErrCredentialRevoked) {
		t.Fatalf("Authenticate(after revoke) error = %v", err)
	}
	replayed, err := service.Revoke(context.Background(), used.ID, used.Version)
	if err != nil || replayed.Version != revoked.Version || replayed.RevokedAt == nil {
		t.Fatalf("Revoke(lost-response replay) = (%+v, %v)", replayed, err)
	}
	if got := store.auditKinds(); fmt.Sprint(got) != "[issued used revoked]" {
		t.Fatalf("audit kinds = %v", got)
	}
	store.mu.Lock()
	audits := append([]PATAuditEvent(nil), store.audits...)
	store.mu.Unlock()
	if got := audits[len(audits)-1].At; !got.Equal(used.LastUsedAt) {
		t.Fatalf("revocation audit time = %s, want high-water %s", got, used.LastUsedAt)
	}
}

func TestPATServiceCASPreventsConcurrentUseLoss(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 26, 11, 0, 0, 0, time.UTC)
	plaintext, record, err := issuePAT(
		bytes.NewReader(bytes.Repeat([]byte{0x24}, TokenEntropyBytes)),
		"tenant-a",
		"user-a",
		[]string{"workspace:read"},
		now,
		now.Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("issuePAT() error = %v", err)
	}
	store := newTestPATStore(record)
	service, err := NewPATService(PATServiceConfig{
		Store:             store,
		Entropy:           bytes.NewReader(make([]byte, TokenEntropyBytes)),
		Now:               func() time.Time { return now },
		MaximumCASRetries: 64,
	})
	if err != nil {
		t.Fatalf("NewPATService() error = %v", err)
	}

	const uses = 16
	var wait sync.WaitGroup
	failures := make(chan error, uses)
	for range uses {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := service.Authenticate(context.Background(), plaintext, "workspace:read")
			failures <- err
		}()
	}
	wait.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatalf("Authenticate() error = %v", err)
		}
	}
	current, err := store.LoadPATByID(context.Background(), record.ID)
	if err != nil {
		t.Fatalf("LoadPATByID() error = %v", err)
	}
	if current.UseCount != uses || current.Version != record.Version+uses {
		t.Fatalf("current PAT = %+v", current)
	}
}

func TestPATServiceRevokeBindsLoadedRecordToRequestedID(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 26, 13, 0, 0, 0, time.UTC)
	_, record, err := issuePAT(
		bytes.NewReader(bytes.Repeat([]byte{0x63}, TokenEntropyBytes)),
		"tenant-a",
		"user-a",
		[]string{"session:write"},
		now,
		now.Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("issuePAT() error = %v", err)
	}
	store := newTestPATStore(record)
	const requestedID = "patid_requested"
	store.mu.Lock()
	store.byID[requestedID] = clonePATRecord(record)
	store.mu.Unlock()
	service, err := NewPATService(PATServiceConfig{
		Store:             store,
		Now:               func() time.Time { return now.Add(time.Minute) },
		MaximumCASRetries: 1,
	})
	if err != nil {
		t.Fatalf("NewPATService() error = %v", err)
	}

	if _, err := service.Revoke(context.Background(), requestedID, record.Version); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("Revoke(mismatched loaded ID) error = %v, want ErrInvalidCredential", err)
	}
	current, err := store.LoadPATByID(context.Background(), record.ID)
	if err != nil || current.Version != record.Version {
		t.Fatalf("stored PAT after rejected revoke = (%+v, %v)", current, err)
	}
	if got := store.auditKinds(); len(got) != 0 {
		t.Fatalf("audit kinds after rejected revoke = %v", got)
	}
}

type testPATStore struct {
	mu       sync.Mutex
	byID     map[string]PATRecord
	byDigest map[string]string
	audits   []PATAuditEvent
}

func newTestPATStore(records ...PATRecord) *testPATStore {
	store := &testPATStore{byID: map[string]PATRecord{}, byDigest: map[string]string{}}
	for _, record := range records {
		store.byID[record.ID] = clonePATRecord(record)
		store.byDigest[record.Digest] = record.ID
	}
	return store
}

func (store *testPATStore) CreatePAT(_ context.Context, record PATRecord, event PATAuditEvent) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, found := store.byID[record.ID]; found {
		return ErrPATConflict
	}
	if _, found := store.byDigest[record.Digest]; found {
		return ErrPATConflict
	}
	store.byID[record.ID] = clonePATRecord(record)
	store.byDigest[record.Digest] = record.ID
	store.audits = append(store.audits, event)
	return nil
}

func (store *testPATStore) LoadPATByDigest(_ context.Context, digest string) (PATRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	id, found := store.byDigest[digest]
	if !found {
		return PATRecord{}, ErrPATNotFound
	}
	return clonePATRecord(store.byID[id]), nil
}

func (store *testPATStore) LoadPATByID(_ context.Context, id string) (PATRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, found := store.byID[id]
	if !found {
		return PATRecord{}, ErrPATNotFound
	}
	return clonePATRecord(record), nil
}

func (store *testPATStore) CommitPAT(
	_ context.Context,
	id string,
	expectedVersion uint64,
	next PATRecord,
	event PATAuditEvent,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	current, found := store.byID[id]
	if !found {
		return ErrPATNotFound
	}
	if current.Version != expectedVersion {
		return ErrPATVersionConflict
	}
	store.byID[id] = clonePATRecord(next)
	store.audits = append(store.audits, event)
	return nil
}

func (store *testPATStore) auditKinds() []PATAuditKind {
	store.mu.Lock()
	defer store.mu.Unlock()
	result := make([]PATAuditKind, len(store.audits))
	for index, event := range store.audits {
		result[index] = event.Kind
	}
	return result
}
