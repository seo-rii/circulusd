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

func TestAuthenticatorCASPreventsConcurrentFailureLoss(t *testing.T) {
	t.Parallel()

	params := Argon2idParams{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1, SaltBytes: 16, KeyBytes: 32}
	hash, err := HashPassword("right-password", params, bytes.NewReader(bytes.Repeat([]byte{0x44}, 16)))
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	store := newTestAccountStore(Account{
		TenantID:     "tenant-a",
		UserID:       "user-a",
		Username:     "alice",
		PasswordHash: hash,
	})
	now := time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC)
	authenticator, err := NewAuthenticator(AuthenticatorConfig{
		Store:                 store,
		PasswordParameters:    params,
		DummyPasswordHash:     hash,
		LoginPolicy:           LoginPolicy{MaximumFailures: 100, LockoutDuration: time.Minute},
		Now:                   func() time.Time { return now },
		MaximumCASRetries:     64,
		MaximumParallelHashes: 2,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}

	const attempts = 16
	var wait sync.WaitGroup
	errorsFound := make(chan error, attempts)
	for range attempts {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := authenticator.Authenticate(context.Background(), "alice", "wrong-password")
			if err == nil && result.Status != LoginInvalidCredentials {
				err = errors.New("wrong password did not return invalid_credentials")
			}
			errorsFound <- err
		}()
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatalf("Authenticate() error = %v", err)
		}
	}

	account, err := store.LoadAccount(context.Background(), "alice")
	if err != nil {
		t.Fatalf("LoadAccount() error = %v", err)
	}
	if account.FailedAttempts != attempts || account.Version != attempts {
		t.Fatalf("account after concurrent failures = %+v", account)
	}
	if got := store.auditCount(); got != attempts {
		t.Fatalf("audit count = %d, want %d", got, attempts)
	}
}

func TestAuthenticatorUsesGenericFailureAndAuditsSuccess(t *testing.T) {
	t.Parallel()

	params := Argon2idParams{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1, SaltBytes: 16, KeyBytes: 32}
	hash, err := HashPassword("right-password", params, bytes.NewReader(bytes.Repeat([]byte{0x55}, 16)))
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	store := newTestAccountStore(Account{
		TenantID:     "tenant-a",
		UserID:       "user-a",
		Username:     "alice",
		PasswordHash: hash,
	})
	authenticator, err := NewAuthenticator(AuthenticatorConfig{
		Store:                 store,
		PasswordParameters:    params,
		DummyPasswordHash:     hash,
		LoginPolicy:           LoginPolicy{MaximumFailures: 3, LockoutDuration: time.Minute},
		Now:                   func() time.Time { return time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC) },
		MaximumCASRetries:     8,
		MaximumParallelHashes: 1,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}

	missing, err := authenticator.Authenticate(context.Background(), "nobody", "right-password")
	if err != nil || missing.Status != LoginInvalidCredentials || missing.UserID != "" {
		t.Fatalf("missing account result = (%+v, %v)", missing, err)
	}
	success, err := authenticator.Authenticate(context.Background(), "alice", "right-password")
	if err != nil {
		t.Fatalf("Authenticate(success) error = %v", err)
	}
	if success.Status != LoginAuthenticated || success.UserID != "user-a" || success.TenantID != "tenant-a" {
		t.Fatalf("Authenticate(success) = %+v", success)
	}
	wrong, err := authenticator.Authenticate(context.Background(), "alice", "wrong-password")
	if err != nil || wrong.Status != LoginInvalidCredentials || wrong.UserID != "" || wrong.TenantID != "" {
		t.Fatalf("Authenticate(wrong) leaked account identity: (%+v, %v)", wrong, err)
	}
	events := store.auditEventsSnapshot()
	if len(events) != 3 || events[0].Status != LoginInvalidCredentials || events[1].Status != LoginAuthenticated || events[2].Status != LoginInvalidCredentials {
		t.Fatalf("audit events = %+v", events)
	}
	if events[0].Username != "nobody" || events[0].UserID != "" || events[1].UserID != "user-a" {
		t.Fatalf("audit identity fields = %+v", events)
	}
}

func TestAuthenticatorDoesNotCommitAccountWithoutDurableAudit(t *testing.T) {
	t.Parallel()

	params := Argon2idParams{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1, SaltBytes: 16, KeyBytes: 32}
	hash, err := HashPassword("right-password", params, bytes.NewReader(bytes.Repeat([]byte{0x66}, 16)))
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	store := newTestAccountStore(Account{
		TenantID:     "tenant-a",
		UserID:       "user-a",
		Username:     "alice",
		PasswordHash: hash,
	})
	store.auditErr = errors.New("audit unavailable")
	authenticator, err := NewAuthenticator(AuthenticatorConfig{
		Store:                 store,
		PasswordParameters:    params,
		DummyPasswordHash:     hash,
		LoginPolicy:           LoginPolicy{MaximumFailures: 3, LockoutDuration: time.Minute},
		Now:                   func() time.Time { return time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC) },
		MaximumCASRetries:     8,
		MaximumParallelHashes: 1,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}

	if _, err := authenticator.Authenticate(context.Background(), "alice", "wrong-password"); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("Authenticate() error = %v, want ErrAuditUnavailable", err)
	}
	account, err := store.LoadAccount(context.Background(), "alice")
	if err != nil {
		t.Fatalf("LoadAccount() error = %v", err)
	}
	if account.Version != 0 || account.FailedAttempts != 0 {
		t.Fatalf("account committed without audit = %+v", account)
	}
}

func TestAuthenticatorRejectsTimingAndMemoryUnsafeConfiguration(t *testing.T) {
	t.Parallel()

	params := Argon2idParams{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1, SaltBytes: 16, KeyBytes: 32}
	dummy, err := HashPassword("dummy-password", params, bytes.NewReader(bytes.Repeat([]byte{0x77}, 16)))
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	base := AuthenticatorConfig{
		Store:                 newTestAccountStore(),
		PasswordParameters:    params,
		DummyPasswordHash:     dummy,
		LoginPolicy:           LoginPolicy{MaximumFailures: 3, LockoutDuration: time.Minute},
		Now:                   time.Now,
		MaximumCASRetries:     8,
		MaximumParallelHashes: 1,
	}
	mismatched := base
	mismatched.PasswordParameters.Iterations = 2
	if _, err := NewAuthenticator(mismatched); err == nil {
		t.Fatal("NewAuthenticator(mismatched dummy cost) error = nil")
	}

	overBudget := base
	overBudget.PasswordParameters.MemoryKiB = maximumMemoryKiB
	overBudget.DummyPasswordHash = "$argon2id$v=19$m=262144,t=1,p=1$WlpaWlpaWlpaWlpaWlpaWg$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	overBudget.MaximumParallelHashes = 3
	if _, err := NewAuthenticator(overBudget); err == nil {
		t.Fatal("NewAuthenticator(over aggregate memory budget) error = nil")
	}
}

func TestAuthenticatorRejectsStoredHashOutsideActiveCostPolicy(t *testing.T) {
	t.Parallel()

	active := Argon2idParams{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1, SaltBytes: 16, KeyBytes: 32}
	legacy := active
	legacy.Iterations = 2
	dummy, err := HashPassword("dummy-password", active, bytes.NewReader(bytes.Repeat([]byte{0x21}, 16)))
	if err != nil {
		t.Fatalf("HashPassword(dummy) error = %v", err)
	}
	legacyHash, err := HashPassword("right-password", legacy, bytes.NewReader(bytes.Repeat([]byte{0x22}, 16)))
	if err != nil {
		t.Fatalf("HashPassword(legacy) error = %v", err)
	}
	store := newTestAccountStore(Account{
		TenantID:     "tenant-a",
		UserID:       "user-a",
		Username:     "alice",
		PasswordHash: legacyHash,
	})
	authenticator, err := NewAuthenticator(AuthenticatorConfig{
		Store:                 store,
		PasswordParameters:    active,
		DummyPasswordHash:     dummy,
		LoginPolicy:           LoginPolicy{MaximumFailures: 3, LockoutDuration: time.Minute},
		Now:                   time.Now,
		MaximumCASRetries:     8,
		MaximumParallelHashes: 1,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}
	if _, err := authenticator.Authenticate(context.Background(), "alice", "right-password"); err == nil {
		t.Fatal("Authenticate(legacy cost) error = nil")
	}
}

func TestAuthenticatorRejectsEmptyStoredHashWithoutMutatingAccount(t *testing.T) {
	t.Parallel()

	params := Argon2idParams{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1, SaltBytes: 16, KeyBytes: 32}
	dummy, err := HashPassword("dummy-password", params, bytes.NewReader(bytes.Repeat([]byte{0x31}, 16)))
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	store := newTestAccountStore(Account{
		TenantID: "tenant-a",
		UserID:   "user-a",
		Username: "alice",
	})
	authenticator, err := NewAuthenticator(AuthenticatorConfig{
		Store:                 store,
		PasswordParameters:    params,
		DummyPasswordHash:     dummy,
		LoginPolicy:           LoginPolicy{MaximumFailures: 3, LockoutDuration: time.Minute},
		Now:                   time.Now,
		MaximumCASRetries:     8,
		MaximumParallelHashes: 1,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}
	if _, err := authenticator.Authenticate(context.Background(), "alice", "password"); err == nil {
		t.Fatal("Authenticate(empty stored hash) error = nil")
	}
	account, err := store.LoadAccount(context.Background(), "alice")
	if err != nil || account.Version != 0 || account.FailedAttempts != 0 {
		t.Fatalf("account after corrupt hash = (%+v, %v)", account, err)
	}
}

func TestAuthenticatorRejectsZeroClockIdenticallyWithoutAudit(t *testing.T) {
	t.Parallel()

	params := Argon2idParams{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1, SaltBytes: 16, KeyBytes: 32}
	hash, err := HashPassword("right-password", params, bytes.NewReader(bytes.Repeat([]byte{0x41}, 16)))
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	for _, accounts := range [][]Account{
		nil,
		{{TenantID: "tenant-a", UserID: "user-a", Username: "alice", PasswordHash: hash}},
	} {
		store := newTestAccountStore(accounts...)
		authenticator, err := NewAuthenticator(AuthenticatorConfig{
			Store:                 store,
			PasswordParameters:    params,
			DummyPasswordHash:     hash,
			LoginPolicy:           LoginPolicy{MaximumFailures: 3, LockoutDuration: time.Minute},
			Now:                   func() time.Time { return time.Time{} },
			MaximumCASRetries:     8,
			MaximumParallelHashes: 1,
		})
		if err != nil {
			t.Fatalf("NewAuthenticator() error = %v", err)
		}
		if _, err := authenticator.Authenticate(context.Background(), "alice", "right-password"); !errors.Is(err, ErrAuthenticationClock) {
			t.Fatalf("Authenticate(zero clock) error = %v, want ErrAuthenticationClock", err)
		}
		if got := store.auditCount(); got != 0 {
			t.Fatalf("zero-clock audit count = %d, want 0", got)
		}
	}
}

type testAccountStore struct {
	mu          sync.Mutex
	accounts    map[string]Account
	auditEvents []LoginAuditEvent
	auditErr    error
}

func newTestAccountStore(accounts ...Account) *testAccountStore {
	store := &testAccountStore{accounts: make(map[string]Account, len(accounts))}
	for _, account := range accounts {
		store.accounts[account.Username] = account
	}
	return store
}

func (store *testAccountStore) LoadAccount(_ context.Context, username string) (Account, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	account, found := store.accounts[username]
	if !found {
		return Account{}, ErrAccountNotFound
	}
	return account, nil
}

func (store *testAccountStore) CommitLoginAttempt(
	_ context.Context,
	username string,
	expectedVersion *uint64,
	next *Account,
	event LoginAuditEvent,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.auditErr != nil {
		return fmt.Errorf("%w: %v", ErrAuditUnavailable, store.auditErr)
	}
	current, found := store.accounts[username]
	if expectedVersion == nil {
		if found || next != nil {
			return ErrAccountVersionConflict
		}
		store.auditEvents = append(store.auditEvents, event)
		return nil
	}
	if !found || current.Version != *expectedVersion || next == nil {
		return ErrAccountVersionConflict
	}
	store.accounts[username] = *next
	store.auditEvents = append(store.auditEvents, event)
	return nil
}

func (store *testAccountStore) auditCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.auditEvents)
}

func (store *testAccountStore) auditEventsSnapshot() []LoginAuditEvent {
	store.mu.Lock()
	defer store.mu.Unlock()
	return append([]LoginAuditEvent(nil), store.auditEvents...)
}
