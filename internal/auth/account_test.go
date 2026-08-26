package auth

import (
	"math"
	"testing"
	"time"
)

func TestLoginAttemptLockoutAndRecoveryAreVersioned(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 26, 9, 0, 0, 0, time.UTC)
	policy := LoginPolicy{MaximumFailures: 3, LockoutDuration: 15 * time.Minute}
	account := Account{
		TenantID:     "tenant_AAAAAAAAAAAAAAAAAAAAAAAAAA",
		UserID:       "subject_AAAAAAAAAAAAAAAAAAAAAAAAAA",
		Username:     "alice",
		PasswordHash: "$argon2id$v=19$m=8192,t=1,p=1$WlpaWlpaWlpaWlpaWlpaWg$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Version:      7,
	}

	for failure := 1; failure <= 3; failure++ {
		var status LoginStatus
		var err error
		account, status, err = ApplyLoginAttempt(account, now, false, policy)
		if err != nil {
			t.Fatalf("ApplyLoginAttempt(%d) error = %v", failure, err)
		}
		want := LoginInvalidCredentials
		if failure == 3 {
			want = LoginLocked
		}
		if status != want {
			t.Fatalf("attempt %d status = %q, want %q", failure, status, want)
		}
	}
	if account.Version != 10 || !account.LockedUntil.Equal(now.Add(15*time.Minute)) {
		t.Fatalf("locked account = %+v", account)
	}

	unchanged, status, err := ApplyLoginAttempt(account, now.Add(time.Minute), true, policy)
	if err != nil || status != LoginLocked || unchanged.Version != account.Version {
		t.Fatalf("locked attempt = (%+v, %q, %v)", unchanged, status, err)
	}
	recovered, status, err := ApplyLoginAttempt(account, account.LockedUntil, true, policy)
	if err != nil || status != LoginAuthenticated {
		t.Fatalf("recovery = (%+v, %q, %v)", recovered, status, err)
	}
	if recovered.FailedAttempts != 0 || !recovered.LockedUntil.IsZero() || recovered.Version != 11 {
		t.Fatalf("recovered account = %+v", recovered)
	}

	expiredThenWrong, status, err := ApplyLoginAttempt(account, account.LockedUntil, false, policy)
	if err != nil || status != LoginInvalidCredentials {
		t.Fatalf("post-lockout failure = (%+v, %q, %v)", expiredThenWrong, status, err)
	}
	if expiredThenWrong.FailedAttempts != 1 || !expiredThenWrong.LockedUntil.IsZero() {
		t.Fatalf("post-lockout failure state = %+v", expiredThenWrong)
	}
}

func TestDisabledAccountNeverAuthenticatesOrMutates(t *testing.T) {
	t.Parallel()

	account := Account{TenantID: "tenant-a", UserID: "user-a", Username: "alice", Disabled: true, Version: 4}
	next, status, err := ApplyLoginAttempt(account, time.Now(), true, LoginPolicy{MaximumFailures: 3, LockoutDuration: time.Minute})
	if err != nil {
		t.Fatalf("ApplyLoginAttempt() error = %v", err)
	}
	if status != LoginDisabled || next != account {
		t.Fatalf("disabled attempt = (%+v, %q)", next, status)
	}
}

func TestLoginAttemptRejectsVersionOverflow(t *testing.T) {
	t.Parallel()

	account := Account{
		TenantID: "tenant-a",
		UserID:   "user-a",
		Username: "alice",
		Version:  math.MaxUint64,
	}
	if _, _, err := ApplyLoginAttempt(
		account,
		time.Now().UTC(),
		false,
		LoginPolicy{MaximumFailures: 3, LockoutDuration: time.Minute},
	); err == nil {
		t.Fatal("ApplyLoginAttempt(version overflow) error = nil")
	}
}

func TestLoginAttemptPreservesAuthenticationTimeHighWater(t *testing.T) {
	t.Parallel()

	lastAuthenticated := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	account := Account{
		TenantID:            "tenant-a",
		UserID:              "user-a",
		Username:            "alice",
		LastAuthenticatedAt: lastAuthenticated,
	}
	next, status, err := ApplyLoginAttempt(
		account,
		lastAuthenticated.Add(-time.Second),
		true,
		LoginPolicy{MaximumFailures: 3, LockoutDuration: time.Minute},
	)
	if err != nil || status != LoginAuthenticated {
		t.Fatalf("ApplyLoginAttempt(clock regression) = (%+v, %q, %v)", next, status, err)
	}
	if !next.LastAuthenticatedAt.Equal(lastAuthenticated) {
		t.Fatalf("LastAuthenticatedAt regressed to %s", next.LastAuthenticatedAt)
	}

	locked, status, err := ApplyLoginAttempt(
		account,
		lastAuthenticated.Add(-time.Hour),
		false,
		LoginPolicy{MaximumFailures: 1, LockoutDuration: 15 * time.Minute},
	)
	if err != nil || status != LoginLocked {
		t.Fatalf("ApplyLoginAttempt(regressed lockout) = (%+v, %q, %v)", locked, status, err)
	}
	if want := lastAuthenticated.Add(15 * time.Minute); !locked.LockedUntil.Equal(want) {
		t.Fatalf("LockedUntil = %s, want high-water %s", locked.LockedUntil, want)
	}
}
