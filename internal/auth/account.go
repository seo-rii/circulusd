package auth

import (
	"errors"
	"fmt"
	"math"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const maximumIdentityBytes = 256

type LoginStatus string

const (
	LoginAuthenticated      LoginStatus = "authenticated"
	LoginInvalidCredentials LoginStatus = "invalid_credentials"
	LoginLocked             LoginStatus = "locked"
	LoginDisabled           LoginStatus = "disabled"
)

type LoginPolicy struct {
	MaximumFailures uint32
	LockoutDuration time.Duration
}

type Account struct {
	TenantID            string
	UserID              string
	Username            string
	PasswordHash        string
	Disabled            bool
	FailedAttempts      uint32
	LockedUntil         time.Time
	LastAuthenticatedAt time.Time
	Version             uint64
}

func ApplyLoginAttempt(
	account Account,
	at time.Time,
	passwordValid bool,
	policy LoginPolicy,
) (Account, LoginStatus, error) {
	if err := validateAccount(account); err != nil {
		return Account{}, "", err
	}
	if policy.MaximumFailures == 0 || policy.MaximumFailures > 100 {
		return Account{}, "", errors.New("maximum login failures must be between 1 and 100")
	}
	if policy.LockoutDuration <= 0 || policy.LockoutDuration > 30*24*time.Hour {
		return Account{}, "", errors.New("login lockout duration is outside the supported range")
	}
	if at.IsZero() {
		return Account{}, "", errors.New("login attempt time is required")
	}
	at = at.UTC()
	if account.Disabled {
		return account, LoginDisabled, nil
	}
	if account.LastAuthenticatedAt.After(at) {
		at = account.LastAuthenticatedAt.UTC()
	}
	if !account.LockedUntil.IsZero() && at.Before(account.LockedUntil) {
		return account, LoginLocked, nil
	}
	if account.Version == math.MaxUint64 {
		return Account{}, "", errors.New("account version cannot advance")
	}
	next := account
	if !next.LockedUntil.IsZero() {
		next.FailedAttempts = 0
		next.LockedUntil = time.Time{}
	}
	if passwordValid {
		next.FailedAttempts = 0
		next.LockedUntil = time.Time{}
		if next.LastAuthenticatedAt.IsZero() || at.After(next.LastAuthenticatedAt) {
			next.LastAuthenticatedAt = at
		}
		next.Version++
		return next, LoginAuthenticated, nil
	}
	if next.FailedAttempts < policy.MaximumFailures {
		next.FailedAttempts++
	}
	next.LockedUntil = time.Time{}
	next.Version++
	if next.FailedAttempts >= policy.MaximumFailures {
		next.LockedUntil = at.Add(policy.LockoutDuration)
		return next, LoginLocked, nil
	}
	return next, LoginInvalidCredentials, nil
}

func validateAccount(account Account) error {
	for field, value := range map[string]string{
		"tenant ID": account.TenantID,
		"user ID":   account.UserID,
		"username":  account.Username,
	} {
		if err := validateBoundedText(value); err != nil {
			return fmt.Errorf("%s: %w", field, err)
		}
	}
	return nil
}

func validateBoundedText(value string) error {
	if value == "" || len(value) > maximumIdentityBytes || !utf8.ValidString(value) || !norm.NFC.IsNormalString(value) {
		return errors.New("must be non-empty bounded NFC text")
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return errors.New("must not contain control characters")
		}
	}
	return nil
}
