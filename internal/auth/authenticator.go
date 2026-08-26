package auth

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"
)

var (
	ErrAccountNotFound         = errors.New("account not found")
	ErrAccountVersionConflict  = errors.New("account version conflict")
	ErrAuthenticationContended = errors.New("authentication state remained contended")
	ErrAuthenticationClock     = errors.New("authentication clock is invalid")
	ErrAuditUnavailable        = errors.New("authentication audit unavailable")
)

var canonicalUsernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

const (
	maximumAggregateHashMemoryKiB = 512 * 1024
	maximumAggregateHashPasses    = 32
)

type AccountStore interface {
	LoadAccount(context.Context, string) (Account, error)
	// CommitLoginAttempt atomically verifies the optional account version,
	// writes next when present, and appends event to a durable audit outbox.
	CommitLoginAttempt(context.Context, string, *uint64, *Account, LoginAuditEvent) error
}

type LoginAuditEvent struct {
	At       time.Time
	Username string
	TenantID string
	UserID   string
	Status   LoginStatus
}

type AuthenticationResult struct {
	Status              LoginStatus
	TenantID            string
	UserID              string
	NeedsPasswordRehash bool
}

type AuthenticatorConfig struct {
	Store                 AccountStore
	PasswordParameters    Argon2idParams
	DummyPasswordHash     string
	LoginPolicy           LoginPolicy
	Now                   func() time.Time
	MaximumCASRetries     uint32
	MaximumParallelHashes uint32
}

type Authenticator struct {
	store              AccountStore
	passwordParameters Argon2idParams
	dummyPasswordHash  string
	loginPolicy        LoginPolicy
	now                func() time.Time
	maximumCASRetries  uint32
	hashSlots          chan struct{}
}

func NewAuthenticator(config AuthenticatorConfig) (*Authenticator, error) {
	if config.Store == nil {
		return nil, errors.New("account store is required")
	}
	if err := validateArgon2idParams(config.PasswordParameters); err != nil {
		return nil, fmt.Errorf("password parameters: %w", err)
	}
	dummyParams, _, _, err := parseArgon2idHash(config.DummyPasswordHash)
	if err != nil {
		return nil, errors.New("dummy password hash is invalid")
	}
	if dummyParams != config.PasswordParameters {
		return nil, errors.New("dummy password hash cost must match account password policy")
	}
	if config.LoginPolicy.MaximumFailures == 0 || config.LoginPolicy.MaximumFailures > 100 {
		return nil, errors.New("maximum login failures must be between 1 and 100")
	}
	if config.LoginPolicy.LockoutDuration <= 0 || config.LoginPolicy.LockoutDuration > 30*24*time.Hour {
		return nil, errors.New("login lockout duration is outside the supported range")
	}
	if config.Now == nil {
		return nil, errors.New("authentication clock is required")
	}
	if config.MaximumCASRetries == 0 || config.MaximumCASRetries > 256 {
		return nil, errors.New("maximum authentication CAS retries must be between 1 and 256")
	}
	if config.MaximumParallelHashes == 0 || config.MaximumParallelHashes > 128 {
		return nil, errors.New("maximum parallel password hashes must be between 1 and 128")
	}
	if uint64(config.MaximumParallelHashes)*uint64(config.PasswordParameters.MemoryKiB) > maximumAggregateHashMemoryKiB ||
		uint64(config.MaximumParallelHashes)*uint64(config.PasswordParameters.Iterations) > maximumAggregateHashPasses {
		return nil, errors.New("parallel password hashing exceeds the aggregate resource budget")
	}
	return &Authenticator{
		store:              config.Store,
		passwordParameters: config.PasswordParameters,
		dummyPasswordHash:  config.DummyPasswordHash,
		loginPolicy:        config.LoginPolicy,
		now:                config.Now,
		maximumCASRetries:  config.MaximumCASRetries,
		hashSlots:          make(chan struct{}, config.MaximumParallelHashes),
	}, nil
}

func (authenticator *Authenticator) Authenticate(
	ctx context.Context,
	username string,
	password string,
) (AuthenticationResult, error) {
	if ctx == nil {
		return AuthenticationResult{}, errors.New("authentication context is required")
	}
	if !canonicalUsernamePattern.MatchString(username) {
		return AuthenticationResult{}, ErrInvalidCredential
	}
	if err := validatePassword(password); err != nil {
		return AuthenticationResult{}, ErrInvalidCredential
	}
	var verifiedHash string
	var verification PasswordVerification
	hasVerification := false
	for range authenticator.maximumCASRetries {
		account, loadErr := authenticator.store.LoadAccount(ctx, username)
		missing := errors.Is(loadErr, ErrAccountNotFound)
		if loadErr != nil && !missing {
			return AuthenticationResult{}, fmt.Errorf("load local account: %w", loadErr)
		}
		hash := authenticator.dummyPasswordHash
		if !missing {
			if err := validateAccount(account); err != nil || account.Username != username {
				return AuthenticationResult{}, errors.New("local account state is invalid")
			}
			hash = account.PasswordHash
		}
		if !hasVerification || hash != verifiedHash {
			hashParams, _, _, err := parseArgon2idHash(hash)
			if err != nil || hashParams != authenticator.passwordParameters {
				return AuthenticationResult{}, errors.New("local account password cost is outside the active policy")
			}
			select {
			case authenticator.hashSlots <- struct{}{}:
			case <-ctx.Done():
				return AuthenticationResult{}, ctx.Err()
			}
			verified, err := VerifyPassword(hash, password, authenticator.passwordParameters)
			<-authenticator.hashSlots
			if err != nil {
				return AuthenticationResult{}, errors.New("local account password state is invalid")
			}
			verifiedHash = hash
			verification = verified
			hasVerification = true
		}
		at := authenticator.now().UTC()
		if at.IsZero() {
			return AuthenticationResult{}, ErrAuthenticationClock
		}
		if missing {
			event := LoginAuditEvent{
				At:       at,
				Username: username,
				Status:   LoginInvalidCredentials,
			}
			if err := authenticator.store.CommitLoginAttempt(
				ctx,
				username,
				nil,
				nil,
				event,
			); err != nil {
				if errors.Is(err, ErrAccountVersionConflict) {
					continue
				}
				return AuthenticationResult{}, fmt.Errorf("commit failed login audit: %w", err)
			}
			return AuthenticationResult{Status: LoginInvalidCredentials}, nil
		}
		next, status, err := ApplyLoginAttempt(
			account,
			at,
			verification.Valid,
			authenticator.loginPolicy,
		)
		if err != nil {
			return AuthenticationResult{}, fmt.Errorf("apply login attempt: %w", err)
		}
		event := LoginAuditEvent{
			At:       at,
			Username: username,
			TenantID: account.TenantID,
			UserID:   account.UserID,
			Status:   status,
		}
		expectedVersion := account.Version
		if err := authenticator.store.CommitLoginAttempt(
			ctx,
			username,
			&expectedVersion,
			&next,
			event,
		); err != nil {
			if errors.Is(err, ErrAccountVersionConflict) {
				continue
			}
			return AuthenticationResult{}, fmt.Errorf("commit login attempt: %w", err)
		}
		if status != LoginAuthenticated {
			return AuthenticationResult{Status: LoginInvalidCredentials}, nil
		}
		return AuthenticationResult{
			Status:              status,
			TenantID:            account.TenantID,
			UserID:              account.UserID,
			NeedsPasswordRehash: status == LoginAuthenticated && verification.NeedsRehash,
		}, nil
	}
	return AuthenticationResult{}, ErrAuthenticationContended
}
