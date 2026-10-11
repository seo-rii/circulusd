package authstate

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/hancomac/circulusd/internal/auth"
	"github.com/hancomac/circulusd/internal/celld"
	"github.com/hancomac/circulusd/internal/dependency"
	"github.com/hancomac/circulusd/internal/identity"
)

const AtomicAccountAudit dependency.AtomicGroup = "account-audit"

var usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

// AccountConfig captures the same bounded password cost and lockout policy as
// the existing local Authenticator. Changing durable policy requires an
// explicit native migration; opening old account state with another policy
// fails closed. No public request can replace these policies.
type AccountConfig struct {
	Config
	LoginPolicy        auth.LoginPolicy
	PasswordParameters auth.Argon2idParams
}

type AccountStore struct {
	source             Source
	binding            dependency.Verified[Source]
	tenantID, objectID string
	now                func() time.Time
	limits             limits
	policy             auth.LoginPolicy
	passwordParameters auth.Argon2idParams
}

func (*AccountStore) String() string   { return "authstate-account-store<redacted>" }
func (*AccountStore) GoString() string { return "authstate-account-store<redacted>" }

func NewAccountStore(config AccountConfig) (*AccountStore, error) {
	source, _, err := config.Source.Open()
	if err != nil || nilInterface(source) {
		return nil, dependency.ErrUnverifiedDependency
	}
	if _, err := dependency.RequireAtomicDomain([]dependency.AtomicGroup{AtomicAccountAudit}, config.Source); err != nil {
		return nil, err
	}
	if _, err := identity.Parse(identity.Tenant, config.TenantID); err != nil || config.Now == nil ||
		config.LoginPolicy.MaximumFailures < 1 || config.LoginPolicy.MaximumFailures > 100 ||
		config.LoginPolicy.LockoutDuration <= 0 || config.LoginPolicy.LockoutDuration > 30*24*time.Hour || !validPasswordParameters(config.PasswordParameters) {
		return nil, ErrInvalidConfiguration
	}
	bound, err := configuredLimits(config.Config)
	if err != nil {
		return nil, err
	}
	return &AccountStore{source: source, binding: config.Source, tenantID: config.TenantID, objectID: "auth-accounts:" + config.TenantID,
		now: config.Now, limits: bound, policy: config.LoginPolicy, passwordParameters: config.PasswordParameters}, nil
}

func (store *AccountStore) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	if store == nil || nilInterface(store.source) {
		return dependency.ProbeResponse{}, dependency.ErrUnverifiedDependency
	}
	if _, _, err := store.binding.Open(); err != nil {
		return dependency.ProbeResponse{}, err
	}
	return store.source.ProbeProduction(ctx, challenge)
}

// CreateAccount is trusted local provisioning, never a login or self-service
// identity registration. It cannot replace an existing account or its tenant.
func (store *AccountStore) CreateAccount(ctx context.Context, account auth.Account) error {
	if err := store.ready(ctx); err != nil {
		return err
	}
	if !store.validAccount(account) || account.Version != 1 || account.FailedAttempts != 0 ||
		!account.LockedUntil.IsZero() || !account.LastAuthenticatedAt.IsZero() {
		return auth.ErrInvalidCredential
	}
	return store.transact(ctx, func(state *accountState, now time.Time) (bool, error) {
		if !validNow(now) {
			return false, auth.ErrAuthenticationClock
		}
		for _, current := range state.accounts {
			if current.Username == account.Username || current.UserID == account.UserID {
				return false, auth.ErrAccountVersionConflict
			}
		}
		if len(state.accounts) >= store.limits.records {
			return false, ErrCapacity
		}
		state.accounts = append(state.accounts, account)
		event := auth.LoginAuditEvent{At: now, Username: account.Username, TenantID: account.TenantID, UserID: account.UserID}
		if err := state.appendAudit("created", event, &account, now, store.limits); err != nil {
			return false, err
		}
		return true, nil
	})
}

func (store *AccountStore) LoadAccount(ctx context.Context, username string) (auth.Account, error) {
	if err := store.ready(ctx); err != nil {
		return auth.Account{}, err
	}
	if !usernamePattern.MatchString(username) {
		return auth.Account{}, auth.ErrInvalidCredential
	}
	var result auth.Account
	err := store.transact(ctx, func(state *accountState, _ time.Time) (bool, error) {
		result = auth.Account{}
		for _, account := range state.accounts {
			if account.Username == username {
				result = account
				return false, nil
			}
		}
		return false, auth.ErrAccountNotFound
	})
	if err != nil {
		return auth.Account{}, err
	}
	return result, nil
}

func (store *AccountStore) CommitLoginAttempt(ctx context.Context, username string, expectedVersion *uint64, next *auth.Account, event auth.LoginAuditEvent) error {
	if err := store.ready(ctx); err != nil {
		return err
	}
	if !usernamePattern.MatchString(username) || username != event.Username || !validNow(event.At) ||
		(expectedVersion == nil) != (next == nil) {
		return auth.ErrInvalidCredential
	}
	var version uint64
	var owned auth.Account
	if expectedVersion != nil {
		version, owned = *expectedVersion, *next
		if version < 1 || version >= maximumInteger || !store.validAccount(owned) {
			return auth.ErrInvalidCredential
		}
	}
	return store.transact(ctx, func(state *accountState, now time.Time) (bool, error) {
		if !validNow(now) || now.Before(event.At) {
			return false, auth.ErrAuthenticationClock
		}
		index := -1
		for i, account := range state.accounts {
			if account.Username == username {
				index = i
				break
			}
		}
		if index == -1 {
			if expectedVersion != nil {
				return false, auth.ErrAccountVersionConflict
			}
			if event.Status != auth.LoginInvalidCredentials || event.TenantID != "" || event.UserID != "" {
				return false, auth.ErrInvalidCredential
			}
			if err := state.appendAudit("login", event, nil, now, store.limits); err != nil {
				return false, err
			}
			return true, nil
		}
		current := state.accounts[index]
		if event.At.Before(state.creationTimes[username]) {
			return false, auth.ErrAuthenticationClock
		}
		if expectedVersion == nil || current.Version != version {
			return false, auth.ErrAccountVersionConflict
		}
		if event.TenantID != current.TenantID || event.UserID != current.UserID ||
			owned.TenantID != current.TenantID || owned.UserID != current.UserID || owned.Username != current.Username ||
			owned.PasswordHash != current.PasswordHash || owned.Disabled != current.Disabled {
			return false, auth.ErrInvalidCredential
		}
		// Recompute the existing transition against CURRENT durable account state
		// and the immutable host policy. A cached pre-lockout success cannot
		// replace a newer failure/disable record or shorten the current lockout.
		expected, status, err := auth.ApplyLoginAttempt(current, event.At, event.Status == auth.LoginAuthenticated, store.policy)
		if err != nil || status != event.Status || !sameAccount(expected, owned) {
			return false, auth.ErrInvalidCredential
		}
		state.accounts[index] = owned
		if err := state.appendAudit("login", event, &owned, now, store.limits); err != nil {
			return false, err
		}
		return true, nil
	})
}

type AccountAuditEntry struct {
	Sequence               uint64
	PreviousDigest, Digest string
	AccountVersion         uint64
	AccountDigest          string
	Kind                   string
	CommittedAt            time.Time
	Event                  auth.LoginAuditEvent
}

func (AccountAuditEntry) String() string   { return "authstate-account-audit-entry<redacted>" }
func (AccountAuditEntry) GoString() string { return "authstate-account-audit-entry<redacted>" }

type AccountAuditPage struct {
	TenantID, ObjectID string
	StateDigest        [32]byte
	Entries            []AccountAuditEntry
	HeadSequence       uint64
	HeadDigest         string
}

func (store *AccountStore) ReadAudit(ctx context.Context, afterSequence uint64, limit uint32) (AccountAuditPage, error) {
	if err := store.ready(ctx); err != nil {
		return AccountAuditPage{}, err
	}
	if afterSequence > maximumInteger || limit < 1 || limit > 1024 {
		return AccountAuditPage{}, ErrInvalidRequest
	}
	var page AccountAuditPage
	err := store.transact(ctx, func(state *accountState, _ time.Time) (bool, error) {
		if afterSequence > uint64(len(state.audit)) {
			return false, ErrInvalidRequest
		}
		end := min(uint64(len(state.audit)), afterSequence+uint64(limit))
		page = AccountAuditPage{TenantID: store.tenantID, ObjectID: store.objectID, StateDigest: state.rawDigest,
			Entries: append([]AccountAuditEntry(nil), state.audit[afterSequence:end]...), HeadSequence: uint64(len(state.audit)), HeadDigest: state.headDigest()}
		return false, nil
	})
	if err != nil {
		return AccountAuditPage{}, err
	}
	return page, nil
}

func (store *AccountStore) ready(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if store == nil || nilInterface(store.source) {
		return dependency.ErrUnverifiedDependency
	}
	if _, _, err := store.binding.Open(); err != nil {
		return dependency.ErrUnverifiedDependency
	}
	return nil
}

func (store *AccountStore) transact(ctx context.Context, apply func(*accountState, time.Time) (bool, error)) error {
	started, completed := 0, 0
	token, err := store.source.Transaction(ctx, store.objectID, func(tx celld.Transaction) error {
		started++
		if nilInterface(tx) {
			return ErrUnavailable
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		bytes, err := tx.ReadState()
		if err != nil {
			return store.safeError(ctx, err)
		}
		state, err := store.decodeState(bytes)
		if err != nil {
			return err
		}
		changed, err := apply(state, store.now().UTC())
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if changed {
			bytes, err := store.encodeState(state)
			if err != nil {
				return err
			}
			if err := tx.WriteState(bytes); err != nil {
				return store.safeError(ctx, err)
			}
		}
		completed++
		return nil
	})
	if err != nil {
		return store.safeError(ctx, err)
	}
	if started == 0 || started != completed || token.ObjectID != store.objectID || token.Revision == 0 {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := store.source.DurabilityBarrier(ctx, token); err != nil {
		return store.safeError(ctx, err)
	}
	return ctx.Err()
}

func (store *AccountStore) safeError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	for _, safe := range []error{auth.ErrInvalidCredential, auth.ErrAccountNotFound, auth.ErrAccountVersionConflict, auth.ErrAuthenticationClock,
		ErrCorruptState, ErrCapacity, ErrInvalidRequest} {
		if errors.Is(err, safe) {
			return safe
		}
	}
	return auth.ErrAuditUnavailable
}

var _ auth.AccountStore = (*AccountStore)(nil)
var _ dependency.ProductionProbe = (*AccountStore)(nil)
