package authstate

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/hancomac/circulusd/internal/auth"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/identity"
)

type accountState struct {
	tenantID      string
	accounts      []auth.Account
	audit         []AccountAuditEntry
	rawDigest     [32]byte
	creationTimes map[string]time.Time
}

func (state *accountState) headDigest() string {
	if len(state.audit) == 0 {
		return zeroDigest
	}
	return state.audit[len(state.audit)-1].Digest
}

func (state *accountState) appendAudit(kind string, event auth.LoginAuditEvent, account *auth.Account, now time.Time, bound limits) error {
	if len(state.audit) >= bound.auditEntries {
		return ErrCapacity
	}
	if !validNow(now) || now.Before(event.At) || (len(state.audit) > 0 && now.Before(state.audit[len(state.audit)-1].CommittedAt)) {
		return auth.ErrAuthenticationClock
	}
	entry := AccountAuditEntry{Sequence: uint64(len(state.audit) + 1), PreviousDigest: state.headDigest(), Kind: kind, Event: event, CommittedAt: now, AccountDigest: zeroDigest}
	if account != nil {
		entry.AccountVersion = account.Version
		digest, err := accountDigest(*account)
		if err != nil {
			return ErrInvalidRequest
		}
		entry.AccountDigest = digest
	}
	digest, err := canonical.StructuredDigest("circulusd.auth.account-audit-entry", 1, accountAuditValue(entry, false))
	if err != nil {
		return ErrInvalidRequest
	}
	entry.Digest = digest
	state.audit = append(state.audit, entry)
	return nil
}

func (store *AccountStore) encodeState(state *accountState) ([]byte, error) {
	sort.Slice(state.accounts, func(i, j int) bool { return state.accounts[i].Username < state.accounts[j].Username })
	if err := store.validateState(state); err != nil {
		return nil, err
	}
	accounts := make(canonical.Array, len(state.accounts))
	for i, account := range state.accounts {
		accounts[i] = accountValue(account)
	}
	audit := make(canonical.Array, len(state.audit))
	for i, entry := range state.audit {
		audit[i] = accountAuditValue(entry, true)
	}
	bytes, err := canonical.Encode(canonical.Map{"version": int64(1), "tenantId": state.tenantID, "policy": store.policyValue(),
		"accounts": accounts, "audit": audit, "headSequence": uint64(len(state.audit)), "headDigest": state.headDigest()}, stateOptions(store.limits))
	if err != nil {
		return nil, ErrCapacity
	}
	return bytes, nil
}

func (store *AccountStore) decodeState(bytes []byte) (*accountState, error) {
	if len(bytes) == 0 {
		return &accountState{tenantID: store.tenantID, rawDigest: sha256.Sum256(bytes)}, nil
	}
	if len(bytes) > store.limits.stateBytes {
		return nil, ErrCapacity
	}
	value, err := canonical.Decode(bytes, stateOptions(store.limits))
	if err != nil {
		return nil, ErrCorruptState
	}
	m, ok := exactMap(value, "version", "tenantId", "policy", "accounts", "audit", "headSequence", "headDigest")
	if !ok || m["version"] != int64(1) || m["tenantId"] != store.tenantID || !store.matchesPolicy(m["policy"]) {
		return nil, ErrCorruptState
	}
	accounts, ok := m["accounts"].(canonical.Array)
	if !ok || len(accounts) > store.limits.records {
		return nil, ErrCorruptState
	}
	audit, ok := m["audit"].(canonical.Array)
	if !ok || len(audit) > store.limits.auditEntries {
		return nil, ErrCorruptState
	}
	state := &accountState{tenantID: store.tenantID, accounts: make([]auth.Account, len(accounts)), audit: make([]AccountAuditEntry, len(audit)), rawDigest: sha256.Sum256(bytes)}
	for i, value := range accounts {
		account, err := parseAccount(value)
		if err != nil {
			return nil, err
		}
		state.accounts[i] = account
	}
	for i, value := range audit {
		entry, err := parseAccountAudit(value)
		if err != nil {
			return nil, err
		}
		state.audit[i] = entry
	}
	sequence, ok := integer(m["headSequence"])
	if !ok || sequence != uint64(len(state.audit)) || m["headDigest"] != state.headDigest() {
		return nil, ErrCorruptState
	}
	if err := store.validateState(state); err != nil {
		return nil, err
	}
	return state, nil
}

func (store *AccountStore) validateState(state *accountState) error {
	if state.tenantID != store.tenantID || len(state.accounts) > store.limits.records || len(state.audit) > store.limits.auditEntries {
		return ErrCapacity
	}
	accounts := make(map[string]auth.Account, len(state.accounts))
	users := make(map[string]bool, len(state.accounts))
	for i, account := range state.accounts {
		if !store.validAccount(account) || users[account.UserID] || (i > 0 && state.accounts[i-1].Username >= account.Username) {
			return ErrCorruptState
		}
		accounts[account.Username], users[account.UserID] = account, true
	}
	history := make(map[string]auth.Account, len(accounts))
	creationTimes := make(map[string]time.Time, len(accounts))
	previous := zeroDigest
	var committed time.Time
	for i, entry := range state.audit {
		if entry.Sequence != uint64(i+1) || entry.PreviousDigest != previous || !validDigest(entry.Digest) ||
			!validNow(entry.CommittedAt) || !validNow(entry.Event.At) || entry.CommittedAt.Before(entry.Event.At) ||
			(!committed.IsZero() && entry.CommittedAt.Before(committed)) || !usernamePattern.MatchString(entry.Event.Username) {
			return ErrCorruptState
		}
		digest, err := canonical.StructuredDigest("circulusd.auth.account-audit-entry", 1, accountAuditValue(entry, false))
		if err != nil || digest != entry.Digest {
			return ErrCorruptState
		}
		account, exists := accounts[entry.Event.Username]
		current, created := history[entry.Event.Username]
		switch entry.Kind {
		case "created":
			if !exists || created || entry.AccountVersion != 1 || entry.Event.Status != "" ||
				entry.Event.TenantID != store.tenantID || entry.Event.UserID != account.UserID {
				return ErrCorruptState
			}
			current = account
			current.Version, current.FailedAttempts, current.LockedUntil, current.LastAuthenticatedAt = 1, 0, time.Time{}, time.Time{}
			history[entry.Event.Username] = current
			creationTimes[entry.Event.Username] = entry.Event.At
		case "login":
			if entry.Event.TenantID == "" && entry.Event.UserID == "" {
				if created || entry.Event.Status != auth.LoginInvalidCredentials || entry.AccountVersion != 0 || entry.AccountDigest != zeroDigest {
					return ErrCorruptState
				}
				previous, committed = entry.Digest, entry.CommittedAt
				continue
			}
			if !exists || !created || entry.Event.TenantID != store.tenantID || entry.Event.UserID != account.UserID || entry.Event.At.Before(creationTimes[entry.Event.Username]) {
				return ErrCorruptState
			}
			next, status, err := auth.ApplyLoginAttempt(current, entry.Event.At, entry.Event.Status == auth.LoginAuthenticated, store.policy)
			if err != nil || status != entry.Event.Status {
				return ErrCorruptState
			}
			current = next
			history[entry.Event.Username] = current
		default:
			return ErrCorruptState
		}
		stateDigest, err := accountDigest(current)
		if err != nil || stateDigest != entry.AccountDigest || current.Version != entry.AccountVersion {
			return ErrCorruptState
		}
		previous, committed = entry.Digest, entry.CommittedAt
	}
	for username, account := range accounts {
		current, found := history[username]
		if !found || !sameAccount(current, account) {
			return ErrCorruptState
		}
	}
	state.creationTimes = creationTimes
	return nil
}

func (store *AccountStore) policyValue() canonical.Map {
	p := store.passwordParameters
	return canonical.Map{"maximumFailures": uint64(store.policy.MaximumFailures), "lockoutNanoseconds": int64(store.policy.LockoutDuration),
		"memoryKiB": uint64(p.MemoryKiB), "iterations": uint64(p.Iterations), "parallelism": uint64(p.Parallelism), "saltBytes": uint64(p.SaltBytes), "keyBytes": uint64(p.KeyBytes)}
}

func (store *AccountStore) matchesPolicy(value canonical.Value) bool {
	m, ok := exactMap(value, "maximumFailures", "lockoutNanoseconds", "memoryKiB", "iterations", "parallelism", "saltBytes", "keyBytes")
	if !ok {
		return false
	}
	for key, want := range store.policyValue() {
		n, ok := integer(m[key])
		if !ok {
			return false
		}
		switch expected := want.(type) {
		case uint64:
			if n != expected {
				return false
			}
		case int64:
			if n != uint64(expected) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func accountValue(account auth.Account) canonical.Map {
	var locked, authenticated canonical.Value
	if !account.LockedUntil.IsZero() {
		locked = timeText(account.LockedUntil)
	}
	if !account.LastAuthenticatedAt.IsZero() {
		authenticated = timeText(account.LastAuthenticatedAt)
	}
	return canonical.Map{"tenantId": account.TenantID, "userId": account.UserID, "username": account.Username, "passwordHash": account.PasswordHash,
		"disabled": account.Disabled, "failedAttempts": uint64(account.FailedAttempts), "lockedUntil": locked, "lastAuthenticatedAt": authenticated, "version": account.Version}
}

func accountDigest(account auth.Account) (string, error) {
	return canonical.StructuredDigest("circulusd.auth.account-state", 1, accountValue(account))
}

func parseAccount(value canonical.Value) (auth.Account, error) {
	r := auth.Account{}
	m, ok := exactMap(value, "tenantId", "userId", "username", "passwordHash", "disabled", "failedAttempts", "lockedUntil", "lastAuthenticatedAt", "version")
	if !ok {
		return r, ErrCorruptState
	}
	for key, target := range map[string]*string{"tenantId": &r.TenantID, "userId": &r.UserID, "username": &r.Username, "passwordHash": &r.PasswordHash} {
		text, ok := m[key].(string)
		if !ok {
			return r, ErrCorruptState
		}
		*target = text
	}
	if r.Disabled, ok = m["disabled"].(bool); !ok {
		return r, ErrCorruptState
	}
	failed, ok := integer(m["failedAttempts"])
	if !ok || failed > 100 {
		return r, ErrCorruptState
	}
	r.FailedAttempts = uint32(failed)
	if r.Version, ok = integer(m["version"]); !ok {
		return r, ErrCorruptState
	}
	if m["lockedUntil"] != nil {
		if r.LockedUntil, ok = parseTime(m["lockedUntil"]); !ok {
			return r, ErrCorruptState
		}
	}
	if m["lastAuthenticatedAt"] != nil {
		if r.LastAuthenticatedAt, ok = parseTime(m["lastAuthenticatedAt"]); !ok {
			return r, ErrCorruptState
		}
	}
	return r, nil
}

func accountAuditValue(entry AccountAuditEntry, withDigest bool) canonical.Map {
	value := canonical.Map{"sequence": entry.Sequence, "previousDigest": entry.PreviousDigest, "accountVersion": entry.AccountVersion, "accountDigest": entry.AccountDigest,
		"kind": entry.Kind, "committedAt": timeText(entry.CommittedAt), "event": canonical.Map{"at": timeText(entry.Event.At), "username": entry.Event.Username,
			"tenantId": entry.Event.TenantID, "userId": entry.Event.UserID, "status": string(entry.Event.Status)}}
	if withDigest {
		value["digest"] = entry.Digest
	}
	return value
}

func parseAccountAudit(value canonical.Value) (AccountAuditEntry, error) {
	r := AccountAuditEntry{}
	m, ok := exactMap(value, "sequence", "previousDigest", "digest", "accountVersion", "accountDigest", "kind", "committedAt", "event")
	if !ok {
		return r, ErrCorruptState
	}
	if r.Sequence, ok = integer(m["sequence"]); !ok {
		return r, ErrCorruptState
	}
	if r.AccountVersion, ok = integer(m["accountVersion"]); !ok {
		return r, ErrCorruptState
	}
	for key, target := range map[string]*string{"previousDigest": &r.PreviousDigest, "digest": &r.Digest, "accountDigest": &r.AccountDigest, "kind": &r.Kind} {
		text, ok := m[key].(string)
		if !ok {
			return r, ErrCorruptState
		}
		*target = text
	}
	if r.CommittedAt, ok = parseTime(m["committedAt"]); !ok {
		return r, ErrCorruptState
	}
	e, ok := exactMap(m["event"], "at", "username", "tenantId", "userId", "status")
	if !ok {
		return r, ErrCorruptState
	}
	if r.Event.At, ok = parseTime(e["at"]); !ok {
		return r, ErrCorruptState
	}
	for key, target := range map[string]*string{"username": &r.Event.Username, "tenantId": &r.Event.TenantID, "userId": &r.Event.UserID} {
		text, ok := e[key].(string)
		if !ok {
			return r, ErrCorruptState
		}
		*target = text
	}
	status, ok := e["status"].(string)
	if !ok {
		return r, ErrCorruptState
	}
	r.Event.Status = auth.LoginStatus(status)
	return r, nil
}

func (store *AccountStore) validAccount(account auth.Account) bool {
	if account.TenantID != store.tenantID || !usernamePattern.MatchString(account.Username) ||
		account.Version < 1 || account.Version > maximumInteger || account.FailedAttempts > store.policy.MaximumFailures || !store.validPasswordHash(account.PasswordHash) {
		return false
	}
	if _, err := identity.Parse(identity.Subject, account.UserID); err != nil {
		return false
	}
	if !account.LockedUntil.IsZero() && !validNow(account.LockedUntil) {
		return false
	}
	if !account.LastAuthenticatedAt.IsZero() && !validNow(account.LastAuthenticatedAt) {
		return false
	}
	return true
}

func sameAccount(a, b auth.Account) bool {
	return a.TenantID == b.TenantID && a.UserID == b.UserID && a.Username == b.Username && a.PasswordHash == b.PasswordHash &&
		a.Disabled == b.Disabled && a.FailedAttempts == b.FailedAttempts && a.LockedUntil.Equal(b.LockedUntil) &&
		a.LastAuthenticatedAt.Equal(b.LastAuthenticatedAt) && a.Version == b.Version
}

func validPasswordParameters(p auth.Argon2idParams) bool {
	return p.MemoryKiB >= 8*1024 && p.MemoryKiB <= 256*1024 && p.Iterations >= 1 && p.Iterations <= 5 && p.Parallelism >= 1 && p.Parallelism <= 4 &&
		p.MemoryKiB >= 8*uint32(p.Parallelism) && p.SaltBytes >= 16 && p.SaltBytes <= 64 && p.KeyBytes >= 16 && p.KeyBytes <= 64
}

func (store *AccountStore) validPasswordHash(hash string) bool {
	if len(hash) > 512 {
		return false
	}
	p := store.passwordParameters
	prefix := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$", p.MemoryKiB, p.Iterations, p.Parallelism)
	encoded, found := strings.CutPrefix(hash, prefix)
	if !found {
		return false
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 2 {
		return false
	}
	for i, size := range []uint32{p.SaltBytes, p.KeyBytes} {
		bytes, err := base64.RawStdEncoding.Strict().DecodeString(parts[i])
		if err != nil || len(bytes) != int(size) || base64.RawStdEncoding.EncodeToString(bytes) != parts[i] {
			return false
		}
	}
	return true
}
