package authstate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/auth"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/dependency"
	proof "github.com/hancomac/circulusd/internal/dependency/contracttest"
	"github.com/hancomac/circulusd/internal/identity"
)

type accountFixture struct {
	store         *AccountStore
	source        *fileSource
	now           atomic.Int64
	account       auth.Account
	authenticator *auth.Authenticator
	password      string
}

func newAccountFixture(t *testing.T, bound int, disabled bool) *accountFixture {
	t.Helper()
	p := proof.NewProductionProofs(t, []dependency.AtomicGroup{AtomicAccountAudit})
	source := &fileSource{ProductionProofs: p, directory: t.TempDir()}
	f := &accountFixture{source: source, password: "fixture-password-please-do-not-store"}
	f.now.Store(time.Unix(2_000_000_000, 123).UnixNano())
	parameters := auth.Argon2idParams{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1, SaltBytes: 16, KeyBytes: 32}
	hash, err := auth.HashPassword(f.password, parameters, bytes.NewReader(bytes.Repeat([]byte{2}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	f.account = auth.Account{TenantID: typedID(t, identity.Tenant), UserID: typedID(t, identity.Subject), Username: "alice", PasswordHash: hash, Disabled: disabled, Version: 1}
	store, err := NewAccountStore(AccountConfig{Config: Config{Source: proof.Verify[Source](t, p, source, []dependency.AtomicGroup{AtomicAccountAudit}), TenantID: f.account.TenantID, Now: f.clock, MaximumAuditEntries: bound},
		LoginPolicy: auth.LoginPolicy{MaximumFailures: 2, LockoutDuration: time.Minute}, PasswordParameters: parameters})
	if err != nil {
		t.Fatal(err)
	}
	f.store = store
	if err := store.CreateAccount(context.Background(), f.account); err != nil {
		t.Fatal(err)
	}
	dummy, err := auth.HashPassword("unusable-dummy-fixture-password", parameters, bytes.NewReader(bytes.Repeat([]byte{3}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	f.authenticator, err = auth.NewAuthenticator(auth.AuthenticatorConfig{Store: store, PasswordParameters: parameters, DummyPasswordHash: dummy,
		LoginPolicy: store.policy, Now: f.clock, MaximumCASRetries: 64, MaximumParallelHashes: 2})
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *accountFixture) clock() time.Time { return time.Unix(0, f.now.Load()).UTC() }

func TestAccountStoreRequiresIndependentAccountAuditAndImmutablePolicy(t *testing.T) {
	if _, err := NewAccountStore(AccountConfig{}); !errors.Is(err, dependency.ErrUnverifiedDependency) {
		t.Fatal(err)
	}
	f := newAccountFixture(t, 0, false)
	config := AccountConfig{Config: Config{Source: f.store.binding, TenantID: f.account.TenantID, Now: f.clock}, LoginPolicy: f.store.policy, PasswordParameters: f.store.passwordParameters}
	for _, mode := range []string{"credential-capability", "failures", "duration", "password-cost", "changed-policy"} {
		t.Run(mode, func(t *testing.T) {
			c := config
			switch mode {
			case "credential-capability":
				p := proof.NewProductionProofs(t, []dependency.AtomicGroup{AtomicCredentialAudit})
				source := &fileSource{ProductionProofs: p, directory: t.TempDir()}
				c.Source = proof.Verify[Source](t, p, source, p.Descriptor().AtomicGroups)
			case "failures":
				c.LoginPolicy.MaximumFailures = 0
			case "duration":
				c.LoginPolicy.LockoutDuration = -time.Second
			case "password-cost":
				c.PasswordParameters.MemoryKiB = 512 * 1024
			case "changed-policy":
				c.LoginPolicy.MaximumFailures++
			}
			store, err := NewAccountStore(c)
			if mode == "changed-policy" {
				if err != nil {
					t.Fatal(err)
				}
				if _, err = store.LoadAccount(context.Background(), "alice"); !errors.Is(err, ErrCorruptState) {
					t.Fatal("weakened durable lockout policy", err)
				}
				return
			}
			if err == nil {
				t.Fatal("invalid account configuration accepted")
			}
		})
	}
}

func TestActualLocalAuthenticatorPersistsLockoutAndMonotonicAuditAfterReopen(t *testing.T) {
	f := newAccountFixture(t, 0, false)
	for range 2 {
		f.now.Add(int64(time.Second))
		result, err := f.authenticator.Authenticate(context.Background(), "alice", "wrong-password")
		if err != nil || result.Status != auth.LoginInvalidCredentials || result.TenantID != "" {
			t.Fatal(result, err)
		}
	}
	current, err := f.store.LoadAccount(context.Background(), "alice")
	if err != nil || current.FailedAttempts != 2 || current.Version != 3 || !current.LockedUntil.Equal(f.clock().Add(time.Minute)) {
		t.Fatal(current.Version, err)
	}
	if result, err := f.authenticator.Authenticate(context.Background(), "alice", f.password); err != nil || result.Status != auth.LoginInvalidCredentials {
		t.Fatal("locked account logged in", err)
	}
	locked, err := f.store.LoadAccount(context.Background(), "alice")
	if err != nil || !sameAccount(locked, current) {
		t.Fatal("locked attempt changed current account", err)
	}
	f.now.Add(int64(61 * time.Second))
	result, err := f.authenticator.Authenticate(context.Background(), "alice", f.password)
	if err != nil || result.Status != auth.LoginAuthenticated || result.TenantID != f.account.TenantID || result.UserID != f.account.UserID {
		t.Fatal(result, err)
	}
	source := &fileSource{ProductionProofs: f.source.ProductionProofs, directory: f.source.directory}
	reopened, err := NewAccountStore(AccountConfig{Config: Config{Source: proof.Verify[Source](t, source.ProductionProofs, source, []dependency.AtomicGroup{AtomicAccountAudit}), TenantID: f.account.TenantID, Now: f.clock}, LoginPolicy: f.store.policy, PasswordParameters: f.store.passwordParameters})
	if err != nil {
		t.Fatal(err)
	}
	current, err = reopened.LoadAccount(context.Background(), "alice")
	if err != nil || current.Version != 4 || current.FailedAttempts != 0 || !current.LockedUntil.IsZero() || !current.LastAuthenticatedAt.Equal(f.clock()) {
		t.Fatal("reopen lost successful authentication", err)
	}
	page, err := reopened.ReadAudit(context.Background(), 0, 1024)
	if err != nil || len(page.Entries) != 5 || page.Entries[3].Event.Status != auth.LoginLocked || page.Entries[3].AccountVersion != 3 {
		t.Fatal("lockout audit chain missing", err)
	}
	frame, err := source.read(reopened.objectID)
	if err != nil || page.StateDigest != sha256.Sum256(frame.State) || page.TenantID != f.account.TenantID || page.ObjectID != reopened.objectID {
		t.Fatal("account audit snapshot relabeled", err)
	}
	snapshot, err := reopened.ReadAuditSnapshot(context.Background())
	if err != nil || snapshot.StateDigest != page.StateDigest || snapshot.HeadSequence != 5 || snapshot.HeadDigest != page.HeadDigest {
		t.Fatal(err)
	}
	for _, entry := range page.Entries {
		if strings.Contains(entry.String(), f.account.PasswordHash) {
			t.Fatal("audit exposes password hash")
		}
	}
	if bytes.Contains(frame.State, []byte(f.password)) {
		t.Fatal("plaintext password stored")
	}
}

func TestLoginCASAuditAndCapacityCannotPublishUnauditedSuccess(t *testing.T) {
	for _, mode := range []string{"write", "capacity", "barrier", "wrong-token", "disabled", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			bound := 0
			if mode == "capacity" {
				bound = 1
			}
			f := newAccountFixture(t, bound, mode == "disabled")
			username := "alice"
			switch mode {
			case "write":
				f.source.failWrite = true
			case "barrier":
				f.source.failBarrier = true
			case "wrong-token":
				f.source.wrongToken = true
			case "unknown":
				username = "missing"
			}
			result, err := f.authenticator.Authenticate(context.Background(), username, f.password)
			if mode == "disabled" || mode == "unknown" {
				if err != nil || result.Status != auth.LoginInvalidCredentials || result.TenantID != "" || result.UserID != "" {
					t.Fatal("generic login response lost", err)
				}
			} else if err == nil || result != (auth.AuthenticationResult{}) || strings.Contains(err.Error(), "private-native") {
				t.Fatal("unaudited success escaped", err)
			}
			f.source.failWrite, f.source.failBarrier, f.source.wrongToken = false, false, false
			current, loadErr := f.store.LoadAccount(context.Background(), "alice")
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			page, auditErr := f.store.ReadAudit(context.Background(), 0, 1024)
			if auditErr != nil {
				t.Fatal(auditErr)
			}
			switch mode {
			case "barrier", "wrong-token":
				if current.Version != 2 || len(page.Entries) != 2 {
					t.Fatal("lost committed atomic account audit")
				}
			case "disabled":
				if current.Version != 1 || len(page.Entries) != 2 || page.Entries[1].Event.Status != auth.LoginDisabled {
					t.Fatal("disabled login not audited")
				}
			case "unknown":
				if current.Version != 1 || len(page.Entries) != 2 || page.Entries[1].Event.UserID != "" || page.Entries[1].AccountVersion != 0 {
					t.Fatal("unknown login was misattributed")
				}
			default:
				if current.Version != 1 || len(page.Entries) != 1 {
					t.Fatal("failed audit did not roll back account mutation")
				}
			}
		})
	}
}

func TestAccountTransitionsRejectStalePasswordProofAndCallerPolicyChanges(t *testing.T) {
	for _, mode := range []string{"stale", "password", "disable", "tenant", "user", "count", "status", "time", "old-time", "missing-became-known"} {
		t.Run(mode, func(t *testing.T) {
			f := newAccountFixture(t, 0, false)
			f.now.Add(int64(time.Second))
			current := f.account
			next, status, err := auth.ApplyLoginAttempt(current, f.clock(), true, f.store.policy)
			if err != nil {
				t.Fatal(err)
			}
			event := auth.LoginAuditEvent{At: f.clock(), Username: "alice", TenantID: current.TenantID, UserID: current.UserID, Status: status}
			version := current.Version
			versionPtr, nextPtr := &version, &next
			want := auth.ErrInvalidCredential
			switch mode {
			case "stale":
				if _, err := f.authenticator.Authenticate(context.Background(), "alice", "wrong-password"); err != nil {
					t.Fatal(err)
				}
				want = auth.ErrAccountVersionConflict
			case "password":
				next.PasswordHash = strings.Replace(next.PasswordHash, "$m=8192,", "$m=16384,", 1)
			case "disable":
				next.Disabled = true
			case "tenant":
				next.TenantID = current.UserID
			case "user":
				next.UserID = current.TenantID
			case "count":
				next.FailedAttempts++
			case "status":
				event.Status = auth.LoginInvalidCredentials
			case "time":
				event.At = f.clock().Add(time.Second)
				want = auth.ErrAuthenticationClock
			case "old-time":
				event.At = f.clock().Add(-2 * time.Second)
				want = auth.ErrAuthenticationClock
			case "missing-became-known":
				versionPtr, nextPtr = nil, nil
				event.TenantID, event.UserID, event.Status = "", "", auth.LoginInvalidCredentials
				want = auth.ErrAccountVersionConflict
			}
			if err := f.store.CommitLoginAttempt(context.Background(), "alice", versionPtr, nextPtr, event); !errors.Is(err, want) {
				t.Fatalf("got %v want %v", err, want)
			}
		})
	}
}

func TestAccountAuditTamperingAndCancellationFailClosed(t *testing.T) {
	for _, mode := range []string{"chain", "account", "event", "policy", "malformed", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			f := newAccountFixture(t, 0, false)
			if mode == "cancelled" {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				before := f.source.transactions.Load()
				if _, err := f.store.LoadAccount(ctx, "alice"); !errors.Is(err, context.Canceled) || f.source.transactions.Load() != before {
					t.Fatal("cancelled login reached native store", err)
				}
				return
			}
			frame, err := f.source.read(f.store.objectID)
			if err != nil {
				t.Fatal(err)
			}
			value, err := canonical.Decode(frame.State, canonical.DefaultOptions())
			if err != nil {
				t.Fatal(err)
			}
			state := value.(canonical.Map)
			switch mode {
			case "chain":
				state["headDigest"] = zeroDigest
			case "account":
				state["accounts"].(canonical.Array)[0].(canonical.Map)["disabled"] = true
			case "event":
				state["audit"].(canonical.Array)[0].(canonical.Map)["event"].(canonical.Map)["userId"] = "different"
			case "policy":
				state["policy"].(canonical.Map)["maximumFailures"] = int64(100)
			case "malformed":
				state["policy"] = canonical.Map{"invalid": canonical.Array{true}}
			}
			frame.State, err = canonical.Encode(state, canonical.DefaultOptions())
			if err != nil {
				t.Fatal(err)
			}
			if err := f.source.persist(f.store.objectID, frame); err != nil {
				t.Fatal(err)
			}
			if _, err := f.store.LoadAccount(context.Background(), "alice"); !errors.Is(err, ErrCorruptState) {
				t.Fatal("corrupt account accepted", err)
			}
			if info, err := os.Stat(f.source.path(f.store.objectID)); err != nil || info.Mode().Perm()&0o077 != 0 {
				t.Fatal("fixture credential file permissions", err)
			}
		})
	}
}
