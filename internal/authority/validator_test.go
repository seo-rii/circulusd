package authority_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/authority"
)

const (
	permissionWorkspaceRead  authority.Permission = "workspace.read"
	permissionWorkspaceWrite authority.Permission = "workspace.write"
	permissionEffectSettle   authority.Permission = "state.effect.settle"
)

func TestIssueAndAdmissionReadAuthoritativeSnapshotEveryTime(t *testing.T) {
	t.Parallel()

	validator, reader, _, scope := newFixture(t)
	handle := issueAuthority(t, validator, scope)
	if got := reader.reads.Load(); got != 1 {
		t.Fatalf("snapshot reads after Issue() = %d, want 1", got)
	}

	request := authority.AdmissionRequest{Scope: scope, Permission: permissionWorkspaceRead}
	if err := validator.ValidateAdmission(context.Background(), handle, authority.BindingWorkspace, request); err != nil {
		t.Fatalf("ValidateAdmission() error = %v", err)
	}
	if got := reader.reads.Load(); got != 2 {
		t.Fatalf("snapshot reads after admission = %d, want 2", got)
	}

	reader.Update(func(snapshot *authority.Snapshot) {
		snapshot.EffectivePermissions = []authority.Permission{permissionEffectSettle}
	})
	if err := validator.ValidateAdmission(context.Background(), handle, authority.BindingWorkspace, request); !errors.Is(err, authority.ErrPermissionDenied) {
		t.Fatalf("ValidateAdmission(revoked permission) error = %v, want ErrPermissionDenied", err)
	}
	if got := reader.reads.Load(); got != 3 {
		t.Fatalf("snapshot reads after revoked admission = %d, want 3", got)
	}
}

func TestAdmissionRejectsForgedScopeAndServiceReuse(t *testing.T) {
	t.Parallel()

	validator, _, _, scope := newFixture(t)
	handle := issueAuthority(t, validator, scope)

	tests := []struct {
		name   string
		mutate func(*authority.Scope)
	}{
		{name: "tenant", mutate: func(value *authority.Scope) { value.TenantID = "tenant-forged" }},
		{name: "user", mutate: func(value *authority.Scope) { value.UserID = "user-forged" }},
		{name: "session", mutate: func(value *authority.Scope) { value.SessionID = "session-forged" }},
		{name: "turn", mutate: func(value *authority.Scope) { value.TurnID = "turn-forged" }},
		{name: "runtime", mutate: func(value *authority.Scope) { value.RuntimeRevision = "runtime-forged" }},
		{name: "workspace", mutate: func(value *authority.Scope) { value.WorkspaceID = "workspace-forged" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			forged := scope
			test.mutate(&forged)
			err := validator.ValidateAdmission(
				context.Background(),
				handle,
				authority.BindingWorkspace,
				authority.AdmissionRequest{Scope: forged, Permission: permissionWorkspaceRead},
			)
			if !errors.Is(err, authority.ErrScopeMismatch) {
				t.Fatalf("ValidateAdmission(forged %s) error = %v, want ErrScopeMismatch", test.name, err)
			}
		})
	}

	err := validator.ValidateAdmission(
		context.Background(),
		handle,
		authority.BindingExecutor,
		authority.AdmissionRequest{Scope: scope, Permission: permissionWorkspaceRead},
	)
	if !errors.Is(err, authority.ErrServiceBindingMismatch) {
		t.Fatalf("ValidateAdmission(other service) error = %v, want ErrServiceBindingMismatch", err)
	}
}

func TestAdmissionRejectsExpiredOrForgedAuthority(t *testing.T) {
	t.Parallel()

	validator, reader, clock, scope := newFixture(t)
	handle := issueAuthority(t, validator, scope)
	request := authority.AdmissionRequest{Scope: scope, Permission: permissionWorkspaceRead}

	if err := validator.ValidateAdmission(context.Background(), authority.TurnAuthority{}, authority.BindingWorkspace, request); !errors.Is(err, authority.ErrInvalidAuthority) {
		t.Fatalf("ValidateAdmission(zero) error = %v, want ErrInvalidAuthority", err)
	}
	otherValidator, err := authority.NewValidator(authority.Config{
		SnapshotReader: reader,
		HMACSecret:     []byte(strings.Repeat("z", 32)),
		AuthorityTTL:   10 * time.Minute,
		Now:            clock.Now,
	})
	if err != nil {
		t.Fatalf("NewValidator(other key) error = %v", err)
	}
	if err := otherValidator.ValidateAdmission(context.Background(), handle, authority.BindingWorkspace, request); !errors.Is(err, authority.ErrInvalidAuthority) {
		t.Fatalf("ValidateAdmission(other signer) error = %v, want ErrInvalidAuthority", err)
	}

	clock.Advance(10 * time.Minute)
	if err := validator.ValidateAdmission(context.Background(), handle, authority.BindingWorkspace, request); !errors.Is(err, authority.ErrAuthorityExpired) {
		t.Fatalf("ValidateAdmission(expired) error = %v, want ErrAuthorityExpired", err)
	}
}

func TestExpiredAdmissionAndRenewalStillReadAuthoritativeSnapshot(t *testing.T) {
	t.Parallel()

	validator, reader, clock, scope := newFixture(t)
	handle := issueAuthority(t, validator, scope)
	clock.Advance(10 * time.Minute)

	request := authority.AdmissionRequest{Scope: scope, Permission: permissionWorkspaceRead}
	if err := validator.ValidateAdmission(context.Background(), handle, authority.BindingWorkspace, request); !errors.Is(err, authority.ErrAuthorityExpired) {
		t.Fatalf("ValidateAdmission(expired) error = %v, want ErrAuthorityExpired", err)
	}
	if got := reader.reads.Load(); got != 2 {
		t.Fatalf("snapshot reads after expired admission = %d, want 2", got)
	}
	if _, err := validator.Renew(context.Background(), handle, authority.BindingWorkspace); !errors.Is(err, authority.ErrAuthorityExpired) {
		t.Fatalf("Renew(expired) error = %v, want ErrAuthorityExpired", err)
	}
	if got := reader.reads.Load(); got != 3 {
		t.Fatalf("snapshot reads after expired renewal = %d, want 3", got)
	}
}

func TestAdmissionAndRenewalRecheckTimeAfterSnapshotRead(t *testing.T) {
	t.Parallel()

	for _, operation := range []string{"admission", "renewal"} {
		t.Run(operation, func(t *testing.T) {
			t.Parallel()

			issuer, reader, clock, scope := newFixture(t)
			handle := issueAuthority(t, issuer, scope)
			delayed, err := authority.NewValidator(authority.Config{
				SnapshotReader: advancingSnapshotReader{
					SnapshotReader: reader,
					clock:          clock,
					advance:        10 * time.Minute,
				},
				HMACSecret:   []byte(strings.Repeat("s", 32)),
				AuthorityTTL: 10 * time.Minute,
				Now:          clock.Now,
			})
			if err != nil {
				t.Fatalf("NewValidator() error = %v", err)
			}

			if operation == "admission" {
				err = delayed.ValidateAdmission(
					context.Background(),
					handle,
					authority.BindingWorkspace,
					authority.AdmissionRequest{
						Scope:      scope,
						Permission: permissionWorkspaceRead,
					},
				)
			} else {
				_, err = delayed.Renew(
					context.Background(),
					handle,
					authority.BindingWorkspace,
				)
			}
			if !errors.Is(err, authority.ErrAuthorityExpired) {
				t.Fatalf("%s after delayed snapshot error = %v, want ErrAuthorityExpired", operation, err)
			}
		})
	}
}

func TestAdmissionRejectsEveryGenerationAndPolicyRotation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*authority.Snapshot)
		want   error
	}{
		{name: "turn lease generation", mutate: func(value *authority.Snapshot) { value.TurnLeaseGeneration++ }, want: authority.ErrStaleTurnLease},
		{name: "placement generation", mutate: func(value *authority.Snapshot) { value.PlacementGeneration++ }, want: authority.ErrStalePlacement},
		{name: "authorization generation", mutate: func(value *authority.Snapshot) { value.AuthorizationGeneration++ }, want: authority.ErrStaleAuthorization},
		{name: "runtime revision", mutate: func(value *authority.Snapshot) { value.Scope.RuntimeRevision = "runtime-next" }, want: authority.ErrRuntimeChanged},
		{name: "immutable policy snapshot", mutate: func(value *authority.Snapshot) { value.PolicySnapshotDigest = digest("c") }, want: authority.ErrPolicySnapshotChanged},
		{name: "emergency overlay", mutate: func(value *authority.Snapshot) { value.EmergencyOverlayDigest = digest("d") }, want: authority.ErrEmergencyOverlayChanged},
		{name: "session inactive", mutate: func(value *authority.Snapshot) { value.SessionStatus = authority.SessionClosed }, want: authority.ErrInactiveSession},
		{name: "turn inactive", mutate: func(value *authority.Snapshot) { value.TurnStatus = authority.TurnCompleted }, want: authority.ErrInactiveTurn},
		{name: "lease invalid", mutate: func(value *authority.Snapshot) { value.LeaseActive = false }, want: authority.ErrLeaseInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			validator, reader, _, scope := newFixture(t)
			handle := issueAuthority(t, validator, scope)
			reader.Update(test.mutate)
			err := validator.ValidateAdmission(
				context.Background(),
				handle,
				authority.BindingWorkspace,
				authority.AdmissionRequest{Scope: scope, Permission: permissionWorkspaceRead},
			)
			if !errors.Is(err, test.want) {
				t.Fatalf("ValidateAdmission() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestAdmissionRequiresClaimedAndCurrentlyEffectivePermission(t *testing.T) {
	t.Parallel()

	validator, _, _, scope := newFixture(t)
	handle, err := validator.Issue(context.Background(), authority.BindingWorkspace, authority.IssueRequest{
		Scope:       scope,
		Permissions: []authority.Permission{permissionWorkspaceRead},
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	err = validator.ValidateAdmission(
		context.Background(),
		handle,
		authority.BindingWorkspace,
		authority.AdmissionRequest{Scope: scope, Permission: permissionWorkspaceWrite},
	)
	if !errors.Is(err, authority.ErrPermissionDenied) {
		t.Fatalf("ValidateAdmission(unclaimed permission) error = %v, want ErrPermissionDenied", err)
	}
}

func TestRenewalExtendsTTLWithoutChangingTurnOrGenerations(t *testing.T) {
	t.Parallel()

	validator, reader, clock, scope := newFixture(t)
	original := issueAuthority(t, validator, scope)
	clock.Advance(5 * time.Minute)
	renewed, err := validator.Renew(context.Background(), original, authority.BindingWorkspace)
	if err != nil {
		t.Fatalf("Renew() error = %v", err)
	}
	if got := reader.reads.Load(); got != 2 {
		t.Fatalf("snapshot reads after Issue/Renew = %d, want 2", got)
	}

	clock.Advance(6 * time.Minute)
	request := authority.AdmissionRequest{Scope: scope, Permission: permissionWorkspaceRead}
	if err := validator.ValidateAdmission(context.Background(), original, authority.BindingWorkspace, request); !errors.Is(err, authority.ErrAuthorityExpired) {
		t.Fatalf("ValidateAdmission(original) error = %v, want ErrAuthorityExpired", err)
	}
	if err := validator.ValidateAdmission(context.Background(), renewed, authority.BindingWorkspace, request); err != nil {
		t.Fatalf("ValidateAdmission(renewed) error = %v", err)
	}
}

func TestRenewalRejectsExpiredRotatedOrInvalidLease(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*mutableClock, *snapshotReader)
		want   error
	}{
		{name: "expired authority", mutate: func(clock *mutableClock, _ *snapshotReader) { clock.Advance(10 * time.Minute) }, want: authority.ErrAuthorityExpired},
		{name: "inactive lease", mutate: func(_ *mutableClock, reader *snapshotReader) {
			reader.Update(func(value *authority.Snapshot) { value.LeaseActive = false })
		}, want: authority.ErrLeaseInvalid},
		{name: "expired lease", mutate: func(clock *mutableClock, reader *snapshotReader) {
			reader.Update(func(value *authority.Snapshot) { value.LeaseExpiresAt = clock.Now() })
		}, want: authority.ErrLeaseInvalid},
		{name: "turn lease rotated", mutate: func(_ *mutableClock, reader *snapshotReader) {
			reader.Update(func(value *authority.Snapshot) { value.TurnLeaseGeneration++ })
		}, want: authority.ErrStaleTurnLease},
		{name: "placement rotated", mutate: func(_ *mutableClock, reader *snapshotReader) {
			reader.Update(func(value *authority.Snapshot) { value.PlacementGeneration++ })
		}, want: authority.ErrStalePlacement},
		{name: "authorization rotated", mutate: func(_ *mutableClock, reader *snapshotReader) {
			reader.Update(func(value *authority.Snapshot) { value.AuthorizationGeneration++ })
		}, want: authority.ErrStaleAuthorization},
		{name: "policy snapshot changed", mutate: func(_ *mutableClock, reader *snapshotReader) {
			reader.Update(func(value *authority.Snapshot) { value.PolicySnapshotDigest = digest("e") })
		}, want: authority.ErrPolicySnapshotChanged},
		{name: "emergency overlay changed", mutate: func(_ *mutableClock, reader *snapshotReader) {
			reader.Update(func(value *authority.Snapshot) { value.EmergencyOverlayDigest = digest("f") })
		}, want: authority.ErrEmergencyOverlayChanged},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			validator, reader, clock, scope := newFixture(t)
			handle := issueAuthority(t, validator, scope)
			test.mutate(clock, reader)
			if _, err := validator.Renew(context.Background(), handle, authority.BindingWorkspace); !errors.Is(err, test.want) {
				t.Fatalf("Renew() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestSettlementOutlivesAuthorityTTLAndBindsExactEffect(t *testing.T) {
	t.Parallel()

	validator, reader, clock, scope := newFixture(t)
	reader.Update(func(snapshot *authority.Snapshot) {
		snapshot.ActiveEffect = &authority.EffectSnapshot{
			EffectID:     "effect-long-command",
			InvocationID: "invocation-long-command",
			Status:       authority.EffectDispatched,
		}
	})
	settlement := authority.SettlementRequest{
		Scope:        scope,
		Permission:   permissionEffectSettle,
		EffectID:     "effect-long-command",
		InvocationID: "invocation-long-command",
	}
	settlementOnly, err := validator.IssueSettlementAuthority(
		context.Background(),
		authority.BindingWorkspace,
		settlement,
	)
	if err != nil {
		t.Fatalf("IssueSettlementAuthority() error = %v", err)
	}
	original := issueAuthority(t, validator, scope)
	clock.Advance(5 * time.Minute)
	handle, err := validator.Renew(context.Background(), original, authority.BindingWorkspace)
	if err != nil {
		t.Fatalf("Renew() error = %v", err)
	}
	clock.Advance(11 * time.Minute)

	admission := authority.AdmissionRequest{Scope: scope, Permission: permissionWorkspaceRead}
	if err := validator.ValidateAdmission(context.Background(), handle, authority.BindingWorkspace, admission); !errors.Is(err, authority.ErrAuthorityExpired) {
		t.Fatalf("ValidateAdmission(expired) error = %v, want ErrAuthorityExpired", err)
	}
	if err := validator.ValidateSettlement(context.Background(), settlementOnly, authority.BindingWorkspace, settlement); err != nil {
		t.Fatalf("ValidateSettlement(long command) error = %v", err)
	}

	wrongEffect := settlement
	wrongEffect.EffectID = "effect-forged"
	if err := validator.ValidateSettlement(context.Background(), settlementOnly, authority.BindingWorkspace, wrongEffect); !errors.Is(err, authority.ErrEffectMismatch) {
		t.Fatalf("ValidateSettlement(wrong effect) error = %v, want ErrEffectMismatch", err)
	}
	wrongInvocation := settlement
	wrongInvocation.InvocationID = "invocation-forged"
	if err := validator.ValidateSettlement(context.Background(), settlementOnly, authority.BindingWorkspace, wrongInvocation); !errors.Is(err, authority.ErrEffectMismatch) {
		t.Fatalf("ValidateSettlement(wrong invocation) error = %v, want ErrEffectMismatch", err)
	}

	reader.Update(func(snapshot *authority.Snapshot) { snapshot.PlacementGeneration++ })
	if err := validator.ValidateSettlement(context.Background(), settlementOnly, authority.BindingWorkspace, settlement); !errors.Is(err, authority.ErrStalePlacement) {
		t.Fatalf("ValidateSettlement(stale placement) error = %v, want ErrStalePlacement", err)
	}
}

func TestSettlementRejectsEveryGenerationRotation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*authority.Snapshot)
		want   error
	}{
		{name: "turn lease", mutate: func(snapshot *authority.Snapshot) { snapshot.TurnLeaseGeneration++ }, want: authority.ErrStaleTurnLease},
		{name: "placement", mutate: func(snapshot *authority.Snapshot) { snapshot.PlacementGeneration++ }, want: authority.ErrStalePlacement},
		{name: "authorization", mutate: func(snapshot *authority.Snapshot) { snapshot.AuthorizationGeneration++ }, want: authority.ErrStaleAuthorization},
		{name: "policy snapshot", mutate: func(snapshot *authority.Snapshot) { snapshot.PolicySnapshotDigest = digest("7") }, want: authority.ErrPolicySnapshotChanged},
		{name: "emergency overlay", mutate: func(snapshot *authority.Snapshot) { snapshot.EmergencyOverlayDigest = digest("8") }, want: authority.ErrEmergencyOverlayChanged},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			validator, reader, _, scope := newFixture(t)
			reader.Update(func(snapshot *authority.Snapshot) {
				snapshot.ActiveEffect = &authority.EffectSnapshot{
					EffectID:     "effect-generation-test",
					InvocationID: "invocation-generation-test",
					Status:       authority.EffectDispatched,
				}
			})
			request := authority.SettlementRequest{
				Scope:        scope,
				Permission:   permissionEffectSettle,
				EffectID:     "effect-generation-test",
				InvocationID: "invocation-generation-test",
			}
			handle, err := validator.IssueSettlementAuthority(
				context.Background(),
				authority.BindingWorkspace,
				request,
			)
			if err != nil {
				t.Fatalf("IssueSettlementAuthority() error = %v", err)
			}
			reader.Update(test.mutate)
			if err := validator.ValidateSettlement(context.Background(), handle, authority.BindingWorkspace, request); !errors.Is(err, test.want) {
				t.Fatalf("ValidateSettlement() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestEmergencyRotationCanIssueSettlementOnlyAuthority(t *testing.T) {
	t.Parallel()

	validator, reader, _, scope := newFixture(t)
	reader.Update(func(snapshot *authority.Snapshot) {
		snapshot.ActiveEffect = &authority.EffectSnapshot{
			EffectID:     "effect-recovery",
			InvocationID: "invocation-recovery",
			Status:       authority.EffectDispatched,
		}
	})
	settlement := authority.SettlementRequest{
		Scope:        scope,
		Permission:   permissionEffectSettle,
		EffectID:     "effect-recovery",
		InvocationID: "invocation-recovery",
	}
	oldSettlementAuthority, err := validator.IssueSettlementAuthority(
		context.Background(),
		authority.BindingWorkspace,
		settlement,
	)
	if err != nil {
		t.Fatalf("IssueSettlementAuthority(old) error = %v", err)
	}
	reader.Update(func(snapshot *authority.Snapshot) {
		snapshot.AuthorizationGeneration++
		snapshot.EmergencyOverlayDigest = digest("9")
	})
	if err := validator.ValidateSettlement(context.Background(), oldSettlementAuthority, authority.BindingWorkspace, settlement); !errors.Is(err, authority.ErrStaleAuthorization) {
		t.Fatalf("ValidateSettlement(old authority) error = %v, want ErrStaleAuthorization", err)
	}

	settlementOnly, err := validator.IssueSettlementAuthority(context.Background(), authority.BindingWorkspace, settlement)
	if err != nil {
		t.Fatalf("IssueSettlementAuthority() error = %v", err)
	}
	if err := validator.ValidateSettlement(context.Background(), settlementOnly, authority.BindingWorkspace, settlement); err != nil {
		t.Fatalf("ValidateSettlement(settlement-only) error = %v", err)
	}
	if err := validator.ValidateSettlement(context.Background(), settlementOnly, authority.BindingExecutor, settlement); !errors.Is(err, authority.ErrServiceBindingMismatch) {
		t.Fatalf("ValidateSettlement(other service) error = %v, want ErrServiceBindingMismatch", err)
	}
}

func TestAuthorityFormattingAlwaysRedactsClaims(t *testing.T) {
	t.Parallel()

	validator, reader, _, scope := newFixture(t)
	scope.TenantID = "tenant-format-secret"
	scope.UserID = "user-format-secret"
	scope.SessionID = "session-format-secret"
	scope.TurnID = "turn-format-secret"
	scope.RuntimeRevision = "runtime-format-secret"
	scope.WorkspaceID = "workspace-format-secret"
	reader.Update(func(snapshot *authority.Snapshot) { snapshot.Scope = scope })
	handle := issueAuthority(t, validator, scope)

	formatted := fmt.Sprintf("%s|%v|%+v|%#v", handle, handle, handle, handle)
	for _, secret := range []string{scope.TenantID, scope.UserID, scope.SessionID, scope.WorkspaceID, scope.TurnID} {
		if strings.Contains(formatted, secret) {
			t.Fatalf("formatted authority leaked %q: %s", secret, formatted)
		}
	}
	if strings.Count(formatted, "redacted") != 4 {
		t.Fatalf("formatted authority = %q, want four redacted renderings", formatted)
	}

	reader.Update(func(snapshot *authority.Snapshot) {
		snapshot.ActiveEffect = &authority.EffectSnapshot{
			EffectID:     "effect-format-secret",
			InvocationID: "invocation-format-secret",
			Status:       authority.EffectDispatched,
		}
	})
	settlementOnly, err := validator.IssueSettlementAuthority(context.Background(), authority.BindingWorkspace, authority.SettlementRequest{
		Scope:        scope,
		Permission:   permissionEffectSettle,
		EffectID:     "effect-format-secret",
		InvocationID: "invocation-format-secret",
	})
	if err != nil {
		t.Fatalf("IssueSettlementAuthority() error = %v", err)
	}
	formatted = fmt.Sprintf("%s|%#v", settlementOnly, settlementOnly)
	if strings.Contains(formatted, "effect-format-secret") || strings.Count(formatted, "redacted") != 2 {
		t.Fatalf("formatted settlement authority leaked claims: %s", formatted)
	}
}

func TestConcurrentRotationAndAdmissionFailClosed(t *testing.T) {
	t.Parallel()

	validator, reader, _, scope := newFixture(t)
	handle := issueAuthority(t, validator, scope)
	request := authority.AdmissionRequest{Scope: scope, Permission: permissionWorkspaceRead}

	const workers = 32
	const attempts = 100
	start := make(chan struct{})
	errs := make(chan error, workers*attempts)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			for range attempts {
				errs <- validator.ValidateAdmission(context.Background(), handle, authority.BindingWorkspace, request)
			}
		}()
	}
	close(start)
	reader.Update(func(snapshot *authority.Snapshot) { snapshot.TurnLeaseGeneration++ })
	wait.Wait()
	close(errs)

	for err := range errs {
		if err != nil && !errors.Is(err, authority.ErrStaleTurnLease) {
			t.Fatalf("concurrent ValidateAdmission() error = %v", err)
		}
	}
	for range 100 {
		if err := validator.ValidateAdmission(context.Background(), handle, authority.BindingWorkspace, request); !errors.Is(err, authority.ErrStaleTurnLease) {
			t.Fatalf("post-rotation ValidateAdmission() error = %v, want ErrStaleTurnLease", err)
		}
	}
}

func TestIssueRejectsCallerScopeThatReaderDoesNotConfirm(t *testing.T) {
	t.Parallel()

	validator, _, _, scope := newFixture(t)
	forged := scope
	forged.SessionID = "session-not-authoritative"
	if _, err := validator.Issue(context.Background(), authority.BindingWorkspace, authority.IssueRequest{
		Scope:       forged,
		Permissions: []authority.Permission{permissionWorkspaceRead},
	}); !errors.Is(err, authority.ErrScopeMismatch) {
		t.Fatalf("Issue(forged session) error = %v, want ErrScopeMismatch", err)
	}
}

func newFixture(t *testing.T) (*authority.Validator, *snapshotReader, *mutableClock, authority.Scope) {
	t.Helper()

	clock := &mutableClock{now: time.Date(2026, time.August, 26, 12, 0, 0, 0, time.UTC)}
	scope := authority.Scope{
		TenantID:        "tenant-a",
		UserID:          "user-a",
		SessionID:       "session-a",
		TurnID:          "turn-a",
		RuntimeRevision: "runtime-a",
		WorkspaceID:     "workspace-a",
	}
	reader := &snapshotReader{snapshot: authority.Snapshot{
		Scope:                   scope,
		SessionStatus:           authority.SessionActive,
		TurnStatus:              authority.TurnActive,
		LeaseActive:             true,
		LeaseExpiresAt:          clock.Now().Add(time.Hour),
		TurnLeaseGeneration:     11,
		PlacementGeneration:     12,
		AuthorizationGeneration: 13,
		PolicySnapshotDigest:    digest("a"),
		EmergencyOverlayDigest:  digest("b"),
		EffectivePermissions: []authority.Permission{
			permissionWorkspaceRead,
			permissionWorkspaceWrite,
			permissionEffectSettle,
		},
	}}
	validator, err := authority.NewValidator(authority.Config{
		SnapshotReader: reader,
		HMACSecret:     []byte(strings.Repeat("s", 32)),
		AuthorityTTL:   10 * time.Minute,
		Now:            clock.Now,
	})
	if err != nil {
		t.Fatalf("NewValidator() error = %v", err)
	}
	return validator, reader, clock, scope
}

func issueAuthority(t *testing.T, validator *authority.Validator, scope authority.Scope) authority.TurnAuthority {
	t.Helper()

	handle, err := validator.Issue(context.Background(), authority.BindingWorkspace, authority.IssueRequest{
		Scope: scope,
		Permissions: []authority.Permission{
			permissionWorkspaceRead,
			permissionWorkspaceWrite,
			permissionEffectSettle,
		},
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	return handle
}

func digest(nibble string) string {
	return "sha256:" + strings.Repeat(nibble, 64)
}

type mutableClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *mutableClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *mutableClock) Advance(duration time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(duration)
	clock.mu.Unlock()
}

type snapshotReader struct {
	mu       sync.RWMutex
	snapshot authority.Snapshot
	reads    atomic.Int64
}

type advancingSnapshotReader struct {
	authority.SnapshotReader
	clock   *mutableClock
	advance time.Duration
}

func (reader advancingSnapshotReader) ReadSnapshot(
	ctx context.Context,
	sessionID string,
) (authority.Snapshot, error) {
	snapshot, err := reader.SnapshotReader.ReadSnapshot(ctx, sessionID)
	reader.clock.Advance(reader.advance)
	return snapshot, err
}

func (reader *snapshotReader) ReadSnapshot(ctx context.Context, _ string) (authority.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return authority.Snapshot{}, err
	}
	reader.reads.Add(1)
	reader.mu.RLock()
	snapshot := copySnapshot(reader.snapshot)
	reader.mu.RUnlock()
	return snapshot, nil
}

func (reader *snapshotReader) Update(update func(*authority.Snapshot)) {
	reader.mu.Lock()
	snapshot := copySnapshot(reader.snapshot)
	update(&snapshot)
	reader.snapshot = snapshot
	reader.mu.Unlock()
}

func copySnapshot(snapshot authority.Snapshot) authority.Snapshot {
	snapshot.EffectivePermissions = append([]authority.Permission(nil), snapshot.EffectivePermissions...)
	if snapshot.ActiveEffect != nil {
		effect := *snapshot.ActiveEffect
		snapshot.ActiveEffect = &effect
	}
	return snapshot
}
