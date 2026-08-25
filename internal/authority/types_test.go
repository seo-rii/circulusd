package authority_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/authority"
)

func TestNewValidatorFailsClosedOnInvalidConfiguration(t *testing.T) {
	t.Parallel()

	_, reader, clock, _ := newFixture(t)
	tests := []struct {
		name   string
		config authority.Config
	}{
		{name: "missing reader", config: authority.Config{HMACSecret: []byte(strings.Repeat("s", 32)), AuthorityTTL: time.Minute, Now: clock.Now}},
		{name: "short secret", config: authority.Config{SnapshotReader: reader, HMACSecret: []byte("short"), AuthorityTTL: time.Minute, Now: clock.Now}},
		{name: "zero TTL", config: authority.Config{SnapshotReader: reader, HMACSecret: []byte(strings.Repeat("s", 32)), Now: clock.Now}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := authority.NewValidator(test.config); !errors.Is(err, authority.ErrInvalidConfig) {
				t.Fatalf("NewValidator() error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestIssueRejectsInvalidBindingSnapshotAndPermissions(t *testing.T) {
	t.Parallel()

	validator, reader, _, scope := newFixture(t)
	if _, err := validator.Issue(context.Background(), authority.ServiceBinding("arbitrary"), authority.IssueRequest{
		Scope: scope, Permissions: []authority.Permission{permissionWorkspaceRead},
	}); !errors.Is(err, authority.ErrInvalidRequest) {
		t.Fatalf("Issue(invalid binding) error = %v, want ErrInvalidRequest", err)
	}
	if _, err := validator.Issue(context.Background(), authority.BindingWorkspace, authority.IssueRequest{Scope: scope}); !errors.Is(err, authority.ErrInvalidRequest) {
		t.Fatalf("Issue(empty permissions) error = %v, want ErrInvalidRequest", err)
	}
	if _, err := validator.Issue(context.Background(), authority.BindingWorkspace, authority.IssueRequest{
		Scope: scope, Permissions: []authority.Permission{permissionWorkspaceRead, permissionWorkspaceRead},
	}); !errors.Is(err, authority.ErrInvalidRequest) {
		t.Fatalf("Issue(duplicate permissions) error = %v, want ErrInvalidRequest", err)
	}

	reader.Update(func(snapshot *authority.Snapshot) { snapshot.PolicySnapshotDigest = "not-a-digest" })
	if _, err := validator.Issue(context.Background(), authority.BindingWorkspace, authority.IssueRequest{
		Scope: scope, Permissions: []authority.Permission{permissionWorkspaceRead},
	}); !errors.Is(err, authority.ErrInvalidSnapshot) {
		t.Fatalf("Issue(invalid snapshot) error = %v, want ErrInvalidSnapshot", err)
	}
}

func TestTurnAuthorityIsNotASettlementCredential(t *testing.T) {
	t.Parallel()

	if _, accepted := any(authority.TurnAuthority{}).(authority.SettlementCredential); accepted {
		t.Fatal("TurnAuthority unexpectedly implements SettlementCredential")
	}
	if _, accepted := any(authority.SettlementAuthority{}).(authority.SettlementCredential); !accepted {
		t.Fatal("SettlementAuthority does not implement SettlementCredential")
	}
}

func TestAuthorityInputsRequireCanonicalIdentifiers(t *testing.T) {
	t.Parallel()

	validator, _, _, scope := newFixture(t)
	for _, invalidUserID := range []string{"use\u0301r", "user\nforged"} {
		invalidScope := scope
		invalidScope.UserID = invalidUserID
		if _, err := validator.Issue(
			context.Background(),
			authority.BindingWorkspace,
			authority.IssueRequest{
				Scope:       invalidScope,
				Permissions: []authority.Permission{permissionWorkspaceRead},
			},
		); !errors.Is(err, authority.ErrInvalidRequest) {
			t.Fatalf("Issue(user ID %q) error = %v, want ErrInvalidRequest", invalidUserID, err)
		}
	}
	if _, err := validator.Issue(
		context.Background(),
		authority.BindingWorkspace,
		authority.IssueRequest{
			Scope:       scope,
			Permissions: []authority.Permission{"workspace.\nread"},
		},
	); !errors.Is(err, authority.ErrInvalidRequest) {
		t.Fatalf("Issue(control permission) error = %v, want ErrInvalidRequest", err)
	}
}
