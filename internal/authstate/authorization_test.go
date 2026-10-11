package authstate

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/hancomac/circulusd/internal/dependency"
	proof "github.com/hancomac/circulusd/internal/dependency/contracttest"
	"github.com/hancomac/circulusd/internal/identity"
	"github.com/hancomac/circulusd/internal/sessionevent"
)

type nativeAuthorizer struct {
	*proof.ProductionProofs
	permit sessionevent.AuthorizationPermit
	calls  int
	err    error
}

func (source *nativeAuthorizer) Authorize(context.Context, sessionevent.AuthorizationRequest) (sessionevent.AuthorizationPermit, error) {
	source.calls++
	return source.permit, source.err
}
func aclFixture(t *testing.T) (*Authorizer, *nativeAuthorizer, sessionevent.AuthorizationRequest) {
	t.Helper()
	groups := []dependency.AtomicGroup{AtomicACLAuthorization, dependency.AtomicCommandReceipt, dependency.AtomicEffectLifecycle, dependency.AtomicPublicEvent}
	p := proof.NewProductionProofs(t, groups)
	request := sessionevent.AuthorizationRequest{Operation: sessionevent.OperationCreateTurn,
		Principal: sessionevent.Principal{TenantID: typedID(t, identity.Tenant), SubjectID: typedID(t, identity.Subject)}, SessionID: typedID(t, identity.Session)}
	source := &nativeAuthorizer{ProductionProofs: p, permit: sessionevent.AuthorizationPermit{Operation: request.Operation,
		Principal: request.Principal, SessionID: request.SessionID, AuthorizationGeneration: 7, Proof: sessionevent.OpaqueAuthorizationProof{8}}}
	adapter, err := NewAuthorizer(proof.Verify[AuthorizationSource](t, p, source, groups))
	if err != nil {
		t.Fatal(err)
	}
	return adapter, source, request
}

func TestACLRequiresNativeCurrentSessionAuthorityAndPreservesOriginalProof(t *testing.T) {
	if _, err := NewAuthorizer(dependency.Verified[AuthorizationSource]{}); !errors.Is(err, dependency.ErrUnverifiedDependency) {
		t.Fatal(err)
	}
	p := proof.NewProductionProofs(t, []dependency.AtomicGroup{dependency.AtomicCommandReceipt, dependency.AtomicEffectLifecycle, dependency.AtomicPublicEvent})
	if _, err := NewAuthorizer(proof.Verify[AuthorizationSource](t, p, &nativeAuthorizer{ProductionProofs: p}, p.Descriptor().AtomicGroups)); !errors.Is(err, dependency.ErrRequirementMismatch) {
		t.Fatal("Session authority borrowed ACL capability", err)
	}
	adapter, source, request := aclFixture(t)
	permit, err := adapter.Authorize(context.Background(), request)
	if err != nil || permit != source.permit {
		t.Fatal("changed native authorization proof", err)
	}
	source.permit.AuthorizationGeneration++
	source.permit.Proof = sessionevent.OpaqueAuthorizationProof{9}
	permit, err = adapter.Authorize(context.Background(), request)
	if err != nil || permit != source.permit || source.calls != 2 {
		t.Fatal("cached old generation instead of querying current ACL", err)
	}
	verified := proof.Verify[sessioneventProductionAuthorizer](t, source.ProductionProofs, adapter, source.Descriptor().AtomicGroups)
	if operational, descriptor, err := verified.Open(); err != nil || operational != adapter || descriptor.TransactionDomainID != source.Descriptor().TransactionDomainID {
		t.Fatal("lost exact source binding", err)
	}
}

type sessioneventProductionAuthorizer interface {
	sessionevent.Authorizer
	dependency.ProductionProbe
}

func TestACLChecksScopeBeforeNativeIOAndRejectsCorruptDecisions(t *testing.T) {
	for _, mode := range []string{"request-tenant", "request-subject", "request-session", "request-operation", "permit-tenant", "permit-subject", "permit-session", "permit-operation", "generation", "overflow", "proof", "error", "denied", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			adapter, source, request := aclFixture(t)
			ctx := context.Background()
			switch mode {
			case "request-tenant":
				request.Principal.TenantID = request.SessionID
			case "request-subject":
				request.Principal.SubjectID = request.SessionID
			case "request-session":
				request.SessionID = request.Principal.SubjectID
			case "request-operation":
				request.Operation = "administrator-all"
			case "permit-tenant":
				source.permit.Principal.TenantID = request.SessionID
			case "permit-subject":
				source.permit.Principal.SubjectID = request.SessionID
			case "permit-session":
				source.permit.SessionID = request.Principal.SubjectID
			case "permit-operation":
				source.permit.Operation = sessionevent.OperationReadEvents
			case "generation":
				source.permit.AuthorizationGeneration = 0
			case "overflow":
				source.permit.AuthorizationGeneration = maximumInteger + 1
			case "proof":
				source.permit.Proof = sessionevent.OpaqueAuthorizationProof{}
			case "error":
				source.err = errors.New("credential-secret-native-diagnostic")
			case "denied":
				source.err = fmt.Errorf("credential-secret-native-diagnostic: %w", sessionevent.ErrAccessDenied)
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			permit, err := adapter.Authorize(ctx, request)
			if err == nil || permit != (sessionevent.AuthorizationPermit{}) || strings.Contains(err.Error(), "credential-secret") {
				t.Fatal("invalid ACL authority escaped", err)
			}
			if strings.HasPrefix(mode, "request-") || mode == "cancelled" {
				if source.calls != 0 {
					t.Fatal("invalid request reached native ACL source")
				}
			}
		})
	}
}
