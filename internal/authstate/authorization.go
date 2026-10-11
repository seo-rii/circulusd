package authstate

import (
	"context"
	"errors"

	"github.com/hancomac/circulusd/internal/dependency"
	"github.com/hancomac/circulusd/internal/identity"
	"github.com/hancomac/circulusd/internal/sessionevent"
)

const AtomicACLAuthorization dependency.AtomicGroup = "acl-authorization"

// AuthorizationSource must check current tenant/principal membership and the
// Session's Workspace and authorization generation inside its native authority.
// There is no caller-supplied ACL policy, cached permission set or fabricated
// opaque proof in this adapter. The source's qualification must attest that
// current authorization and the Session mutation/event domain are joined.
type AuthorizationSource interface {
	sessionevent.Authorizer
	dependency.ProductionProbe
}

type Authorizer struct {
	source  AuthorizationSource
	binding dependency.Verified[AuthorizationSource]
}

func (*Authorizer) String() string   { return "authstate-authorizer<redacted>" }
func (*Authorizer) GoString() string { return "authstate-authorizer<redacted>" }

func NewAuthorizer(binding dependency.Verified[AuthorizationSource]) (*Authorizer, error) {
	source, _, err := binding.Open()
	if err != nil || nilInterface(source) {
		return nil, dependency.ErrUnverifiedDependency
	}
	if _, err := dependency.RequireAtomicDomain([]dependency.AtomicGroup{AtomicACLAuthorization,
		dependency.AtomicCommandReceipt, dependency.AtomicEffectLifecycle, dependency.AtomicPublicEvent}, binding); err != nil {
		return nil, err
	}
	return &Authorizer{source: source, binding: binding}, nil
}

func (authorizer *Authorizer) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	if authorizer == nil || nilInterface(authorizer.source) {
		return dependency.ProbeResponse{}, dependency.ErrUnverifiedDependency
	}
	if _, _, err := authorizer.binding.Open(); err != nil {
		return dependency.ProbeResponse{}, err
	}
	return authorizer.source.ProbeProduction(ctx, challenge)
}

func (authorizer *Authorizer) Authorize(ctx context.Context, request sessionevent.AuthorizationRequest) (sessionevent.AuthorizationPermit, error) {
	var empty sessionevent.AuthorizationPermit
	if ctx == nil {
		return empty, sessionevent.ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if authorizer == nil || nilInterface(authorizer.source) {
		return empty, dependency.ErrUnverifiedDependency
	}
	if _, _, err := authorizer.binding.Open(); err != nil {
		return empty, dependency.ErrUnverifiedDependency
	}
	if request.Operation != sessionevent.OperationCreateTurn && request.Operation != sessionevent.OperationReadEvents {
		return empty, sessionevent.ErrAccessDenied
	}
	for kind, text := range map[identity.Kind]string{identity.Tenant: request.Principal.TenantID,
		identity.Subject: request.Principal.SubjectID, identity.Session: request.SessionID} {
		if _, err := identity.Parse(kind, text); err != nil {
			return empty, sessionevent.ErrInvalidRequest
		}
	}
	permit, err := authorizer.source.Authorize(ctx, request)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return empty, ctxErr
	}
	if err != nil {
		if errors.Is(err, sessionevent.ErrAccessDenied) {
			return empty, sessionevent.ErrAccessDenied
		}
		return empty, sessionevent.ErrRepositoryFailure
	}
	if permit.Principal != request.Principal || permit.SessionID != request.SessionID || permit.Operation != request.Operation ||
		permit.AuthorizationGeneration < 1 || permit.AuthorizationGeneration > maximumInteger || permit.Proof == (sessionevent.OpaqueAuthorizationProof{}) {
		return empty, sessionevent.ErrRepositoryFailure
	}
	return permit, nil
}

var _ sessionevent.Authorizer = (*Authorizer)(nil)
var _ dependency.ProductionProbe = (*Authorizer)(nil)
