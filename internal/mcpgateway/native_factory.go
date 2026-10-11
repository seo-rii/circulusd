package mcpgateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"reflect"
	"slices"
	"time"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/dependency"
)

// MCPWireTransport is the lowest-level port reserved for an actual MCP
// transport. It handles bounded JSON-RPC bytes for an operator registry target,
// and has no admission, start-permit, cancellation or ledger authority.
// Arbitrary implementations are never accepted by NativeFactory. Its real
// anonymous HTTP adapter is constructed from an immutable concrete config.
type MCPWireTransport interface {
	Exchange(context.Context, MCPWireRequest) (MCPWireResponse, error)
}

type MCPWireRequest struct {
	TargetRef     string
	ConnectionRef string
	MessageJSON   []byte
}
type MCPWireResponse struct {
	ConnectionRef string
	MessageJSON   []byte
}

func (MCPWireRequest) String() string    { return "mcp-wire-request<redacted>" }
func (MCPWireRequest) GoString() string  { return "mcp-wire-request<redacted>" }
func (MCPWireResponse) String() string   { return "mcp-wire-response<redacted>" }
func (MCPWireResponse) GoString() string { return "mcp-wire-response<redacted>" }

type NativeProviderConfig struct {
	Transport         MCPWireTransport // Arbitrary operational ports remain rejected.
	StreamableHTTP    *StreamableHTTPConfig
	UnavailableReason string
}

type NativeFactoryConfig struct {
	Repository    NativeRepositoryConfig
	Configuration Configuration
	Providers     map[string]NativeProviderConfig
}

func (NativeFactoryConfig) String() string   { return "native-mcp-factory-config<redacted>" }
func (NativeFactoryConfig) GoString() string { return "native-mcp-factory-config<redacted>" }

// NativeAuthorityGrant is an operator-provisioned immutable admission record.
// It contains a digest of the bearer, never bearer bytes or an external secret.
// Current validation ignores admission TTL after an effect was admitted, but
// always checks the currently persisted native fence and exact request identity.
type NativeAuthorityGrant struct {
	BearerDigest      Digest
	Scope             ValidatedAuthority
	RequestDigest     Digest
	ExpiresAtUnixNano int64
	Permissions       []string
}

func (NativeAuthorityGrant) String() string   { return "native-mcp-authority-grant<redacted>" }
func (NativeAuthorityGrant) GoString() string { return "native-mcp-authority-grant<redacted>" }

// NativeCandidates must be independently verified with the actual source's
// MCP-specific evidence before SealDependencies can admit their exact instances.
type NativeCandidates struct {
	Authority  ProductionAuthorityValidator
	Authorizer ProductionToolAuthorizer
	Repository ProductionEffectRepository
	Audit      ProductionAuditSink
	Providers  map[string]ProductionProvider
}

type NativeFactory struct {
	repository    *NativeRepository
	configuration Configuration
	policyDigest  Digest
	validator     *Gateway
	authority     *nativeAuthority
	authorizer    *nativeAuthorizer
	audit         *nativeAudit
	providers     map[string]ProductionProvider
}

func (*NativeFactory) String() string   { return "native-mcp-factory<redacted>" }
func (*NativeFactory) GoString() string { return "native-mcp-factory<redacted>" }

func NewNativeFactory(config NativeFactoryConfig) (*NativeFactory, error) {
	repository, err := NewNativeRepository(config.Repository)
	if err != nil {
		return nil, err
	}
	return newNativeFactory(repository, config.Configuration, config.Providers)
}

func newNativeFactory(repository *NativeRepository, configuration Configuration, providers map[string]NativeProviderConfig) (*NativeFactory, error) {
	if repository == nil || repository.factory != nil || configuration.AllowReferenceMemory || len(providers) == 0 {
		return nil, ErrInvalidConfiguration
	}
	configuration = cloneNativeConfiguration(configuration)
	for _, server := range configuration.Servers {
		if !server.Credential.Handle.IsZero() || server.Credential.Audience != "" {
			return nil, ErrCredentialUnavailable
		}
		if len(server.AllowedServerRequests) != 0 {
			return nil, ErrStoreUnavailable
		}
	}
	factory := &NativeFactory{repository: repository, configuration: configuration, providers: make(map[string]ProductionProvider)}
	factory.authority = &nativeAuthority{factory}
	factory.authorizer = &nativeAuthorizer{factory}
	factory.audit = &nativeAudit{factory}
	operationalProviders := make(map[string]Provider, len(providers))
	for id, config := range providers {
		if !isNilInterface(config.Transport) {
			return nil, ErrProviderUnavailable
		}
		if config.StreamableHTTP != nil {
			if config.UnavailableReason != "" {
				return nil, ErrInvalidConfiguration
			}
			transport, err := NewStreamableHTTPTransport(*config.StreamableHTTP)
			if err != nil {
				return nil, err
			}
			provider := &nativeHTTPProvider{factory: factory, id: id, transport: transport}
			factory.providers[id], operationalProviders[id] = provider, provider
			continue
		}
		unavailable, err := NewUnavailableProvider(config.UnavailableReason)
		if err != nil {
			return nil, err
		}
		provider := &nativeUnavailableProvider{factory: factory, unavailable: unavailable}
		factory.providers[id] = provider
		operationalProviders[id] = provider
	}
	validator, err := newGateway(configuration, Dependencies{Authority: factory.authority, Authorizer: factory.authorizer,
		Repository: repository, Audit: factory.audit, Providers: operationalProviders}, true)
	if err != nil {
		return nil, err
	}
	factory.validator = validator
	for _, server := range configuration.Servers {
		if provider, real := factory.providers[server.ProviderID].(*nativeHTTPProvider); real {
			if !provider.registered(server) {
				return nil, ErrInvalidConfiguration
			}
		}
	}
	digest, err := nativeFactoryPolicyDigest(configuration, factory.providers)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	factory.policyDigest = digest
	repository.factory = factory
	return factory, nil
}

func nativeFactoryPolicyDigest(configuration Configuration, providers map[string]ProductionProvider) (Digest, error) {
	value, err := nativeEncodeValue(reflect.ValueOf(configuration))
	if err != nil {
		return Digest{}, err
	}
	ports := canonical.Map{}
	for id, candidate := range providers {
		switch provider := candidate.(type) {
		case *nativeHTTPProvider:
			config, err := nativeEncodeValue(reflect.ValueOf(provider.transport.config))
			if err != nil {
				return Digest{}, err
			}
			ports[id] = canonical.Array{"anonymous-streamable-http.v1", config}
		case *nativeUnavailableProvider:
			ports[id] = canonical.Array{"unavailable.v1", provider.unavailable.(unavailableProvider).reason}
		default:
			return Digest{}, ErrInvalidConfiguration
		}
	}
	encoded, err := canonical.Encode(canonical.Array{"circulus.native-mcp-factory-policy.v2", value, ports}, canonical.DefaultOptions())
	if err != nil {
		return Digest{}, err
	}
	return sha256.Sum256(encoded), nil
}

func cloneNativeConfiguration(configuration Configuration) Configuration {
	configuration.Servers = slices.Clone(configuration.Servers)
	for i := range configuration.Servers {
		configuration.Servers[i].AllowedServerRequests = slices.Clone(configuration.Servers[i].AllowedServerRequests)
	}
	configuration.Tools = slices.Clone(configuration.Tools)
	return configuration
}

func nativeConfigurationDigest(configuration Configuration) (Digest, error) {
	value, err := nativeEncodeValue(reflect.ValueOf(configuration))
	if err != nil {
		return Digest{}, err
	}
	encoded, err := canonical.Encode(canonical.Array{"circulus.native-mcp-policy.v1", value}, canonical.DefaultOptions())
	if err != nil {
		return Digest{}, err
	}
	return sha256.Sum256(encoded), nil
}

func NativeBearerDigest(authority OpaqueAuthority) (Digest, error) {
	if len(authority) == 0 || len(authority) > hardMaxAuthorityBytes {
		return Digest{}, ErrInvalidRequest
	}
	return sha256.Sum256(authority), nil
}
func permitKey(proof ToolAuthorizationProof) string { return fmt.Sprintf("%x", proof[:]) }
func nativeGrantKey(digest Digest) string           { return fmt.Sprintf("%x", digest[:]) }

func validNativeGrant(grant NativeAuthorityGrant) bool {
	if grant.BearerDigest == (Digest{}) || !validScope(grant.Scope) || grant.RequestDigest == (Digest{}) ||
		grant.ExpiresAtUnixNano <= 0 || len(grant.Permissions) == 0 || len(grant.Permissions) > 6 || !slices.IsSorted(grant.Permissions) {
		return false
	}
	for i, permission := range grant.Permissions {
		if i > 0 && permission == grant.Permissions[i-1] {
			return false
		}
		switch permission {
		case "mcp.tools.call", "mcp.tools.list", "mcp.cancel", "mcp.recover", "mcp.confirm":
		default:
			return false
		}
	}
	return true
}

// ProvisionGrant is a trusted operator operation, separate from Gateway.
// Reusing a bearer digest with different immutable facts is rejected. Rotating
// authority requires an explicitly monotonic fence in the same native object.
func (factory *NativeFactory) ProvisionGrant(ctx context.Context, grant NativeAuthorityGrant) error {
	if factory == nil || !validNativeGrant(grant) {
		return ErrInvalidRequest
	}
	grant.Permissions = slices.Clone(grant.Permissions)
	_, err := nativeStateOperation(ctx, factory.repository, func(state *nativeRepositoryState) (struct{}, error) {
		if state.PolicyDigest != (Digest{}) && state.PolicyDigest != factory.policyDigest {
			return struct{}{}, ErrStaleAuthority
		}
		now := factory.repository.now()
		if grant.ExpiresAtUnixNano <= now.UnixNano() || grant.ExpiresAtUnixNano-now.UnixNano() > int64(24*time.Hour) {
			return struct{}{}, ErrStaleAuthority
		}
		key := nativeGrantKey(grant.BearerDigest)
		if previous, found := state.AuthorityGrants[key]; found && !reflect.DeepEqual(previous, grant) {
			return struct{}{}, ErrAuthorityMismatch
		}
		current, found := state.Repository.scopes[keyForScope(grant.Scope)]
		if found && !sameFence(current, grant.Scope) {
			return struct{}{}, ErrStaleAuthority
		}
		if err := state.Repository.SetCurrentAuthority(grant.Scope); err != nil {
			return struct{}{}, err
		}
		state.PolicyDigest = factory.policyDigest
		state.AuthorityGrants[key] = grant
		return struct{}{}, nil
	})
	return err
}

func (factory *NativeFactory) Candidates() NativeCandidates {
	if factory == nil {
		return NativeCandidates{}
	}
	providers := make(map[string]ProductionProvider, len(factory.providers))
	for id, provider := range factory.providers {
		providers[id] = provider
	}
	return NativeCandidates{Authority: factory.authority, Authorizer: factory.authorizer, Repository: factory.repository, Audit: factory.audit, Providers: providers}
}

// SealDependencies checks exact factory-owned operational instances as well
// as their independently verified native bindings. Copying a valid probe onto
// unrelated operational wrappers never obtains this package-private seal.
func (factory *NativeFactory) SealDependencies(production ProductionDependencies) (ProductionDependencies, error) {
	if err := factory.validateDependencies(production); err != nil {
		return ProductionDependencies{}, err
	}
	sealed := production
	sealed.Providers = make(map[string]dependency.Verified[ProductionProvider], len(production.Providers))
	for id, provider := range production.Providers {
		sealed.Providers[id] = provider
	}
	sealed.factory = factory
	return sealed, nil
}

func (factory *NativeFactory) validateDependencies(production ProductionDependencies) error {
	if factory == nil || factory.repository == nil || factory.repository.factory != factory {
		return ErrStoreUnavailable
	}
	authority, descriptor, err := production.Authority.Open()
	if err != nil || authority != factory.authority || !reflect.DeepEqual(descriptor, factory.repository.descriptor) {
		return ErrStoreUnavailable
	}
	authorizer, descriptor, err := production.Authorizer.Open()
	if err != nil || authorizer != factory.authorizer || !reflect.DeepEqual(descriptor, factory.repository.descriptor) {
		return ErrStoreUnavailable
	}
	repository, descriptor, err := production.Repository.Open()
	if err != nil || repository != factory.repository || !reflect.DeepEqual(descriptor, factory.repository.descriptor) {
		return ErrStoreUnavailable
	}
	audit, descriptor, err := production.Audit.Open()
	if err != nil || audit != factory.audit || !reflect.DeepEqual(descriptor, factory.repository.descriptor) {
		return ErrStoreUnavailable
	}
	// This version deliberately has no credential or server-request adapter.
	if _, _, err := production.Credentials.Open(); err == nil {
		return ErrStoreUnavailable
	}
	if _, _, err := production.Sampling.Open(); err == nil {
		return ErrStoreUnavailable
	}
	if _, _, err := production.Elicitation.Open(); err == nil {
		return ErrStoreUnavailable
	}
	if _, _, err := production.Roots.Open(); err == nil {
		return ErrStoreUnavailable
	}
	if len(production.Providers) != len(factory.providers) {
		return ErrStoreUnavailable
	}
	bindings := []dependency.Binding{factory.repository.binding, production.Authority, production.Authorizer, production.Repository, production.Audit}
	for id, candidate := range factory.providers {
		binding, found := production.Providers[id]
		if !found {
			return ErrStoreUnavailable
		}
		provider, descriptor, err := binding.Open()
		if err != nil || provider != candidate || !reflect.DeepEqual(descriptor, factory.repository.descriptor) {
			return ErrStoreUnavailable
		}
		bindings = append(bindings, binding)
	}
	if _, err := dependency.RequireAtomicDomain(nativeRepositoryGroups(), bindings...); err != nil {
		return ErrStoreUnavailable
	}
	return nil
}

func (factory *NativeFactory) authorizedEffect(state *nativeRepositoryState, effect Effect) bool {
	if state.PolicyDigest != factory.policyDigest || factory.validator.validateEffect(effect) != nil {
		return false
	}
	if !factory.currentGrant(state, effect.Scope, effect.RequestDigest, "mcp.tools.call", true) {
		return false
	}
	for _, permit := range state.ToolPermits {
		if validAuthorizationPermit(permit, effect.Scope, effect.ServerID, effect.ToolName, effect.RequestDigest) {
			return true
		}
	}
	return false
}

func (factory *NativeFactory) currentGrant(state *nativeRepositoryState, scope ValidatedAuthority, digest Digest, permission string, admission bool) bool {
	if state.PolicyDigest != factory.policyDigest || !sameFence(state.Repository.scopes[keyForScope(scope)], scope) {
		return false
	}
	for _, grant := range state.AuthorityGrants {
		if grant.Scope == scope && grant.RequestDigest == digest && slices.Contains(grant.Permissions, permission) &&
			(!admission || factory.repository.now().UnixNano() < grant.ExpiresAtUnixNano) {
			return true
		}
	}
	return false
}

type nativeAuthority struct{ factory *NativeFactory }

func (authority *nativeAuthority) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	return authority.factory.repository.ProbeProduction(ctx, challenge)
}
func (authority *nativeAuthority) ValidateCurrent(ctx context.Context, bearer OpaqueAuthority, request CurrentAuthorityRequest) (ValidatedAuthority, error) {
	bearerDigest, err := NativeBearerDigest(bearer)
	if err != nil {
		return ValidatedAuthority{}, err
	}
	return nativeStateOperation(ctx, authority.factory.repository, func(state *nativeRepositoryState) (ValidatedAuthority, error) {
		grant, found := state.AuthorityGrants[nativeGrantKey(bearerDigest)]
		if !found || state.PolicyDigest != authority.factory.policyDigest || grant.RequestDigest != request.RequestDigest ||
			!sameOperationScope(grant.Scope, request.Scope) || !slices.Contains(grant.Permissions, request.Permission) ||
			!sameFence(state.Repository.scopes[keyForScope(grant.Scope)], grant.Scope) {
			return ValidatedAuthority{}, ErrStaleAuthority
		}
		if authority.factory.repository.now().UnixNano() >= grant.ExpiresAtUnixNano {
			effect, admitted := state.Repository.effects[grant.Scope.InvocationID.String()]
			if !admitted || effect.RequestDigest != grant.RequestDigest || !sameOperationScope(effect.Scope, grant.Scope) {
				return ValidatedAuthority{}, ErrStaleAuthority
			}
		}
		return grant.Scope, nil
	})
}
func (authority *nativeAuthority) ValidateAdmission(ctx context.Context, bearer OpaqueAuthority, request AuthorityRequest) (ValidatedAuthority, error) {
	digest, err := NativeBearerDigest(bearer)
	if err != nil {
		return ValidatedAuthority{}, err
	}
	return nativeStateOperation(ctx, authority.factory.repository, func(state *nativeRepositoryState) (ValidatedAuthority, error) {
		grant, found := state.AuthorityGrants[nativeGrantKey(digest)]
		if !found || grant.Scope.EffectID != request.EffectID || grant.Scope.InvocationID != request.InvocationID {
			return ValidatedAuthority{}, ErrAuthorityMismatch
		}
		if state.PolicyDigest != authority.factory.policyDigest || grant.RequestDigest != request.RequestDigest ||
			!slices.Contains(grant.Permissions, request.Permission) || !sameFence(state.Repository.scopes[keyForScope(grant.Scope)], grant.Scope) ||
			authority.factory.repository.now().UnixNano() >= grant.ExpiresAtUnixNano {
			return ValidatedAuthority{}, ErrStaleAuthority
		}
		return grant.Scope, nil
	})
}

type nativeAuthorizer struct{ factory *NativeFactory }

func (authorizer *nativeAuthorizer) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	return authorizer.factory.repository.ProbeProduction(ctx, challenge)
}
func (authorizer *nativeAuthorizer) Authorize(ctx context.Context, request ToolAuthorizationRequest) (ToolAuthorizationPermit, error) {
	return nativeStateOperation(ctx, authorizer.factory.repository, func(state *nativeRepositoryState) (ToolAuthorizationPermit, error) {
		if state.PolicyDigest != authorizer.factory.policyDigest || !validScope(request.Scope) || request.RequestDigest == (Digest{}) ||
			!sameFence(state.Repository.scopes[keyForScope(request.Scope)], request.Scope) {
			return ToolAuthorizationPermit{}, ErrStaleAuthority
		}
		key := toolKey{serverKey: serverKey{tenant: request.Scope.TenantID, user: request.Scope.UserID, server: request.ServerID}, tool: request.ToolName}
		if _, found := authorizer.factory.validator.tools[key]; !found {
			return ToolAuthorizationPermit{}, ErrToolNotAllowed
		}
		allowed := false
		for _, grant := range state.AuthorityGrants {
			if grant.Scope == request.Scope && grant.RequestDigest == request.RequestDigest && slices.Contains(grant.Permissions, request.Permission) {
				allowed = true
				break
			}
		}
		if !allowed {
			return ToolAuthorizationPermit{}, ErrToolNotAllowed
		}
		value, err := nativeEncodeValue(reflect.ValueOf(request))
		if err != nil {
			return ToolAuthorizationPermit{}, ErrInvalidRequest
		}
		encoded, err := canonical.Encode(canonical.Array{"circulus.native-mcp-authorization.v1", canonical.Bytes(authorizer.factory.policyDigest[:]), value}, canonical.DefaultOptions())
		if err != nil {
			return ToolAuthorizationPermit{}, ErrInvalidRequest
		}
		permit := ToolAuthorizationPermit{Proof: ToolAuthorizationProof(sha256.Sum256(encoded)), Durable: true, Scope: request.Scope,
			ServerID: request.ServerID, ToolName: request.ToolName, RequestDigest: request.RequestDigest}
		state.ToolPermits[permitKey(permit.Proof)] = permit
		return permit, nil
	})
}

type nativeAudit struct{ factory *NativeFactory }

func (audit *nativeAudit) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	return audit.factory.repository.ProbeProduction(ctx, challenge)
}
func (audit *nativeAudit) Record(ctx context.Context, event AuditEvent) error {
	_, err := nativeStateOperation(ctx, audit.factory.repository, func(state *nativeRepositoryState) (struct{}, error) {
		if event.OutboxSequence == 0 || state.PolicyDigest != audit.factory.policyDigest {
			return struct{}{}, ErrAuditUnavailable
		}
		if previous, found := state.DeliveredAudits[event.OutboxSequence]; found {
			if previous != event {
				return struct{}{}, ErrAuditUnavailable
			}
			return struct{}{}, nil
		}
		outbox, found := state.Repository.pendingAudits[event.OutboxSequence]
		if !found || outbox.Event != event {
			return struct{}{}, ErrAuditUnavailable
		}
		state.DeliveredAudits[event.OutboxSequence] = event
		return struct{}{}, nil
	})
	return err
}

type nativeUnavailableProvider struct {
	factory     *NativeFactory
	unavailable Provider
}

func (provider *nativeUnavailableProvider) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	return provider.factory.repository.ProbeProduction(ctx, challenge)
}
func (provider *nativeUnavailableProvider) Availability(ctx context.Context, server ServerDescriptor) (ServerAvailability, error) {
	if err := provider.factory.repository.ready(ctx); err != nil {
		return ServerAvailability{}, err
	}
	return provider.unavailable.Availability(ctx, server)
}
func (provider *nativeUnavailableProvider) Negotiate(ctx context.Context, command NegotiationCommand) (StartNegotiationReceipt, error) {
	return provider.unavailable.Negotiate(ctx, command)
}
func (provider *nativeUnavailableProvider) Start(ctx context.Context, command ProviderCommand) (ProviderStartResult, error) {
	return provider.unavailable.Start(ctx, command)
}
func (provider *nativeUnavailableProvider) Cancel(ctx context.Context, command CancelCommand) (CancellationResult, error) {
	return provider.unavailable.Cancel(ctx, command)
}
func (provider *nativeUnavailableProvider) Lookup(ctx context.Context, query LedgerQuery) (LedgerRecord, error) {
	return provider.unavailable.Lookup(ctx, query)
}

func equalNativeConfiguration(left, right Configuration) bool {
	leftDigest, leftErr := nativeConfigurationDigest(left)
	rightDigest, rightErr := nativeConfigurationDigest(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftDigest[:], rightDigest[:])
}
