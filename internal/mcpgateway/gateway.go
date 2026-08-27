package mcpgateway

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/identity"
)

const (
	hardMaxAuthorityBytes         = 64 << 10
	hardMaxIdentifierBytes        = 512
	hardMaxTargetRefBytes         = 1024
	hardMaxCredentialHandleBytes  = 1024
	hardMaxInputBytes             = 16 << 20
	hardMaxInputDepth             = 64
	hardMaxProviderRequestIDBytes = 1024
	hardMaxExternalCommitIDBytes  = 1024
	hardMaxChunkBytes             = 1 << 20
	hardMaxChunks                 = 1 << 20
	hardMaxOutputBytes            = 64 << 20
	hardMaxFailureBytes           = 4096
	hardMaxEvents                 = 1 << 20
	hardMaxRetries                = 16
)

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*$`)
	targetRefPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*$`)
)

type serverKey struct {
	tenant identity.ID
	user   identity.ID
	server string
}

type toolKey struct {
	serverKey
	tool string
}

// Gateway is immutable after construction. Its dependencies must be safe for
// concurrent use; Apply is pure and EffectRepository owns durable CAS.
type Gateway struct {
	bounds      Bounds
	servers     map[serverKey]ServerRegistration
	tools       map[toolKey]ToolRegistration
	authority   AuthorityValidator
	authorizer  ToolAuthorizer
	credentials CredentialBroker
	repository  EffectRepository
	audit       AuditSink
	providers   map[string]Provider
	sampling    SamplingBroker
	elicitation ElicitationBroker
	roots       RootsProvider
}

func NewCredentialHandle(value string) (CredentialHandle, error) {
	if !validRegistryRef(value, hardMaxCredentialHandleBytes) {
		return CredentialHandle{}, fmt.Errorf("%w: credential handle must be an opaque registry reference", ErrInvalidConfiguration)
	}
	return CredentialHandle{value: value}, nil
}

// NewGateway constructs the explicitly selected process-local reference
// gateway. Production bootstrap must use NewProductionGateway; raw dependency
// interfaces and optimistic durability booleans are not production evidence.
func NewGateway(configuration Configuration, dependencies Dependencies) (*Gateway, error) {
	if !configuration.AllowReferenceMemory {
		return nil, ErrStoreUnavailable
	}
	return newGateway(configuration, dependencies, false)
}

func NewProductionGateway(configuration Configuration, production ProductionDependencies) (*Gateway, error) {
	_ = production
	if configuration.AllowReferenceMemory {
		return nil, fmt.Errorf("%w: production gateway cannot enable reference memory", ErrInvalidConfiguration)
	}
	// Verified probe wrappers cannot bind their operational methods to the
	// probed runtime: a wrapper can delegate calls to process-local or split
	// backends while forwarding ProbeProduction to a genuine endpoint. Until a
	// sealed factory constructs the actual operational graph, accepting any
	// graph here would be a confused-deputy durability claim.
	return nil, fmt.Errorf("%w: sealed MCP production adapter factory is unavailable", ErrStoreUnavailable)
}

func newGateway(configuration Configuration, dependencies Dependencies, verifiedProduction bool) (*Gateway, error) {
	if err := validateBounds(configuration.Bounds); err != nil {
		return nil, err
	}
	if isNilInterface(dependencies.Authority) || isNilInterface(dependencies.Authorizer) ||
		isNilInterface(dependencies.Repository) || isNilInterface(dependencies.Audit) || len(dependencies.Providers) == 0 {
		return nil, fmt.Errorf("%w: authority, authorizer, durable repository, audit sink, and providers are required", ErrInvalidConfiguration)
	}
	durability := dependencies.Repository.Durability()
	atomicRepository := durability.AtomicAdmissionCAS && durability.AtomicAdmissionReplay && durability.AtomicTransitionCAS &&
		durability.ExclusiveDispatchClaim && durability.ExclusiveProviderStartClaim &&
		durability.AtomicProviderStartResolution && durability.ExclusiveCancellationClaim &&
		durability.AtomicExpiredRequestReconciliation &&
		durability.AtomicCurrentFence && durability.AtomicActiveEffect &&
		durability.AtomicAuditOutbox
	productionRepository := verifiedProduction && durability.CrashDurable && atomicRepository && !durability.ReferenceMemory
	referenceRepository := !verifiedProduction && configuration.AllowReferenceMemory && !durability.CrashDurable &&
		atomicRepository && durability.ReferenceMemory
	if !productionRepository && !referenceRepository {
		return nil, fmt.Errorf("%w: repository lacks required crash durability and atomic fencing", ErrStoreUnavailable)
	}

	providers := make(map[string]Provider, len(dependencies.Providers))
	for providerID, provider := range dependencies.Providers {
		if !validIdentifier(providerID, configuration.Bounds.MaxServerIDBytes) || isNilInterface(provider) {
			return nil, fmt.Errorf("%w: invalid provider registration %q", ErrInvalidConfiguration, providerID)
		}
		providers[providerID] = provider
	}
	if len(configuration.Servers) == 0 || len(configuration.Tools) == 0 {
		return nil, fmt.Errorf("%w: at least one exact server and tool registration is required", ErrInvalidConfiguration)
	}

	servers := make(map[serverKey]ServerRegistration, len(configuration.Servers))
	requiresCredentialBroker := false
	for _, registration := range configuration.Servers {
		if registration.TenantID.Kind() != identity.Tenant || registration.UserID.Kind() != identity.Subject ||
			!validIdentifier(registration.ServerID, configuration.Bounds.MaxServerIDBytes) ||
			!validIdentifier(registration.ProviderID, configuration.Bounds.MaxServerIDBytes) ||
			!validBoundedText(registration.ProtocolVersion, configuration.Bounds.MaxProtocolVersionBytes) ||
			!identifierPattern.MatchString(registration.ProtocolVersion) ||
			!validRegistryRef(registration.TargetRef, configuration.Bounds.MaxTargetRefBytes) {
			return nil, fmt.Errorf("%w: invalid MCP server registration", ErrInvalidConfiguration)
		}
		if _, found := providers[registration.ProviderID]; !found {
			return nil, fmt.Errorf("%w: server references unregistered provider %q", ErrInvalidConfiguration, registration.ProviderID)
		}
		switch registration.Transport {
		case TransportStdio:
			if err := validateAffinity(registration.Affinity, true); err != nil {
				return nil, err
			}
		case TransportStreamableHTTP:
			if registration.Affinity != (BackendAffinity{}) {
				return nil, fmt.Errorf("%w: HTTP MCP registration cannot carry stdio affinity", ErrInvalidConfiguration)
			}
		default:
			return nil, fmt.Errorf("%w: unsupported MCP transport", ErrInvalidConfiguration)
		}
		if registration.Credential.Handle.IsZero() != (registration.Credential.Audience == "") {
			return nil, fmt.Errorf("%w: credential handle and audience must be configured together", ErrInvalidConfiguration)
		}
		if !registration.Credential.Handle.IsZero() {
			requiresCredentialBroker = true
			if uint64(len(registration.Credential.Handle.value)) > configuration.Bounds.MaxCredentialHandleBytes ||
				!validBoundedText(registration.Credential.Audience, configuration.Bounds.MaxAudienceBytes) ||
				!identifierPattern.MatchString(registration.Credential.Audience) {
				return nil, fmt.Errorf("%w: invalid credential binding", ErrInvalidConfiguration)
			}
		}
		seenMethods := make(map[ServerRequestMethod]struct{}, len(registration.AllowedServerRequests))
		for _, method := range registration.AllowedServerRequests {
			switch method {
			case ServerRequestSampling:
				if isNilInterface(dependencies.Sampling) {
					return nil, fmt.Errorf("%w: sampling is allowed without a model-gateway broker", ErrInvalidConfiguration)
				}
			case ServerRequestElicitation:
				if isNilInterface(dependencies.Elicitation) {
					return nil, fmt.Errorf("%w: elicitation is allowed without its broker", ErrInvalidConfiguration)
				}
			case ServerRequestRoots:
				if isNilInterface(dependencies.Roots) {
					return nil, fmt.Errorf("%w: roots/list is allowed without a workspace roots provider", ErrInvalidConfiguration)
				}
			default:
				return nil, fmt.Errorf("%w: unsupported server-initiated method %q", ErrInvalidConfiguration, method)
			}
			if _, duplicate := seenMethods[method]; duplicate {
				return nil, fmt.Errorf("%w: duplicate server-initiated method", ErrInvalidConfiguration)
			}
			seenMethods[method] = struct{}{}
		}
		key := serverKey{tenant: registration.TenantID, user: registration.UserID, server: registration.ServerID}
		if _, duplicate := servers[key]; duplicate {
			return nil, fmt.Errorf("%w: duplicate exact server registration", ErrInvalidConfiguration)
		}
		registration.AllowedServerRequests = append([]ServerRequestMethod(nil), registration.AllowedServerRequests...)
		servers[key] = registration
	}
	if requiresCredentialBroker && isNilInterface(dependencies.Credentials) {
		return nil, fmt.Errorf("%w: configured credential binding has no broker", ErrCredentialUnavailable)
	}

	tools := make(map[toolKey]ToolRegistration, len(configuration.Tools))
	for _, registration := range configuration.Tools {
		if registration.TenantID.Kind() != identity.Tenant || registration.UserID.Kind() != identity.Subject ||
			!validIdentifier(registration.ServerID, configuration.Bounds.MaxServerIDBytes) ||
			!validIdentifier(registration.ToolName, configuration.Bounds.MaxToolNameBytes) ||
			registration.MaxAutomaticRetries > hardMaxRetries || registration.MaxConfirmationRetries > hardMaxRetries {
			return nil, fmt.Errorf("%w: invalid MCP tool registration", ErrInvalidConfiguration)
		}
		server := serverKey{tenant: registration.TenantID, user: registration.UserID, server: registration.ServerID}
		if _, found := servers[server]; !found {
			return nil, fmt.Errorf("%w: tool references an unregistered exact tenant/user/server", ErrInvalidConfiguration)
		}
		if registration.SideEffecting && registration.ReplayPolicy == "" {
			return nil, ErrReplayPolicyRequired
		}
		if !registration.SideEffecting && registration.ReplayPolicy == "" {
			registration.ReplayPolicy = ReplaySafe
		}
		switch registration.ReplayPolicy {
		case ReplaySafe, ReplayIdempotencyKey, ReplayNever, ReplayConfirm:
		default:
			return nil, fmt.Errorf("%w: invalid replay policy", ErrInvalidConfiguration)
		}
		if registration.ReplayPolicy == ReplayConfirm && registration.MaxConfirmationRetries == 0 {
			return nil, fmt.Errorf("%w: confirm policy has no bounded confirmation retry", ErrInvalidConfiguration)
		}
		requiredEvents := uint64(configuration.Bounds.MaxChunks)
		switch registration.ReplayPolicy {
		case ReplaySafe, ReplayIdempotencyKey:
			requiredEvents += 4*uint64(registration.MaxAutomaticRetries) + 10
		case ReplayNever:
			requiredEvents += 3*uint64(registration.MaxAutomaticRetries) + 10
		case ReplayConfirm:
			requiredEvents += 3*uint64(registration.MaxAutomaticRetries) +
				10*uint64(registration.MaxConfirmationRetries) + 12
		}
		if requiredEvents > uint64(configuration.Bounds.MaxEvents) {
			return nil, fmt.Errorf("%w: event bound cannot preserve the configured retry and settlement envelope", ErrInvalidConfiguration)
		}
		key := toolKey{serverKey: server, tool: registration.ToolName}
		if _, duplicate := tools[key]; duplicate {
			return nil, fmt.Errorf("%w: duplicate exact tool registration", ErrInvalidConfiguration)
		}
		tools[key] = registration
	}

	return &Gateway{
		bounds: configuration.Bounds, servers: servers, tools: tools,
		authority: dependencies.Authority, authorizer: dependencies.Authorizer,
		credentials: dependencies.Credentials, repository: dependencies.Repository,
		audit: dependencies.Audit, providers: providers, sampling: dependencies.Sampling,
		elicitation: dependencies.Elicitation, roots: dependencies.Roots,
	}, nil
}

func validateBounds(bounds Bounds) error {
	if bounds.MaxAuthorityBytes == 0 || bounds.MaxAuthorityBytes > hardMaxAuthorityBytes ||
		bounds.MaxServerIDBytes == 0 || bounds.MaxServerIDBytes > hardMaxIdentifierBytes ||
		bounds.MaxToolNameBytes == 0 || bounds.MaxToolNameBytes > hardMaxIdentifierBytes ||
		bounds.MaxTargetRefBytes == 0 || bounds.MaxTargetRefBytes > hardMaxTargetRefBytes ||
		bounds.MaxProtocolVersionBytes == 0 || bounds.MaxProtocolVersionBytes > hardMaxIdentifierBytes ||
		bounds.MaxCredentialHandleBytes == 0 || bounds.MaxCredentialHandleBytes > hardMaxCredentialHandleBytes ||
		bounds.MaxAudienceBytes == 0 || bounds.MaxAudienceBytes > hardMaxIdentifierBytes ||
		bounds.MaxInputBytes == 0 || bounds.MaxInputBytes > hardMaxInputBytes ||
		bounds.MaxInputDepth <= 0 || bounds.MaxInputDepth > hardMaxInputDepth ||
		bounds.MaxProviderRequestIDBytes == 0 || bounds.MaxProviderRequestIDBytes > hardMaxProviderRequestIDBytes ||
		bounds.MaxExternalCommitIDBytes == 0 || bounds.MaxExternalCommitIDBytes > hardMaxExternalCommitIDBytes ||
		bounds.MaxChunkBytes == 0 || bounds.MaxChunkBytes > hardMaxChunkBytes ||
		bounds.MaxChunks == 0 || bounds.MaxChunks > hardMaxChunks ||
		bounds.MaxOutputBytes == 0 || bounds.MaxOutputBytes > hardMaxOutputBytes ||
		bounds.MaxFailureBytes == 0 || bounds.MaxFailureBytes > hardMaxFailureBytes ||
		bounds.MaxEvents < 8 || bounds.MaxEvents > hardMaxEvents ||
		bounds.MaxChunkBytes > bounds.MaxOutputBytes || bounds.MaxChunks > bounds.MaxEvents ||
		bounds.CancelTimeout <= 0 || bounds.CancelTimeout > 30_000_000_000 {
		return fmt.Errorf("%w: every MCP input/output/time bound must be positive, consistent, and below its hard ceiling", ErrInvalidConfiguration)
	}
	return nil
}

func validateAffinity(affinity BackendAffinity, template bool) error {
	if !validIdentifier(affinity.Backend, hardMaxIdentifierBytes) ||
		affinity.EnvironmentRevision.Kind() != identity.EnvironmentRevision ||
		affinity.ResourceProfileDigest == (Digest{}) || affinity.NetworkPolicyDigest == (Digest{}) ||
		!validIdentifier(affinity.SecretExposureClass, hardMaxIdentifierBytes) ||
		!validIdentifier(affinity.SandboxProtocolVersion, hardMaxIdentifierBytes) {
		return fmt.Errorf("%w: incomplete stdio backend affinity", ErrInvalidConfiguration)
	}
	if template && affinity.ScopeID != (identity.ID{}) {
		return fmt.Errorf("%w: stdio affinity template cannot pin a caller scope identity", ErrInvalidConfiguration)
	}
	switch affinity.Scope {
	case ScopeWorkspace:
		if !template && affinity.ScopeID.Kind() != identity.Workspace {
			return fmt.Errorf("%w: workspace affinity has wrong scope identity", ErrInvalidConfiguration)
		}
	case ScopeSession:
		if !template && affinity.ScopeID.Kind() != identity.Session {
			return fmt.Errorf("%w: session affinity has wrong scope identity", ErrInvalidConfiguration)
		}
	case ScopeInvocation:
		if !template && affinity.ScopeID.Kind() != identity.Invocation {
			return fmt.Errorf("%w: invocation affinity has wrong scope identity", ErrInvalidConfiguration)
		}
	default:
		return fmt.Errorf("%w: invalid stdio scope", ErrInvalidConfiguration)
	}
	return nil
}

func CallRequestDigest(request CallRequest, bounds Bounds) (Digest, error) {
	_, digest, err := canonicalizeCall(request, bounds)
	return digest, err
}

func canonicalizeCall(request CallRequest, bounds Bounds) ([]byte, Digest, error) {
	if bounds.MaxInputBytes == 0 || bounds.MaxInputBytes > hardMaxInputBytes || bounds.MaxInputDepth <= 0 ||
		bounds.MaxInputDepth > hardMaxInputDepth || bounds.MaxServerIDBytes == 0 || bounds.MaxServerIDBytes > hardMaxIdentifierBytes ||
		bounds.MaxToolNameBytes == 0 || bounds.MaxToolNameBytes > hardMaxIdentifierBytes {
		return nil, Digest{}, ErrInvalidConfiguration
	}
	if !validIdentifier(request.ServerID, bounds.MaxServerIDBytes) || !validIdentifier(request.ToolName, bounds.MaxToolNameBytes) {
		return nil, Digest{}, ErrInvalidRequest
	}
	if err := preflightCanonical(request.Input, 0, bounds.MaxInputDepth, bounds.MaxInputBytes); err != nil {
		if errors.Is(err, canonical.ErrLimitExceeded) {
			return nil, Digest{}, fmt.Errorf("%w: %v", ErrInputLimit, err)
		}
		return nil, Digest{}, fmt.Errorf("%w: canonical MCP input: %v", ErrInvalidRequest, err)
	}
	input, err := canonical.Encode(request.Input, canonical.Options{
		MaxDepth: bounds.MaxInputDepth, MaxBytes: int(bounds.MaxInputBytes),
		MaxItems: canonical.DefaultOptions().MaxItems,
	})
	if err != nil {
		if errorsIsCanonicalLimit(err) {
			return nil, Digest{}, fmt.Errorf("%w: %v", ErrInputLimit, err)
		}
		return nil, Digest{}, fmt.Errorf("%w: canonical MCP input: %v", ErrInvalidRequest, err)
	}
	digest, err := digestCanonicalCall(request.ServerID, request.ToolName, input)
	if err != nil {
		return nil, Digest{}, fmt.Errorf("%w: digest MCP request: %v", ErrInvalidRequest, err)
	}
	return input, digest, nil
}

func digestCanonicalCall(serverID, toolName string, input []byte) (Digest, error) {
	encoded, err := canonical.Encode(canonical.Array{
		"circulusd.hash", int64(1), "mcp.tool.call", int64(1),
		canonical.Map{"server": serverID, "tool": toolName, "input": canonical.Bytes(input)},
	}, canonical.DefaultOptions())
	if err != nil {
		return Digest{}, err
	}
	return sha256.Sum256(encoded), nil
}

func (gateway *Gateway) Admit(ctx context.Context, request AdmissionRequest) (Effect, error) {
	if err := ctx.Err(); err != nil {
		return Effect{}, err
	}
	if request.EffectID.Kind() != identity.Effect || request.InvocationID.Kind() != identity.Invocation ||
		request.RequestDigest == (Digest{}) || len(request.Authority) == 0 || uint64(len(request.Authority)) > gateway.bounds.MaxAuthorityBytes {
		return Effect{}, ErrInvalidRequest
	}
	input, digest, err := canonicalizeCall(request.Call, gateway.bounds)
	if err != nil {
		return Effect{}, err
	}
	if digest != request.RequestDigest {
		return Effect{}, fmt.Errorf("%w: request digest does not match prepared effect", ErrInvalidRequest)
	}

	scope, err := gateway.authority.ValidateAdmission(ctx, append(OpaqueAuthority(nil), request.Authority...), AuthorityRequest{
		EffectID: request.EffectID, InvocationID: request.InvocationID,
		RequestDigest: digest, Permission: "mcp.tools.call",
	})
	if err != nil {
		return Effect{}, redactedDependencyError(ctx, err, ErrStaleAuthority,
			ErrInvalidRequest, ErrStaleAuthority, ErrAuthorityMismatch)
	}
	if !validScope(scope) || scope.EffectID != request.EffectID || scope.InvocationID != request.InvocationID {
		return Effect{}, ErrAuthorityMismatch
	}
	server, allowed := gateway.servers[serverKey{tenant: scope.TenantID, user: scope.UserID, server: request.Call.ServerID}]
	if !allowed {
		return Effect{}, ErrServerNotAllowed
	}
	server, err = resolveServerRegistration(server, scope)
	if err != nil {
		return Effect{}, redactedDependencyError(ctx, err, ErrToolNotAllowed,
			ErrInvalidRequest, ErrServerNotAllowed, ErrToolNotAllowed, ErrAuthorizationMismatch)
	}
	tool, allowed := gateway.tools[toolKey{serverKey: serverKey{tenant: scope.TenantID, user: scope.UserID, server: request.Call.ServerID}, tool: request.Call.ToolName}]
	if !allowed {
		return Effect{}, ErrToolNotAllowed
	}
	permit, err := gateway.authorizer.Authorize(ctx, ToolAuthorizationRequest{
		Scope: scope, ServerID: server.ServerID, ToolName: tool.ToolName,
		RequestDigest: digest, Permission: "mcp.tools.call",
	})
	if err != nil {
		return Effect{}, redactedDependencyError(ctx, err, ErrToolNotAllowed,
			ErrInvalidRequest, ErrServerNotAllowed, ErrToolNotAllowed, ErrAuthorizationMismatch, ErrStaleAuthority)
	}
	if !validAuthorizationPermit(permit, scope, server.ServerID, tool.ToolName, digest) {
		return Effect{}, ErrAuthorizationMismatch
	}
	replayed, replayErr := gateway.repository.ReplayAdmission(ctx, AdmissionReplayRequest{
		CurrentScope: scope, EffectID: request.EffectID, InvocationID: request.InvocationID,
		RequestDigest: digest, ServerID: server.ServerID, ToolName: tool.ToolName,
		InputCanonical: append([]byte(nil), input...),
	})
	if replayErr == nil {
		if !replayed.Durable || gateway.validateEffect(replayed.Effect) != nil ||
			!sameOperationScope(scope, replayed.Effect.Scope) || replayed.Effect.Scope.EffectID != request.EffectID ||
			replayed.Effect.RequestDigest != digest || replayed.Effect.ServerID != server.ServerID ||
			replayed.Effect.ToolName != tool.ToolName || !reflect.DeepEqual(replayed.Effect.InputCanonical, input) {
			return Effect{}, ErrStoreUnavailable
		}
		return cloneEffect(replayed.Effect), nil
	}
	if !errors.Is(replayErr, ErrInvocationNotFound) {
		return Effect{}, redactedDependencyError(ctx, replayErr, ErrStoreUnavailable,
			ErrInvocationConflict, ErrStaleAuthority, ErrInvalidTransition, ErrConcurrentTransition)
	}

	availability, err := gateway.checkAvailability(ctx, server, tool)
	if err != nil {
		return Effect{}, err
	}
	if _, err := gateway.authorizeCredential(ctx, scope, server); err != nil {
		return Effect{}, err
	}

	effect := Effect{
		Scope: scope, RequestDigest: digest, ServerID: server.ServerID, ToolName: tool.ToolName,
		ProviderID: server.ProviderID, Transport: server.Transport, TargetRef: server.TargetRef,
		ProtocolVersion: server.ProtocolVersion, Affinity: server.Affinity, Credential: server.Credential,
		InputCanonical: append([]byte(nil), input...), SideEffecting: tool.SideEffecting,
		ReplayPolicy: tool.ReplayPolicy, MaxAutomaticRetries: tool.MaxAutomaticRetries,
		MaxConfirmationRetries:   tool.MaxConfirmationRetries,
		SupportsInvocationLedger: availability.SupportsInvocationLedger,
		SupportsIdempotencyKey:   availability.SupportsIdempotencyKey,
		State:                    StateAdmitted, Revision: 1,
	}
	stored, err := gateway.repository.Admit(ctx, cloneEffect(effect))
	if err != nil {
		return Effect{}, redactedDependencyError(ctx, err, ErrStoreUnavailable,
			ErrInvocationConflict, ErrEffectInFlight, ErrStaleAuthority, ErrInvalidTransition, ErrConcurrentTransition)
	}
	if !stored.Durable || !sameImmutableEffect(stored.Effect, effect) {
		return Effect{}, fmt.Errorf("%w: admission was not durably recorded exactly", ErrStoreUnavailable)
	}
	if err := gateway.validateEffect(stored.Effect); err != nil {
		return Effect{}, fmt.Errorf("%w: durable admission record is invalid: %v", ErrStoreUnavailable, err)
	}
	return cloneEffect(stored.Effect), nil
}

func (gateway *Gateway) checkAvailability(ctx context.Context, server ServerRegistration, tool ToolRegistration) (ServerAvailability, error) {
	provider := gateway.providers[server.ProviderID]
	availability, err := provider.Availability(ctx, descriptorFor(server))
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return ServerAvailability{}, contextErr
		}
		return ServerAvailability{}, ErrProviderUnavailable
	}
	if !availability.Available {
		return ServerAvailability{}, fmt.Errorf("%w: unavailable", ErrProviderUnavailable)
	}
	if !availability.DurableNegotiation || availability.NegotiatedProtocolVersion != server.ProtocolVersion {
		return ServerAvailability{}, ErrProtocolMismatch
	}
	if server.Transport == TransportStdio && availability.Affinity != server.Affinity {
		return ServerAvailability{}, ErrAffinityMismatch
	}
	if server.Transport == TransportStreamableHTTP && availability.Affinity != (BackendAffinity{}) {
		return ServerAvailability{}, ErrAffinityMismatch
	}
	if tool.ReplayPolicy == ReplayIdempotencyKey && (!availability.SupportsIdempotencyKey || !availability.SupportsInvocationLedger) {
		return ServerAvailability{}, fmt.Errorf("%w: idempotency-key tool lacks durable target deduplication", ErrProviderUnavailable)
	}
	return availability, nil
}

func (gateway *Gateway) authorizeCredential(ctx context.Context, scope ValidatedAuthority, server ServerRegistration) (CredentialPermit, error) {
	if server.Credential.Handle.IsZero() {
		return CredentialPermit{}, nil
	}
	if isNilInterface(gateway.credentials) {
		return CredentialPermit{}, ErrCredentialUnavailable
	}
	request := CredentialRequest{
		Handle: server.Credential.Handle, TenantID: scope.TenantID, UserID: scope.UserID,
		ServerID: server.ServerID, Audience: server.Credential.Audience, TargetRef: server.TargetRef,
	}
	permit, err := gateway.credentials.Authorize(ctx, request)
	if err != nil {
		return CredentialPermit{}, redactedDependencyError(ctx, err, ErrCredentialUnavailable,
			ErrCredentialUnavailable, ErrCredentialMismatch, ErrStaleAuthority)
	}
	if !permit.Durable || permit.Proof == (CredentialProof{}) || permit.Handle != request.Handle ||
		permit.TenantID != request.TenantID || permit.UserID != request.UserID ||
		permit.ServerID != request.ServerID || permit.Audience != request.Audience || permit.TargetRef != request.TargetRef {
		return CredentialPermit{}, ErrCredentialMismatch
	}
	return permit, nil
}

func validScope(scope ValidatedAuthority) bool {
	return scope.TenantID.Kind() == identity.Tenant && scope.UserID.Kind() == identity.Subject &&
		scope.SessionID.Kind() == identity.Session && scope.TurnID.Kind() == identity.Turn &&
		scope.EffectID.Kind() == identity.Effect && scope.InvocationID.Kind() == identity.Invocation &&
		scope.RuntimeRevision.Kind() == identity.RuntimeRevision && scope.Generations.TurnLease != 0 &&
		scope.Generations.Placement != 0 && scope.Generations.Policy != 0 &&
		(scope.WorkspaceID == (identity.ID{}) || scope.WorkspaceID.Kind() == identity.Workspace)
}

func validAuthorizationPermit(permit ToolAuthorizationPermit, scope ValidatedAuthority, serverID, toolName string, digest Digest) bool {
	return permit.Durable && permit.Proof != (ToolAuthorizationProof{}) && permit.Scope == scope &&
		permit.ServerID == serverID && permit.ToolName == toolName && permit.RequestDigest == digest
}

func descriptorFor(server ServerRegistration) ServerDescriptor {
	return ServerDescriptor{
		ServerID: server.ServerID, Transport: server.Transport, TargetRef: server.TargetRef,
		ProtocolVersion: server.ProtocolVersion, Affinity: server.Affinity,
	}
}

func resolveServerRegistration(server ServerRegistration, scope ValidatedAuthority) (ServerRegistration, error) {
	if server.Transport != TransportStdio {
		return server, nil
	}
	affinity := server.Affinity
	switch affinity.Scope {
	case ScopeSession:
		affinity.ScopeID = scope.SessionID
	case ScopeInvocation:
		affinity.ScopeID = scope.InvocationID
	case ScopeWorkspace:
		if scope.WorkspaceID.Kind() != identity.Workspace {
			return ServerRegistration{}, ErrAffinityMismatch
		}
		affinity.ScopeID = scope.WorkspaceID
	default:
		return ServerRegistration{}, ErrAffinityMismatch
	}
	if err := validateAffinity(affinity, false); err != nil {
		return ServerRegistration{}, ErrAffinityMismatch
	}
	server.Affinity = affinity
	return server, nil
}

func serverForEffect(effect Effect) ServerDescriptor {
	return ServerDescriptor{
		ServerID: effect.ServerID, Transport: effect.Transport, TargetRef: effect.TargetRef,
		ProtocolVersion: effect.ProtocolVersion, Affinity: effect.Affinity,
	}
}

func validIdentifier(value string, maximum uint64) bool {
	return validBoundedText(value, maximum) && identifierPattern.MatchString(value)
}

func validRegistryRef(value string, maximum uint64) bool {
	if !validBoundedText(value, maximum) || !targetRefPattern.MatchString(value) || strings.HasPrefix(value, "/") ||
		strings.HasSuffix(value, "/") || strings.Contains(value, "//") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "." || segment == ".." || segment == "" {
			return false
		}
	}
	return true
}

func validBoundedText(value string, maximum uint64) bool {
	return value != "" && uint64(len(value)) <= maximum && utf8.ValidString(value) &&
		strings.IndexFunc(value, unicode.IsControl) < 0
}

func safeReason(value string, maximum uint64) string {
	value = strings.TrimSpace(value)
	if !validBoundedText(value, maximum) {
		return "unavailable"
	}
	return value
}

func isNilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func errorsIsCanonicalLimit(err error) bool {
	return errors.Is(err, canonical.ErrLimitExceeded)
}

func redactedDependencyError(ctx context.Context, err, fallback error, allowed ...error) error {
	if err == nil {
		return nil
	}
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	for _, candidate := range allowed {
		if errors.Is(err, candidate) {
			return candidate
		}
	}
	return fallback
}

func cloneEffect(effect Effect) Effect {
	copy := effect
	copy.InputCanonical = append([]byte(nil), effect.InputCanonical...)
	copy.Attempts = append([]AttemptRecord(nil), effect.Attempts...)
	copy.Output = append([]byte(nil), effect.Output...)
	return copy
}

func cloneServerResponse(response ServerResponse) ServerResponse {
	copy := response
	copy.ResultCanonical = append([]byte(nil), response.ResultCanonical...)
	if response.Error != nil {
		errorCopy := *response.Error
		copy.Error = &errorCopy
	}
	return copy
}

func cloneServerRequestRecord(record ServerRequestRecord) ServerRequestRecord {
	copy := record
	copy.Response = cloneServerResponse(record.Response)
	return copy
}

func sameEffect(left, right Effect) bool {
	return reflect.DeepEqual(left, right)
}

func sameImmutableEffect(left, right Effect) bool {
	left.State, right.State = "", ""
	left.Revision, right.Revision = 0, 0
	left.EventCount, right.EventCount = 0, 0
	left.EventBytes, right.EventBytes = 0, 0
	left.Attempts, right.Attempts = nil, nil
	left.AutomaticRetriesUsed, right.AutomaticRetriesUsed = 0, 0
	left.ConfirmationRetriesUsed, right.ConfirmationRetriesUsed = 0, 0
	left.ChunkCount, right.ChunkCount = 0, 0
	left.StreamBytes, right.StreamBytes = 0, 0
	left.ExternalCommitID, right.ExternalCommitID = "", ""
	left.Output, right.Output = nil, nil
	left.FailureReason, right.FailureReason = "", ""
	left.CancellationRequested, right.CancellationRequested = false, false
	return sameEffect(left, right)
}

func preflightCanonical(value canonical.Value, depth, maxDepth int, maxBytes uint64) error {
	if depth > maxDepth {
		return canonical.ErrLimitExceeded
	}
	switch value := value.(type) {
	case nil, bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return nil
	case string:
		if !utf8.ValidString(value) {
			return canonical.ErrInvalidValue
		}
		if uint64(len(value)) > maxBytes {
			return canonical.ErrLimitExceeded
		}
		return nil
	case canonical.Bytes:
		if uint64(len(value)) > maxBytes {
			return canonical.ErrLimitExceeded
		}
		return nil
	case canonical.Array:
		if uint64(len(value)) > maxBytes {
			return canonical.ErrLimitExceeded
		}
		for _, item := range value {
			if err := preflightCanonical(item, depth+1, maxDepth, maxBytes); err != nil {
				return err
			}
		}
		return nil
	case canonical.Map:
		if uint64(len(value)) > maxBytes {
			return canonical.ErrLimitExceeded
		}
		for key, item := range value {
			if !utf8.ValidString(key) {
				return canonical.ErrInvalidValue
			}
			if uint64(len(key)) > maxBytes {
				return canonical.ErrLimitExceeded
			}
			if err := preflightCanonical(item, depth+1, maxDepth, maxBytes); err != nil {
				return err
			}
		}
		return nil
	default:
		return canonical.ErrInvalidValue
	}
}
