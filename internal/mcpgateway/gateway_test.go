package mcpgateway

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/identity"
)

type authorityStub struct {
	mu      sync.Mutex
	scope   ValidatedAuthority
	err     error
	current error
}

func (stub *authorityStub) ValidateAdmission(_ context.Context, _ OpaqueAuthority, request AuthorityRequest) (ValidatedAuthority, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if stub.err != nil {
		return ValidatedAuthority{}, stub.err
	}
	scope := stub.scope
	scope.EffectID = request.EffectID
	scope.InvocationID = request.InvocationID
	return scope, nil
}

func (stub *authorityStub) ValidateCurrent(_ context.Context, _ OpaqueAuthority, request CurrentAuthorityRequest) (ValidatedAuthority, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if stub.current != nil {
		return ValidatedAuthority{}, stub.current
	}
	scope := stub.scope
	scope.EffectID = request.Scope.EffectID
	scope.InvocationID = request.Scope.InvocationID
	return scope, nil
}

type authorizerStub struct {
	mu     sync.Mutex
	denied bool
	err    error
	calls  []ToolAuthorizationRequest
}

func (stub *authorizerStub) Authorize(_ context.Context, request ToolAuthorizationRequest) (ToolAuthorizationPermit, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.calls = append(stub.calls, request)
	if stub.err != nil {
		return ToolAuthorizationPermit{}, stub.err
	}
	if stub.denied {
		return ToolAuthorizationPermit{}, ErrToolNotAllowed
	}
	proof := ToolAuthorizationProof{}
	proof[0] = 1
	return ToolAuthorizationPermit{
		Proof: proof, Durable: true, Scope: request.Scope, ServerID: request.ServerID,
		ToolName: request.ToolName, RequestDigest: request.RequestDigest,
	}, nil
}

func (stub *authorizerStub) setDenied(denied bool) {
	stub.mu.Lock()
	stub.denied = denied
	stub.mu.Unlock()
}

type credentialStub struct {
	mu       sync.Mutex
	request  CredentialRequest
	mutate   func(*CredentialPermit)
	rawValue string
	err      error
}

func (stub *credentialStub) Authorize(_ context.Context, request CredentialRequest) (CredentialPermit, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.request = request
	if stub.err != nil {
		return CredentialPermit{}, stub.err
	}
	proof := CredentialProof{}
	proof[0] = 1
	permit := CredentialPermit{
		Proof: proof, Durable: true, Handle: request.Handle, TenantID: request.TenantID,
		UserID: request.UserID, ServerID: request.ServerID, Audience: request.Audience,
		TargetRef: request.TargetRef,
	}
	if stub.mutate != nil {
		stub.mutate(&permit)
	}
	return permit, nil
}

type auditStub struct {
	mu     sync.Mutex
	events []AuditEvent
	err    error
}

func (stub *auditStub) Record(_ context.Context, event AuditEvent) error {
	stub.mu.Lock()
	stub.events = append(stub.events, event)
	err := stub.err
	stub.mu.Unlock()
	return err
}

type providerStub struct {
	mu              sync.Mutex
	availability    ServerAvailability
	availabilityErr error
	negotiations    int
	lastNegotiation NegotiationCommand
	negotiate       func(context.Context, NegotiationCommand) (StartNegotiationReceipt, error)
	starts          int
	lastCommand     ProviderCommand
	start           func(context.Context, ProviderCommand) (ProviderStartResult, error)
	cancel          func(context.Context, CancelCommand) (CancellationResult, error)
	lookup          func(context.Context, LedgerQuery) (LedgerRecord, error)
}

func (stub *providerStub) Availability(context.Context, ServerDescriptor) (ServerAvailability, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	return stub.availability, stub.availabilityErr
}

func (stub *providerStub) Negotiate(ctx context.Context, command NegotiationCommand) (StartNegotiationReceipt, error) {
	stub.mu.Lock()
	stub.negotiations++
	stub.lastNegotiation = command
	negotiate := stub.negotiate
	availability := stub.availability
	stub.mu.Unlock()
	if negotiate != nil {
		return negotiate(ctx, command)
	}
	return StartNegotiationReceipt{
		Durable: true, Scope: command.Scope, Server: command.Server,
		InvocationID: command.InvocationID, RequestDigest: command.RequestDigest, Attempt: command.Attempt,
		NegotiatedProtocolVersion: command.Server.ProtocolVersion, Affinity: command.Server.Affinity,
		SupportsInvocationLedger: availability.SupportsInvocationLedger,
		SupportsIdempotencyKey:   availability.SupportsIdempotencyKey, ConnectionGeneration: 1,
	}, nil
}

func (stub *providerStub) Start(ctx context.Context, command ProviderCommand) (ProviderStartResult, error) {
	stub.mu.Lock()
	stub.starts++
	stub.lastCommand = command
	start := stub.start
	stub.mu.Unlock()
	if start == nil {
		return ProviderStartResult{}, errors.New("unexpected provider start")
	}
	return start(ctx, command)
}

func (stub *providerStub) Cancel(ctx context.Context, command CancelCommand) (CancellationResult, error) {
	stub.mu.Lock()
	cancel := stub.cancel
	stub.mu.Unlock()
	if cancel == nil {
		return CancellationResult{Status: CancellationUnknown}, nil
	}
	return cancel(ctx, command)
}

func (stub *providerStub) Lookup(ctx context.Context, query LedgerQuery) (LedgerRecord, error) {
	stub.mu.Lock()
	lookup := stub.lookup
	stub.mu.Unlock()
	if lookup == nil {
		return LedgerRecord{InvocationID: query.InvocationID, RequestDigest: query.RequestDigest, Status: LedgerUnknown}, nil
	}
	return lookup(ctx, query)
}

func (stub *providerStub) startCount() int {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	return stub.starts
}

func (stub *providerStub) negotiationCount() int {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	return stub.negotiations
}

type gatewayFixture struct {
	gateway     *Gateway
	authority   *authorityStub
	authorizer  *authorizerStub
	credentials *credentialStub
	provider    *providerStub
	repository  *MemoryRepository
	scope       ValidatedAuthority
	server      ServerRegistration
	tool        ToolRegistration
	handle      CredentialHandle
}

func newGatewayFixture(t *testing.T, replay ReplayPolicy) gatewayFixture {
	t.Helper()
	scope := ValidatedAuthority{
		TenantID: mustID(t, identity.Tenant), UserID: mustID(t, identity.Subject),
		SessionID: mustID(t, identity.Session), TurnID: mustID(t, identity.Turn),
		RuntimeRevision: mustID(t, identity.RuntimeRevision),
		Generations:     Generations{TurnLease: 3, Placement: 5, Policy: 7},
	}
	handle, err := NewCredentialHandle("credential/internal-git/read-write")
	if err != nil {
		t.Fatal(err)
	}
	affinity := BackendAffinity{
		Backend: "nsjail", EnvironmentRevision: mustID(t, identity.EnvironmentRevision),
		Scope: ScopeSession, ResourceProfileDigest: digestWithByte(11),
		NetworkPolicyDigest: digestWithByte(12), SecretExposureClass: "proxy-only",
		SandboxProtocolVersion: "sandboxd/v1",
	}
	server := ServerRegistration{
		TenantID: scope.TenantID, UserID: scope.UserID, ServerID: "internal-git",
		ProviderID: "stdio", Transport: TransportStdio, TargetRef: "mcp-process/internal-git",
		ProtocolVersion: "2025-06-18", Affinity: affinity,
		Credential: CredentialBinding{Handle: handle, Audience: "mcp.internal-git"},
	}
	tool := ToolRegistration{
		TenantID: scope.TenantID, UserID: scope.UserID, ServerID: server.ServerID,
		ToolName: "repository.create", SideEffecting: true, ReplayPolicy: replay,
		MaxAutomaticRetries: 2, MaxConfirmationRetries: 2,
	}
	resolvedAffinity := affinity
	resolvedAffinity.ScopeID = scope.SessionID
	provider := &providerStub{availability: ServerAvailability{
		Available: true, DurableNegotiation: true, NegotiatedProtocolVersion: server.ProtocolVersion,
		Affinity: resolvedAffinity, SupportsInvocationLedger: true, SupportsIdempotencyKey: true,
	}}
	authority := &authorityStub{scope: scope}
	authorizer := &authorizerStub{}
	credentials := &credentialStub{rawValue: "raw-secret-must-never-leave-broker"}
	repository := NewMemoryRepository()
	gateway, err := NewGateway(Configuration{
		Bounds: testBounds(), Servers: []ServerRegistration{server}, Tools: []ToolRegistration{tool}, AllowReferenceMemory: true,
	}, Dependencies{
		Authority: authority, Authorizer: authorizer, Credentials: credentials,
		Repository: repository, Audit: &auditStub{}, Providers: map[string]Provider{"stdio": provider},
	})
	if err != nil {
		t.Fatal(err)
	}
	return gatewayFixture{
		gateway: gateway, authority: authority, authorizer: authorizer, credentials: credentials,
		provider: provider, repository: repository, scope: scope, server: server, tool: tool, handle: handle,
	}
}

func testBounds() Bounds {
	return Bounds{
		MaxAuthorityBytes: 1024, MaxServerIDBytes: 128, MaxToolNameBytes: 128,
		MaxTargetRefBytes: 256, MaxProtocolVersionBytes: 64, MaxCredentialHandleBytes: 256,
		MaxAudienceBytes: 128, MaxInputBytes: 4096, MaxInputDepth: 16,
		MaxProviderRequestIDBytes: 256, MaxExternalCommitIDBytes: 256,
		MaxChunkBytes: 1024, MaxChunks: 32, MaxOutputBytes: 8192,
		MaxFailureBytes: 512, MaxEvents: 128, CancelTimeout: 100000000,
	}
}

func TestGatewayRequiresFullConfiguredEventEnvelope(t *testing.T) {
	tests := []struct {
		name      string
		policy    ReplayPolicy
		automatic uint32
		confirm   uint32
		required  uint32
	}{
		{name: "safe", policy: ReplaySafe, automatic: 2, required: 32 + 4*2 + 10},
		{name: "idempotency", policy: ReplayIdempotencyKey, automatic: 2, required: 32 + 4*2 + 10},
		{name: "never", policy: ReplayNever, automatic: 2, required: 32 + 3*2 + 10},
		{name: "confirm", policy: ReplayConfirm, automatic: 2, confirm: 2, required: 32 + 3*2 + 10*2 + 12},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newGatewayFixture(t, test.policy)
			tool := fixture.tool
			tool.MaxAutomaticRetries = test.automatic
			tool.MaxConfirmationRetries = test.confirm
			dependencies := Dependencies{
				Authority: fixture.authority, Authorizer: fixture.authorizer, Credentials: fixture.credentials,
				Repository: NewMemoryRepository(), Audit: &auditStub{}, Providers: map[string]Provider{"stdio": fixture.provider},
			}
			bounds := testBounds()
			bounds.MaxEvents = test.required - 1
			_, err := NewGateway(Configuration{
				Bounds: bounds, Servers: []ServerRegistration{fixture.server}, Tools: []ToolRegistration{tool},
				AllowReferenceMemory: true,
			}, dependencies)
			if !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("undersized event envelope error=%v, want %v", err, ErrInvalidConfiguration)
			}

			bounds.MaxEvents = test.required
			if _, err := NewGateway(Configuration{
				Bounds: bounds, Servers: []ServerRegistration{fixture.server}, Tools: []ToolRegistration{tool},
				AllowReferenceMemory: true,
			}, dependencies); err != nil {
				t.Fatalf("exact event envelope rejected: %v", err)
			}
		})
	}
}

func TestCanonicalAdmissionIsDurablyIdempotent(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayIdempotencyKey)
	effectID := mustID(t, identity.Effect)
	invocationID := mustID(t, identity.Invocation)
	firstCall := CallRequest{
		ServerID: fixture.server.ServerID, ToolName: fixture.tool.ToolName,
		Input: canonical.Map{"message": "caf\u00e9", "nested": canonical.Map{"b": int64(2), "a": int64(1)}},
	}
	secondCall := CallRequest{
		ServerID: fixture.server.ServerID, ToolName: fixture.tool.ToolName,
		Input: canonical.Map{"nested": canonical.Map{"a": int64(1), "b": int64(2)}, "message": "cafe\u0301"},
	}
	firstDigest, err := CallRequestDigest(firstCall, testBounds())
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := CallRequestDigest(secondCall, testBounds())
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest != secondDigest {
		t.Fatalf("canonical requests produced different digests: %x != %x", firstDigest, secondDigest)
	}

	first, err := fixture.gateway.Admit(context.Background(), AdmissionRequest{
		Authority: OpaqueAuthority("turn-secret"), EffectID: effectID, InvocationID: invocationID,
		RequestDigest: firstDigest, Call: firstCall,
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := fixture.gateway.Admit(context.Background(), AdmissionRequest{
		Authority: OpaqueAuthority("turn-secret"), EffectID: effectID, InvocationID: invocationID,
		RequestDigest: secondDigest, Call: secondCall,
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Revision != 1 || second.Revision != first.Revision || first.RequestDigest != second.RequestDigest {
		t.Fatalf("idempotent admission changed durable effect: first=%+v second=%+v", first, second)
	}

	changed := firstCall
	changed.Input = canonical.Map{"message": "different"}
	changedDigest, err := CallRequestDigest(changed, testBounds())
	if err != nil {
		t.Fatal(err)
	}
	_, err = fixture.gateway.Admit(context.Background(), AdmissionRequest{
		Authority: OpaqueAuthority("turn-secret"), EffectID: effectID, InvocationID: invocationID,
		RequestDigest: changedDigest, Call: changed,
	})
	if !errors.Is(err, ErrInvocationConflict) {
		t.Fatalf("different request reused invocation: got %v, want %v", err, ErrInvocationConflict)
	}
}

func TestAdmissionRejectsCrossTenantAndUnpreparedDigest(t *testing.T) {
	fixture := newGatewayFixture(t, ReplaySafe)
	call := CallRequest{ServerID: fixture.server.ServerID, ToolName: fixture.tool.ToolName, Input: canonical.Map{"x": int64(1)}}
	digest, err := CallRequestDigest(call, testBounds())
	if err != nil {
		t.Fatal(err)
	}

	fixture.authority.mu.Lock()
	fixture.authority.scope.TenantID = mustID(t, identity.Tenant)
	fixture.authority.mu.Unlock()
	_, err = fixture.gateway.Admit(context.Background(), AdmissionRequest{
		Authority: OpaqueAuthority("turn-secret"), EffectID: mustID(t, identity.Effect),
		InvocationID: mustID(t, identity.Invocation), RequestDigest: digest, Call: call,
	})
	if !errors.Is(err, ErrServerNotAllowed) {
		t.Fatalf("cross-tenant admission error = %v, want %v", err, ErrServerNotAllowed)
	}

	fixture = newGatewayFixture(t, ReplaySafe)
	digest[0] ^= 0xff
	_, err = fixture.gateway.Admit(context.Background(), AdmissionRequest{
		Authority: OpaqueAuthority("turn-secret"), EffectID: mustID(t, identity.Effect),
		InvocationID: mustID(t, identity.Invocation), RequestDigest: digest, Call: call,
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("unprepared digest error = %v, want %v", err, ErrInvalidRequest)
	}
}

func TestAdmissionFailsClosedOnProtocolAffinityAndCredentialBinding(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*gatewayFixture)
		want   error
	}{
		{
			name: "protocol mismatch",
			mutate: func(fixture *gatewayFixture) {
				fixture.provider.availability.NegotiatedProtocolVersion = "2024-11-05"
			},
			want: ErrProtocolMismatch,
		},
		{
			name: "non-durable negotiation",
			mutate: func(fixture *gatewayFixture) {
				fixture.provider.availability.DurableNegotiation = false
			},
			want: ErrProtocolMismatch,
		},
		{
			name: "backend affinity mismatch",
			mutate: func(fixture *gatewayFixture) {
				fixture.provider.availability.Affinity.Backend = "docker"
			},
			want: ErrAffinityMismatch,
		},
		{
			name: "credential audience mismatch",
			mutate: func(fixture *gatewayFixture) {
				fixture.credentials.mutate = func(permit *CredentialPermit) { permit.Audience = "other-service" }
			},
			want: ErrCredentialMismatch,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newGatewayFixture(t, ReplayIdempotencyKey)
			test.mutate(&fixture)
			call := CallRequest{ServerID: fixture.server.ServerID, ToolName: fixture.tool.ToolName, Input: canonical.Map{"x": int64(1)}}
			digest, err := CallRequestDigest(call, testBounds())
			if err != nil {
				t.Fatal(err)
			}
			_, err = fixture.gateway.Admit(context.Background(), AdmissionRequest{
				Authority: OpaqueAuthority("turn-secret"), EffectID: mustID(t, identity.Effect),
				InvocationID: mustID(t, identity.Invocation), RequestDigest: digest, Call: call,
			})
			if !errors.Is(err, test.want) {
				t.Fatalf("admission error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestRawEndpointAndMissingSideEffectReplayPolicyAreRejectedAtConfiguration(t *testing.T) {
	fixture := newGatewayFixture(t, ReplaySafe)
	configuration := Configuration{Bounds: testBounds(), Servers: []ServerRegistration{fixture.server}, Tools: []ToolRegistration{fixture.tool}, AllowReferenceMemory: true}
	dependencies := Dependencies{
		Authority: fixture.authority, Authorizer: fixture.authorizer, Credentials: fixture.credentials,
		Repository: fixture.repository, Audit: &auditStub{}, Providers: map[string]Provider{"stdio": fixture.provider},
	}

	configuration.Servers[0].Transport = TransportStreamableHTTP
	configuration.Servers[0].TargetRef = "https://internal.example/mcp"
	configuration.Servers[0].Affinity = BackendAffinity{}
	_, err := NewGateway(configuration, dependencies)
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("raw endpoint configuration error = %v, want %v", err, ErrInvalidConfiguration)
	}

	configuration.Servers[0] = fixture.server
	configuration.Tools[0].ReplayPolicy = ""
	_, err = NewGateway(configuration, dependencies)
	if !errors.Is(err, ErrReplayPolicyRequired) {
		t.Fatalf("missing replay policy error = %v, want %v", err, ErrReplayPolicyRequired)
	}
}

func mustID(t *testing.T, kind identity.Kind) identity.ID {
	t.Helper()
	id, err := identity.New(kind)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func digestWithByte(value byte) Digest {
	digest := Digest{}
	digest[0] = value
	return digest
}
