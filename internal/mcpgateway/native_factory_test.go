package mcpgateway

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/celldbridge"
	"github.com/hancomac/circulusd/internal/dependency"
	"github.com/hancomac/circulusd/internal/effectledger"
)

type nativeFactoryFixture struct {
	factory       *NativeFactory
	source        *nativeRepositoryFixtureSource
	proofs        mcpProductionProofs
	reference     gatewayFixture
	effect        Effect
	configuration Configuration
	grant         NativeAuthorityGrant
	bearer        OpaqueAuthority
	now           time.Time
}

func newNativeFactoryFixture(t *testing.T) nativeFactoryFixture {
	t.Helper()
	reference := newGatewayFixture(t, ReplayNever)
	server := reference.server
	server.Credential = CredentialBinding{}
	configuration := Configuration{Bounds: testBounds(), Servers: []ServerRegistration{server}, Tools: []ToolRegistration{reference.tool}}
	refConfig := configuration
	refConfig.AllowReferenceMemory = true
	refGateway, err := NewGateway(refConfig, Dependencies{Authority: reference.authority, Authorizer: reference.authorizer, Repository: reference.repository,
		Audit: &auditStub{}, Providers: map[string]Provider{server.ProviderID: reference.provider}})
	if err != nil {
		t.Fatal(err)
	}
	reference.gateway = refGateway
	reference.server = server
	effect := admitFixtureEffect(t, reference)
	groups := append(nativeRepositoryGroups(), celldbridge.AtomicNativeStorage, dependency.AtomicEffectLifecycle, effectledger.AtomicProviderObservationLedger)
	proofs := newMCPProductionProofs(t, "native-mcp-factory-test", groups)
	source := &nativeRepositoryFixtureSource{mcpRuntimeProof: proofs.runtimeProof}
	binding := verifyMCPProduction(t, proofs, nativeRepositorySource(source))
	now := time.Unix(1_800_000_000, 123456789)
	repository, err := newNativeRepository(source, binding, func() error { _, _, err := binding.Open(); return err }, "native-mcp-factory-test", 128, 1<<20, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	factory, err := newNativeFactory(repository, configuration, map[string]NativeProviderConfig{server.ProviderID: {UnavailableReason: "actual MCP transport is not configured"}})
	if err != nil {
		t.Fatal(err)
	}
	bearer := OpaqueAuthority("fixture-only native bearer")
	digest, err := NativeBearerDigest(bearer)
	if err != nil {
		t.Fatal(err)
	}
	grant := NativeAuthorityGrant{BearerDigest: digest, Scope: effect.Scope, RequestDigest: effect.RequestDigest, ExpiresAtUnixNano: now.Add(time.Minute).UnixNano(),
		Permissions: []string{"mcp.cancel", "mcp.recover", "mcp.tools.call"}}
	return nativeFactoryFixture{factory, source, proofs, reference, effect, configuration, grant, bearer, now}
}

func qualifyNativeFactory(t *testing.T, fixture nativeFactoryFixture) ProductionDependencies {
	t.Helper()
	candidates := fixture.factory.Candidates()
	providers := make(map[string]dependency.Verified[ProductionProvider], len(candidates.Providers))
	for id, provider := range candidates.Providers {
		providers[id] = verifyMCPProduction(t, fixture.proofs, provider)
	}
	production := ProductionDependencies{Authority: verifyMCPProduction(t, fixture.proofs, candidates.Authority), Authorizer: verifyMCPProduction(t, fixture.proofs, candidates.Authorizer),
		Repository: verifyMCPProduction(t, fixture.proofs, candidates.Repository), Audit: verifyMCPProduction(t, fixture.proofs, candidates.Audit), Providers: providers}
	sealed, err := fixture.factory.SealDependencies(production)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func provisionNativeFixture(t *testing.T, fixture nativeFactoryFixture) ToolAuthorizationPermit {
	t.Helper()
	ctx := context.Background()
	if err := fixture.factory.ProvisionGrant(ctx, fixture.grant); err != nil {
		t.Fatal(err)
	}
	permit, err := fixture.factory.authorizer.Authorize(ctx, ToolAuthorizationRequest{Scope: fixture.effect.Scope, ServerID: fixture.effect.ServerID, ToolName: fixture.effect.ToolName,
		RequestDigest: fixture.effect.RequestDigest, Permission: "mcp.tools.call"})
	if err != nil {
		t.Fatal(err)
	}
	return permit
}

func TestNativeFactorySealsExactCandidatesButKeepsActualProviderUnavailable(t *testing.T) {
	fixture := newNativeFactoryFixture(t)
	production := qualifyNativeFactory(t, fixture)
	gateway, err := NewProductionGateway(fixture.configuration, production)
	if err != nil || gateway == nil {
		t.Fatalf("sealed exact native factory: %v", err)
	}
	provisionNativeFixture(t, fixture)
	input, err := canonical.Decode(fixture.effect.InputCanonical, canonical.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	_, err = gateway.Admit(context.Background(), AdmissionRequest{Authority: fixture.bearer, EffectID: fixture.effect.Scope.EffectID, InvocationID: fixture.effect.Scope.InvocationID,
		RequestDigest: fixture.effect.RequestDigest, Call: CallRequest{ServerID: fixture.effect.ServerID, ToolName: fixture.effect.ToolName, Input: input}})
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("unavailable provider enabled actual admission: %v", err)
	}
	state, err := decodeNativeState(fixture.source.state, fixture.factory.repository.objectID, 128, 1<<20)
	if err != nil || len(state.Repository.effects) != 0 {
		t.Fatal("unavailable provider manufactured an admitted effect")
	}
	for id := range production.Providers {
		delete(production.Providers, id)
	}
	if _, err := NewProductionGateway(fixture.configuration, production); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatal("mutable verified provider map changed a sealed graph")
	}
}

func TestNativeFactoryRejectsProbeWrappersCrossFactoryAndChangedPolicy(t *testing.T) {
	fixture := newNativeFactoryFixture(t)
	sealed := qualifyNativeFactory(t, fixture)
	wrapped := sealed
	wrapped.Repository = verifyMCPProduction(t, fixture.proofs, ProductionEffectRepository(&mcpProductionRepository{EffectRepository: fixture.factory.repository, proof: fixture.proofs.runtimeProof}))
	if _, err := fixture.factory.SealDependencies(wrapped); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatal("genuine probe wrapper obtained a sealed operational repository")
	}
	if _, err := NewProductionGateway(fixture.configuration, wrapped); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatal("a copied factory seal authenticated different operations")
	}
	otherRepository, err := newNativeRepository(fixture.source, fixture.factory.repository.binding, fixture.factory.repository.check,
		"different-native-factory", 128, 1<<20, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	other, err := newNativeFactory(otherRepository, fixture.configuration, map[string]NativeProviderConfig{fixture.effect.ProviderID: {UnavailableReason: "not configured"}})
	if err != nil {
		t.Fatal(err)
	}
	wrapped = sealed
	wrapped.Authority = verifyMCPProduction(t, fixture.proofs, ProductionAuthorityValidator(other.authority))
	if _, err := fixture.factory.SealDependencies(wrapped); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatal("same native probe authenticated a different factory aggregate")
	}
}

func TestNativeFactoryRejectsChangedConfigurationAndUnsupportedSources(t *testing.T) {
	fixture := newNativeFactoryFixture(t)
	sealed := qualifyNativeFactory(t, fixture)
	changed := cloneNativeConfiguration(fixture.configuration)
	changed.Tools[0].ToolName = "different.tool"
	if _, err := NewProductionGateway(changed, sealed); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatal("sealed graph used an unmeasured tool policy")
	}
	reference := fixture.configuration
	reference.AllowReferenceMemory = true
	if _, err := NewProductionGateway(reference, sealed); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatal("reference-memory option entered a native graph")
	}
	configuration := cloneNativeConfiguration(fixture.configuration)
	configuration.Servers[0].Credential = fixture.reference.server.Credential
	handle, err := NewCredentialHandle("credential/needs-real-registry")
	if err != nil {
		t.Fatal(err)
	}
	configuration.Servers[0].Credential = CredentialBinding{Handle: handle, Audience: "real-mcp"}
	repository, _ := nativeRepositoryFixture(t)
	if _, err := newNativeFactory(repository, configuration, map[string]NativeProviderConfig{"stdio": {UnavailableReason: "not configured"}}); !errors.Is(err, ErrCredentialUnavailable) {
		t.Fatal("factory minted a credential broker without its actual registry")
	}
	repository, _ = nativeRepositoryFixture(t)
	configuration = cloneNativeConfiguration(fixture.configuration)
	configuration.Servers[0].AllowedServerRequests = []ServerRequestMethod{ServerRequestSampling}
	if _, err := newNativeFactory(repository, configuration, map[string]NativeProviderConfig{"stdio": {UnavailableReason: "not configured"}}); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatal("factory accepted an unimplemented sampling bridge")
	}
	if _, err := NewNativeFactory(NativeFactoryConfig{Configuration: fixture.configuration}); !errors.Is(err, dependency.ErrUnverifiedDependency) {
		t.Fatal("factory accepted absent native source evidence")
	}
}

func TestNativeFactoryPersistedGrantsRejectWrongExpiredAndRotatedAuthority(t *testing.T) {
	fixture := newNativeFactoryFixture(t)
	ctx := context.Background()
	factory := fixture.factory
	provisionNativeFixture(t, fixture)
	if _, err := factory.repository.Admit(ctx, fixture.effect); err != nil {
		t.Fatal(err)
	}
	request := AuthorityRequest{EffectID: fixture.effect.Scope.EffectID, InvocationID: fixture.effect.Scope.InvocationID, RequestDigest: fixture.effect.RequestDigest, Permission: "mcp.tools.call"}
	got, err := factory.authority.ValidateAdmission(ctx, fixture.bearer, request)
	if err != nil || got != fixture.effect.Scope {
		t.Fatalf("exact persisted native grant: %v", err)
	}
	if _, err := factory.authority.ValidateAdmission(ctx, OpaqueAuthority("different bearer"), request); !errors.Is(err, ErrAuthorityMismatch) {
		t.Fatal("different bearer obtained admission")
	}
	wrong := request
	wrong.RequestDigest = digestWithByte(91)
	if _, err := factory.authority.ValidateAdmission(ctx, fixture.bearer, wrong); !errors.Is(err, ErrStaleAuthority) {
		t.Fatal("grant accepted a different immutable request")
	}
	changed := fixture.grant
	changed.ExpiresAtUnixNano++
	if err := factory.ProvisionGrant(ctx, changed); !errors.Is(err, ErrAuthorityMismatch) {
		t.Fatal("existing bearer grant was overwritten")
	}
	factory.repository.now = func() time.Time { return fixture.now.Add(2 * time.Minute) }
	if _, err := factory.authority.ValidateAdmission(ctx, fixture.bearer, request); !errors.Is(err, ErrStaleAuthority) {
		t.Fatal("expired admission grant accepted")
	}
	current, err := factory.authority.ValidateCurrent(ctx, fixture.bearer, CurrentAuthorityRequest{Scope: fixture.effect.Scope, RequestDigest: fixture.effect.RequestDigest, Permission: "mcp.cancel"})
	if err != nil || current != fixture.effect.Scope {
		t.Fatal("admission TTL disabled cleanup of an already admitted effect")
	}
	rotated := fixture.effect.Scope
	rotated.Generations.Policy++
	if err := factory.repository.SetCurrentAuthority(ctx, rotated); err != nil {
		t.Fatal(err)
	}
	if _, err := factory.authority.ValidateCurrent(ctx, fixture.bearer, CurrentAuthorityRequest{Scope: fixture.effect.Scope, RequestDigest: fixture.effect.RequestDigest, Permission: "mcp.cancel"}); !errors.Is(err, ErrStaleAuthority) {
		t.Fatal("native current fence rotation was bypassed")
	}
	if err := factory.repository.SetCurrentAuthority(ctx, fixture.effect.Scope); !errors.Is(err, ErrStaleAuthority) {
		t.Fatal("operator fence rollback revived stale authority")
	}
}

func TestNativeFactoryExpiredGrantCannotInventCurrentCleanupAuthority(t *testing.T) {
	fixture := newNativeFactoryFixture(t)
	provisionNativeFixture(t, fixture)
	fixture.factory.repository.now = func() time.Time { return fixture.now.Add(2 * time.Minute) }
	if _, err := fixture.factory.authority.ValidateCurrent(context.Background(), fixture.bearer, CurrentAuthorityRequest{Scope: fixture.effect.Scope,
		RequestDigest: fixture.effect.RequestDigest, Permission: "mcp.cancel"}); !errors.Is(err, ErrStaleAuthority) {
		t.Fatal("expired unadmitted grant obtained cleanup authority")
	}
}

func TestNativeFactoryRepositoryRejectsFabricatedPermitAndTTLGap(t *testing.T) {
	fixture := newNativeFactoryFixture(t)
	ctx := context.Background()
	permit := provisionNativeFixture(t, fixture)
	if _, err := fixture.factory.repository.Admit(ctx, fixture.effect); err != nil {
		t.Fatal(err)
	}
	next := applyFixtureEvent(t, fixture.reference.gateway, fixture.effect, Event{Kind: EventBeginDispatch})
	request := DispatchClaimRequest{ExpectedRevision: fixture.effect.Revision, CurrentScope: fixture.effect.Scope, Previous: fixture.effect, Next: next, Authorization: permit}
	fabricated := request
	fabricated.Authorization.Proof = ToolAuthorizationProof(digestWithByte(51))
	before := bytes.Clone(fixture.source.state)
	if _, err := fixture.factory.repository.CommitAndClaimDispatch(ctx, fabricated); !errors.Is(err, ErrAuthorizationMismatch) || !bytes.Equal(before, fixture.source.state) {
		t.Fatalf("fabricated durable permit entered native claim: %v", err)
	}
	fixture.factory.repository.now = func() time.Time { return fixture.now.Add(2 * time.Minute) }
	if _, err := fixture.factory.repository.CommitAndClaimDispatch(ctx, request); !errors.Is(err, ErrAuthorizationMismatch) {
		t.Fatal("admission expiry between validation and atomic dispatch was bypassed")
	}
}

func TestNativeFactoryAuditDeliveryIsNativeExactAndIdempotent(t *testing.T) {
	fixture := newNativeFactoryFixture(t)
	provisionNativeFixture(t, fixture)
	ctx := context.Background()
	event := AuditEvent{TenantID: fixture.effect.Scope.TenantID, UserID: fixture.effect.Scope.UserID, SessionID: fixture.effect.Scope.SessionID, TurnID: fixture.effect.Scope.TurnID,
		InvocationID: fixture.effect.Scope.InvocationID, ServerID: fixture.effect.ServerID, Method: "tools/call", Decision: "denied"}
	envelope, err := fixture.factory.repository.AppendAudit(ctx, event)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.factory.audit.Record(ctx, envelope.Event); err != nil {
		t.Fatal(err)
	}
	state, err := decodeNativeState(fixture.source.state, fixture.factory.repository.objectID, 128, 1<<20)
	if err != nil || state.DeliveredAudits[envelope.Sequence] != envelope.Event {
		t.Fatal("audit delivery existed only in process memory")
	}
	if err := fixture.factory.repository.AcknowledgeAudit(ctx, envelope.Sequence); err != nil {
		t.Fatal(err)
	}
	if err := fixture.factory.audit.Record(ctx, envelope.Event); err != nil {
		t.Fatal("durable exact audit delivery was not idempotent after acknowledgment")
	}
	changed := envelope.Event
	changed.Reason = "different event"
	if err := fixture.factory.audit.Record(ctx, changed); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatal("delivered audit sequence was reused with different facts")
	}
	fixture.source.barrierError = errors.New("backend secret must remain redacted")
	if err := fixture.factory.audit.Record(ctx, envelope.Event); !errors.Is(err, ErrStoreUnavailable) || strings.Contains(err.Error(), "backend secret") {
		t.Fatal("audit delivery bypassed exact native barrier or exposed its source error")
	}
}

func TestNativeFactoryProbeAlwaysChallengesCapturedOperationalSource(t *testing.T) {
	fixture := newNativeFactoryFixture(t)
	provisionNativeFixture(t, fixture)
	challenge := dependency.ProbeChallenge{Nonce: bytes.Repeat([]byte{17}, dependency.ChallengeBytes)}
	for _, candidate := range []dependency.ProductionProbe{fixture.factory.authority, fixture.factory.authorizer, fixture.factory.repository, fixture.factory.audit, fixture.factory.providers[fixture.effect.ProviderID]} {
		response, err := candidate.ProbeProduction(context.Background(), challenge)
		expected, expectedErr := fixture.source.ProbeProduction(context.Background(), challenge)
		if err != nil || expectedErr != nil || !reflect.DeepEqual(response, expected) {
			t.Fatal("operational adapter challenged a different native source")
		}
	}
}
