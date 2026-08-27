package mcpgateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/dependency"
)

func TestProductionGatewayRejectsProbeVerifiedButUnsealedOperationalGraph(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	server := fixture.server
	server.AllowedServerRequests = []ServerRequestMethod{ServerRequestSampling}
	configuration := Configuration{
		Bounds: testBounds(), Servers: []ServerRegistration{server}, Tools: []ToolRegistration{fixture.tool},
	}
	groups := []dependency.AtomicGroup{
		AtomicMCPAuditOutbox, AtomicMCPAuthorityFence, AtomicMCPEffectLifecycle,
		AtomicMCPAuthorization, AtomicMCPProviderDispatch, AtomicMCPCredentialBinding, AtomicMCPSamplingBridge,
	}
	proofs := newMCPProductionProofs(t, "mcp-domain-a", groups)
	durability := NewMemoryRepository().Durability()
	durability.CrashDurable = true
	durability.ReferenceMemory = false
	repository := &durabilityOverrideRepository{MemoryRepository: NewMemoryRepository(), durability: durability}
	sampling := &samplingStub{result: SamplingResult{Durable: true}}

	production := ProductionDependencies{
		Authority: verifyMCPProduction(t, proofs, ProductionAuthorityValidator(&mcpProductionAuthority{
			AuthorityValidator: fixture.authority, proof: proofs.runtimeProof,
		})),
		Authorizer: verifyMCPProduction(t, proofs, ProductionToolAuthorizer(&mcpProductionAuthorizer{
			ToolAuthorizer: fixture.authorizer, proof: proofs.runtimeProof,
		})),
		Credentials: verifyMCPProduction(t, proofs, ProductionCredentialBroker(&mcpProductionCredentials{
			CredentialBroker: fixture.credentials, proof: proofs.runtimeProof,
		})),
		Repository: verifyMCPProduction(t, proofs, ProductionEffectRepository(&mcpProductionRepository{
			EffectRepository: repository, proof: proofs.runtimeProof,
		})),
		Audit: verifyMCPProduction(t, proofs, ProductionAuditSink(&mcpProductionAudit{
			AuditSink: &auditStub{}, proof: proofs.runtimeProof,
		})),
		Providers: map[string]dependency.Verified[ProductionProvider]{
			"stdio": verifyMCPProduction(t, proofs, ProductionProvider(&mcpProductionProvider{
				Provider: fixture.provider, proof: proofs.runtimeProof,
			})),
		},
		Sampling: verifyMCPProduction(t, proofs, ProductionSamplingBroker(&mcpProductionSampling{
			SamplingBroker: sampling, proof: proofs.runtimeProof,
		})),
	}
	gateway, err := NewProductionGateway(configuration, production)
	if gateway != nil || !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("probe-only operational graph gateway=%v error=%v", gateway, err)
	}
}

func TestProductionGatewayRejectsZeroOrCrossDomainProviderProof(t *testing.T) {
	fixture := newGatewayFixture(t, ReplayNever)
	configuration := Configuration{Bounds: testBounds(), Servers: []ServerRegistration{fixture.server}, Tools: []ToolRegistration{fixture.tool}}
	groups := []dependency.AtomicGroup{
		AtomicMCPAuditOutbox, AtomicMCPAuthorityFence, AtomicMCPEffectLifecycle,
		AtomicMCPAuthorization, AtomicMCPProviderDispatch, AtomicMCPCredentialBinding,
	}
	proofs := newMCPProductionProofs(t, "mcp-domain-a", groups)
	durability := NewMemoryRepository().Durability()
	durability.CrashDurable = true
	durability.ReferenceMemory = false
	repository := &durabilityOverrideRepository{MemoryRepository: NewMemoryRepository(), durability: durability}
	production := ProductionDependencies{
		Authority:   verifyMCPProduction(t, proofs, ProductionAuthorityValidator(&mcpProductionAuthority{AuthorityValidator: fixture.authority, proof: proofs.runtimeProof})),
		Authorizer:  verifyMCPProduction(t, proofs, ProductionToolAuthorizer(&mcpProductionAuthorizer{ToolAuthorizer: fixture.authorizer, proof: proofs.runtimeProof})),
		Credentials: verifyMCPProduction(t, proofs, ProductionCredentialBroker(&mcpProductionCredentials{CredentialBroker: fixture.credentials, proof: proofs.runtimeProof})),
		Repository:  verifyMCPProduction(t, proofs, ProductionEffectRepository(&mcpProductionRepository{EffectRepository: repository, proof: proofs.runtimeProof})),
		Audit:       verifyMCPProduction(t, proofs, ProductionAuditSink(&mcpProductionAudit{AuditSink: &auditStub{}, proof: proofs.runtimeProof})),
		Providers:   map[string]dependency.Verified[ProductionProvider]{"stdio": {}},
	}
	if _, err := NewProductionGateway(configuration, production); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("zero provider proof error=%v, want %v", err, ErrStoreUnavailable)
	}

	other := newMCPProductionProofs(t, "mcp-domain-b", groups)
	production.Providers["stdio"] = verifyMCPProduction(t, other, ProductionProvider(&mcpProductionProvider{
		Provider: fixture.provider, proof: other.runtimeProof,
	}))
	if _, err := NewProductionGateway(configuration, production); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("cross-domain provider proof error=%v, want %v", err, ErrStoreUnavailable)
	}
}

func fixtureDigest(t *testing.T, fixture gatewayFixture) Digest {
	t.Helper()
	digest, err := CallRequestDigest(CallRequest{
		ServerID: fixture.server.ServerID, ToolName: fixture.tool.ToolName, Input: mapInput("production"),
	}, testBounds())
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

type mcpProductionAuthority struct {
	AuthorityValidator
	proof mcpRuntimeProof
}

func (adapter *mcpProductionAuthority) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	return adapter.proof.respond(ctx, challenge)
}

type mcpProductionAuthorizer struct {
	ToolAuthorizer
	proof mcpRuntimeProof
}

func (adapter *mcpProductionAuthorizer) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	return adapter.proof.respond(ctx, challenge)
}

type mcpProductionCredentials struct {
	CredentialBroker
	proof mcpRuntimeProof
}

func (adapter *mcpProductionCredentials) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	return adapter.proof.respond(ctx, challenge)
}

type mcpProductionRepository struct {
	EffectRepository
	proof mcpRuntimeProof
}

func (adapter *mcpProductionRepository) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	return adapter.proof.respond(ctx, challenge)
}

type mcpProductionAudit struct {
	AuditSink
	proof mcpRuntimeProof
}

func (adapter *mcpProductionAudit) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	return adapter.proof.respond(ctx, challenge)
}

type mcpProductionProvider struct {
	Provider
	proof mcpRuntimeProof
}

func (adapter *mcpProductionProvider) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	return adapter.proof.respond(ctx, challenge)
}

type mcpProductionSampling struct {
	SamplingBroker
	proof mcpRuntimeProof
}

func (adapter *mcpProductionSampling) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	return adapter.proof.respond(ctx, challenge)
}

type mcpRuntimeProof struct {
	descriptor dependency.Descriptor
	privateKey ed25519.PrivateKey
}

func (proof mcpRuntimeProof) respond(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	if err := ctx.Err(); err != nil {
		return dependency.ProbeResponse{}, err
	}
	digest, err := dependency.ProbeSigningDigest(proof.descriptor, challenge.Nonce)
	if err != nil {
		return dependency.ProbeResponse{}, err
	}
	return dependency.ProbeResponse{
		Descriptor: proof.descriptor, KeyID: proof.descriptor.RuntimeKeyID,
		Signature: ed25519.Sign(proof.privateKey, []byte(digest)),
	}, nil
}

type mcpProductionProofs struct {
	verifier     *dependency.Verifier
	evidence     dependency.Evidence
	descriptor   dependency.Descriptor
	runtimeProof mcpRuntimeProof
}

func newMCPProductionProofs(t *testing.T, domain string, groups []dependency.AtomicGroup) mcpProductionProofs {
	t.Helper()
	conformancePublic, conformancePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	runtimePublic, runtimePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	verifier, err := dependency.NewVerifier(dependency.VerifierConfig{
		ConformanceRoots: map[string]ed25519.PublicKey{"mcp-conformance": conformancePublic},
		RuntimeRoots:     map[string]ed25519.PublicKey{"mcp-runtime": runtimePublic},
		Clock:            func() time.Time { return now }, Entropy: rand.Reader,
	})
	if err != nil {
		t.Fatal(err)
	}
	groups = append([]dependency.AtomicGroup(nil), groups...)
	slices.Sort(groups)
	descriptor := dependency.Descriptor{
		SchemaVersion: 1, BackendKind: dependency.BackendCelld,
		BuildDigest: "sha256:" + strings.Repeat("4", 64), ApplicationDigest: "sha256:" + strings.Repeat("5", 64),
		InstanceID: "mcp-production-instance", TransactionDomainID: domain,
		DurabilityClass: dependency.DurabilityCrashRPOZero, ConformanceRunID: "mcp-conformance-run",
		ConformanceDigest: "sha256:" + strings.Repeat("6", 64), RuntimeKeyID: "mcp-runtime",
		ProbeEpoch: 1, ProductionEligible: true, AtomicGroups: groups,
	}
	evidence := dependency.Evidence{
		Descriptor: descriptor, IssuedAtUnix: now.Add(-time.Minute).Unix(), ExpiresAtUnix: now.Add(time.Hour).Unix(),
		KeyID: "mcp-conformance",
	}
	digest, err := dependency.EvidenceSigningDigest(evidence)
	if err != nil {
		t.Fatal(err)
	}
	evidence.Signature = ed25519.Sign(conformancePrivate, []byte(digest))
	return mcpProductionProofs{
		verifier: verifier, evidence: evidence, descriptor: descriptor,
		runtimeProof: mcpRuntimeProof{descriptor: descriptor, privateKey: runtimePrivate},
	}
}

func verifyMCPProduction[T dependency.ProductionProbe](t *testing.T, proofs mcpProductionProofs, adapter T) dependency.Verified[T] {
	t.Helper()
	verified, err := dependency.VerifyDependency(context.Background(), proofs.verifier, adapter, proofs.evidence, dependency.Requirements{
		BackendKind: proofs.descriptor.BackendKind, BuildDigest: proofs.descriptor.BuildDigest,
		ApplicationDigest: proofs.descriptor.ApplicationDigest, InstanceID: proofs.descriptor.InstanceID,
		TransactionDomainID:  proofs.descriptor.TransactionDomainID,
		RequiredAtomicGroups: append([]dependency.AtomicGroup(nil), proofs.descriptor.AtomicGroups...),
		MinimumProbeEpoch:    proofs.descriptor.ProbeEpoch, MaximumEvidenceAge: time.Hour,
	})
	if err != nil {
		t.Fatalf("VerifyDependency() error=%v", err)
	}
	return verified
}
