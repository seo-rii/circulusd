package modelgateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/dependency"
	releasecontract "github.com/hancomac/circulusd/internal/release/contracttest"
)

func TestProductionGatewayAcceptsOnlyVerifiedAdapterInstances(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	configuration := fixture.configuration()
	configuration.AllowReferenceMemory = false
	proofs := newModelProductionProofs(t, []dependency.AtomicGroup{
		AtomicModelAuthorityFence,
		AtomicModelEffectLifecycle,
		AtomicModelQuotaSettlement,
	})
	raw := fixture.dependencies()
	authority := &productionAuthority{AuthorityValidator: raw.Authority, proof: proofs.runtimeProof}
	quota := &productionQuota{QuotaAdmitter: raw.Quota, proof: proofs.runtimeProof}
	dispatches := &productionDispatch{DispatchCoordinator: raw.Dispatches, proof: proofs.runtimeProof}
	dependencies := ProductionDependencies{
		Authority:    proofs.verifyAuthority(t, authority, AtomicModelAuthorityFence),
		Quota:        proofs.verifyQuota(t, quota, AtomicModelQuotaSettlement),
		Dispatches:   proofs.verifyDispatch(t, dispatches, AtomicModelEffectLifecycle),
		TokenCounter: raw.TokenCounter,
		Providers:    raw.Providers,
	}

	gateway, err := NewProductionGateway(configuration, dependencies)
	if err != nil {
		t.Fatalf("NewProductionGateway() error = %v", err)
	}
	if _, err := gateway.Admit(context.Background(), fixture.admissionRequest()); err != nil {
		t.Fatalf("Admit() through verified adapters error = %v", err)
	}
}

func TestProductionGatewayRejectsAValidProofForTheWrongAtomicContract(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	configuration := fixture.configuration()
	configuration.AllowReferenceMemory = false
	proofs := newModelProductionProofs(t, []dependency.AtomicGroup{dependency.AtomicCommandReceipt})
	raw := fixture.dependencies()
	authority := &productionAuthority{AuthorityValidator: raw.Authority, proof: proofs.runtimeProof}
	quota := &productionQuota{QuotaAdmitter: raw.Quota, proof: proofs.runtimeProof}
	dispatches := &productionDispatch{DispatchCoordinator: raw.Dispatches, proof: proofs.runtimeProof}
	dependencies := ProductionDependencies{
		Authority:    proofs.verifyAuthority(t, authority, dependency.AtomicCommandReceipt),
		Quota:        proofs.verifyQuota(t, quota, dependency.AtomicCommandReceipt),
		Dispatches:   proofs.verifyDispatch(t, dispatches, dependency.AtomicCommandReceipt),
		TokenCounter: raw.TokenCounter,
		Providers:    raw.Providers,
	}

	_, err := NewProductionGateway(configuration, dependencies)
	if !errors.Is(err, ErrStateDependenciesNotDurable) {
		t.Fatalf("NewProductionGateway(wrong atomic contract) error = %v, want ErrStateDependenciesNotDurable", err)
	}
}

func TestProductionGatewayRejectsReferenceConfigurationAndZeroProof(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	raw := fixture.dependencies()
	configuration := fixture.configuration()
	proofs := newModelProductionProofs(t, []dependency.AtomicGroup{
		AtomicModelAuthorityFence,
		AtomicModelEffectLifecycle,
		AtomicModelQuotaSettlement,
	})
	quota := &productionQuota{QuotaAdmitter: raw.Quota, proof: proofs.runtimeProof}
	dispatches := &productionDispatch{DispatchCoordinator: raw.Dispatches, proof: proofs.runtimeProof}
	dependencies := ProductionDependencies{
		Quota:        proofs.verifyQuota(t, quota, AtomicModelQuotaSettlement),
		Dispatches:   proofs.verifyDispatch(t, dispatches, AtomicModelEffectLifecycle),
		TokenCounter: raw.TokenCounter,
		Providers:    raw.Providers,
	}

	if _, err := NewProductionGateway(configuration, dependencies); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("NewProductionGateway(reference configuration) error = %v, want ErrInvalidConfiguration", err)
	}
	configuration.AllowReferenceMemory = false
	if _, err := NewProductionGateway(configuration, dependencies); !errors.Is(err, ErrStateDependenciesNotDurable) {
		t.Fatalf("NewProductionGateway(zero authority proof) error = %v, want ErrStateDependenciesNotDurable", err)
	}
}

type productionAuthority struct {
	AuthorityValidator
	proof modelRuntimeProof
}

func (*productionAuthority) Durability() AuthorityDurability {
	return AuthorityDurability{CrashDurable: true, CurrentGenerationFencing: true}
}

func (adapter *productionAuthority) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	return adapter.proof.respond(ctx, challenge)
}

type productionQuota struct {
	QuotaAdmitter
	proof modelRuntimeProof
}

func (*productionQuota) Durability() QuotaDurability {
	return QuotaDurability{CrashDurable: true, AtomicReservationSettlement: true}
}

func (adapter *productionQuota) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	return adapter.proof.respond(ctx, challenge)
}

type productionDispatch struct {
	DispatchCoordinator
	proof modelRuntimeProof
}

func (*productionDispatch) Durability() DispatchDurability {
	return DispatchDurability{CrashDurable: true, AtomicEffectTransitions: true, ExclusiveDispatchClaim: true}
}

func (adapter *productionDispatch) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	return adapter.proof.respond(ctx, challenge)
}

type modelRuntimeProof struct {
	descriptor dependency.Descriptor
	privateKey ed25519.PrivateKey
}

func (proof modelRuntimeProof) respond(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	if err := ctx.Err(); err != nil {
		return dependency.ProbeResponse{}, err
	}
	digest, err := dependency.ProbeSigningDigest(proof.descriptor, challenge.Nonce)
	if err != nil {
		return dependency.ProbeResponse{}, err
	}
	return dependency.ProbeResponse{
		Descriptor: proof.descriptor,
		KeyID:      proof.descriptor.RuntimeKeyID,
		Signature:  ed25519.Sign(proof.privateKey, []byte(digest)),
	}, nil
}

type modelProductionProofs struct {
	verifier     *dependency.Verifier
	evidence     dependency.Evidence
	descriptor   dependency.Descriptor
	runtimeProof modelRuntimeProof
}

func newModelProductionProofs(t *testing.T, atomicGroups []dependency.AtomicGroup) modelProductionProofs {
	t.Helper()
	conformancePublic, conformancePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(conformance) error = %v", err)
	}
	runtimePublic, runtimePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(runtime) error = %v", err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	verifier, err := dependency.NewVerifier(dependency.VerifierConfig{
		ConformanceRoots: map[string]ed25519.PublicKey{"conformance-root": conformancePublic},
		RuntimeRoots:     map[string]ed25519.PublicKey{"runtime-root": runtimePublic},
		Clock:            func() time.Time { return now },
		Entropy:          rand.Reader,
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	descriptor := dependency.Descriptor{
		SchemaVersion:       1,
		BackendKind:         dependency.BackendCelld,
		BuildDigest:         "sha256:" + strings.Repeat("1", 64),
		ApplicationDigest:   "sha256:" + strings.Repeat("2", 64),
		InstanceID:          "state-instance-a",
		TransactionDomainID: "state-domain-a",
		DurabilityClass:     dependency.DurabilityCrashRPOZero,
		ConformanceRunID:    "model-gateway-run-1",
		ConformanceDigest:   "sha256:" + strings.Repeat("3", 64),
		RuntimeKeyID:        "runtime-root",
		ProbeEpoch:          1,
		ProductionEligible:  true,
		AtomicGroups:        append([]dependency.AtomicGroup(nil), atomicGroups...),
	}
	evidence := dependency.Evidence{
		Descriptor:    descriptor,
		IssuedAtUnix:  now.Add(-time.Minute).Unix(),
		ExpiresAtUnix: now.Add(time.Hour).Unix(),
		KeyID:         "conformance-root",
	}
	digest, err := dependency.EvidenceSigningDigest(evidence)
	if err != nil {
		t.Fatalf("EvidenceSigningDigest() error = %v", err)
	}
	evidence.Signature = ed25519.Sign(conformancePrivate, []byte(digest))
	return modelProductionProofs{
		verifier:     verifier,
		evidence:     evidence,
		descriptor:   descriptor,
		runtimeProof: modelRuntimeProof{descriptor: descriptor, privateKey: runtimePrivate},
	}
}

func (proofs *modelProductionProofs) verifyAuthority(t *testing.T, adapter *productionAuthority, group dependency.AtomicGroup) dependency.Verified[ProductionAuthorityValidator] {
	t.Helper()
	verified, err := dependency.VerifyDependency(context.Background(), proofs.verifier, ProductionAuthorityValidator(adapter), proofs.evidence, proofs.requirements(t, group))
	if err != nil {
		t.Fatalf("VerifyDependency(authority) error = %v", err)
	}
	return verified
}

func (proofs *modelProductionProofs) verifyQuota(t *testing.T, adapter *productionQuota, group dependency.AtomicGroup) dependency.Verified[ProductionQuotaAdmitter] {
	t.Helper()
	verified, err := dependency.VerifyDependency(context.Background(), proofs.verifier, ProductionQuotaAdmitter(adapter), proofs.evidence, proofs.requirements(t, group))
	if err != nil {
		t.Fatalf("VerifyDependency(quota) error = %v", err)
	}
	return verified
}

func (proofs *modelProductionProofs) verifyDispatch(t *testing.T, adapter *productionDispatch, group dependency.AtomicGroup) dependency.Verified[ProductionDispatchCoordinator] {
	t.Helper()
	verified, err := dependency.VerifyDependency(context.Background(), proofs.verifier, ProductionDispatchCoordinator(adapter), proofs.evidence, proofs.requirements(t, group))
	if err != nil {
		t.Fatalf("VerifyDependency(dispatch) error = %v", err)
	}
	return verified
}

func (proofs modelProductionProofs) requirements(t *testing.T, group dependency.AtomicGroup) dependency.Requirements {
	t.Helper()
	artifacts := releasecontract.StateArtifactDigests(t, proofs.descriptor.BuildDigest, proofs.descriptor.ApplicationDigest)
	requirements, err := dependency.NewProductionRequirements(artifacts, dependency.ProductionRequirementsConfig{
		InstanceID:           proofs.descriptor.InstanceID,
		TransactionDomainID:  proofs.descriptor.TransactionDomainID,
		RequiredAtomicGroups: []dependency.AtomicGroup{group},
		MinimumProbeEpoch:    proofs.descriptor.ProbeEpoch,
		MaximumEvidenceAge:   time.Hour,
	})
	if err != nil {
		t.Fatalf("NewProductionRequirements() error = %v", err)
	}
	return requirements
}
