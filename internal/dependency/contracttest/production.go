// Package contracttest provides signed production dependency fixtures for
// cross-package constructor tests that cannot mint dependency.Verified values.
package contracttest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/dependency"
	"github.com/hancomac/circulusd/internal/release"
	releasecontract "github.com/hancomac/circulusd/internal/release/contracttest"
)

// ProductionProofs owns one immutable signed descriptor and both independent
// verifier trust domains. Embed it in a test adapter, or forward that adapter's
// ProbeProduction method to it, so Verify seals the exact operational object.
type ProductionProofs struct {
	descriptor        dependency.Descriptor
	evidence          dependency.Evidence
	verifier          *dependency.Verifier
	runtimePrivateKey ed25519.PrivateKey
	artifacts         release.AuthenticatedStateArtifactDigests
}

func NewProductionProofs(
	t testing.TB,
	atomicGroups []dependency.AtomicGroup,
) *ProductionProofs {
	t.Helper()
	conformancePublic, conformancePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(conformance) error = %v", err)
	}
	runtimePublic, runtimePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(runtime) error = %v", err)
	}
	descriptor := dependency.Descriptor{
		SchemaVersion:       1,
		BackendKind:         dependency.BackendCelld,
		BuildDigest:         "sha256:" + strings.Repeat("1", 64),
		ApplicationDigest:   "sha256:" + strings.Repeat("2", 64),
		InstanceID:          "state-node-contract-test",
		TransactionDomainID: "state-domain-contract-test",
		DurabilityClass:     dependency.DurabilityCrashRPOZero,
		ConformanceRunID:    "state-conformance-contract-test",
		ConformanceDigest:   "sha256:" + strings.Repeat("3", 64),
		RuntimeKeyID:        "state-runtime-contract-test",
		ProbeEpoch:          7,
		ProductionEligible:  true,
		AtomicGroups:        append([]dependency.AtomicGroup(nil), atomicGroups...),
	}
	now := time.Unix(1_900_000_000, 0).UTC()
	evidence := dependency.Evidence{
		Descriptor:   descriptor,
		IssuedAtUnix: now.Add(-time.Minute).Unix(), ExpiresAtUnix: now.Add(time.Hour).Unix(),
		KeyID: "state-conformance-contract-test",
	}
	digest, err := dependency.EvidenceSigningDigest(evidence)
	if err != nil {
		t.Fatalf("EvidenceSigningDigest() error = %v", err)
	}
	evidence.Signature = ed25519.Sign(conformancePrivate, []byte(digest))
	verifier, err := dependency.NewVerifier(dependency.VerifierConfig{
		ConformanceRoots: map[string]ed25519.PublicKey{evidence.KeyID: conformancePublic},
		RuntimeRoots:     map[string]ed25519.PublicKey{descriptor.RuntimeKeyID: runtimePublic},
		Clock:            func() time.Time { return now },
		Entropy:          rand.Reader,
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	return &ProductionProofs{
		descriptor: descriptor, evidence: evidence, verifier: verifier,
		runtimePrivateKey: append(ed25519.PrivateKey(nil), runtimePrivate...),
		artifacts: releasecontract.StateArtifactDigests(
			t, descriptor.BuildDigest, descriptor.ApplicationDigest,
		),
	}
}

func (proofs *ProductionProofs) ProbeProduction(
	ctx context.Context,
	challenge dependency.ProbeChallenge,
) (dependency.ProbeResponse, error) {
	if proofs == nil || ctx == nil || len(challenge.Nonce) != dependency.ChallengeBytes {
		return dependency.ProbeResponse{}, dependency.ErrInvalidConfiguration
	}
	if err := ctx.Err(); err != nil {
		return dependency.ProbeResponse{}, err
	}
	descriptor := proofs.Descriptor()
	digest, err := dependency.ProbeSigningDigest(descriptor, challenge.Nonce)
	if err != nil {
		return dependency.ProbeResponse{}, dependency.ErrUnverifiedDependency
	}
	return dependency.ProbeResponse{
		Descriptor: descriptor,
		KeyID:      descriptor.RuntimeKeyID,
		Signature:  ed25519.Sign(proofs.runtimePrivateKey, []byte(digest)),
	}, nil
}

func (proofs *ProductionProofs) Descriptor() dependency.Descriptor {
	if proofs == nil {
		return dependency.Descriptor{}
	}
	descriptor := proofs.descriptor
	descriptor.AtomicGroups = append([]dependency.AtomicGroup(nil), descriptor.AtomicGroups...)
	return descriptor
}

func Verify[T dependency.ProductionProbe](
	t testing.TB,
	proofs *ProductionProofs,
	candidate T,
	requiredAtomicGroups []dependency.AtomicGroup,
) dependency.Verified[T] {
	t.Helper()
	if proofs == nil {
		t.Fatal("production proofs are nil")
	}
	descriptor := proofs.Descriptor()
	requirements, err := dependency.NewProductionRequirements(
		proofs.artifacts,
		dependency.ProductionRequirementsConfig{
			InstanceID: descriptor.InstanceID, TransactionDomainID: descriptor.TransactionDomainID,
			RequiredAtomicGroups: append([]dependency.AtomicGroup(nil), requiredAtomicGroups...),
			MinimumProbeEpoch:    descriptor.ProbeEpoch, MaximumEvidenceAge: time.Hour,
		},
	)
	if err != nil {
		t.Fatalf("NewProductionRequirements() error = %v", err)
	}
	evidence := proofs.evidence
	evidence.Descriptor = descriptor
	evidence.Signature = append([]byte(nil), evidence.Signature...)
	verified, err := dependency.VerifyDependency(
		context.Background(), proofs.verifier, candidate, evidence, requirements,
	)
	if err != nil {
		t.Fatalf("VerifyDependency() error = %v", err)
	}
	return verified
}
