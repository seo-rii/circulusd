package dependency

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestVerifiedDependencyRequiresSignedConformanceAndLiveRuntimeProof(t *testing.T) {
	t.Parallel()

	fixture := newVerificationFixture(t, "state-domain-a")
	probe := &signedProbe{descriptor: fixture.descriptor, privateKey: fixture.runtimePrivateKey}
	verified, err := VerifyDependency(context.Background(), fixture.verifier, probe, fixture.evidence, fixture.requirements())
	if err != nil {
		t.Fatalf("VerifyDependency() error = %v", err)
	}

	opened, descriptor, err := verified.Open()
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if opened != probe {
		t.Fatal("Open() returned a different dependency instance")
	}
	if descriptor.TransactionDomainID != "state-domain-a" || descriptor.BackendKind != BackendCelld {
		t.Fatalf("Open() descriptor = %#v", descriptor)
	}
	if probe.calls.Load() != 1 {
		t.Fatalf("ProbeProduction() calls = %d, want 1", probe.calls.Load())
	}
}

func TestSelfReportedProductionFlagsCannotMintAVerifiedDependency(t *testing.T) {
	t.Parallel()

	fixture := newVerificationFixture(t, "state-domain-a")
	probe := &signedProbe{descriptor: fixture.descriptor, privateKey: fixture.runtimePrivateKey}
	unsigned := fixture.evidence
	unsigned.Signature = nil

	_, err := VerifyDependency(context.Background(), fixture.verifier, probe, unsigned, fixture.requirements())
	if !errors.Is(err, ErrUnverifiedDependency) {
		t.Fatalf("VerifyDependency(unsigned) error = %v, want ErrUnverifiedDependency", err)
	}
	if probe.calls.Load() != 0 {
		t.Fatalf("ProbeProduction() calls = %d, want evidence rejection before runtime probe", probe.calls.Load())
	}
}

func TestReferenceMemoryCannotEnterTheProductionDependencyGraph(t *testing.T) {
	t.Parallel()

	fixture := newVerificationFixture(t, "state-domain-a")
	requirements := fixture.requirements()
	fixture.descriptor.BackendKind = BackendReferenceMemory
	fixture.descriptor.DurabilityClass = DurabilityProcessLocal
	fixture.descriptor.ProductionEligible = false
	fixture.evidence.Descriptor = fixture.descriptor
	fixture.evidence = signEvidence(t, fixture.evidence, fixture.conformancePrivateKey)
	probe := &signedProbe{descriptor: fixture.descriptor, privateKey: fixture.runtimePrivateKey}

	_, err := VerifyDependency(context.Background(), fixture.verifier, probe, fixture.evidence, requirements)
	if !errors.Is(err, ErrRequirementMismatch) {
		t.Fatalf("VerifyDependency(reference memory) error = %v, want ErrRequirementMismatch", err)
	}
	if probe.calls.Load() != 0 {
		t.Fatalf("ProbeProduction() calls = %d, want descriptor rejection before runtime probe", probe.calls.Load())
	}
}

func TestAtomicDomainRejectsCrossWiredVerifiedDependencies(t *testing.T) {
	t.Parallel()

	firstFixture := newVerificationFixture(t, "state-domain-a")
	first, err := VerifyDependency(
		context.Background(),
		firstFixture.verifier,
		&signedProbe{descriptor: firstFixture.descriptor, privateKey: firstFixture.runtimePrivateKey},
		firstFixture.evidence,
		firstFixture.requirements(),
	)
	if err != nil {
		t.Fatalf("VerifyDependency(first) error = %v", err)
	}

	secondFixture := newVerificationFixture(t, "state-domain-b")
	second, err := VerifyDependency(
		context.Background(),
		secondFixture.verifier,
		&signedProbe{descriptor: secondFixture.descriptor, privateKey: secondFixture.runtimePrivateKey},
		secondFixture.evidence,
		secondFixture.requirements(),
	)
	if err != nil {
		t.Fatalf("VerifyDependency(second) error = %v", err)
	}

	_, err = RequireAtomicDomain([]AtomicGroup{AtomicEffectLifecycle}, first, second)
	if !errors.Is(err, ErrTransactionDomainMismatch) {
		t.Fatalf("RequireAtomicDomain(cross-wired) error = %v, want ErrTransactionDomainMismatch", err)
	}
}

func TestVerificationRejectsMissingAtomicGroupsAndStaleEvidenceBeforeProbe(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		configure func(*verificationFixture)
		want      error
	}{
		{
			name: "missing atomic group",
			configure: func(fixture *verificationFixture) {
				fixture.requirementOverride = &Requirements{
					BackendKind: BackendCelld, BuildDigest: fixture.descriptor.BuildDigest,
					ApplicationDigest: fixture.descriptor.ApplicationDigest,
					InstanceID:        fixture.descriptor.InstanceID, TransactionDomainID: fixture.descriptor.TransactionDomainID,
					RequiredAtomicGroups: []AtomicGroup{"missing.atomic.group"}, MaximumEvidenceAge: time.Hour,
					MinimumProbeEpoch: fixture.descriptor.ProbeEpoch,
				}
			},
			want: ErrRequirementMismatch,
		},
		{
			name: "expired evidence",
			configure: func(fixture *verificationFixture) {
				fixture.evidence.IssuedAtUnix = fixture.now.Add(-2 * time.Hour).Unix()
				fixture.evidence.ExpiresAtUnix = fixture.now.Add(-time.Hour).Unix()
				fixture.evidence = signEvidence(t, fixture.evidence, fixture.conformancePrivateKey)
			},
			want: ErrEvidenceExpired,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newVerificationFixture(t, "state-domain-a")
			test.configure(&fixture)
			probe := &signedProbe{descriptor: fixture.descriptor, privateKey: fixture.runtimePrivateKey}
			_, err := VerifyDependency(context.Background(), fixture.verifier, probe, fixture.evidence, fixture.requirements())
			if !errors.Is(err, test.want) {
				t.Fatalf("VerifyDependency() error = %v, want %v", err, test.want)
			}
			if probe.calls.Load() != 0 {
				t.Fatalf("ProbeProduction() calls = %d, want pre-probe rejection", probe.calls.Load())
			}
		})
	}
}

func TestRuntimeProofIsBoundToChallengeAndExactDescriptor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		configure func(*signedProbe)
	}{
		{
			name: "stale challenge",
			configure: func(probe *signedProbe) {
				probe.signingNonce = []byte(strings.Repeat("x", ChallengeBytes))
			},
		},
		{
			name: "different transaction domain",
			configure: func(probe *signedProbe) {
				probe.descriptor.TransactionDomainID = "state-domain-b"
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newVerificationFixture(t, "state-domain-a")
			probe := &signedProbe{descriptor: fixture.descriptor, privateKey: fixture.runtimePrivateKey}
			test.configure(probe)
			_, err := VerifyDependency(context.Background(), fixture.verifier, probe, fixture.evidence, fixture.requirements())
			if !errors.Is(err, ErrUnverifiedDependency) {
				t.Fatalf("VerifyDependency() error = %v, want ErrUnverifiedDependency", err)
			}
		})
	}
}

func TestZeroVerifiedDependencyAndMutatedCallerRootsFailClosed(t *testing.T) {
	t.Parallel()

	var zero Verified[*signedProbe]
	if _, _, err := zero.Open(); !errors.Is(err, ErrUnverifiedDependency) {
		t.Fatalf("zero.Open() error = %v, want ErrUnverifiedDependency", err)
	}

	fixture := newVerificationFixture(t, "state-domain-a")
	for index := range fixture.conformancePublicKey {
		fixture.conformancePublicKey[index] ^= 0xff
	}
	for index := range fixture.runtimePublicKey {
		fixture.runtimePublicKey[index] ^= 0xff
	}
	_, err := VerifyDependency(
		context.Background(), fixture.verifier,
		&signedProbe{descriptor: fixture.descriptor, privateKey: fixture.runtimePrivateKey},
		fixture.evidence, fixture.requirements(),
	)
	if err != nil {
		t.Fatalf("VerifyDependency() after caller root mutation error = %v", err)
	}
}

func TestVerifierRejectsARepeatedRuntimeChallenge(t *testing.T) {
	t.Parallel()

	fixture := newVerificationFixture(t, "state-domain-a")
	for attempt := 0; attempt < 2; attempt++ {
		_, err := VerifyDependency(
			context.Background(), fixture.verifier,
			&signedProbe{descriptor: fixture.descriptor, privateKey: fixture.runtimePrivateKey},
			fixture.evidence, fixture.requirements(),
		)
		if attempt == 0 && err != nil {
			t.Fatalf("VerifyDependency(first) error = %v", err)
		}
		if attempt == 1 && !errors.Is(err, ErrUnverifiedDependency) {
			t.Fatalf("VerifyDependency(repeated challenge) error = %v, want ErrUnverifiedDependency", err)
		}
	}
}

type signedProbe struct {
	descriptor   Descriptor
	privateKey   ed25519.PrivateKey
	signingNonce []byte
	calls        atomic.Int64
}

func (probe *signedProbe) ProbeProduction(ctx context.Context, challenge ProbeChallenge) (ProbeResponse, error) {
	if err := ctx.Err(); err != nil {
		return ProbeResponse{}, err
	}
	probe.calls.Add(1)
	nonce := challenge.Nonce
	if probe.signingNonce != nil {
		nonce = probe.signingNonce
	}
	digest, err := ProbeSigningDigest(probe.descriptor, nonce)
	if err != nil {
		return ProbeResponse{}, err
	}
	return ProbeResponse{
		Descriptor: probe.descriptor,
		KeyID:      probe.descriptor.RuntimeKeyID,
		Signature:  ed25519.Sign(probe.privateKey, []byte(digest)),
	}, nil
}

type verificationFixture struct {
	now                   time.Time
	verifier              *Verifier
	descriptor            Descriptor
	evidence              Evidence
	conformancePublicKey  ed25519.PublicKey
	conformancePrivateKey ed25519.PrivateKey
	runtimePublicKey      ed25519.PublicKey
	runtimePrivateKey     ed25519.PrivateKey
	requirementOverride   *Requirements
}

func newVerificationFixture(t *testing.T, transactionDomainID string) verificationFixture {
	t.Helper()

	conformancePublicKey, conformancePrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(conformance) error = %v", err)
	}
	runtimePublicKey, runtimePrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(runtime) error = %v", err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	verifier, err := NewVerifier(VerifierConfig{
		ConformanceRoots: map[string]ed25519.PublicKey{"conformance-root": conformancePublicKey},
		RuntimeRoots:     map[string]ed25519.PublicKey{"state-instance-key": runtimePublicKey},
		Clock:            func() time.Time { return now },
		Entropy:          strings.NewReader(strings.Repeat("n", ChallengeBytes*4)),
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	descriptor := Descriptor{
		SchemaVersion:       1,
		BackendKind:         BackendCelld,
		BuildDigest:         testDigest("1"),
		ApplicationDigest:   testDigest("2"),
		InstanceID:          "state-instance-a",
		TransactionDomainID: transactionDomainID,
		DurabilityClass:     DurabilityCrashRPOZero,
		ConformanceRunID:    "run-0001",
		ConformanceDigest:   testDigest("3"),
		RuntimeKeyID:        "state-instance-key",
		ProbeEpoch:          7,
		ProductionEligible:  true,
		AtomicGroups:        []AtomicGroup{AtomicCommandReceipt, AtomicEffectLifecycle},
	}
	evidence := signEvidence(t, Evidence{
		Descriptor:    descriptor,
		IssuedAtUnix:  now.Add(-time.Minute).Unix(),
		ExpiresAtUnix: now.Add(time.Hour).Unix(),
		KeyID:         "conformance-root",
	}, conformancePrivateKey)
	return verificationFixture{
		now: now, verifier: verifier, descriptor: descriptor, evidence: evidence,
		conformancePublicKey: conformancePublicKey, conformancePrivateKey: conformancePrivateKey,
		runtimePublicKey: runtimePublicKey, runtimePrivateKey: runtimePrivateKey,
	}
}

func (fixture verificationFixture) requirements() Requirements {
	if fixture.requirementOverride != nil {
		return *fixture.requirementOverride
	}
	return Requirements{
		BackendKind:          fixture.descriptor.BackendKind,
		BuildDigest:          fixture.descriptor.BuildDigest,
		ApplicationDigest:    fixture.descriptor.ApplicationDigest,
		InstanceID:           fixture.descriptor.InstanceID,
		TransactionDomainID:  fixture.descriptor.TransactionDomainID,
		RequiredAtomicGroups: []AtomicGroup{AtomicCommandReceipt, AtomicEffectLifecycle},
		MinimumProbeEpoch:    fixture.descriptor.ProbeEpoch,
		MaximumEvidenceAge:   time.Hour,
	}
}

func signEvidence(t *testing.T, evidence Evidence, privateKey ed25519.PrivateKey) Evidence {
	t.Helper()
	digest, err := EvidenceSigningDigest(evidence)
	if err != nil {
		t.Fatalf("EvidenceSigningDigest() error = %v", err)
	}
	evidence.Signature = ed25519.Sign(privateKey, []byte(digest))
	return evidence
}

func testDigest(nibble string) string {
	return "sha256:" + strings.Repeat(nibble, 64)
}
