package dependency

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/release"
	releasecontract "github.com/hancomac/circulusd/internal/release/contracttest"
)

func TestNewProductionRequirementsBindsAuthenticatedStateArtifactDigests(t *testing.T) {
	t.Parallel()

	buildDigest := testDigest("1")
	applicationDigest := testDigest("2")
	artifacts := releasecontract.StateArtifactDigests(t, buildDigest, applicationDigest)
	groups := []AtomicGroup{AtomicCommandReceipt, AtomicEffectLifecycle}
	requirements, err := NewProductionRequirements(artifacts, ProductionRequirementsConfig{
		InstanceID:           "state-instance-a",
		TransactionDomainID:  "state-domain-a",
		RequiredAtomicGroups: groups,
		MinimumProbeEpoch:    7,
		MaximumEvidenceAge:   time.Hour,
	})
	if err != nil {
		t.Fatalf("NewProductionRequirements() error = %v", err)
	}
	groups[0] = "caller-mutation"
	if requirements.BackendKind != BackendCelld || requirements.BuildDigest != buildDigest ||
		requirements.ApplicationDigest != applicationDigest || requirements.InstanceID != "state-instance-a" ||
		requirements.TransactionDomainID != "state-domain-a" || requirements.MinimumProbeEpoch != 7 ||
		requirements.MaximumEvidenceAge != time.Hour ||
		len(requirements.RequiredAtomicGroups) != 2 || requirements.RequiredAtomicGroups[0] != AtomicCommandReceipt {
		t.Fatalf("production requirements = %#v", requirements)
	}
}

func TestProductionRequirementsRejectZeroArtifactsAndSealMutation(t *testing.T) {
	t.Parallel()

	config := ProductionRequirementsConfig{
		InstanceID:           "state-instance-a",
		TransactionDomainID:  "state-domain-a",
		RequiredAtomicGroups: []AtomicGroup{AtomicCommandReceipt, AtomicEffectLifecycle},
		MinimumProbeEpoch:    7,
		MaximumEvidenceAge:   time.Hour,
	}
	if requirements, err := NewProductionRequirements(release.AuthenticatedStateArtifactDigests{}, config); !errors.Is(err, ErrInvalidConfiguration) || requirements.seal != nil {
		t.Fatalf("NewProductionRequirements(zero artifacts) = %#v/%v", requirements, err)
	}

	fixture := newVerificationFixture(t, "state-domain-a")
	artifacts := releasecontract.StateArtifactDigests(t, fixture.descriptor.BuildDigest, fixture.descriptor.ApplicationDigest)
	tests := []struct {
		name   string
		mutate func(*Requirements)
	}{
		{name: "celld digest", mutate: func(requirements *Requirements) { requirements.BuildDigest = testDigest("8") }},
		{name: "state app digest", mutate: func(requirements *Requirements) { requirements.ApplicationDigest = testDigest("9") }},
		{name: "instance", mutate: func(requirements *Requirements) { requirements.InstanceID = "other-instance" }},
		{name: "domain", mutate: func(requirements *Requirements) { requirements.TransactionDomainID = "other-domain" }},
		{name: "group", mutate: func(requirements *Requirements) { requirements.RequiredAtomicGroups[0] = AtomicQuotaSettlement }},
		{name: "epoch", mutate: func(requirements *Requirements) { requirements.MinimumProbeEpoch++ }},
		{name: "age", mutate: func(requirements *Requirements) { requirements.MaximumEvidenceAge++ }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			requirements, err := NewProductionRequirements(artifacts, config)
			if err != nil {
				t.Fatalf("NewProductionRequirements() error = %v", err)
			}
			test.mutate(&requirements)
			probe := &signedProbe{descriptor: fixture.descriptor, privateKey: fixture.runtimePrivateKey}
			_, err = VerifyDependency(context.Background(), fixture.verifier, probe, fixture.evidence, requirements)
			if !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("VerifyDependency(mutated requirements) error = %v, want ErrInvalidConfiguration", err)
			}
			if probe.calls.Load() != 0 {
				t.Fatalf("ProbeProduction() calls = %d, want pre-probe rejection", probe.calls.Load())
			}
		})
	}
}

func TestNewProductionRequirementsRejectsUnboundedPolicy(t *testing.T) {
	t.Parallel()

	artifacts := releasecontract.StateArtifactDigests(t, testDigest("1"), testDigest("2"))
	base := ProductionRequirementsConfig{
		InstanceID:           "state-instance-a",
		TransactionDomainID:  "state-domain-a",
		RequiredAtomicGroups: []AtomicGroup{AtomicCommandReceipt},
		MinimumProbeEpoch:    1,
		MaximumEvidenceAge:   time.Hour,
	}
	tests := []struct {
		name      string
		configure func(*ProductionRequirementsConfig)
	}{
		{name: "too many atomic groups", configure: func(config *ProductionRequirementsConfig) {
			config.RequiredAtomicGroups = make([]AtomicGroup, 65)
			for index := range config.RequiredAtomicGroups {
				config.RequiredAtomicGroups[index] = AtomicGroup(fmt.Sprintf("group-%02d", index))
			}
		}},
		{name: "evidence age above production maximum", configure: func(config *ProductionRequirementsConfig) {
			config.MaximumEvidenceAge = 24*time.Hour + 1
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			config := base
			config.RequiredAtomicGroups = append([]AtomicGroup(nil), base.RequiredAtomicGroups...)
			test.configure(&config)
			requirements, err := NewProductionRequirements(artifacts, config)
			if !errors.Is(err, ErrInvalidConfiguration) || requirements.seal != nil {
				t.Fatalf("NewProductionRequirements(unbounded policy) = %#v/%v", requirements, err)
			}
		})
	}
}

func TestVerifyDependencyRejectsUnsealedProductionRequirementsBeforeProbe(t *testing.T) {
	t.Parallel()

	fixture := newVerificationFixture(t, "state-domain-unsealed")
	probe := &signedProbe{descriptor: fixture.descriptor, privateKey: fixture.runtimePrivateKey}
	requirements := fixture.requirements()
	requirements.seal = nil
	unsigned := fixture.evidence
	unsigned.Signature = nil
	for _, evidence := range []Evidence{fixture.evidence, unsigned} {
		_, err := VerifyDependency(
			context.Background(),
			fixture.verifier,
			probe,
			evidence,
			requirements,
		)
		if !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("VerifyDependency(unsealed requirements) error = %v, want ErrInvalidConfiguration", err)
		}
	}
	if probe.calls.Load() != 0 {
		t.Fatalf("ProbeProduction() calls = %d, want pre-probe rejection", probe.calls.Load())
	}
}
