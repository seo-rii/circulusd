package dependency

import (
	"time"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/release"
)

const (
	productionRequirementsSealDomain = "circulusd.production-dependency-requirements"
	maximumProductionAtomicGroups    = 64
	maximumProductionEvidenceAge     = 24 * time.Hour
)

type productionRequirementsSeal struct {
	digest string
}

// ProductionRequirementsConfig contains deployment policy that is sealed with
// one authenticated celld/state-app release pair.
type ProductionRequirementsConfig struct {
	InstanceID           string
	TransactionDomainID  string
	RequiredAtomicGroups []AtomicGroup
	MinimumProbeEpoch    uint64
	MaximumEvidenceAge   time.Duration
}

// NewProductionRequirements is the only cross-package constructor for sealed
// production requirements. Both expected digests come from one opaque,
// release-authenticated manifest result; raw struct literals remain unsealed
// and VerifyDependency rejects them before issuing a live probe.
func NewProductionRequirements(
	artifacts release.AuthenticatedStateArtifactDigests,
	config ProductionRequirementsConfig,
) (Requirements, error) {
	return sealProductionRequirements(Requirements{
		BackendKind:          BackendCelld,
		BuildDigest:          artifacts.CelldBuildDigest(),
		ApplicationDigest:    artifacts.StateAppApplicationDigest(),
		InstanceID:           config.InstanceID,
		TransactionDomainID:  config.TransactionDomainID,
		RequiredAtomicGroups: config.RequiredAtomicGroups,
		MinimumProbeEpoch:    config.MinimumProbeEpoch,
		MaximumEvidenceAge:   config.MaximumEvidenceAge,
	})
}

func sealProductionRequirements(requirements Requirements) (Requirements, error) {
	requirements.RequiredAtomicGroups = append([]AtomicGroup(nil), requirements.RequiredAtomicGroups...)
	if err := validateRequirementsShape(requirements); err != nil {
		return Requirements{}, err
	}
	digest, err := productionRequirementsDigest(requirements)
	if err != nil {
		return Requirements{}, ErrInvalidConfiguration
	}
	requirements.seal = &productionRequirementsSeal{digest: digest}
	return requirements, nil
}

func productionRequirementsDigest(requirements Requirements) (string, error) {
	groups := make(canonical.Array, len(requirements.RequiredAtomicGroups))
	for index, group := range requirements.RequiredAtomicGroups {
		groups[index] = string(group)
	}
	return canonical.StructuredDigest(
		productionRequirementsSealDomain,
		verificationSchemaVersion,
		canonical.Map{
			"backendKind":          requirements.BackendKind,
			"buildDigest":          requirements.BuildDigest,
			"applicationDigest":    requirements.ApplicationDigest,
			"instanceId":           requirements.InstanceID,
			"transactionDomainId":  requirements.TransactionDomainID,
			"requiredAtomicGroups": groups,
			"minimumProbeEpoch":    requirements.MinimumProbeEpoch,
			"maximumEvidenceAgeNs": int64(requirements.MaximumEvidenceAge),
		},
	)
}
