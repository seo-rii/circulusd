package dependency

import (
	"errors"
	"io"
	"time"
)

var (
	ErrInvalidEvidenceFile             = errors.New("dependency: invalid production evidence file")
	ErrInvalidTrustRootsFile           = errors.New("dependency: invalid production trust-roots file")
	ErrProductionProofFilesUnsupported = errors.New("dependency: production proof files are unsupported on this platform")
)

// ProductionProofFileConfig names the immutable production evidence and two
// role-separated trust-root files used to construct a Verifier. Loading this
// bundle does not establish freshness, deployment requirements, or liveness;
// callers must still use VerifyDependency with release-derived requirements.
type ProductionProofFileConfig struct {
	EvidenceFile         string
	ConformanceRootsFile string
	RuntimeRootsFile     string
	Clock                func() time.Time
	Entropy              io.Reader
}

// NewVerifierFromFiles snapshots all three root-owned production proof files
// once and constructs a verifier from the role-bound trust roots.
func NewVerifierFromFiles(config ProductionProofFileConfig) (*Verifier, Evidence, error) {
	return newVerifierFromFiles(config)
}

func validateProductionProofFileConfig(config ProductionProofFileConfig) error {
	if config.EvidenceFile == "" || config.ConformanceRootsFile == "" || config.RuntimeRootsFile == "" ||
		config.EvidenceFile == config.ConformanceRootsFile ||
		config.EvidenceFile == config.RuntimeRootsFile ||
		config.ConformanceRootsFile == config.RuntimeRootsFile ||
		config.Clock == nil || interfaceNil(config.Entropy) {
		return ErrInvalidConfiguration
	}
	return nil
}
