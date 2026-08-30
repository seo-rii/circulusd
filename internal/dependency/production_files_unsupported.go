//go:build !linux

package dependency

func newVerifierFromFiles(config ProductionProofFileConfig) (*Verifier, Evidence, error) {
	if err := validateProductionProofFileConfig(config); err != nil {
		return nil, Evidence{}, err
	}
	return nil, Evidence{}, ErrProductionProofFilesUnsupported
}
