package issuance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/hancomac/circulusd/internal/conformance/celld"
)

// PhaseDigest binds the exact bounded phase document retained by the process
// owner. These reports are observations, not conformance signatures.
func PhaseDigest(p celld.ObservationReport) (string, error) {
	encoded, err := json.Marshal(p)
	if err != nil || len(encoded) > MaximumReportBytes {
		return "", ErrInvalidReport
	}
	encoded = append(encoded, '\n')
	h := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

func validatePhases(r RawReport) error {
	if len(r.PhaseReports) != 5 {
		return ErrUnqualified
	}
	kinds := []string{"seed", "verify", "verify", "stale-cas", "response-loss"}
	for i, p := range r.PhaseReports {
		b, f := p.ClaimedBinding, p.Facts
		expectedEpoch := r.Measurement.ProbeEpoch
		if i == 0 {
			expectedEpoch = r.ProcessFaults[0].BeforeEpoch
		}
		if i == 1 {
			expectedEpoch = r.ProcessFaults[0].AfterEpoch
		}
		if p.SchemaVersion != 1 || p.Kind != "circulusd.celld.raw-observation/v1" || p.Phase != kinds[i] || p.RunID != r.RunID ||
			len(p.Errors) != 0 || !digest.MatchString(p.EndpointDigest) || p.EndpointDigest != r.PhaseReports[0].EndpointDigest ||
			b.ReleaseDigest != r.Measurement.BuildDigest || b.ExecutableDigest != r.Measurement.BuildDigest ||
			b.ApplicationDigest != r.Measurement.ApplicationDigest || b.EffectiveConfigDigest != r.Measurement.EffectiveConfigurationDigest ||
			b.DurabilityDomain != r.Measurement.TransactionDomainID || b.DurabilityEpoch != expectedEpoch ||
			f.After == nil || f.Receipt == nil || f.Barrier == nil || f.EffectDispatchCount != 0 ||
			!f.After.Exists || !p.Expected.Receipt.Found || p.Expected.Receipt != *f.Receipt ||
			f.After.ObjectID != p.Expected.Token.ObjectID || f.After.Revision != p.Expected.Token.Revision ||
			f.After.StateDigest != p.Expected.StateDigest || !digest.MatchString(p.Expected.StateDigest) ||
			f.Barrier.Token != p.Expected.Token || f.Barrier.ObservedRevision < p.Expected.Token.Revision || f.Barrier.BarrierSerial == 0 ||
			!digest.MatchString(f.Barrier.MarkerDigest) || !digest.MatchString(p.Expected.RequestDigest) ||
			!digest.MatchString(f.Receipt.CommandDigest) || !digest.MatchString(f.Receipt.ResponseDigest) ||
			!digest.MatchString(f.Receipt.CapabilityClaimsDigest) {
			return ErrUnqualified
		}
		if i < 4 && (f.After.ObjectID != r.Transaction.ObjectID || f.Receipt.CommandID != r.Transaction.CommandID ||
			p.Expected.RequestDigest != r.Transaction.RequestDigest || f.After.Revision != r.Transaction.AcknowledgedRevision ||
			f.After.StateDigest != r.Transaction.ExpectedStateDigest || f.Receipt.CommandDigest != r.Transaction.CommandDigest ||
			f.Receipt.ResponseDigest != r.Transaction.ResponseDigest || f.Receipt.CapabilityClaimsDigest != r.Transaction.CapabilityClaimsDigest) {
			return ErrUnqualified
		}
		switch i {
		case 0:
			if f.Commit == nil || f.Commit.Attempts != 1 || f.Commit.Token != p.Expected.Token || f.Commit.RequestDigest != p.Expected.RequestDigest || f.Before == nil || f.Before.Exists || f.Before.Revision != r.Transaction.BeforeRevision || f.Before.ObjectID != r.Transaction.ObjectID || f.StaleCAS != nil || f.ResponseLoss != nil {
				return ErrUnqualified
			}
		case 1, 2:
			if f.Commit != nil || f.Before != nil || f.StaleCAS != nil || f.ResponseLoss != nil {
				return ErrUnqualified
			}
		case 3:
			if f.Commit == nil || f.Commit.Attempts != 1 || f.Commit.Token != (celld.TokenFact{}) || !digest.MatchString(f.Commit.RequestDigest) || f.Commit.RequestDigest == p.Expected.RequestDigest || f.Before == nil || !f.Before.Exists || f.Before.Revision != p.Expected.Token.Revision || f.StaleCAS == nil || f.StaleCAS.Snapshot.ObjectID != p.Expected.Token.ObjectID || f.StaleCAS.Snapshot.Revision != r.Transaction.BeforeRevision || f.StaleCAS.ErrorCode != "SNAPSHOT_CONFLICT" || f.StaleCAS.RequestCount != 1 || f.ResponseLoss != nil {
				return ErrUnqualified
			}
			if r.PhaseReports[0].Facts.Before == nil || f.StaleCAS.Snapshot != *r.PhaseReports[0].Facts.Before || f.Before.StateDigest != r.Transaction.ExpectedStateDigest {
				return ErrUnqualified
			}
		case 4:
			if f.Commit == nil || f.Commit.Attempts != 1 || f.Commit.Token != p.Expected.Token || f.Commit.RequestDigest != p.Expected.RequestDigest || f.Before == nil || f.ResponseLoss == nil || f.StaleCAS != nil || f.Before.ObjectID != r.Transaction.ObjectID ||
				f.After.ObjectID != r.Transaction.ObjectID || f.Before.Revision != r.Transaction.AcknowledgedRevision ||
				f.After.Revision != f.Before.Revision+1 || f.ResponseLoss.BackendStatus != int(r.ResponseLoss.BackendStatus) ||
				f.ResponseLoss.ReceivedBytes == nil || *f.ResponseLoss.ReceivedBytes != r.ResponseLoss.ReceivedBytes ||
				f.ResponseLoss.RequestCount != uint64(r.ResponseLoss.BackendRequests) || f.ResponseLoss.ClientError != r.ResponseLoss.ClientErrorCode {
				return ErrUnqualified
			}
			if !f.Before.Exists || f.Before.StateDigest != r.Transaction.ExpectedStateDigest ||
				f.Receipt.CommandID == r.Transaction.CommandID || f.Receipt.CommandDigest == r.Transaction.CommandDigest ||
				f.Receipt.ResponseDigest == r.Transaction.ResponseDigest || f.Receipt.CapabilityClaimsDigest == r.Transaction.CapabilityClaimsDigest ||
				p.Expected.RequestDigest == r.Transaction.RequestDigest || p.Expected.StateDigest == r.Transaction.ExpectedStateDigest {
				return ErrUnqualified
			}
		}
	}
	for i, f := range r.ProcessFaults {
		seed, err := PhaseDigest(r.PhaseReports[i])
		if err != nil {
			return err
		}
		recovery, err := PhaseDigest(r.PhaseReports[i+1])
		if err != nil {
			return err
		}
		if f.SeedObservationDigest != seed || f.RecoveryObservationDigest != recovery {
			return ErrUnqualified
		}
	}
	loss, err := PhaseDigest(r.PhaseReports[4])
	if err != nil {
		return err
	}
	if loss != r.ResponseLoss.ObservationDigest {
		return ErrUnqualified
	}
	return nil
}
