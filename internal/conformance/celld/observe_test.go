package celld

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	state "github.com/hancomac/circulusd/internal/celld"
	"github.com/hancomac/circulusd/internal/celldbridge"
)

type observationMemory struct {
	snapshot       celldbridge.Snapshot
	receipts       map[string]state.StoredReceipt
	serial         uint64
	omitReceipt    bool
	corruptReceipt bool
	acceptStale    bool
	commitThenLose bool
	barrierErr     error
	commits        int
}

func (m *observationMemory) ReadSnapshot(_ context.Context, request celldbridge.SnapshotRequest) (celldbridge.Snapshot, error) {
	if m.snapshot.ObjectID == "" {
		return celldbridge.Snapshot{SnapshotRef: celldbridge.SnapshotRef{ObjectID: request.ObjectID, StateDigest: state.Digest(sha256.Sum256(nil))}}, nil
	}
	return m.snapshot, nil
}
func (m *observationMemory) ReadReceipt(_ context.Context, request celldbridge.ReceiptRequest) (celldbridge.ReceiptResult, error) {
	if request.Snapshot != m.snapshot.SnapshotRef {
		return celldbridge.ReceiptResult{}, celldbridge.ErrSnapshotConflict
	}
	r, found := m.receipts[request.CommandID]
	if m.omitReceipt {
		found = false
	}
	if m.corruptReceipt {
		r.Response = []byte("torn receipt")
	}
	return celldbridge.ReceiptResult{Snapshot: request.Snapshot, CommandID: request.CommandID, Found: found, Receipt: r}, nil
}
func (m *observationMemory) CompareAndCommit(_ context.Context, request celldbridge.CommitRequest) (celldbridge.CommitResult, error) {
	m.commits++
	if m.snapshot.Exists && request.Snapshot != m.snapshot.SnapshotRef && !m.acceptStale {
		return celldbridge.CommitResult{}, celldbridge.ErrSnapshotConflict
	}
	ref := request.Snapshot
	ref.Exists = true
	ref.Revision++
	ref.StateDigest = state.Digest(sha256.Sum256(request.State))
	m.snapshot = celldbridge.Snapshot{SnapshotRef: ref, State: bytes.Clone(request.State)}
	if m.receipts == nil {
		m.receipts = make(map[string]state.StoredReceipt)
	}
	for _, write := range request.Receipts {
		m.receipts[write.CommandID] = write.Receipt
	}
	if m.commitThenLose {
		return celldbridge.CommitResult{}, celldbridge.ErrUnavailable
	}
	return celldbridge.CommitResult{Snapshot: ref, RequestDigest: request.RequestDigest, Token: state.CommitToken{ObjectID: ref.ObjectID, Revision: ref.Revision}}, nil
}
func (m *observationMemory) ConfirmBarrier(_ context.Context, request celldbridge.BarrierRequest) (celldbridge.BarrierResult, error) {
	if m.barrierErr != nil {
		return celldbridge.BarrierResult{}, m.barrierErr
	}
	m.serial++
	return celldbridge.BarrierResult{Token: request.Token, Marker: request.Marker, ObservedRevision: m.snapshot.Revision, BarrierSerial: m.serial}, nil
}
func testObservation(phase string) ObservationReport {
	digest := "sha256:" + strings.Repeat("1", 64)
	return NewObservation(phase, strings.Repeat("a", 64), "http://127.0.0.1:29930", ObservationBinding{ReleaseDigest: digest, ExecutableDigest: digest, ApplicationDigest: digest, EffectiveConfigDigest: digest, DurabilityDomain: "qualification", DurabilityEpoch: 1})
}
func TestObservationSeedAndRecoveryFactGraph(t *testing.T) {
	m := new(observationMemory)
	seed := testObservation("seed")
	if err := SeedObservation(context.Background(), m, &seed); err != nil {
		t.Fatal(err)
	}
	if seed.Facts.Before.Exists || !seed.Facts.After.Exists || seed.Facts.After.Revision != 1 || seed.Facts.Commit.Attempts != 1 || seed.Facts.Receipt == nil || *seed.Facts.Receipt != seed.Expected.Receipt || seed.Facts.Barrier.BarrierSerial != 1 {
		t.Fatalf("incomplete graph: %+v", seed)
	}
	recovered := testObservation("verify")
	recovered.ClaimedBinding.DurabilityEpoch = 2
	if err := VerifyObservation(context.Background(), m, &recovered, seed); err != nil {
		t.Fatal(err)
	}
	if m.commits != 1 || recovered.Facts.Commit != nil || recovered.Expected.Token != seed.Facts.Commit.Token || recovered.Facts.Barrier.BarrierSerial != 2 || recovered.Facts.Barrier.MarkerDigest == seed.Facts.Barrier.MarkerDigest || recovered.Facts.EffectDispatchCount != 0 {
		t.Fatal("recovery must only read and confirm a fresh barrier")
	}
}
func TestObservationRejectsTornReceiptAndState(t *testing.T) {
	for _, fault := range []string{"missing-receipt", "corrupt-receipt", "wrong-state", "barrier-unavailable"} {
		t.Run(fault, func(t *testing.T) {
			m := new(observationMemory)
			seed := testObservation("seed")
			if err := SeedObservation(context.Background(), m, &seed); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "missing-receipt":
				m.omitReceipt = true
			case "corrupt-receipt":
				m.corruptReceipt = true
			case "wrong-state":
				m.snapshot.StateDigest = state.Digest(sha256.Sum256([]byte("lost state")))
			case "barrier-unavailable":
				m.barrierErr = celldbridge.ErrUnavailable
			}
			report := testObservation("verify")
			if err := VerifyObservation(context.Background(), m, &report, seed); err == nil || len(report.Errors) == 0 {
				t.Fatal("torn recovery must fail with facts retained")
			}
			if report.Facts.EffectDispatchCount != 0 {
				t.Fatal("failed recovery must not dispatch")
			}
		})
	}
}
func TestObservationRejectsInconsistentOrUnboundSeed(t *testing.T) {
	m := new(observationMemory)
	seed := testObservation("seed")
	if err := SeedObservation(context.Background(), m, &seed); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*ObservationReport){func(r *ObservationReport) { r.RunID = "other" }, func(r *ObservationReport) { r.ClaimedBinding.ApplicationDigest = "other" }, func(r *ObservationReport) { r.Expected.StateDigest = "other" }, func(r *ObservationReport) { r.Errors = []string{"bad"} }, func(r *ObservationReport) { r.Facts.Commit = nil }} {
		altered := seed
		mutate(&altered)
		report := testObservation("verify")
		if err := VerifyObservation(context.Background(), m, &report, altered); err == nil {
			t.Fatal("invalid seed accepted")
		}
	}
}
func TestObservationStaleCASIsDistinctFromOwnerFencing(t *testing.T) {
	m := new(observationMemory)
	seed := testObservation("seed")
	if err := SeedObservation(context.Background(), m, &seed); err != nil {
		t.Fatal(err)
	}
	report := testObservation("stale-cas")
	if err := StaleCASObservation(context.Background(), m, &report, seed); err != nil {
		t.Fatal(err)
	}
	if report.Facts.StaleCAS.ErrorCode != "SNAPSHOT_CONFLICT" || report.Facts.StaleCAS.RequestCount != 1 || report.Facts.StaleCAS.Snapshot.Revision != 0 || report.Facts.Before.Revision != 1 || report.Facts.After.Revision != 1 || report.Facts.Commit.Token != (TokenFact{}) || report.Facts.Commit.RequestDigest == seed.Facts.Commit.RequestDigest {
		t.Fatal("stale CAS facts missing")
	}
	m.acceptStale = true
	report = testObservation("stale-cas")
	if err := StaleCASObservation(context.Background(), m, &report, seed); err == nil {
		t.Fatal("an accepted stale write cannot qualify")
	}
}
func TestObservationResponseLossResolvesReceiptBeforeFreshBarrier(t *testing.T) {
	m := new(observationMemory)
	seed := testObservation("seed")
	if err := SeedObservation(context.Background(), m, &seed); err != nil {
		t.Fatal(err)
	}
	m.commitThenLose = true
	report := testObservation("response-loss")
	received := uint64(0)
	if err := ResponseLossObservation(context.Background(), m, m, func() ResponseLossFact {
		return ResponseLossFact{BackendStatus: 200, RequestCount: 1, ReceivedBytes: &received}
	}, &report, seed); err != nil {
		t.Fatal(err)
	}
	if m.commits != 2 || report.Facts.After.Revision != 2 || report.Facts.Receipt.ResponseDigest != report.Expected.Receipt.ResponseDigest || report.Facts.ResponseLoss.ClientError != "UNAVAILABLE" || report.Facts.Barrier.BarrierSerial != 2 || report.Facts.EffectDispatchCount != 0 {
		t.Fatal("lost response facts do not establish readback and fresh barrier")
	}
}
func TestObservationResponseLossRejectsRetriesOrUnavailableBarrier(t *testing.T) {
	for _, fault := range []string{"retry", "backend-error", "no-drop", "barrier-failure", "bytes-unobserved", "bytes-delivered"} {
		t.Run(fault, func(t *testing.T) {
			m := new(observationMemory)
			seed := testObservation("seed")
			if err := SeedObservation(context.Background(), m, &seed); err != nil {
				t.Fatal(err)
			}
			m.commitThenLose = true
			received := uint64(0)
			facts := ResponseLossFact{BackendStatus: 200, RequestCount: 1, ReceivedBytes: &received}
			switch fault {
			case "retry":
				facts.RequestCount = 2
			case "backend-error":
				facts.BackendStatus = 503
			case "no-drop":
				m.commitThenLose = false
			case "barrier-failure":
				m.barrierErr = celldbridge.ErrUnavailable
			case "bytes-unobserved":
				facts.ReceivedBytes = nil
			case "bytes-delivered":
				received = 1
			}
			report := testObservation("response-loss")
			if err := ResponseLossObservation(context.Background(), m, m, func() ResponseLossFact { return facts }, &report, seed); err == nil {
				t.Fatal("invalid loss observation accepted")
			}
			if report.Facts.EffectDispatchCount != 0 {
				t.Fatal("invalid barrier authorized effects")
			}
		})
	}
}
func TestObservationErrorsRedactTransportDetails(t *testing.T) {
	report := testObservation("seed")
	err := observeError(&report, "snapshot", errors.New("super-secret root key"))
	if err.Error() != "snapshot:ERROR" || strings.Contains(strings.Join(report.Errors, ","), "secret") {
		t.Fatal("transport details exposed")
	}
}
