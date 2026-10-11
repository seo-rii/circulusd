package celld

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/hancomac/circulusd/internal/canonical"
	state "github.com/hancomac/circulusd/internal/celld"
	"github.com/hancomac/circulusd/internal/celldbridge"
)

// ObservationReport records authenticated native operations, not a durability
// verdict. ClaimedBinding must be measured independently by the process owner.
// In particular, a stale application CAS does not establish a native owner fence.
type ObservationReport struct {
	SchemaVersion  int                 `json:"schemaVersion"`
	Kind           string              `json:"kind"`
	Phase          string              `json:"phase"`
	RunID          string              `json:"runId"`
	EndpointDigest string              `json:"endpointDigest"`
	ClaimedBinding ObservationBinding  `json:"claimedBinding"`
	Expected       ObservationExpected `json:"expected"`
	Facts          ObservationFacts    `json:"facts"`
	Errors         []string            `json:"errors"`
}

type ObservationBinding struct {
	ReleaseDigest         string `json:"releaseDigest"`
	ExecutableDigest      string `json:"executableDigest"`
	ApplicationDigest     string `json:"applicationDigest"`
	EffectiveConfigDigest string `json:"effectiveConfigDigest"`
	DurabilityDomain      string `json:"durabilityDomain"`
	DurabilityEpoch       uint64 `json:"durabilityEpoch"`
}

type SnapshotFact struct {
	ObjectID    string `json:"objectId"`
	Exists      bool   `json:"exists"`
	Revision    uint64 `json:"revision"`
	StateDigest string `json:"stateDigest"`
}
type TokenFact struct {
	ObjectID string `json:"objectId"`
	Revision uint64 `json:"revision"`
}
type CommitFact struct {
	RequestDigest string    `json:"requestDigest"`
	Token         TokenFact `json:"token"`
	Attempts      uint64    `json:"attempts"`
}
type ReceiptFact struct {
	CommandID              string `json:"commandId"`
	Found                  bool   `json:"found"`
	CommandDigest          string `json:"commandDigest"`
	ResponseDigest         string `json:"responseDigest"`
	CapabilityClaimsDigest string `json:"capabilityClaimsDigest"`
}
type BarrierFact struct {
	Token            TokenFact `json:"token"`
	MarkerDigest     string    `json:"markerDigest"`
	ObservedRevision uint64    `json:"observedRevision"`
	BarrierSerial    uint64    `json:"barrierSerial"`
}
type ResponseLossFact struct {
	BackendStatus int    `json:"backendStatus"`
	RequestCount  uint64 `json:"requestCount"`
	ClientError   string `json:"clientError"`
	// Nil means the relay did not observe delivered response bytes. An explicit
	// zero is a measured result, distinct from a missing field in older reports.
	ReceivedBytes *uint64 `json:"receivedBytes"`
}
type StaleCASFact struct {
	ErrorCode    string       `json:"errorCode"`
	RequestCount uint64       `json:"requestCount"`
	Snapshot     SnapshotFact `json:"snapshot"`
}
type ObservationExpected struct {
	Token         TokenFact   `json:"token"`
	RequestDigest string      `json:"requestDigest"`
	StateDigest   string      `json:"stateDigest"`
	Receipt       ReceiptFact `json:"receipt"`
}
type ObservationFacts struct {
	Before              *SnapshotFact     `json:"before,omitempty"`
	After               *SnapshotFact     `json:"after,omitempty"`
	Commit              *CommitFact       `json:"commit,omitempty"`
	Receipt             *ReceiptFact      `json:"receipt,omitempty"`
	Barrier             *BarrierFact      `json:"barrier,omitempty"`
	ResponseLoss        *ResponseLossFact `json:"responseLoss,omitempty"`
	StaleCAS            *StaleCASFact     `json:"staleCAS,omitempty"`
	EffectDispatchCount uint64            `json:"effectDispatchCount"`
}

// ObservationClient deliberately excludes production probing: raw observations
// must exist before a conformance issuer or native signer can bind them.
type ObservationClient interface {
	ReadSnapshot(context.Context, celldbridge.SnapshotRequest) (celldbridge.Snapshot, error)
	ReadReceipt(context.Context, celldbridge.ReceiptRequest) (celldbridge.ReceiptResult, error)
	CompareAndCommit(context.Context, celldbridge.CommitRequest) (celldbridge.CommitResult, error)
	ConfirmBarrier(context.Context, celldbridge.BarrierRequest) (celldbridge.BarrierResult, error)
}

func NewObservation(phase, runID, endpoint string, binding ObservationBinding) ObservationReport {
	return ObservationReport{SchemaVersion: 1, Kind: "circulusd.celld.raw-observation/v1", Phase: phase,
		RunID: runID, EndpointDigest: observationDigest([]byte(endpoint)), ClaimedBinding: binding, Errors: []string{}}
}

// SeedObservation writes an unpredictable, run-owned state and command receipt
// in one native transaction, then reads both and confirms a fresh native barrier.
func SeedObservation(ctx context.Context, client ObservationClient, report *ObservationReport) error {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	objectID := "qualification-" + hex.EncodeToString(nonce[:])
	commandID := "command-" + hex.EncodeToString(nonce[:])
	before, err := client.ReadSnapshot(ctx, celldbridge.SnapshotRequest{ObjectID: objectID})
	if err != nil {
		return observeError(report, "snapshot-before", err)
	}
	report.Facts.Before = snapshotFact(before)
	if before.Exists || before.Revision != 0 {
		return observeError(report, "fresh-object-collision", nil)
	}
	request, expected, err := observationCommit(before.SnapshotRef, commandID, nonce[:])
	if err != nil {
		return err
	}
	report.Expected = expected
	result, err := client.CompareAndCommit(ctx, request)
	if err != nil {
		return observeError(report, "commit", err)
	}
	report.Facts.Commit = &CommitFact{RequestDigest: digestText(result.RequestDigest), Token: tokenFact(result.Token), Attempts: 1}
	return observeReadback(ctx, client, report, result.Token)
}

// VerifyObservation reads a prior seed after the process owner has performed a
// crash/recovery. The caller must record the PID, actual signal and recovery root
// independently; calling this function alone does not prove that any crash ran.
func VerifyObservation(ctx context.Context, client ObservationClient, report *ObservationReport, seed ObservationReport) error {
	if err := validSeed(seed, *report); err != nil {
		return observeError(report, "invalid-seed", err)
	}
	report.Expected = seed.Expected
	return observeReadback(ctx, client, report, state.CommitToken{ObjectID: seed.Facts.Commit.Token.ObjectID, Revision: seed.Facts.Commit.Token.Revision})
}

func observeReadback(ctx context.Context, client ObservationClient, report *ObservationReport, token state.CommitToken) error {
	after, err := client.ReadSnapshot(ctx, celldbridge.SnapshotRequest{ObjectID: token.ObjectID})
	if err != nil {
		return observeError(report, "snapshot-after", err)
	}
	report.Facts.After = snapshotFact(after)
	if tokenFact(token) != report.Expected.Token || !after.Exists || after.Revision != token.Revision || digestText(after.StateDigest) != report.Expected.StateDigest {
		return observeError(report, "state-readback-mismatch", nil)
	}
	receipt, err := client.ReadReceipt(ctx, celldbridge.ReceiptRequest{Snapshot: after.SnapshotRef, CommandID: report.Expected.Receipt.CommandID})
	if err != nil {
		return observeError(report, "receipt-after", err)
	}
	fact, err := receiptFact(receipt.CommandID, receipt.Found, receipt.Receipt)
	if err != nil {
		return observeError(report, "receipt-digest", err)
	}
	report.Facts.Receipt = &fact
	if fact != report.Expected.Receipt {
		return observeError(report, "receipt-readback-mismatch", nil)
	}
	var marker [32]byte
	if _, err := rand.Read(marker[:]); err != nil {
		return observeError(report, "barrier-marker", err)
	}
	barrier, err := client.ConfirmBarrier(ctx, celldbridge.BarrierRequest{Token: token, Marker: marker})
	if err != nil {
		return observeError(report, "barrier", err)
	}
	report.Facts.Barrier = &BarrierFact{Token: tokenFact(barrier.Token), MarkerDigest: observationDigest(barrier.Marker[:]), ObservedRevision: barrier.ObservedRevision, BarrierSerial: barrier.BarrierSerial}
	if barrier.Token != token || barrier.Marker != marker || barrier.ObservedRevision < token.Revision || barrier.BarrierSerial == 0 {
		return observeError(report, "barrier-mismatch", nil)
	}
	return nil
}

// StaleCASObservation proves only the application's authenticated CAS conflict.
// No native ownership or old-epoch fencing claim is made by this operation.
func StaleCASObservation(ctx context.Context, client ObservationClient, report *ObservationReport, seed ObservationReport) error {
	if err := validSeed(seed, *report); err != nil || seed.Facts.Before == nil {
		return observeError(report, "invalid-seed", err)
	}
	before, err := snapshotRef(*seed.Facts.Before)
	if err != nil {
		return observeError(report, "invalid-seed", err)
	}
	current, err := client.ReadSnapshot(ctx, celldbridge.SnapshotRequest{ObjectID: before.ObjectID})
	if err != nil {
		return observeError(report, "snapshot-before", err)
	}
	report.Facts.Before = snapshotFact(current)
	if !current.Exists || current.Revision != seed.Expected.Token.Revision || digestText(current.StateDigest) != seed.Expected.StateDigest {
		return observeError(report, "stale-cas-baseline-mismatch", nil)
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	request, _, err := observationCommit(before, "late-"+hex.EncodeToString(nonce[:]), nonce[:])
	if err != nil {
		return err
	}
	_, err = client.CompareAndCommit(ctx, request)
	report.Facts.StaleCAS = &StaleCASFact{ErrorCode: observationErrorCode(err), RequestCount: 1, Snapshot: *seed.Facts.Before}
	report.Facts.Commit = &CommitFact{RequestDigest: digestText(request.RequestDigest), Attempts: 1}
	if !errors.Is(err, celldbridge.ErrSnapshotConflict) {
		return observeError(report, "stale-cas-not-rejected", err)
	}
	report.Expected = seed.Expected
	return observeReadback(ctx, client, report, state.CommitToken{ObjectID: seed.Facts.Commit.Token.ObjectID, Revision: seed.Facts.Commit.Token.Revision})
}

// ResponseLossObservation submits exactly one commit through a response-dropping
// transport. Its callback reports only network observations. A fresh direct read
// and barrier resolves the commit; no external effect is dispatched by this tool.
func ResponseLossObservation(ctx context.Context, direct ObservationClient, lost ObservationClient, lossFacts func() ResponseLossFact, report *ObservationReport, seed ObservationReport) error {
	if err := validSeed(seed, *report); err != nil {
		return observeError(report, "invalid-seed", err)
	}
	before, err := direct.ReadSnapshot(ctx, celldbridge.SnapshotRequest{ObjectID: seed.Facts.Commit.Token.ObjectID})
	if err != nil {
		return observeError(report, "snapshot-before", err)
	}
	report.Facts.Before = snapshotFact(before)
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	request, expected, err := observationCommit(before.SnapshotRef, "lost-"+hex.EncodeToString(nonce[:]), nonce[:])
	if err != nil {
		return err
	}
	report.Expected = expected
	_, commitErr := lost.CompareAndCommit(ctx, request)
	facts := lossFacts()
	facts.ClientError = observationErrorCode(commitErr)
	report.Facts.ResponseLoss = &facts
	report.Facts.Commit = &CommitFact{RequestDigest: digestText(request.RequestDigest), Token: TokenFact{ObjectID: before.ObjectID, Revision: before.Revision + 1}, Attempts: 1}
	if commitErr == nil || facts.RequestCount != 1 || facts.BackendStatus != 200 || facts.ReceivedBytes == nil || *facts.ReceivedBytes != 0 || (!errors.Is(commitErr, celldbridge.ErrUnavailable) && !errors.Is(commitErr, celldbridge.ErrInvalidResponse)) {
		return observeError(report, "response-loss-not-observed", commitErr)
	}
	return observeReadback(ctx, direct, report, state.CommitToken{ObjectID: before.ObjectID, Revision: before.Revision + 1})
}

func validSeed(seed, current ObservationReport) error {
	if seed.SchemaVersion != 1 || seed.Kind != "circulusd.celld.raw-observation/v1" || seed.Phase != "seed" || seed.RunID != current.RunID ||
		seed.ClaimedBinding.ReleaseDigest != current.ClaimedBinding.ReleaseDigest || seed.ClaimedBinding.ExecutableDigest != current.ClaimedBinding.ExecutableDigest ||
		seed.ClaimedBinding.ApplicationDigest != current.ClaimedBinding.ApplicationDigest || seed.ClaimedBinding.EffectiveConfigDigest != current.ClaimedBinding.EffectiveConfigDigest ||
		seed.ClaimedBinding.DurabilityDomain != current.ClaimedBinding.DurabilityDomain || len(seed.Errors) != 0 || seed.Facts.Commit == nil || seed.Facts.After == nil || seed.Facts.Receipt == nil || seed.Facts.Barrier == nil ||
		seed.Facts.Commit.Attempts != 1 || seed.Facts.Commit.Token.Revision == 0 || seed.Facts.Commit.Token != seed.Expected.Token || seed.Facts.Commit.RequestDigest != seed.Expected.RequestDigest || seed.Facts.After.ObjectID != seed.Facts.Commit.Token.ObjectID || seed.Facts.After.Revision != seed.Facts.Commit.Token.Revision ||
		seed.Expected.StateDigest != seed.Facts.After.StateDigest || seed.Expected.Receipt != *seed.Facts.Receipt || !seed.Expected.Receipt.Found {
		return errors.New("invalid observation seed")
	}
	return nil
}

func observationCommit(before celldbridge.SnapshotRef, commandID string, nonce []byte) (celldbridge.CommitRequest, ObservationExpected, error) {
	payload := append([]byte("circulusd-native-durability-state-v1\x00"), nonce...)
	receipt := state.StoredReceipt{CommandDigest: state.Digest(sha256.Sum256(append([]byte("command\x00"), nonce...))), Response: append([]byte("durable-receipt\x00"), nonce...), CapabilityClaims: []state.RawCapabilityClaims{{Kind: "qualification", Payload: bytes.Clone(nonce)}}}
	request := celldbridge.CommitRequest{Snapshot: before, StateWritten: true, State: payload, Receipts: []celldbridge.ReceiptWrite{{CommandID: commandID, Receipt: receipt}}}
	digest, err := celldbridge.CommitDigest(request)
	request.RequestDigest = digest
	expectedReceipt, factErr := receiptFact(commandID, true, receipt)
	if err == nil {
		err = factErr
	}
	return request, ObservationExpected{Token: TokenFact{ObjectID: before.ObjectID, Revision: before.Revision + 1}, RequestDigest: digestText(digest), StateDigest: observationDigest(payload), Receipt: expectedReceipt}, err
}

func snapshotFact(s celldbridge.Snapshot) *SnapshotFact {
	return &SnapshotFact{ObjectID: s.ObjectID, Exists: s.Exists, Revision: s.Revision, StateDigest: digestText(s.StateDigest)}
}
func tokenFact(t state.CommitToken) TokenFact {
	return TokenFact{ObjectID: t.ObjectID, Revision: t.Revision}
}
func snapshotRef(f SnapshotFact) (celldbridge.SnapshotRef, error) {
	var digest state.Digest
	if len(f.StateDigest) != 71 || f.StateDigest[:7] != "sha256:" {
		return celldbridge.SnapshotRef{}, errors.New("invalid snapshot digest")
	}
	b, err := hex.DecodeString(f.StateDigest[7:])
	if err != nil || hex.EncodeToString(b) != f.StateDigest[7:] {
		return celldbridge.SnapshotRef{}, errors.New("invalid snapshot digest")
	}
	copy(digest[:], b)
	return celldbridge.SnapshotRef{ObjectID: f.ObjectID, Exists: f.Exists, Revision: f.Revision, StateDigest: digest}, nil
}
func receiptFact(commandID string, found bool, receipt state.StoredReceipt) (ReceiptFact, error) {
	if !found {
		return ReceiptFact{CommandID: commandID}, nil
	}
	claims := make(canonical.Array, 0, len(receipt.CapabilityClaims))
	for _, c := range receipt.CapabilityClaims {
		claims = append(claims, canonical.Map{"kind": c.Kind, "payload": canonical.Bytes(c.Payload)})
	}
	encoded, err := canonical.Encode(claims, canonical.DefaultOptions())
	if err != nil {
		return ReceiptFact{}, err
	}
	return ReceiptFact{CommandID: commandID, Found: true, CommandDigest: digestText(receipt.CommandDigest), ResponseDigest: observationDigest(receipt.Response), CapabilityClaimsDigest: observationDigest(encoded)}, nil
}
func observationDigest(value []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(value)) }
func digestText(value state.Digest) string  { return fmt.Sprintf("sha256:%x", value) }
func observeError(report *ObservationReport, operation string, err error) error {
	code := operation + ":" + observationErrorCode(err)
	report.Errors = append(report.Errors, code)
	return errors.New(code)
}
func observationErrorCode(err error) string {
	switch {
	case err == nil:
		return "NONE"
	case errors.Is(err, celldbridge.ErrSnapshotConflict):
		return "SNAPSHOT_CONFLICT"
	case errors.Is(err, celldbridge.ErrUnavailable):
		return "UNAVAILABLE"
	case errors.Is(err, celldbridge.ErrInvalidResponse):
		return "INVALID_RESPONSE"
	case errors.Is(err, celldbridge.ErrUnauthenticatedResponse):
		return "UNAUTHENTICATED_RESPONSE"
	case errors.Is(err, context.DeadlineExceeded):
		return "TIMEOUT"
	case errors.Is(err, context.Canceled):
		return "CANCELED"
	default:
		return "ERROR"
	}
}
