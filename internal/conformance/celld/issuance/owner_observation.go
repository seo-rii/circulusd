package issuance

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
)

// OwnershipRecord contains the actual native own.json response body and ETag.
// The cell epoch is deliberately distinct from a runtime probe epoch.
type OwnershipRecord struct {
	Body string `json:"body"`
	ETag string `json:"etag"`
}

// OwnerObservation is the retained protocol transcript for a prior live owner.
// An ownership read after the bucket proof must show the newer owner/epoch,
// and the held old write must receive a failure instead of an acknowledgement.
// This excludes application snapshot conflicts and plain LTX PUT failures.
type OwnerObservation struct {
	SchemaVersion                  uint32          `json:"schemaVersion"`
	Kind                           string          `json:"kind"`
	ObjectID                       string          `json:"objectId"`
	CellID                         string          `json:"cellId"`
	OwnershipKeyDigest             string          `json:"ownershipKeyDigest"`
	LTXKeyDigest                   string          `json:"ltxKeyDigest"`
	LTXBodyDigest                  string          `json:"ltxBodyDigest"`
	LTXPutStatus                   uint32          `json:"ltxPutStatus"`
	LTXPutCompletedSequence        uint64          `json:"ltxPutCompletedSequence"`
	OwnershipGetStartedSequence    uint64          `json:"ownershipGetStartedSequence"`
	OwnershipGetReleasedSequence   uint64          `json:"ownershipGetReleasedSequence"`
	OwnershipGetCompletedSequence  uint64          `json:"ownershipGetCompletedSequence"`
	OwnershipGetStatus             uint32          `json:"ownershipGetStatus"`
	HeldRequests                   uint32          `json:"heldRequests"`
	ClientRequestCount             uint32          `json:"clientRequestCount"`
	PriorMeasurement               Measurement     `json:"priorMeasurement"`
	CurrentMeasurement             Measurement     `json:"currentMeasurement"`
	PriorRecord                    OwnershipRecord `json:"priorRecord"`
	CurrentRecord                  OwnershipRecord `json:"currentRecord"`
	ProofOwnershipRead             OwnershipRecord `json:"proofOwnershipRead"`
	PriorProcessStateBeforeRelease string          `json:"priorProcessStateBeforeRelease"`
	PausedRequestDigest            string          `json:"pausedRequestDigest"`
	PriorWriteStartedSequence      uint64          `json:"priorWriteStartedSequence"`
	CurrentOwnerObservedSequence   uint64          `json:"currentOwnerObservedSequence"`
	PriorWriteReleasedSequence     uint64          `json:"priorWriteReleasedSequence"`
	PriorResponseObservedSequence  uint64          `json:"priorResponseObservedSequence"`
	OldResponseStatus              uint32          `json:"oldResponseStatus"`
	OldResponseBody                string          `json:"oldResponseBody"`
	ClientErrorCode                string          `json:"clientErrorCode"`
	PriorExitCode                  uint32          `json:"priorExitCode"`
	PriorExitSignal                uint32          `json:"priorExitSignal"`
	PriorTerminationLogBody        string          `json:"priorTerminationLogBody"`
	BeforeRevision                 uint64          `json:"beforeRevision"`
	AfterRevision                  uint64          `json:"afterRevision"`
	BeforeStateDigest              string          `json:"beforeStateDigest"`
	AfterStateDigest               string          `json:"afterStateDigest"`
}

func OwnerObservationDigest(o OwnerObservation) (string, error) {
	encoded, err := json.Marshal(o)
	if err != nil || len(encoded) > 32<<10 {
		return "", ErrInvalidReport
	}
	encoded = append(encoded, '\n')
	h := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

type ownWire struct {
	Node  string `json:"node"`
	Epoch uint64 `json:"epoch"`
}

func decodeOwnerRecord(r OwnershipRecord) (ownWire, error) {
	var owner ownWire
	body, err := base64.StdEncoding.Strict().DecodeString(r.Body)
	if err != nil || len(body) == 0 || len(body) > 1024 || base64.StdEncoding.EncodeToString(body) != r.Body || !validETag(r.ETag) || DecodeStrict(body, &owner) != nil ||
		!identifier.MatchString(owner.Node) || owner.Epoch == 0 {
		return ownWire{}, ErrUnqualified
	}
	return owner, nil
}

func validateOwnerObservation(r RawReport) error {
	o, f := r.OwnerObservation, r.NativeOwnerFence
	prior, err := decodeOwnerRecord(o.PriorRecord)
	if err != nil {
		return err
	}
	current, err := decodeOwnerRecord(o.CurrentRecord)
	if err != nil {
		return err
	}
	proof, err := decodeOwnerRecord(o.ProofOwnershipRead)
	if err != nil {
		return err
	}
	body, err := base64.StdEncoding.Strict().DecodeString(o.OldResponseBody)
	if err != nil || len(body) > 4096 || base64.StdEncoding.EncodeToString(body) != o.OldResponseBody {
		return ErrUnqualified
	}
	if o.OldResponseStatus == 0 {
		log, err := base64.StdEncoding.Strict().DecodeString(o.PriorTerminationLogBody)
		if err != nil || len(log) == 0 || len(log) > 4096 || base64.StdEncoding.EncodeToString(log) != o.PriorTerminationLogBody ||
			!bytes.Contains(log, []byte("SELF-FENCE:")) || len(body) != 0 || o.PriorExitCode != 3 || o.PriorExitSignal != 0 ||
			(o.ClientErrorCode != "UNAVAILABLE" && o.ClientErrorCode != "INVALID_RESPONSE") {
			return ErrUnqualified
		}
	} else if (o.OldResponseStatus != 500 && o.OldResponseStatus != 503) || len(body) == 0 ||
		o.ClientErrorCode != "HTTP_FAILURE" || o.PriorExitCode != 0 || o.PriorExitSignal != 0 || o.PriorTerminationLogBody != "" {
		return ErrUnqualified
	}
	computed, err := OwnerObservationDigest(o)
	if err != nil {
		return err
	}
	if o.SchemaVersion != 1 || o.Kind != "circulusd.native-owner-observation/v1" || o.ObjectID != r.Transaction.ObjectID ||
		!identifier.MatchString(o.CellID) || !digest.MatchString(o.OwnershipKeyDigest) ||
		!digest.MatchString(o.LTXKeyDigest) || !digest.MatchString(o.LTXBodyDigest) || o.LTXPutStatus < 200 || o.LTXPutStatus >= 300 ||
		o.HeldRequests != 1 || o.ClientRequestCount != 1 || o.OwnershipGetStatus != 200 ||
		o.LTXPutCompletedSequence <= o.PriorWriteStartedSequence || o.OwnershipGetStartedSequence <= o.LTXPutCompletedSequence ||
		o.CurrentOwnerObservedSequence <= o.OwnershipGetStartedSequence || o.OwnershipGetReleasedSequence != o.PriorWriteReleasedSequence ||
		o.OwnershipGetCompletedSequence <= o.OwnershipGetReleasedSequence || o.PriorResponseObservedSequence < o.OwnershipGetCompletedSequence ||
		!validMeasurement(o.PriorMeasurement) || o.CurrentMeasurement != r.Measurement ||
		o.PriorMeasurement.BuildDigest != r.Measurement.BuildDigest || o.PriorMeasurement.ApplicationDigest != r.Measurement.ApplicationDigest ||
		o.PriorMeasurement.TransactionDomainID != r.Measurement.TransactionDomainID ||
		o.PriorMeasurement.ProbeEpoch != f.PriorEpoch || o.PriorMeasurement.ProcessID != f.PriorPID ||
		prior.Node == current.Node || current.Epoch <= prior.Epoch || o.PriorRecord.ETag == o.CurrentRecord.ETag ||
		proof != current || o.ProofOwnershipRead != o.CurrentRecord || o.PriorProcessStateBeforeRelease != f.PriorProcessState || (o.PriorProcessStateBeforeRelease != "running" && o.PriorProcessStateBeforeRelease != "stopped") ||
		!digest.MatchString(o.PausedRequestDigest) || o.PausedRequestDigest == r.Transaction.RequestDigest ||
		o.PriorWriteStartedSequence == 0 || o.CurrentOwnerObservedSequence <= o.PriorWriteStartedSequence ||
		o.PriorWriteReleasedSequence <= o.CurrentOwnerObservedSequence || o.PriorResponseObservedSequence <= o.PriorWriteReleasedSequence ||
		o.BeforeRevision != f.BeforeRevision || o.AfterRevision != f.AfterRevision ||
		!digest.MatchString(o.BeforeStateDigest) || o.BeforeStateDigest != o.AfterStateDigest || computed != f.ObservationDigest {
		return ErrUnqualified
	}
	return nil
}
