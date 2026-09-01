package workerd

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"sync"
)

const (
	maximumWorkerdCheckpointPayloadBytes  = 4 << 20
	maximumWorkerdCheckpointWorkerIDBytes = 256
)

var (
	errInvalidWorkerdCheckpointRequest = errors.New("workerd checkpoint store: invalid request")
	errNoAcknowledgedWorkerdCheckpoint = errors.New("workerd checkpoint store: no acknowledged checkpoint")
	errWorkerdCheckpointStoreContract  = errors.New("workerd checkpoint store: contract violation")
)

// workerdCheckpointAck proves one checkpoint commit was durably recorded by
// the external store. Reconstruction probes require this acknowledgement
// before any destructive fault may be injected.
type workerdCheckpointAck struct {
	WorkerID string
	Sequence uint64
	Digest   string
}

// workerdAcknowledgedCheckpoint is the reloadable acknowledged state for one
// content-addressed Worker ID. Payload is always an unaliased copy.
type workerdAcknowledgedCheckpoint struct {
	WorkerID string
	Sequence uint64
	Digest   string
	Payload  []byte
}

type workerdCheckpointRecord struct {
	sequence uint64
	digest   string
	payload  []byte
}

// workerdCheckpointStore is the deterministic Phase 0A checkpoint authority
// that lives outside the workerd process. Only state whose commit this store
// acknowledged is ever reloadable; a rejected or in-flight commit is never
// visible. It is reference test infrastructure, not durable production state.
type workerdCheckpointStore struct {
	mu      sync.Mutex
	records map[string]workerdCheckpointRecord
}

func newWorkerdCheckpointStore() *workerdCheckpointStore {
	return &workerdCheckpointStore{records: make(map[string]workerdCheckpointRecord)}
}

func validWorkerdCheckpointWorkerID(workerID string) bool {
	if workerID == "" || len(workerID) > maximumWorkerdCheckpointWorkerIDBytes {
		return false
	}
	for _, character := range workerID {
		if character <= 0x20 || character >= 0x7f {
			return false
		}
	}
	return true
}

func canonicalWorkerdCheckpointDigest(payload []byte) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256(payload))
}

// commit records canonical checkpoint bytes for one content-addressed Worker
// ID and returns the acknowledgement only after the state is durably
// replaceable as the latest acknowledged checkpoint. The per-worker sequence
// never wraps; exhaustion fails closed and retains the prior state.
func (store *workerdCheckpointStore) commit(workerID string, payload []byte) (workerdCheckpointAck, error) {
	if store == nil || !validWorkerdCheckpointWorkerID(workerID) ||
		len(payload) == 0 || len(payload) > maximumWorkerdCheckpointPayloadBytes {
		return workerdCheckpointAck{}, errInvalidWorkerdCheckpointRequest
	}
	digest := canonicalWorkerdCheckpointDigest(payload)
	stored := make([]byte, len(payload))
	copy(stored, payload)
	store.mu.Lock()
	defer store.mu.Unlock()
	previous := store.records[workerID].sequence
	if previous == math.MaxUint64 {
		return workerdCheckpointAck{}, fmt.Errorf("%w: checkpoint sequence exhausted for %q", errWorkerdCheckpointStoreContract, workerID)
	}
	record := workerdCheckpointRecord{sequence: previous + 1, digest: digest, payload: stored}
	store.records[workerID] = record
	return workerdCheckpointAck{WorkerID: workerID, Sequence: record.sequence, Digest: digest}, nil
}

// acknowledged reloads the latest acknowledged checkpoint. The returned
// payload is an unaliased copy whose digest is reverified on every reload.
func (store *workerdCheckpointStore) acknowledged(workerID string) (workerdAcknowledgedCheckpoint, error) {
	if store == nil || !validWorkerdCheckpointWorkerID(workerID) {
		return workerdAcknowledgedCheckpoint{}, errInvalidWorkerdCheckpointRequest
	}
	store.mu.Lock()
	record, found := store.records[workerID]
	if !found {
		store.mu.Unlock()
		return workerdAcknowledgedCheckpoint{}, fmt.Errorf("%w: %q", errNoAcknowledgedWorkerdCheckpoint, workerID)
	}
	payload := make([]byte, len(record.payload))
	copy(payload, record.payload)
	store.mu.Unlock()
	if digest := canonicalWorkerdCheckpointDigest(payload); digest != record.digest {
		return workerdAcknowledgedCheckpoint{}, fmt.Errorf("%w: reload digest mismatch for %q", errWorkerdCheckpointStoreContract, workerID)
	}
	return workerdAcknowledgedCheckpoint{
		WorkerID: workerID, Sequence: record.sequence, Digest: record.digest, Payload: payload,
	}, nil
}

// requireAcknowledged gates destructive fault injection: it succeeds only
// when the exact digest is the current acknowledged checkpoint for the
// content-addressed Worker ID.
func (store *workerdCheckpointStore) requireAcknowledged(workerID string, digest string) error {
	acknowledged, err := store.acknowledged(workerID)
	if err != nil {
		return err
	}
	if acknowledged.Digest != digest {
		return fmt.Errorf("%w: checkpoint %q is not the acknowledged state for %q", errWorkerdCheckpointStoreContract, digest, workerID)
	}
	return nil
}
