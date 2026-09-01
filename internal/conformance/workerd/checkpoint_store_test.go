package workerd

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
)

func workerdTestWorkerID(fill byte) string {
	return "sha256-" + strings.Repeat(fmt.Sprintf("%02x", fill), 32)
}

func TestWorkerdCheckpointStoreAcknowledgesCanonicalCommitBeforeReload(t *testing.T) {
	t.Parallel()
	store := newWorkerdCheckpointStore()
	workerID := workerdTestWorkerID(0x11)
	payload := []byte("checkpoint-one")
	wantDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(payload))

	ack, err := store.commit(workerID, payload)
	if err != nil {
		t.Fatalf("commit() error = %v", err)
	}
	if ack.WorkerID != workerID || ack.Sequence != 1 || ack.Digest != wantDigest {
		t.Fatalf("commit() ack = %+v, want sequence 1 with canonical digest %q", ack, wantDigest)
	}
	payload[0] = 'X'
	acknowledged, err := store.acknowledged(workerID)
	if err != nil {
		t.Fatalf("acknowledged() error = %v", err)
	}
	if acknowledged.WorkerID != workerID || acknowledged.Sequence != 1 ||
		acknowledged.Digest != wantDigest || string(acknowledged.Payload) != "checkpoint-one" {
		t.Fatalf("acknowledged() = %+v, want the exact committed bytes", acknowledged)
	}
	acknowledged.Payload[0] = 'Y'
	reloaded, err := store.acknowledged(workerID)
	if err != nil || string(reloaded.Payload) != "checkpoint-one" {
		t.Fatalf("acknowledged(after caller mutation) = %+v, %v, want unaliased stored bytes", reloaded, err)
	}
}

func TestWorkerdCheckpointStoreNeverServesUnacknowledgedOrForeignState(t *testing.T) {
	t.Parallel()
	store := newWorkerdCheckpointStore()
	other := newWorkerdCheckpointStore()
	first := workerdTestWorkerID(0x22)
	second := workerdTestWorkerID(0x33)

	if _, err := store.acknowledged(first); !errors.Is(err, errNoAcknowledgedWorkerdCheckpoint) {
		t.Fatalf("acknowledged(no commit) error = %v, want no acknowledged checkpoint", err)
	}
	if _, err := store.commit(first, []byte("first-state")); err != nil {
		t.Fatalf("commit(first) error = %v", err)
	}
	if _, err := store.acknowledged(second); !errors.Is(err, errNoAcknowledgedWorkerdCheckpoint) {
		t.Fatalf("acknowledged(other worker) error = %v, want isolated worker state", err)
	}
	if _, err := other.acknowledged(first); !errors.Is(err, errNoAcknowledgedWorkerdCheckpoint) {
		t.Fatalf("acknowledged(other store) error = %v, want isolated store state", err)
	}
}

func TestWorkerdCheckpointStoreReplacesAcknowledgedStateInCommitOrder(t *testing.T) {
	t.Parallel()
	store := newWorkerdCheckpointStore()
	workerID := workerdTestWorkerID(0x44)
	firstAck, err := store.commit(workerID, []byte("state-one"))
	if err != nil {
		t.Fatalf("commit(one) error = %v", err)
	}
	secondAck, err := store.commit(workerID, []byte("state-two"))
	if err != nil {
		t.Fatalf("commit(two) error = %v", err)
	}
	if firstAck.Sequence != 1 || secondAck.Sequence != 2 || firstAck.Digest == secondAck.Digest {
		t.Fatalf("acks = %+v, %+v, want increasing sequences with distinct digests", firstAck, secondAck)
	}
	acknowledged, err := store.acknowledged(workerID)
	if err != nil || acknowledged.Sequence != 2 || acknowledged.Digest != secondAck.Digest ||
		string(acknowledged.Payload) != "state-two" {
		t.Fatalf("acknowledged() = %+v, %v, want the latest committed state", acknowledged, err)
	}
	if err := store.requireAcknowledged(workerID, secondAck.Digest); err != nil {
		t.Fatalf("requireAcknowledged(current) error = %v", err)
	}
	if err := store.requireAcknowledged(workerID, firstAck.Digest); !errors.Is(err, errWorkerdCheckpointStoreContract) {
		t.Fatalf("requireAcknowledged(replaced) error = %v, want stale state rejected before fault injection", err)
	}
	if err := store.requireAcknowledged(workerdTestWorkerID(0x55), secondAck.Digest); !errors.Is(err, errNoAcknowledgedWorkerdCheckpoint) {
		t.Fatalf("requireAcknowledged(unknown worker) error = %v, want no acknowledged checkpoint", err)
	}
}

func TestWorkerdCheckpointStoreRejectsInvalidCommits(t *testing.T) {
	t.Parallel()
	store := newWorkerdCheckpointStore()
	validID := workerdTestWorkerID(0x66)
	oversized := make([]byte, maximumWorkerdCheckpointPayloadBytes+1)
	for name, request := range map[string]struct {
		workerID string
		payload  []byte
	}{
		"empty worker id":     {workerID: "", payload: []byte("state")},
		"oversized worker id": {workerID: strings.Repeat("a", maximumWorkerdCheckpointWorkerIDBytes+1), payload: []byte("state")},
		"worker id space":     {workerID: "sha256 state", payload: []byte("state")},
		"worker id control":   {workerID: "sha256\x00state", payload: []byte("state")},
		"worker id non-ascii": {workerID: "sha256-état", payload: []byte("state")},
		"empty payload":       {workerID: validID, payload: nil},
		"oversized payload":   {workerID: validID, payload: oversized},
	} {
		t.Run(name, func(t *testing.T) {
			if ack, err := store.commit(request.workerID, request.payload); !errors.Is(err, errInvalidWorkerdCheckpointRequest) || ack != (workerdCheckpointAck{}) {
				t.Fatalf("commit(%s) = %+v, %v, want invalid request", name, ack, err)
			}
		})
	}
	if _, err := store.acknowledged(validID); !errors.Is(err, errNoAcknowledgedWorkerdCheckpoint) {
		t.Fatalf("acknowledged(after rejected commits) error = %v, want empty store", err)
	}
	var nilStore *workerdCheckpointStore
	if _, err := nilStore.commit(validID, []byte("state")); !errors.Is(err, errInvalidWorkerdCheckpointRequest) {
		t.Fatalf("commit(nil store) error = %v, want invalid request", err)
	}
	if _, err := nilStore.acknowledged(validID); !errors.Is(err, errInvalidWorkerdCheckpointRequest) {
		t.Fatalf("acknowledged(nil store) error = %v, want invalid request", err)
	}
}

func TestWorkerdCheckpointStoreFailsClosedAtSequenceExhaustion(t *testing.T) {
	t.Parallel()
	store := newWorkerdCheckpointStore()
	workerID := workerdTestWorkerID(0x77)
	store.mu.Lock()
	store.records[workerID] = workerdCheckpointRecord{
		sequence: math.MaxUint64,
		digest:   fmt.Sprintf("sha256:%x", sha256.Sum256([]byte("terminal"))),
		payload:  []byte("terminal"),
	}
	store.mu.Unlock()
	if ack, err := store.commit(workerID, []byte("next")); !errors.Is(err, errWorkerdCheckpointStoreContract) || ack != (workerdCheckpointAck{}) {
		t.Fatalf("commit(at exhaustion) = %+v, %v, want fail closed without wrap", ack, err)
	}
	acknowledged, err := store.acknowledged(workerID)
	if err != nil || acknowledged.Sequence != math.MaxUint64 || string(acknowledged.Payload) != "terminal" {
		t.Fatalf("acknowledged(after exhaustion) = %+v, %v, want prior state retained", acknowledged, err)
	}
}

func TestWorkerdCheckpointStoreSerializesConcurrentCommits(t *testing.T) {
	t.Parallel()
	store := newWorkerdCheckpointStore()
	workerID := workerdTestWorkerID(0x88)
	const writers = 32
	acks := make([]workerdCheckpointAck, writers)
	var group sync.WaitGroup
	for index := range writers {
		group.Add(1)
		go func() {
			defer group.Done()
			ack, err := store.commit(workerID, fmt.Appendf(nil, "state-%02d", index))
			if err != nil {
				t.Errorf("commit(%d) error = %v", index, err)
				return
			}
			acks[index] = ack
		}()
	}
	group.Wait()
	if t.Failed() {
		t.FailNow()
	}
	seen := make(map[uint64]int, writers)
	var last workerdCheckpointAck
	for index, ack := range acks {
		if previous, duplicated := seen[ack.Sequence]; duplicated {
			t.Fatalf("commits %d and %d share sequence %d", previous, index, ack.Sequence)
		}
		seen[ack.Sequence] = index
		if ack.Sequence < 1 || ack.Sequence > writers {
			t.Fatalf("commit %d sequence = %d, want contiguous 1..%d", index, ack.Sequence, writers)
		}
		if ack.Sequence == writers {
			last = ack
		}
	}
	acknowledged, err := store.acknowledged(workerID)
	if err != nil || acknowledged.Sequence != writers || acknowledged.Digest != last.Digest {
		t.Fatalf("acknowledged() = %+v, %v, want the final commit %+v", acknowledged, err, last)
	}
}
