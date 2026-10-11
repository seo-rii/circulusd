package auditcheckpoint

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/hancomac/circulusd/internal/authstate"
	"github.com/hancomac/circulusd/internal/celld"
	"github.com/hancomac/circulusd/internal/celldbridge"
	proof "github.com/hancomac/circulusd/internal/dependency/contracttest"
)

// A pinned snapshot can conflict during lazy receipt lookup, before the
// callback's successful return. This wrapper stages the failed attempt only,
// then commits the actual subsequent callback through the fsync-backed source.
// Other modes deliberately violate Source's final-callback contract.
type retryCheckpointStorage struct {
	*testSource
	mode          string
	conflicts     int
	confirmations int
}

type checkpointReceiptConflict struct {
	celld.Transaction
	conflicts *int
}

func (tx *checkpointReceiptConflict) LookupReceipt(string) (celld.StoredReceipt, bool, error) {
	*tx.conflicts++
	return celld.StoredReceipt{}, false, celldbridge.ErrSnapshotConflict
}

func (source *retryCheckpointStorage) failedCallback(object string, callback func(celld.Transaction) error) error {
	source.mu.Lock()
	frame, err := source.read(object)
	source.mu.Unlock()
	if err != nil {
		return err
	}
	tx := &checkpointReceiptConflict{Transaction: &testTransaction{frame: cloneFrame(frame)}, conflicts: &source.conflicts}
	return callback(tx)
}

func (source *retryCheckpointStorage) Transaction(ctx context.Context, object string, callback func(celld.Transaction) error) (celld.CommitToken, error) {
	switch source.mode {
	case "retry":
		if err := source.failedCallback(object, callback); !errors.Is(err, celldbridge.ErrSnapshotConflict) {
			return celld.CommitToken{}, celld.ErrStorageContract
		}
		return source.testSource.Transaction(ctx, object, callback)
	case "skip":
		return source.testSource.Transaction(ctx, object, func(celld.Transaction) error { return nil })
	case "failed-final":
		token, err := source.testSource.Transaction(ctx, object, callback)
		if err != nil {
			return token, err
		}
		if err := source.failedCallback(object, callback); !errors.Is(err, celldbridge.ErrSnapshotConflict) {
			return celld.CommitToken{}, celld.ErrStorageContract
		}
		// A fraudulent source ignores an incomplete LAST callback and returns
		// the previous token. The consumer must reject before its barrier.
		return token, nil
	}
	return source.testSource.Transaction(ctx, object, callback)
}

func (source *retryCheckpointStorage) DurabilityBarrier(ctx context.Context, token celld.CommitToken) error {
	source.confirmations++
	return source.testSource.DurabilityBarrier(ctx, token)
}

func TestCheckpointRetriesAbortedReceiptLookupThenCommitsOriginalSignedReceipt(t *testing.T) {
	f := newFixture(t, authstate.AtomicCredentialAudit, true)
	source := &retryCheckpointStorage{testSource: f.source, mode: "retry"}
	config := f.config
	config.Storage = proof.Verify[authstate.Source](t, f.source.ProductionProofs, source, f.source.Descriptor().AtomicGroups)
	publisher, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	beforeBarriers := f.source.barriers.Load()
	checkpoint, err := publisher.Publish(context.Background())
	if err != nil || checkpoint.Claims.HeadSequence != 1 || Verify(checkpoint, config.PublicKey) != nil {
		t.Fatal("successful final callback was rejected after earlier lazy receipt conflict", err)
	}
	if source.conflicts != 2 || source.confirmations != 2 || f.source.receiptWrites.Load() != 1 || f.signer.calls.Load() != 1 || f.source.barriers.Load() != beforeBarriers+3 {
		t.Fatal("checkpoint retry lost original signature, atomic receipt or exact barriers")
	}
	replay, err := publisher.Publish(context.Background())
	if err != nil || replay.Claims != checkpoint.Claims || !bytes.Equal(replay.Signature, checkpoint.Signature) ||
		f.signer.calls.Load() != 1 || f.source.receiptWrites.Load() != 1 {
		t.Fatal("retry replay resigned or republished checkpoint", err)
	}
}

func TestCheckpointRejectsSkippedOrIncompleteFinalCallbackBeforeBarrierAndSigning(t *testing.T) {
	for _, mode := range []string{"skip", "failed-final"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, authstate.AtomicCredentialAudit, true)
			source := &retryCheckpointStorage{testSource: f.source, mode: mode}
			config := f.config
			config.Storage = proof.Verify[authstate.Source](t, f.source.ProductionProofs, source, f.source.Descriptor().AtomicGroups)
			publisher, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			beforeBarriers := f.source.barriers.Load()
			checkpoint, err := publisher.Publish(context.Background())
			if !errors.Is(err, celld.ErrStorageContract) || checkpoint.Signature != nil || f.signer.calls.Load() != 0 ||
				source.confirmations != 0 || f.source.barriers.Load() != beforeBarriers+1 || f.source.receiptWrites.Load() != 0 {
				t.Fatal("incomplete final callback published a checkpoint", err)
			}
		})
	}
}
