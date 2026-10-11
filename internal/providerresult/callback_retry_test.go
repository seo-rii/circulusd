package providerresult

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/hancomac/circulusd/internal/celld"
	"github.com/hancomac/circulusd/internal/celldbridge"
	proof "github.com/hancomac/circulusd/internal/dependency/contracttest"
)

type retryResultStorage struct {
	*persistenceTestStorage
	mode      string
	conflicts int
}

type resultReceiptConflict struct {
	celld.Transaction
	conflicts *int
}

func (tx *resultReceiptConflict) LookupReceipt(string) (celld.StoredReceipt, bool, error) {
	*tx.conflicts++
	return celld.StoredReceipt{}, false, celldbridge.ErrSnapshotConflict
}

func (source *retryResultStorage) failedCallback(object string, callback func(celld.Transaction) error) error {
	source.mu.Lock()
	frame := clonePersistenceObject(source.objects[object])
	source.mu.Unlock()
	tx := &resultReceiptConflict{Transaction: &persistenceTestTransaction{object: frame}, conflicts: &source.conflicts}
	return callback(tx)
}

func (source *retryResultStorage) Transaction(ctx context.Context, object string, callback func(celld.Transaction) error) (celld.CommitToken, error) {
	switch source.mode {
	case "retry":
		if err := source.failedCallback(object, callback); !errors.Is(err, celldbridge.ErrSnapshotConflict) {
			return celld.CommitToken{}, celld.ErrStorageContract
		}
		return source.persistenceTestStorage.Transaction(ctx, object, callback)
	case "skip":
		// The deliberately false token is otherwise shape-valid; the consumer
		// must reject its absent callback before invoking the native barrier.
		return celld.CommitToken{ObjectID: object, Revision: 1}, nil
	case "failed-final":
		token, err := source.persistenceTestStorage.Transaction(ctx, object, callback)
		if err != nil {
			return token, err
		}
		if err := source.failedCallback(object, callback); !errors.Is(err, celldbridge.ErrSnapshotConflict) {
			return celld.CommitToken{}, celld.ErrStorageContract
		}
		return token, nil
	}
	return source.persistenceTestStorage.Transaction(ctx, object, callback)
}

func TestProviderPublicationAndReadRetryAbortedLazyReceiptLookup(t *testing.T) {
	storage, _, _, record := newPersistenceFixture(t, "model_final")
	source := &retryResultStorage{persistenceTestStorage: storage, mode: "retry"}
	binding := proof.Verify[TransactionStorage](t, storage.ProductionProofs, source, storage.Descriptor().AtomicGroups)
	store, err := NewPersistentRecords(binding, RecordResolverConfig{})
	if err != nil {
		t.Fatal(err)
	}
	commit, err := store.WriteCommittedResult(context.Background(), record)
	if err != nil || commit.Replayed || storage.commits != 1 || storage.barriers != 1 || source.conflicts != 1 {
		t.Fatal("failed prior callback blocked actual publication", err)
	}
	read, err := store.ReadCommittedResult(context.Background(), record.Request)
	if err != nil || read.Request != record.Request || !bytes.Equal(read.CanonicalCBOR, record.CanonicalCBOR) || !bytes.Equal(read.LedgerResult, record.LedgerResult) ||
		storage.commits != 1 || storage.barriers != 2 || source.conflicts != 2 {
		t.Fatal("failed prior callback blocked original immutable read", err)
	}
	replay, err := store.WriteCommittedResult(context.Background(), record)
	if err != nil || !replay.Replayed || replay.RecordDigest != commit.RecordDigest || storage.commits != 1 || storage.barriers != 3 {
		t.Fatal("publication retry replaced original record", err)
	}
}

func TestProviderResultRejectsSkippedOrFailedFinalCallbackWithoutExposure(t *testing.T) {
	for _, operation := range []string{"write", "read"} {
		for _, mode := range []string{"skip", "failed-final"} {
			t.Run(operation+"/"+mode, func(t *testing.T) {
				storage, _, original, record := newPersistenceFixture(t, "model_final")
				if operation == "read" {
					if _, err := original.WriteCommittedResult(context.Background(), record); err != nil {
						t.Fatal(err)
					}
				}
				source := &retryResultStorage{persistenceTestStorage: storage, mode: mode}
				store, err := NewPersistentRecords(proof.Verify[TransactionStorage](t, storage.ProductionProofs, source, storage.Descriptor().AtomicGroups), RecordResolverConfig{})
				if err != nil {
					t.Fatal(err)
				}
				before := storage.barriers
				if operation == "write" {
					commit, err := store.WriteCommittedResult(context.Background(), record)
					if !errors.Is(err, celld.ErrStorageContract) || commit != (RecordCommit{}) {
						t.Fatal("failed final callback acknowledged publication", err)
					}
				} else {
					read, err := store.ReadCommittedResult(context.Background(), record.Request)
					if !errors.Is(err, celld.ErrStorageContract) || read.CanonicalCBOR != nil || read.LedgerResult != nil {
						t.Fatal("failed final callback exposed record bytes", err)
					}
				}
				if storage.barriers != before {
					t.Fatal("failed final callback reached durability barrier")
				}
			})
		}
	}
}
