package sessionstate

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/hancomac/circulusd/internal/celld"
)

// ReferenceStorage is a process-local, in-memory celld.Storage for reference and
// crash-window tests. Committed bytes persist across a simulated restart (a fresh
// celld.Host constructed over the same ReferenceStorage), which models durability
// and single-writer serialization but is NOT a production durable substrate: it
// commits at transaction time rather than proving an fsync-equivalent barrier.
// The real durability barrier is qualified separately against a provisioned celld
// process (Unit 11.6). Its mutex serializes every object transaction.
type ReferenceStorage struct {
	mu      sync.Mutex
	objects map[string]*referenceObject
}

type referenceObject struct {
	state    []byte
	receipts map[string]celld.StoredReceipt
	revision uint64
}

// State returns a copy of the committed state bytes for objectID, modeling a
// durable read after a restart.
func (storage *ReferenceStorage) State(objectID string) ([]byte, bool) {
	storage.mu.Lock()
	defer storage.mu.Unlock()
	object := storage.objects[objectID]
	if object == nil {
		return nil, false
	}
	return append([]byte(nil), object.state...), true
}

// NewReferenceStorage returns an empty reference storage.
func NewReferenceStorage() *ReferenceStorage {
	return &ReferenceStorage{objects: make(map[string]*referenceObject)}
}

// Transaction serializes one object's read/write set. Staged writes are applied
// only when the callback returns nil; any error rolls the whole set back.
func (storage *ReferenceStorage) Transaction(
	ctx context.Context,
	objectID string,
	callback func(celld.Transaction) error,
) (celld.CommitToken, error) {
	if err := ctx.Err(); err != nil {
		return celld.CommitToken{}, err
	}
	if objectID == "" || callback == nil {
		return celld.CommitToken{}, errors.New("sessionstate: invalid transaction request")
	}
	storage.mu.Lock()
	defer storage.mu.Unlock()
	object := storage.objects[objectID]
	if object == nil {
		object = &referenceObject{receipts: make(map[string]celld.StoredReceipt)}
	}
	transaction := &referenceTransaction{object: object}
	if err := callback(transaction); err != nil {
		return celld.CommitToken{}, err
	}
	if transaction.stateWritten {
		object.state = transaction.stagedState
	}
	for id, receipt := range transaction.stagedReceipts {
		object.receipts[id] = receipt
	}
	object.revision++
	storage.objects[objectID] = object
	return celld.CommitToken{ObjectID: objectID, Revision: object.revision}, nil
}

// DurabilityBarrier confirms the committed revision exists. In-memory commits are
// already durable, so this only validates the token.
func (storage *ReferenceStorage) DurabilityBarrier(ctx context.Context, token celld.CommitToken) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	storage.mu.Lock()
	defer storage.mu.Unlock()
	object := storage.objects[token.ObjectID]
	if object == nil || token.Revision == 0 || object.revision < token.Revision {
		return fmt.Errorf("sessionstate: unknown commit token %s@%d", token.ObjectID, token.Revision)
	}
	return nil
}

type referenceTransaction struct {
	object         *referenceObject
	stagedState    []byte
	stateWritten   bool
	stagedReceipts map[string]celld.StoredReceipt
}

func (transaction *referenceTransaction) ReadState() ([]byte, error) {
	if transaction.stateWritten {
		return append([]byte(nil), transaction.stagedState...), nil
	}
	return append([]byte(nil), transaction.object.state...), nil
}

func (transaction *referenceTransaction) LookupReceipt(commandID string) (celld.StoredReceipt, bool, error) {
	if receipt, ok := transaction.stagedReceipts[commandID]; ok {
		return cloneReceipt(receipt), true, nil
	}
	if receipt, ok := transaction.object.receipts[commandID]; ok {
		return cloneReceipt(receipt), true, nil
	}
	return celld.StoredReceipt{}, false, nil
}

func (transaction *referenceTransaction) WriteState(state []byte) error {
	transaction.stagedState = append([]byte(nil), state...)
	transaction.stateWritten = true
	return nil
}

func (transaction *referenceTransaction) WriteReceipt(commandID string, receipt celld.StoredReceipt) error {
	if transaction.stagedReceipts == nil {
		transaction.stagedReceipts = make(map[string]celld.StoredReceipt)
	}
	transaction.stagedReceipts[commandID] = cloneReceipt(receipt)
	return nil
}

func cloneReceipt(receipt celld.StoredReceipt) celld.StoredReceipt {
	clone := celld.StoredReceipt{
		CommandDigest: receipt.CommandDigest,
		Response:      append([]byte(nil), receipt.Response...),
	}
	if len(receipt.CapabilityClaims) != 0 {
		clone.CapabilityClaims = make([]celld.RawCapabilityClaims, len(receipt.CapabilityClaims))
		for index, claim := range receipt.CapabilityClaims {
			clone.CapabilityClaims[index] = celld.RawCapabilityClaims{
				Kind:    claim.Kind,
				Payload: append([]byte(nil), claim.Payload...),
			}
		}
	}
	return clone
}
