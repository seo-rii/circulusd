package blob

import "context"

type storageGate struct {
	turn  chan struct{}
	users int
}

// acquireStorage fences storage mutations through their matching guard update.
// The authority is process-local: all ContentStores operating on the same blob
// namespace must share this GuardTable, and physical writes/deletes must go
// through those stores. A durable or distributed adapter needs an equivalent
// fence at its own storage mutation boundary.
//
// The gate is per key, so slow storage does not hold the guard table mutex or
// block unrelated blobs. Its reference count includes queued callers; canceled
// waiters and idle keys leave no retained gate entries.
func (table *GuardTable) acquireStorage(ctx context.Context, key Key) (func(), error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	table.storageMu.Lock()
	gate := table.storageGates[key]
	if gate == nil {
		gate = &storageGate{turn: make(chan struct{}, 1)}
		table.storageGates[key] = gate
	}
	gate.users++
	table.storageMu.Unlock()

	select {
	case gate.turn <- struct{}{}:
	case <-ctx.Done():
		table.releaseStorageReference(key, gate)
		return nil, ctx.Err()
	}
	release := func() {
		<-gate.turn
		table.releaseStorageReference(key, gate)
	}
	if err := ctx.Err(); err != nil {
		release()
		return nil, err
	}
	return release, nil
}

func (table *GuardTable) releaseStorageReference(key Key, gate *storageGate) {
	table.storageMu.Lock()
	defer table.storageMu.Unlock()
	gate.users--
	if gate.users == 0 {
		delete(table.storageGates, key)
	}
}
