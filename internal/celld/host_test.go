package celld

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
)

var (
	errCrashInjected  = errors.New("test: crash injected")
	errBadCommand     = errors.New("test: bad command shape")
	errBadState       = errors.New("test: bad state shape")
	errStaleAuthority = errors.New("test: stale capability")
)

type counterState struct {
	Value      int    `json:"value"`
	Generation uint64 `json:"generation"`
}

type counterCommand struct {
	Delta       int    `json:"delta"`
	Generation  uint64 `json:"generation"`
	IssuePermit bool   `json:"issuePermit"`
}

type counterAggregate struct {
	applyCalls        atomic.Int64
	nextStateOverride []byte
	responseOverride  []byte
	claimsOverride    []RawCapabilityClaims
}

func (aggregate *counterAggregate) ValidateCommand(_ context.Context, command []byte) error {
	var decoded counterCommand
	if err := decodeExactJSON(command, &decoded); err != nil || decoded.Delta == 0 || decoded.Generation == 0 {
		return errBadCommand
	}
	return nil
}

func (aggregate *counterAggregate) ValidateState(_ context.Context, state []byte) error {
	var decoded counterState
	if err := decodeExactJSON(state, &decoded); err != nil || decoded.Generation == 0 || decoded.Value < 0 {
		return errBadState
	}
	return nil
}

func (aggregate *counterAggregate) Authorize(_ context.Context, state []byte, command []byte) error {
	var current counterState
	var requested counterCommand
	if decodeExactJSON(state, &current) != nil || decodeExactJSON(command, &requested) != nil {
		return errBadCommand
	}
	if requested.Generation != current.Generation {
		return errStaleAuthority
	}
	return nil
}

func (aggregate *counterAggregate) Apply(_ context.Context, state []byte, command []byte) (ApplyResult, error) {
	aggregate.applyCalls.Add(1)
	var current counterState
	var requested counterCommand
	if err := decodeExactJSON(state, &current); err != nil {
		return ApplyResult{}, errBadState
	}
	if err := decodeExactJSON(command, &requested); err != nil {
		return ApplyResult{}, errBadCommand
	}
	current.Value += requested.Delta
	nextState, _ := json.Marshal(current)
	response, _ := json.Marshal(struct {
		Value int `json:"value"`
	}{Value: current.Value})
	claims := []RawCapabilityClaims(nil)
	if requested.IssuePermit {
		claims = []RawCapabilityClaims{{Kind: "dispatch", Payload: []byte("generation-bound-claims")}}
	}
	if aggregate.nextStateOverride != nil {
		nextState = aggregate.nextStateOverride
	}
	if aggregate.responseOverride != nil {
		response = aggregate.responseOverride
	}
	if aggregate.claimsOverride != nil {
		claims = aggregate.claimsOverride
	}
	return ApplyResult{NextState: nextState, Response: response, CapabilityClaims: claims}, nil
}

func decodeExactJSON(encoded []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("trailing JSON value")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

type memoryStorage struct {
	mu           sync.Mutex
	objectID     string
	state        []byte
	receipts     map[string]StoredReceipt
	revision     uint64
	barrierCount int
	barrierErr   error
}

func newMemoryStorage(objectID string, initialState []byte) *memoryStorage {
	return &memoryStorage{
		objectID: objectID,
		state:    append([]byte(nil), initialState...),
		receipts: make(map[string]StoredReceipt),
		revision: 1,
	}
}

func (storage *memoryStorage) Transaction(
	ctx context.Context,
	objectID string,
	callback func(Transaction) error,
) (CommitToken, error) {
	if err := ctx.Err(); err != nil {
		return CommitToken{}, err
	}
	storage.mu.Lock()
	defer storage.mu.Unlock()
	if objectID != storage.objectID {
		return CommitToken{}, errors.New("test: wrong object")
	}
	tx := &memoryTransaction{
		state:    append([]byte(nil), storage.state...),
		receipts: cloneStoredReceipts(storage.receipts),
	}
	if err := callback(tx); err != nil {
		return CommitToken{}, err
	}
	if tx.dirty {
		storage.state = append([]byte(nil), tx.state...)
		storage.receipts = cloneStoredReceipts(tx.receipts)
		storage.revision++
	}
	return CommitToken{ObjectID: objectID, Revision: storage.revision}, nil
}

func (storage *memoryStorage) DurabilityBarrier(ctx context.Context, token CommitToken) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	storage.mu.Lock()
	defer storage.mu.Unlock()
	if token.ObjectID != storage.objectID || token.Revision == 0 || token.Revision > storage.revision {
		return errors.New("test: bad commit token")
	}
	if storage.barrierErr != nil {
		return storage.barrierErr
	}
	storage.barrierCount++
	return nil
}

func (storage *memoryStorage) snapshot() (counterState, int, int) {
	storage.mu.Lock()
	defer storage.mu.Unlock()
	var state counterState
	_ = json.Unmarshal(storage.state, &state)
	return state, len(storage.receipts), storage.barrierCount
}

func (storage *memoryStorage) forceState(state counterState) {
	storage.mu.Lock()
	defer storage.mu.Unlock()
	storage.state, _ = json.Marshal(state)
	storage.revision++
}

type memoryTransaction struct {
	state    []byte
	receipts map[string]StoredReceipt
	dirty    bool
}

func (transaction *memoryTransaction) ReadState() ([]byte, error) {
	return append([]byte(nil), transaction.state...), nil
}

func (transaction *memoryTransaction) LookupReceipt(commandID string) (StoredReceipt, bool, error) {
	receipt, found := transaction.receipts[commandID]
	return cloneStoredReceipt(receipt), found, nil
}

func (transaction *memoryTransaction) WriteState(state []byte) error {
	transaction.state = append([]byte(nil), state...)
	transaction.dirty = true
	return nil
}

func (transaction *memoryTransaction) WriteReceipt(commandID string, receipt StoredReceipt) error {
	transaction.receipts[commandID] = cloneStoredReceipt(receipt)
	transaction.dirty = true
	return nil
}

type recordingSealer struct {
	codec   *PermitCodec
	storage *memoryStorage
	mu      sync.Mutex
	tokens  [][]byte
}

func (sealer *recordingSealer) Seal(
	ctx context.Context,
	binding PermitBinding,
	claims RawCapabilityClaims,
) (SealedPermit, error) {
	if err := ctx.Err(); err != nil {
		return SealedPermit{}, err
	}
	_, _, barriers := sealer.storage.snapshot()
	if barriers == 0 {
		return SealedPermit{}, errors.New("test: seal called before durability barrier")
	}
	permit, err := sealer.codec.Seal(ctx, binding, claims)
	if err != nil {
		return SealedPermit{}, err
	}
	encoded, _ := permit.MarshalBinary()
	sealer.mu.Lock()
	sealer.tokens = append(sealer.tokens, encoded)
	sealer.mu.Unlock()
	return permit, nil
}

func (sealer *recordingSealer) count() int {
	sealer.mu.Lock()
	defer sealer.mu.Unlock()
	return len(sealer.tokens)
}

func (sealer *recordingSealer) token(index int) []byte {
	sealer.mu.Lock()
	defer sealer.mu.Unlock()
	return append([]byte(nil), sealer.tokens[index]...)
}

type faultOnce struct {
	mu      sync.Mutex
	target  FaultPoint
	fired   bool
	visited []FaultPoint
}

func (fault *faultOnce) Inject(_ context.Context, point FaultPoint) error {
	fault.mu.Lock()
	defer fault.mu.Unlock()
	fault.visited = append(fault.visited, point)
	if point == fault.target && !fault.fired {
		fault.fired = true
		return errCrashInjected
	}
	return nil
}

func TestHostCommitsStateAndReceiptBeforeSealingCapability(t *testing.T) {
	t.Parallel()
	state := mustJSON(t, counterState{Generation: 7})
	storage := newMemoryStorage("session-1", state)
	aggregate := &counterAggregate{}
	codec := mustPermitCodec(t)
	sealer := &recordingSealer{codec: codec, storage: storage}
	host := mustHost(t, Config{Storage: storage, Aggregate: aggregate, Sealer: sealer})
	command := mustJSON(t, counterCommand{Delta: 1, Generation: 7, IssuePermit: true})

	result, err := host.Execute(context.Background(), Request{
		ObjectID: "session-1", CommandID: "dispatch-1", Command: command,
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	current, receipts, barriers := storage.snapshot()
	if current.Value != 1 || receipts != 1 || barriers != 1 {
		t.Fatalf("durable state = %#v, receipts=%d barriers=%d", current, receipts, barriers)
	}
	if !result.Durable || result.Replayed || len(result.Permits) != 1 || sealer.count() != 1 {
		t.Fatalf("result = %#v, seal count = %d", result, sealer.count())
	}
	claims, err := codec.Open(result.Permits[0], PermitBinding{
		ObjectID: "session-1", CommandID: "dispatch-1", CommandDigest: result.CommandDigest, ClaimIndex: 0,
	})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if claims.Kind != "dispatch" || string(claims.Payload) != "generation-bound-claims" {
		t.Fatalf("opened claims = %#v", claims)
	}
}

func TestHostCrashMatrixHasDeterministicIdempotentRecovery(t *testing.T) {
	t.Parallel()
	for _, point := range []FaultPoint{
		FaultBeforeCommit,
		FaultAfterCommit,
		FaultBeforeBarrier,
		FaultAfterBarrier,
		FaultBeforeResponse,
	} {
		point := point
		t.Run(string(point), func(t *testing.T) {
			t.Parallel()
			storage := newMemoryStorage("session-fault", mustJSON(t, counterState{Generation: 3}))
			aggregate := &counterAggregate{}
			codec := mustPermitCodec(t)
			sealer := &recordingSealer{codec: codec, storage: storage}
			fault := &faultOnce{target: point}
			host := mustHost(t, Config{Storage: storage, Aggregate: aggregate, Sealer: sealer, FaultInjector: fault})
			request := Request{
				ObjectID: "session-fault", CommandID: "same-command",
				Command: mustJSON(t, counterCommand{Delta: 1, Generation: 3, IssuePermit: true}),
			}

			first, err := host.Execute(context.Background(), request)
			if !errors.Is(err, errCrashInjected) {
				t.Fatalf("first Execute() error = %v, want injected crash", err)
			}
			if first.Durable || len(first.Permits) != 0 {
				t.Fatalf("failed call leaked result: %#v", first)
			}
			stateAfterCrash, receiptsAfterCrash, barriersAfterCrash := storage.snapshot()
			if point == FaultBeforeCommit {
				if stateAfterCrash.Value != 0 || receiptsAfterCrash != 0 {
					t.Fatalf("before-commit crash persisted state=%#v receipts=%d", stateAfterCrash, receiptsAfterCrash)
				}
			} else if stateAfterCrash.Value != 1 || receiptsAfterCrash != 1 {
				t.Fatalf("post-commit crash lost atomic mutation: state=%#v receipts=%d", stateAfterCrash, receiptsAfterCrash)
			}
			if point == FaultAfterBarrier || point == FaultBeforeResponse {
				if barriersAfterCrash != 1 {
					t.Fatalf("barriers after %s = %d, want 1", point, barriersAfterCrash)
				}
			} else if barriersAfterCrash != 0 {
				t.Fatalf("barriers after %s = %d, want 0", point, barriersAfterCrash)
			}
			if point == FaultBeforeResponse {
				if sealer.count() != 1 {
					t.Fatalf("seal count after before-response crash = %d, want 1", sealer.count())
				}
			} else if sealer.count() != 0 {
				t.Fatalf("seal count after %s = %d, want 0", point, sealer.count())
			}

			recoverySealer := &recordingSealer{codec: codec, storage: storage}
			restartedHost := mustHost(t, Config{Storage: storage, Aggregate: aggregate, Sealer: recoverySealer})
			recovered, err := restartedHost.Execute(context.Background(), request)
			if err != nil {
				t.Fatalf("retry Execute() error = %v", err)
			}
			wantReplay := point != FaultBeforeCommit
			if recovered.Replayed != wantReplay || !recovered.Durable || len(recovered.Permits) != 1 {
				t.Fatalf("recovered result = %#v, want replay=%t", recovered, wantReplay)
			}
			current, receiptCount, _ := storage.snapshot()
			if current.Value != 1 || receiptCount != 1 {
				t.Fatalf("recovered state=%#v receipts=%d", current, receiptCount)
			}
			wantApplyCalls := int64(1)
			if point == FaultBeforeCommit {
				wantApplyCalls = 2
			}
			if aggregate.applyCalls.Load() != wantApplyCalls {
				t.Fatalf("Apply calls = %d, want %d", aggregate.applyCalls.Load(), wantApplyCalls)
			}
			if point == FaultBeforeResponse && !bytes.Equal(sealer.token(0), recoverySealer.token(0)) {
				t.Fatal("response-loss replay minted different opaque permit bytes")
			}
		})
	}
}

func TestHostFailsClosedWhenDurabilityBarrierFails(t *testing.T) {
	t.Parallel()
	barrierFailure := errors.New("test: fsync failed")
	storage := newMemoryStorage("session-barrier", mustJSON(t, counterState{Generation: 9}))
	storage.barrierErr = barrierFailure
	aggregate := &counterAggregate{}
	sealer := &recordingSealer{codec: mustPermitCodec(t), storage: storage}
	host := mustHost(t, Config{Storage: storage, Aggregate: aggregate, Sealer: sealer})

	result, err := host.Execute(context.Background(), Request{
		ObjectID: "session-barrier", CommandID: "dispatch-barrier",
		Command: mustJSON(t, counterCommand{Delta: 1, Generation: 9, IssuePermit: true}),
	})
	if !errors.Is(err, ErrDurabilityBarrier) || !errors.Is(err, barrierFailure) {
		t.Fatalf("Execute() error = %v, want barrier and backend failures", err)
	}
	if result.Durable || len(result.Permits) != 0 || sealer.count() != 0 {
		t.Fatalf("barrier failure leaked result=%#v seals=%d", result, sealer.count())
	}
	current, receipts, barriers := storage.snapshot()
	if current.Value != 1 || receipts != 1 || barriers != 0 {
		t.Fatalf("logical commit state=%#v receipts=%d barriers=%d", current, receipts, barriers)
	}
	storage.mu.Lock()
	storage.barrierErr = nil
	storage.mu.Unlock()
	recovered, err := host.Execute(context.Background(), Request{
		ObjectID: "session-barrier", CommandID: "dispatch-barrier",
		Command: mustJSON(t, counterCommand{Delta: 1, Generation: 9, IssuePermit: true}),
	})
	if err != nil || !recovered.Replayed || !recovered.Durable || len(recovered.Permits) != 1 {
		t.Fatalf("barrier recovery = %#v, %v", recovered, err)
	}
	if aggregate.applyCalls.Load() != 1 {
		t.Fatalf("barrier recovery called Apply %d times", aggregate.applyCalls.Load())
	}
}

func TestHostSerializesConcurrentSameCommand(t *testing.T) {
	t.Parallel()
	storage := newMemoryStorage("session-concurrent", mustJSON(t, counterState{Generation: 11}))
	aggregate := &counterAggregate{}
	codec := mustPermitCodec(t)
	sealer := &recordingSealer{codec: codec, storage: storage}
	host := mustHost(t, Config{Storage: storage, Aggregate: aggregate, Sealer: sealer})
	request := Request{
		ObjectID: "session-concurrent", CommandID: "one-command",
		Command: mustJSON(t, counterCommand{Delta: 1, Generation: 11, IssuePermit: true}),
	}

	const callers = 64
	results := make(chan Result, callers)
	errorsSeen := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := host.Execute(context.Background(), request)
			results <- result
			errorsSeen <- err
		}()
	}
	wait.Wait()
	close(results)
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatalf("concurrent Execute() error = %v", err)
		}
	}
	var firstToken []byte
	fresh := 0
	for result := range results {
		if !result.Replayed {
			fresh++
		}
		if !result.Durable || len(result.Permits) != 1 {
			t.Fatalf("concurrent result = %#v", result)
		}
		token, _ := result.Permits[0].MarshalBinary()
		if firstToken == nil {
			firstToken = token
		} else if !bytes.Equal(firstToken, token) {
			t.Fatal("same-command calls received different permit bytes")
		}
	}
	current, receiptCount, barriers := storage.snapshot()
	if current.Value != 1 || receiptCount != 1 || aggregate.applyCalls.Load() != 1 || fresh != 1 {
		t.Fatalf("state=%#v receipts=%d apply=%d fresh=%d", current, receiptCount, aggregate.applyCalls.Load(), fresh)
	}
	if barriers != callers {
		t.Fatalf("barriers = %d, want %d", barriers, callers)
	}
}

func TestHostRevalidatesCurrentCapabilityBeforeReceiptReplay(t *testing.T) {
	t.Parallel()
	storage := newMemoryStorage("session-stale", mustJSON(t, counterState{Generation: 5}))
	aggregate := &counterAggregate{}
	codec := mustPermitCodec(t)
	host := mustHost(t, Config{Storage: storage, Aggregate: aggregate, Sealer: codec})
	request := Request{
		ObjectID: "session-stale", CommandID: "dispatch-once",
		Command: mustJSON(t, counterCommand{Delta: 1, Generation: 5, IssuePermit: true}),
	}
	if _, err := host.Execute(context.Background(), request); err != nil {
		t.Fatalf("first Execute() error = %v", err)
	}
	storage.forceState(counterState{Value: 1, Generation: 6})

	result, err := host.Execute(context.Background(), request)
	if !errors.Is(err, errStaleAuthority) {
		t.Fatalf("stale replay error = %v, want %v", err, errStaleAuthority)
	}
	if result.Durable || len(result.Permits) != 0 {
		t.Fatalf("stale replay leaked result: %#v", result)
	}
	if aggregate.applyCalls.Load() != 1 {
		t.Fatalf("stale replay called Apply %d times", aggregate.applyCalls.Load())
	}
}

func TestHostDefensivelyCopiesAggregateAndPermitBytes(t *testing.T) {
	t.Parallel()
	nextState := mustJSON(t, counterState{Value: 1, Generation: 4})
	response := []byte(`{"value":1}`)
	claimPayload := []byte("original-claims")
	aggregate := &counterAggregate{
		nextStateOverride: nextState,
		responseOverride:  response,
		claimsOverride:    []RawCapabilityClaims{{Kind: "dispatch", Payload: claimPayload}},
	}
	storage := newMemoryStorage("session-copies", mustJSON(t, counterState{Generation: 4}))
	codec := mustPermitCodec(t)
	host := mustHost(t, Config{Storage: storage, Aggregate: aggregate, Sealer: codec})
	request := Request{ObjectID: "session-copies", CommandID: "copy-command", Command: mustJSON(t, counterCommand{Delta: 1, Generation: 4})}

	first, err := host.Execute(context.Background(), request)
	if err != nil {
		t.Fatalf("first Execute() error = %v", err)
	}
	firstToken, _ := first.Permits[0].MarshalBinary()
	nextState[0] = 'x'
	response[0] = 'x'
	claimPayload[0] = 'x'
	first.Response[0] = 'x'
	firstToken[0] ^= 0xff

	replayed, err := host.Execute(context.Background(), request)
	if err != nil {
		t.Fatalf("replay Execute() error = %v", err)
	}
	if string(replayed.Response) != `{"value":1}` {
		t.Fatalf("replayed response = %q", replayed.Response)
	}
	claims, err := codec.Open(replayed.Permits[0], PermitBinding{
		ObjectID: "session-copies", CommandID: "copy-command", CommandDigest: replayed.CommandDigest, ClaimIndex: 0,
	})
	if err != nil || string(claims.Payload) != "original-claims" {
		t.Fatalf("replayed claims = %#v, %v", claims, err)
	}
}

func TestHostRejectsIdempotencyKeyReuseWithDifferentCommand(t *testing.T) {
	t.Parallel()
	storage := newMemoryStorage("session-conflict", mustJSON(t, counterState{Generation: 2}))
	aggregate := &counterAggregate{}
	host := mustHost(t, Config{Storage: storage, Aggregate: aggregate, Sealer: mustPermitCodec(t)})
	first := Request{ObjectID: "session-conflict", CommandID: "same-id", Command: mustJSON(t, counterCommand{Delta: 1, Generation: 2})}
	if _, err := host.Execute(context.Background(), first); err != nil {
		t.Fatalf("first Execute() error = %v", err)
	}
	second := first
	second.Command = mustJSON(t, counterCommand{Delta: 2, Generation: 2})
	if _, err := host.Execute(context.Background(), second); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflicting Execute() error = %v, want %v", err, ErrIdempotencyConflict)
	}
	current, receipts, _ := storage.snapshot()
	if current.Value != 1 || receipts != 1 || aggregate.applyCalls.Load() != 1 {
		t.Fatalf("conflict mutated state=%#v receipts=%d apply=%d", current, receipts, aggregate.applyCalls.Load())
	}
}

func TestHostPropagatesShapeAndSizeFailuresWithoutPartialMutation(t *testing.T) {
	t.Parallel()
	t.Run("command shape", func(t *testing.T) {
		storage := newMemoryStorage("shape-command", mustJSON(t, counterState{Generation: 1}))
		host := mustHost(t, Config{Storage: storage, Aggregate: &counterAggregate{}, Sealer: mustPermitCodec(t)})
		_, err := host.Execute(context.Background(), Request{ObjectID: "shape-command", CommandID: "bad", Command: []byte(`{"delta":1,"generation":1,"unknown":true}`)})
		if !errors.Is(err, errBadCommand) {
			t.Fatalf("shape error = %v, want %v", err, errBadCommand)
		}
		assertUnchanged(t, storage)
	})

	t.Run("stored state shape", func(t *testing.T) {
		storage := newMemoryStorage("shape-state", []byte(`{"value":0,"generation":1,"unknown":true}`))
		host := mustHost(t, Config{Storage: storage, Aggregate: &counterAggregate{}, Sealer: mustPermitCodec(t)})
		_, err := host.Execute(context.Background(), Request{ObjectID: "shape-state", CommandID: "bad", Command: mustJSON(t, counterCommand{Delta: 1, Generation: 1})})
		if !errors.Is(err, errBadState) {
			t.Fatalf("state shape error = %v, want %v", err, errBadState)
		}
		_, receipts, _ := storage.snapshot()
		if receipts != 0 {
			t.Fatalf("state shape failure stored %d receipts", receipts)
		}
	})

	t.Run("command size", func(t *testing.T) {
		storage := newMemoryStorage("size-command", mustJSON(t, counterState{Generation: 1}))
		host := mustHost(t, Config{
			Storage: storage, Aggregate: &counterAggregate{}, Sealer: mustPermitCodec(t),
			Limits: Limits{MaxCommandBytes: 4, MaxStateBytes: 1024, MaxResponseBytes: 1024, MaxCapabilityClaims: 4, MaxCapabilityClaimBytes: 1024},
		})
		_, err := host.Execute(context.Background(), Request{ObjectID: "size-command", CommandID: "large", Command: []byte("12345")})
		if !errors.Is(err, ErrCommandTooLarge) {
			t.Fatalf("command size error = %v, want %v", err, ErrCommandTooLarge)
		}
		assertUnchanged(t, storage)
	})

	t.Run("next state size", func(t *testing.T) {
		storage := newMemoryStorage("size-state", mustJSON(t, counterState{Generation: 1}))
		aggregate := &counterAggregate{nextStateOverride: bytes.Repeat([]byte("x"), 129)}
		host := mustHost(t, Config{
			Storage: storage, Aggregate: aggregate, Sealer: mustPermitCodec(t),
			Limits: Limits{MaxCommandBytes: 1024, MaxStateBytes: 128, MaxResponseBytes: 1024, MaxCapabilityClaims: 4, MaxCapabilityClaimBytes: 1024},
		})
		_, err := host.Execute(context.Background(), Request{ObjectID: "size-state", CommandID: "large", Command: mustJSON(t, counterCommand{Delta: 1, Generation: 1})})
		if !errors.Is(err, ErrStateTooLarge) {
			t.Fatalf("state size error = %v, want %v", err, ErrStateTooLarge)
		}
		assertUnchanged(t, storage)
	})

	t.Run("next state shape", func(t *testing.T) {
		storage := newMemoryStorage("shape-next-state", mustJSON(t, counterState{Generation: 1}))
		aggregate := &counterAggregate{nextStateOverride: []byte(`{"value":1,"generation":1,"unknown":true}`)}
		host := mustHost(t, Config{Storage: storage, Aggregate: aggregate, Sealer: mustPermitCodec(t)})
		_, err := host.Execute(context.Background(), Request{ObjectID: "shape-next-state", CommandID: "bad", Command: mustJSON(t, counterCommand{Delta: 1, Generation: 1})})
		if !errors.Is(err, errBadState) {
			t.Fatalf("next state shape error = %v, want %v", err, errBadState)
		}
		assertUnchanged(t, storage)
	})

	t.Run("response size", func(t *testing.T) {
		storage := newMemoryStorage("size-response", mustJSON(t, counterState{Generation: 1}))
		aggregate := &counterAggregate{responseOverride: bytes.Repeat([]byte("r"), 65)}
		host := mustHost(t, Config{
			Storage: storage, Aggregate: aggregate, Sealer: mustPermitCodec(t),
			Limits: Limits{MaxCommandBytes: 1024, MaxStateBytes: 1024, MaxResponseBytes: 64, MaxCapabilityClaims: 4, MaxCapabilityClaimBytes: 1024},
		})
		_, err := host.Execute(context.Background(), Request{ObjectID: "size-response", CommandID: "large", Command: mustJSON(t, counterCommand{Delta: 1, Generation: 1})})
		if !errors.Is(err, ErrResponseTooLarge) {
			t.Fatalf("response size error = %v, want %v", err, ErrResponseTooLarge)
		}
		assertUnchanged(t, storage)
	})

	t.Run("claim size", func(t *testing.T) {
		storage := newMemoryStorage("size-claim", mustJSON(t, counterState{Generation: 1}))
		aggregate := &counterAggregate{claimsOverride: []RawCapabilityClaims{{Kind: "dispatch", Payload: bytes.Repeat([]byte("c"), 65)}}}
		host := mustHost(t, Config{
			Storage: storage, Aggregate: aggregate, Sealer: mustPermitCodec(t),
			Limits: Limits{MaxCommandBytes: 1024, MaxStateBytes: 1024, MaxResponseBytes: 1024, MaxCapabilityClaims: 4, MaxCapabilityClaimBytes: 64},
		})
		_, err := host.Execute(context.Background(), Request{ObjectID: "size-claim", CommandID: "large", Command: mustJSON(t, counterCommand{Delta: 1, Generation: 1})})
		if !errors.Is(err, ErrCapabilityClaimsTooLarge) {
			t.Fatalf("claim size error = %v, want %v", err, ErrCapabilityClaimsTooLarge)
		}
		assertUnchanged(t, storage)
	})
}

func TestPermitCodecRejectsTamperingAndWrongBinding(t *testing.T) {
	t.Parallel()
	codec := mustPermitCodec(t)
	digest := Digest{1, 2, 3}
	binding := PermitBinding{ObjectID: "session-codec", CommandID: "command-codec", CommandDigest: digest, ClaimIndex: 4}
	claims := RawCapabilityClaims{Kind: "dispatch", Payload: []byte("secret-claims")}
	permit, err := codec.Seal(context.Background(), binding, claims)
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	encoded, err := permit.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	encoded[len(encoded)/2] ^= 0xff
	tampered, err := ParseSealedPermit(encoded)
	if err != nil {
		t.Fatalf("ParseSealedPermit() error = %v", err)
	}
	if _, err := codec.Open(tampered, binding); !errors.Is(err, ErrInvalidPermit) {
		t.Fatalf("tampered Open() error = %v, want %v", err, ErrInvalidPermit)
	}
	wrong := binding
	wrong.ClaimIndex++
	if _, err := codec.Open(permit, wrong); !errors.Is(err, ErrInvalidPermit) {
		t.Fatalf("wrong-binding Open() error = %v, want %v", err, ErrInvalidPermit)
	}
	if fmt.Sprint(permit) != "sealed-permit<redacted>" || fmt.Sprintf("%#v", permit) != "sealed-permit<redacted>" {
		t.Fatalf("permit formatting was not redacted: %s %#v", permit, permit)
	}
}

func mustHost(t *testing.T, config Config) *Host {
	t.Helper()
	host, err := NewHost(config)
	if err != nil {
		t.Fatalf("NewHost() error = %v", err)
	}
	return host
}

func mustPermitCodec(t *testing.T) *PermitCodec {
	t.Helper()
	codec, err := NewPermitCodec(bytes.Repeat([]byte{0xa5}, 32))
	if err != nil {
		t.Fatalf("NewPermitCodec() error = %v", err)
	}
	return codec
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return encoded
}

func assertUnchanged(t *testing.T, storage *memoryStorage) {
	t.Helper()
	state, receipts, barriers := storage.snapshot()
	if state.Value != 0 || receipts != 0 || barriers != 0 {
		t.Fatalf("failure changed state=%#v receipts=%d barriers=%d", state, receipts, barriers)
	}
}

func cloneStoredReceipts(source map[string]StoredReceipt) map[string]StoredReceipt {
	cloned := make(map[string]StoredReceipt, len(source))
	for key, receipt := range source {
		cloned[key] = cloneStoredReceipt(receipt)
	}
	return cloned
}

func cloneStoredReceipt(receipt StoredReceipt) StoredReceipt {
	receipt.Response = append([]byte(nil), receipt.Response...)
	receipt.CapabilityClaims = cloneRawClaims(receipt.CapabilityClaims)
	return receipt
}

func cloneRawClaims(claims []RawCapabilityClaims) []RawCapabilityClaims {
	cloned := make([]RawCapabilityClaims, len(claims))
	for index, claim := range claims {
		cloned[index] = RawCapabilityClaims{Kind: claim.Kind, Payload: append([]byte(nil), claim.Payload...)}
	}
	return cloned
}
