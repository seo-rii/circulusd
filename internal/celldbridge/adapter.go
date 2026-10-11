package celldbridge

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"reflect"
	"slices"
	"sort"
	"sync"

	"github.com/hancomac/circulusd/internal/celld"
	"github.com/hancomac/circulusd/internal/dependency"
)

type Config struct {
	Transport            dependency.Verified[NativeTransport]
	Bounds               Bounds
	MaximumAttempts      int
	RequiredAtomicGroups []dependency.AtomicGroup
}

func (Config) String() string   { return "native-storage-config<redacted>" }
func (Config) GoString() string { return "native-storage-config<redacted>" }

// Storage translates pure callbacks to native snapshot/CAS operations. It owns
// no durable state, commit registry, runtime signing key, or fallback store.
// Consumers qualify this exact adapter again through its retained native probe.
type Storage struct {
	transport       NativeTransport
	binding         dependency.Verified[NativeTransport]
	bounds          Bounds
	maximumAttempts int
}

func (*Storage) String() string   { return "qualified-native-storage<redacted>" }
func (*Storage) GoString() string { return "qualified-native-storage<redacted>" }

func ValidateBounds(b Bounds) error {
	for _, pair := range [][2]int{{b.MaxStateBytes, MaximumStateBytes}, {b.MaxReceiptResponseBytes, MaximumReceiptResponseBytes},
		{b.MaxCapabilityClaims, MaximumCapabilityClaims}, {b.MaxCapabilityClaimBytes, MaximumCapabilityClaimBytes},
		{b.MaxReceiptLookups, MaximumReceiptLookups}, {b.MaxReceiptWrites, MaximumReceiptWrites}, {b.MaxTransactionBytes, MaximumTransactionBytes}} {
		if pair[0] <= 0 || pair[0] > pair[1] {
			return ErrInvalidConfig
		}
	}
	return nil
}

func New(config Config) (*Storage, error) {
	transport, descriptor, err := config.Transport.Open()
	if err != nil || nilValue(transport) {
		return nil, dependency.ErrUnverifiedDependency
	}
	if ValidateBounds(config.Bounds) != nil || config.MaximumAttempts <= 0 || config.MaximumAttempts > MaximumAttempts {
		return nil, ErrInvalidConfig
	}
	if len(config.RequiredAtomicGroups) > 64 {
		return nil, ErrInvalidConfig
	}
	groups := append([]dependency.AtomicGroup{AtomicNativeStorage, dependency.AtomicCommandReceipt}, config.RequiredAtomicGroups...)
	slices.Sort(groups)
	groups = slices.Compact(groups)
	for _, group := range groups {
		if !slices.Contains(descriptor.AtomicGroups, group) {
			return nil, dependency.ErrRequirementMismatch
		}
	}
	return &Storage{transport: transport, binding: config.Transport, bounds: config.Bounds, maximumAttempts: config.MaximumAttempts}, nil
}

func (s *Storage) ready(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || nilValue(s.transport) {
		return dependency.ErrUnverifiedDependency
	}
	_, _, err := s.binding.Open()
	return err
}

func (s *Storage) ProbeProduction(ctx context.Context, c dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	if err := s.ready(ctx); err != nil {
		return dependency.ProbeResponse{}, err
	}
	if len(c.Nonce) != dependency.ChallengeBytes {
		return dependency.ProbeResponse{}, ErrInvalidRequest
	}
	_, descriptor, err := s.binding.Open()
	if err != nil {
		return dependency.ProbeResponse{}, dependency.ErrUnverifiedDependency
	}
	response, err := s.transport.ProbeProduction(ctx, dependency.ProbeChallenge{Nonce: bytes.Clone(c.Nonce)})
	if err != nil {
		return dependency.ProbeResponse{}, nativeError(ctx, err)
	}
	if err = ctx.Err(); err != nil {
		return dependency.ProbeResponse{}, err
	}
	if len(response.Signature) != ed25519.SignatureSize || response.KeyID != descriptor.RuntimeKeyID || !sameDescriptor(response.Descriptor, descriptor) {
		return dependency.ProbeResponse{}, ErrInvalidResponse
	}
	response.Signature = bytes.Clone(response.Signature)
	response.Descriptor.AtomicGroups = slices.Clone(response.Descriptor.AtomicGroups)
	return response, nil
}

func sameDescriptor(actual, expected dependency.Descriptor) bool {
	return reflect.DeepEqual(actual, expected)
}

// Transaction retries only a definite snapshot conflict. All callback writes
// remain owned and staged until a successful callback closes its transaction.
// An ambiguous native commit response is never replayed internally; a caller's
// later command retry must recover through the native immutable receipt.
func (s *Storage) Transaction(ctx context.Context, objectID string, callback func(celld.Transaction) error) (celld.CommitToken, error) {
	if err := s.ready(ctx); err != nil {
		return celld.CommitToken{}, err
	}
	if !validIdentifier(objectID) || callback == nil {
		return celld.CommitToken{}, ErrInvalidRequest
	}
	for attempt := 0; attempt < s.maximumAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return celld.CommitToken{}, err
		}
		snapshot, err := s.transport.ReadSnapshot(ctx, SnapshotRequest{ObjectID: objectID})
		if err != nil {
			if ctx.Err() != nil {
				return celld.CommitToken{}, ctx.Err()
			}
			if errors.Is(err, ErrSnapshotConflict) {
				continue
			}
			return celld.CommitToken{}, nativeError(ctx, err)
		}
		if err := ctx.Err(); err != nil {
			return celld.CommitToken{}, err
		}
		if !validSnapshot(snapshot, objectID, s.bounds) {
			return celld.CommitToken{}, ErrInvalidResponse
		}
		tx := &transaction{ctx: ctx, transport: s.transport, bounds: s.bounds, snapshot: snapshot.SnapshotRef,
			state: bytes.Clone(snapshot.State), reads: map[string]receiptRead{}, writes: map[string]celld.StoredReceipt{}, footprint: len(snapshot.State)}
		callbackErr := runCallback(tx, callback)
		if err = ctx.Err(); err != nil {
			return celld.CommitToken{}, err
		}
		if tx.err != nil {
			if errors.Is(tx.err, ErrSnapshotConflict) {
				continue
			}
			return celld.CommitToken{}, tx.err
		}
		if callbackErr != nil {
			return celld.CommitToken{}, callbackErr
		}
		request := tx.commitRequest()
		request.RequestDigest, err = CommitDigest(request)
		if err != nil {
			return celld.CommitToken{}, ErrInvalidRequest
		}
		if err = ctx.Err(); err != nil {
			return celld.CommitToken{}, err
		}
		result, err := s.transport.CompareAndCommit(ctx, request)
		if err != nil {
			if ctx.Err() != nil {
				return celld.CommitToken{}, ctx.Err()
			}
			if errors.Is(err, ErrSnapshotConflict) {
				continue
			}
			return celld.CommitToken{}, nativeError(ctx, err)
		}
		if err = ctx.Err(); err != nil {
			return celld.CommitToken{}, err
		}
		expectedDigest := snapshot.StateDigest
		if tx.stateWritten {
			expectedDigest = celld.Digest(sha256.Sum256(tx.stagedState))
		}
		if result.Snapshot != (SnapshotRef{ObjectID: objectID, Exists: true, Revision: snapshot.Revision + 1, StateDigest: expectedDigest}) ||
			result.RequestDigest != request.RequestDigest || result.Token != (celld.CommitToken{ObjectID: objectID, Revision: snapshot.Revision + 1}) {
			return celld.CommitToken{}, ErrInvalidResponse
		}
		return result.Token, nil
	}
	return celld.CommitToken{}, ErrSnapshotConflict
}

func runCallback(tx *transaction, callback func(celld.Transaction) error) error {
	defer func() { tx.mu.Lock(); tx.closed = true; tx.mu.Unlock() }()
	return callback(tx)
}

func (s *Storage) DurabilityBarrier(ctx context.Context, token celld.CommitToken) error {
	if err := s.ready(ctx); err != nil {
		return err
	}
	if !validIdentifier(token.ObjectID) || token.Revision == 0 || token.Revision > MaximumRevision {
		return ErrInvalidRequest
	}
	request := BarrierRequest{Token: token}
	if _, err := rand.Read(request.Marker[:]); err != nil {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	response, err := s.transport.ConfirmBarrier(ctx, request)
	if err != nil {
		return nativeError(ctx, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if response.Token != token || response.Marker != request.Marker || response.ObservedRevision < token.Revision ||
		response.ObservedRevision > MaximumRevision || response.BarrierSerial == 0 || response.BarrierSerial > MaximumRevision {
		return ErrInvalidResponse
	}
	return nil
}

type receiptRead struct {
	receipt celld.StoredReceipt
	found   bool
}
type transaction struct {
	mu                   sync.Mutex
	ctx                  context.Context
	transport            NativeTransport
	bounds               Bounds
	snapshot             SnapshotRef
	state, stagedState   []byte
	stateWritten, closed bool
	reads                map[string]receiptRead
	writes               map[string]celld.StoredReceipt
	footprint            int
	err                  error
}

func (tx *transaction) ready() error {
	if tx.closed {
		return celld.ErrStorageContract
	}
	if err := tx.ctx.Err(); err != nil {
		return err
	}
	return tx.err
}
func (tx *transaction) fail(err error) error {
	if tx.err == nil {
		tx.err = err
	}
	return err
}
func (tx *transaction) ReadState() ([]byte, error) {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	if err := tx.ready(); err != nil {
		return nil, err
	}
	if tx.stateWritten {
		return bytes.Clone(tx.stagedState), nil
	}
	return bytes.Clone(tx.state), nil
}
func (tx *transaction) LookupReceipt(id string) (celld.StoredReceipt, bool, error) {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	if err := tx.ready(); err != nil {
		return celld.StoredReceipt{}, false, err
	}
	if !validIdentifier(id) {
		return celld.StoredReceipt{}, false, tx.fail(ErrInvalidRequest)
	}
	if receipt, ok := tx.writes[id]; ok {
		return cloneReceipt(receipt), true, nil
	}
	read, err := tx.lookup(id)
	if err != nil {
		return celld.StoredReceipt{}, false, err
	}
	return cloneReceipt(read.receipt), read.found, nil
}
func (tx *transaction) lookup(id string) (receiptRead, error) {
	if read, ok := tx.reads[id]; ok {
		return read, nil
	}
	if len(tx.reads) >= tx.bounds.MaxReceiptLookups {
		return receiptRead{}, tx.fail(ErrInvalidRequest)
	}
	response, err := tx.transport.ReadReceipt(tx.ctx, ReceiptRequest{Snapshot: tx.snapshot, CommandID: id})
	if err != nil {
		return receiptRead{}, tx.fail(nativeError(tx.ctx, err))
	}
	if err = tx.ctx.Err(); err != nil {
		return receiptRead{}, tx.fail(err)
	}
	if response.Snapshot != tx.snapshot || response.CommandID != id {
		return receiptRead{}, tx.fail(ErrInvalidResponse)
	}
	if !response.Found && (response.Receipt.CommandDigest != (celld.Digest{}) || len(response.Receipt.Response) != 0 || len(response.Receipt.CapabilityClaims) != 0) {
		return receiptRead{}, tx.fail(ErrInvalidResponse)
	}
	size := len(id)
	if response.Found {
		if err = validateReceipt(response.Receipt, tx.bounds); err != nil {
			return receiptRead{}, tx.fail(ErrInvalidResponse)
		}
		size += receiptSize(response.Receipt)
	}
	if size > tx.bounds.MaxTransactionBytes-tx.footprint {
		return receiptRead{}, tx.fail(ErrInvalidResponse)
	}
	read := receiptRead{receipt: cloneReceipt(response.Receipt), found: response.Found}
	tx.reads[id] = read
	tx.footprint += size
	return read, nil
}
func (tx *transaction) WriteState(state []byte) error {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	if err := tx.ready(); err != nil {
		return err
	}
	if len(state) > tx.bounds.MaxStateBytes {
		return tx.fail(celld.ErrStateTooLarge)
	}
	current := 0
	if tx.stateWritten {
		current = len(tx.stagedState)
	}
	if len(state) > tx.bounds.MaxTransactionBytes-(tx.footprint-current) {
		return tx.fail(celld.ErrStateTooLarge)
	}
	tx.footprint += len(state) - current
	tx.stagedState = bytes.Clone(state)
	tx.stateWritten = true
	return nil
}
func (tx *transaction) WriteReceipt(id string, receipt celld.StoredReceipt) error {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	if err := tx.ready(); err != nil {
		return err
	}
	if !validIdentifier(id) {
		return tx.fail(ErrInvalidRequest)
	}
	if err := validateReceipt(receipt, tx.bounds); err != nil {
		return tx.fail(err)
	}
	if staged, ok := tx.writes[id]; ok {
		if !sameReceipt(staged, receipt) {
			return tx.fail(celld.ErrIdempotencyConflict)
		}
		return nil
	}
	read, err := tx.lookup(id)
	if err != nil {
		return err
	}
	if read.found {
		if !sameReceipt(read.receipt, receipt) {
			return tx.fail(celld.ErrIdempotencyConflict)
		}
		return nil
	}
	if len(tx.writes) >= tx.bounds.MaxReceiptWrites {
		return tx.fail(ErrInvalidRequest)
	}
	size := len(id) + receiptSize(receipt)
	if size > tx.bounds.MaxTransactionBytes-tx.footprint {
		return tx.fail(celld.ErrResponseTooLarge)
	}
	tx.writes[id] = cloneReceipt(receipt)
	tx.footprint += size
	return nil
}
func (tx *transaction) commitRequest() CommitRequest {
	request := CommitRequest{Snapshot: tx.snapshot, StateWritten: tx.stateWritten}
	if tx.stateWritten {
		request.State = bytes.Clone(tx.stagedState)
	}
	ids := make([]string, 0, len(tx.writes))
	for id := range tx.writes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		request.Receipts = append(request.Receipts, ReceiptWrite{CommandID: id, Receipt: cloneReceipt(tx.writes[id])})
	}
	return request
}
func validateReceipt(receipt celld.StoredReceipt, b Bounds) error {
	if len(receipt.Response) > b.MaxReceiptResponseBytes {
		return celld.ErrResponseTooLarge
	}
	if len(receipt.CapabilityClaims) > b.MaxCapabilityClaims {
		return celld.ErrCapabilityClaimsTooLarge
	}
	total := 0
	for _, claim := range receipt.CapabilityClaims {
		if !validIdentifier(claim.Kind) {
			return celld.ErrCorruptReceipt
		}
		if len(claim.Payload) > b.MaxCapabilityClaimBytes-total {
			return celld.ErrCapabilityClaimsTooLarge
		}
		total += len(claim.Payload)
	}
	return nil
}
func receiptSize(receipt celld.StoredReceipt) int {
	size := 32 + len(receipt.Response)
	for _, claim := range receipt.CapabilityClaims {
		size += len(claim.Kind) + len(claim.Payload)
	}
	return size
}
func cloneReceipt(receipt celld.StoredReceipt) celld.StoredReceipt {
	r := celld.StoredReceipt{CommandDigest: receipt.CommandDigest, Response: bytes.Clone(receipt.Response)}
	for _, claim := range receipt.CapabilityClaims {
		r.CapabilityClaims = append(r.CapabilityClaims, celld.RawCapabilityClaims{Kind: claim.Kind, Payload: bytes.Clone(claim.Payload)})
	}
	return r
}
func sameReceipt(a, b celld.StoredReceipt) bool {
	if a.CommandDigest != b.CommandDigest || !bytes.Equal(a.Response, b.Response) || len(a.CapabilityClaims) != len(b.CapabilityClaims) {
		return false
	}
	for i, claim := range a.CapabilityClaims {
		if claim.Kind != b.CapabilityClaims[i].Kind || !bytes.Equal(claim.Payload, b.CapabilityClaims[i].Payload) {
			return false
		}
	}
	return true
}
func validSnapshot(snapshot Snapshot, object string, b Bounds) bool {
	if snapshot.ObjectID != object || len(snapshot.State) > b.MaxStateBytes || len(snapshot.State) > b.MaxTransactionBytes || snapshot.Revision >= MaximumRevision ||
		celld.Digest(sha256.Sum256(snapshot.State)) != snapshot.StateDigest {
		return false
	}
	if !snapshot.Exists {
		return snapshot.Revision == 0 && len(snapshot.State) == 0
	}
	return snapshot.Revision > 0
}
func nilValue(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}
func nativeError(ctx context.Context, err error) error {
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	for _, safe := range []error{context.Canceled, context.DeadlineExceeded, ErrSnapshotConflict, ErrInvalidResponse, ErrUnauthenticatedResponse, ErrClosed, dependency.ErrUnverifiedDependency} {
		if errors.Is(err, safe) {
			return safe
		}
	}
	return ErrUnavailable
}

var _ celld.Storage = (*Storage)(nil)
var _ dependency.ProductionProbe = (*Storage)(nil)
