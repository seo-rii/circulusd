package celldbridge

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/auditcheckpoint"
	"github.com/hancomac/circulusd/internal/auth"
	"github.com/hancomac/circulusd/internal/authstate"
	"github.com/hancomac/circulusd/internal/celld"
	"github.com/hancomac/circulusd/internal/dependency"
	proof "github.com/hancomac/circulusd/internal/dependency/contracttest"
	"github.com/hancomac/circulusd/internal/identity"
)

// This native-operation fixture models CAS fault windows only. Its contract-test
// proofs and process memory never qualify an operational native storage driver.
type adapterObject struct {
	state                   []byte
	receipts                map[string]celld.StoredReceipt
	revision, barrierSerial uint64
}
type adapterNative struct {
	*proof.ProductionProofs
	mu                                                                 sync.Mutex
	objects                                                            map[string]adapterObject
	snapshotError, receiptError, commitError, barrierError, probeError error
	receiptConflicts, commitConflicts                                  int
	commitLost                                                         bool
	mutateSnapshot                                                     func(*Snapshot)
	mutateReceipt                                                      func(*ReceiptResult)
	mutateCommit                                                       func(*CommitResult)
	mutateBarrier                                                      func(*BarrierResult)
	mutateProbe                                                        func(*dependency.ProbeResponse)
	afterSnapshot, afterReceipt, afterCommit, afterBarrier             context.CancelFunc
	lastCommit                                                         CommitRequest
	markers                                                            [][32]byte
	snapshots, receipts, commits, barriers, probes                     atomic.Int32
}

var adapterDiagnostic = errors.New("native implementation secret diagnostic")

func (n *adapterNative) ProbeProduction(ctx context.Context, c dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	n.probes.Add(1)
	if n.probeError != nil {
		return dependency.ProbeResponse{}, n.probeError
	}
	result, err := n.ProductionProofs.ProbeProduction(ctx, c)
	if n.mutateProbe != nil {
		n.mutateProbe(&result)
	}
	return result, err
}
func (n *adapterNative) ref(object string) SnapshotRef {
	o, ok := n.objects[object]
	return SnapshotRef{ObjectID: object, Exists: ok, Revision: o.revision, StateDigest: celld.Digest(sha256.Sum256(o.state))}
}
func (n *adapterNative) ReadSnapshot(ctx context.Context, r SnapshotRequest) (Snapshot, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.snapshots.Add(1)
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	if n.snapshotError != nil {
		return Snapshot{}, n.snapshotError
	}
	result := Snapshot{SnapshotRef: n.ref(r.ObjectID), State: bytes.Clone(n.objects[r.ObjectID].state)}
	if n.mutateSnapshot != nil {
		n.mutateSnapshot(&result)
	}
	if n.afterSnapshot != nil {
		n.afterSnapshot()
	}
	return result, nil
}
func (n *adapterNative) ReadReceipt(ctx context.Context, r ReceiptRequest) (ReceiptResult, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.receipts.Add(1)
	if err := ctx.Err(); err != nil {
		return ReceiptResult{}, err
	}
	if n.receiptError != nil {
		return ReceiptResult{}, n.receiptError
	}
	if n.receiptConflicts > 0 {
		n.receiptConflicts--
		o := n.objects[r.Snapshot.ObjectID]
		o.revision++
		if o.receipts == nil {
			o.receipts = map[string]celld.StoredReceipt{}
		}
		n.objects[r.Snapshot.ObjectID] = o
		return ReceiptResult{}, ErrSnapshotConflict
	}
	if n.ref(r.Snapshot.ObjectID) != r.Snapshot {
		return ReceiptResult{}, ErrSnapshotConflict
	}
	receipt, found := n.objects[r.Snapshot.ObjectID].receipts[r.CommandID]
	result := ReceiptResult{Snapshot: r.Snapshot, CommandID: r.CommandID, Found: found, Receipt: cloneReceipt(receipt)}
	if n.mutateReceipt != nil {
		n.mutateReceipt(&result)
	}
	if n.afterReceipt != nil {
		n.afterReceipt()
	}
	return result, nil
}
func (n *adapterNative) CompareAndCommit(ctx context.Context, r CommitRequest) (CommitResult, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.commits.Add(1)
	if err := ctx.Err(); err != nil {
		return CommitResult{}, err
	}
	if n.commitError != nil {
		return CommitResult{}, n.commitError
	}
	if n.commitConflicts > 0 {
		n.commitConflicts--
		return CommitResult{}, ErrSnapshotConflict
	}
	if n.ref(r.Snapshot.ObjectID) != r.Snapshot {
		return CommitResult{}, ErrSnapshotConflict
	}
	digest, err := CommitDigest(r)
	if err != nil || digest != r.RequestDigest {
		return CommitResult{}, ErrInvalidRequest
	}
	o := n.objects[r.Snapshot.ObjectID]
	if o.receipts == nil {
		o.receipts = map[string]celld.StoredReceipt{}
	}
	for _, write := range r.Receipts {
		if old, ok := o.receipts[write.CommandID]; ok && !sameReceipt(old, write.Receipt) {
			return CommitResult{}, celld.ErrIdempotencyConflict
		}
	}
	if r.StateWritten {
		o.state = bytes.Clone(r.State)
	}
	for _, write := range r.Receipts {
		o.receipts[write.CommandID] = cloneReceipt(write.Receipt)
	}
	o.revision++
	n.objects[r.Snapshot.ObjectID] = o
	n.lastCommit = r
	result := CommitResult{Snapshot: n.ref(r.Snapshot.ObjectID), RequestDigest: r.RequestDigest, Token: celld.CommitToken{ObjectID: r.Snapshot.ObjectID, Revision: o.revision}}
	if n.mutateCommit != nil {
		n.mutateCommit(&result)
	}
	if n.afterCommit != nil {
		n.afterCommit()
	}
	if n.commitLost {
		return CommitResult{}, adapterDiagnostic
	}
	return result, nil
}
func (n *adapterNative) ConfirmBarrier(ctx context.Context, r BarrierRequest) (BarrierResult, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.barriers.Add(1)
	if err := ctx.Err(); err != nil {
		return BarrierResult{}, err
	}
	if n.barrierError != nil {
		return BarrierResult{}, n.barrierError
	}
	o, ok := n.objects[r.Token.ObjectID]
	if !ok || r.Token.Revision == 0 || r.Token.Revision > o.revision {
		return BarrierResult{}, ErrInvalidRequest
	}
	o.barrierSerial++
	n.objects[r.Token.ObjectID] = o
	n.markers = append(n.markers, r.Marker)
	result := BarrierResult{Token: r.Token, Marker: r.Marker, ObservedRevision: o.revision, BarrierSerial: o.barrierSerial}
	if n.mutateBarrier != nil {
		n.mutateBarrier(&result)
	}
	if n.afterBarrier != nil {
		n.afterBarrier()
	}
	return result, nil
}
func adapterBounds() Bounds {
	return Bounds{MaxStateBytes: 1 << 20, MaxReceiptResponseBytes: 1 << 16, MaxCapabilityClaims: 8, MaxCapabilityClaimBytes: 1 << 16, MaxReceiptLookups: 8, MaxReceiptWrites: 8, MaxTransactionBytes: 2 << 20}
}
func newAdapter(t *testing.T, extra ...dependency.AtomicGroup) (*adapterNative, Config, *Storage) {
	t.Helper()
	groups := append([]dependency.AtomicGroup{AtomicNativeStorage, dependency.AtomicCommandReceipt}, extra...)
	slices.Sort(groups)
	groups = slices.Compact(groups)
	p := proof.NewProductionProofs(t, groups)
	n := &adapterNative{ProductionProofs: p, objects: map[string]adapterObject{}}
	config := Config{Transport: proof.Verify[NativeTransport](t, p, n, groups), Bounds: adapterBounds(), MaximumAttempts: 4, RequiredAtomicGroups: slices.Clone(extra)}
	s, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	return n, config, s
}
func adapterReceipt(text string) celld.StoredReceipt {
	return celld.StoredReceipt{CommandDigest: celld.Digest(sha256.Sum256([]byte(text))), Response: []byte("response-" + text), CapabilityClaims: []celld.RawCapabilityClaims{{Kind: "test-capability", Payload: []byte("opaque-" + text)}}}
}

func TestAdapterStagesOwnedStateReceiptsAndCanonicalCommit(t *testing.T) {
	n, _, s := newAdapter(t)
	input := []byte("state")
	receipt := adapterReceipt("command")
	original := cloneReceipt(receipt)
	var retained celld.Transaction
	token, err := s.Transaction(context.Background(), "object:한글", func(tx celld.Transaction) error {
		retained = tx
		state, err := tx.ReadState()
		if err != nil || len(state) != 0 {
			t.Fatal(err)
		}
		if err = tx.WriteState(input); err != nil {
			return err
		}
		input[0] = 'X'
		state, err = tx.ReadState()
		if err != nil || string(state) != "state" {
			t.Fatal("state alias", err)
		}
		state[0] = 'Y'
		if err = tx.WriteReceipt("z", receipt); err != nil {
			return err
		}
		receipt.Response[0] = 'X'
		receipt.CapabilityClaims[0].Payload[0] = 'X'
		read, found, err := tx.LookupReceipt("z")
		if err != nil || !found || !sameReceipt(read, original) {
			t.Fatal("receipt alias", err)
		}
		read.Response[0] = 'Y'
		return tx.WriteReceipt("a", adapterReceipt("second"))
	})
	if err != nil || token != (celld.CommitToken{ObjectID: "object:한글", Revision: 1}) {
		t.Fatal(token, err)
	}
	if _, err = retained.ReadState(); err != celld.ErrStorageContract {
		t.Fatal("retained transaction remained open", err)
	}
	if err = retained.WriteState([]byte("late")); err != celld.ErrStorageContract {
		t.Fatal(err)
	}
	if len(n.lastCommit.Receipts) != 2 || n.lastCommit.Receipts[0].CommandID != "a" || n.lastCommit.Receipts[1].CommandID != "z" || string(n.lastCommit.State) != "state" {
		t.Fatal("commit order or state changed")
	}
	digest, err := CommitDigest(n.lastCommit)
	if err != nil || digest != n.lastCommit.RequestDigest {
		t.Fatal("canonical commit digest", err)
	}
	if err = s.DurabilityBarrier(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	if err = s.DurabilityBarrier(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	if n.markers[0] == n.markers[1] || n.markers[0] == ([32]byte{}) {
		t.Fatal("barrier marker did not change")
	}
	readToken, err := s.Transaction(context.Background(), token.ObjectID, func(tx celld.Transaction) error {
		state, err := tx.ReadState()
		if err != nil || string(state) != "state" {
			t.Fatal(err)
		}
		r, found, err := tx.LookupReceipt("z")
		if err != nil || !found || !sameReceipt(r, original) {
			t.Fatal(err)
		}
		return nil
	})
	if err != nil || readToken.Revision != 2 || n.lastCommit.StateWritten || len(n.lastCommit.Receipts) != 0 {
		t.Fatal("read-only native ack did not advance", err)
	}
	if err = s.DurabilityBarrier(context.Background(), token); err != nil {
		t.Fatal("historical barrier rejected", err)
	}
}

func TestAdapterRollbackCallbackErrorsAndPanic(t *testing.T) {
	n, _, s := newAdapter(t)
	semantic := errors.New("trusted semantic failure")
	token, err := s.Transaction(context.Background(), "rollback", func(tx celld.Transaction) error {
		if err := tx.WriteState([]byte("staged")); err != nil {
			return err
		}
		if err := tx.WriteReceipt("c", adapterReceipt("c")); err != nil {
			return err
		}
		return semantic
	})
	if err != semantic || token != (celld.CommitToken{}) || n.commits.Load() != 0 || len(n.objects) != 0 {
		t.Fatal("callback rollback failed", err)
	}
	var retained celld.Transaction
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("callback panic disappeared")
			}
		}()
		_, _ = s.Transaction(context.Background(), "panic", func(tx celld.Transaction) error {
			retained = tx
			_ = tx.WriteState([]byte("staged"))
			panic("trusted callback panic")
		})
	}()
	if n.commits.Load() != 0 {
		t.Fatal("panic committed")
	}
	if _, err = retained.ReadState(); err != celld.ErrStorageContract {
		t.Fatal("panic transaction not closed", err)
	}
}

func TestAdapterReceiptReplayIsImmutableAcrossAllBytes(t *testing.T) {
	for _, mode := range []string{"exact", "digest", "response", "claim-kind", "claim-payload", "claim-order", "staged-conflict"} {
		t.Run(mode, func(t *testing.T) {
			n, _, s := newAdapter(t)
			receipt := adapterReceipt("c")
			receipt.CapabilityClaims = append(receipt.CapabilityClaims, celld.RawCapabilityClaims{Kind: "other", Payload: []byte("other")})
			_, err := s.Transaction(context.Background(), "immutable", func(tx celld.Transaction) error { return tx.WriteReceipt("c", receipt) })
			if err != nil {
				t.Fatal(err)
			}
			changed := cloneReceipt(receipt)
			switch mode {
			case "digest":
				changed.CommandDigest[0] ^= 1
			case "response":
				changed.Response[0] ^= 1
			case "claim-kind":
				changed.CapabilityClaims[0].Kind += "-other"
			case "claim-payload":
				changed.CapabilityClaims[0].Payload[0] ^= 1
			case "claim-order":
				slices.Reverse(changed.CapabilityClaims)
			}
			commits := n.commits.Load()
			_, err = s.Transaction(context.Background(), "immutable", func(tx celld.Transaction) error {
				if mode == "staged-conflict" {
					if err := tx.WriteReceipt("new", receipt); err != nil {
						return err
					}
					changed.Response[0] ^= 1
					return tx.WriteReceipt("new", changed)
				}
				return tx.WriteReceipt("c", changed)
			})
			if mode == "exact" {
				if err != nil || len(n.lastCommit.Receipts) != 0 || n.commits.Load() != commits+1 {
					t.Fatal("immutable replay failed", err)
				}
			} else if err != celld.ErrIdempotencyConflict || n.commits.Load() != commits {
				t.Fatal("receipt replaced", err)
			}
		})
	}
}

func TestAdapterRetriesOnlyDefiniteConflictsIncludingSanitizedCallbackError(t *testing.T) {
	for _, mode := range []string{"receipt", "commit", "exhaustion"} {
		t.Run(mode, func(t *testing.T) {
			n, config, s := newAdapter(t)
			calls := 0
			if mode == "receipt" {
				n.receiptConflicts = 1
			} else if mode == "commit" {
				n.commitConflicts = 1
			} else {
				n.commitConflicts = config.MaximumAttempts + 1
			}
			token, err := s.Transaction(context.Background(), "conflict", func(tx celld.Transaction) error {
				calls++
				_, _, err := tx.LookupReceipt("c")
				if err != nil {
					return errors.New("callback deliberately sanitizes native error")
				}
				if err = tx.WriteState([]byte(strconv.Itoa(calls))); err != nil {
					return err
				}
				return tx.WriteReceipt("c", adapterReceipt("c"))
			})
			if mode == "exhaustion" {
				if err != ErrSnapshotConflict || calls != config.MaximumAttempts || token != (celld.CommitToken{}) {
					t.Fatal("retry exhaustion", err)
				}
				return
			}
			if err != nil || calls != 2 || string(n.objects["conflict"].state) != "2" {
				t.Fatal("definite conflict retry failed", err)
			}
		})
	}
	for _, mode := range []string{"commit error", "ambiguous commit"} {
		t.Run(mode, func(t *testing.T) {
			n, config, s := newAdapter(t)
			if mode == "commit error" {
				n.commitError = adapterDiagnostic
			} else {
				n.commitLost = true
			}
			calls := 0
			token, err := s.Transaction(context.Background(), "uncertain", func(tx celld.Transaction) error { calls++; return tx.WriteReceipt("c", adapterReceipt("c")) })
			if err != ErrUnavailable || token != (celld.CommitToken{}) || calls != 1 || n.commits.Load() != 1 {
				t.Fatal("ambiguous response replayed", err)
			}
			if mode == "ambiguous commit" {
				n.commitLost = false
				cold, err := New(config)
				if err != nil {
					t.Fatal(err)
				}
				token, err = cold.Transaction(context.Background(), "uncertain", func(tx celld.Transaction) error {
					r, found, err := tx.LookupReceipt("c")
					if err != nil || !found || !sameReceipt(r, adapterReceipt("c")) {
						t.Fatal("lost commit not recovered", err)
					}
					return nil
				})
				if err != nil || token.Revision != 2 || len(n.lastCommit.Receipts) != 0 {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestAdapterConcurrentCASCallbacksObserveOneWholeSnapshot(t *testing.T) {
	n, _, s := newAdapter(t)
	var wg sync.WaitGroup
	arrived := make(chan struct{}, 2)
	release := make(chan struct{})
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			calls := 0
			_, err := s.Transaction(context.Background(), "counter", func(tx celld.Transaction) error {
				calls++
				state, err := tx.ReadState()
				if err != nil {
					return err
				}
				value := 0
				if len(state) > 0 {
					value, err = strconv.Atoi(string(state))
					if err != nil {
						return err
					}
				}
				if calls == 1 {
					arrived <- struct{}{}
					<-release
				}
				return tx.WriteState([]byte(strconv.Itoa(value + 1)))
			})
			errs <- err
		}()
	}
	<-arrived
	<-arrived
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if string(n.objects["counter"].state) != "2" || n.objects["counter"].revision != 2 {
		t.Fatal("lost update")
	}
}

func TestAdapterRejectsMismatchedNativeSnapshotAndCommitResponses(t *testing.T) {
	for _, mode := range []string{"snapshot-object", "snapshot-digest", "absent-state", "exists-zero", "revision-max", "commit-object", "commit-revision", "commit-digest", "commit-state", "commit-exists", "token-object", "token-revision"} {
		t.Run(mode, func(t *testing.T) {
			n, _, s := newAdapter(t)
			callbacks := 0
			n.mutateSnapshot = func(r *Snapshot) {
				switch mode {
				case "snapshot-object":
					r.ObjectID += "-other"
				case "snapshot-digest":
					r.StateDigest[0] ^= 1
				case "absent-state":
					r.State = []byte("nonempty")
					r.StateDigest = celld.Digest(sha256.Sum256(r.State))
				case "exists-zero":
					r.Exists = true
				case "revision-max":
					r.Exists = true
					r.Revision = MaximumRevision
				}
			}
			n.mutateCommit = func(r *CommitResult) {
				switch mode {
				case "commit-object":
					r.Snapshot.ObjectID += "-other"
				case "commit-revision":
					r.Snapshot.Revision++
				case "commit-digest":
					r.RequestDigest[0] ^= 1
				case "commit-state":
					r.Snapshot.StateDigest[0] ^= 1
				case "commit-exists":
					r.Snapshot.Exists = false
				case "token-object":
					r.Token.ObjectID += "-other"
				case "token-revision":
					r.Token.Revision++
				}
			}
			token, err := s.Transaction(context.Background(), "mismatch", func(tx celld.Transaction) error { callbacks++; return tx.WriteState([]byte("state")) })
			if err != ErrInvalidResponse || token != (celld.CommitToken{}) {
				t.Fatal("malformed native response accepted", err)
			}
			if strings.HasPrefix(mode, "snapshot") || mode == "absent-state" || mode == "exists-zero" || mode == "revision-max" {
				if callbacks != 0 {
					t.Fatal("invalid snapshot reached callback")
				}
			}
		})
	}
}

func TestAdapterReceiptAndBarrierResponsesEchoExactBinding(t *testing.T) {
	for _, mode := range []string{"receipt-object", "receipt-revision", "receipt-digest", "receipt-command", "missing-payload", "barrier-object", "barrier-token", "barrier-marker", "barrier-observed", "barrier-overflow", "barrier-serial"} {
		t.Run(mode, func(t *testing.T) {
			n, _, s := newAdapter(t)
			n.mutateReceipt = func(r *ReceiptResult) {
				switch mode {
				case "receipt-object":
					r.Snapshot.ObjectID += "other"
				case "receipt-revision":
					r.Snapshot.Revision++
				case "receipt-digest":
					r.Snapshot.StateDigest[0] ^= 1
				case "receipt-command":
					r.CommandID += "other"
				case "missing-payload":
					r.Receipt.Response = []byte("unexpected")
				}
			}
			token, err := s.Transaction(context.Background(), "binding", func(tx celld.Transaction) error { _, _, err := tx.LookupReceipt("c"); return err })
			if strings.HasPrefix(mode, "receipt") || mode == "missing-payload" {
				if err != ErrInvalidResponse || n.commits.Load() != 0 {
					t.Fatal(err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			n.mutateBarrier = func(r *BarrierResult) {
				switch mode {
				case "barrier-object":
					r.Token.ObjectID += "other"
				case "barrier-token":
					r.Token.Revision++
				case "barrier-marker":
					r.Marker[0] ^= 1
				case "barrier-observed":
					r.ObservedRevision = 0
				case "barrier-overflow":
					r.ObservedRevision = MaximumRevision + 1
				case "barrier-serial":
					r.BarrierSerial = 0
				}
			}
			if err = s.DurabilityBarrier(context.Background(), token); err != ErrInvalidResponse {
				t.Fatal("invalid barrier acknowledged", err)
			}
		})
	}
}

func TestAdapterBoundsGuardAllBuffersAndIgnoredMethodErrors(t *testing.T) {
	for _, mode := range []string{"read-state", "write-state", "receipt-response", "claims-count", "claims-total", "lookups", "writes", "footprint"} {
		t.Run(mode, func(t *testing.T) {
			n, config, _ := newAdapter(t)
			config.Bounds = Bounds{MaxStateBytes: 8, MaxReceiptResponseBytes: 8, MaxCapabilityClaims: 1, MaxCapabilityClaimBytes: 8, MaxReceiptLookups: 1, MaxReceiptWrites: 1, MaxTransactionBytes: 128}
			if mode == "writes" {
				config.Bounds.MaxReceiptLookups = 2
			}
			if mode == "footprint" {
				config.Bounds.MaxTransactionBytes = 10
			}
			s, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "read-state" {
				n.mutateSnapshot = func(r *Snapshot) {
					r.Exists = true
					r.Revision = 1
					r.State = make([]byte, 9)
					r.StateDigest = celld.Digest(sha256.Sum256(r.State))
				}
			}
			_, err = s.Transaction(context.Background(), "bounds", func(tx celld.Transaction) error {
				r := celld.StoredReceipt{CommandDigest: celld.Digest{1}, Response: []byte("r")}
				switch mode {
				case "write-state":
					_ = tx.WriteState(make([]byte, 9))
				case "receipt-response":
					r.Response = make([]byte, 9)
					_ = tx.WriteReceipt("c", r)
				case "claims-count":
					r.CapabilityClaims = []celld.RawCapabilityClaims{{Kind: "a"}, {Kind: "b"}}
					_ = tx.WriteReceipt("c", r)
				case "claims-total":
					r.CapabilityClaims = []celld.RawCapabilityClaims{{Kind: "a", Payload: make([]byte, 9)}}
					_ = tx.WriteReceipt("c", r)
				case "lookups":
					_, _, _ = tx.LookupReceipt("a")
					_, _, _ = tx.LookupReceipt("b")
				case "writes":
					_ = tx.WriteReceipt("a", r)
					_ = tx.WriteReceipt("b", r)
				case "footprint":
					_ = tx.WriteState(make([]byte, 8))
					_ = tx.WriteReceipt("c", r)
				}
				return nil
			})
			if err == nil || n.commits.Load() != 0 {
				t.Fatal("ignored bound error committed")
			}
		})
	}
	for _, mode := range []string{"response", "claims", "claim-bytes"} {
		t.Run("native-receipt/"+mode, func(t *testing.T) {
			n, config, s := newAdapter(t)
			n.mutateReceipt = func(r *ReceiptResult) {
				r.Found = true
				r.Receipt = adapterReceipt("c")
				switch mode {
				case "response":
					r.Receipt.Response = make([]byte, config.Bounds.MaxReceiptResponseBytes+1)
				case "claims":
					r.Receipt.CapabilityClaims = make([]celld.RawCapabilityClaims, config.Bounds.MaxCapabilityClaims+1)
				case "claim-bytes":
					r.Receipt.CapabilityClaims[0].Payload = make([]byte, config.Bounds.MaxCapabilityClaimBytes+1)
				}
			}
			_, err := s.Transaction(context.Background(), "receipt-bounds", func(tx celld.Transaction) error { _, _, err := tx.LookupReceipt("c"); return err })
			if err != ErrInvalidResponse || n.commits.Load() != 0 {
				t.Fatal(err)
			}
		})
	}
}

func TestAdapterCancellationAndTransportErrorsExposeNoSuccess(t *testing.T) {
	for _, phase := range []string{"snapshot", "receipt", "callback", "commit", "barrier"} {
		for _, cancelled := range []bool{false, true} {
			t.Run(phase+fmt.Sprint(cancelled), func(t *testing.T) {
				n, _, s := newAdapter(t)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				want := error(ErrUnavailable)
				if cancelled {
					want = context.Canceled
				}
				if cancelled {
					switch phase {
					case "snapshot":
						n.afterSnapshot = cancel
					case "receipt":
						n.afterReceipt = cancel
					case "commit":
						n.afterCommit = cancel
					case "barrier":
						n.afterBarrier = cancel
					}
				} else {
					switch phase {
					case "snapshot":
						n.snapshotError = adapterDiagnostic
					case "receipt":
						n.receiptError = adapterDiagnostic
					case "commit":
						n.commitError = adapterDiagnostic
					case "barrier":
						n.barrierError = adapterDiagnostic
					}
				}
				if phase == "callback" && !cancelled {
					return
				}
				token, err := s.Transaction(ctx, "errors", func(tx celld.Transaction) error {
					if phase == "callback" {
						cancel()
						return nil
					}
					_, _, err := tx.LookupReceipt("c")
					return err
				})
				if phase == "barrier" {
					if err != nil {
						t.Fatal(err)
					}
					err = s.DurabilityBarrier(ctx, token)
				} else if token != (celld.CommitToken{}) {
					t.Fatal("partial token escaped")
				}
				if err != want || strings.Contains(err.Error(), "secret") {
					t.Fatal("native diagnostics escaped", err)
				}
			})
		}
	}
}

func TestAdapterMandatoryQualificationImmutableBoundsAndIdentifiers(t *testing.T) {
	_, config, s := newAdapter(t)
	for _, mode := range []string{"unverified", "state", "response", "claims", "claim-bytes", "lookups", "writes", "total", "attempts", "group"} {
		t.Run(mode, func(t *testing.T) {
			c := config
			switch mode {
			case "unverified":
				c.Transport = dependency.Verified[NativeTransport]{}
			case "state":
				c.Bounds.MaxStateBytes = 0
			case "response":
				c.Bounds.MaxReceiptResponseBytes = MaximumReceiptResponseBytes + 1
			case "claims":
				c.Bounds.MaxCapabilityClaims = 0
			case "claim-bytes":
				c.Bounds.MaxCapabilityClaimBytes = 0
			case "lookups":
				c.Bounds.MaxReceiptLookups = 0
			case "writes":
				c.Bounds.MaxReceiptWrites = 0
			case "total":
				c.Bounds.MaxTransactionBytes = MaximumTransactionBytes + 1
			case "attempts":
				c.MaximumAttempts = MaximumAttempts + 1
			case "group":
				c.RequiredAtomicGroups = []dependency.AtomicGroup{"not-qualified"}
			}
			if _, err := New(c); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	for _, group := range []dependency.AtomicGroup{AtomicNativeStorage, dependency.AtomicCommandReceipt} {
		p := proof.NewProductionProofs(t, []dependency.AtomicGroup{group})
		n := &adapterNative{ProductionProofs: p}
		c := config
		c.Transport = proof.Verify[NativeTransport](t, p, n, p.Descriptor().AtomicGroups)
		if _, err := New(c); err != dependency.ErrRequirementMismatch {
			t.Fatal("missing mandatory role accepted", err)
		}
	}
	config.Bounds.MaxStateBytes = 1
	if _, err := s.Transaction(context.Background(), "immutable-policy", func(tx celld.Transaction) error { return tx.WriteState([]byte("larger")) }); err != nil {
		t.Fatal("caller mutated constructor bounds", err)
	}
	for _, id := range []string{"", "\n", strings.Repeat("x", 257), "e\u0301", string([]byte{255})} {
		if _, err := s.Transaction(context.Background(), id, func(celld.Transaction) error { return nil }); err != ErrInvalidRequest {
			t.Fatal("invalid id accepted")
		}
	}
	if _, err := s.Transaction(nil, "x", func(celld.Transaction) error { return nil }); err != ErrInvalidRequest {
		t.Fatal(err)
	}
	if _, err := (*Storage)(nil).Transaction(context.Background(), "x", func(celld.Transaction) error { return nil }); err != dependency.ErrUnverifiedDependency {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Transaction(ctx, "x", func(celld.Transaction) error { return nil }); err != context.Canceled {
		t.Fatal(err)
	}
}

func TestAdapterDelegatesOnlyOwnedExactNativeProbe(t *testing.T) {
	n, _, s := newAdapter(t)
	baseline := n.probes.Load()
	challenge := dependency.ProbeChallenge{Nonce: bytes.Repeat([]byte{7}, dependency.ChallengeBytes)}
	var nativeSignature []byte
	var nativeGroups []dependency.AtomicGroup
	n.mutateProbe = func(r *dependency.ProbeResponse) {
		nativeSignature = r.Signature
		nativeGroups = r.Descriptor.AtomicGroups
	}
	result, err := s.ProbeProduction(context.Background(), challenge)
	if err != nil || n.probes.Load() != baseline+1 {
		t.Fatal("probe did not use retained operational source", err)
	}
	before := bytes.Clone(result.Signature)
	nativeSignature[0] ^= 1
	nativeGroups[0] = "other"
	if !bytes.Equal(result.Signature, before) || !slices.Equal(result.Descriptor.AtomicGroups, n.Descriptor().AtomicGroups) {
		t.Fatal("probe response aliases source")
	}
	for _, mode := range []string{"key", "descriptor", "signature", "diagnostic"} {
		t.Run(mode, func(t *testing.T) {
			n.mutateProbe = func(r *dependency.ProbeResponse) {
				switch mode {
				case "key":
					r.KeyID += "other"
				case "descriptor":
					r.Descriptor.InstanceID += "other"
				case "signature":
					r.Signature = make([]byte, 1024)
				}
			}
			want := ErrInvalidResponse
			if mode == "diagnostic" {
				n.probeError = adapterDiagnostic
				want = ErrUnavailable
			}
			result, err := s.ProbeProduction(context.Background(), challenge)
			if err != want || len(result.Signature) != 0 {
				t.Fatal("invalid native proof delegated", err)
			}
			n.probeError = nil
		})
	}
	if _, err = s.ProbeProduction(context.Background(), dependency.ProbeChallenge{}); err != ErrInvalidRequest {
		t.Fatal("unbounded challenge accepted", err)
	}
}

type adapterSigner struct {
	*proof.ProductionProofs
	private ed25519.PrivateKey
}

func (s *adapterSigner) SignCheckpoint(ctx context.Context, r auditcheckpoint.SigningRequest) (auditcheckpoint.SigningResponse, error) {
	if err := ctx.Err(); err != nil {
		return auditcheckpoint.SigningResponse{}, err
	}
	digest, err := auditcheckpoint.SigningDigest(r.CanonicalClaims)
	if err != nil || digest != r.SigningDigest {
		return auditcheckpoint.SigningResponse{}, ErrInvalidRequest
	}
	return auditcheckpoint.SigningResponse{KeyID: r.KeyID, SigningDigest: digest, Signature: ed25519.Sign(s.private, digest[:])}, nil
}
func TestActualPATAndSignedCheckpointUseNativeAdapterReceiptConflictRetry(t *testing.T) {
	n, _, s := newAdapter(t, authstate.AtomicCredentialAudit)
	storage := proof.Verify[authstate.Source](t, n.ProductionProofs, s, n.Descriptor().AtomicGroups)
	tenantID, err := identity.New(identity.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	userID, err := identity.New(identity.Subject)
	if err != nil {
		t.Fatal(err)
	}
	clock := func() time.Time { return time.Unix(2_000_000_000, 0).UTC() }
	store, err := authstate.New(authstate.Config{Source: storage, TenantID: tenantID.String(), Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	service, err := auth.NewPATService(auth.PATServiceConfig{Store: store, Now: clock, MaximumCASRetries: 8})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = service.Issue(context.Background(), tenantID.String(), userID.String(), []string{"events:read"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	reader := proof.Verify[auditcheckpoint.AuditReader](t, n.ProductionProofs, store, []dependency.AtomicGroup{authstate.AtomicCredentialAudit})
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signerProof := proof.NewProductionProofs(t, []dependency.AtomicGroup{auditcheckpoint.AtomicCheckpointSigning})
	signer := &adapterSigner{ProductionProofs: signerProof, private: private}
	publisher, err := auditcheckpoint.New(auditcheckpoint.Config{TenantID: tenantID.String(), Reader: reader, Storage: storage, Signer: proof.Verify[auditcheckpoint.Signer](t, signerProof, signer, []dependency.AtomicGroup{auditcheckpoint.AtomicCheckpointSigning}), KeyID: "checkpoint-v1", PublicKey: public})
	if err != nil {
		t.Fatal(err)
	}
	n.receiptConflicts = 1
	checkpoint, err := publisher.Publish(context.Background())
	if err != nil || auditcheckpoint.Verify(checkpoint, public) != nil || checkpoint.Claims.HeadSequence != 1 {
		t.Fatal("real checkpoint callback conflict retry failed", err)
	}
	replayed, err := publisher.Publish(context.Background())
	if err != nil || replayed.Claims != checkpoint.Claims || !bytes.Equal(replayed.Signature, checkpoint.Signature) {
		t.Fatal("forced read commits relabeled checkpoint", err)
	}
}
