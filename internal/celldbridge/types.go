// Package celldbridge adapts bounded native object operations to celld.Storage.
// Native durability requires an independently qualified, replication-backed
// DO fetch output gate; local transactions and transport MACs cannot grant it.
package celldbridge

import (
	"context"
	"errors"

	"github.com/hancomac/circulusd/internal/celld"
	"github.com/hancomac/circulusd/internal/dependency"
)

const (
	AtomicNativeStorage         dependency.AtomicGroup = "native-storage"
	MaximumRevision                                    = uint64(9_007_199_254_740_991)
	MaximumStateBytes                                  = 16 << 20
	MaximumReceiptResponseBytes                        = 4 << 20
	MaximumCapabilityClaims                            = 64
	MaximumCapabilityClaimBytes                        = 1 << 20
	MaximumReceiptLookups                              = 64
	MaximumReceiptWrites                               = 64
	MaximumTransactionBytes                            = 32 << 20
	MaximumAttempts                                    = 8
)

var (
	ErrInvalidConfig           = errors.New("celld bridge: invalid configuration")
	ErrInvalidRequest          = errors.New("celld bridge: invalid request")
	ErrInvalidResponse         = errors.New("celld bridge: invalid response")
	ErrUnauthenticatedResponse = errors.New("celld bridge: unauthenticated response")
	ErrUnavailable             = errors.New("celld bridge: qualified native source unavailable")
	// Only an authenticated, definitely not committed revision conflict may
	// trigger another evaluation of a deterministic transaction callback.
	ErrSnapshotConflict = errors.New("celld bridge: snapshot changed before commit")
	ErrClosed           = errors.New("celld bridge: source closed")
)

type Bounds struct {
	MaxStateBytes           int
	MaxReceiptResponseBytes int
	MaxCapabilityClaims     int
	MaxCapabilityClaimBytes int
	MaxReceiptLookups       int
	MaxReceiptWrites        int
	MaxTransactionBytes     int
}

// Exists describes the native object record, not whether an application has
// provisioned credentials or state. An absent record has revision zero and the
// SHA256 of empty bytes. Every successful commit creates/advances the record.
type SnapshotRef struct {
	ObjectID    string
	Exists      bool
	Revision    uint64
	StateDigest celld.Digest
}

type SnapshotRequest struct{ ObjectID string }
type Snapshot struct {
	SnapshotRef
	State []byte
}
type ReceiptRequest struct {
	Snapshot  SnapshotRef
	CommandID string
}
type ReceiptResult struct {
	Snapshot  SnapshotRef
	CommandID string
	Found     bool
	Receipt   celld.StoredReceipt
}
type ReceiptWrite struct {
	CommandID string
	Receipt   celld.StoredReceipt
}
type CommitRequest struct {
	Snapshot      SnapshotRef
	StateWritten  bool
	State         []byte
	Receipts      []ReceiptWrite
	RequestDigest celld.Digest
}
type CommitResult struct {
	Snapshot      SnapshotRef
	RequestDigest celld.Digest
	Token         celld.CommitToken
}
type BarrierRequest struct {
	Token  celld.CommitToken
	Marker [32]byte
}
type BarrierResult struct {
	Token            celld.CommitToken
	Marker           [32]byte
	ObservedRevision uint64
	BarrierSerial    uint64
}

// NativeTransport must bind all operations and its native challenge to one
// measured source/domain. Receipt reads validate the complete snapshot tuple.
// CompareAndCommit validates it again and advances revision exactly once even
// for read-only callbacks. ConfirmBarrier writes a fresh same-object marker and
// returns only after the native DO fetch gate; it never substitutes JS sync().
type NativeTransport interface {
	dependency.ProductionProbe
	ReadSnapshot(context.Context, SnapshotRequest) (Snapshot, error)
	ReadReceipt(context.Context, ReceiptRequest) (ReceiptResult, error)
	CompareAndCommit(context.Context, CommitRequest) (CommitResult, error)
	ConfirmBarrier(context.Context, BarrierRequest) (BarrierResult, error)
}

func (Snapshot) String() string        { return "native-storage-snapshot<redacted>" }
func (Snapshot) GoString() string      { return "native-storage-snapshot<redacted>" }
func (ReceiptResult) String() string   { return "native-storage-receipt<redacted>" }
func (ReceiptResult) GoString() string { return "native-storage-receipt<redacted>" }
func (ReceiptWrite) String() string    { return "native-storage-receipt-write<redacted>" }
func (ReceiptWrite) GoString() string  { return "native-storage-receipt-write<redacted>" }
func (CommitRequest) String() string   { return "native-storage-commit-request<redacted>" }
func (CommitRequest) GoString() string { return "native-storage-commit-request<redacted>" }
