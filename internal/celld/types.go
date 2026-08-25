// Package celld provides the trusted host boundary between a celld object
// transaction and a pure aggregate state application.
package celld

import (
	"context"
	"errors"
)

var (
	ErrInvalidConfig            = errors.New("celld: invalid host configuration")
	ErrInvalidRequest           = errors.New("celld: invalid request")
	ErrCommandTooLarge          = errors.New("celld: command exceeds configured size")
	ErrStateTooLarge            = errors.New("celld: aggregate state exceeds configured size")
	ErrResponseTooLarge         = errors.New("celld: response exceeds configured size")
	ErrCapabilityClaimsTooLarge = errors.New("celld: capability claims exceed configured size")
	ErrIdempotencyConflict      = errors.New("celld: command ID reused with different input")
	ErrInvalidAggregateOutput   = errors.New("celld: invalid aggregate output")
	ErrCorruptReceipt           = errors.New("celld: stored command receipt is invalid")
	ErrStorageContract          = errors.New("celld: storage contract violated")
	ErrDurabilityBarrier        = errors.New("celld: durability barrier not confirmed")
	ErrInvalidPermit            = errors.New("celld: invalid sealed permit")
	ErrPermitTooLarge           = errors.New("celld: sealed permit exceeds size limit")
)

// Digest is the SHA-256 digest of the exact, already canonical command bytes.
type Digest [32]byte

// Limits bound every value that crosses the trusted aggregate boundary. Zero
// fields select conservative defaults; negative fields are invalid.
type Limits struct {
	MaxCommandBytes         int
	MaxStateBytes           int
	MaxResponseBytes        int
	MaxCapabilityClaims     int
	MaxCapabilityClaimBytes int
}

// RawCapabilityClaims are trusted state-application output. Host callers never
// receive this type in Execute results: it is persisted with the command
// receipt and converted to SealedPermit only after a durability barrier.
type RawCapabilityClaims struct {
	Kind    string
	Payload []byte
}

func (RawCapabilityClaims) String() string { return "raw-capability-claims<redacted>" }

func (RawCapabilityClaims) GoString() string { return "raw-capability-claims<redacted>" }

// ApplyResult is produced by a pure aggregate transition. NextState, Response,
// and CapabilityClaims are copied before they reach storage.
type ApplyResult struct {
	NextState        []byte
	Response         []byte
	CapabilityClaims []RawCapabilityClaims
}

func (ApplyResult) String() string { return "aggregate-apply-result<redacted>" }

func (ApplyResult) GoString() string { return "aggregate-apply-result<redacted>" }

// Aggregate owns state and command shape validation. Authorize is called
// against current state before idempotency lookup on every request, including
// receipt replay, so a stale capability cannot recover an old permit.
//
// Apply must be deterministic and side-effect free. A storage implementation
// may retry a transaction callback, and a crash before commit may cause the
// command to be evaluated again.
type Aggregate interface {
	ValidateCommand(context.Context, []byte) error
	ValidateState(context.Context, []byte) error
	Authorize(context.Context, []byte, []byte) error
	Apply(context.Context, []byte, []byte) (ApplyResult, error)
}

// StoredReceipt is trusted celld-local data committed atomically with state.
// CapabilityClaims must never be returned directly across an untrusted RPC.
type StoredReceipt struct {
	CommandDigest    Digest
	Response         []byte
	CapabilityClaims []RawCapabilityClaims
}

func (StoredReceipt) String() string { return "stored-command-receipt<redacted>" }

func (StoredReceipt) GoString() string { return "stored-command-receipt<redacted>" }

// Transaction exposes one object's serialized read/write set. Implementations
// must stage writes and roll all of them back when the callback returns an
// error. Returned byte slices must not alias durable storage.
type Transaction interface {
	ReadState() ([]byte, error)
	LookupReceipt(commandID string) (StoredReceipt, bool, error)
	WriteState([]byte) error
	WriteReceipt(commandID string, receipt StoredReceipt) error
}

// CommitToken identifies the exact object revision observed or committed by a
// transaction. Storage implementations may retain backend details keyed by
// ObjectID and Revision.
type CommitToken struct {
	ObjectID string
	Revision uint64
}

// Storage supplies celld's object-level single-writer transaction and explicit
// commit durability barrier. Transaction returning success is not permission
// to dispatch; DurabilityBarrier must also return success.
type Storage interface {
	Transaction(context.Context, string, func(Transaction) error) (CommitToken, error)
	DurabilityBarrier(context.Context, CommitToken) error
}

// PermitBinding prevents a sealed capability from being moved to a different
// aggregate, command receipt, command body, or claim position.
type PermitBinding struct {
	ObjectID      string
	CommandID     string
	CommandDigest Digest
	ClaimIndex    uint32
}

// PermitSealer is trusted host wiring. Implementations must be deterministic
// for the same binding and claims so response-loss replay returns the same
// opaque bytes. PermitCodec is the reference implementation.
type PermitSealer interface {
	Seal(context.Context, PermitBinding, RawCapabilityClaims) (SealedPermit, error)
}

type FaultPoint string

const (
	FaultBeforeCommit   FaultPoint = "before_commit"
	FaultAfterCommit    FaultPoint = "after_commit"
	FaultBeforeBarrier  FaultPoint = "before_barrier"
	FaultAfterBarrier   FaultPoint = "after_barrier"
	FaultBeforeResponse FaultPoint = "before_response"
)

// FaultInjector is used by deterministic crash-window conformance tests. A
// returned error aborts the current call at exactly the named boundary.
type FaultInjector interface {
	Inject(context.Context, FaultPoint) error
}

type FaultInjectorFunc func(context.Context, FaultPoint) error

func (injector FaultInjectorFunc) Inject(ctx context.Context, point FaultPoint) error {
	return injector(ctx, point)
}

type Config struct {
	Storage       Storage
	Aggregate     Aggregate
	Sealer        PermitSealer
	Limits        Limits
	FaultInjector FaultInjector
}

type Request struct {
	ObjectID  string
	CommandID string
	Command   []byte
}

type Result struct {
	CommandDigest  Digest
	Response       []byte
	Permits        []SealedPermit
	CommitRevision uint64
	Replayed       bool
	Durable        bool
}
