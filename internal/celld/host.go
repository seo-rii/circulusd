package celld

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const (
	defaultMaxCommandBytes         = 8 << 20
	defaultMaxStateBytes           = 32 << 20
	defaultMaxResponseBytes        = 8 << 20
	defaultMaxCapabilityClaims     = 8
	defaultMaxCapabilityClaimBytes = 1 << 20
	maxProtocolIdentifierBytes     = 256
)

// Host is immutable after construction. Object serialization and durability
// come from Storage, rather than process-local locks that disappear on owner
// transfer or restart.
type Host struct {
	storage       Storage
	aggregate     Aggregate
	sealer        PermitSealer
	limits        Limits
	faultInjector FaultInjector
}

func NewHost(config Config) (*Host, error) {
	if config.Storage == nil || config.Aggregate == nil || config.Sealer == nil {
		return nil, fmt.Errorf("%w: storage, aggregate, and sealer are required", ErrInvalidConfig)
	}
	limits := config.Limits
	if limits.MaxCommandBytes < 0 || limits.MaxStateBytes < 0 || limits.MaxResponseBytes < 0 || limits.MaxCapabilityClaims < 0 || limits.MaxCapabilityClaimBytes < 0 {
		return nil, fmt.Errorf("%w: limits cannot be negative", ErrInvalidConfig)
	}
	if limits.MaxCommandBytes == 0 {
		limits.MaxCommandBytes = defaultMaxCommandBytes
	}
	if limits.MaxStateBytes == 0 {
		limits.MaxStateBytes = defaultMaxStateBytes
	}
	if limits.MaxResponseBytes == 0 {
		limits.MaxResponseBytes = defaultMaxResponseBytes
	}
	if limits.MaxCapabilityClaims == 0 {
		limits.MaxCapabilityClaims = defaultMaxCapabilityClaims
	}
	if limits.MaxCapabilityClaimBytes == 0 {
		limits.MaxCapabilityClaimBytes = defaultMaxCapabilityClaimBytes
	}
	if uint64(limits.MaxCapabilityClaims) > uint64(^uint32(0)) {
		return nil, fmt.Errorf("%w: capability claim count exceeds permit index range", ErrInvalidConfig)
	}
	return &Host{
		storage:       config.Storage,
		aggregate:     config.Aggregate,
		sealer:        config.Sealer,
		limits:        limits,
		faultInjector: config.FaultInjector,
	}, nil
}

// Execute runs one command through the aggregate's authoritative transaction.
// It does not expose a response or permit until the exact transaction token
// passes the explicit durability barrier.
func (host *Host) Execute(ctx context.Context, request Request) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if host == nil || host.storage == nil || host.aggregate == nil || host.sealer == nil {
		return Result{}, ErrInvalidConfig
	}
	if !validProtocolIdentifier(request.ObjectID) || !validProtocolIdentifier(request.CommandID) || len(request.Command) == 0 {
		return Result{}, ErrInvalidRequest
	}
	if len(request.Command) > host.limits.MaxCommandBytes {
		return Result{}, fmt.Errorf("%w: got %d bytes, limit %d", ErrCommandTooLarge, len(request.Command), host.limits.MaxCommandBytes)
	}
	command := append([]byte(nil), request.Command...)
	if err := host.aggregate.ValidateCommand(ctx, append([]byte(nil), command...)); err != nil {
		return Result{}, err
	}
	commandDigest := sha256.Sum256(command)
	var receipt StoredReceipt
	var replayed bool
	var transactionInvoked bool

	commit, err := host.storage.Transaction(ctx, request.ObjectID, func(transaction Transaction) error {
		transactionInvoked = true
		if transaction == nil {
			return ErrStorageContract
		}
		state, err := transaction.ReadState()
		if err != nil {
			return err
		}
		if len(state) > host.limits.MaxStateBytes {
			return fmt.Errorf("%w: got %d bytes, limit %d", ErrStateTooLarge, len(state), host.limits.MaxStateBytes)
		}
		state = append([]byte(nil), state...)
		if err := host.aggregate.ValidateState(ctx, append([]byte(nil), state...)); err != nil {
			return err
		}
		// Authorization deliberately precedes receipt lookup. Authentication,
		// ACL, and live generation fences therefore remain effective on replay.
		if err := host.aggregate.Authorize(ctx, append([]byte(nil), state...), append([]byte(nil), command...)); err != nil {
			return err
		}

		stored, found, err := transaction.LookupReceipt(request.CommandID)
		if err != nil {
			return err
		}
		if found {
			if stored.CommandDigest != commandDigest {
				return ErrIdempotencyConflict
			}
			if len(stored.Response) > host.limits.MaxResponseBytes || len(stored.CapabilityClaims) > host.limits.MaxCapabilityClaims {
				return ErrCorruptReceipt
			}
			totalClaimBytes := 0
			for _, claim := range stored.CapabilityClaims {
				if !validProtocolIdentifier(claim.Kind) || len(claim.Payload) == 0 || len(claim.Payload) > host.limits.MaxCapabilityClaimBytes-totalClaimBytes {
					return ErrCorruptReceipt
				}
				totalClaimBytes += len(claim.Payload)
			}
			storedClaims := make([]RawCapabilityClaims, len(stored.CapabilityClaims))
			for index, claim := range stored.CapabilityClaims {
				storedClaims[index] = RawCapabilityClaims{Kind: claim.Kind, Payload: append([]byte(nil), claim.Payload...)}
			}
			receipt = StoredReceipt{
				CommandDigest:    stored.CommandDigest,
				Response:         append([]byte(nil), stored.Response...),
				CapabilityClaims: storedClaims,
			}
			replayed = true
			if host.faultInjector != nil {
				if err := host.faultInjector.Inject(ctx, FaultBeforeCommit); err != nil {
					return err
				}
			}
			return nil
		}

		applied, err := host.aggregate.Apply(ctx, append([]byte(nil), state...), append([]byte(nil), command...))
		if err != nil {
			return err
		}
		if len(applied.NextState) > host.limits.MaxStateBytes {
			return fmt.Errorf("%w: got %d bytes, limit %d", ErrStateTooLarge, len(applied.NextState), host.limits.MaxStateBytes)
		}
		if len(applied.Response) > host.limits.MaxResponseBytes {
			return fmt.Errorf("%w: got %d bytes, limit %d", ErrResponseTooLarge, len(applied.Response), host.limits.MaxResponseBytes)
		}
		if len(applied.CapabilityClaims) > host.limits.MaxCapabilityClaims {
			return fmt.Errorf("%w: got %d claims, limit %d", ErrCapabilityClaimsTooLarge, len(applied.CapabilityClaims), host.limits.MaxCapabilityClaims)
		}
		totalClaimBytes := 0
		for _, claim := range applied.CapabilityClaims {
			if !validProtocolIdentifier(claim.Kind) || len(claim.Payload) == 0 {
				return ErrInvalidAggregateOutput
			}
			if len(claim.Payload) > host.limits.MaxCapabilityClaimBytes-totalClaimBytes {
				return fmt.Errorf("%w: limit %d", ErrCapabilityClaimsTooLarge, host.limits.MaxCapabilityClaimBytes)
			}
			totalClaimBytes += len(claim.Payload)
		}
		nextState := append([]byte(nil), applied.NextState...)
		if err := host.aggregate.ValidateState(ctx, append([]byte(nil), nextState...)); err != nil {
			return err
		}
		appliedClaims := make([]RawCapabilityClaims, len(applied.CapabilityClaims))
		for index, claim := range applied.CapabilityClaims {
			appliedClaims[index] = RawCapabilityClaims{Kind: claim.Kind, Payload: append([]byte(nil), claim.Payload...)}
		}
		receipt = StoredReceipt{
			CommandDigest:    commandDigest,
			Response:         append([]byte(nil), applied.Response...),
			CapabilityClaims: appliedClaims,
		}
		if err := transaction.WriteState(nextState); err != nil {
			return err
		}
		if err := transaction.WriteReceipt(request.CommandID, receipt); err != nil {
			return err
		}
		if host.faultInjector != nil {
			if err := host.faultInjector.Inject(ctx, FaultBeforeCommit); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return Result{}, err
	}
	if !transactionInvoked || commit.ObjectID != request.ObjectID || commit.Revision == 0 {
		return Result{}, ErrStorageContract
	}
	if host.faultInjector != nil {
		if err := host.faultInjector.Inject(ctx, FaultAfterCommit); err != nil {
			return Result{}, err
		}
		if err := host.faultInjector.Inject(ctx, FaultBeforeBarrier); err != nil {
			return Result{}, err
		}
	}
	if err := host.storage.DurabilityBarrier(ctx, commit); err != nil {
		return Result{}, errors.Join(ErrDurabilityBarrier, err)
	}
	if host.faultInjector != nil {
		if err := host.faultInjector.Inject(ctx, FaultAfterBarrier); err != nil {
			return Result{}, err
		}
	}

	permits := make([]SealedPermit, len(receipt.CapabilityClaims))
	for index, claims := range receipt.CapabilityClaims {
		permit, err := host.sealer.Seal(ctx, PermitBinding{
			ObjectID:      request.ObjectID,
			CommandID:     request.CommandID,
			CommandDigest: commandDigest,
			ClaimIndex:    uint32(index),
		}, RawCapabilityClaims{Kind: claims.Kind, Payload: append([]byte(nil), claims.Payload...)})
		if err != nil {
			return Result{}, err
		}
		if len(permit.token) == 0 {
			return Result{}, ErrInvalidPermit
		}
		permits[index] = SealedPermit{token: append([]byte(nil), permit.token...)}
	}
	if host.faultInjector != nil {
		if err := host.faultInjector.Inject(ctx, FaultBeforeResponse); err != nil {
			return Result{}, err
		}
	}
	return Result{
		CommandDigest:  commandDigest,
		Response:       append([]byte(nil), receipt.Response...),
		Permits:        permits,
		CommitRevision: commit.Revision,
		Replayed:       replayed,
		Durable:        true,
	}, nil
}

func validProtocolIdentifier(value string) bool {
	if value == "" || !utf8.ValidString(value) || norm.NFC.String(value) != value || len(value) > maxProtocolIdentifierBytes {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}
