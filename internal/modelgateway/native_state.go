package modelgateway

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/hancomac/circulusd/internal/celld"
	"github.com/hancomac/circulusd/internal/celldbridge"
	"github.com/hancomac/circulusd/internal/dependency"
)

// Native state contains admission primitives and authenticated accounting
// projections only. Session remains the owner
// of effect transitions, provider start claims, retries and settlement.
type nativeModelState struct {
	Protocol     string
	ObjectID     string
	PolicyDigest Digest
	Fences       map[string]ValidatedAuthority
	Grants       map[string]NativeAuthorityGrant
	Reservations map[string]nativeQuotaReservation
	Projections  map[string]nativeSessionQuotaRecord
}

type nativeQuotaReservation struct {
	Request QuotaRequest
	Permit  QuotaPermit
}

type nativeModelSource interface {
	celld.Storage
	dependency.ProductionProbe
}

func nativeModelGroups() []dependency.AtomicGroup {
	return []dependency.AtomicGroup{dependency.AtomicCommandReceipt, AtomicModelAuthorityFence,
		AtomicModelQuotaSettlement, AtomicModelEffectLifecycle}
}

func (factory *NativeFactory) ready(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if factory == nil || factory.source == nil || factory.check == nil || factory.check() != nil {
		return ErrStateDependenciesNotDurable
	}
	return nil
}

func nativeModelError(ctx context.Context, err error) error {
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	for _, allowed := range []error{ErrInvalidRequest, ErrStaleAuthority, ErrAuthorityMismatch,
		ErrQuotaConflict, ErrQuotaExceeded, ErrInputLimit} {
		if errors.Is(err, allowed) {
			return allowed
		}
	}
	return ErrStateDependenciesNotDurable
}

// Every call reads actual native state, including read-only validation. A
// callback retry discards its previous result. Neither a lost commit reply nor
// an ambiguous barrier can publish a permit or stale validation result.
func nativeModelOperation[T any](ctx context.Context, factory *NativeFactory, operation func(*nativeModelState) (T, error)) (T, error) {
	var zero, result T
	if err := factory.ready(ctx); err != nil {
		return zero, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var invoked, complete bool
	commit, err := factory.source.Transaction(ctx, factory.objectID, func(transaction celld.Transaction) error {
		invoked, complete, result = true, false, zero
		if transaction == nil {
			return ErrStateDependenciesNotDurable
		}
		encoded, err := transaction.ReadState()
		if err != nil || len(encoded) > factory.maximumBytes {
			return ErrStateDependenciesNotDurable
		}
		state, err := factory.decodeState(encoded)
		if err != nil {
			return ErrStateDependenciesNotDurable
		}
		result, err = operation(state)
		if err != nil {
			return err
		}
		next, err := factory.encodeState(state)
		if err != nil {
			if errors.Is(err, ErrInputLimit) {
				return ErrInputLimit
			}
			return ErrStateDependenciesNotDurable
		}
		if !bytes.Equal(encoded, next) {
			if err := transaction.WriteState(next); err != nil {
				return err
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		complete = true
		return nil
	})
	if err != nil {
		return zero, nativeModelError(ctx, err)
	}
	if !invoked || !complete || commit.ObjectID != factory.objectID || commit.Revision == 0 {
		return zero, ErrStateDependenciesNotDurable
	}
	if err := factory.source.DurabilityBarrier(ctx, commit); err != nil {
		return zero, nativeModelError(ctx, err)
	}
	if err := factory.ready(ctx); err != nil {
		return zero, err
	}
	return result, nil
}

func (factory *NativeFactory) probe(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	if err := factory.ready(ctx); err != nil {
		return dependency.ProbeResponse{}, err
	}
	return factory.source.ProbeProduction(ctx, challenge)
}

// NativeStateBounds returns immutable aggregate bounds; it does not attest
// that Session settlement or any provider path has been qualified.
func (factory *NativeFactory) NativeStateBounds() (records, bytes int) {
	if factory == nil {
		return 0, 0
	}
	return factory.maximumRecords, factory.maximumBytes
}

var _ nativeModelSource = (*celldbridge.Storage)(nil)
