package effectledger

import (
	"context"

	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/celld"
	"github.com/hancomac/circulusd/internal/celldbridge"
	"github.com/hancomac/circulusd/internal/dependency"
	"github.com/hancomac/circulusd/internal/identity"
)

// AtomicProviderObservationLedger qualifies subordinate acceptance/terminal
// facts. A Session/storage proof alone cannot qualify this distinct source.
const AtomicProviderObservationLedger dependency.AtomicGroup = "provider-observation-ledger"

const nativeRecordOverheadBytes = 16 << 10

type NativeConfig struct {
	Storage           dependency.Verified[*celldbridge.Storage]
	Service           broker.EffectService
	RouteDigest       broker.Digest
	Limits            ReferenceLimits
	MaximumStateBytes int
}

func (NativeConfig) String() string   { return "native-effect-ledger-config<redacted>" }
func (NativeConfig) GoString() string { return "native-effect-ledger-config<redacted>" }

// NativeLedger owns immutable policy and a concrete qualified Storage adapter.
// All facts are read from transactions; there is no authoritative local cache.
// Observations can record facts but never recover provider-start authority.
type NativeLedger struct {
	storage           *celldbridge.Storage
	binding           dependency.Verified[*celldbridge.Storage]
	service           broker.EffectService
	routeDigest       broker.Digest
	limits            ReferenceLimits
	maximumStateBytes int
}

func NewNativeLedger(config NativeConfig) (*NativeLedger, error) {
	storage, _, err := config.Storage.Open()
	if err != nil || storage == nil {
		return nil, dependency.ErrUnverifiedDependency
	}
	if _, err := dependency.RequireAtomicDomain([]dependency.AtomicGroup{
		dependency.AtomicCommandReceipt, dependency.AtomicEffectLifecycle, AtomicProviderObservationLedger,
	}, config.Storage); err != nil {
		return nil, err
	}
	if !validService(config.Service) || config.RouteDigest == (broker.Digest{}) ||
		config.Limits.MaximumPayloadBytes <= 0 || config.Limits.MaximumPayloadBytes > maximumReferenceBytes ||
		config.Limits.MaximumResultBytes <= 0 || config.Limits.MaximumResultBytes > maximumReferenceBytes ||
		config.MaximumStateBytes > celldbridge.MaximumStateBytes ||
		config.MaximumStateBytes < config.Limits.MaximumPayloadBytes+config.Limits.MaximumResultBytes+nativeRecordOverheadBytes {
		return nil, ErrInvalidConfiguration
	}
	return &NativeLedger{storage: storage, binding: config.Storage, service: config.Service,
		routeDigest: config.RouteDigest, limits: config.Limits, maximumStateBytes: config.MaximumStateBytes}, nil
}

func (*NativeLedger) String() string   { return "native-effect-ledger<redacted>" }
func (*NativeLedger) GoString() string { return "native-effect-ledger<redacted>" }

func (ledger *NativeLedger) Service() broker.EffectService {
	if ledger == nil {
		return ""
	}
	return ledger.service
}

func (ledger *NativeLedger) RouteDigest() broker.Digest {
	if ledger == nil {
		return broker.Digest{}
	}
	return ledger.routeDigest
}

func (ledger *NativeLedger) Limits() ReferenceLimits {
	if ledger == nil {
		return ReferenceLimits{}
	}
	return ledger.limits
}

func (ledger *NativeLedger) ready(ctx context.Context) error {
	if err := validateContext(ctx); err != nil {
		return err
	}
	if ledger == nil || ledger.storage == nil {
		return dependency.ErrUnverifiedDependency
	}
	storage, _, err := ledger.binding.Open()
	if err != nil || storage != ledger.storage {
		return dependency.ErrUnverifiedDependency
	}
	return nil
}

func (ledger *NativeLedger) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	if err := ledger.ready(ctx); err != nil {
		return dependency.ProbeResponse{}, err
	}
	return ledger.storage.ProbeProduction(ctx, challenge)
}

func (ledger *NativeLedger) Prepare(ctx context.Context, command Command) error {
	if err := ledger.ready(ctx); err != nil {
		return err
	}
	if err := validateCommand(command); err != nil {
		return err
	}
	if command.Dispatch.Service != ledger.service || command.Dispatch.ProviderRouteDigest != ledger.routeDigest {
		return ErrBindingMismatch
	}
	if len(command.Payload) > ledger.limits.MaximumPayloadBytes {
		return ErrLimitExceeded
	}
	command = nativeCommandSnapshot(command)
	if err := ledger.validateEntry(&entry{state: StatePrepared, command: command}); err != nil {
		return ErrInvalidCommand
	}
	_, err := ledger.transact(ctx, keyForDispatch(command.Dispatch), func(record *entry) (*entry, bool, error) {
		if record != nil {
			if !sameCommand(record.command, command) {
				return nil, false, ErrPrepareConflict
			}
			return record, false, nil
		}
		return &entry{state: StatePrepared, command: command}, true, nil
	})
	return err
}

func (ledger *NativeLedger) ClaimStart(ctx context.Context, claim broker.ClaimedDispatchStart) (ClaimedCommand, error) {
	if err := ledger.ready(ctx); err != nil {
		return ClaimedCommand{}, err
	}
	start, opened := claim.Open()
	if !opened || start.Opaque == "" || !start.Durable || start.EventSequence == 0 || start.CommandDigest == (broker.Digest{}) {
		return ClaimedCommand{}, ErrInvalidClaim
	}
	if err := validateDispatch(start.Dispatch); err != nil {
		return ClaimedCommand{}, ErrInvalidClaim
	}
	if start.Dispatch.Service != ledger.service || start.Dispatch.ProviderRouteDigest != ledger.routeDigest {
		return ClaimedCommand{}, ErrBindingMismatch
	}
	command := nativeCommandSnapshot(Command{Dispatch: start.Dispatch, CommandDigest: start.CommandDigest})
	key := keyForDispatch(command.Dispatch)
	record, err := ledger.transact(ctx, key, func(record *entry) (*entry, bool, error) {
		if record == nil {
			return nil, false, ErrCommandNotPrepared
		}
		if record.command.Dispatch != command.Dispatch || record.command.CommandDigest != command.CommandDigest {
			return nil, false, ErrBindingMismatch
		}
		if record.state != StatePrepared {
			return nil, false, ErrStartAlreadyClaimed
		}
		record.state = StateClaimed
		return record, true, nil
	})
	if err != nil {
		return ClaimedCommand{}, err
	}
	return ClaimedCommand{command: cloneCommand(record.command), observation: ledger.observation(key, command.CommandDigest), seal: claimedCommandSeal}, nil
}

func (ledger *NativeLedger) RecordAccepted(ctx context.Context, observation Observation, providerRequestID string) error {
	if err := ledger.validateObservation(ctx, observation); err != nil {
		return err
	}
	if err := validateProviderRequestID(providerRequestID); err != nil {
		return err
	}
	if !nativeText(providerRequestID, maximumProviderRequestBytes, false) {
		return ErrInvalidCommand
	}
	_, err := ledger.transact(ctx, observation.key, func(record *entry) (*entry, bool, error) {
		if err := ledger.matchObservation(record, observation); err != nil {
			return nil, false, err
		}
		if record.externalProviderRequestID != "" {
			if record.externalProviderRequestID != providerRequestID {
				return nil, false, ErrAcceptanceConflict
			}
			return record, false, nil
		}
		if record.state != StateClaimed {
			return nil, false, ErrInvalidTransition
		}
		record.externalProviderRequestID, record.state = providerRequestID, StateAccepted
		return record, true, nil
	})
	return err
}

func (ledger *NativeLedger) RecordTerminal(ctx context.Context, observation Observation, terminal Terminal) (Terminal, error) {
	if err := ledger.validateObservation(ctx, observation); err != nil {
		return Terminal{}, err
	}
	if len(terminal.Result) > ledger.limits.MaximumResultBytes {
		return Terminal{}, ErrLimitExceeded
	}
	if err := validateTerminal(terminal); err != nil {
		return Terminal{}, err
	}
	requested := cloneTerminal(terminal)
	// Generate once outside the retryable callback. A replay always returns the
	// previously persisted identities rather than this call's unused candidate.
	normalized := cloneTerminal(requested)
	var err error
	if normalized.Status == TerminalCommitted && normalized.ExternalCommitID == (identity.ID{}) {
		normalized.ExternalCommitID, err = identity.New(identity.Commit)
		if err != nil {
			return Terminal{}, ErrIdentityGeneration
		}
	}
	if normalized.Status == TerminalCommitted && len(normalized.Result) != 0 && normalized.ResultRef == (identity.ID{}) {
		normalized.ResultRef, err = identity.New(identity.Artifact)
		if err != nil {
			return Terminal{}, ErrIdentityGeneration
		}
	}
	record, err := ledger.transact(ctx, observation.key, func(record *entry) (*entry, bool, error) {
		if err := ledger.matchObservation(record, observation); err != nil {
			return nil, false, err
		}
		if record.terminal != nil {
			if !terminalReplays(*record.terminal, requested) {
				return nil, false, ErrTerminalConflict
			}
			return record, false, nil
		}
		if record.state != StateClaimed && record.state != StateAccepted ||
			normalized.Status == TerminalCommitted && record.state != StateAccepted {
			return nil, false, ErrInvalidTransition
		}
		copy := cloneTerminal(normalized)
		record.terminal, record.state = &copy, StateTerminal
		return record, true, nil
	})
	if err != nil {
		return Terminal{}, err
	}
	return cloneTerminal(*record.terminal), nil
}

func (ledger *NativeLedger) ResumeObservation(ctx context.Context, lookup broker.LedgerLookup, commandDigest broker.Digest) (Observation, error) {
	if commandDigest == (broker.Digest{}) {
		return Observation{}, ErrBindingMismatch
	}
	record, err := ledger.read(ctx, lookup)
	if err != nil {
		return Observation{}, err
	}
	if record == nil || record.state == StatePrepared {
		return Observation{}, ErrObservationUnavailable
	}
	if record.command.CommandDigest != commandDigest {
		return Observation{}, ErrBindingMismatch
	}
	return ledger.observation(keyForLookup(lookup), commandDigest), nil
}

func (ledger *NativeLedger) Inspect(ctx context.Context, lookup broker.LedgerLookup) (Facts, error) {
	record, err := ledger.read(ctx, lookup)
	if err != nil {
		return Facts{}, err
	}
	if record == nil {
		return Facts{}, ErrObservationUnavailable
	}
	facts := Facts{State: record.state, Command: cloneCommand(record.command), ExternalProviderRequestID: record.externalProviderRequestID}
	if record.terminal != nil {
		facts.Terminal = cloneTerminal(*record.terminal)
	}
	return facts, nil
}

func (ledger *NativeLedger) Lookup(ctx context.Context, lookup broker.LedgerLookup) (broker.LedgerRecord, error) {
	record, err := ledger.read(ctx, lookup)
	if err != nil {
		return broker.LedgerRecord{}, err
	}
	result := ledgerRecord(lookup, broker.LedgerAbsent)
	if record == nil || record.state == StatePrepared {
		return result, nil
	}
	result.Status = broker.LedgerInflight
	if record.terminal != nil {
		switch record.terminal.Status {
		case TerminalCommitted:
			result.Status, result.ExternalCommitID, result.ResultRef = broker.LedgerCommitted, record.terminal.ExternalCommitID, record.terminal.ResultRef
		case TerminalFailed:
			result.Status = broker.LedgerFailed
		case TerminalUnknown:
			result.Status = broker.LedgerUnknown
		}
	}
	return result, nil
}

func (ledger *NativeLedger) read(ctx context.Context, lookup broker.LedgerLookup) (*entry, error) {
	if err := ledger.ready(ctx); err != nil {
		return nil, err
	}
	if err := validateLookupBinding(lookup, ledger.service, ledger.routeDigest); err != nil {
		return nil, err
	}
	if !nativeText(lookup.Operation, 256, false) {
		return nil, ErrInvalidCommand
	}
	return ledger.transact(ctx, keyForLookup(lookup), func(record *entry) (*entry, bool, error) {
		if record != nil && lookup != lookupFor(record.command.Dispatch) {
			return nil, false, ErrBindingMismatch
		}
		return record, false, nil
	})
}

func (ledger *NativeLedger) observation(key attemptKey, digest broker.Digest) Observation {
	return Observation{native: ledger, key: key, service: ledger.service, routeDigest: ledger.routeDigest, commandDigest: digest, seal: observationSeal}
}

func (ledger *NativeLedger) validateObservation(ctx context.Context, observation Observation) error {
	if err := ledger.ready(ctx); err != nil {
		return err
	}
	if observation.seal != observationSeal || observation.native != ledger || observation.store != nil ||
		observation.service != ledger.service || observation.routeDigest != ledger.routeDigest || observation.commandDigest == (broker.Digest{}) {
		return ErrInvalidObservation
	}
	return nil
}

func (ledger *NativeLedger) matchObservation(record *entry, observation Observation) error {
	if record == nil || record.command.CommandDigest != observation.commandDigest ||
		record.command.Dispatch.Service != observation.service || record.command.Dispatch.ProviderRouteDigest != observation.routeDigest || record.state == StatePrepared {
		return ErrInvalidObservation
	}
	return nil
}

func (ledger *NativeLedger) transact(ctx context.Context, key attemptKey, apply func(*entry) (*entry, bool, error)) (*entry, error) {
	objectID, err := nativeObjectID(key)
	if err != nil {
		return nil, err
	}
	var result *entry
	token, err := ledger.storage.Transaction(ctx, objectID, func(tx celld.Transaction) error {
		// A definite CAS conflict may re-evaluate this callback. Never retain an
		// earlier callback's result, especially a fresh provider-start candidate.
		result = nil
		state, err := tx.ReadState()
		if err != nil {
			return err
		}
		var record *entry
		if len(state) != 0 {
			record, err = ledger.decodeEntry(state)
			if err != nil {
				return err
			}
			if keyForDispatch(record.command.Dispatch) != key {
				return celld.ErrStorageContract
			}
			if record.command.Dispatch.Service != ledger.service || record.command.Dispatch.ProviderRouteDigest != ledger.routeDigest {
				return ErrBindingMismatch
			}
		}
		next, changed, err := apply(record)
		if err != nil {
			return err
		}
		if changed {
			encoded, err := ledger.encodeEntry(next)
			if err != nil {
				return err
			}
			if err := tx.WriteState(encoded); err != nil {
				return err
			}
		}
		result = next
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := ledger.storage.DurabilityBarrier(ctx, token); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

var _ Ledger = (*NativeLedger)(nil)
var _ dependency.ProductionProbe = (*NativeLedger)(nil)
