// Package effectledger provides a process-local reference ledger for tests and
// development adapters. It is deliberately not a production durability or
// availability implementation.
package effectledger

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/identity"
)

const (
	maximumReferenceBytes       = 16 << 20
	maximumProviderRequestBytes = 4 << 10
)

var (
	ErrInvalidConfiguration   = errors.New("effect ledger: invalid reference configuration")
	ErrInvalidCommand         = errors.New("effect ledger: invalid command")
	ErrInvalidClaim           = errors.New("effect ledger: invalid claimed dispatch start")
	ErrInvalidObservation     = errors.New("effect ledger: invalid observation handle")
	ErrBindingMismatch        = errors.New("effect ledger: immutable binding mismatch")
	ErrPrepareConflict        = errors.New("effect ledger: prepared command conflict")
	ErrCommandNotPrepared     = errors.New("effect ledger: command not prepared")
	ErrStartAlreadyClaimed    = errors.New("effect ledger: start already claimed")
	ErrObservationUnavailable = errors.New("effect ledger: observation unavailable")
	ErrAcceptanceConflict     = errors.New("effect ledger: provider acceptance conflict")
	ErrTerminalConflict       = errors.New("effect ledger: terminal fact conflict")
	ErrInvalidTransition      = errors.New("effect ledger: invalid fact transition")
	ErrLimitExceeded          = errors.New("effect ledger: configured byte limit exceeded")
	ErrIdentityGeneration     = errors.New("effect ledger: reference identity generation failed")
)

type ReferenceLimits struct {
	MaximumPayloadBytes int
	MaximumResultBytes  int
}

// Command binds opaque service payload bytes to the complete Session dispatch
// identity and its canonical command digest. Prepare validates the incoming
// dispatch proof, then removes it before retaining or returning the command.
type Command struct {
	Dispatch      broker.DispatchPermit
	CommandDigest broker.Digest
	Payload       []byte
}

func (Command) String() string   { return "effect-command<redacted>" }
func (Command) GoString() string { return "effect-command<redacted>" }

type State string

const (
	StatePrepared State = "prepared"
	StateClaimed  State = "claimed"
	StateAccepted State = "accepted"
	StateTerminal State = "terminal"
)

type TerminalStatus string

const (
	TerminalCommitted TerminalStatus = "committed"
	TerminalFailed    TerminalStatus = "failed"
	TerminalUnknown   TerminalStatus = "unknown"
)

// Terminal retains bounded service result bytes in the subordinate reference
// ledger. Lookup exposes only the broker-safe identity projection.
type Terminal struct {
	Status           TerminalStatus
	ExternalCommitID identity.ID
	ResultRef        identity.ID
	Result           []byte
}

func (Terminal) String() string   { return "effect-terminal<redacted>" }
func (Terminal) GoString() string { return "effect-terminal<redacted>" }

type Facts struct {
	State                     State
	Command                   Command
	ExternalProviderRequestID string
	Terminal                  Terminal
}

func (Facts) String() string   { return "effect-facts<redacted>" }
func (Facts) GoString() string { return "effect-facts<redacted>" }

var observationSeal = new(struct{})

// Observation can append facts to one already-claimed command, but it contains
// neither provider-start authority nor command payload. ResumeObservation is
// the only restart-oriented minting path.
type Observation struct {
	store         *ReferenceStore
	key           attemptKey
	service       broker.EffectService
	routeDigest   broker.Digest
	commandDigest broker.Digest
	seal          *struct{}
}

func (Observation) String() string   { return "effect-observation<redacted>" }
func (Observation) GoString() string { return "effect-observation<redacted>" }

var claimedCommandSeal = new(struct{})

// ClaimedCommand is minted only from broker.ClaimedDispatchStart. Open returns
// a defensive copy for one provider invocation.
type ClaimedCommand struct {
	command     Command
	observation Observation
	seal        *struct{}
}

func (claimed ClaimedCommand) Open() (Command, bool) {
	if claimed.seal != claimedCommandSeal || claimed.observation.seal != observationSeal {
		return Command{}, false
	}
	return cloneCommand(claimed.command), true
}

func (claimed ClaimedCommand) Observation() (Observation, bool) {
	if claimed.seal != claimedCommandSeal || claimed.observation.seal != observationSeal {
		return Observation{}, false
	}
	return claimed.observation, true
}

func (ClaimedCommand) String() string   { return "claimed-effect-command<redacted>" }
func (ClaimedCommand) GoString() string { return "claimed-effect-command<redacted>" }

// Ledger is the reference adapter contract consumed by model, MCP, and fake
// effect starters. Implementations must not infer provider-start authority from
// an Observation.
type Ledger interface {
	Prepare(context.Context, Command) error
	ClaimStart(context.Context, broker.ClaimedDispatchStart) (ClaimedCommand, error)
	RecordAccepted(context.Context, Observation, string) error
	RecordTerminal(context.Context, Observation, Terminal) (Terminal, error)
	ResumeObservation(context.Context, broker.LedgerLookup, broker.Digest) (Observation, error)
	Inspect(context.Context, broker.LedgerLookup) (Facts, error)
	Lookup(context.Context, broker.LedgerLookup) (broker.LedgerRecord, error)
}

type IdentityGenerator interface {
	New(identity.Kind) (identity.ID, error)
}

type systemIdentityGenerator struct{}

func (systemIdentityGenerator) New(kind identity.Kind) (identity.ID, error) {
	return identity.New(kind)
}

// ReferenceStore lets multiple reference-ledger objects observe the same
// process-local facts. Sharing it models object reconstruction, not a process
// crash or durable restart.
type ReferenceStore struct {
	mu        sync.RWMutex
	records   map[attemptKey]*entry
	generator IdentityGenerator
}

func NewReferenceStore() *ReferenceStore {
	return &ReferenceStore{records: make(map[attemptKey]*entry), generator: systemIdentityGenerator{}}
}

func (*ReferenceStore) String() string   { return "reference-effect-store<redacted>" }
func (*ReferenceStore) GoString() string { return "reference-effect-store<redacted>" }

func NewReferenceStoreWithGenerator(generator IdentityGenerator) (*ReferenceStore, error) {
	if interfaceNil(generator) {
		return nil, ErrInvalidConfiguration
	}
	return &ReferenceStore{records: make(map[attemptKey]*entry), generator: generator}, nil
}

type ReferenceLedger struct {
	store       *ReferenceStore
	service     broker.EffectService
	routeDigest broker.Digest
	limits      ReferenceLimits
}

func NewReferenceLedger(
	store *ReferenceStore,
	service broker.EffectService,
	routeDigest broker.Digest,
	limits ReferenceLimits,
) (*ReferenceLedger, error) {
	if store == nil || store.records == nil || interfaceNil(store.generator) || !validService(service) ||
		routeDigest == (broker.Digest{}) || limits.MaximumPayloadBytes <= 0 ||
		limits.MaximumPayloadBytes > maximumReferenceBytes || limits.MaximumResultBytes <= 0 ||
		limits.MaximumResultBytes > maximumReferenceBytes {
		return nil, ErrInvalidConfiguration
	}
	return &ReferenceLedger{store: store, service: service, routeDigest: routeDigest, limits: limits}, nil
}

func (ledger *ReferenceLedger) Service() broker.EffectService {
	if ledger == nil {
		return ""
	}
	return ledger.service
}

func (ledger *ReferenceLedger) RouteDigest() broker.Digest {
	if ledger == nil {
		return broker.Digest{}
	}
	return ledger.routeDigest
}

func (*ReferenceLedger) String() string   { return "reference-effect-ledger<redacted>" }
func (*ReferenceLedger) GoString() string { return "reference-effect-ledger<redacted>" }

func (ledger *ReferenceLedger) Prepare(ctx context.Context, command Command) error {
	if err := validateContext(ctx); err != nil {
		return err
	}
	if ledger == nil || ledger.store == nil {
		return ErrInvalidConfiguration
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
	command.Dispatch = dispatchWithoutOpaque(command.Dispatch)
	key := keyForDispatch(command.Dispatch)
	ledger.store.mu.Lock()
	defer ledger.store.mu.Unlock()
	existing, found := ledger.store.records[key]
	if found {
		if sameCommand(existing.command, command) {
			return nil
		}
		return ErrPrepareConflict
	}
	ledger.store.records[key] = &entry{state: StatePrepared, command: cloneCommand(command)}
	return nil
}

func (ledger *ReferenceLedger) ClaimStart(ctx context.Context, claim broker.ClaimedDispatchStart) (ClaimedCommand, error) {
	if err := validateContext(ctx); err != nil {
		return ClaimedCommand{}, err
	}
	if ledger == nil || ledger.store == nil {
		return ClaimedCommand{}, ErrInvalidConfiguration
	}
	start, opened := claim.Open()
	if !opened || start.Opaque == "" || !start.Durable || start.EventSequence == 0 ||
		start.CommandDigest == (broker.Digest{}) {
		return ClaimedCommand{}, ErrInvalidClaim
	}
	if err := validateDispatch(start.Dispatch); err != nil {
		return ClaimedCommand{}, fmt.Errorf("%w: %v", ErrInvalidClaim, err)
	}
	if start.Dispatch.Service != ledger.service || start.Dispatch.ProviderRouteDigest != ledger.routeDigest {
		return ClaimedCommand{}, ErrBindingMismatch
	}
	key := keyForDispatch(start.Dispatch)
	ledger.store.mu.Lock()
	defer ledger.store.mu.Unlock()
	record, found := ledger.store.records[key]
	if !found {
		return ClaimedCommand{}, ErrCommandNotPrepared
	}
	if record.command.Dispatch != dispatchWithoutOpaque(start.Dispatch) || record.command.CommandDigest != start.CommandDigest {
		return ClaimedCommand{}, ErrBindingMismatch
	}
	if record.state != StatePrepared {
		return ClaimedCommand{}, ErrStartAlreadyClaimed
	}
	record.state = StateClaimed
	observation := ledger.observation(key, start.CommandDigest)
	return ClaimedCommand{
		command: cloneCommand(record.command), observation: observation, seal: claimedCommandSeal,
	}, nil
}

func (ledger *ReferenceLedger) RecordAccepted(ctx context.Context, observation Observation, externalProviderRequestID string) error {
	if err := validateContext(ctx); err != nil {
		return err
	}
	if ledger == nil || ledger.store == nil {
		return ErrInvalidConfiguration
	}
	invalidProviderID := externalProviderRequestID == "" || !utf8.ValidString(externalProviderRequestID) ||
		len(externalProviderRequestID) > maximumProviderRequestBytes ||
		strings.TrimSpace(externalProviderRequestID) != externalProviderRequestID
	if !invalidProviderID {
		for _, codePoint := range externalProviderRequestID {
			if unicode.IsControl(codePoint) || unicode.In(codePoint, unicode.Cf) {
				invalidProviderID = true
				break
			}
		}
	}
	if invalidProviderID {
		return ErrInvalidCommand
	}
	ledger.store.mu.Lock()
	defer ledger.store.mu.Unlock()
	record, err := ledger.recordForObservationLocked(observation)
	if err != nil {
		return err
	}
	if record.externalProviderRequestID != "" {
		if record.externalProviderRequestID == externalProviderRequestID {
			return nil
		}
		return ErrAcceptanceConflict
	}
	if record.state != StateClaimed {
		return ErrInvalidTransition
	}
	record.externalProviderRequestID = externalProviderRequestID
	record.state = StateAccepted
	return nil
}

func (ledger *ReferenceLedger) RecordTerminal(ctx context.Context, observation Observation, terminal Terminal) (Terminal, error) {
	if err := validateContext(ctx); err != nil {
		return Terminal{}, err
	}
	if ledger == nil || ledger.store == nil {
		return Terminal{}, ErrInvalidConfiguration
	}
	if len(terminal.Result) > ledger.limits.MaximumResultBytes {
		return Terminal{}, ErrLimitExceeded
	}
	if err := validateTerminal(terminal); err != nil {
		return Terminal{}, err
	}
	ledger.store.mu.Lock()
	defer ledger.store.mu.Unlock()
	record, err := ledger.recordForObservationLocked(observation)
	if err != nil {
		return Terminal{}, err
	}
	if record.terminal != nil {
		if terminalReplays(*record.terminal, terminal) {
			return cloneTerminal(*record.terminal), nil
		}
		return Terminal{}, ErrTerminalConflict
	}
	if record.state != StateClaimed && record.state != StateAccepted {
		return Terminal{}, ErrInvalidTransition
	}
	if terminal.Status == TerminalCommitted && record.state != StateAccepted {
		return Terminal{}, ErrInvalidTransition
	}
	normalized := cloneTerminal(terminal)
	if normalized.Status == TerminalCommitted && normalized.ExternalCommitID == (identity.ID{}) {
		normalized.ExternalCommitID, err = ledger.store.generator.New(identity.Commit)
		if err != nil || normalized.ExternalCommitID.Kind() != identity.Commit {
			return Terminal{}, ErrIdentityGeneration
		}
	}
	if normalized.Status == TerminalCommitted && len(normalized.Result) != 0 && normalized.ResultRef == (identity.ID{}) {
		normalized.ResultRef, err = ledger.store.generator.New(identity.Artifact)
		if err != nil || normalized.ResultRef.Kind() != identity.Artifact {
			return Terminal{}, ErrIdentityGeneration
		}
	}
	record.terminal = &normalized
	record.state = StateTerminal
	return cloneTerminal(normalized), nil
}

func (ledger *ReferenceLedger) ResumeObservation(
	ctx context.Context,
	lookup broker.LedgerLookup,
	commandDigest broker.Digest,
) (Observation, error) {
	if err := validateContext(ctx); err != nil {
		return Observation{}, err
	}
	if ledger == nil || ledger.store == nil {
		return Observation{}, ErrInvalidConfiguration
	}
	if err := ledger.validateLookup(lookup); err != nil {
		return Observation{}, err
	}
	if commandDigest == (broker.Digest{}) {
		return Observation{}, ErrBindingMismatch
	}
	key := keyForLookup(lookup)
	ledger.store.mu.RLock()
	defer ledger.store.mu.RUnlock()
	record, found := ledger.store.records[key]
	if !found || record.state == StatePrepared {
		return Observation{}, ErrObservationUnavailable
	}
	if lookup != lookupFor(record.command.Dispatch) || record.command.CommandDigest != commandDigest {
		return Observation{}, ErrBindingMismatch
	}
	return ledger.observation(key, commandDigest), nil
}

func (ledger *ReferenceLedger) Inspect(ctx context.Context, lookup broker.LedgerLookup) (Facts, error) {
	if err := validateContext(ctx); err != nil {
		return Facts{}, err
	}
	if ledger == nil || ledger.store == nil {
		return Facts{}, ErrInvalidConfiguration
	}
	if err := ledger.validateLookup(lookup); err != nil {
		return Facts{}, err
	}
	ledger.store.mu.RLock()
	defer ledger.store.mu.RUnlock()
	record, found := ledger.store.records[keyForLookup(lookup)]
	if !found {
		return Facts{}, ErrObservationUnavailable
	}
	if lookup != lookupFor(record.command.Dispatch) {
		return Facts{}, ErrBindingMismatch
	}
	facts := Facts{
		State: record.state, Command: cloneCommand(record.command),
		ExternalProviderRequestID: record.externalProviderRequestID,
	}
	if record.terminal != nil {
		facts.Terminal = cloneTerminal(*record.terminal)
	}
	return facts, nil
}

// Lookup implements broker.InvocationLedger and repeats the complete supplied
// identity even when no command has been prepared.
func (ledger *ReferenceLedger) Lookup(ctx context.Context, lookup broker.LedgerLookup) (broker.LedgerRecord, error) {
	if err := validateContext(ctx); err != nil {
		return broker.LedgerRecord{}, err
	}
	if ledger == nil || ledger.store == nil {
		return broker.LedgerRecord{}, ErrInvalidConfiguration
	}
	if err := ledger.validateLookup(lookup); err != nil {
		return broker.LedgerRecord{}, err
	}
	result := ledgerRecord(lookup, broker.LedgerAbsent)
	ledger.store.mu.RLock()
	defer ledger.store.mu.RUnlock()
	record, found := ledger.store.records[keyForLookup(lookup)]
	if !found {
		return result, nil
	}
	if lookup != lookupFor(record.command.Dispatch) {
		return broker.LedgerRecord{}, ErrBindingMismatch
	}
	switch record.state {
	case StatePrepared:
		result.Status = broker.LedgerAbsent
	case StateClaimed, StateAccepted:
		result.Status = broker.LedgerInflight
	case StateTerminal:
		if record.terminal == nil {
			return broker.LedgerRecord{}, ErrInvalidTransition
		}
		switch record.terminal.Status {
		case TerminalCommitted:
			result.Status = broker.LedgerCommitted
			result.ExternalCommitID = record.terminal.ExternalCommitID
			result.ResultRef = record.terminal.ResultRef
		case TerminalFailed:
			result.Status = broker.LedgerFailed
		case TerminalUnknown:
			result.Status = broker.LedgerUnknown
		default:
			return broker.LedgerRecord{}, ErrInvalidTransition
		}
	default:
		return broker.LedgerRecord{}, ErrInvalidTransition
	}
	return result, nil
}

type attemptKey struct {
	sessionID       identity.ID
	turnID          identity.ID
	effectID        identity.ID
	invocationID    identity.ID
	dispatchAttempt uint64
}

type entry struct {
	state                     State
	command                   Command
	externalProviderRequestID string
	terminal                  *Terminal
}

func (ledger *ReferenceLedger) observation(key attemptKey, commandDigest broker.Digest) Observation {
	return Observation{
		store: ledger.store, key: key, service: ledger.service, routeDigest: ledger.routeDigest,
		commandDigest: commandDigest, seal: observationSeal,
	}
}

func (ledger *ReferenceLedger) recordForObservationLocked(observation Observation) (*entry, error) {
	if observation.seal != observationSeal || observation.store != ledger.store ||
		observation.service != ledger.service || observation.routeDigest != ledger.routeDigest ||
		observation.commandDigest == (broker.Digest{}) {
		return nil, ErrInvalidObservation
	}
	record, found := ledger.store.records[observation.key]
	if !found || record.command.CommandDigest != observation.commandDigest ||
		record.command.Dispatch.Service != observation.service ||
		record.command.Dispatch.ProviderRouteDigest != observation.routeDigest {
		return nil, ErrInvalidObservation
	}
	return record, nil
}

func (ledger *ReferenceLedger) validateLookup(lookup broker.LedgerLookup) error {
	if lookup.TenantID.Kind() != identity.Tenant || lookup.WorkspaceID.Kind() != identity.Workspace ||
		lookup.SessionID.Kind() != identity.Session || lookup.TurnID.Kind() != identity.Turn ||
		lookup.EffectID.Kind() != identity.Effect || lookup.InvocationID.Kind() != identity.Invocation ||
		lookup.RequestDigest == (broker.Digest{}) || !validService(lookup.Service) ||
		lookup.Operation == "" || lookup.DispatchAttempt == 0 ||
		(lookup.ProviderRequestID != (identity.ID{}) && lookup.ProviderRequestID.Kind() != identity.Request) ||
		lookup.ProviderRouteDigest == (broker.Digest{}) {
		return ErrInvalidCommand
	}
	if lookup.Service != ledger.service || lookup.ProviderRouteDigest != ledger.routeDigest {
		return ErrBindingMismatch
	}
	return nil
}

func validateContext(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidCommand
	}
	return ctx.Err()
}

func validateCommand(command Command) error {
	if command.CommandDigest == (broker.Digest{}) {
		return ErrInvalidCommand
	}
	return validateDispatch(command.Dispatch)
}

func validateDispatch(dispatch broker.DispatchPermit) error {
	if dispatch.SessionID.Kind() != identity.Session || dispatch.TurnID.Kind() != identity.Turn ||
		dispatch.EffectID.Kind() != identity.Effect || dispatch.InvocationID.Kind() != identity.Invocation ||
		dispatch.RequestDigest == (broker.Digest{}) || dispatch.Opaque == "" ||
		dispatch.TenantID.Kind() != identity.Tenant || dispatch.WorkspaceID.Kind() != identity.Workspace ||
		dispatch.UserID.Kind() != identity.Subject || !validService(dispatch.Service) || dispatch.Operation == "" ||
		(dispatch.ParentOperationID != (identity.ID{}) && dispatch.ParentOperationID.Kind() != identity.Operation) ||
		dispatch.Ordinal == 0 || !validReplayPolicy(dispatch.ReplayPolicy) ||
		dispatch.Generations.TurnLease == 0 || dispatch.Generations.Placement == 0 ||
		dispatch.Generations.Sandbox == 0 || dispatch.Generations.Authorization == 0 ||
		dispatch.DispatchAttempt == 0 ||
		(dispatch.ProviderRequestID != (identity.ID{}) && dispatch.ProviderRequestID.Kind() != identity.Request) ||
		dispatch.ProviderRouteDigest == (broker.Digest{}) || dispatch.Deadline.IsZero() ||
		dispatch.EventSequence == 0 || !dispatch.Durable {
		return ErrInvalidCommand
	}
	return nil
}

func validateTerminal(terminal Terminal) error {
	switch terminal.Status {
	case TerminalCommitted:
		if len(terminal.Result) == 0 && terminal.ResultRef == (identity.ID{}) {
			return ErrInvalidCommand
		}
		if terminal.ExternalCommitID != (identity.ID{}) && terminal.ExternalCommitID.Kind() != identity.Commit {
			return ErrInvalidCommand
		}
		if terminal.ResultRef != (identity.ID{}) && terminal.ResultRef.Kind() != identity.Artifact {
			return ErrInvalidCommand
		}
	case TerminalFailed, TerminalUnknown:
		if terminal.ExternalCommitID != (identity.ID{}) || terminal.ResultRef != (identity.ID{}) {
			return ErrInvalidCommand
		}
	default:
		return ErrInvalidCommand
	}
	return nil
}

func validService(service broker.EffectService) bool {
	switch service {
	case broker.ServiceModel, broker.ServiceWorkspace, broker.ServiceExecutor, broker.ServiceMCP,
		broker.ServiceArtifact, broker.ServiceExternalTool:
		return true
	default:
		return false
	}
}

func validReplayPolicy(policy broker.ReplayPolicy) bool {
	switch policy {
	case broker.ReplaySafe, broker.ReplayIdempotencyKey, broker.ReplayNever, broker.ReplayConfirm:
		return true
	default:
		return false
	}
}

func dispatchWithoutOpaque(dispatch broker.DispatchPermit) broker.DispatchPermit {
	dispatch.Opaque = ""
	return dispatch
}

func interfaceNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func keyForDispatch(dispatch broker.DispatchPermit) attemptKey {
	return attemptKey{
		sessionID: dispatch.SessionID, turnID: dispatch.TurnID, effectID: dispatch.EffectID,
		invocationID: dispatch.InvocationID, dispatchAttempt: dispatch.DispatchAttempt,
	}
}

func keyForLookup(lookup broker.LedgerLookup) attemptKey {
	return attemptKey{
		sessionID: lookup.SessionID, turnID: lookup.TurnID, effectID: lookup.EffectID,
		invocationID: lookup.InvocationID, dispatchAttempt: lookup.DispatchAttempt,
	}
}

func lookupFor(dispatch broker.DispatchPermit) broker.LedgerLookup {
	return broker.LedgerLookup{
		EffectKey: dispatch.EffectKey, TenantID: dispatch.TenantID, WorkspaceID: dispatch.WorkspaceID,
		Service: dispatch.Service, Operation: dispatch.Operation, DispatchAttempt: dispatch.DispatchAttempt,
		ProviderRequestID: dispatch.ProviderRequestID, ProviderRouteDigest: dispatch.ProviderRouteDigest,
	}
}

func ledgerRecord(lookup broker.LedgerLookup, status broker.LedgerStatus) broker.LedgerRecord {
	return broker.LedgerRecord{
		Status: status, TenantID: lookup.TenantID, WorkspaceID: lookup.WorkspaceID,
		EffectID: lookup.EffectID, InvocationID: lookup.InvocationID, RequestDigest: lookup.RequestDigest,
		Service: lookup.Service, Operation: lookup.Operation, DispatchAttempt: lookup.DispatchAttempt,
		ProviderRequestID: lookup.ProviderRequestID, ProviderRouteDigest: lookup.ProviderRouteDigest,
	}
}

func cloneCommand(command Command) Command {
	command.Payload = append([]byte(nil), command.Payload...)
	return command
}

func sameCommand(left, right Command) bool {
	return left.Dispatch == right.Dispatch && left.CommandDigest == right.CommandDigest &&
		bytes.Equal(left.Payload, right.Payload)
}

func cloneTerminal(terminal Terminal) Terminal {
	terminal.Result = append([]byte(nil), terminal.Result...)
	return terminal
}

func terminalReplays(stored, requested Terminal) bool {
	if stored.Status != requested.Status || !bytes.Equal(stored.Result, requested.Result) {
		return false
	}
	if requested.ExternalCommitID != (identity.ID{}) && stored.ExternalCommitID != requested.ExternalCommitID {
		return false
	}
	if requested.ResultRef != (identity.ID{}) && stored.ResultRef != requested.ResultRef {
		return false
	}
	return true
}
