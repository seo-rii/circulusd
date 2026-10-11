package modelgateway

import (
	"context"
	"crypto/sha256"
	"math"
	"reflect"
	"time"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/dependency"
	"github.com/hancomac/circulusd/internal/effectledger"
	"github.com/hancomac/circulusd/internal/identity"
	"github.com/hancomac/circulusd/internal/stateappbroker"
	"google.golang.org/protobuf/proto"
)

type NativeSessionQuotaScope struct{ TenantID, UserID, WorkspaceID, SessionID identity.ID }

type NativeSessionQuotaConfig struct {
	Factory     *NativeFactory
	Session     dependency.Verified[*stateappbroker.Store]
	Ledger      dependency.Verified[*effectledger.NativeLedger]
	Scope       NativeSessionQuotaScope
	RouteDigest broker.Digest
}

func (NativeSessionQuotaConfig) String() string   { return "native-session-quota-config<redacted>" }
func (NativeSessionQuotaConfig) GoString() string { return "native-session-quota-config<redacted>" }

// NativeSessionOperation is a lookup identity, never a caller-supplied receipt.
type NativeSessionOperation struct {
	Kind   broker.OperationKind
	Key    string
	Digest broker.Digest
}

// This immutable receipt acknowledges quota accounting only. It supplies no
// effect, provider-start, retry, cancellation or Session settlement authority.
type NativeSessionQuotaReceipt struct {
	Reservation          QuotaPermit
	Operation            NativeSessionOperation
	Disposition          QuotaDisposition
	Usage                Usage
	SessionEventSequence uint64
	DispatchAttempt      uint64
	ExternalCommitID     identity.ID
	ResultRef            identity.ID
	ProviderRequestID    string
	WitnessDigest        Digest
}

func (NativeSessionQuotaReceipt) String() string   { return "native-session-quota-receipt<redacted>" }
func (NativeSessionQuotaReceipt) GoString() string { return "native-session-quota-receipt<redacted>" }

type nativeSessionQuotaRecord struct {
	Scope                NativeSessionQuotaScope
	RouteDigest          broker.Digest
	Found                bool
	SessionReceiptDigest Digest
	CommandDigest        broker.Digest
	ModelResultDigest    Digest
	Receipt              NativeSessionQuotaReceipt
}

type NativeSessionQuotaBridge struct {
	factory        *NativeFactory
	session        *stateappbroker.Store
	ledger         *effectledger.NativeLedger
	sessionBinding dependency.Verified[*stateappbroker.Store]
	ledgerBinding  dependency.Verified[*effectledger.NativeLedger]
	scope          NativeSessionQuotaScope
	route          broker.Digest
}

func (*NativeSessionQuotaBridge) String() string   { return "native-session-quota-bridge<redacted>" }
func (*NativeSessionQuotaBridge) GoString() string { return "native-session-quota-bridge<redacted>" }

func validNativeSessionScope(scope NativeSessionQuotaScope) bool {
	return scope.TenantID.Kind() == identity.Tenant && scope.UserID.Kind() == identity.Subject && scope.WorkspaceID.Kind() == identity.Workspace && scope.SessionID.Kind() == identity.Session
}

func NewNativeSessionQuotaBridge(config NativeSessionQuotaConfig) (*NativeSessionQuotaBridge, error) {
	if config.Factory == nil || config.Factory.check == nil || config.Factory.check() != nil || !validNativeSessionScope(config.Scope) || config.RouteDigest == (broker.Digest{}) {
		return nil, ErrInvalidConfiguration
	}
	session, _, err := config.Session.Open()
	if err != nil || session == nil {
		return nil, dependency.ErrUnverifiedDependency
	}
	ledger, _, err := config.Ledger.Open()
	if err != nil || ledger == nil || ledger.Service() != broker.ServiceModel || ledger.RouteDigest() != config.RouteDigest {
		return nil, dependency.ErrUnverifiedDependency
	}
	if _, err := dependency.RequireAtomicDomain([]dependency.AtomicGroup{dependency.AtomicCommandReceipt, dependency.AtomicEffectLifecycle}, config.Session); err != nil {
		return nil, err
	}
	if _, err := dependency.RequireAtomicDomain([]dependency.AtomicGroup{dependency.AtomicCommandReceipt, dependency.AtomicEffectLifecycle, effectledger.AtomicProviderObservationLedger}, config.Ledger); err != nil {
		return nil, err
	}
	// Matching native domains do not claim an atomic transaction across objects.
	if _, err := dependency.RequireAtomicDomain([]dependency.AtomicGroup{dependency.AtomicCommandReceipt}, config.Factory.binding, config.Session, config.Ledger); err != nil {
		return nil, err
	}
	required := requiredSessionDispatchLedgerLimits(config.Factory.configuration.Bounds)
	limits := ledger.Limits()
	if limits.MaximumPayloadBytes < required.MaximumPayloadBytes || limits.MaximumResultBytes < required.MaximumResultBytes {
		return nil, ErrInvalidConfiguration
	}
	return &NativeSessionQuotaBridge{factory: config.Factory, session: session, ledger: ledger, sessionBinding: config.Session, ledgerBinding: config.Ledger, scope: config.Scope, route: config.RouteDigest}, nil
}

func (bridge *NativeSessionQuotaBridge) ready(ctx context.Context) error {
	if bridge == nil || bridge.session == nil || bridge.ledger == nil {
		return ErrStateDependenciesNotDurable
	}
	if err := bridge.factory.ready(ctx); err != nil {
		return err
	}
	session, _, err := bridge.sessionBinding.Open()
	if err != nil || session != bridge.session {
		return ErrStateDependenciesNotDurable
	}
	ledger, _, err := bridge.ledgerBinding.Open()
	if err != nil || ledger != bridge.ledger {
		return ErrStateDependenciesNotDurable
	}
	return nil
}

func validNativeSessionOperation(operation NativeSessionOperation) bool {
	return (operation.Kind == broker.OperationSettlement || operation.Kind == broker.OperationRecoverySettlement) &&
		operation.Key != "" && len(operation.Key) <= 256 && identifierPattern.MatchString(operation.Key) && operation.Digest != (broker.Digest{})
}

// Reconcile reads authenticated Session and native terminal facts internally.
// Absence or unsupported recovery retains the reservation; only an exact
// successful terminal receipt or dispatchAttempt=0 failed recovery can change
// accounting. It never invokes a provider or mutates the canonical effect.
func (bridge *NativeSessionQuotaBridge) Reconcile(ctx context.Context, request QuotaRequest, operation NativeSessionOperation) (NativeSessionQuotaReceipt, error) {
	if err := bridge.ready(ctx); err != nil {
		return NativeSessionQuotaReceipt{}, err
	}
	if !validNativeQuotaRequest(request) || !validNativeSessionOperation(operation) || request.TenantID != bridge.scope.TenantID || request.UserID != bridge.scope.UserID || request.SessionID != bridge.scope.SessionID {
		return NativeSessionQuotaReceipt{}, ErrInvalidRequest
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	permit, found, err := bridge.factory.InspectReservation(ctx, request)
	if err != nil {
		return NativeSessionQuotaReceipt{}, err
	}
	if !found {
		return NativeSessionQuotaReceipt{}, ErrQuotaMismatch
	}
	lookup := broker.OperationLookup{Kind: operation.Kind, OperationKey: operation.Key, OperationDigest: operation.Digest, TenantID: bridge.scope.TenantID, WorkspaceID: bridge.scope.WorkspaceID, SessionID: bridge.scope.SessionID}
	observed, err := bridge.session.LookupOperation(ctx, lookup)
	if err != nil {
		return NativeSessionQuotaReceipt{}, ErrStateDependenciesNotDurable
	}
	record := nativeSessionQuotaRecord{Scope: bridge.scope, RouteDigest: bridge.route, Found: observed.Found,
		Receipt: NativeSessionQuotaReceipt{Reservation: permit, Operation: operation, Disposition: QuotaDispositionHold}}
	if observed.Kind != operation.Kind || observed.OperationDigest != operation.Digest {
		return NativeSessionQuotaReceipt{}, ErrAuthorityMismatch
	}
	if observed.Found {
		settlement := observed.Settlement
		if settlement == nil || !bridge.matchesSettlement(request, operation, *settlement) {
			return NativeSessionQuotaReceipt{}, ErrAuthorityMismatch
		}
		record.SessionReceiptDigest, err = nativeSessionReceiptDigest(*settlement)
		if err != nil {
			return NativeSessionQuotaReceipt{}, ErrStateDependenciesNotDurable
		}
		record.Receipt.SessionEventSequence, record.Receipt.DispatchAttempt = settlement.EventSequence, settlement.DispatchAttempt
		record.Receipt.ExternalCommitID, record.Receipt.ResultRef = settlement.ExternalCommitID, settlement.ResultRef
		if operation.Kind == broker.OperationRecoverySettlement && settlement.RecoveryKind == broker.RecoverySettlementFailed && settlement.DispatchAttempt == 0 && settlement.Error != nil {
			if settlement.ExternalCommitID != (identity.ID{}) || settlement.ResultRef != (identity.ID{}) || settlement.Effect.ProviderRequestId != nil {
				return NativeSessionQuotaReceipt{}, ErrAuthorityMismatch
			}
			record.Receipt.Disposition = QuotaDispositionRelease
		} else if operation.Kind == broker.OperationSettlement && settlement.RecoveryKind == "" && settlement.Error == nil {
			if err := bridge.readSuccessfulTerminal(ctx, request, *settlement, &record); err != nil {
				return NativeSessionQuotaReceipt{}, err
			}
		}
	}
	record.Receipt.WitnessDigest, err = nativeSessionQuotaDigest(record, bridge.factory.stateOptions())
	if err != nil {
		return NativeSessionQuotaReceipt{}, ErrStateDependenciesNotDurable
	}
	return nativeModelOperation(ctx, bridge.factory, func(state *nativeModelState) (NativeSessionQuotaReceipt, error) {
		reservation, found := state.Reservations[request.InvocationID.String()]
		if !found || reservation.Request != request || reservation.Permit != permit {
			return NativeSessionQuotaReceipt{}, ErrQuotaConflict
		}
		if previous, found := state.Projections[request.InvocationID.String()]; found {
			if reflect.DeepEqual(previous, record) {
				return previous.Receipt, nil
			}
			if previous.Scope != record.Scope || previous.RouteDigest != record.RouteDigest || previous.Receipt.Disposition != QuotaDispositionHold ||
				record.Receipt.Disposition == QuotaDispositionHold || (previous.Found && record.Receipt.SessionEventSequence <= previous.Receipt.SessionEventSequence) {
				return NativeSessionQuotaReceipt{}, ErrQuotaConflict
			}
		}
		state.Projections[request.InvocationID.String()] = record
		return record.Receipt, nil
	})
}

func (bridge *NativeSessionQuotaBridge) matchesSettlement(request QuotaRequest, operation NativeSessionOperation, receipt broker.SettlementReceipt) bool {
	effect := receipt.Effect
	if !receipt.Durable || receipt.EventSequence == 0 || receipt.State != broker.EffectSettled || receipt.TenantID != bridge.scope.TenantID || receipt.WorkspaceID != bridge.scope.WorkspaceID ||
		receipt.EffectKey != (broker.EffectKey{SessionID: request.SessionID, TurnID: request.TurnID, EffectID: request.EffectID, InvocationID: request.InvocationID, RequestDigest: broker.Digest(request.RequestDigest)}) || receipt.OperationDigest != operation.Digest || effect == nil {
		return false
	}
	return string(effect.TenantId.GetValue()) == request.TenantID.String() && string(effect.UserId.GetValue()) == request.UserID.String() && string(effect.SessionId.GetValue()) == request.SessionID.String() &&
		string(effect.TurnId.GetValue()) == request.TurnID.String() && string(effect.EffectId.GetValue()) == request.EffectID.String() && string(effect.InvocationId.GetValue()) == request.InvocationID.String() &&
		effect.RequestDigest.GetAlgorithm() == v1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256 && bytesDigest(effect.RequestDigest.GetValue(), request.RequestDigest) && effect.Service == v1.EffectService_EFFECT_SERVICE_MODEL && effect.Operation == sessionDispatchOperation &&
		effect.State == v1.EffectState_EFFECT_STATE_SETTLED && effect.DispatchAttempt == receipt.DispatchAttempt && string(effect.ExternalCommitId.GetValue()) == receipt.ExternalCommitID.String() && string(effect.ResultRef.GetValue()) == receipt.ResultRef.String()
}

func bytesDigest(encoded []byte, digest Digest) bool {
	return len(encoded) == len(digest) && reflect.DeepEqual(encoded, digest[:])
}

func (bridge *NativeSessionQuotaBridge) readSuccessfulTerminal(ctx context.Context, request QuotaRequest, settlement broker.SettlementReceipt, record *nativeSessionQuotaRecord) error {
	if settlement.DispatchAttempt == 0 || settlement.DispatchAttempt > math.MaxUint32 || settlement.ExternalCommitID.Kind() != identity.Commit || settlement.ResultRef.Kind() != identity.Artifact {
		return ErrAuthorityMismatch
	}
	providerRequest := identity.ID{}
	if text := string(settlement.Effect.ProviderRequestId.GetValue()); text != "" {
		var err error
		providerRequest, err = identity.Parse(identity.Request, text)
		if err != nil {
			return ErrAuthorityMismatch
		}
	}
	lookup := broker.LedgerLookup{EffectKey: settlement.EffectKey, TenantID: bridge.scope.TenantID, WorkspaceID: bridge.scope.WorkspaceID, Service: broker.ServiceModel, Operation: sessionDispatchOperation,
		DispatchAttempt: settlement.DispatchAttempt, ProviderRequestID: providerRequest, ProviderRouteDigest: bridge.route}
	facts, err := bridge.ledger.Inspect(ctx, lookup)
	if err != nil {
		return ErrStateDependenciesNotDurable
	}
	dispatch := facts.Command.Dispatch
	if facts.State != effectledger.StateTerminal || facts.Terminal.Status != effectledger.TerminalCommitted || facts.Terminal.ExternalCommitID != settlement.ExternalCommitID || facts.Terminal.ResultRef != settlement.ResultRef ||
		dispatch.Service != broker.ServiceModel || dispatch.ProviderRouteDigest != bridge.route || dispatch.UserID != bridge.scope.UserID || dispatch.Ordinal != settlement.Effect.Ordinal ||
		dispatch.Generations.TurnLease != settlement.Effect.TurnLeaseGeneration || dispatch.Generations.Placement != settlement.Effect.PlacementGeneration ||
		dispatch.Generations.Sandbox != settlement.Effect.SandboxGeneration || dispatch.Generations.Authorization != settlement.Effect.AuthorizationGeneration ||
		uint64(dispatch.Deadline.UnixMilli()) != settlement.Effect.DeadlineUnixMs || !nativeSessionReplayPolicy(dispatch.ReplayPolicy, settlement.Effect.ReplayPolicy) ||
		dispatch.ParentOperationID.String()+dispatch.ParentOperation != string(settlement.Effect.ParentOperationId.GetValue()) ||
		sessionDispatchCommandDigest(facts.Command.Payload) != facts.Command.CommandDigest {
		return ErrAuthorityMismatch
	}
	var payload sessionDispatchPayload
	if decodeCanonicalJSON(facts.Command.Payload, &payload) != nil || payload.Version != sessionDispatchCommandVersion || payload.Scope != quotaRequestScope(request) || payload.RequestDigest != request.RequestDigest || payload.QuotaPermit != record.Receipt.Reservation ||
		payload.State != StateDispatching || payload.Revision != uint64(payload.EventCount)+1 || payload.EventCount == 0 || payload.StreamBytes != 0 ||
		dispatch.Generations.TurnLease != payload.Scope.Generations.TurnLease || dispatch.Generations.Placement != payload.Scope.Generations.Placement || dispatch.Generations.Authorization != payload.Scope.Generations.Policy ||
		payload.Attempt != uint32(settlement.DispatchAttempt) || payload.ContextTokens != request.ContextTokens || payload.RequestedOutputTokens != request.OutputTokens {
		return ErrAuthorityMismatch
	}
	result, err := DecodeSessionDispatchResult(facts.Terminal.Result)
	if err != nil || result.State != StateCompleted || result.Outcome != OutcomeCompleted || result.Attempt != payload.Attempt || result.Response == nil ||
		result.Revision <= payload.Revision || result.EventCount <= payload.EventCount ||
		result.ProviderRequestID != facts.ExternalProviderRequestID || result.Response.Usage != (Usage{InputTokens: request.ContextTokens, OutputTokens: request.OutputTokens}) {
		return ErrAuthorityMismatch
	}
	effect := Effect{Scope: payload.Scope, RequestDigest: payload.RequestDigest, Request: payload.Request, ProviderID: payload.ProviderID, QuotaPermit: payload.QuotaPermit, ContextTokens: payload.ContextTokens,
		RequestedOutputTokens: payload.RequestedOutputTokens, MaxContextTokens: payload.MaxContextTokens, MaxTotalTokens: payload.MaxTotalTokens, MaxPreDispatchRetries: payload.MaxPreDispatchRetries, DurableRequestRetrieval: payload.DurableRequestRetrieval,
		State: result.State, Outcome: result.Outcome, Revision: result.Revision, Attempt: result.Attempt, EventCount: result.EventCount, EventBytes: result.EventBytes, StreamBytes: result.StreamBytes, ProviderRequestID: result.ProviderRequestID,
		PartialOutput: result.PartialOutput, FailureReason: result.FailureReason, Response: result.Response}
	validator, err := newGatewayConfiguration(bridge.factory.configuration, bridge.factory.Candidates().Providers)
	if err != nil || validator.validateEffect(effect) != nil {
		return ErrAuthorityMismatch
	}
	record.CommandDigest, record.ModelResultDigest = facts.Command.CommandDigest, sha256.Sum256(facts.Terminal.Result)
	record.Receipt.Disposition, record.Receipt.Usage, record.Receipt.ProviderRequestID = QuotaDispositionConsume, result.Response.Usage, result.ProviderRequestID
	return nil
}

func nativeSessionReplayPolicy(policy broker.ReplayPolicy, wire v1.ReplayPolicy) bool {
	switch policy {
	case broker.ReplaySafe:
		return wire == v1.ReplayPolicy_REPLAY_POLICY_SAFE
	case broker.ReplayIdempotencyKey:
		return wire == v1.ReplayPolicy_REPLAY_POLICY_IDEMPOTENCY_KEY
	case broker.ReplayNever:
		return wire == v1.ReplayPolicy_REPLAY_POLICY_NEVER
	case broker.ReplayConfirm:
		return wire == v1.ReplayPolicy_REPLAY_POLICY_CONFIRM
	}
	return false
}

func nativeSessionReceiptDigest(receipt broker.SettlementReceipt) (Digest, error) {
	var effect, errorBytes []byte
	var err error
	if receipt.Effect != nil {
		effect, err = proto.MarshalOptions{Deterministic: true}.Marshal(receipt.Effect)
		if err != nil {
			return Digest{}, err
		}
	}
	if receipt.Error != nil {
		errorBytes, err = proto.MarshalOptions{Deterministic: true}.Marshal(receipt.Error)
		if err != nil {
			return Digest{}, err
		}
	}
	wire := struct {
		Key               broker.EffectKey
		Tenant, Workspace identity.ID
		State             broker.EffectState
		Attempt           uint64
		Commit, Result    identity.ID
		Error             []byte
		Operation         broker.Digest
		Recovery          broker.RecoverySettlementKind
		Effect            []byte
		Sequence          uint64
		Durable           bool
	}{
		receipt.EffectKey, receipt.TenantID, receipt.WorkspaceID, receipt.State, receipt.DispatchAttempt, receipt.ExternalCommitID, receipt.ResultRef, errorBytes, receipt.OperationDigest, receipt.RecoveryKind, effect, receipt.EventSequence, receipt.Durable}
	value, err := nativeEncodeValue(reflect.ValueOf(wire))
	if err != nil {
		return Digest{}, err
	}
	encoded, err := canonical.Encode(value, canonical.Options{MaxBytes: 64 << 10, MaxDepth: 24, MaxItems: 1024})
	if err != nil {
		return Digest{}, err
	}
	return sha256.Sum256(encoded), nil
}

func nativeSessionQuotaDigest(record nativeSessionQuotaRecord, options canonical.Options) (Digest, error) {
	record.Receipt.WitnessDigest = Digest{}
	value, err := nativeEncodeValue(reflect.ValueOf(record))
	if err != nil {
		return Digest{}, err
	}
	encoded, err := canonical.Encode(value, options)
	if err != nil {
		return Digest{}, err
	}
	return sha256.Sum256(encoded), nil
}

func (factory *NativeFactory) validateProjection(record nativeSessionQuotaRecord, reservation nativeQuotaReservation) error {
	receipt := record.Receipt
	request := reservation.Request
	if !validNativeSessionScope(record.Scope) || record.Scope.TenantID != request.TenantID || record.Scope.UserID != request.UserID || record.Scope.SessionID != request.SessionID ||
		record.RouteDigest == (broker.Digest{}) || receipt.Reservation != reservation.Permit || !validNativeSessionOperation(receipt.Operation) || receipt.WitnessDigest == (Digest{}) {
		return errNativeState
	}
	if record.Found {
		if receipt.SessionEventSequence == 0 || record.SessionReceiptDigest == (Digest{}) {
			return errNativeState
		}
	} else if receipt.SessionEventSequence != 0 || record.SessionReceiptDigest != (Digest{}) || receipt.DispatchAttempt != 0 || receipt.ExternalCommitID != (identity.ID{}) || receipt.ResultRef != (identity.ID{}) {
		return errNativeState
	}
	if receipt.ExternalCommitID != (identity.ID{}) && receipt.ExternalCommitID.Kind() != identity.Commit {
		return errNativeState
	}
	if receipt.ResultRef != (identity.ID{}) && receipt.ResultRef.Kind() != identity.Artifact {
		return errNativeState
	}
	switch receipt.Disposition {
	case QuotaDispositionConsume:
		if !record.Found || receipt.Operation.Kind != broker.OperationSettlement || receipt.DispatchAttempt == 0 || receipt.DispatchAttempt > math.MaxUint32 || receipt.ExternalCommitID.Kind() != identity.Commit || receipt.ResultRef.Kind() != identity.Artifact ||
			receipt.Usage != (Usage{InputTokens: request.ContextTokens, OutputTokens: request.OutputTokens}) || receipt.ProviderRequestID == "" || uint64(len(receipt.ProviderRequestID)) > factory.configuration.Bounds.MaxProviderRequestIDBytes ||
			record.CommandDigest == (broker.Digest{}) || record.ModelResultDigest == (Digest{}) {
			return errNativeState
		}
	case QuotaDispositionRelease:
		if !record.Found || receipt.Operation.Kind != broker.OperationRecoverySettlement || receipt.DispatchAttempt != 0 || receipt.ExternalCommitID != (identity.ID{}) || receipt.ResultRef != (identity.ID{}) {
			return errNativeState
		}
		fallthrough
	case QuotaDispositionHold:
		if receipt.Usage != (Usage{}) || receipt.ProviderRequestID != "" || record.CommandDigest != (broker.Digest{}) || record.ModelResultDigest != (Digest{}) {
			return errNativeState
		}
	default:
		return errNativeState
	}
	digest, err := nativeSessionQuotaDigest(record, factory.stateOptions())
	if err != nil || digest != receipt.WitnessDigest {
		return errNativeState
	}
	return nil
}
