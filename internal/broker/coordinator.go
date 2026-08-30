package broker

import (
	"bytes"
	"context"
	"fmt"
	"time"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/identity"
	"google.golang.org/protobuf/proto"
)

// Coordinator is immutable after construction. Concurrent correctness is
// anchored in DurableStore's atomic compare-and-commit methods, not local
// process locks that disappear during placement changes or crashes.
type Coordinator struct {
	store  DurableStore
	ledger InvocationLedger
}

func NewCoordinator(store DurableStore, ledger InvocationLedger) (*Coordinator, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: durable store is required", ErrInvalidRequest)
	}
	return &Coordinator{store: store, ledger: ledger}, nil
}

func (coordinator *Coordinator) AcquireEngineStep(ctx context.Context, request EngineStepRequest) (EngineStepPermit, error) {
	if err := ctx.Err(); err != nil {
		return EngineStepPermit{}, err
	}
	if request.Now.IsZero() || request.OperationKey == "" || request.Budget.MaximumEvents == 0 || request.Budget.MaximumEphemeralBytes == 0 || request.Budget.MaximumWallClock <= 0 {
		return EngineStepPermit{}, ErrInvalidRequest
	}
	snapshot, err := coordinator.store.ReadTurn(ctx, request.Authority.SessionID)
	if err != nil {
		return EngineStepPermit{}, fmt.Errorf("read turn for engine step: %w", err)
	}
	if err := validateTurn(snapshot, request.Authority); err != nil {
		return EngineStepPermit{}, err
	}
	if !request.Now.Before(request.Authority.ExpiresAt) {
		return EngineStepPermit{}, ErrAdmissionExpired
	}
	if !request.Now.Before(snapshot.LeaseExpiresAt) {
		return EngineStepPermit{}, ErrLeaseExpired
	}
	if snapshot.AbortRequested {
		return EngineStepPermit{}, fmt.Errorf("%w: abort has been requested", ErrInvalidEffectState)
	}
	if snapshot.ActiveEffect != nil && snapshot.ActiveEffect.State != EffectSettled {
		return EngineStepPermit{}, ErrEffectInFlight
	}
	budget := request.Budget
	budget.MaximumEvents = 1
	if budget.MaximumEphemeralBytes > snapshot.EngineStepLimits.MaximumEphemeralBytes {
		budget.MaximumEphemeralBytes = snapshot.EngineStepLimits.MaximumEphemeralBytes
	}
	if budget.MaximumWallClock > snapshot.EngineStepLimits.MaximumWallClock {
		budget.MaximumWallClock = snapshot.EngineStepLimits.MaximumWallClock
	}
	if remaining := request.Authority.ExpiresAt.Sub(request.Now); budget.MaximumWallClock > remaining {
		budget.MaximumWallClock = remaining
	}
	if remaining := snapshot.LeaseExpiresAt.Sub(request.Now); budget.MaximumWallClock > remaining {
		budget.MaximumWallClock = remaining
	}
	deadline := request.Now.Add(budget.MaximumWallClock)
	permit, err := coordinator.store.AcquireEngineStep(ctx, AcquireStepCommand{
		Snapshot: snapshot, Now: request.Now, Budget: budget, OperationKey: request.OperationKey,
	})
	if err != nil {
		return EngineStepPermit{}, fmt.Errorf("acquire durable engine step: %w", err)
	}
	if !permit.Durable {
		return EngineStepPermit{}, ErrDurabilityBarrier
	}
	if permit.Opaque == "" || permit.TenantID != snapshot.TenantID || permit.WorkspaceID != snapshot.WorkspaceID || permit.UserID != snapshot.UserID || permit.OperationKey != request.OperationKey || permit.SessionID != snapshot.SessionID || permit.TurnID != snapshot.TurnID || permit.Generations != snapshot.Generations || permit.ExpectedEventSequence != snapshot.EventSequence || permit.CheckpointDigest != snapshot.CheckpointDigest || permit.Budget != budget || !permit.Deadline.Equal(deadline) {
		return EngineStepPermit{}, fmt.Errorf("%w: invalid engine-step receipt", ErrFenceMismatch)
	}
	if !proto.Equal(permit.Checkpoint, snapshot.Checkpoint) || !proto.Equal(permit.UnconsumedSettlement, snapshot.UnconsumedSettlement) {
		return EngineStepPermit{}, fmt.Errorf("%w: invalid engine resume context", ErrFenceMismatch)
	}
	return permit, nil
}

func (coordinator *Coordinator) CommitEngineStep(ctx context.Context, request EngineStepCommit) (EngineStepReceipt, error) {
	if err := ctx.Err(); err != nil {
		return EngineStepReceipt{}, err
	}
	if !request.Permit.Durable || request.Permit.Opaque == "" || request.Permit.TenantID.Kind() != identity.Tenant || request.Permit.WorkspaceID.Kind() != identity.Workspace || request.Permit.UserID.Kind() != identity.Subject || request.Permit.Deadline.IsZero() || request.Now.IsZero() || !request.Now.Before(request.Permit.Deadline) || request.OperationKey == "" || request.RequestDigest == (Digest{}) {
		return EngineStepReceipt{}, ErrInvalidRequest
	}
	if request.Boundary.CheckpointDigest == (Digest{}) {
		return EngineStepReceipt{}, ErrInvalidRequest
	}
	if request.Boundary.Message != nil && (request.Boundary.Kind != "" || request.Boundary.Effect != nil) {
		return EngineStepReceipt{}, ErrInvalidRequest
	}
	if request.Boundary.Message != nil {
		if request.Boundary.Message.Checkpoint == nil || request.Boundary.Message.Boundary == nil {
			return EngineStepReceipt{}, ErrInvalidRequest
		}
		switch boundary := request.Boundary.Message.Boundary.(type) {
		case *v1.EngineStepBoundary_CheckpointOnly:
			if boundary.CheckpointOnly == nil {
				return EngineStepReceipt{}, ErrInvalidRequest
			}
		case *v1.EngineStepBoundary_EffectRequest:
			if boundary.EffectRequest == nil || boundary.EffectRequest.Service == v1.EffectService_EFFECT_SERVICE_UNSPECIFIED || boundary.EffectRequest.Operation == "" || boundary.EffectRequest.ReplayPolicy == v1.ReplayPolicy_REPLAY_POLICY_UNSPECIFIED || boundary.EffectRequest.RequestDigest == nil {
				return EngineStepReceipt{}, ErrInvalidRequest
			}
		case *v1.EngineStepBoundary_TurnComplete:
			if boundary.TurnComplete == nil {
				return EngineStepReceipt{}, ErrInvalidRequest
			}
		case *v1.EngineStepBoundary_TurnError:
			if boundary.TurnError == nil {
				return EngineStepReceipt{}, ErrInvalidRequest
			}
		default:
			return EngineStepReceipt{}, ErrInvalidRequest
		}
	} else {
		switch request.Boundary.Kind {
		case BoundaryEffectRequest:
			if request.Boundary.Effect == nil || request.Boundary.Effect.RequestDigest == (Digest{}) || request.Boundary.Effect.Operation == "" || !validService(request.Boundary.Effect.Service) {
				return EngineStepReceipt{}, ErrInvalidRequest
			}
			switch request.Boundary.Effect.ReplayPolicy {
			case ReplaySafe, ReplayIdempotencyKey, ReplayNever, ReplayConfirm:
			default:
				return EngineStepReceipt{}, ErrInvalidRequest
			}
		case BoundaryCheckpoint, BoundaryTurnComplete, BoundaryTurnError:
			if request.Boundary.Effect != nil {
				return EngineStepReceipt{}, ErrInvalidRequest
			}
		default:
			return EngineStepReceipt{}, ErrInvalidRequest
		}
	}
	snapshot, err := coordinator.store.ReadTurn(ctx, request.Permit.SessionID)
	if err != nil {
		return EngineStepReceipt{}, fmt.Errorf("read turn for engine commit: %w", err)
	}
	if snapshot.TenantID.Kind() != identity.Tenant || snapshot.WorkspaceID.Kind() != identity.Workspace {
		return EngineStepReceipt{}, ErrInvalidRequest
	}
	if snapshot.SessionID != request.Permit.SessionID || snapshot.TurnID != request.Permit.TurnID || snapshot.Generations != request.Permit.Generations {
		return EngineStepReceipt{}, ErrStaleGeneration
	}
	if snapshot.TenantID != request.Permit.TenantID || snapshot.WorkspaceID != request.Permit.WorkspaceID || snapshot.UserID != request.Permit.UserID {
		return EngineStepReceipt{}, ErrFenceMismatch
	}
	receipt, err := coordinator.store.CommitEngineStep(ctx, CommitStepCommand{
		Snapshot: snapshot, Permit: request.Permit, Now: request.Now, OperationKey: request.OperationKey,
		RequestDigest: request.RequestDigest, Boundary: request.Boundary,
	})
	if err != nil {
		return EngineStepReceipt{}, fmt.Errorf("commit engine boundary: %w", err)
	}
	if !receipt.Durable {
		return EngineStepReceipt{}, ErrDurabilityBarrier
	}
	if receipt.OperationKey != request.OperationKey || receipt.EventSequence == 0 {
		return EngineStepReceipt{}, fmt.Errorf("%w: engine receipt operation", ErrFenceMismatch)
	}
	isEffectBoundary := request.Boundary.Message != nil && request.Boundary.Message.GetEffectRequest() != nil || request.Boundary.Message == nil && request.Boundary.Kind == BoundaryEffectRequest
	if isEffectBoundary != (receipt.PreparedEffect != nil && receipt.PreparationPermit != nil) {
		return EngineStepReceipt{}, fmt.Errorf("%w: prepared effect response", ErrFenceMismatch)
	}
	if isEffectBoundary {
		preparation := receipt.PreparationPermit
		var expectedService EffectService
		var expectedOperation string
		var expectedReplayPolicy ReplayPolicy
		var expectedRequestDigest Digest
		if request.Boundary.Effect != nil {
			expectedService = request.Boundary.Effect.Service
			expectedOperation = request.Boundary.Effect.Operation
			expectedReplayPolicy = request.Boundary.Effect.ReplayPolicy
			expectedRequestDigest = request.Boundary.Effect.RequestDigest
		}
		if intent := request.Boundary.Message.GetEffectRequest(); intent != nil {
			expectedOperation = intent.Operation
			if len(intent.RequestDigest.Value) == len(expectedRequestDigest) {
				copy(expectedRequestDigest[:], intent.RequestDigest.Value)
			}
			switch intent.Service {
			case v1.EffectService_EFFECT_SERVICE_MODEL:
				expectedService = ServiceModel
			case v1.EffectService_EFFECT_SERVICE_WORKSPACE:
				expectedService = ServiceWorkspace
			case v1.EffectService_EFFECT_SERVICE_EXECUTOR:
				expectedService = ServiceExecutor
			case v1.EffectService_EFFECT_SERVICE_MCP:
				expectedService = ServiceMCP
			case v1.EffectService_EFFECT_SERVICE_ARTIFACT:
				expectedService = ServiceArtifact
			case v1.EffectService_EFFECT_SERVICE_EXTERNAL_TOOL:
				expectedService = ServiceExternalTool
			}
			switch intent.ReplayPolicy {
			case v1.ReplayPolicy_REPLAY_POLICY_SAFE:
				expectedReplayPolicy = ReplaySafe
			case v1.ReplayPolicy_REPLAY_POLICY_IDEMPOTENCY_KEY:
				expectedReplayPolicy = ReplayIdempotencyKey
			case v1.ReplayPolicy_REPLAY_POLICY_NEVER:
				expectedReplayPolicy = ReplayNever
			case v1.ReplayPolicy_REPLAY_POLICY_CONFIRM:
				expectedReplayPolicy = ReplayConfirm
			}
		}
		if preparation.Opaque == "" || preparation.SessionID != snapshot.SessionID || preparation.TurnID != snapshot.TurnID || preparation.EffectID.Kind() != identity.Effect || preparation.InvocationID.Kind() != identity.Invocation || preparation.RequestDigest != expectedRequestDigest || preparation.TenantID != snapshot.TenantID || preparation.WorkspaceID != snapshot.WorkspaceID || preparation.UserID != snapshot.UserID || preparation.Service != expectedService || preparation.Operation != expectedOperation || preparation.ReplayPolicy != expectedReplayPolicy || preparation.Generations != snapshot.Generations || preparation.DispatchAttempt != 1 || preparation.Deadline.IsZero() || preparation.EventSequence != receipt.EventSequence || !preparation.Durable || receipt.PreparedEffect.State != v1.EffectState_EFFECT_STATE_PREPARED || receipt.PreparedEffect.DispatchAttempt != 0 || !bytes.Equal(receipt.PreparedEffect.TenantId.GetValue(), []byte(preparation.TenantID.String())) || !bytes.Equal(receipt.PreparedEffect.UserId.GetValue(), []byte(preparation.UserID.String())) || !bytes.Equal(receipt.PreparedEffect.SessionId.GetValue(), []byte(preparation.SessionID.String())) || !bytes.Equal(receipt.PreparedEffect.TurnId.GetValue(), []byte(preparation.TurnID.String())) || !bytes.Equal(receipt.PreparedEffect.EffectId.GetValue(), []byte(preparation.EffectID.String())) || !bytes.Equal(receipt.PreparedEffect.InvocationId.GetValue(), []byte(preparation.InvocationID.String())) || receipt.PreparedEffect.RequestDigest == nil || !bytes.Equal(receipt.PreparedEffect.RequestDigest.Value, preparation.RequestDigest[:]) || receipt.PreparedEffect.Operation != preparation.Operation || receipt.PreparedEffect.TurnLeaseGeneration != preparation.Generations.TurnLease || receipt.PreparedEffect.PlacementGeneration != preparation.Generations.Placement || receipt.PreparedEffect.SandboxGeneration != preparation.Generations.Sandbox || receipt.PreparedEffect.AuthorizationGeneration != preparation.Generations.Authorization || receipt.PreparedEffect.DeadlineUnixMs != uint64(preparation.Deadline.UnixMilli()) {
			return EngineStepReceipt{}, fmt.Errorf("%w: invalid preparation receipt", ErrFenceMismatch)
		}
	}
	return receipt, nil
}

func (coordinator *Coordinator) AdmitDispatch(ctx context.Context, request DispatchRequest) (DispatchPermit, error) {
	if err := ctx.Err(); err != nil {
		return DispatchPermit{}, err
	}
	if request.Now.IsZero() || request.Deadline.IsZero() || !request.Now.Before(request.Deadline) || request.Deadline.After(request.Authority.ExpiresAt) || request.OperationKey == "" || request.OperationDigest == (Digest{}) || request.RequestDigest == (Digest{}) || request.Operation == "" || !validService(request.Service) {
		return DispatchPermit{}, ErrInvalidRequest
	}
	if request.ProviderRequestID != (identity.ID{}) && request.ProviderRequestID.Kind() != identity.Request {
		return DispatchPermit{}, ErrInvalidRequest
	}
	snapshot, effect, key, err := coordinator.readAndFenceEffect(ctx, request.Authority, request.Now, request.EffectID, request.InvocationID, request.RequestDigest, true)
	if err != nil {
		return DispatchPermit{}, err
	}
	if effect.Service != request.Service || effect.Operation != request.Operation {
		return DispatchPermit{}, ErrFenceMismatch
	}
	if effect.State != EffectPrepared && effect.State != EffectDispatched {
		return DispatchPermit{}, ErrInvalidEffectState
	}
	replay, err := coordinator.store.LookupOperation(ctx, OperationLookup{Kind: OperationDispatch, OperationKey: request.OperationKey, OperationDigest: request.OperationDigest, TenantID: request.Authority.TenantID, WorkspaceID: request.Authority.WorkspaceID, SessionID: request.Authority.SessionID})
	if err != nil {
		return DispatchPermit{}, fmt.Errorf("lookup dispatch receipt: %w", err)
	}
	if replay.Found {
		if replay.Kind != OperationDispatch || replay.OperationDigest != request.OperationDigest || replay.Dispatch == nil || !replay.Dispatch.Durable || replay.Dispatch.EventSequence == 0 || replay.Dispatch.EffectKey != key || replay.Dispatch.Opaque == "" || replay.Dispatch.TenantID != snapshot.TenantID || replay.Dispatch.WorkspaceID != snapshot.WorkspaceID || replay.Dispatch.TenantID != request.PreparationPermit.TenantID || replay.Dispatch.WorkspaceID != request.PreparationPermit.WorkspaceID || replay.Dispatch.UserID != request.PreparationPermit.UserID || replay.Dispatch.Service != request.Service || replay.Dispatch.Operation != request.Operation || replay.Dispatch.ParentOperationID != request.PreparationPermit.ParentOperationID || replay.Dispatch.Ordinal != request.PreparationPermit.Ordinal || replay.Dispatch.ReplayPolicy != request.PreparationPermit.ReplayPolicy || replay.Dispatch.Generations != request.Authority.Generations || replay.Dispatch.DispatchAttempt != request.PreparationPermit.DispatchAttempt || replay.Dispatch.ProviderRequestID != request.ProviderRequestID || !replay.Dispatch.Deadline.Equal(request.Deadline) {
			return DispatchPermit{}, fmt.Errorf("%w: invalid replayed dispatch receipt", ErrFenceMismatch)
		}
		if err := coordinator.validateCurrentDispatchReplay(ctx, request.Authority, request.Now, *replay.Dispatch); err != nil {
			return DispatchPermit{}, err
		}
		return *replay.Dispatch, nil
	}
	if effect.State != EffectPrepared {
		return DispatchPermit{}, ErrInvalidEffectState
	}
	if request.PreparationPermit.EffectKey != key || request.PreparationPermit.Opaque == "" || !request.PreparationPermit.Durable || request.PreparationPermit.EventSequence == 0 || request.PreparationPermit.TenantID != snapshot.TenantID || request.PreparationPermit.WorkspaceID != snapshot.WorkspaceID || request.PreparationPermit.UserID != snapshot.UserID || request.PreparationPermit.Service != effect.Service || request.PreparationPermit.Operation != effect.Operation || request.PreparationPermit.ParentOperationID != effect.ParentOperationID || request.PreparationPermit.Ordinal != effect.Ordinal || request.PreparationPermit.ReplayPolicy != effect.ReplayPolicy || request.PreparationPermit.Generations != snapshot.Generations || request.PreparationPermit.DispatchAttempt != effect.DispatchAttempt+1 || !request.PreparationPermit.Deadline.Equal(request.Deadline) {
		return DispatchPermit{}, ErrFenceMismatch
	}
	permit, err := coordinator.store.MarkDispatched(ctx, MarkDispatchedCommand{
		Snapshot: snapshot, Key: key, Service: request.Service, Operation: request.Operation, OperationKey: request.OperationKey,
		OperationDigest: request.OperationDigest, PreparationPermit: request.PreparationPermit,
		ProviderRequestID: request.ProviderRequestID, Now: request.Now, Deadline: request.Deadline,
	})
	if err != nil {
		return DispatchPermit{}, fmt.Errorf("mark effect dispatched: %w", err)
	}
	if !permit.Durable {
		return DispatchPermit{}, ErrDurabilityBarrier
	}
	if permit.EffectKey != key || permit.Opaque == "" || permit.EventSequence == 0 || permit.TenantID != snapshot.TenantID || permit.WorkspaceID != snapshot.WorkspaceID || permit.UserID != snapshot.UserID || permit.Service != request.Service || permit.Operation != request.Operation || permit.ParentOperationID != effect.ParentOperationID || permit.Ordinal != effect.Ordinal || permit.ReplayPolicy != effect.ReplayPolicy || permit.Generations != snapshot.Generations || permit.DispatchAttempt != request.PreparationPermit.DispatchAttempt || permit.ProviderRequestID != request.ProviderRequestID || !permit.Deadline.Equal(request.Deadline) {
		return DispatchPermit{}, fmt.Errorf("%w: invalid dispatch permit", ErrFenceMismatch)
	}
	if err := coordinator.validateCurrentDispatchReplay(ctx, request.Authority, request.Now, permit); err != nil {
		return DispatchPermit{}, err
	}
	return permit, nil
}

func (coordinator *Coordinator) ConfirmExternalCommit(ctx context.Context, request ConfirmationRequest) (ConfirmationReceipt, error) {
	if err := ctx.Err(); err != nil {
		return ConfirmationReceipt{}, err
	}
	if request.Now.IsZero() || request.OperationKey == "" || request.OperationDigest == (Digest{}) || request.RequestDigest == (Digest{}) || !validService(request.Service) || request.Operation == "" || request.DispatchAttempt == 0 || request.ProviderRequestID != (identity.ID{}) && request.ProviderRequestID.Kind() != identity.Request {
		return ConfirmationReceipt{}, ErrInvalidRequest
	}
	if !validAuthorityRoute(request.Authority) {
		return ConfirmationReceipt{}, ErrFenceMismatch
	}
	replay, err := coordinator.store.LookupOperation(ctx, OperationLookup{Kind: OperationConfirmation, OperationKey: request.OperationKey, OperationDigest: request.OperationDigest, TenantID: request.Authority.TenantID, WorkspaceID: request.Authority.WorkspaceID, SessionID: request.Authority.SessionID})
	if err != nil {
		return ConfirmationReceipt{}, fmt.Errorf("lookup confirmation receipt: %w", err)
	}
	if replay.Found {
		key := EffectKey{SessionID: request.Authority.SessionID, TurnID: request.Authority.TurnID, EffectID: request.EffectID, InvocationID: request.InvocationID, RequestDigest: request.RequestDigest}
		if replay.Kind != OperationConfirmation || replay.OperationDigest != request.OperationDigest || replay.Confirmation == nil || !replay.Confirmation.Durable || replay.Confirmation.EventSequence == 0 || replay.Confirmation.EffectKey != key || replay.Confirmation.TenantID != request.Authority.TenantID || replay.Confirmation.WorkspaceID != request.Authority.WorkspaceID || replay.Confirmation.Service != request.Service || replay.Confirmation.Operation != request.Operation || replay.Confirmation.DispatchAttempt != request.DispatchAttempt || replay.Confirmation.ProviderRequestID != request.ProviderRequestID || replay.Confirmation.ExternalCommitID.Kind() != identity.Commit || replay.Confirmation.ResultRef != (identity.ID{}) && replay.Confirmation.ResultRef.Kind() != identity.Artifact || replay.Confirmation.OperationDigest != request.OperationDigest {
			return ConfirmationReceipt{}, fmt.Errorf("%w: invalid replayed confirmation receipt", ErrFenceMismatch)
		}
		return *replay.Confirmation, nil
	}
	if coordinator.ledger == nil {
		return ConfirmationReceipt{}, ErrLedgerUnavailable
	}
	snapshot, effect, key, err := coordinator.readAndFenceEffect(ctx, request.Authority, request.Now, request.EffectID, request.InvocationID, request.RequestDigest, false)
	if err != nil {
		return ConfirmationReceipt{}, err
	}
	if effect.State != EffectDispatched && effect.State != EffectBlocked && effect.State != EffectExternallyCommitted {
		return ConfirmationReceipt{}, ErrInvalidEffectState
	}
	if request.Service != effect.Service || request.Operation != effect.Operation {
		return ConfirmationReceipt{}, ErrFenceMismatch
	}
	if effect.LastDispatch == nil || request.DispatchAttempt != effect.DispatchAttempt || request.DispatchAttempt != effect.LastDispatch.DispatchAttempt || request.ProviderRequestID != effect.LastDispatch.ProviderRequestID {
		return ConfirmationReceipt{}, ErrFenceMismatch
	}
	lookup := LedgerLookup{EffectKey: key, TenantID: snapshot.TenantID, WorkspaceID: snapshot.WorkspaceID, Service: effect.Service, Operation: effect.Operation, DispatchAttempt: request.DispatchAttempt, ProviderRequestID: effect.LastDispatch.ProviderRequestID}
	record, err := coordinator.ledger.Lookup(ctx, lookup)
	if err != nil {
		return ConfirmationReceipt{}, fmt.Errorf("lookup invocation ledger: %w", err)
	}
	if err := validateLedgerRoute(record, lookup); err != nil {
		return ConfirmationReceipt{}, err
	}
	if err := validateCommittedRecord(record, lookup); err != nil {
		return ConfirmationReceipt{}, err
	}
	receipt, err := coordinator.store.MarkExternallyCommitted(ctx, MarkExternalCommand{
		Snapshot: snapshot, Key: key, Record: record, DispatchAttempt: request.DispatchAttempt, OperationKey: request.OperationKey, OperationDigest: request.OperationDigest,
	})
	if err != nil {
		return ConfirmationReceipt{}, fmt.Errorf("mark effect externally committed: %w", err)
	}
	if !receipt.Durable {
		return ConfirmationReceipt{}, ErrDurabilityBarrier
	}
	if err := validateConfirmationReceipt(receipt, key, record, request.OperationDigest); err != nil {
		return ConfirmationReceipt{}, err
	}
	return receipt, nil
}

func (coordinator *Coordinator) SettleEffect(ctx context.Context, request SettlementRequest) (SettlementReceipt, error) {
	if err := ctx.Err(); err != nil {
		return SettlementReceipt{}, err
	}
	if request.Now.IsZero() || request.OperationKey == "" || request.RequestDigest == (Digest{}) || request.SettlementDigest == (Digest{}) || request.ExternalCommitID.Kind() != identity.Commit || request.ResultRef != (identity.ID{}) && request.ResultRef.Kind() != identity.Artifact || (request.ResultRef == (identity.ID{})) == (request.Error == nil) {
		return SettlementReceipt{}, ErrInvalidRequest
	}
	if !validAuthorityRoute(request.Authority) {
		return SettlementReceipt{}, ErrFenceMismatch
	}
	replay, err := coordinator.store.LookupOperation(ctx, OperationLookup{Kind: OperationSettlement, OperationKey: request.OperationKey, OperationDigest: request.SettlementDigest, TenantID: request.Authority.TenantID, WorkspaceID: request.Authority.WorkspaceID, SessionID: request.Authority.SessionID})
	if err != nil {
		return SettlementReceipt{}, fmt.Errorf("lookup settlement receipt: %w", err)
	}
	if replay.Found {
		key := EffectKey{SessionID: request.Authority.SessionID, TurnID: request.Authority.TurnID, EffectID: request.EffectID, InvocationID: request.InvocationID, RequestDigest: request.RequestDigest}
		if replay.Kind != OperationSettlement || replay.OperationDigest != request.SettlementDigest || replay.Settlement == nil || !replay.Settlement.Durable || replay.Settlement.EventSequence == 0 || replay.Settlement.EffectKey != key || replay.Settlement.TenantID != request.Authority.TenantID || replay.Settlement.WorkspaceID != request.Authority.WorkspaceID || replay.Settlement.State != EffectSettled || replay.Settlement.DispatchAttempt != request.DispatchAttempt || replay.Settlement.ExternalCommitID != request.ExternalCommitID || replay.Settlement.ResultRef != request.ResultRef || !proto.Equal(replay.Settlement.Error, request.Error) || replay.Settlement.OperationDigest != request.SettlementDigest || replay.Settlement.RecoveryKind != "" || replay.Settlement.Effect == nil {
			return SettlementReceipt{}, fmt.Errorf("%w: invalid replayed settlement receipt", ErrFenceMismatch)
		}
		return *replay.Settlement, nil
	}
	snapshot, effect, key, err := coordinator.readAndFenceEffect(ctx, request.Authority, request.Now, request.EffectID, request.InvocationID, request.RequestDigest, false)
	if err != nil {
		return SettlementReceipt{}, err
	}
	if effect.State != EffectExternallyCommitted && effect.State != EffectSettled {
		return SettlementReceipt{}, ErrInvalidEffectState
	}
	if request.DispatchAttempt == 0 || effect.LastDispatch == nil || request.DispatchAttempt != effect.DispatchAttempt || request.DispatchAttempt != effect.LastDispatch.DispatchAttempt {
		return SettlementReceipt{}, ErrFenceMismatch
	}
	if effect.ExternalCommitID != request.ExternalCommitID || effect.ResultRef != request.ResultRef {
		return SettlementReceipt{}, ErrFenceMismatch
	}
	receipt, err := coordinator.store.SettleEffect(ctx, SettleCommand{
		Snapshot: snapshot, Key: key, ExternalCommitID: request.ExternalCommitID, ResultRef: request.ResultRef, Error: request.Error, DispatchAttempt: request.DispatchAttempt,
		OperationKey: request.OperationKey, SettlementDigest: request.SettlementDigest,
	})
	if err != nil {
		return SettlementReceipt{}, fmt.Errorf("settle effect: %w", err)
	}
	if !receipt.Durable {
		return SettlementReceipt{}, ErrDurabilityBarrier
	}
	if receipt.EffectKey != key || receipt.TenantID != snapshot.TenantID || receipt.WorkspaceID != snapshot.WorkspaceID || receipt.EventSequence == 0 || receipt.State != EffectSettled || receipt.DispatchAttempt != request.DispatchAttempt || receipt.ExternalCommitID != request.ExternalCommitID || receipt.ResultRef != request.ResultRef || !proto.Equal(receipt.Error, request.Error) || receipt.OperationDigest != request.SettlementDigest || receipt.RecoveryKind != "" || receipt.Effect == nil {
		return SettlementReceipt{}, fmt.Errorf("%w: invalid settlement receipt", ErrFenceMismatch)
	}
	return receipt, nil
}

func (coordinator *Coordinator) RecoverEffect(ctx context.Context, request RecoveryRequest) (RecoveryDecision, error) {
	if err := ctx.Err(); err != nil {
		return RecoveryDecision{}, err
	}
	if request.Now.IsZero() || request.OperationKey == "" || request.OperationDigest == (Digest{}) || request.RequestDigest == (Digest{}) {
		return RecoveryDecision{}, ErrInvalidRequest
	}
	if !validAuthorityRoute(request.Authority) {
		return RecoveryDecision{}, ErrFenceMismatch
	}
	requestedKey := EffectKey{SessionID: request.Authority.SessionID, TurnID: request.Authority.TurnID, EffectID: request.EffectID, InvocationID: request.InvocationID, RequestDigest: request.RequestDigest}
	dispatchReplay, err := coordinator.store.LookupOperation(ctx, OperationLookup{Kind: OperationDispatch, OperationKey: request.OperationKey, OperationDigest: request.OperationDigest, TenantID: request.Authority.TenantID, WorkspaceID: request.Authority.WorkspaceID, SessionID: request.Authority.SessionID})
	if err != nil {
		return RecoveryDecision{}, fmt.Errorf("lookup recovery dispatch receipt: %w", err)
	}
	if dispatchReplay.Found {
		permit := dispatchReplay.Dispatch
		if dispatchReplay.Kind != OperationDispatch || dispatchReplay.OperationDigest != request.OperationDigest || permit == nil || !permit.Durable || permit.EventSequence == 0 || permit.EffectKey != requestedKey || permit.Opaque == "" || permit.TenantID != request.Authority.TenantID || permit.WorkspaceID != request.Authority.WorkspaceID || permit.UserID.Kind() != identity.Subject || permit.Generations != request.Authority.Generations || permit.DispatchAttempt == 0 || permit.ProviderRequestID != request.ProviderRequestID || !permit.Deadline.Equal(request.Deadline) || !validService(permit.Service) || !validReplayPolicy(permit.ReplayPolicy) || permit.Operation == "" {
			return RecoveryDecision{}, fmt.Errorf("%w: invalid replayed recovery dispatch receipt", ErrFenceMismatch)
		}
		if err := coordinator.validateCurrentDispatchReplay(ctx, request.Authority, request.Now, *permit); err != nil {
			return RecoveryDecision{}, err
		}
		return RecoveryDecision{Action: RecoveryReplay, EffectKey: requestedKey, ReplayPolicy: permit.ReplayPolicy, DispatchAttempt: permit.DispatchAttempt, DispatchPermit: permit}, nil
	}
	settlementReplay, err := coordinator.store.LookupOperation(ctx, OperationLookup{Kind: OperationRecoverySettlement, OperationKey: request.OperationKey, OperationDigest: request.OperationDigest, TenantID: request.Authority.TenantID, WorkspaceID: request.Authority.WorkspaceID, SessionID: request.Authority.SessionID})
	if err != nil {
		return RecoveryDecision{}, fmt.Errorf("lookup recovery settlement receipt: %w", err)
	}
	if settlementReplay.Found {
		receipt := settlementReplay.Settlement
		if settlementReplay.Kind != OperationRecoverySettlement || settlementReplay.OperationDigest != request.OperationDigest || receipt == nil || receipt.EffectKey != requestedKey || receipt.TenantID != request.Authority.TenantID || receipt.WorkspaceID != request.Authority.WorkspaceID || !receipt.Durable || receipt.EventSequence == 0 || receipt.State != EffectSettled || receipt.ExternalCommitID != (identity.ID{}) || receipt.ResultRef != (identity.ID{}) || !proto.Equal(receipt.Error, request.Reason) || receipt.OperationDigest != request.OperationDigest || receipt.Effect == nil {
			return RecoveryDecision{}, fmt.Errorf("%w: invalid replayed recovery settlement receipt", ErrFenceMismatch)
		}
		action := RecoverySettleInterrupted
		if receipt.RecoveryKind == RecoverySettlementFailed {
			action = RecoverySettleFailed
		} else if receipt.RecoveryKind != RecoverySettlementInterrupted {
			return RecoveryDecision{}, fmt.Errorf("%w: invalid replayed recovery settlement kind", ErrFenceMismatch)
		}
		return RecoveryDecision{Action: action, EffectKey: requestedKey, DispatchAttempt: receipt.DispatchAttempt, SettlementReceipt: receipt}, nil
	}
	blockReplay, err := coordinator.store.LookupOperation(ctx, OperationLookup{Kind: OperationBlock, OperationKey: request.OperationKey, OperationDigest: request.OperationDigest, TenantID: request.Authority.TenantID, WorkspaceID: request.Authority.WorkspaceID, SessionID: request.Authority.SessionID})
	if err != nil {
		return RecoveryDecision{}, fmt.Errorf("lookup recovery block receipt: %w", err)
	}
	if blockReplay.Found {
		receipt := blockReplay.Block
		if blockReplay.Kind != OperationBlock || blockReplay.OperationDigest != request.OperationDigest || receipt == nil || receipt.EffectKey != requestedKey || receipt.TenantID != request.Authority.TenantID || receipt.WorkspaceID != request.Authority.WorkspaceID || !receipt.Durable || receipt.EventSequence == 0 || receipt.State != EffectBlocked || receipt.ReplayPolicy != ReplayConfirm || receipt.DispatchAttempt == 0 || receipt.OperationDigest != request.OperationDigest || !proto.Equal(receipt.Reason, request.Reason) {
			return RecoveryDecision{}, fmt.Errorf("%w: invalid replayed block receipt", ErrFenceMismatch)
		}
		return RecoveryDecision{Action: RecoveryNeedsConfirmation, EffectKey: requestedKey, ReplayPolicy: ReplayConfirm, DispatchAttempt: receipt.DispatchAttempt, BlockReceipt: receipt}, nil
	}
	snapshot, effect, key, err := coordinator.readAndFenceEffect(ctx, request.Authority, request.Now, request.EffectID, request.InvocationID, request.RequestDigest, false)
	if err != nil {
		return RecoveryDecision{}, err
	}
	decision := RecoveryDecision{EffectKey: key, ReplayPolicy: effect.ReplayPolicy, DispatchAttempt: effect.DispatchAttempt}
	switch effect.State {
	case EffectPrepared:
		if snapshot.AbortRequested {
			receipt, err := coordinator.store.SettleRecovery(ctx, SettleRecoveryCommand{Snapshot: snapshot, Key: key, OperationKey: request.OperationKey, OperationDigest: request.OperationDigest, Kind: RecoverySettlementInterrupted, Error: request.Reason})
			if err != nil {
				return RecoveryDecision{}, fmt.Errorf("settle aborted prepared effect: %w", err)
			}
			if !validRecoverySettlementReceipt(receipt, key, snapshot.TenantID, snapshot.WorkspaceID, effect.DispatchAttempt, request.OperationDigest, RecoverySettlementInterrupted, request.Reason) {
				return RecoveryDecision{}, fmt.Errorf("%w: invalid abort settlement receipt", ErrFenceMismatch)
			}
			decision.Action = RecoverySettleInterrupted
			decision.SettlementReceipt = &receipt
			return decision, nil
		}
		decision.Action = RecoveryDispatch
		decision.PreparationPermit = effect.PreparationPermit
		return decision, nil
	case EffectExternallyCommitted:
		decision.Action = RecoverySettleOnly
		decision.ExternalCommitID = effect.ExternalCommitID
		decision.ResultRef = effect.ResultRef
		return decision, nil
	case EffectSettled:
		decision.Action = RecoveryNone
		return decision, nil
	case EffectBlocked:
		if snapshot.AbortRequested {
			receipt, err := coordinator.store.SettleRecovery(ctx, SettleRecoveryCommand{Snapshot: snapshot, Key: key, OperationKey: request.OperationKey, OperationDigest: request.OperationDigest, Kind: RecoverySettlementInterrupted, Error: request.Reason})
			if err != nil {
				return RecoveryDecision{}, fmt.Errorf("settle aborted blocked effect: %w", err)
			}
			if !validRecoverySettlementReceipt(receipt, key, snapshot.TenantID, snapshot.WorkspaceID, effect.DispatchAttempt, request.OperationDigest, RecoverySettlementInterrupted, request.Reason) {
				return RecoveryDecision{}, fmt.Errorf("%w: invalid blocked abort settlement receipt", ErrFenceMismatch)
			}
			decision.Action = RecoverySettleInterrupted
			decision.SettlementReceipt = &receipt
			return decision, nil
		}
		if request.UserConfirmed && effect.ReplayPolicy == ReplayConfirm && !snapshot.AbortRequested {
			if request.Deadline.IsZero() || !request.Now.Before(request.Deadline) || !request.Now.Before(request.Authority.ExpiresAt) || request.Deadline.After(request.Authority.ExpiresAt) {
				return RecoveryDecision{}, ErrAdmissionExpired
			}
			if !request.Now.Before(snapshot.LeaseExpiresAt) || request.Deadline.After(snapshot.LeaseExpiresAt) {
				return RecoveryDecision{}, ErrLeaseExpired
			}
			if request.ProviderRequestID != (identity.ID{}) && request.ProviderRequestID.Kind() != identity.Request {
				return RecoveryDecision{}, ErrInvalidRequest
			}
			preparation, err := coordinator.store.PrepareRetry(ctx, PrepareRetryCommand{Snapshot: snapshot, Key: key, OperationKey: request.OperationKey + ":prepare", OperationDigest: request.OperationDigest, Now: request.Now, Deadline: request.Deadline, UserConfirmed: true})
			if err != nil {
				return RecoveryDecision{}, fmt.Errorf("prepare confirmed retry: %w", err)
			}
			if preparation.EffectKey != key || preparation.Opaque == "" || !preparation.Durable || preparation.EventSequence == 0 || preparation.TenantID != snapshot.TenantID || preparation.WorkspaceID != snapshot.WorkspaceID || preparation.UserID != snapshot.UserID || preparation.Service != effect.Service || preparation.Operation != effect.Operation || preparation.ParentOperationID != effect.ParentOperationID || preparation.Ordinal != effect.Ordinal || preparation.ReplayPolicy != effect.ReplayPolicy || preparation.DispatchAttempt != effect.DispatchAttempt+1 || preparation.Generations != snapshot.Generations || !preparation.Deadline.Equal(request.Deadline) {
				return RecoveryDecision{}, fmt.Errorf("%w: invalid retry preparation", ErrFenceMismatch)
			}
			permit, err := coordinator.store.MarkDispatched(ctx, MarkDispatchedCommand{Snapshot: snapshot, Key: key, Service: effect.Service, Operation: effect.Operation, OperationKey: request.OperationKey, OperationDigest: request.OperationDigest, PreparationPermit: preparation, ProviderRequestID: request.ProviderRequestID, Now: request.Now, Deadline: request.Deadline})
			if err != nil {
				return RecoveryDecision{}, fmt.Errorf("dispatch confirmed retry: %w", err)
			}
			if permit.EffectKey != key || permit.Opaque == "" || !permit.Durable || permit.EventSequence == 0 || permit.TenantID != snapshot.TenantID || permit.WorkspaceID != snapshot.WorkspaceID || permit.UserID != snapshot.UserID || permit.Service != effect.Service || permit.Operation != effect.Operation || permit.ParentOperationID != effect.ParentOperationID || permit.Ordinal != effect.Ordinal || permit.ReplayPolicy != effect.ReplayPolicy || permit.Generations != snapshot.Generations || permit.DispatchAttempt != preparation.DispatchAttempt || permit.ProviderRequestID != request.ProviderRequestID || !permit.Deadline.Equal(request.Deadline) {
				return RecoveryDecision{}, fmt.Errorf("%w: invalid confirmed retry permit", ErrFenceMismatch)
			}
			decision.Action = RecoveryReplay
			decision.PreparationPermit = &preparation
			decision.DispatchPermit = &permit
		} else {
			decision.Action = RecoveryAwaitConfirmation
		}
		return decision, nil
	case EffectDispatched:
		if coordinator.ledger == nil {
			return RecoveryDecision{}, ErrLedgerUnavailable
		}
		lookup := LedgerLookup{EffectKey: decision.EffectKey, TenantID: snapshot.TenantID, WorkspaceID: snapshot.WorkspaceID, Service: effect.Service, Operation: effect.Operation, DispatchAttempt: effect.DispatchAttempt, ProviderRequestID: effect.LastDispatch.ProviderRequestID}
		record, err := coordinator.ledger.Lookup(ctx, lookup)
		if err != nil {
			return RecoveryDecision{}, fmt.Errorf("lookup invocation ledger for recovery: %w", err)
		}
		if err := validateLedgerRoute(record, lookup); err != nil {
			return RecoveryDecision{}, err
		}
		if record.Status == LedgerCommitted {
			if err := validateCommittedRecord(record, lookup); err != nil {
				return RecoveryDecision{}, err
			}
			receipt, err := coordinator.store.MarkExternallyCommitted(ctx, MarkExternalCommand{
				Snapshot: snapshot, Key: decision.EffectKey, Record: record, DispatchAttempt: effect.DispatchAttempt, OperationKey: request.OperationKey, OperationDigest: request.OperationDigest,
			})
			if err != nil {
				return RecoveryDecision{}, fmt.Errorf("recover external commit: %w", err)
			}
			if !receipt.Durable {
				return RecoveryDecision{}, ErrDurabilityBarrier
			}
			if err := validateConfirmationReceipt(receipt, decision.EffectKey, record, request.OperationDigest); err != nil {
				return RecoveryDecision{}, err
			}
			decision.Action = RecoverySettleOnly
			decision.ExternalCommitID = record.ExternalCommitID
			decision.ResultRef = record.ResultRef
			return decision, nil
		}
		if record.Status == LedgerInflight || record.Status == LedgerFailed {
			if record.EffectID != lookup.EffectID ||
				record.InvocationID != lookup.InvocationID ||
				record.RequestDigest != lookup.RequestDigest ||
				record.Service != lookup.Service ||
				record.Operation != lookup.Operation ||
				record.DispatchAttempt != lookup.DispatchAttempt ||
				record.ProviderRequestID != lookup.ProviderRequestID ||
				record.ExternalCommitID != (identity.ID{}) ||
				record.ResultRef != (identity.ID{}) {
				return RecoveryDecision{}, ErrLedgerMismatch
			}
		}
		if record.Status == LedgerInflight {
			decision.Action = RecoveryWaitExternal
			return decision, nil
		}
		if record.Status == LedgerFailed {
			receipt, err := coordinator.store.SettleRecovery(ctx, SettleRecoveryCommand{Snapshot: snapshot, Key: key, OperationKey: request.OperationKey, OperationDigest: request.OperationDigest, Kind: RecoverySettlementFailed, Error: request.Reason})
			if err != nil {
				return RecoveryDecision{}, fmt.Errorf("settle failed effect: %w", err)
			}
			if !validRecoverySettlementReceipt(receipt, key, snapshot.TenantID, snapshot.WorkspaceID, effect.DispatchAttempt, request.OperationDigest, RecoverySettlementFailed, request.Reason) {
				return RecoveryDecision{}, fmt.Errorf("%w: invalid failed settlement receipt", ErrFenceMismatch)
			}
			decision.Action = RecoverySettleFailed
			decision.SettlementReceipt = &receipt
			return decision, nil
		}
		if record.Status != LedgerAbsent && record.Status != LedgerUnknown {
			return RecoveryDecision{}, fmt.Errorf("%w: invalid ledger status %q", ErrLedgerMismatch, record.Status)
		}
		switch effect.ReplayPolicy {
		case ReplaySafe, ReplayIdempotencyKey:
			if snapshot.AbortRequested {
				receipt, err := coordinator.store.SettleRecovery(ctx, SettleRecoveryCommand{Snapshot: snapshot, Key: key, OperationKey: request.OperationKey, OperationDigest: request.OperationDigest, Kind: RecoverySettlementInterrupted, Error: request.Reason})
				if err != nil {
					return RecoveryDecision{}, fmt.Errorf("settle aborted dispatched effect: %w", err)
				}
				if !validRecoverySettlementReceipt(receipt, key, snapshot.TenantID, snapshot.WorkspaceID, effect.DispatchAttempt, request.OperationDigest, RecoverySettlementInterrupted, request.Reason) {
					return RecoveryDecision{}, fmt.Errorf("%w: invalid abort recovery receipt", ErrFenceMismatch)
				}
				decision.Action = RecoverySettleInterrupted
				decision.SettlementReceipt = &receipt
				break
			}
			if request.Deadline.IsZero() || !request.Now.Before(request.Deadline) || !request.Now.Before(request.Authority.ExpiresAt) || request.Deadline.After(request.Authority.ExpiresAt) {
				return RecoveryDecision{}, ErrAdmissionExpired
			}
			if !request.Now.Before(snapshot.LeaseExpiresAt) || request.Deadline.After(snapshot.LeaseExpiresAt) {
				return RecoveryDecision{}, ErrLeaseExpired
			}
			if request.ProviderRequestID != (identity.ID{}) && request.ProviderRequestID.Kind() != identity.Request {
				return RecoveryDecision{}, ErrInvalidRequest
			}
			preparation, err := coordinator.store.PrepareRetry(ctx, PrepareRetryCommand{Snapshot: snapshot, Key: key, OperationKey: request.OperationKey + ":prepare", OperationDigest: request.OperationDigest, Now: request.Now, Deadline: request.Deadline})
			if err != nil {
				return RecoveryDecision{}, fmt.Errorf("prepare effect retry: %w", err)
			}
			if preparation.EffectKey != key || preparation.Opaque == "" || !preparation.Durable || preparation.EventSequence == 0 || preparation.TenantID != snapshot.TenantID || preparation.WorkspaceID != snapshot.WorkspaceID || preparation.UserID != snapshot.UserID || preparation.Service != effect.Service || preparation.Operation != effect.Operation || preparation.ParentOperationID != effect.ParentOperationID || preparation.Ordinal != effect.Ordinal || preparation.ReplayPolicy != effect.ReplayPolicy || preparation.DispatchAttempt != effect.DispatchAttempt+1 || preparation.Generations != snapshot.Generations || !preparation.Deadline.Equal(request.Deadline) {
				return RecoveryDecision{}, fmt.Errorf("%w: invalid retry preparation", ErrFenceMismatch)
			}
			permit, err := coordinator.store.MarkDispatched(ctx, MarkDispatchedCommand{Snapshot: snapshot, Key: key, Service: effect.Service, Operation: effect.Operation, OperationKey: request.OperationKey, OperationDigest: request.OperationDigest, PreparationPermit: preparation, ProviderRequestID: request.ProviderRequestID, Now: request.Now, Deadline: request.Deadline})
			if err != nil {
				return RecoveryDecision{}, fmt.Errorf("dispatch effect retry: %w", err)
			}
			if permit.EffectKey != key || permit.Opaque == "" || !permit.Durable || permit.EventSequence == 0 || permit.TenantID != snapshot.TenantID || permit.WorkspaceID != snapshot.WorkspaceID || permit.UserID != snapshot.UserID || permit.Service != effect.Service || permit.Operation != effect.Operation || permit.ParentOperationID != effect.ParentOperationID || permit.Ordinal != effect.Ordinal || permit.ReplayPolicy != effect.ReplayPolicy || permit.Generations != snapshot.Generations || permit.DispatchAttempt != preparation.DispatchAttempt || permit.ProviderRequestID != request.ProviderRequestID || !permit.Deadline.Equal(request.Deadline) {
				return RecoveryDecision{}, fmt.Errorf("%w: invalid retry dispatch permit", ErrFenceMismatch)
			}
			decision.Action = RecoveryReplay
			decision.PreparationPermit = &preparation
			decision.DispatchPermit = &permit
		case ReplayNever:
			receipt, err := coordinator.store.SettleRecovery(ctx, SettleRecoveryCommand{Snapshot: snapshot, Key: key, OperationKey: request.OperationKey, OperationDigest: request.OperationDigest, Kind: RecoverySettlementInterrupted, Error: request.Reason})
			if err != nil {
				return RecoveryDecision{}, fmt.Errorf("settle interrupted effect: %w", err)
			}
			if !validRecoverySettlementReceipt(receipt, key, snapshot.TenantID, snapshot.WorkspaceID, effect.DispatchAttempt, request.OperationDigest, RecoverySettlementInterrupted, request.Reason) {
				return RecoveryDecision{}, fmt.Errorf("%w: invalid recovery settlement receipt", ErrFenceMismatch)
			}
			decision.Action = RecoverySettleInterrupted
			decision.SettlementReceipt = &receipt
		case ReplayConfirm:
			receipt, err := coordinator.store.BlockEffect(ctx, BlockCommand{Snapshot: snapshot, Key: decision.EffectKey, OperationKey: request.OperationKey, OperationDigest: request.OperationDigest, Reason: request.Reason})
			if err != nil {
				return RecoveryDecision{}, fmt.Errorf("block uncertain effect: %w", err)
			}
			if !receipt.Durable {
				return RecoveryDecision{}, ErrDurabilityBarrier
			}
			if receipt.EffectKey != decision.EffectKey || receipt.TenantID != snapshot.TenantID || receipt.WorkspaceID != snapshot.WorkspaceID || receipt.EventSequence == 0 || receipt.State != EffectBlocked || receipt.ReplayPolicy != effect.ReplayPolicy || receipt.DispatchAttempt != effect.DispatchAttempt || receipt.OperationDigest != request.OperationDigest || !proto.Equal(receipt.Reason, request.Reason) {
				return RecoveryDecision{}, fmt.Errorf("%w: invalid block receipt", ErrFenceMismatch)
			}
			decision.Action = RecoveryNeedsConfirmation
			decision.BlockReceipt = &receipt
		default:
			return RecoveryDecision{}, ErrInvalidRequest
		}
		return decision, nil
	default:
		return RecoveryDecision{}, ErrInvalidEffectState
	}
}

func (coordinator *Coordinator) validateCurrentDispatchReplay(ctx context.Context, authority ValidatedTurnFence, now time.Time, permit DispatchPermit) error {
	snapshot, effect, key, err := coordinator.readAndFenceEffect(
		ctx,
		authority,
		now,
		permit.EffectID,
		permit.InvocationID,
		permit.RequestDigest,
		false,
	)
	if err != nil {
		return err
	}
	if snapshot.AbortRequested || effect.State != EffectDispatched || effect.LastDispatch == nil {
		return ErrInvalidEffectState
	}
	if permit.EffectKey != key ||
		permit.TenantID != snapshot.TenantID ||
		permit.WorkspaceID != snapshot.WorkspaceID ||
		permit.UserID != snapshot.UserID ||
		permit.Service != effect.Service ||
		permit.Operation != effect.Operation ||
		permit.ParentOperationID != effect.ParentOperationID ||
		permit.Ordinal != effect.Ordinal ||
		permit.ReplayPolicy != effect.ReplayPolicy ||
		permit.Generations != snapshot.Generations ||
		permit.DispatchAttempt != effect.DispatchAttempt ||
		permit.DispatchAttempt != effect.LastDispatch.DispatchAttempt ||
		permit.ProviderRequestID != effect.LastDispatch.ProviderRequestID ||
		!permit.Deadline.Equal(effect.LastDispatch.Deadline) {
		return ErrFenceMismatch
	}
	return nil
}

func (coordinator *Coordinator) readAndFenceEffect(ctx context.Context, authority ValidatedTurnFence, now time.Time, effectID, invocationID identity.ID, requestDigest Digest, newAdmission bool) (TurnSnapshot, *EffectSnapshot, EffectKey, error) {
	snapshot, err := coordinator.store.ReadTurn(ctx, authority.SessionID)
	if err != nil {
		return TurnSnapshot{}, nil, EffectKey{}, fmt.Errorf("read active effect: %w", err)
	}
	if err := validateTurn(snapshot, authority); err != nil {
		return TurnSnapshot{}, nil, EffectKey{}, err
	}
	if newAdmission {
		if !now.Before(authority.ExpiresAt) {
			return TurnSnapshot{}, nil, EffectKey{}, ErrAdmissionExpired
		}
		if !now.Before(snapshot.LeaseExpiresAt) {
			return TurnSnapshot{}, nil, EffectKey{}, ErrLeaseExpired
		}
		if snapshot.AbortRequested {
			return TurnSnapshot{}, nil, EffectKey{}, fmt.Errorf("%w: abort has been requested", ErrInvalidEffectState)
		}
	}
	if snapshot.ActiveEffect == nil {
		return TurnSnapshot{}, nil, EffectKey{}, ErrInvalidEffectState
	}
	effect := snapshot.ActiveEffect
	if effect.EffectID.Kind() != identity.Effect || effect.InvocationID.Kind() != identity.Invocation || effect.RequestDigest == (Digest{}) || !validService(effect.Service) || effect.Operation == "" {
		return TurnSnapshot{}, nil, EffectKey{}, ErrInvalidRequest
	}
	if !validReplayPolicy(effect.ReplayPolicy) {
		return TurnSnapshot{}, nil, EffectKey{}, ErrInvalidRequest
	}
	switch effect.State {
	case EffectPrepared:
		if effect.DispatchAttempt != 0 || effect.LastDispatch != nil || effect.ExternalCommitID != (identity.ID{}) || effect.ResultRef != (identity.ID{}) || effect.Settlement != nil || effect.PreparationPermit == nil || effect.PreparationPermit.EffectKey != (EffectKey{SessionID: snapshot.SessionID, TurnID: snapshot.TurnID, EffectID: effect.EffectID, InvocationID: effect.InvocationID, RequestDigest: effect.RequestDigest}) || effect.PreparationPermit.Opaque == "" || effect.PreparationPermit.TenantID != snapshot.TenantID || effect.PreparationPermit.WorkspaceID != snapshot.WorkspaceID || effect.PreparationPermit.UserID != snapshot.UserID || effect.PreparationPermit.Service != effect.Service || effect.PreparationPermit.Operation != effect.Operation || effect.PreparationPermit.ParentOperationID != effect.ParentOperationID || effect.PreparationPermit.Ordinal != effect.Ordinal || effect.PreparationPermit.ReplayPolicy != effect.ReplayPolicy || effect.PreparationPermit.Generations != effect.Generations || effect.PreparationPermit.DispatchAttempt != 1 || effect.PreparationPermit.Deadline.IsZero() || effect.PreparationPermit.EventSequence == 0 || !effect.PreparationPermit.Durable {
			return TurnSnapshot{}, nil, EffectKey{}, ErrInvalidRequest
		}
	case EffectDispatched:
		if effect.DispatchAttempt == 0 || effect.LastDispatch == nil || effect.LastDispatch.DispatchAttempt != effect.DispatchAttempt || effect.ExternalCommitID != (identity.ID{}) || effect.ResultRef != (identity.ID{}) || effect.Settlement != nil {
			return TurnSnapshot{}, nil, EffectKey{}, ErrInvalidRequest
		}
	case EffectBlocked:
		if effect.ReplayPolicy != ReplayConfirm || effect.DispatchAttempt == 0 || effect.LastDispatch == nil || effect.LastDispatch.DispatchAttempt != effect.DispatchAttempt || effect.ExternalCommitID != (identity.ID{}) || effect.ResultRef != (identity.ID{}) || effect.Settlement != nil {
			return TurnSnapshot{}, nil, EffectKey{}, ErrInvalidRequest
		}
	case EffectExternallyCommitted:
		if effect.DispatchAttempt == 0 || effect.LastDispatch == nil || effect.LastDispatch.DispatchAttempt != effect.DispatchAttempt || effect.ExternalCommitID.Kind() != identity.Commit || effect.Settlement != nil {
			return TurnSnapshot{}, nil, EffectKey{}, ErrInvalidRequest
		}
	case EffectSettled:
		if effect.Settlement == nil || effect.Settlement.State != v1.EffectState_EFFECT_STATE_SETTLED || effect.Settlement.DispatchAttempt != effect.DispatchAttempt || effect.DispatchAttempt == 0 && effect.LastDispatch != nil || effect.DispatchAttempt > 0 && (effect.LastDispatch == nil || effect.LastDispatch.DispatchAttempt != effect.DispatchAttempt) {
			return TurnSnapshot{}, nil, EffectKey{}, ErrInvalidRequest
		}
	default:
		return TurnSnapshot{}, nil, EffectKey{}, ErrInvalidRequest
	}
	if effect.LastDispatch != nil && (effect.LastDispatch.DispatchAttempt == 0 || effect.LastDispatch.Generations != effect.Generations || effect.LastDispatch.Deadline.IsZero() || effect.LastDispatch.ProviderRequestID != (identity.ID{}) && effect.LastDispatch.ProviderRequestID.Kind() != identity.Request) {
		return TurnSnapshot{}, nil, EffectKey{}, ErrInvalidRequest
	}
	if effect.EffectID != effectID || effect.InvocationID != invocationID || effect.RequestDigest != requestDigest {
		return TurnSnapshot{}, nil, EffectKey{}, ErrFenceMismatch
	}
	if effect.Generations != snapshot.Generations {
		return TurnSnapshot{}, nil, EffectKey{}, ErrStaleGeneration
	}
	key := EffectKey{SessionID: snapshot.SessionID, TurnID: snapshot.TurnID, EffectID: effectID, InvocationID: invocationID, RequestDigest: requestDigest}
	return snapshot, effect, key, nil
}

func validateTurn(snapshot TurnSnapshot, authority ValidatedTurnFence) error {
	if snapshot.TenantID.Kind() != identity.Tenant || snapshot.WorkspaceID.Kind() != identity.Workspace || snapshot.SessionID.Kind() != identity.Session || snapshot.TurnID.Kind() != identity.Turn ||
		snapshot.CheckpointDigest == (Digest{}) || snapshot.EngineStepLimits.MaximumEvents == 0 || snapshot.EngineStepLimits.MaximumEphemeralBytes == 0 || snapshot.EngineStepLimits.MaximumWallClock <= 0 {
		return ErrInvalidRequest
	}
	if !snapshot.Active || snapshot.TenantID != authority.TenantID || snapshot.WorkspaceID != authority.WorkspaceID || snapshot.SessionID != authority.SessionID || snapshot.TurnID != authority.TurnID {
		return ErrFenceMismatch
	}
	if snapshot.Generations != authority.Generations {
		return ErrStaleGeneration
	}
	if snapshot.LeaseExpiresAt.IsZero() || authority.ExpiresAt.IsZero() {
		return ErrInvalidRequest
	}
	return nil
}

func validAuthorityRoute(authority ValidatedTurnFence) bool {
	return authority.TenantID.Kind() == identity.Tenant && authority.WorkspaceID.Kind() == identity.Workspace
}

func validateLedgerRoute(record LedgerRecord, lookup LedgerLookup) error {
	if record.TenantID != lookup.TenantID || record.WorkspaceID != lookup.WorkspaceID {
		return ErrLedgerMismatch
	}
	return nil
}

func validateCommittedRecord(record LedgerRecord, lookup LedgerLookup) error {
	if record.Status != LedgerCommitted || record.EffectID != lookup.EffectID || record.InvocationID != lookup.InvocationID || record.RequestDigest != lookup.RequestDigest || record.Service != lookup.Service || record.Operation != lookup.Operation || record.DispatchAttempt != lookup.DispatchAttempt || record.ProviderRequestID != lookup.ProviderRequestID || record.ExternalCommitID.Kind() != identity.Commit || record.ResultRef != (identity.ID{}) && record.ResultRef.Kind() != identity.Artifact {
		return ErrLedgerMismatch
	}
	return nil
}

func validateConfirmationReceipt(receipt ConfirmationReceipt, key EffectKey, record LedgerRecord, operationDigest Digest) error {
	if receipt.EventSequence == 0 || receipt.EffectKey != key || receipt.TenantID != record.TenantID || receipt.WorkspaceID != record.WorkspaceID || receipt.Service != record.Service || receipt.Operation != record.Operation || receipt.DispatchAttempt != record.DispatchAttempt || receipt.ProviderRequestID != record.ProviderRequestID || receipt.ExternalCommitID != record.ExternalCommitID || receipt.ResultRef != record.ResultRef || receipt.OperationDigest != operationDigest {
		return fmt.Errorf("%w: invalid external commit receipt", ErrFenceMismatch)
	}
	return nil
}

func validRecoverySettlementReceipt(receipt SettlementReceipt, key EffectKey, tenantID, workspaceID identity.ID, dispatchAttempt uint64, operationDigest Digest, kind RecoverySettlementKind, publicError *v1.PublicError) bool {
	return receipt.Durable && receipt.EventSequence != 0 && receipt.EffectKey == key && receipt.TenantID == tenantID && receipt.WorkspaceID == workspaceID && receipt.State == EffectSettled && receipt.DispatchAttempt == dispatchAttempt && receipt.ExternalCommitID == (identity.ID{}) && receipt.ResultRef == (identity.ID{}) && proto.Equal(receipt.Error, publicError) && receipt.OperationDigest == operationDigest && receipt.RecoveryKind == kind && receipt.Effect != nil
}

func validService(service EffectService) bool {
	switch service {
	case ServiceModel, ServiceWorkspace, ServiceExecutor, ServiceMCP, ServiceArtifact, ServiceExternalTool:
		return true
	default:
		return false
	}
}

func validReplayPolicy(policy ReplayPolicy) bool {
	switch policy {
	case ReplaySafe, ReplayIdempotencyKey, ReplayNever, ReplayConfirm:
		return true
	default:
		return false
	}
}
