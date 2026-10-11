package broker

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/identity"
)

const rawPiParent = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type parentReceiptStore struct {
	*fakeStore
	dispatchParent *string
	retryParent    *string
	replayParent   *string
	startParent    *string
	commitRelabel  string
}

func (store *parentReceiptStore) CommitEngineStep(ctx context.Context, command CommitStepCommand) (EngineStepReceipt, error) {
	receipt, err := store.fakeStore.CommitEngineStep(ctx, command)
	if receipt.PreparationPermit != nil {
		switch store.commitRelabel {
		case "preparation":
			receipt.PreparationPermit.ParentOperation = ""
			receipt.PreparationPermit.ParentOperationID = identity.ID{}
		case "record":
			receipt.PreparedEffect.ParentOperationId = nil
		case "preparation-ordinal":
			receipt.PreparationPermit.Ordinal++
		case "record-ordinal":
			receipt.PreparedEffect.Ordinal++
		}
	}
	return receipt, err
}

func (store *parentReceiptStore) MarkDispatched(ctx context.Context, command MarkDispatchedCommand) (DispatchPermit, error) {
	permit, err := store.fakeStore.MarkDispatched(ctx, command)
	if store.dispatchParent != nil {
		permit.ParentOperation = *store.dispatchParent
	}
	return permit, err
}
func (store *parentReceiptStore) PrepareRetry(ctx context.Context, command PrepareRetryCommand) (EffectPreparationPermit, error) {
	permit, err := store.fakeStore.PrepareRetry(ctx, command)
	if store.retryParent != nil {
		permit.ParentOperation = *store.retryParent
	}
	return permit, err
}
func (store *parentReceiptStore) LookupOperation(ctx context.Context, lookup OperationLookup) (OperationReceipt, error) {
	receipt, err := store.fakeStore.LookupOperation(ctx, lookup)
	if store.replayParent != nil && receipt.Dispatch != nil {
		receipt.Dispatch.ParentOperation = *store.replayParent
	}
	return receipt, err
}
func (store *parentReceiptStore) ClaimDispatchStart(ctx context.Context, command ClaimDispatchStartCommand) (DispatchStartClaim, error) {
	claim, err := store.fakeStore.ClaimDispatchStart(ctx, command)
	if store.startParent != nil {
		claim.Permit.Dispatch.ParentOperation = *store.startParent
	}
	return claim, err
}

func rawParentDispatch(t *testing.T) (*parentReceiptStore, *Coordinator, DispatchRequest) {
	t.Helper()
	now := time.Unix(1_900_002_000, 0).UTC()
	snapshot := baseSnapshot(now)
	snapshot.ActiveEffect = baseEffect(EffectPrepared)
	request := baseDispatchRequest(now)
	snapshot.ActiveEffect.ParentOperation = rawPiParent
	snapshot.ActiveEffect.PreparationPermit.ParentOperation = rawPiParent
	snapshot.ActiveEffect.PreparationPermit.Deadline = request.Deadline
	request.PreparationPermit = *snapshot.ActiveEffect.PreparationPermit
	store := &parentReceiptStore{fakeStore: newFakeStore(snapshot)}
	return store, mustCoordinator(t, store, nil), request
}

func TestRawParentSurvivesDispatchReplayAndStart(t *testing.T) {
	t.Parallel()
	store, coordinator, request := rawParentDispatch(t)
	permit, err := coordinator.AdmitDispatch(context.Background(), request)
	if err != nil || permit.ParentOperation != rawPiParent || permit.ParentOperationID.String() != "" || permit.Ordinal != 0 {
		t.Fatalf("dispatch lost raw Pi parent: %v", err)
	}
	replay, err := coordinator.AdmitDispatch(context.Background(), request)
	if err != nil || replay != permit || store.markDispatchTransitions != 1 {
		t.Fatalf("dispatch replay changed parent: %v", err)
	}
	claim, err := coordinator.ClaimDispatchStart(context.Background(), DispatchStartRequest{Authority: request.Authority, Now: request.Now, Dispatch: permit, CommandDigest: digest(211)})
	if err != nil || !claim.Fresh || claim.Permit.Dispatch.ParentOperation != rawPiParent {
		t.Fatalf("start lost raw Pi parent: %v", err)
	}
}

func TestRawParentAdmissionAndReceiptRelabelsFailClosed(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"snapshot-proof", "request-proof", "dispatch-receipt", "dispatch-replay", "start-request", "start-receipt"} {
		t.Run(mode, func(t *testing.T) {
			store, coordinator, request := rawParentDispatch(t)
			empty := ""
			switch mode {
			case "snapshot-proof":
				store.snapshot.ActiveEffect.PreparationPermit.ParentOperation = ""
			case "request-proof":
				request.PreparationPermit.ParentOperation = ""
			case "dispatch-receipt":
				store.dispatchParent = &empty
			}
			permit, err := coordinator.AdmitDispatch(context.Background(), request)
			if mode == "snapshot-proof" {
				if !errors.Is(err, ErrInvalidRequest) || store.markDispatchTransitions != 0 {
					t.Fatalf("snapshot proof relabel: %v", err)
				}
				return
			}
			if mode == "request-proof" || mode == "dispatch-receipt" {
				if !errors.Is(err, ErrFenceMismatch) {
					t.Fatalf("parent relabel accepted: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "dispatch-replay":
				store.replayParent = &empty
				_, err = coordinator.AdmitDispatch(context.Background(), request)
			case "start-request":
				permit.ParentOperation = ""
				_, err = coordinator.ClaimDispatchStart(context.Background(), DispatchStartRequest{Authority: request.Authority, Now: request.Now, Dispatch: permit, CommandDigest: digest(211)})
			case "start-receipt":
				store.startParent = &empty
				_, err = coordinator.ClaimDispatchStart(context.Background(), DispatchStartRequest{Authority: request.Authority, Now: request.Now, Dispatch: permit, CommandDigest: digest(211)})
			}
			if !errors.Is(err, ErrFenceMismatch) {
				t.Fatalf("parent relabel accepted: %v", err)
			}
		})
	}
}

func TestRawParentRetryPreparationAndPermitBothBindOriginal(t *testing.T) {
	t.Parallel()
	for _, phase := range []EffectState{EffectBlocked, EffectDispatched} {
		for _, mode := range []string{"preserved", "preparation-relabel", "dispatch-relabel"} {
			t.Run(string(phase)+"/"+mode, func(t *testing.T) {
				now := time.Unix(1_900_002_000, 0).UTC()
				snapshot := baseSnapshot(now)
				snapshot.ActiveEffect = baseEffect(phase)
				snapshot.ActiveEffect.ParentOperation = rawPiParent
				request := baseRecoveryRequest(now, "parent-retry")
				if phase == EffectBlocked {
					snapshot.ActiveEffect.ReplayPolicy = ReplayConfirm
					request.UserConfirmed = true
				}
				store := &parentReceiptStore{fakeStore: newFakeStore(snapshot)}
				empty := ""
				if mode == "preparation-relabel" {
					store.retryParent = &empty
				}
				if mode == "dispatch-relabel" {
					store.dispatchParent = &empty
				}
				ledger := &fakeLedger{lookup: func(_ context.Context, lookup LedgerLookup) (LedgerRecord, error) {
					return exactLedgerRecord(lookup, LedgerAbsent), nil
				}}
				decision, err := mustCoordinator(t, store, ledger).RecoverEffect(context.Background(), request)
				if mode != "preserved" {
					if !errors.Is(err, ErrFenceMismatch) {
						t.Fatalf("retry parent relabel accepted: %v", err)
					}
					return
				}
				if err != nil || decision.Action != RecoveryReplay || decision.PreparationPermit.ParentOperation != rawPiParent || decision.DispatchPermit.ParentOperation != rawPiParent {
					t.Fatalf("retry lost Pi parent: %v", err)
				}
			})
		}
	}
}

func TestConcurrentDispatchStartCannotRelabelRawParent(t *testing.T) {
	t.Parallel()
	store, coordinator, request := rawParentDispatch(t)
	permit, err := coordinator.AdmitDispatch(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	_, err = coordinator.ClaimDispatchStart(context.Background(), DispatchStartRequest{Authority: request.Authority, Now: request.Now, Dispatch: permit, CommandDigest: digest(211)})
	if err != nil {
		t.Fatal(err)
	}
	expected := *store.snapshot.ActiveEffect
	store.snapshot.ActiveEffect.ParentOperation = "sha256:" + strings.Repeat("b", 64)
	store.snapshot.ActiveEffect.LastDispatch.Start.Dispatch.ParentOperation = store.snapshot.ActiveEffect.ParentOperation
	if _, err := coordinator.readExactDispatchStart(context.Background(), request.Authority, request.Now, &expected, permit.EffectKey); !errors.Is(err, ErrFenceMismatch) {
		t.Fatalf("concurrent parent relabel accepted: %v", err)
	}
}

func TestEnginePreparationReceiptBindsRawAndTypedParentToIntent(t *testing.T) {
	t.Parallel()
	for _, wire := range []string{"legacy", "protobuf"} {
		for _, parent := range []string{rawPiParent, mustID(identity.Operation, "typed-parent").String()} {
			for _, relabel := range []string{"", "preparation", "record", "preparation-ordinal", "record-ordinal"} {
				t.Run(wire+"/"+parent[:6]+"/"+relabel, func(t *testing.T) {
					now := time.Unix(1_900_002_000, 0).UTC()
					store := &parentReceiptStore{fakeStore: newFakeStore(baseSnapshot(now)), commitRelabel: relabel}
					coordinator := mustCoordinator(t, store, nil)
					permit := acquirePermit(t, coordinator, now, "parent-acquire")
					requestDigest := digest(212)
					intent := &EffectIntent{Service: ServiceExecutor, Operation: "run", ReplayPolicy: ReplaySafe, RequestDigest: requestDigest, Ordinal: 0}
					if typed, err := identity.Parse(identity.Operation, parent); err == nil {
						intent.ParentOperationID = typed
					} else {
						intent.ParentOperation = parent
					}
					boundary := EngineBoundary{Kind: BoundaryEffectRequest, CheckpointDigest: digest(213), Effect: intent}
					if wire == "protobuf" {
						boundary = EngineBoundary{CheckpointDigest: digest(213), Message: &v1.EngineStepBoundary{Checkpoint: &v1.AgentCheckpoint{PayloadBytes: []byte("checkpoint")}, Boundary: &v1.EngineStepBoundary_EffectRequest{EffectRequest: &v1.EffectIntent{
							Service: v1.EffectService_EFFECT_SERVICE_EXECUTOR, Operation: "run", ReplayPolicy: v1.ReplayPolicy_REPLAY_POLICY_SAFE,
							RequestDigest: &v1.Digest{Algorithm: v1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: requestDigest[:]}, ParentOperationId: &v1.OpaqueId{Value: []byte(parent)}, Ordinal: 0,
						}}}}
					}
					receipt, err := coordinator.CommitEngineStep(context.Background(), EngineStepCommit{Permit: permit, Now: now, OperationKey: "parent-commit", RequestDigest: digest(214), Boundary: boundary})
					if relabel != "" {
						if !errors.Is(err, ErrFenceMismatch) {
							t.Fatalf("preparation parent/ordinal relabel accepted: %v", err)
						}
						return
					}
					if err != nil || receipt.PreparationPermit.ParentOperation != intent.ParentOperation || receipt.PreparationPermit.ParentOperationID != intent.ParentOperationID || receipt.PreparationPermit.Ordinal != 0 || string(receipt.PreparedEffect.ParentOperationId.Value) != parent {
						t.Fatalf("preparation lost exact parent: %v", err)
					}
				})
			}
		}
	}
}
