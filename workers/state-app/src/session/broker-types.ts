import type { Digest, EngineStepResult } from "@circulusd/protocol-types";
import type {
  EffectSettlement, SessionEffect, SessionFence, SessionPayloadRef,
  StoredEffectSettlement, StoredSessionCheckpoint,
} from "./types.ts";

// These fixed maps are the signed Session broker wire contract. Times and
// durations are integral milliseconds; missing optional facts are explicit null.
// A snapshot is a CAS comparison, never an authority credential.
export interface SessionBrokerAuthority {
  tenantId: string;
  workspaceId: string;
  sessionId: string;
  actorSubjectId: string;
  expectedAuthorizationGeneration: number;
}

export interface SessionBrokerBudget {
  maximumEvents: number;
  maximumEphemeralBytes: number;
  maximumWallClockMs: number;
}

export interface SessionBrokerPolicy {
  engineStepLimits: SessionBrokerBudget;
  preparationTTLms: number;
}

export interface SessionBrokerSnapshot {
  turnId: string;
  eventSequence: number;
  checkpointDigest: Digest;
  fence: SessionFence;
  activeEffect: null | {
    effectId: string;
    invocationId: string;
    requestDigest: Digest;
    phase: SessionEffect["phase"];
    dispatchAttempt: number;
  };
}

export interface SessionBrokerEffectKey {
  turnId: string;
  effectId: string;
  invocationId: string;
  requestDigest: Digest;
}

// Every declared PublicError field survives original-receipt replay, including
// metadata and request identity. Go rejects unsupported protobuf unknown fields.
export interface SessionBrokerPublicError {
  code: number;
  reason: string;
  message: string;
  retryable: boolean;
  retryAfterMs: number;
  metadata: Record<string, string>;
  requestId: string | null;
}

export interface SessionBrokerSettlementSnapshot {
  effect: SessionEffect;
  settlement: StoredEffectSettlement;
}

interface SessionBrokerScope {
  tenantId: string;
  workspaceId: string;
  userId: string;
  sessionId: string;
  turnId: string;
}

export interface SessionBrokerEngineGrant extends SessionBrokerScope {
  opaque: Uint8Array;
  operationKey: string;
  fence: SessionFence;
  expectedEventSequence: number;
  checkpointDigest: Digest;
  budget: SessionBrokerBudget;
  deadline: number;
  checkpoint: StoredSessionCheckpoint;
  unconsumedSettlement: SessionBrokerSettlementSnapshot | null;
  durable: true;
}

export interface SessionBrokerPreparationPermit extends SessionBrokerScope, SessionBrokerEffectKey {
  opaque: Uint8Array;
  service: SessionEffect["service"];
  operation: string;
  parentOperationId: string | null;
  ordinal: number;
  replayPolicy: SessionEffect["replayPolicy"];
  fence: SessionFence;
  dispatchAttempt: number;
  deadline: number;
  eventSequence: number;
  durable: true;
}

export interface SessionBrokerDispatchPermit extends SessionBrokerPreparationPermit {
  providerRequestId: string | null;
  providerRouteDigest: Digest;
}

export interface SessionBrokerDispatchStartPermit {
  dispatch: SessionBrokerDispatchPermit;
  opaque: Uint8Array;
  commandDigest: Digest;
  eventSequence: number;
  durable: true;
}

export interface SessionBrokerDispatchStartClaim {
  fresh: boolean;
  permit: SessionBrokerDispatchStartPermit;
}

export interface SessionBrokerStepReceipt {
  operationKey: string;
  eventSequence: number;
  durable: true;
  preparedEffect: SessionEffect | null;
  preparation: SessionBrokerPreparationPermit | null;
}

export interface SessionBrokerConfirmationReceipt extends SessionBrokerScope, SessionBrokerEffectKey {
  service: SessionEffect["service"];
  operation: string;
  dispatchAttempt: number;
  providerRequestId: string | null;
  externalCommitId: string;
  resultRef: string | null;
  operationDigest: Digest;
  eventSequence: number;
  durable: true;
}

export interface SessionBrokerSettlementReceipt extends SessionBrokerScope, SessionBrokerEffectKey {
  state: "settled";
  dispatchAttempt: number;
  externalCommitId: string | null;
  resultRef: string | null;
  error: SessionBrokerPublicError | null;
  operationDigest: Digest;
  recoveryKind: "failed" | "interrupted_unknown" | null;
  effect: SessionEffect;
  eventSequence: number;
  durable: true;
}

export interface SessionBrokerBlockReceipt extends SessionBrokerScope, SessionBrokerEffectKey {
  state: "blocked";
  replayPolicy: SessionEffect["replayPolicy"];
  dispatchAttempt: number;
  operationDigest: Digest;
  reason: SessionBrokerPublicError;
  eventSequence: number;
  durable: true;
}

export interface SessionBrokerTurn {
  tenantId: string;
  workspaceId: string;
  userId: string;
  sessionId: string;
  turnId: string | null;
  active: boolean;
  abortRequested: boolean;
  leaseExpiresAt: number | null;
  fence: SessionFence;
  eventSequence: number;
  engineStepLimits: SessionBrokerBudget;
  checkpointDigest: Digest | null;
  checkpoint: StoredSessionCheckpoint | null;
  activeEffect: SessionEffect | null;
  preparation: SessionBrokerPreparationPermit | null;
  dispatch: SessionBrokerDispatchPermit | null;
  start: SessionBrokerDispatchStartPermit | null;
  unconsumedSettlement: SessionBrokerSettlementSnapshot | null;
}

export type SessionBrokerLookupKind = "dispatch" | "confirmation" | "settlement" | "recovery_settlement" | "block";
export type SessionBrokerReceiptKind = SessionBrokerLookupKind | "acquire" | "commit" | "retry" | "claim";
export type SessionBrokerReceiptValue = SessionBrokerEngineGrant | SessionBrokerStepReceipt |
  SessionBrokerPreparationPermit | SessionBrokerDispatchPermit | SessionBrokerDispatchStartClaim |
  SessionBrokerConfirmationReceipt | SessionBrokerSettlementReceipt | SessionBrokerBlockReceipt;

export interface SessionBrokerOperationLookup {
  kind: SessionBrokerLookupKind;
  operationKey: string;
  operationDigest: Digest;
}

export interface SessionBrokerOperationReceipt {
  found: boolean;
  kind: SessionBrokerLookupKind;
  operationDigest: Digest;
  receipt: SessionBrokerDispatchPermit | SessionBrokerConfirmationReceipt |
    SessionBrokerSettlementReceipt | SessionBrokerBlockReceipt | null;
}

interface MutationBase {
  snapshot: SessionBrokerSnapshot;
  operationKey: string;
}
interface EffectMutationBase extends MutationBase {
  key: SessionBrokerEffectKey;
  operationDigest: Digest;
}

export interface SessionBrokerAcquire extends MutationBase {
  nowUnixMs: number;
  budget: SessionBrokerBudget;
}
export interface SessionBrokerCommit extends MutationBase {
  requestDigest: Digest;
  permitOpaque: Uint8Array;
  nowUnixMs: number;
  step: EngineStepResult;
}
export interface SessionBrokerDispatch extends EffectMutationBase {
  preparationOpaque: Uint8Array;
  providerRequestId: string | null;
  providerRouteDigest: Digest;
  nowUnixMs: number;
  deadlineUnixMs: number;
}
export interface SessionBrokerClaim {
  snapshot: SessionBrokerSnapshot;
  key: SessionBrokerEffectKey;
  dispatchOpaque: Uint8Array;
  commandDigest: Digest;
  nowUnixMs: number;
}
export interface SessionBrokerConfirm extends EffectMutationBase {
  dispatchAttempt: number;
  providerRequestId: string | null;
  providerRouteDigest: Digest;
  externalCommitId: string;
  resultRef: string | null;
}
export interface SessionBrokerSettle extends EffectMutationBase {
  dispatchAttempt: number;
  externalCommitId: string;
  resultRef: string | null;
  error: SessionBrokerPublicError | null;
  // The trusted result resolver supplies the actual canonical result/error.
  // An artifact identifier is never a replacement for the result body.
  settlement: EffectSettlement;
}
export interface SessionBrokerBlock extends EffectMutationBase {
  reason: SessionBrokerPublicError;
}
// prepare-retry also renews an expired initial preparation. The owner caps
// that initial deadline by preparationTTLms, retains dispatch attempt 1 and
// requires a new operation key for each subsequent expiry. Dispatched retries
// retain their replay-policy and user-confirmation checks.
export interface SessionBrokerRetry extends EffectMutationBase {
  nowUnixMs: number;
  deadlineUnixMs: number;
  userConfirmed: boolean;
}
export interface SessionBrokerRecoverySettlement extends EffectMutationBase {
  kind: "failed" | "interrupted_unknown";
  error: SessionBrokerPublicError;
}

export type SessionBrokerMutation =
  | { operation: "acquire-step"; body: SessionBrokerAcquire }
  | { operation: "commit-step"; body: SessionBrokerCommit }
  | { operation: "dispatch"; body: SessionBrokerDispatch }
  | { operation: "claim-start"; body: SessionBrokerClaim }
  | { operation: "confirm"; body: SessionBrokerConfirm }
  | { operation: "settle"; body: SessionBrokerSettle }
  | { operation: "block"; body: SessionBrokerBlock }
  | { operation: "prepare-retry"; body: SessionBrokerRetry }
  | { operation: "settle-recovery"; body: SessionBrokerRecoverySettlement };

export type SessionBrokerRequest = SessionBrokerMutation |
  { operation: "read-turn"; body: Record<string, never> } |
  { operation: "lookup-operation"; body: SessionBrokerOperationLookup };

// Internal host context is not accepted in the signed caller body. Entropy is
// minted once outside transaction retries; state and receipt writes are atomic.
export interface SessionBrokerHostContext {
  policy: SessionBrokerPolicy;
  opaque: Uint8Array;
  secondaryOpaque: Uint8Array;
  effectId: string;
  invocationId: string;
}

export type SessionBrokerCommand = SessionBrokerMutation & {
  kind: "broker_operation";
  commandId: string;
  expectedEventSequence: number;
  operationKeyDigest: Digest;
  operationKey: string;
  authority: SessionBrokerAuthority;
  host: SessionBrokerHostContext;
};

export interface SessionBrokerStoredReceipt {
  sequence: number;
  kind: SessionBrokerReceiptKind;
  operationKey: string;
  operationKeyDigest: Digest;
  operationDigest: Digest;
  requestDigest: Digest;
  resultPayloadRef: SessionPayloadRef;
  // Transitive payload ownership remains explicit when the receipt itself is
  // externalized. This bounded list pins original checkpoint/result payloads.
  referencedBlobs: Array<{ digest: Digest; encodedBytes: number }>;
}

export interface SessionBrokerPreparation {
  permit: SessionBrokerPreparationPermit;
  sourceEventSequence: number;
  sourceDispatchAttempt: number;
  sourceCheckpointDigest: Digest;
  retry: boolean;
}

export interface SessionBrokerState {
  receiptSequence: number;
  receiptsThrough: number;
  receipts: SessionBrokerStoredReceipt[];
  engineGrant: SessionBrokerEngineGrant | null;
  preparation: SessionBrokerPreparation | null;
  dispatch: SessionBrokerDispatchPermit | null;
  start: SessionBrokerDispatchStartPermit | null;
}

export const SESSION_BROKER_HOT_RECEIPTS = 32;
