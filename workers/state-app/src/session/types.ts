import type {
  AgentCheckpoint,
  AgentError,
  Digest,
  DispatchPermitClaims,
  EffectClaim,
  EngineKind,
  EngineStepResult,
  ExternalizedAgentCheckpoint,
  NormalizedValue,
} from "@circulusd/protocol-types";
import type { SessionBrokerCommand, SessionBrokerReceiptValue, SessionBrokerState, SessionBrokerStoredReceipt } from "./broker-types.ts";

// Schema v7 adds optional broker grants/reservations and bounded receipt history.
// Legacy inline fields and v6 typed blob references need no bulk rewrite.
export const SESSION_STATE_SCHEMA_VERSION = 7 as const;
export const SESSION_COMMAND_SCHEMA_VERSION = 1 as const;
export const SESSION_CHECKPOINT_DIGEST_SCHEMA_VERSION = 1 as const;
export const SESSION_CHECKPOINT_DIGEST_DOMAIN = "circulusd.session.agent-checkpoint" as const;
export const SESSION_TURN_INPUT_DIGEST_SCHEMA_VERSION = 1 as const;
export const SESSION_TURN_INPUT_DIGEST_DOMAIN = "circulusd.session.turn-input" as const;
export const SESSION_EFFECT_REQUEST_DIGEST_SCHEMA_VERSION = 1 as const;
export const SESSION_EFFECT_REQUEST_DIGEST_DOMAIN = "circulusd.session.effect-request" as const;
export const SESSION_VALUE_MAX_ENCODED_BYTES = 1_048_576 as const;
export const SESSION_COMMAND_MAX_ENCODED_BYTES = 8 * 1_048_576;
// The host record adds routing and manifest metadata around this value. Three
// MiB leaves headroom below the host's 4 MiB record/isolate-memory boundary.
export const SESSION_STATE_MAX_ENCODED_BYTES = 3 * 1_048_576;
// The host storage record bounds encoded item count, not just bytes: it rejects a
// record whose canonical CBOR exceeds MAX_RECORD_ITEMS (100_000). The aggregate must
// enforce the same budget on its state, minus the record wrapper's own items, so it
// never produces a state the host storage then rejects with a late, opaque error
// (review U04). Kept strictly below the host limit; host.storage.test asserts the
// margin covers the wrapper. (Depth is already bounded by the canonical normalizer's
// default, which is stricter than the host's depth limit.)
export const SESSION_STATE_MAX_ENCODED_ITEMS = 99_936;
// Payload bodies are externalized. Each reservation unit covers a bounded
// transition's metadata, command receipt and public event at their maximum field
// sizes. Two units per pending turn cover abort request plus terminal completion;
// effects reserve additional dispatch, claim, external-commit and settlement units.
// The final candidate (including receipts/events) must fit both limits with every
// outstanding reservation before forward growth is accepted.
export const SESSION_CAPACITY_RESERVE_UNIT_BYTES = 16 * 1024;
export const SESSION_CAPACITY_RESERVE_UNIT_ITEMS = 1024;
export const SESSION_TURN_COMPLETION_RESERVE_BYTES = 2 * SESSION_CAPACITY_RESERVE_UNIT_BYTES;
export const SESSION_TURN_COMPLETION_RESERVE_ITEMS = 2 * SESSION_CAPACITY_RESERVE_UNIT_ITEMS;
export const SESSION_PUBLIC_EVENT_REPLAY_MAX_EVENTS = 256 as const;

export interface SessionPayloadRef {
  readonly encoding: "canonical-cbor-v1";
  readonly digest: Digest;
  readonly encodedBytes: number;
  readonly encodedItems: number;
}

export type StoredSessionInput =
  | { input: NormalizedValue; inputRef?: never }
  | { input?: never; inputRef: SessionPayloadRef };
export type StoredSessionResult =
  | { result: NormalizedValue; resultPayloadRef?: never }
  | { result?: never; resultPayloadRef: SessionPayloadRef };
export type StoredAgentError = Omit<AgentError, "details"> & (
  | { readonly details?: NormalizedValue; readonly detailsRef?: never }
  | { readonly details?: never; readonly detailsRef: SessionPayloadRef }
);
export type StoredSessionCheckpoint = AgentCheckpoint | ExternalizedAgentCheckpoint;
type StoredTurnCheckpoint =
  | { checkpoint: AgentCheckpoint; checkpointChainDigest?: Digest }
  | { checkpoint: ExternalizedAgentCheckpoint; checkpointChainDigest: Digest };

export type SessionStatus =
  | "created"
  | "starting"
  | "ready"
  | "running"
  | "interrupted"
  | "failed"
  | "closed";
export type TurnStatus =
  | "queued"
  | "active"
  | "needs_confirmation"
  | "completed"
  | "failed"
  | "aborted";
export type EffectPhase =
  | "prepared"
  | "dispatched"
  | "externally_committed"
  | "blocked"
  | "settled";

export interface SessionFence {
  readonly turnLeaseGeneration: number;
  readonly placementGeneration: number;
  readonly sandboxGeneration: number;
  readonly authorizationGeneration: number;
}

export interface SessionRuntimeConfiguration {
  readonly runtimeRevisionDigest: Digest;
  readonly policySnapshotDigest: Digest;
  readonly engineKind: EngineKind;
  readonly adapterAbiVersion: number;
  readonly checkpointSchemaVersion: number;
}

export interface RuntimePointer {
  activeRevision: Digest;
  candidateRevision: Digest | null;
  previousRevision: Digest | null;
  switchGeneration: number;
}

export interface CreateSessionStateInput extends SessionRuntimeConfiguration {
  readonly sessionId: string;
  readonly tenantId: string;
  readonly userId: string;
  readonly workspaceId: string;
  readonly placementGeneration: number;
  readonly sandboxGeneration: number;
  readonly authorizationGeneration: number;
  readonly emergencyOverlayDigest: Digest;
}

interface TurnRecordBase {
  turnId: string;
  sequence: number;
  inputDigest: Digest;
  // The latest checkpoint in its durable form; its payload bytes are the blob
  // keyed by checkpoint.payloadDigest.
  // The chain digest of `checkpoint` (computed over its wire form at ingestion,
  // when the payload bytes were present). The next engine step's
  // predecessorDigest must equal it; storing it lets the aggregate verify the
  // chain without re-materializing the externalized payload.
  turnLeaseGeneration: number;
  leaseExpiresAt: number;
}

export type QueuedTurn = TurnRecordBase & StoredSessionInput & StoredTurnCheckpoint & { status: "queued" };

export type ActiveTurn = TurnRecordBase & StoredSessionInput & StoredTurnCheckpoint & {
  status: "active" | "needs_confirmation";
  abortRequested: boolean;
  abortReason: string | null;
  activeEffectId: string | null;
};

interface TerminalTurnBase {
  turnId: string;
  sequence: number;
  inputDigest: Digest;
  finalCheckpoint: StoredSessionCheckpoint;
  turnLeaseGeneration: number;
  leaseExpiresAt: number;
  abortRequested: boolean;
  abortReason: string | null;
}

export type TerminalTurn =
  | (TerminalTurnBase & StoredSessionInput & StoredSessionResult & {
      status: "completed";
      error: null;
    })
  | (TerminalTurnBase & StoredSessionInput & {
      status: "failed";
      result: null;
      error: StoredAgentError;
    })
  | (TerminalTurnBase & StoredSessionInput & {
      status: "aborted";
      result: null;
      error: null;
      abortRequested: true;
      abortReason: string;
    });

export type EffectSettlement =
  | { readonly kind: "success"; readonly result: NormalizedValue }
  | {
      readonly kind: "error";
      readonly code: string;
      readonly message: string;
      readonly retryable: boolean;
    }
  | { readonly kind: "interrupted_unknown"; readonly reason: string }
  | { readonly kind: "abandoned"; readonly reason: string };

export type StoredEffectSettlement =
  | Exclude<EffectSettlement, { readonly kind: "success" }>
  | ({ readonly kind: "success" } & StoredSessionResult);

export interface EffectDispatchMetadata extends SessionFence {
  dispatchAttempt: number;
  deadline: number;
  providerRequestId: string | null;
  providerRouteDigest: Digest;
  start: EffectDispatchStartMetadata | null;
}

export interface EffectDispatchStartMetadata extends SessionFence {
  dispatchAttempt: number;
  deadline: number;
  providerRequestId: string | null;
  providerRouteDigest: Digest;
  commandDigest: Digest;
  claimedEventSequence: number;
}

export interface DispatchStartPermitClaims {
  readonly dispatchPermitClaims: DispatchPermitClaims;
  readonly providerRequestId: string | null;
  readonly commandDigest: Digest;
  readonly claimedEventSequence: number;
}

export type SessionEffect = EffectClaim & {
  phase: EffectPhase;
  dispatchAttempt: number;
  lastDispatch: EffectDispatchMetadata | null;
  externalCommitId: string | null;
  resultRef: string | null;
  settlement: StoredEffectSettlement | null;
  consumedAtCheckpointSequence: number | null;
  consumedByAbort: boolean;
} & (
  | { requestPayload: NormalizedValue; requestPayloadRef?: never }
  | { requestPayload?: never; requestPayloadRef: SessionPayloadRef }
);

export interface CommandReceipt {
  commandId: string;
  commandDigest: Digest;
  committedEventSequence: number;
  outcome: StoredSessionCommandOutcome;
}

export interface PublicTurnAdmission {
  readonly tenantId?: string;
  readonly actorSubjectId?: string;
  readonly authorizationGeneration: number;
  readonly idempotencyKeyDigest: Digest;
  readonly requestDigest: Digest;
}

export interface TurnAdmissionReceipt {
  idempotencyKeyDigest: Digest;
  requestDigest: Digest;
  inputDigest: Digest;
  turnId: string;
  turnSequence: number;
  activated: boolean;
  publicEventSequence: number;
}

interface SessionPublicEventBase {
  sequence: number;
  turnId: string;
  turnSequence: number;
}

export interface SessionPublicTurnAcceptedEvent extends SessionPublicEventBase {
  type: "turn.accepted";
  status: "active" | "queued";
}

interface SessionPublicEffectEventBase extends SessionPublicEventBase {
  effectId: string;
  invocationId: string;
  service: SessionEffect["service"];
  operation: string;
}

export interface SessionPublicEffectPreparedEvent
  extends SessionPublicEffectEventBase {
  type: "model.effect.prepared" | "tool.effect.prepared";
}

export interface SessionPublicToolExternallyCommittedEvent
  extends SessionPublicEffectEventBase {
  type: "tool.externally_committed";
  externalCommitId: string;
  resultRef: string | null;
}

export interface SessionPublicEffectSettledEvent
  extends SessionPublicEffectEventBase {
  type: "model.settled" | "tool.settled";
  settlementKind: EffectSettlement["kind"];
}

export interface SessionPublicNeedsConfirmationEvent
  extends SessionPublicEffectEventBase {
  type: "turn.needs_confirmation";
}

export interface SessionPublicTerminalEvent extends SessionPublicEventBase {
  type: "turn.completed" | "turn.failed" | "turn.aborted";
}

export type SessionPublicEvent =
  | SessionPublicTurnAcceptedEvent
  | SessionPublicEffectPreparedEvent
  | SessionPublicToolExternallyCommittedEvent
  | SessionPublicEffectSettledEvent
  | SessionPublicNeedsConfirmationEvent
  | SessionPublicTerminalEvent;

export interface SessionPublicEventSnapshot {
  readonly sessionId: string;
  readonly activeTurnId: string | null;
  readonly turnStatus: ActiveTurn["status"] | null;
  readonly lastEventSequence: number;
}

export interface SessionPublicEventReplay {
  readonly snapshot: SessionPublicEventSnapshot;
  readonly events: readonly SessionPublicEvent[];
}

export interface SessionAggregateState extends SessionRuntimeConfiguration {
  schemaVersion: typeof SESSION_STATE_SCHEMA_VERSION;
  sessionId: string;
  tenantId: string;
  userId: string;
  workspaceId: string;
  runtimeRevisionDigest: Digest;
  runtimePointer: RuntimePointer;
  status: SessionStatus;
  eventSequence: number;
  publicEventSequence: number;
  nextTurnSequence: number;
  activeTurn: ActiveTurn | null;
  queuedTurns: QueuedTurn[];
  terminalTurns: TerminalTurn[];
  knownTurnIds: string[];
  latestSettledTurn: string | null;
  effects: SessionEffect[];
  placementGeneration: number;
  sandboxGeneration: number;
  authorizationGeneration: number;
  emergencyOverlayDigest: Digest;
  commandReceipts: CommandReceipt[];
  publicEvents: SessionPublicEvent[];
  turnAdmissionReceipts: TurnAdmissionReceipt[];
  // Omitted by legacy full-history records. Every nonzero prefix is backed by
  // the host's authenticated history index in the same storage transaction.
  history?: SessionHistoryState;
  broker?: SessionBrokerState;
}

export const SESSION_HISTORY_HOT_COMMANDS = 32;
export const SESSION_HISTORY_HOT_PUBLIC_EVENTS = 32;
export const SESSION_HISTORY_HOT_TERMINAL_TURNS = 8;
export const SESSION_HISTORY_HOT_EFFECTS = 8;
export const SESSION_HISTORY_MAX_RECORDS = 16;

export interface SessionTurnIdentity { turnId: string; turnSequence: number }
export interface SessionInvocationIdentity { invocationId: string; effectId: string }
export interface SessionHistoryState {
  commandThrough: number;
  publicEventThrough: number;
  turnThrough: number;
  runtimePointerAtCommandThrough: RuntimePointer;
  latestSettledTurnAtTurnThrough: string | null;
  // Only evidence still referenced by hot entities survives in these anchors.
  publicEventAnchors: SessionPublicEvent[];
  dispatchStartReceipts: CommandReceipt[];
  runtimeRevisionDigests: Digest[];
}
export interface SessionArchiveDelta {
  commandReceipts: CommandReceipt[];
  publicEvents: SessionPublicEvent[];
  terminalTurns: TerminalTurn[];
  effects: SessionEffect[];
  turnAdmissionReceipts: TurnAdmissionReceipt[];
  turnIdentities: SessionTurnIdentity[];
  brokerReceipts?: SessionBrokerStoredReceipt[];
}
export interface SessionHistoryReadPlan {
  commandId?: string;
  idempotencyKeyDigest?: Digest;
  turnId?: string;
  effectId?: string;
  invocationId?: string;
  issuingEventSequence?: number;
  brokerOperation?: { kind: SessionBrokerStoredReceipt["kind"]; operationKey: string; operationKeyDigest: Digest };
}
export interface SessionHistoryWitness {
  command?: { commandId: string; receipt: CommandReceipt | null };
  admission?: { idempotencyKeyDigest: Digest; receipt: TurnAdmissionReceipt | null };
  turn?: { turnId: string; record: SessionTurnIdentity | null };
  effect?: { effectId: string; record: SessionEffect | null };
  invocation?: { invocationId: string; record: SessionInvocationIdentity | null };
  issuingReceipt?: { eventSequence: number; receipt: CommandReceipt | null };
  brokerOperation?: { kind: SessionBrokerStoredReceipt["kind"]; operationKey: string; operationKeyDigest: Digest; receipt: SessionBrokerStoredReceipt | null };
}
export interface SessionApplyContext {
  readonly transactionTime: number;
  readonly history?: SessionHistoryWitness;
  readonly historyMaxRecords?: number;
}

interface SessionCommandBase {
  readonly commandId: string;
  readonly expectedEventSequence: number;
}

interface ActiveTurnCommandBase extends SessionCommandBase {
  readonly turnId: string;
  readonly fence: SessionFence;
}

interface EffectCommandBase extends ActiveTurnCommandBase {
  readonly effectId: string;
  readonly invocationId: string;
  readonly requestDigest: Digest;
}

export interface EnqueueTurnCommand extends SessionCommandBase {
  readonly kind: "enqueue_turn";
  readonly transactionTime: number;
  readonly turnId: string;
  readonly input: NormalizedValue;
  readonly inputDigest: Digest;
  readonly genesisCheckpoint: AgentCheckpoint;
  readonly turnLeaseGeneration: number;
  readonly leaseExpiresAt: number;
  readonly publicAdmission?: PublicTurnAdmission;
}

export interface CommitEngineStepCommand extends ActiveTurnCommandBase {
  readonly kind: "commit_engine_step";
  readonly transactionTime: number;
  readonly consumedSettlementEffectId: string | null;
  readonly effectIdentity: {
    readonly effectId: string;
    readonly invocationId: string;
  } | null;
  readonly step: EngineStepResult;
}

export interface DispatchEffectCommand extends EffectCommandBase {
  readonly kind: "dispatch_effect";
  readonly transactionTime: number;
  readonly deadline: number;
  readonly providerRequestId?: string | null;
  readonly providerRouteDigest: Digest;
}

export interface ClaimDispatchStartCommand extends EffectCommandBase {
  readonly kind: "claim_dispatch_start";
  readonly workspaceId: string;
  readonly transactionTime: number;
  readonly dispatchAttempt: number;
  readonly providerRequestId: string | null;
  readonly providerRouteDigest: Digest;
  readonly dispatchPermitClaims: DispatchPermitClaims;
  readonly commandDigest: Digest;
}

export interface RecordExternalCommitCommand extends EffectCommandBase {
  readonly kind: "record_external_commit";
  readonly dispatchAttempt: number;
  readonly externalCommitId: string;
  readonly resultRef: string | null;
}

export interface SettleEffectCommand extends EffectCommandBase {
  readonly kind: "settle_effect";
  readonly dispatchAttempt: number | null;
  readonly settlement: EffectSettlement;
}

export interface RecoverEffectCommand extends EffectCommandBase {
  readonly kind: "recover_effect";
  readonly transactionTime: number;
  readonly deadline: number;
  readonly providerRequestId?: string | null;
  readonly providerRouteDigest?: Digest;
}

export type ResolveConfirmationCommand = EffectCommandBase &
  (
    | {
        readonly kind: "resolve_confirmation";
        readonly decision: "retry";
        readonly transactionTime: number;
        readonly deadline: number;
        readonly providerRequestId?: string | null;
        readonly providerRouteDigest: Digest;
      }
    | {
        readonly kind: "resolve_confirmation";
        readonly decision: "abandon";
        readonly transactionTime: null;
        readonly deadline: null;
        readonly providerRequestId?: never;
      }
  );

export interface RequestAbortCommand extends ActiveTurnCommandBase {
  readonly kind: "request_abort";
  readonly transactionTime: number;
  readonly reason: string;
}

export interface FinalizeAbortCommand extends ActiveTurnCommandBase {
  readonly kind: "finalize_abort";
  readonly transactionTime: number;
}

export interface RotateTurnLeaseCommand extends ActiveTurnCommandBase {
  readonly kind: "rotate_turn_lease";
  readonly transactionTime: number;
  readonly nextTurnLeaseGeneration: number;
  readonly nextLeaseExpiresAt: number;
}

export interface RotateGenerationsCommand extends SessionCommandBase {
  readonly kind: "rotate_generations";
  readonly nextPlacementGeneration: number;
  readonly nextSandboxGeneration: number;
  readonly nextAuthorizationGeneration: number;
  readonly nextEmergencyOverlayDigest: Digest;
}

export interface StageRuntimeRevisionCommand extends SessionCommandBase {
  readonly kind: "stage_runtime_revision";
  readonly candidateRevision: Digest;
}

export interface DiscardRuntimeCandidateCommand extends SessionCommandBase {
  readonly kind: "discard_runtime_candidate";
  readonly expectedCandidateRevision: Digest;
  readonly failureReceiptDigest: Digest;
}

export interface ActivateRuntimeRevisionCommand extends SessionCommandBase {
  readonly kind: "activate_runtime_revision";
  readonly expectedActiveRevision: Digest;
  readonly expectedCandidateRevision: Digest;
  readonly expectedSwitchGeneration: number;
  readonly healthReceiptDigest: Digest;
  readonly migrationReceiptDigest: Digest;
}

export interface RollbackRuntimeRevisionCommand extends SessionCommandBase {
  readonly kind: "rollback_runtime_revision";
  readonly expectedActiveRevision: Digest;
  readonly expectedPreviousRevision: Digest;
  readonly expectedSwitchGeneration: number;
  readonly failureReceiptDigest: Digest;
}

export type SessionCommand =
  | SessionBrokerCommand
  | EnqueueTurnCommand
  | CommitEngineStepCommand
  | DispatchEffectCommand
  | ClaimDispatchStartCommand
  | RecordExternalCommitCommand
  | SettleEffectCommand
  | RecoverEffectCommand
  | ResolveConfirmationCommand
  | RequestAbortCommand
  | FinalizeAbortCommand
  | RotateTurnLeaseCommand
  | RotateGenerationsCommand
  | StageRuntimeRevisionCommand
  | DiscardRuntimeCandidateCommand
  | ActivateRuntimeRevisionCommand
  | RollbackRuntimeRevisionCommand;

export type SessionCommandOutcome =
  | { readonly kind: "broker_result"; readonly result: SessionBrokerReceiptValue }
  | { readonly kind: "broker_boundary"; readonly operation: "retry" | "block" | "recovery_settlement"; readonly effectId: string }
  | {
      readonly kind: "turn_enqueued";
      readonly turnId: string;
      readonly turnSequence: number;
      readonly activated: boolean;
    }
  | {
      readonly kind: "engine_step_committed";
      readonly turnId: string;
      readonly boundaryKind: EngineStepResult["kind"];
      readonly checkpointSequence: number;
      readonly consumedEffectId: string | null;
      readonly preparedEffectId: string | null;
      readonly status: "active" | "completed" | "failed";
    }
  | {
      readonly kind: "effect_dispatched";
      readonly effectId: string;
      /** Seal these claims only after the enclosing state transaction is durably committed. */
      readonly dispatchPermitClaims: DispatchPermitClaims;
    }
  | {
      readonly kind: "dispatch_start_claimed";
      readonly effectId: string;
      readonly fresh: boolean;
      /** Seal these claims only after the enclosing state transaction is durably committed. */
      readonly startPermit: DispatchStartPermitClaims;
    }
  | {
      readonly kind: "external_commit_recorded";
      readonly effectId: string;
      readonly externalCommitId: string;
    }
  | {
      readonly kind: "effect_settled";
      readonly effectId: string;
      readonly settlement: EffectSettlement;
    }
  | {
      readonly kind: "effect_recovered";
      readonly effectId: string;
      readonly action: "retry" | "interrupted" | "blocked";
      /** Present only when recovery authorized a new dispatch attempt. */
      readonly dispatchPermitClaims?: DispatchPermitClaims;
    }
  | {
      readonly kind: "confirmation_resolved";
      readonly effectId: string;
      readonly decision: "retry" | "abandon";
      /** Present only for an explicitly confirmed retry. */
      readonly dispatchPermitClaims?: DispatchPermitClaims;
    }
  | {
      readonly kind: "abort_requested";
      readonly turnId: string;
      readonly status: "active" | "needs_confirmation" | "aborted";
    }
  | { readonly kind: "abort_finalized"; readonly turnId: string; readonly status: "aborted" }
  | {
      readonly kind: "turn_lease_rotated";
      readonly turnId: string;
      readonly turnLeaseGeneration: number;
      readonly leaseExpiresAt: number;
    }
  | {
      readonly kind: "generations_rotated";
      readonly placementGeneration: number;
      readonly sandboxGeneration: number;
      readonly authorizationGeneration: number;
      readonly emergencyOverlayDigest: Digest;
    }
  | {
      readonly kind: "runtime_revision_staged";
      readonly activeRevision: Digest;
      readonly candidateRevision: Digest;
      readonly switchGeneration: number;
    }
  | {
      readonly kind: "runtime_candidate_discarded";
      readonly activeRevision: Digest;
      readonly candidateRevision: Digest;
      readonly switchGeneration: number;
      readonly failureReceiptDigest: Digest;
    }
  | {
      readonly kind: "runtime_revision_activated";
      readonly activeRevision: Digest;
      readonly previousRevision: Digest;
      readonly switchGeneration: number;
      readonly healthReceiptDigest: Digest;
      readonly migrationReceiptDigest: Digest;
    }
  | {
      readonly kind: "runtime_revision_rolled_back";
      readonly activeRevision: Digest;
      readonly previousRevision: Digest;
      readonly switchGeneration: number;
      readonly failureReceiptDigest: Digest;
    };

export type StoredSessionCommandOutcome =
  | Exclude<SessionCommandOutcome, { readonly kind: "effect_settled" | "broker_result" }>
  | { readonly kind: "broker_result"; readonly receipt: SessionBrokerStoredReceipt; readonly replayedClaim: boolean }
  | {
      readonly kind: "effect_settled";
      readonly effectId: string;
      readonly settlement: StoredEffectSettlement;
    };

export interface ApplySessionCommandResult {
  readonly state: SessionAggregateState;
  readonly outcome: StoredSessionCommandOutcome;
  readonly commandDigest: Digest;
  readonly replayed: boolean;
  // Payload externalization side channel (see host AggregateBlobEffects): the new
  // blob bytes this command introduced, keyed by content digest, and the complete
  // set of blob digests the returned state references. Omitted on replay, where
  // the host persists nothing.
  readonly blobs?: ReadonlyMap<Digest, Uint8Array>;
  readonly referencedBlobs?: readonly Digest[];
  readonly archiveDelta?: SessionArchiveDelta;
}
