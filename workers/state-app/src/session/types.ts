import type {
  AgentCheckpoint,
  AgentError,
  Digest,
  DispatchPermitClaims,
  EffectClaim,
  EngineKind,
  EngineStepResult,
  NormalizedValue,
} from "@circulusd/protocol-types";

export const SESSION_STATE_SCHEMA_VERSION = 1 as const;
export const SESSION_COMMAND_SCHEMA_VERSION = 1 as const;
export const SESSION_CHECKPOINT_DIGEST_SCHEMA_VERSION = 1 as const;
export const SESSION_CHECKPOINT_DIGEST_DOMAIN = "circulusd.session.agent-checkpoint" as const;
export const SESSION_TURN_INPUT_DIGEST_SCHEMA_VERSION = 1 as const;
export const SESSION_TURN_INPUT_DIGEST_DOMAIN = "circulusd.session.turn-input" as const;
export const SESSION_EFFECT_REQUEST_DIGEST_SCHEMA_VERSION = 1 as const;
export const SESSION_EFFECT_REQUEST_DIGEST_DOMAIN = "circulusd.session.effect-request" as const;
export const SESSION_VALUE_MAX_ENCODED_BYTES = 1_048_576 as const;
export const SESSION_COMMAND_MAX_ENCODED_BYTES = 8 * 1_048_576;
export const SESSION_STATE_MAX_ENCODED_BYTES = 32 * 1_048_576;

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
  input: NormalizedValue;
  inputDigest: Digest;
  checkpoint: AgentCheckpoint;
  turnLeaseGeneration: number;
  leaseExpiresAt: number;
}

export interface QueuedTurn extends TurnRecordBase {
  status: "queued";
}

export interface ActiveTurn extends TurnRecordBase {
  status: "active" | "needs_confirmation";
  abortRequested: boolean;
  abortReason: string | null;
  activeEffectId: string | null;
}

interface TerminalTurnBase {
  turnId: string;
  sequence: number;
  input: NormalizedValue;
  inputDigest: Digest;
  finalCheckpoint: AgentCheckpoint;
  turnLeaseGeneration: number;
  leaseExpiresAt: number;
  abortRequested: boolean;
  abortReason: string | null;
}

export type TerminalTurn =
  | (TerminalTurnBase & {
      status: "completed";
      result: NormalizedValue;
      error: null;
    })
  | (TerminalTurnBase & {
      status: "failed";
      result: null;
      error: AgentError;
    })
  | (TerminalTurnBase & {
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

export interface EffectDispatchMetadata extends SessionFence {
  dispatchAttempt: number;
  deadline: number;
  providerRequestId: string | null;
}

export interface SessionEffect extends EffectClaim {
  phase: EffectPhase;
  dispatchAttempt: number;
  lastDispatch: EffectDispatchMetadata | null;
  requestPayload: NormalizedValue;
  externalCommitId: string | null;
  resultRef: string | null;
  settlement: EffectSettlement | null;
  consumedAtCheckpointSequence: number | null;
  consumedByAbort: boolean;
}

export interface CommandReceipt {
  commandId: string;
  commandDigest: Digest;
  committedEventSequence: number;
  outcome: SessionCommandOutcome;
}

export interface SessionAggregateState extends SessionRuntimeConfiguration {
  schemaVersion: typeof SESSION_STATE_SCHEMA_VERSION;
  sessionId: string;
  tenantId: string;
  userId: string;
  workspaceId: string;
  status: SessionStatus;
  eventSequence: number;
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
}

export interface RecordExternalCommitCommand extends EffectCommandBase {
  readonly kind: "record_external_commit";
  readonly dispatchAttempt: number;
  readonly externalCommitId: string;
  readonly resultRef: string;
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
}

export type ResolveConfirmationCommand = EffectCommandBase &
  (
    | {
        readonly kind: "resolve_confirmation";
        readonly decision: "retry";
        readonly transactionTime: number;
        readonly deadline: number;
        readonly providerRequestId?: string | null;
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

export type SessionCommand =
  | EnqueueTurnCommand
  | CommitEngineStepCommand
  | DispatchEffectCommand
  | RecordExternalCommitCommand
  | SettleEffectCommand
  | RecoverEffectCommand
  | ResolveConfirmationCommand
  | RequestAbortCommand
  | FinalizeAbortCommand
  | RotateTurnLeaseCommand
  | RotateGenerationsCommand;

export type SessionCommandOutcome =
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
    };

export interface ApplySessionCommandResult {
  readonly state: SessionAggregateState;
  readonly outcome: SessionCommandOutcome;
  readonly commandDigest: Digest;
  readonly replayed: boolean;
}
