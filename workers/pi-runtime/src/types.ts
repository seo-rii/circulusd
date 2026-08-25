import type {
  AgentCheckpoint,
  AgentError,
  ConformanceStatus,
  Digest,
  EffectIntent,
  EffectService,
  EngineStepResult,
  NormalizedValue,
  ReplayPolicy,
} from "@circulusd/protocol-types";

import type { OpaqueTurnAuthority } from "./authority.ts";

export interface EngineIdentity {
  readonly sessionId: string;
  readonly runtimeRevisionDigest: Digest;
  readonly adapterAbiVersion: number;
  readonly checkpointSchemaVersion: number;
}

export type EffectRequestDraft = Omit<EffectIntent, "requestDigest">;

export type EffectSettlementOutcome =
  | { readonly kind: "success"; readonly result: NormalizedValue }
  | {
      readonly kind: "error";
      readonly code: string;
      readonly message: string;
      readonly retryable: boolean;
    }
  | { readonly kind: "interrupted_unknown"; readonly reason: string }
  | { readonly kind: "abandoned"; readonly reason: string };

export interface EngineSettlement {
  readonly requestDigest: Digest;
  readonly outcome: EffectSettlementOutcome;
}

export interface SettledToolResult {
  readonly request: EffectIntent;
  readonly settlement: EffectSettlementOutcome;
}

export type AgentCoreInput =
  | { readonly kind: "turn_start"; readonly input: NormalizedValue }
  | { readonly kind: "continue" }
  | {
      readonly kind: "effect_settlement";
      readonly request: EffectIntent;
      readonly settlement: EffectSettlementOutcome;
    }
  | { readonly kind: "tool_settlements"; readonly results: readonly SettledToolResult[] };

export interface AgentCoreStepContext {
  readonly sessionId: string;
  readonly turnId: string;
  readonly runtimeRevisionDigest: Digest;
  readonly state: NormalizedValue;
  readonly input: AgentCoreInput;
  readonly signal: AbortSignal;
}

interface AgentCoreTransitionBase {
  readonly state: NormalizedValue;
  readonly assistantDeltas?: readonly NormalizedValue[];
}

export type AgentCoreTransition =
  | (AgentCoreTransitionBase & { readonly kind: "checkpoint_only" })
  | (AgentCoreTransitionBase & {
      readonly kind: "model_request";
      readonly request: EffectRequestDraft;
    })
  | (AgentCoreTransitionBase & {
      readonly kind: "tool_requests";
      readonly requests: readonly EffectRequestDraft[];
    })
  | (AgentCoreTransitionBase & {
      readonly kind: "turn_complete";
      readonly result: NormalizedValue;
    })
  | (AgentCoreTransitionBase & {
      readonly kind: "turn_error";
      readonly error: AgentError;
    });

export interface AgentCore {
  advance(context: Readonly<AgentCoreStepContext>): Promise<unknown>;
  abortTurn?(turnId: string): Promise<void>;
}

export interface AgentCoreFactoryContext {
  readonly sessionId: string;
  readonly runtimeRevisionDigest: Digest;
  readonly adapterAbiVersion: number;
  readonly checkpointSchemaVersion: number;
}

/**
 * Reconstructs a fresh core for one bounded step. The factory itself must be
 * deterministic and must not retain mutable turn state: durable progress lives
 * exclusively in AgentCoreStepContext.state and the enclosing checkpoint.
 */
export type AgentCoreFactory = (context: Readonly<AgentCoreFactoryContext>) => AgentCore;

export interface EngineStepContext {
  readonly authority: OpaqueTurnAuthority;
  readonly checkpoint: AgentCheckpoint;
  readonly settlement?: EngineSettlement;
  readonly emitDelta?: (delta: NormalizedValue) => void | Promise<void>;
}

export interface GenesisCheckpointInput {
  readonly turnId: string;
  readonly input: unknown;
  readonly initialCoreState: unknown;
}

export interface EngineBudgets {
  readonly maxStepInputBytes: number;
  readonly maxCoreOutputBytes: number;
  readonly maxExtensionOutputBytes: number;
  readonly maxCheckpointBytes: number;
  readonly maxAssistantDeltaBytes: number;
  readonly maxEventsPerStep: number;
  readonly maxPendingToolCalls: number;
  readonly maxWallClockMs: number;
}

export interface EngineClock {
  now(): number;
  setTimeout(callback: () => void, delayMs: number): unknown;
  clearTimeout(handle: unknown): void;
}

export interface LowLevelPiAgentEngineOptions {
  readonly budgets?: Partial<EngineBudgets>;
  readonly clock?: EngineClock;
}

export type RequestPatchField = "operation" | "replayPolicy" | "payload";
export type ResultPatchField = "result";
export type PatchableHook =
  | "beforeModelRequest"
  | "afterModelResponse"
  | "beforeToolCall"
  | "afterToolCall";

export interface ExtensionManifest {
  readonly id: string;
  readonly priority: number;
  readonly tools: readonly string[];
  readonly configuration?: NormalizedValue;
  readonly patchableFields: Partial<{
    readonly beforeModelRequest: readonly RequestPatchField[];
    readonly afterModelResponse: readonly ResultPatchField[];
    readonly beforeToolCall: readonly RequestPatchField[];
    readonly afterToolCall: readonly ResultPatchField[];
  }>;
}

export interface ExtensionContext {
  readonly sessionId: string;
  readonly runtimeRevisionDigest: Digest;
  readonly extensionId: string;
  readonly configuration: NormalizedValue;
}

export interface AgentStartEvent {
  readonly sessionId: string;
  readonly runtimeRevisionDigest: Digest;
  readonly signal: AbortSignal;
}

export interface TurnEvent {
  readonly sessionId: string;
  readonly turnId: string;
  readonly input: NormalizedValue;
  readonly signal: AbortSignal;
}

export interface ModelRequestEvent {
  readonly sessionId: string;
  readonly turnId: string;
  readonly request: EffectRequestDraft;
  readonly signal: AbortSignal;
}

export interface ModelResponseEvent {
  readonly sessionId: string;
  readonly turnId: string;
  readonly request: EffectIntent;
  readonly result: NormalizedValue;
  readonly signal: AbortSignal;
}

export interface ToolCallEvent {
  readonly sessionId: string;
  readonly turnId: string;
  readonly request: EffectRequestDraft;
  readonly signal: AbortSignal;
}

export interface ToolResultEvent {
  readonly sessionId: string;
  readonly turnId: string;
  readonly request: EffectIntent;
  readonly result: NormalizedValue;
  readonly signal: AbortSignal;
}

export interface TurnCompletedEvent {
  readonly sessionId: string;
  readonly turnId: string;
  readonly result: NormalizedValue;
  readonly signal: AbortSignal;
}

export interface PiPlatformExtension {
  initialize?(context: Readonly<ExtensionContext>): Promise<unknown>;
  beforeAgentStart?(event: Readonly<AgentStartEvent>): Promise<unknown>;
  beforeTurn?(event: Readonly<TurnEvent>): Promise<unknown>;
  beforeModelRequest?(event: Readonly<ModelRequestEvent>): Promise<unknown>;
  afterModelResponse?(event: Readonly<ModelResponseEvent>): Promise<unknown>;
  beforeToolCall?(event: Readonly<ToolCallEvent>): Promise<unknown>;
  afterToolCall?(event: Readonly<ToolResultEvent>): Promise<unknown>;
  afterTurn?(event: Readonly<TurnCompletedEvent>): Promise<unknown>;
  snapshot?(): Promise<unknown>;
  shutdown?(): Promise<unknown>;
}

export interface ExtensionRegistration {
  readonly manifest: ExtensionManifest;
  readonly create: () => PiPlatformExtension;
}

export interface AgentEngine {
  step(context: EngineStepContext): Promise<EngineStepResult>;
  abortTurn(turnId: string): Promise<void>;
}

export type PiWorkerdConformanceStatus = ConformanceStatus;

export const EFFECT_SERVICE_VALUES = [
  "model",
  "workspace",
  "executor",
  "mcp",
  "artifact",
  "external-tool",
] as const satisfies readonly EffectService[];

export const REPLAY_POLICY_VALUES = [
  "safe",
  "idempotency-key",
  "never",
  "confirm",
] as const satisfies readonly ReplayPolicy[];
