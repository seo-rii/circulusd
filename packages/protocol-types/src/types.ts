export const PROTOCOL_NAME = "circulus.v1alpha1" as const;
export const PROTOCOL_MAJOR = 1 as const;
export const PROTOCOL_MINOR = 0 as const;

export type Digest = `sha256:${string}`;

export type NormalizedValue =
  | null
  | boolean
  | number
  | string
  | Uint8Array
  | NormalizedValue[]
  | { readonly [key: string]: NormalizedValue };

export interface RpcEnvelope<T> {
  readonly protocol: typeof PROTOCOL_NAME;
  readonly major: typeof PROTOCOL_MAJOR;
  readonly minor: typeof PROTOCOL_MINOR;
  readonly schemaDigest: Digest;
  readonly requestId: string;
  readonly payload: T;
}

export type EngineKind = "low-level" | "agent-harness";
export type CheckpointPayloadEncoding = "protobuf" | "canonical-cbor" | "opaque-v1";

interface AgentCheckpointBase {
  readonly engineKind: EngineKind;
  readonly adapterAbiVersion: number;
  readonly checkpointSchemaVersion: number;
  readonly runtimeRevisionDigest: Digest;
  readonly sessionId: string;
  readonly turnId: string;
  readonly payloadEncoding: CheckpointPayloadEncoding;
  readonly payloadBytes: Uint8Array;
  readonly payloadDigest: Digest;
}

export interface GenesisAgentCheckpoint extends AgentCheckpointBase {
  readonly kind: "genesis";
  readonly checkpointSequence: 0;
  readonly predecessorDigest: null;
}

export interface EngineAgentCheckpoint extends AgentCheckpointBase {
  readonly kind: "engine";
  readonly checkpointSequence: number;
  readonly predecessorDigest: Digest;
}

export type AgentCheckpoint = GenesisAgentCheckpoint | EngineAgentCheckpoint;

// The durable (externalized) form of a checkpoint (storage redesign stage B):
// identical metadata, but the payload bytes live in a content-addressed blob keyed
// by payloadDigest, and only their exact length is retained inline. The wire form
// (AgentCheckpoint) keeps payloadBytes; the checkpoint chain digest is always
// computed over the wire form, so externalization never changes it.
interface ExternalizedAgentCheckpointBase {
  readonly engineKind: EngineKind;
  readonly adapterAbiVersion: number;
  readonly checkpointSchemaVersion: number;
  readonly runtimeRevisionDigest: Digest;
  readonly sessionId: string;
  readonly turnId: string;
  readonly payloadEncoding: CheckpointPayloadEncoding;
  readonly payloadDigest: Digest;
  readonly payloadSize: number;
}

export interface GenesisExternalizedAgentCheckpoint extends ExternalizedAgentCheckpointBase {
  readonly kind: "genesis";
  readonly checkpointSequence: 0;
  readonly predecessorDigest: null;
}

export interface EngineExternalizedAgentCheckpoint extends ExternalizedAgentCheckpointBase {
  readonly kind: "engine";
  readonly checkpointSequence: number;
  readonly predecessorDigest: Digest;
}

export type ExternalizedAgentCheckpoint =
  | GenesisExternalizedAgentCheckpoint
  | EngineExternalizedAgentCheckpoint;

export const EFFECT_SERVICES = [
  "model",
  "workspace",
  "executor",
  "mcp",
  "artifact",
  "external-tool",
] as const;

export type EffectService = (typeof EFFECT_SERVICES)[number];

export const REPLAY_POLICIES = ["safe", "idempotency-key", "never", "confirm"] as const;
export type ReplayPolicy = (typeof REPLAY_POLICIES)[number];

export interface EffectClaim {
  readonly tenantId: string;
  readonly userId: string;
  readonly sessionId: string;
  readonly turnId: string;
  readonly effectId: string;
  readonly invocationId: string;
  readonly requestDigest: Digest;
  readonly service: EffectService;
  readonly operation: string;
  readonly replayPolicy: ReplayPolicy;
  readonly parentOperationId?: string;
  readonly ordinal?: number;
}

export type EffectClaims = EffectClaim;

export interface DispatchPermitClaims extends EffectClaim {
  readonly dispatchAttempt: number;
  readonly turnLeaseGeneration: number;
  readonly placementGeneration: number;
  readonly sandboxGeneration: number;
  readonly authorizationGeneration: number;
  readonly providerRouteDigest: Digest;
  readonly deadline: number;
}

export interface EffectIntent {
  readonly service: EffectService;
  readonly operation: string;
  readonly replayPolicy: ReplayPolicy;
  readonly requestDigest: Digest;
  readonly payload: NormalizedValue;
  readonly parentOperationId?: string;
  readonly ordinal?: number;
}

export interface AgentError {
  readonly code: string;
  readonly message: string;
  readonly retryable: boolean;
  readonly details?: NormalizedValue;
}

export type EngineStepResult =
  | { readonly kind: "checkpoint"; readonly checkpoint: AgentCheckpoint }
  | {
      readonly kind: "effect_request";
      readonly checkpoint: AgentCheckpoint;
      readonly request: EffectIntent;
    }
  | {
      readonly kind: "turn_complete";
      readonly checkpoint: AgentCheckpoint;
      readonly result: NormalizedValue;
    }
  | {
      readonly kind: "turn_error";
      readonly checkpoint: AgentCheckpoint;
      readonly error: AgentError;
    };

export type ConformanceStatus =
  | { readonly status: "PASS" }
  | { readonly status: "FAIL" }
  | { readonly status: "NOT_RUN" }
  | { readonly status: "UNAVAILABLE"; readonly reason: string };

export interface CanonicalCborOptions {
  readonly maxDepth?: number;
  readonly maxBytes?: number;
  readonly maxItems?: number;
}

export interface RpcValidationOptions {
  readonly expectedSchemaDigest?: string;
  readonly maxDepth?: number;
  readonly maxEncodedBytes?: number;
  readonly maxItems?: number;
}

export type ValueParser<T> = (value: unknown) => T;
