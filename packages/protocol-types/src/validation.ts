import { encodeCanonicalCbor, normalizeProtocolValue } from "./cbor.ts";
import { digestBytes, parseDigest } from "./digest.ts";
import { validationError } from "./errors.ts";
import { assertUnicodeScalarString } from "./text.ts";
import {
  EFFECT_SERVICES,
  PROTOCOL_MAJOR,
  PROTOCOL_MINOR,
  PROTOCOL_NAME,
  REPLAY_POLICIES,
} from "./types.ts";
import type {
  AgentCheckpoint,
  ConformanceStatus,
  DispatchPermitClaims,
  EffectClaim,
  EffectService,
  EngineStepResult,
  ReplayPolicy,
  RpcEnvelope,
  RpcValidationOptions,
  ValueParser,
} from "./types.ts";

const DEFAULT_RPC_MAX_DEPTH = 64;
const DEFAULT_RPC_MAX_ENCODED_BYTES = 1_048_576;
const MAX_IDENTIFIER_BYTES = 256;
const MAX_OPERATION_BYTES = 256;
const MAX_CHECKPOINT_PAYLOAD_BYTES = 4 * 1_048_576;
const textEncoder = new TextEncoder();

const hasOwn = (record: Record<string, unknown>, key: string): boolean =>
  Object.prototype.hasOwnProperty.call(record, key);

function plainRecord(value: unknown, path: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    validationError(path, "must be a plain object");
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    validationError(path, "must be a plain object");
  }
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string") {
      validationError(path, "symbol keys are unsupported");
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor)) {
      validationError(`${path}.${key}`, "must be an enumerable data property");
    }
  }
  return value as Record<string, unknown>;
}

function exactRecord(
  value: unknown,
  required: readonly string[],
  optional: readonly string[],
  path: string,
): Record<string, unknown> {
  const record = plainRecord(value, path);
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) {
      validationError(`${path}.${key}`, `unknown field ${JSON.stringify(key)}`);
    }
  }
  for (const key of required) {
    if (!hasOwn(record, key)) {
      validationError(`${path}.${key}`, `missing required field ${JSON.stringify(key)}`);
    }
  }
  return record;
}

function nfcString(
  value: unknown,
  path: string,
  options: { readonly maxBytes: number; readonly allowEmpty?: boolean },
): string {
  if (typeof value !== "string") {
    validationError(path, "must be a string");
  }
  assertUnicodeScalarString(value, path);
  if (value !== value.normalize("NFC")) {
    validationError(path, "must be NFC-normalized");
  }
  if (options.allowEmpty !== true && value.length === 0) {
    validationError(path, "must not be empty");
  }
  if (textEncoder.encode(value).byteLength > options.maxBytes) {
    validationError(path, `must not exceed ${options.maxBytes} UTF-8 bytes`);
  }
  if (/\p{Cc}/u.test(value)) {
    validationError(path, "must not contain control characters");
  }
  return value;
}

function identifier(value: unknown, path: string): string {
  return nfcString(value, path, { maxBytes: MAX_IDENTIFIER_BYTES });
}

function operation(value: unknown, path: string): string {
  return nfcString(value, path, { maxBytes: MAX_OPERATION_BYTES });
}

function safeInteger(value: unknown, path: string, minimum: number): number {
  if (!Number.isSafeInteger(value) || typeof value !== "number" || value < minimum) {
    validationError(path, `must be a safe integer greater than or equal to ${minimum}`);
  }
  return value;
}

function exactLiteral<T extends string | number>(
  value: unknown,
  expected: T,
  path: string,
): T {
  if (value !== expected) {
    validationError(path, `must be ${JSON.stringify(expected)}`);
  }
  return expected;
}

function oneOf<const T extends readonly string[]>(
  value: unknown,
  allowed: T,
  path: string,
): T[number] {
  if (typeof value !== "string" || !allowed.includes(value)) {
    validationError(path, `must be one of ${allowed.join(", ")}`);
  }
  return value;
}

export function parseRpcEnvelope<T>(
  value: unknown,
  payloadParser: ValueParser<T>,
  options: RpcValidationOptions = {},
): RpcEnvelope<T> {
  const record = exactRecord(
    value,
    ["protocol", "major", "minor", "schemaDigest", "requestId", "payload"],
    [],
    "$envelope",
  );
  const schemaDigest = parseDigest(record.schemaDigest, "$envelope.schemaDigest");
  if (options.expectedSchemaDigest !== undefined) {
    const expected = parseDigest(options.expectedSchemaDigest, "options.expectedSchemaDigest");
    if (schemaDigest !== expected) {
      validationError("$envelope.schemaDigest", "does not match the expected schemaDigest");
    }
  }

  const envelope: RpcEnvelope<T> = {
    protocol: exactLiteral(record.protocol, PROTOCOL_NAME, "$envelope.protocol"),
    major: exactLiteral(record.major, PROTOCOL_MAJOR, "$envelope.major"),
    minor: exactLiteral(record.minor, PROTOCOL_MINOR, "$envelope.minor"),
    schemaDigest,
    requestId: identifier(record.requestId, "$envelope.requestId"),
    payload: payloadParser(record.payload),
  };

  const maxDepth = options.maxDepth ?? DEFAULT_RPC_MAX_DEPTH;
  const maxEncodedBytes = options.maxEncodedBytes ?? DEFAULT_RPC_MAX_ENCODED_BYTES;
  encodeCanonicalCbor(envelope, { maxBytes: maxEncodedBytes, maxDepth });
  return envelope;
}

export const validateRpcEnvelope = parseRpcEnvelope;

const CHECKPOINT_FIELDS = [
  "kind",
  "engineKind",
  "adapterAbiVersion",
  "checkpointSchemaVersion",
  "runtimeRevisionDigest",
  "sessionId",
  "turnId",
  "checkpointSequence",
  "predecessorDigest",
  "payloadEncoding",
  "payloadBytes",
  "payloadDigest",
] as const;

export function parseAgentCheckpoint(value: unknown): AgentCheckpoint {
  const record = exactRecord(value, CHECKPOINT_FIELDS, [], "$checkpoint");
  if (
    !(record.payloadBytes instanceof Uint8Array) ||
    Object.getPrototypeOf(record.payloadBytes) !== Uint8Array.prototype
  ) {
    validationError("$checkpoint.payloadBytes", "must be an exact Uint8Array");
  }
  if (record.payloadBytes.byteLength > MAX_CHECKPOINT_PAYLOAD_BYTES) {
    validationError(
      "$checkpoint.payloadBytes",
      `must not exceed ${MAX_CHECKPOINT_PAYLOAD_BYTES} bytes`,
    );
  }
  const common = {
    engineKind: oneOf(
      record.engineKind,
      ["low-level", "agent-harness"] as const,
      "$checkpoint.engineKind",
    ),
    adapterAbiVersion: safeInteger(record.adapterAbiVersion, "$checkpoint.adapterAbiVersion", 1),
    checkpointSchemaVersion: safeInteger(
      record.checkpointSchemaVersion,
      "$checkpoint.checkpointSchemaVersion",
      1,
    ),
    runtimeRevisionDigest: parseDigest(
      record.runtimeRevisionDigest,
      "$checkpoint.runtimeRevisionDigest",
    ),
    sessionId: identifier(record.sessionId, "$checkpoint.sessionId"),
    turnId: identifier(record.turnId, "$checkpoint.turnId"),
    payloadEncoding: oneOf(
      record.payloadEncoding,
      ["protobuf", "canonical-cbor", "opaque-v1"] as const,
      "$checkpoint.payloadEncoding",
    ),
    payloadBytes: new Uint8Array(record.payloadBytes),
    payloadDigest: parseDigest(record.payloadDigest, "$checkpoint.payloadDigest"),
  };

  if (record.kind === "genesis") {
    exactLiteral(record.checkpointSequence, 0, "$checkpoint.checkpointSequence");
    if (record.predecessorDigest !== null) {
      validationError("$checkpoint.predecessorDigest", "must be null for a genesis checkpoint");
    }
    return {
      kind: "genesis",
      ...common,
      checkpointSequence: 0,
      predecessorDigest: null,
    };
  }
  if (record.kind === "engine") {
    return {
      kind: "engine",
      ...common,
      checkpointSequence: safeInteger(
        record.checkpointSequence,
        "$checkpoint.checkpointSequence",
        1,
      ),
      predecessorDigest: parseDigest(
        record.predecessorDigest,
        "$checkpoint.predecessorDigest",
      ),
    };
  }
  validationError("$checkpoint.kind", "must be genesis or engine");
}

export async function assertCheckpointPayloadDigest(
  checkpoint: AgentCheckpoint,
): Promise<void> {
  const actual = await digestBytes(checkpoint.payloadBytes);
  if (actual !== checkpoint.payloadDigest) {
    validationError("$checkpoint.payloadDigest", "does not match payloadBytes");
  }
}

export async function validateAgentCheckpoint(value: unknown): Promise<AgentCheckpoint> {
  const checkpoint = parseAgentCheckpoint(value);
  await assertCheckpointPayloadDigest(checkpoint);
  return checkpoint;
}

const EFFECT_REQUIRED_FIELDS = [
  "tenantId",
  "userId",
  "sessionId",
  "turnId",
  "effectId",
  "invocationId",
  "requestDigest",
  "service",
  "operation",
  "replayPolicy",
] as const;
const EFFECT_OPTIONAL_FIELDS = ["parentOperationId", "ordinal"] as const;

function parseEffectService(value: unknown, path: string): EffectService {
  return oneOf(value, EFFECT_SERVICES, path);
}

function parseReplayPolicy(value: unknown, path: string): ReplayPolicy {
  return oneOf(value, REPLAY_POLICIES, path);
}

function compositeFields(
  record: Record<string, unknown>,
  path: string,
): Pick<EffectClaim, "parentOperationId" | "ordinal"> {
  const hasParent = hasOwn(record, "parentOperationId");
  const hasOrdinal = hasOwn(record, "ordinal");
  if (hasParent !== hasOrdinal) {
    validationError(path, "parentOperationId and ordinal must appear together");
  }
  if (!hasParent) {
    return {};
  }
  return {
    parentOperationId: identifier(record.parentOperationId, `${path}.parentOperationId`),
    ordinal: safeInteger(record.ordinal, `${path}.ordinal`, 0),
  };
}

function effectClaimFromRecord(record: Record<string, unknown>, path: string): EffectClaim {
  return {
    tenantId: identifier(record.tenantId, `${path}.tenantId`),
    userId: identifier(record.userId, `${path}.userId`),
    sessionId: identifier(record.sessionId, `${path}.sessionId`),
    turnId: identifier(record.turnId, `${path}.turnId`),
    effectId: identifier(record.effectId, `${path}.effectId`),
    invocationId: identifier(record.invocationId, `${path}.invocationId`),
    requestDigest: parseDigest(record.requestDigest, `${path}.requestDigest`),
    service: parseEffectService(record.service, `${path}.service`),
    operation: operation(record.operation, `${path}.operation`),
    replayPolicy: parseReplayPolicy(record.replayPolicy, `${path}.replayPolicy`),
    ...compositeFields(record, path),
  };
}

export function parseEffectClaim(value: unknown): EffectClaim {
  const record = exactRecord(
    value,
    EFFECT_REQUIRED_FIELDS,
    EFFECT_OPTIONAL_FIELDS,
    "$effectClaim",
  );
  return effectClaimFromRecord(record, "$effectClaim");
}

const PERMIT_FIELDS = [
  ...EFFECT_REQUIRED_FIELDS,
  "dispatchAttempt",
  "turnLeaseGeneration",
  "placementGeneration",
  "sandboxGeneration",
  "authorizationGeneration",
  "deadline",
] as const;

export function parseDispatchPermitClaims(value: unknown): DispatchPermitClaims {
  const record = exactRecord(
    value,
    PERMIT_FIELDS,
    EFFECT_OPTIONAL_FIELDS,
    "$dispatchPermitClaims",
  );
  return {
    ...effectClaimFromRecord(record, "$dispatchPermitClaims"),
    dispatchAttempt: safeInteger(
      record.dispatchAttempt,
      "$dispatchPermitClaims.dispatchAttempt",
      1,
    ),
    turnLeaseGeneration: safeInteger(
      record.turnLeaseGeneration,
      "$dispatchPermitClaims.turnLeaseGeneration",
      0,
    ),
    placementGeneration: safeInteger(
      record.placementGeneration,
      "$dispatchPermitClaims.placementGeneration",
      0,
    ),
    sandboxGeneration: safeInteger(
      record.sandboxGeneration,
      "$dispatchPermitClaims.sandboxGeneration",
      0,
    ),
    authorizationGeneration: safeInteger(
      record.authorizationGeneration,
      "$dispatchPermitClaims.authorizationGeneration",
      0,
    ),
    deadline: safeInteger(record.deadline, "$dispatchPermitClaims.deadline", 1),
  };
}

export function parseEngineStepResult(value: unknown): EngineStepResult {
  const preliminary = plainRecord(value, "$engineStepResult");
  switch (preliminary.kind) {
    case "checkpoint": {
      const record = exactRecord(
        preliminary,
        ["kind", "checkpoint"],
        [],
        "$engineStepResult",
      );
      return { kind: "checkpoint", checkpoint: parseAgentCheckpoint(record.checkpoint) };
    }
    case "effect_request": {
      const record = exactRecord(
        preliminary,
        ["kind", "checkpoint", "request"],
        [],
        "$engineStepResult",
      );
      const request = exactRecord(
        record.request,
        ["service", "operation", "replayPolicy", "requestDigest", "payload"],
        EFFECT_OPTIONAL_FIELDS,
        "$engineStepResult.request",
      );
      return {
        kind: "effect_request",
        checkpoint: parseAgentCheckpoint(record.checkpoint),
        request: {
          service: parseEffectService(
            request.service,
            "$engineStepResult.request.service",
          ),
          operation: operation(request.operation, "$engineStepResult.request.operation"),
          replayPolicy: parseReplayPolicy(
            request.replayPolicy,
            "$engineStepResult.request.replayPolicy",
          ),
          requestDigest: parseDigest(
            request.requestDigest,
            "$engineStepResult.request.requestDigest",
          ),
          payload: normalizeProtocolValue(request.payload),
          ...compositeFields(request, "$engineStepResult.request"),
        },
      };
    }
    case "turn_complete": {
      const record = exactRecord(
        preliminary,
        ["kind", "checkpoint", "result"],
        [],
        "$engineStepResult",
      );
      return {
        kind: "turn_complete",
        checkpoint: parseAgentCheckpoint(record.checkpoint),
        result: normalizeProtocolValue(record.result),
      };
    }
    case "turn_error": {
      const record = exactRecord(
        preliminary,
        ["kind", "checkpoint", "error"],
        [],
        "$engineStepResult",
      );
      const error = exactRecord(
        record.error,
        ["code", "message", "retryable"],
        ["details"],
        "$engineStepResult.error",
      );
      if (typeof error.retryable !== "boolean") {
        validationError("$engineStepResult.error.retryable", "must be a boolean");
      }
      const parsedError = {
        code: operation(error.code, "$engineStepResult.error.code"),
        message: nfcString(error.message, "$engineStepResult.error.message", {
          maxBytes: 4096,
        }),
        retryable: error.retryable,
      };
      return {
        kind: "turn_error",
        checkpoint: parseAgentCheckpoint(record.checkpoint),
        error: hasOwn(error, "details")
          ? { ...parsedError, details: normalizeProtocolValue(error.details) }
          : parsedError,
      };
    }
    default:
      validationError(
        "$engineStepResult.kind",
        "must be checkpoint, effect_request, turn_complete, or turn_error",
      );
  }
}

export async function validateEngineStepResult(value: unknown): Promise<EngineStepResult> {
  const result = parseEngineStepResult(value);
  await assertCheckpointPayloadDigest(result.checkpoint);
  return result;
}

export function parseConformanceStatus(value: unknown): ConformanceStatus {
  const preliminary = plainRecord(value, "$conformanceStatus");
  if (preliminary.status === "UNAVAILABLE") {
    const record = exactRecord(
      preliminary,
      ["status", "reason"],
      [],
      "$conformanceStatus",
    );
    return {
      status: "UNAVAILABLE",
      reason: nfcString(record.reason, "$conformanceStatus.reason", { maxBytes: 4096 }),
    };
  }
  const record = exactRecord(preliminary, ["status"], [], "$conformanceStatus");
  if (record.status === "PASS" || record.status === "FAIL" || record.status === "NOT_RUN") {
    return { status: record.status };
  }
  validationError(
    "$conformanceStatus.status",
    "must be PASS, FAIL, UNAVAILABLE, or NOT_RUN",
  );
}

export function isPassingConformanceStatus(status: ConformanceStatus): boolean {
  return status.status === "PASS";
}
