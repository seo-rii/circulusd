import {
  ProtocolValidationError,
  encodeCanonicalCbor,
  normalizeProtocolValue,
  parseDigest,
  type Digest,
  type EffectIntent,
  type NormalizedValue,
} from "@circulusd/protocol-types";

import { BoundaryFault, PiRuntimeError } from "./errors.ts";
import {
  EFFECT_SERVICE_VALUES,
  REPLAY_POLICY_VALUES,
  type EffectRequestDraft,
  type EffectSettlementOutcome,
  type EngineSettlement,
} from "./types.ts";
import type { BoundaryFaultCode, PiRuntimeErrorCode } from "./errors.ts";

const textEncoder = new TextEncoder();

type ValidationCode = PiRuntimeErrorCode | BoundaryFaultCode;

function validationFailure(code: ValidationCode, message: string, cause?: unknown): never {
  if (
    code === "CORE_OUTPUT_INVALID" ||
    code === "CORE_EXECUTION_FAILED" ||
    code === "EXTENSION_OUTPUT_INVALID" ||
    code === "EXTENSION_HOOK_FAILED" ||
    code === "EVENT_BUDGET_EXCEEDED" ||
    code === "STEP_TIMEOUT" ||
    code === "TURN_ABORTED"
  ) {
    throw new BoundaryFault(code, message, cause === undefined ? undefined : { cause });
  }
  throw new PiRuntimeError(code, message, cause === undefined ? undefined : { cause });
}

export function exactRecord(
  value: unknown,
  required: readonly string[],
  optional: readonly string[],
  path: string,
  code: ValidationCode,
): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    validationFailure(code, `${path} must be a plain object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    validationFailure(code, `${path} must be a plain object`);
  }
  const allowed = new Set([...required, ...optional]);
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string" || !allowed.has(key)) {
      validationFailure(code, `${path} has unknown field ${String(key)}`);
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !descriptor.enumerable ||
      !("value" in descriptor)
    ) {
      validationFailure(code, `${path}.${key} must be an enumerable data property`);
    }
  }
  const record = value as Record<string, unknown>;
  for (const field of required) {
    if (!Object.prototype.hasOwnProperty.call(record, field)) {
      validationFailure(code, `${path} is missing field ${field}`);
    }
  }
  return record;
}

export function boundedIdentifier(
  value: unknown,
  path: string,
  code: ValidationCode,
): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value !== value.normalize("NFC") ||
    textEncoder.encode(value).byteLength > 256 ||
    /\p{Cc}/u.test(value)
  ) {
    validationFailure(code, `${path} must be a non-empty bounded NFC identifier`);
  }
  return value;
}

export function boundedSafeInteger(
  value: unknown,
  minimum: number,
  path: string,
  code: ValidationCode,
): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum) {
    validationFailure(code, `${path} must be a safe integer >= ${minimum}`);
  }
  return value;
}

export function boundedProtocolValue(
  value: unknown,
  maxBytes: number,
  path: string,
  code: ValidationCode,
): NormalizedValue {
  try {
    const normalized = normalizeProtocolValue(value);
    encodeCanonicalCbor(normalized, { maxBytes });
    return normalized;
  } catch (error) {
    if (error instanceof ProtocolValidationError) {
      validationFailure(code, `${path} is not a bounded protocol value: ${error.message}`, error);
    }
    throw error;
  }
}

export function parseEffectRequestDraft(
  value: unknown,
  maxBytes: number,
  path: string,
  code: ValidationCode,
): EffectRequestDraft {
  const record = exactRecord(
    value,
    ["service", "operation", "replayPolicy", "payload"],
    ["parentOperationId", "ordinal"],
    path,
    code,
  );
  if (
    typeof record.service !== "string" ||
    !EFFECT_SERVICE_VALUES.includes(record.service as (typeof EFFECT_SERVICE_VALUES)[number])
  ) {
    validationFailure(code, `${path}.service is unsupported`);
  }
  if (
    typeof record.replayPolicy !== "string" ||
    !REPLAY_POLICY_VALUES.includes(record.replayPolicy as (typeof REPLAY_POLICY_VALUES)[number])
  ) {
    validationFailure(code, `${path}.replayPolicy is unsupported`);
  }
  const hasParent = Object.prototype.hasOwnProperty.call(record, "parentOperationId");
  const hasOrdinal = Object.prototype.hasOwnProperty.call(record, "ordinal");
  if (hasParent !== hasOrdinal) {
    validationFailure(code, `${path} must provide parentOperationId and ordinal together`);
  }
  const draft: EffectRequestDraft = {
    service: record.service as EffectRequestDraft["service"],
    operation: boundedIdentifier(record.operation, `${path}.operation`, code),
    replayPolicy: record.replayPolicy as EffectRequestDraft["replayPolicy"],
    payload: boundedProtocolValue(record.payload, maxBytes, `${path}.payload`, code),
    ...(hasParent
      ? {
          parentOperationId: boundedIdentifier(
            record.parentOperationId,
            `${path}.parentOperationId`,
            code,
          ),
          ordinal: boundedSafeInteger(record.ordinal, 0, `${path}.ordinal`, code),
        }
      : {}),
  };
  boundedProtocolValue(draft, maxBytes, path, code);
  return draft;
}

export function parseEffectIntent(
  value: unknown,
  maxBytes: number,
  path: string,
  code: ValidationCode,
): EffectIntent {
  const record = exactRecord(
    value,
    ["service", "operation", "replayPolicy", "requestDigest", "payload"],
    ["parentOperationId", "ordinal"],
    path,
    code,
  );
  const draft = parseEffectRequestDraft(
    {
      service: record.service,
      operation: record.operation,
      replayPolicy: record.replayPolicy,
      payload: record.payload,
      ...(Object.prototype.hasOwnProperty.call(record, "parentOperationId")
        ? { parentOperationId: record.parentOperationId, ordinal: record.ordinal }
        : {}),
    },
    maxBytes,
    path,
    code,
  );
  return {
    ...draft,
    requestDigest: parseDigestForBoundary(record.requestDigest, `${path}.requestDigest`, code),
  };
}

export function parseSettlementOutcome(
  value: unknown,
  maxBytes: number,
  path: string,
  code: ValidationCode,
): EffectSettlementOutcome {
  const preliminary = exactRecord(value, ["kind"], ["result", "code", "message", "retryable", "reason"], path, code);
  switch (preliminary.kind) {
    case "success": {
      const record = exactRecord(value, ["kind", "result"], [], path, code);
      return {
        kind: "success",
        result: boundedProtocolValue(record.result, maxBytes, `${path}.result`, code),
      };
    }
    case "error": {
      const record = exactRecord(
        value,
        ["kind", "code", "message", "retryable"],
        [],
        path,
        code,
      );
      if (typeof record.retryable !== "boolean") {
        validationFailure(code, `${path}.retryable must be a boolean`);
      }
      return {
        kind: "error",
        code: boundedIdentifier(record.code, `${path}.code`, code),
        message: boundedIdentifier(record.message, `${path}.message`, code),
        retryable: record.retryable,
      };
    }
    case "interrupted_unknown":
    case "abandoned": {
      const record = exactRecord(value, ["kind", "reason"], [], path, code);
      return {
        kind: preliminary.kind,
        reason: boundedIdentifier(record.reason, `${path}.reason`, code),
      };
    }
    default:
      validationFailure(code, `${path}.kind is unsupported`);
  }
}

export function parseEngineSettlement(
  value: unknown,
  maxBytes: number,
  path: string,
): EngineSettlement {
  const record = exactRecord(
    value,
    ["requestDigest", "outcome"],
    [],
    path,
    "INVALID_CONTEXT",
  );
  let requestDigest: Digest;
  try {
    requestDigest = parseDigest(record.requestDigest, `${path}.requestDigest`);
  } catch (error) {
    validationFailure("INVALID_CONTEXT", `${path}.requestDigest is invalid`, error);
  }
  return {
    requestDigest,
    outcome: parseSettlementOutcome(
      record.outcome,
      maxBytes,
      `${path}.outcome`,
      "INVALID_CONTEXT",
    ),
  };
}

export function frozenProtocolClone<T>(value: T): T {
  const cloned = structuredClone(value);
  const pending: object[] = [];
  if (cloned !== null && typeof cloned === "object") pending.push(cloned);
  const visited = new WeakSet<object>();
  while (pending.length > 0) {
    const current = pending.pop();
    if (current === undefined || visited.has(current)) continue;
    visited.add(current);
    if (current instanceof Uint8Array) continue;
    for (const entry of Object.values(current)) {
      if (entry !== null && typeof entry === "object") pending.push(entry);
    }
    Object.freeze(current);
  }
  return cloned;
}

export function frozenSignalContext<T extends Record<string, unknown>>(
  value: T,
): Readonly<T> {
  const cloned: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value)) {
    Object.defineProperty(cloned, key, {
      enumerable: true,
      value: key === "signal" ? entry : frozenProtocolClone(entry),
    });
  }
  return Object.freeze(cloned) as T;
}

export function parseDigestForBoundary(
  value: unknown,
  path: string,
  code: ValidationCode,
): Digest {
  try {
    return parseDigest(value, path);
  } catch (error) {
    validationFailure(code, `${path} is invalid`, error);
  }
}
