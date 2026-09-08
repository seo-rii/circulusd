import { normalizeProtocolValue } from "@circulusd/protocol-types";
import type { NormalizedValue } from "@circulusd/protocol-types";

import { PiRuntimeError } from "./errors.ts";

// Reserved wrapper key carrying a fractional (non-safe-integer) JSON number across
// the integer-only canonical CBOR boundary. Tool-call arguments and tool JSON
// Schemas legitimately contain fractional numbers (e.g. {"temperature":1.25},
// {"type":"number","minimum":0.1}), but the shared canonical encoder is integer-only
// by design so that digests and idempotency stay deterministic. A fractional number
// is therefore encoded as { [PI_NUMBER_WRAPPER_KEY]: "<canonical decimal>" } and
// restored before schema validation, tool execution, or a provider request. Safe
// integers are left untouched, so encodePiJson is byte-identical to
// normalizeProtocolValue for any integer-only value.
export const PI_NUMBER_WRAPPER_KEY = "$pi.number.v1" as const;

function decimalString(value: number): string {
  // Number.prototype.toString() round-trips the exact binary64 value and Number()
  // restores it; no currency quantum or precision assumption is introduced.
  return value.toString();
}

function isPlainObject(value: object): boolean {
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function walkPiJson(value: unknown, path: string, seen: WeakSet<object>, wrap: boolean): unknown {
  if (value === null || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "string") {
    return value.normalize("NFC");
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new PiRuntimeError("INVALID_CONTEXT", `${path} must be a finite JSON number`);
    }
    if (Object.is(value, -0)) {
      throw new PiRuntimeError("INVALID_CONTEXT", `${path} negative zero is unsupported`);
    }
    if (Number.isSafeInteger(value)) {
      return value;
    }
    return wrap ? { [PI_NUMBER_WRAPPER_KEY]: decimalString(value) } : value;
  }
  if (value instanceof Uint8Array) {
    throw new PiRuntimeError("INVALID_CONTEXT", `${path} must be JSON, not bytes`);
  }
  if (typeof value !== "object") {
    throw new PiRuntimeError("INVALID_CONTEXT", `${path} has an unsupported ${typeof value} value`);
  }
  if (seen.has(value)) {
    throw new PiRuntimeError("INVALID_CONTEXT", `${path} contains a cyclic reference`);
  }
  seen.add(value);
  if (Array.isArray(value)) {
    return value.map((entry, index) => walkPiJson(entry, `${path}[${index}]`, seen, wrap));
  }
  if (!isPlainObject(value)) {
    throw new PiRuntimeError("INVALID_CONTEXT", `${path} must be a plain object`);
  }
  const record = value as Record<string, unknown>;
  if (Object.prototype.hasOwnProperty.call(record, PI_NUMBER_WRAPPER_KEY)) {
    throw new PiRuntimeError("INVALID_CONTEXT", `${path} uses the reserved key ${PI_NUMBER_WRAPPER_KEY}`);
  }
  const result: Record<string, unknown> = {};
  for (const key of Object.keys(record)) {
    result[key.normalize("NFC")] = walkPiJson(record[key], `${path}.${key}`, seen, wrap);
  }
  return result;
}

/**
 * Validates a Pi tool JSON value (tool-call arguments or a tool JSON Schema) with
 * the same structural rules as the canonical encoder but permitting finite
 * fractional numbers, which it leaves as real numbers. Use it where the value is
 * consumed as real JSON in process (JSON-Schema validation, model-request tools
 * before encoding). Rejects non-finite numbers, byte values, cycles, non-plain
 * objects, and any object that already uses the reserved wrapper key.
 */
export function validatePiJson(value: unknown): unknown {
  return walkPiJson(value, "$", new WeakSet<object>(), false);
}

/**
 * Validates a Pi tool JSON value and returns a canonical, integer-only
 * NormalizedValue with every fractional number replaced by a wrapper. The result
 * is safe to store durably or place in an effect payload. For any integer-only
 * value the result is identical to normalizeProtocolValue(value).
 */
export function encodePiJson(value: unknown): NormalizedValue {
  return normalizeProtocolValue(walkPiJson(value, "$", new WeakSet<object>(), true));
}

function unwrapPiJson(value: NormalizedValue, path: string): unknown {
  if (
    value === null || typeof value === "boolean" ||
    typeof value === "string" || typeof value === "number" ||
    value instanceof Uint8Array
  ) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((entry, index) => unwrapPiJson(entry, `${path}[${index}]`));
  }
  const record = value as Record<string, NormalizedValue>;
  const entries = Object.entries(record);
  if (entries.length === 1 && entries[0]?.[0] === PI_NUMBER_WRAPPER_KEY) {
    const decimal = entries[0][1];
    if (typeof decimal !== "string") {
      throw new PiRuntimeError("INVALID_CONTEXT", `${path} number wrapper must hold a decimal string`);
    }
    const restored = Number(decimal);
    if (!Number.isFinite(restored) || Object.is(restored, -0) || restored.toString() !== decimal) {
      throw new PiRuntimeError("INVALID_CONTEXT", `${path} number wrapper is not a canonical decimal`);
    }
    return restored;
  }
  const result: Record<string, unknown> = {};
  for (const [key, entry] of entries) {
    if (key === PI_NUMBER_WRAPPER_KEY) {
      throw new PiRuntimeError("INVALID_CONTEXT", `${path} misuses the reserved number-wrapper key`);
    }
    result[key] = unwrapPiJson(entry, `${path}.${key}`);
  }
  return result;
}

/**
 * Restores a value produced by encodePiJson to real JSON, converting each
 * { [PI_NUMBER_WRAPPER_KEY]: "<decimal>" } wrapper back to its number. Every
 * consumer that needs real numbers (JSON-Schema validation, tool execution, a
 * provider request) must decode first.
 */
export function decodePiJson(value: NormalizedValue): unknown {
  return unwrapPiJson(value, "$");
}
