import {
  assertUnicodeScalarString, normalizeCanonicalText, normalizeProtocolValue,
} from "@circulusd/protocol-types";
import type { NormalizedValue } from "@circulusd/protocol-types";

import { PiRuntimeError } from "./errors.ts";

// A finite non-safe-integer JSON number crosses the integer-only durable boundary
// as one canonical Number.toString() decimal. Integer-only values keep their bytes.
export const PI_NUMBER_WRAPPER_KEY = "$pi.number.v1" as const;
const maximumDepth = 64;
const maximumItems = 1_000_000;
type Mode = "encode" | "decode" | "validate";

interface Traversal {
  readonly mode: Mode;
  readonly seen: WeakSet<object>;
  items: number;
}

function invalid(path: string, message: string): never {
  throw new PiRuntimeError("INVALID_CONTEXT", `${path} ${message}`);
}

function walkPiJson(value: unknown, path: string, depth: number, traversal: Traversal): unknown {
  if (depth > maximumDepth) invalid(path, `exceeds maximum depth ${maximumDepth}`);
  if (traversal.items >= maximumItems) invalid(path, `exceeds encoded item limit ${maximumItems}`);
  traversal.items += 1;
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") {
    assertUnicodeScalarString(value, path);
    return normalizeCanonicalText(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) invalid(path, "must be a finite JSON number");
    if (Object.is(value, -0)) invalid(path, "negative zero is unsupported");
    if (Number.isSafeInteger(value)) return value;
    if (traversal.mode === "decode") invalid(path, "durable numbers must be safe integers or wrappers");
    if (traversal.mode === "validate") return value;
    // Account for the wrapper's key and decimal, including its additional depth.
    if (depth + 1 > maximumDepth) invalid(path, `exceeds maximum depth ${maximumDepth}`);
    if (traversal.items + 2 > maximumItems) invalid(path, `exceeds encoded item limit ${maximumItems}`);
    traversal.items += 2;
    return { [PI_NUMBER_WRAPPER_KEY]: value.toString() };
  }
  if (value instanceof Uint8Array) invalid(path, "must be JSON, not bytes");
  if (typeof value !== "object") invalid(path, `has an unsupported ${typeof value} value`);
  if (traversal.seen.has(value)) invalid(path, "cyclic or repeated object references are unsupported");
  traversal.seen.add(value);

  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype) invalid(path, "must be a plain array");
    if (value.length > maximumItems - traversal.items) invalid(path, `exceeds encoded item limit ${maximumItems}`);
    const keys = Reflect.ownKeys(value);
    if (keys.length !== value.length + 1) invalid(path, "sparse or custom arrays are unsupported");
    for (const key of keys) {
      if (key === "length") continue;
      if (typeof key !== "string" || !/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= value.length) {
        invalid(path, "arrays cannot have custom properties");
      }
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor)) {
        invalid(`${path}[${key}]`, "must be an enumerable data property");
      }
    }
    const result: unknown[] = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (descriptor === undefined || !("value" in descriptor)) invalid(path, "sparse arrays are unsupported");
      result.push(walkPiJson(descriptor.value, `${path}[${index}]`, depth + 1, traversal));
    }
    return result;
  }

  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) invalid(path, "must be a plain object");
  const keys = Reflect.ownKeys(value);
  if (keys.length > maximumItems - traversal.items) invalid(path, `exceeds encoded item limit ${maximumItems}`);
  const entries: [string, unknown][] = [];
  const normalizedKeys = new Set<string>();
  for (const key of keys) {
    if (typeof key !== "string") invalid(path, "symbol keys are unsupported");
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor)) {
      invalid(`${path}.${key}`, "must be an enumerable data property");
    }
    assertUnicodeScalarString(key, path);
    const normalizedKey = normalizeCanonicalText(key);
    if (normalizedKeys.has(normalizedKey)) invalid(path, `has duplicate normalized key ${JSON.stringify(normalizedKey)}`);
    normalizedKeys.add(normalizedKey);
    entries.push([normalizedKey, descriptor.value]);
  }
  traversal.items += keys.length;
  if (normalizedKeys.has(PI_NUMBER_WRAPPER_KEY)) {
    if (traversal.mode !== "decode") invalid(path, `uses the reserved key ${PI_NUMBER_WRAPPER_KEY}`);
    if (entries.length !== 1) invalid(path, "misuses the reserved number-wrapper key");
    const decimal = walkPiJson(entries[0]![1], `${path}.${PI_NUMBER_WRAPPER_KEY}`, depth + 1, traversal);
    if (typeof decimal !== "string" || decimal.length > 32) invalid(path, "number wrapper must hold a bounded decimal string");
    const restored = Number(decimal);
    if (
      !Number.isFinite(restored) || Object.is(restored, -0) ||
      Number.isSafeInteger(restored) || restored.toString() !== decimal
    ) invalid(path, "number wrapper is not a canonical non-safe-integer decimal");
    return restored;
  }
  const result: Record<string, unknown> = {};
  for (const [key, entry] of entries) {
    Object.defineProperty(result, key, {
      configurable: true, enumerable: true, writable: true,
      value: walkPiJson(entry, `${path}.${key}`, depth + 1, traversal),
    });
  }
  return result;
}

/** Validate and clone raw JSON without changing finite numeric values. */
export function validatePiJson(value: unknown): unknown {
  return walkPiJson(value, "$", 0, { mode: "validate", seen: new WeakSet<object>(), items: 0 });
}

/** Encode raw JSON for durable storage, rejecting pre-encoded reserved keys. */
export function encodePiJson(value: unknown): NormalizedValue {
  return normalizeProtocolValue(
    walkPiJson(value, "$", 0, { mode: "encode", seen: new WeakSet<object>(), items: 0 }),
    { maxDepth: maximumDepth, maxItems: maximumItems },
  );
}

/** Restore canonical durable JSON before schema validation, tools or providers. */
export function decodePiJson(value: NormalizedValue): unknown {
  return walkPiJson(value, "$", 0, { mode: "decode", seen: new WeakSet<object>(), items: 0 });
}
