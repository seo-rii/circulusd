import { digestStructuredValue, encodeCanonicalCbor, type Digest } from "@circulusd/protocol-types";

export type JsonValue = null | boolean | number | string | readonly JsonValue[] | { readonly [key: string]: JsonValue };

/**
 * Extension JSON accepts finite binary64 numbers, empty strings, and nested
 * values; -0 becomes +0 and text becomes NFC. Native control-plane CBOR remains
 * integer-only. Safe-integer JSON uses the existing domain/version-1 digest.
 * Other numbers select version 2 in the SAME domain, hashing a CBOR byte string
 * containing ["circulusd.extension-json", 2, fullyTypeTaggedTree]. Number nodes
 * contain 16 lowercase big-endian binary64 hex digits. Every JSON node is tagged
 * so user keys/arrays can never masquerade as a numeric transport wrapper.
 */
export function normalizeExtensionJson(value: unknown): JsonValue {
  let items = 0;
  let bytes = 0;
  const seen = new WeakSet<object>();
  const text = (input: string, maximum: number): string => {
    for (let index = 0; index < input.length; index++) {
      const code = input.charCodeAt(index);
      if (code >= 0xd800 && code <= 0xdbff) {
        const next = input.charCodeAt(++index);
        if (!(next >= 0xdc00 && next <= 0xdfff)) throw new Error("JSON text must contain Unicode scalar values");
      } else if (code >= 0xdc00 && code <= 0xdfff) throw new Error("JSON text must contain Unicode scalar values");
    }
    const normalized = input.normalize("NFC");
    const size = new TextEncoder().encode(normalized).byteLength;
    bytes += size;
    if (size > maximum || bytes > 1_048_576) throw new Error("extension JSON text exceeds its byte limit");
    return normalized;
  };
  const visit = (current: unknown, depth: number): JsonValue => {
    if (++items > 10_000 || depth > 64) throw new Error("extension JSON exceeds its item or depth limit");
    if (current === null || typeof current === "boolean") return current;
    if (typeof current === "string") return text(current, 65_536);
    if (typeof current === "number") {
      if (!Number.isFinite(current)) throw new Error("extension JSON numbers must be finite binary64 values");
      return Object.is(current, -0) ? 0 : current;
    }
    if (current === null || typeof current !== "object" || seen.has(current)) throw new Error("extension JSON must have unique plain objects and arrays");
    seen.add(current);
    if (Array.isArray(current)) {
      if (Object.getPrototypeOf(current) !== Array.prototype) throw new Error("extension JSON arrays must be plain");
      if (current.length > 10_000) throw new Error("extension JSON exceeds its item limit");
      for (const key of Reflect.ownKeys(current)) {
        if (key !== "length" && (typeof key !== "string" || !/^(?:0|[1-9]\d*)$/.test(key))) throw new Error("extension JSON arrays cannot have extra properties");
      }
      return Array.from({ length: current.length }, (_, index) => {
        const descriptor = Object.getOwnPropertyDescriptor(current, String(index));
        if (!descriptor?.enumerable || !("value" in descriptor)) throw new Error("extension JSON arrays must be dense data arrays");
        return visit(descriptor.value, depth + 1);
      });
    }
    if (Object.getPrototypeOf(current) !== Object.prototype) throw new Error("extension JSON objects must be plain");
    const entries: [string, JsonValue][] = [];
    const keys = new Set<string>();
    for (const key of Reflect.ownKeys(current)) {
      if (typeof key !== "string") throw new Error("extension JSON cannot have symbol properties");
      const descriptor = Object.getOwnPropertyDescriptor(current, key);
      if (!descriptor?.enumerable || !("value" in descriptor)) throw new Error("extension JSON properties must be enumerable data properties");
      const normalizedKey = text(key, 256);
      if (["__proto__", "constructor", "prototype"].includes(normalizedKey)) throw new Error("dangerous extension JSON object key is not allowed");
      if (keys.has(normalizedKey)) throw new Error("extension JSON has duplicate normalized keys");
      keys.add(normalizedKey);
      entries.push([normalizedKey, visit(descriptor.value, depth + 1)]);
    }
    return Object.fromEntries(entries);
  };
  return visit(value, 0);
}

function needsVersion2(value: JsonValue): boolean {
  if (typeof value === "number") return !Number.isSafeInteger(value);
  if (Array.isArray(value)) return value.some(needsVersion2);
  if (value !== null && typeof value === "object") return Object.values(value).some(needsVersion2);
  return false;
}

function tagged(value: JsonValue): unknown {
  if (value === null) return ["null"];
  if (typeof value === "boolean") return ["boolean", value];
  if (typeof value === "string") return ["string", value];
  if (typeof value === "number") {
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setFloat64(0, value, false);
    return ["number", [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("")];
  }
  if (Array.isArray(value)) return ["array", value.map(tagged)];
  // Canonical CBOR sorts UTF-8 map keys; retaining the object here gives the
  // same order in Go and TS without relying on JavaScript UTF-16 ordering.
  return ["object", Object.fromEntries(Object.entries(value).map(([key, item]) => [key, tagged(item)]))];
}

export function extensionJsonDigestPayload(value: unknown): { readonly schemaVersion: 1 | 2; readonly payload: unknown } {
  const normalized = normalizeExtensionJson(value);
  if (!needsVersion2(normalized)) return { schemaVersion: 1, payload: normalized };
  return { schemaVersion: 2, payload: ["circulusd.extension-json", 2, tagged(normalized)] };
}

export function encodeExtensionJsonDigestPayload(value: unknown): Uint8Array {
  const { payload } = extensionJsonDigestPayload(value);
  return encodeCanonicalCbor(payload, { maxDepth: 140, maxItems: 100_000 });
}

export async function digestExtensionJson(domain: string, value: unknown): Promise<Digest> {
  const { schemaVersion, payload } = extensionJsonDigestPayload(value);
  // Tagged nodes can double JSON depth. Pass the already encoded payload as
  // bytes only for v2, whose schema version makes that representation explicit.
  return digestStructuredValue(domain, schemaVersion, schemaVersion === 1 ? payload : encodeCanonicalCbor(payload, { maxDepth: 140, maxItems: 100_000 }));
}
