import { validationError } from "./errors.ts";
import { assertUnicodeScalarString } from "./text.ts";
import type { CanonicalCborOptions, NormalizedValue } from "./types.ts";

const DEFAULT_MAX_DEPTH = 64;
const textEncoder = new TextEncoder();

function checkedLimit(
  value: number | undefined,
  fallback: number,
  name: string,
): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < 0) {
    validationError(`options.${name}`, "must be a non-negative safe integer");
  }
  return resolved;
}

function normalize(
  value: unknown,
  path: string,
  depth: number,
  maxDepth: number,
  seen: WeakSet<object>,
): NormalizedValue {
  if (depth > maxDepth) {
    validationError(path, `maximum depth ${maxDepth} exceeded`);
  }
  if (value === null || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "string") {
    assertUnicodeScalarString(value, path);
    return value.normalize("NFC");
  }
  if (typeof value === "number") {
    if (Object.is(value, -0)) {
      validationError(path, "negative zero is unsupported");
    }
    if (!Number.isSafeInteger(value)) {
      validationError(path, "numbers must be safe integers; floating-point values are unsupported");
    }
    return value;
  }
  if (value instanceof Uint8Array) {
    if (Object.getPrototypeOf(value) !== Uint8Array.prototype) {
      validationError(path, "bytes must be an exact Uint8Array");
    }
    const backing = value.buffer;
    if (
      !(backing instanceof ArrayBuffer) ||
      Object.getPrototypeOf(backing) !== ArrayBuffer.prototype
    ) {
      validationError(path, "bytes must use an ordinary ArrayBuffer");
    }
    if (value.byteOffset !== 0 || value.byteLength !== backing.byteLength) {
      validationError(path, "bytes must cover their full backing buffer");
    }
    if (seen.has(value)) {
      validationError(path, "cyclic or repeated object references are unsupported");
    }
    if (seen.has(backing)) {
      validationError(path, "repeated byte storage is unsupported");
    }
    seen.add(value);
    seen.add(backing);
    return new Uint8Array(value);
  }
  if (typeof value !== "object") {
    validationError(path, `unsupported value type ${typeof value}`);
  }

  if (seen.has(value)) {
    validationError(path, "cyclic or repeated object references are unsupported");
  }
  seen.add(value);
  if (Array.isArray(value)) {
    const ownKeys = Reflect.ownKeys(value);
    for (const key of ownKeys) {
      if (key === "length") {
        continue;
      }
      if (typeof key !== "string" || !/^(0|[1-9][0-9]*)$/.test(key)) {
        validationError(path, "arrays cannot have custom properties");
      }
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (
        descriptor === undefined ||
        !descriptor.enumerable ||
        !("value" in descriptor)
      ) {
        validationError(`${path}[${key}]`, "must be an enumerable data property");
      }
    }
    if (Object.keys(value).length !== value.length) {
      validationError(path, "sparse arrays are unsupported");
    }
    return value.map((entry, index) =>
      normalize(entry, `${path}[${index}]`, depth + 1, maxDepth, seen),
    );
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
    if (
      descriptor === undefined ||
      !descriptor.enumerable ||
      !("value" in descriptor)
    ) {
      validationError(`${path}.${key}`, "must be an enumerable data property");
    }
  }

  const record = value as Record<string, unknown>;
  const result: Record<string, NormalizedValue> = {};
  const normalizedKeys = new Set<string>();
  for (const key of Object.keys(record)) {
    assertUnicodeScalarString(key, `${path}.${key}`);
    const normalizedKey = key.normalize("NFC");
    if (normalizedKeys.has(normalizedKey)) {
      validationError(path, `duplicate normalized key ${JSON.stringify(normalizedKey)}`);
    }
    normalizedKeys.add(normalizedKey);
    Object.defineProperty(result, normalizedKey, {
      configurable: true,
      enumerable: true,
      value: normalize(record[key], `${path}.${key}`, depth + 1, maxDepth, seen),
      writable: true,
    });
  }
  return result;
}

export function normalizeProtocolValue(
  value: unknown,
  options: Pick<CanonicalCborOptions, "maxDepth"> = {},
): NormalizedValue {
  const maxDepth = checkedLimit(options.maxDepth, DEFAULT_MAX_DEPTH, "maxDepth");
  return normalize(value, "$", 0, maxDepth, new WeakSet<object>());
}

export const parseNormalizedValue = normalizeProtocolValue;

class ByteWriter {
  readonly #bytes: number[] = [];
  readonly #maxBytes: number;

  constructor(maxBytes: number) {
    this.#maxBytes = maxBytes;
  }

  push(byte: number): void {
    if (this.#bytes.length >= this.#maxBytes) {
      validationError("$", `encoded size exceeds ${this.#maxBytes} bytes`);
    }
    this.#bytes.push(byte);
  }

  pushBytes(bytes: Uint8Array): void {
    if (this.#bytes.length + bytes.byteLength > this.#maxBytes) {
      validationError("$", `encoded size exceeds ${this.#maxBytes} bytes`);
    }
    for (const byte of bytes) {
      this.#bytes.push(byte);
    }
  }

  finish(): Uint8Array {
    return Uint8Array.from(this.#bytes);
  }
}

function writeArgument(writer: ByteWriter, major: number, argument: bigint): void {
  const prefix = major << 5;
  if (argument < 24n) {
    writer.push(prefix | Number(argument));
    return;
  }
  if (argument <= 0xffn) {
    writer.push(prefix | 24);
    writer.push(Number(argument));
    return;
  }
  if (argument <= 0xffffn) {
    writer.push(prefix | 25);
    writer.push(Number(argument >> 8n));
    writer.push(Number(argument & 0xffn));
    return;
  }
  if (argument <= 0xffff_ffffn) {
    writer.push(prefix | 26);
    for (let shift = 24n; shift >= 0n; shift -= 8n) {
      writer.push(Number((argument >> shift) & 0xffn));
    }
    return;
  }

  writer.push(prefix | 27);
  for (let shift = 56n; shift >= 0n; shift -= 8n) {
    writer.push(Number((argument >> shift) & 0xffn));
  }
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  const length = Math.min(left.byteLength, right.byteLength);
  for (let index = 0; index < length; index += 1) {
    const leftByte = left[index];
    const rightByte = right[index];
    if (leftByte === undefined || rightByte === undefined) {
      validationError("$", "internal byte comparison exceeded its input");
    }
    const difference = leftByte - rightByte;
    if (difference !== 0) {
      return difference;
    }
  }
  return left.byteLength - right.byteLength;
}

function writeValue(writer: ByteWriter, value: NormalizedValue): void {
  if (value === null) {
    writer.push(0xf6);
    return;
  }
  if (typeof value === "boolean") {
    writer.push(value ? 0xf5 : 0xf4);
    return;
  }
  if (typeof value === "number") {
    if (value >= 0) {
      writeArgument(writer, 0, BigInt(value));
    } else {
      writeArgument(writer, 1, BigInt(-1 - value));
    }
    return;
  }
  if (typeof value === "string") {
    const bytes = textEncoder.encode(value);
    writeArgument(writer, 3, BigInt(bytes.byteLength));
    writer.pushBytes(bytes);
    return;
  }
  if (value instanceof Uint8Array) {
    writeArgument(writer, 2, BigInt(value.byteLength));
    writer.pushBytes(value);
    return;
  }
  if (Array.isArray(value)) {
    writeArgument(writer, 4, BigInt(value.length));
    for (const entry of value) {
      writeValue(writer, entry);
    }
    return;
  }

  const entries = Object.keys(value).map((key) => {
    const keyBytes = textEncoder.encode(key);
    const keyWriter = new ByteWriter(Number.MAX_SAFE_INTEGER);
    writeArgument(keyWriter, 3, BigInt(keyBytes.byteLength));
    keyWriter.pushBytes(keyBytes);
    return { encodedKey: keyWriter.finish(), key };
  });
  entries.sort((left, right) => {
    const lengthDifference = left.encodedKey.byteLength - right.encodedKey.byteLength;
    return lengthDifference === 0
      ? compareBytes(left.encodedKey, right.encodedKey)
      : lengthDifference;
  });
  writeArgument(writer, 5, BigInt(entries.length));
  for (const entry of entries) {
    writer.pushBytes(entry.encodedKey);
    const item = value[entry.key];
    if (item === undefined) {
      validationError(`$.${entry.key}`, "unsupported undefined value");
    }
    writeValue(writer, item);
  }
}

export function encodeCanonicalCbor(
  value: unknown,
  options: CanonicalCborOptions = {},
): Uint8Array {
  const maxDepth = checkedLimit(options.maxDepth, DEFAULT_MAX_DEPTH, "maxDepth");
  const maxBytes = checkedLimit(options.maxBytes, Number.MAX_SAFE_INTEGER, "maxBytes");
  const normalized = normalizeProtocolValue(value, { maxDepth });
  const writer = new ByteWriter(maxBytes);
  writeValue(writer, normalized);
  return writer.finish();
}

export function encodeHex(bytes: Uint8Array): string {
  let result = "";
  for (const byte of bytes) {
    result += byte.toString(16).padStart(2, "0");
  }
  return result;
}

export function decodeHex(value: string): Uint8Array {
  if (value.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(value)) {
    validationError("$", "hex must contain an even number of hexadecimal characters");
  }
  const result = new Uint8Array(value.length / 2);
  for (let index = 0; index < value.length; index += 2) {
    result[index / 2] = Number.parseInt(value.slice(index, index + 2), 16);
  }
  return result;
}

export function normalizeStringSet(values: readonly string[]): readonly string[] {
  const normalized = values.map((value, index) => {
    if (typeof value !== "string") {
      validationError(`$[${index}]`, "must be a string");
    }
    return assertUnicodeScalarString(value, `$[${index}]`).normalize("NFC");
  });
  const unique = new Set(normalized);
  if (unique.size !== normalized.length) {
    validationError("$", "duplicate normalized string in set");
  }
  return normalized.sort((left, right) =>
    compareBytes(textEncoder.encode(left), textEncoder.encode(right)),
  );
}
