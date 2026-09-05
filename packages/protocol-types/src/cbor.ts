import { validationError } from "./errors.ts";
import { assertUnicodeScalarString } from "./text.ts";
import type { CanonicalCborOptions, NormalizedValue } from "./types.ts";

const DEFAULT_MAX_DEPTH = 64;
const DEFAULT_MAX_DECODED_ITEMS = 1_000_000;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

export interface CanonicalCborDecodeOptions {
  readonly maxBytes?: number;
  readonly maxDepth?: number;
  readonly maxItems?: number;
}

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
  itemBudget: { items: number; readonly maxItems: number },
  seen: WeakSet<object>,
): NormalizedValue {
  if (depth > maxDepth) {
    validationError(path, `maximum depth ${maxDepth} exceeded`);
  }
  if (itemBudget.items >= itemBudget.maxItems) {
    validationError(path, `encoded item limit ${itemBudget.maxItems} exceeded`);
  }
  itemBudget.items += 1;
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
    if (Object.getPrototypeOf(value) !== Array.prototype) {
      validationError(path, "must be a plain array");
    }
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
    const result: NormalizedValue[] = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (descriptor === undefined || !("value" in descriptor)) {
        validationError(`${path}[${index}]`, "must be a data property");
      }
      result.push(normalize(
        descriptor.value, `${path}[${index}]`, depth + 1, maxDepth, itemBudget, seen,
      ));
    }
    return result;
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
    if (itemBudget.items >= itemBudget.maxItems) {
      validationError(path, `encoded item limit ${itemBudget.maxItems} exceeded`);
    }
    itemBudget.items += 1;
    assertUnicodeScalarString(key, `${path}.${key}`);
    const normalizedKey = key.normalize("NFC");
    if (normalizedKeys.has(normalizedKey)) {
      validationError(path, `duplicate normalized key ${JSON.stringify(normalizedKey)}`);
    }
    normalizedKeys.add(normalizedKey);
    Object.defineProperty(result, normalizedKey, {
      configurable: true,
      enumerable: true,
      value: normalize(
        record[key],
        `${path}.${key}`,
        depth + 1,
        maxDepth,
        itemBudget,
        seen,
      ),
      writable: true,
    });
  }
  return result;
}

export function normalizeProtocolValue(
  value: unknown,
  options: Pick<CanonicalCborOptions, "maxDepth" | "maxItems"> = {},
): NormalizedValue {
  const maxDepth = checkedLimit(options.maxDepth, DEFAULT_MAX_DEPTH, "maxDepth");
  const maxItems = checkedLimit(
    options.maxItems,
    Number.MAX_SAFE_INTEGER,
    "maxItems",
  );
  return normalize(
    value,
    "$",
    0,
    maxDepth,
    { items: 0, maxItems },
    new WeakSet<object>(),
  );
}

export const parseNormalizedValue = normalizeProtocolValue;

class ByteWriter {
  readonly #chunks: Uint8Array[] = [];
  readonly #maxBytes: number;
  readonly #pendingBytes: number[] = [];
  #length = 0;

  constructor(maxBytes: number) {
    this.#maxBytes = maxBytes;
  }

  push(byte: number): void {
    if (this.#length >= this.#maxBytes) {
      validationError("$", `encoded size exceeds ${this.#maxBytes} bytes`);
    }
    this.#pendingBytes.push(byte);
    this.#length += 1;
  }

  pushBytes(bytes: Uint8Array): void {
    if (this.#length + bytes.byteLength > this.#maxBytes) {
      validationError("$", `encoded size exceeds ${this.#maxBytes} bytes`);
    }
    if (bytes.byteLength === 0) {
      return;
    }
    this.#flushPendingBytes();
    this.#chunks.push(bytes);
    this.#length += bytes.byteLength;
  }

  finish(): Uint8Array {
    this.#flushPendingBytes();
    const result = new Uint8Array(this.#length);
    let offset = 0;
    for (const chunk of this.#chunks) {
      result.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return result;
  }

  #flushPendingBytes(): void {
    if (this.#pendingBytes.length === 0) {
      return;
    }
    this.#chunks.push(Uint8Array.from(this.#pendingBytes));
    this.#pendingBytes.length = 0;
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
  const maxItems = checkedLimit(
    options.maxItems,
    Number.MAX_SAFE_INTEGER,
    "maxItems",
  );
  const normalized = normalizeProtocolValue(value, { maxDepth, maxItems });
  const writer = new ByteWriter(maxBytes);
  writeValue(writer, normalized);
  return writer.finish();
}

class CanonicalCborDecoder {
  readonly #bytes: Uint8Array;
  readonly #maxDepth: number;
  readonly #maxItems: number;
  #items = 0;
  #offset = 0;

  constructor(bytes: Uint8Array, maxDepth: number, maxItems: number) {
    this.#bytes = bytes;
    this.#maxDepth = maxDepth;
    this.#maxItems = maxItems;
  }

  decode(): NormalizedValue {
    const result = this.#readValue("$", 0);
    if (this.#offset !== this.#bytes.byteLength) {
      validationError("$", "trailing bytes after the canonical CBOR value");
    }
    return result;
  }

  #readValue(path: string, depth: number): NormalizedValue {
    if (depth > this.#maxDepth) {
      validationError(path, `maximum depth ${this.#maxDepth} exceeded`);
    }
    if (this.#items >= this.#maxItems) {
      validationError(path, `decoded item limit ${this.#maxItems} exceeded`);
    }
    this.#items += 1;

    const initial = this.#readByte(path);
    const major = initial >> 5;
    const additional = initial & 0x1f;

    if (major === 7) {
      if (initial === 0xf4) {
        return false;
      }
      if (initial === 0xf5) {
        return true;
      }
      if (initial === 0xf6) {
        return null;
      }
      if (additional >= 28 && additional <= 30) {
        validationError(path, "reserved CBOR additional information is unsupported");
      }
      validationError(path, "unsupported CBOR simple, floating-point, or break value");
    }
    if (major === 6) {
      validationError(path, "CBOR tags are unsupported");
    }

    const argument = this.#readArgument(additional, path);
    if (major === 0) {
      if (argument > BigInt(Number.MAX_SAFE_INTEGER)) {
        validationError(path, "integer must be a safe integer");
      }
      return Number(argument);
    }
    if (major === 1) {
      const value = -1n - argument;
      if (value < BigInt(Number.MIN_SAFE_INTEGER)) {
        validationError(path, "integer must be a safe integer");
      }
      return Number(value);
    }
    if (major === 2 || major === 3) {
      const remaining = this.#bytes.byteLength - this.#offset;
      if (argument > BigInt(remaining)) {
        validationError(
          path,
          `declared ${major === 2 ? "byte string" : "text string"} length exceeds remaining input`,
        );
      }
      const length = Number(argument);
      const start = this.#offset;
      this.#offset += length;
      const encoded = this.#bytes.subarray(start, this.#offset);
      if (major === 2) {
        return encoded.slice();
      }

      let value: string;
      try {
        value = textDecoder.decode(encoded);
      } catch {
        validationError(path, "text string must contain valid UTF-8");
      }
      assertUnicodeScalarString(value, path);
      if (value !== value.normalize("NFC")) {
        validationError(path, "text string must already be NFC-normalized");
      }
      return value;
    }
    if (major === 4) {
      const remaining = this.#bytes.byteLength - this.#offset;
      const availableItems = this.#maxItems - this.#items;
      if (argument > BigInt(remaining)) {
        validationError(path, "declared array length exceeds remaining input");
      }
      if (argument > BigInt(availableItems)) {
        validationError(path, `decoded item limit ${this.#maxItems} exceeded`);
      }
      const length = Number(argument);
      const result: NormalizedValue[] = [];
      for (let index = 0; index < length; index += 1) {
        result.push(this.#readValue(`${path}[${index}]`, depth + 1));
      }
      return result;
    }
    if (major === 5) {
      const remaining = this.#bytes.byteLength - this.#offset;
      const availableItems = this.#maxItems - this.#items;
      if (argument * 2n > BigInt(remaining)) {
        validationError(path, "declared map length exceeds remaining input");
      }
      if (argument * 2n > BigInt(availableItems)) {
        validationError(path, `decoded item limit ${this.#maxItems} exceeded`);
      }
      const length = Number(argument);
      const result: Record<string, NormalizedValue> = {};
      const keys = new Set<string>();
      let previousKeyStart = -1;
      let previousKeyEnd = -1;
      for (let index = 0; index < length; index += 1) {
        const keyStart = this.#offset;
        const keyInitial = this.#bytes[this.#offset];
        if (keyInitial === undefined) {
          validationError(`${path}{key:${index}}`, "truncated CBOR input");
        }
        if (keyInitial >> 5 !== 3) {
          validationError(`${path}{key:${index}}`, "map keys must be text strings");
        }
        const key = this.#readValue(`${path}{key:${index}}`, depth + 1);
        if (typeof key !== "string") {
          validationError(`${path}{key:${index}}`, "map keys must be text strings");
        }
        const keyEnd = this.#offset;
        if (keys.has(key)) {
          validationError(path, `duplicate map key ${JSON.stringify(key)}`);
        }
        keys.add(key);

        if (previousKeyStart >= 0) {
          const previousLength = previousKeyEnd - previousKeyStart;
          const currentLength = keyEnd - keyStart;
          let ordering = previousLength - currentLength;
          if (ordering === 0) {
            for (let offset = 0; offset < currentLength; offset += 1) {
              const previousByte = this.#bytes[previousKeyStart + offset];
              const currentByte = this.#bytes[keyStart + offset];
              if (previousByte === undefined || currentByte === undefined) {
                validationError(path, "map key comparison exceeded the input");
              }
              ordering = previousByte - currentByte;
              if (ordering !== 0) {
                break;
              }
            }
          }
          if (ordering >= 0) {
            validationError(path, "map key order is not RFC 8949 deterministic order");
          }
        }
        previousKeyStart = keyStart;
        previousKeyEnd = keyEnd;

        const item = this.#readValue(`${path}.${key}`, depth + 1);
        Object.defineProperty(result, key, {
          configurable: true,
          enumerable: true,
          value: item,
          writable: true,
        });
      }
      return result;
    }

    validationError(path, `unsupported CBOR major type ${major}`);
  }

  #readArgument(additional: number, path: string): bigint {
    if (additional < 24) {
      return BigInt(additional);
    }
    if (additional > 27) {
      if (additional === 31) {
        validationError(path, "indefinite-length CBOR is unsupported");
      }
      validationError(path, "reserved CBOR additional information is unsupported");
    }

    const width = 1 << (additional - 24);
    if (this.#bytes.byteLength - this.#offset < width) {
      validationError(path, "truncated CBOR argument");
    }
    let value = 0n;
    for (let index = 0; index < width; index += 1) {
      value = (value << 8n) | BigInt(this.#readByte(path));
    }
    const minimum =
      width === 1
        ? 24n
        : width === 2
          ? 0x100n
          : width === 4
            ? 0x1_0000n
            : 0x1_0000_0000n;
    if (value < minimum) {
      validationError(path, "non-minimal CBOR argument encoding");
    }
    return value;
  }

  #readByte(path: string): number {
    const value = this.#bytes[this.#offset];
    if (value === undefined) {
      validationError(path, "truncated CBOR input");
    }
    this.#offset += 1;
    return value;
  }
}

export function decodeCanonicalCbor(
  bytes: Uint8Array,
  options: CanonicalCborDecodeOptions = {},
): NormalizedValue {
  if (!(bytes instanceof Uint8Array) || Object.getPrototypeOf(bytes) !== Uint8Array.prototype) {
    validationError("$", "encoded input must be an exact Uint8Array");
  }
  const backing = bytes.buffer;
  if (
    !(backing instanceof ArrayBuffer) ||
    Object.getPrototypeOf(backing) !== ArrayBuffer.prototype
  ) {
    validationError("$", "encoded input must use an ordinary ArrayBuffer");
  }
  if (bytes.byteOffset !== 0 || bytes.byteLength !== backing.byteLength) {
    validationError("$", "encoded input must cover its full backing buffer");
  }

  const maxBytes = checkedLimit(options.maxBytes, Number.MAX_SAFE_INTEGER, "maxBytes");
  const maxDepth = checkedLimit(options.maxDepth, DEFAULT_MAX_DEPTH, "maxDepth");
  const maxItems = checkedLimit(
    options.maxItems,
    DEFAULT_MAX_DECODED_ITEMS,
    "maxItems",
  );
  if (bytes.byteLength > maxBytes) {
    validationError("$", `encoded size exceeds ${maxBytes} bytes`);
  }
  return new CanonicalCborDecoder(bytes, maxDepth, maxItems).decode();
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
