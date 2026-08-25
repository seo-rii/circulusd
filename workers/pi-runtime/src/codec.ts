import {
  ProtocolValidationError,
  encodeCanonicalCbor,
  normalizeProtocolValue,
  type NormalizedValue,
} from "@circulusd/protocol-types";

import { PiRuntimeError } from "./errors.ts";

const textDecoder = new TextDecoder("utf-8", { fatal: true });

class CanonicalCborReader {
  readonly #bytes: Uint8Array;
  readonly #maxDepth: number;
  #offset = 0;

  constructor(bytes: Uint8Array, maxDepth: number) {
    this.#bytes = bytes;
    this.#maxDepth = maxDepth;
  }

  read(depth = 0): NormalizedValue {
    if (depth > this.#maxDepth || this.#offset >= this.#bytes.byteLength) {
      throw new PiRuntimeError("INVALID_CHECKPOINT", "checkpoint CBOR is truncated or too deep");
    }
    const initial = this.#bytes[this.#offset];
    if (initial === undefined) {
      throw new PiRuntimeError("INVALID_CHECKPOINT", "checkpoint CBOR is truncated");
    }
    this.#offset += 1;
    const major = initial >> 5;
    const additional = initial & 0x1f;
    let argument: bigint;
    if (additional < 24) {
      argument = BigInt(additional);
    } else {
      const byteCount = additional === 24 ? 1 : additional === 25 ? 2 : additional === 26 ? 4 : additional === 27 ? 8 : 0;
      if (byteCount === 0 || this.#offset + byteCount > this.#bytes.byteLength) {
        throw new PiRuntimeError("INVALID_CHECKPOINT", "checkpoint CBOR has an invalid argument");
      }
      argument = 0n;
      for (let index = 0; index < byteCount; index += 1) {
        const byte = this.#bytes[this.#offset];
        if (byte === undefined) {
          throw new PiRuntimeError("INVALID_CHECKPOINT", "checkpoint CBOR is truncated");
        }
        this.#offset += 1;
        argument = (argument << 8n) | BigInt(byte);
      }
      const minimum = byteCount === 1 ? 24n : byteCount === 2 ? 256n : byteCount === 4 ? 65_536n : 4_294_967_296n;
      if (argument < minimum) {
        throw new PiRuntimeError("INVALID_CHECKPOINT", "checkpoint CBOR is not minimally encoded");
      }
    }
    if (argument > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new PiRuntimeError("INVALID_CHECKPOINT", "checkpoint CBOR integer exceeds safe range");
    }
    const length = Number(argument);

    if (major === 0) return length;
    if (major === 1) return -1 - length;
    if (major === 2 || major === 3) {
      if (this.#offset + length > this.#bytes.byteLength) {
        throw new PiRuntimeError("INVALID_CHECKPOINT", "checkpoint CBOR byte string is truncated");
      }
      const value = this.#bytes.slice(this.#offset, this.#offset + length);
      this.#offset += length;
      if (major === 2) return value;
      try {
        const text = textDecoder.decode(value);
        if (text !== text.normalize("NFC")) {
          throw new PiRuntimeError("INVALID_CHECKPOINT", "checkpoint CBOR text is not NFC");
        }
        return text;
      } catch (error) {
        if (error instanceof PiRuntimeError) throw error;
        throw new PiRuntimeError("INVALID_CHECKPOINT", "checkpoint CBOR text is invalid UTF-8", {
          cause: error,
        });
      }
    }
    if (major === 4) {
      const values: NormalizedValue[] = [];
      for (let index = 0; index < length; index += 1) values.push(this.read(depth + 1));
      return values;
    }
    if (major === 5) {
      const result: Record<string, NormalizedValue> = {};
      for (let index = 0; index < length; index += 1) {
        const key = this.read(depth + 1);
        if (typeof key !== "string" || Object.prototype.hasOwnProperty.call(result, key)) {
          throw new PiRuntimeError("INVALID_CHECKPOINT", "checkpoint CBOR map key is invalid");
        }
        Object.defineProperty(result, key, {
          configurable: true,
          enumerable: true,
          value: this.read(depth + 1),
          writable: true,
        });
      }
      return result;
    }
    if (major === 7 && additional === 20) return false;
    if (major === 7 && additional === 21) return true;
    if (major === 7 && additional === 22) return null;
    throw new PiRuntimeError("INVALID_CHECKPOINT", "checkpoint CBOR contains an unsupported type");
  }

  atEnd(): boolean {
    return this.#offset === this.#bytes.byteLength;
  }
}

export function decodeCanonicalCheckpointPayload(
  bytes: Uint8Array,
  maxBytes: number,
): NormalizedValue {
  if (
    !(bytes instanceof Uint8Array) ||
    Object.getPrototypeOf(bytes) !== Uint8Array.prototype ||
    bytes.byteLength > maxBytes
  ) {
    throw new PiRuntimeError("INVALID_CHECKPOINT", "checkpoint payload exceeds its byte budget");
  }
  const copy = new Uint8Array(bytes);
  const reader = new CanonicalCborReader(copy, 64);
  const decoded = reader.read();
  if (!reader.atEnd()) {
    throw new PiRuntimeError("INVALID_CHECKPOINT", "checkpoint payload has trailing CBOR bytes");
  }
  let canonical: Uint8Array;
  try {
    canonical = encodeCanonicalCbor(normalizeProtocolValue(decoded), { maxBytes });
  } catch (error) {
    if (error instanceof ProtocolValidationError) {
      throw new PiRuntimeError("INVALID_CHECKPOINT", "checkpoint payload is invalid", {
        cause: error,
      });
    }
    throw error;
  }
  if (
    canonical.byteLength !== copy.byteLength ||
    canonical.some((byte, index) => byte !== copy[index])
  ) {
    throw new PiRuntimeError("INVALID_CHECKPOINT", "checkpoint payload CBOR is not canonical");
  }
  return decoded;
}
