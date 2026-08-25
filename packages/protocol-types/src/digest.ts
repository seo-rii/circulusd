import { encodeCanonicalCbor, encodeHex } from "./cbor.ts";
import { validationError } from "./errors.ts";
import { assertUnicodeScalarString } from "./text.ts";
import type { Digest } from "./types.ts";

const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;

export function isDigest(value: unknown): value is Digest {
  return typeof value === "string" && DIGEST_PATTERN.test(value);
}

export function parseDigest(value: unknown, path = "$digest"): Digest {
  if (!isDigest(value)) {
    validationError(path, "must be sha256: followed by 64 lowercase hexadecimal characters");
  }
  return value;
}

export async function digestBytes(bytes: Uint8Array): Promise<Digest> {
  if (!(bytes instanceof Uint8Array)) {
    validationError("$bytes", "must be a Uint8Array");
  }
  const input = Uint8Array.from(bytes);
  const result = await globalThis.crypto.subtle.digest("SHA-256", input);
  return `sha256:${encodeHex(new Uint8Array(result))}`;
}

export async function digestStructuredValue(
  domain: string,
  schemaVersion: number,
  normalizedPayload: unknown,
): Promise<Digest> {
  if (typeof domain !== "string" || domain.length === 0) {
    validationError("$domain", "must be a non-empty string");
  }
  assertUnicodeScalarString(domain, "$domain");
  if (domain !== domain.normalize("NFC")) {
    validationError("$domain", "must be NFC-normalized");
  }
  if (!Number.isSafeInteger(schemaVersion) || schemaVersion < 1) {
    validationError("$schemaVersion", "must be a positive safe integer");
  }
  return digestBytes(
    encodeCanonicalCbor([
      "circulusd.hash",
      1,
      domain,
      schemaVersion,
      normalizedPayload,
    ]),
  );
}

export const digestValue = digestStructuredValue;
