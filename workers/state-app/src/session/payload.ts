import {
  decodeCanonicalCbor,
  digestBytes,
  encodeCanonicalCbor,
  normalizeProtocolValue,
  parseDigest,
  type Digest,
  type NormalizedValue,
} from "@circulusd/protocol-types";

import { sessionError } from "./errors.ts";
import { SESSION_VALUE_MAX_ENCODED_BYTES, type SessionPayloadRef } from "./types.ts";

/** Canonical item count includes map keys, array entries and their containers. */
export function sessionPayloadItems(value: NormalizedValue): number {
  let count = 0;
  const pending = [value];
  while (pending.length > 0) {
    const current = pending.pop()!;
    count += 1;
    if (Array.isArray(current)) {
      for (const entry of current) pending.push(entry);
    } else if (current !== null && typeof current === "object" && !(current instanceof Uint8Array)) {
      for (const entry of Object.values(current)) {
        count += 1;
        pending.push(entry);
      }
    }
  }
  return count;
}

export function validateSessionPayloadRef(value: unknown, field: string): SessionPayloadRef {
  const normalized = normalizeProtocolValue(value);
  if (
    normalized === null || typeof normalized !== "object" ||
    Array.isArray(normalized) || normalized instanceof Uint8Array ||
    Object.keys(normalized).length !== 4 ||
    normalized.encoding !== "canonical-cbor-v1" ||
    typeof normalized.encodedBytes !== "number" ||
    normalized.encodedBytes < 1 || normalized.encodedBytes > SESSION_VALUE_MAX_ENCODED_BYTES ||
    typeof normalized.encodedItems !== "number" ||
    normalized.encodedItems < 1 || normalized.encodedItems > normalized.encodedBytes
  ) {
    sessionError("FAILED_PRECONDITION", `${field} is not a bounded canonical payload reference`);
  }
  return {
    encoding: "canonical-cbor-v1",
    digest: parseDigest(normalized.digest, `${field}.digest`),
    encodedBytes: normalized.encodedBytes,
    encodedItems: normalized.encodedItems,
  };
}

export async function storeSessionPayload(
  value: NormalizedValue,
  blobs: Map<Digest, Uint8Array>,
): Promise<SessionPayloadRef> {
  const bytes = encodeCanonicalCbor(value, { maxBytes: SESSION_VALUE_MAX_ENCODED_BYTES });
  const digest = await digestBytes(bytes);
  blobs.set(digest, bytes);
  return {
    encoding: "canonical-cbor-v1", digest, encodedBytes: bytes.byteLength,
    encodedItems: sessionPayloadItems(value),
  };
}

/** Read only the requested value; never hydrate the whole session history. */
export async function readSessionPayload(
  reference: SessionPayloadRef,
  readBlob: (digest: Digest) => Promise<Uint8Array | undefined>,
): Promise<NormalizedValue> {
  const ref = validateSessionPayloadRef(reference, "payload reference");
  const bytes = await readBlob(ref.digest);
  if (bytes === undefined) sessionError("FAILED_PRECONDITION", "referenced session payload is missing");
  if (bytes.byteLength !== ref.encodedBytes || await digestBytes(bytes) !== ref.digest) {
    sessionError("DIGEST_MISMATCH", "session payload bytes do not match their reference");
  }
  const value = decodeCanonicalCbor(bytes, {
    maxBytes: ref.encodedBytes, maxDepth: 64, maxItems: ref.encodedItems,
  });
  if (sessionPayloadItems(value) !== ref.encodedItems) {
    sessionError("DIGEST_MISMATCH", "session payload item count does not match its reference");
  }
  return value;
}
