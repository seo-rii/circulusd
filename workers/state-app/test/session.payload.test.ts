import { digestBytes, encodeCanonicalCbor, type Digest } from "@circulusd/protocol-types";
import { describe, expect, it } from "vitest";

import {
  readSessionPayload, sessionPayloadItems, storeSessionPayload, validateSessionPayloadRef,
} from "../src/session/payload.ts";

describe("Session canonical payload references", () => {
  it("round trips nested values and binds raw CBOR bytes plus exact item count", async () => {
    const value = { nested: [null, true, { bytes: new Uint8Array([1, 2]), text: "é" }] };
    const blobs = new Map<Digest, Uint8Array>();
    const reference = await storeSessionPayload(value, blobs);
    const bytes = encodeCanonicalCbor(value);
    expect(reference).toEqual({
      encoding: "canonical-cbor-v1", digest: await digestBytes(bytes),
      encodedBytes: bytes.byteLength, encodedItems: 10,
    });
    expect(sessionPayloadItems(value)).toBe(10);
    await expect(readSessionPayload(reference, async (digest) => blobs.get(digest)))
      .resolves.toEqual(value);
  });

  it("rejects missing or tampered blobs and inconsistent encoded metadata", async () => {
    const blobs = new Map<Digest, Uint8Array>();
    const reference = await storeSessionPayload({ message: "preserved" }, blobs);
    const read = async (digest: Digest) => blobs.get(digest);
    await expect(readSessionPayload(reference, async () => undefined))
      .rejects.toMatchObject({ code: "FAILED_PRECONDITION" });
    await expect(readSessionPayload(reference, async () => encodeCanonicalCbor({ message: "corrupted" })))
      .rejects.toMatchObject({ code: "DIGEST_MISMATCH" });
    await expect(readSessionPayload({ ...reference, encodedBytes: reference.encodedBytes + 1 }, read))
      .rejects.toMatchObject({ code: "DIGEST_MISMATCH" });
    await expect(readSessionPayload({ ...reference, encodedItems: reference.encodedItems + 1 }, read))
      .rejects.toMatchObject({ code: "DIGEST_MISMATCH" });
    await expect(readSessionPayload({ ...reference, encodedItems: reference.encodedItems - 1 }, read))
      .rejects.toThrow(/item/);
  });

  it("requires the exact bounded reference schema", async () => {
    const reference = await storeSessionPayload(null, new Map());
    const invalid = [
      { ...reference, encoding: "json" }, { ...reference, digest: "sha256:bad" },
      { ...reference, encodedBytes: 0 }, { ...reference, encodedBytes: 1_048_577 },
      { ...reference, encodedItems: 0 }, { ...reference, encodedItems: 2 },
      { ...reference, encodedItems: 1.5 }, { ...reference, extra: true },
      { encoding: "canonical-cbor-v1", digest: reference.digest, encodedBytes: 1 },
    ];
    for (const candidate of invalid) {
      expect(() => validateSessionPayloadRef(candidate, "test")).toThrow();
    }
  });
});
