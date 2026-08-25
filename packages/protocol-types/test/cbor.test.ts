import { describe, expect, it } from "vitest";

import golden from "../fixtures/v1alpha-golden.json";
import {
  ProtocolValidationError,
  decodeHex,
  digestStructuredValue,
  encodeCanonicalCbor,
  encodeHex,
  normalizeProtocolValue,
  normalizeStringSet,
} from "../src/index.ts";

describe("RFC 8949 deterministic CBOR", () => {
  it("matches cross-language golden encodings and versioned digests", async () => {
    for (const vector of golden.vectors) {
      let payload: unknown;
      if (vector.payload.kind === "bytes" && vector.payload.hex !== undefined) {
        payload = decodeHex(vector.payload.hex);
      } else if (vector.payload.kind === "json") {
        payload = vector.payload.value;
      } else {
        throw new Error(`unknown fixture payload kind ${vector.payload.kind}`);
      }
      expect(encodeHex(encodeCanonicalCbor(payload))).toBe(vector.payloadCborHex);
      expect(
        encodeHex(
          encodeCanonicalCbor([
            "circulusd.hash",
            1,
            vector.domain,
            vector.schemaVersion,
            payload,
          ]),
        ),
      ).toBe(vector.digestInputCborHex);
      await expect(
        digestStructuredValue(vector.domain, vector.schemaVersion, payload),
      ).resolves.toBe(vector.digest);
    }
  });

  it("uses length-first then bytewise map-key ordering", () => {
    expect(encodeHex(encodeCanonicalCbor({ z: 0, aa: 1, b: 2 }))).toBe(
      "a3616202617a0062616101",
    );
  });

  it("normalizes external text to NFC", () => {
    expect(encodeHex(encodeCanonicalCbor("e\u0301"))).toBe("62c3a9");
    expect(normalizeProtocolValue({ "e\u0301": "A\u030A" })).toEqual({ é: "Å" });
  });

  it("rejects ambiguous or non-protocol values", () => {
    expect(() => encodeCanonicalCbor(1.5)).toThrow(/safe integer/);
    expect(() => encodeCanonicalCbor(-0)).toThrow(/negative zero/);
    expect(() => encodeCanonicalCbor(undefined)).toThrow(/unsupported/);
    expect(() => encodeCanonicalCbor({ value: undefined })).toThrow(/unsupported/);
    expect(() => encodeCanonicalCbor(new Date(0))).toThrow(/plain object/);
    expect(() => encodeCanonicalCbor(9_007_199_254_740_992)).toThrow(/safe integer/);

    const cyclic: unknown[] = [];
    cyclic.push(cyclic);
    expect(() => encodeCanonicalCbor(cyclic)).toThrow(/cyclic/);

    const accessorArray = [0];
    Object.defineProperty(accessorArray, "0", {
      enumerable: true,
      get: () => 0,
    });
    expect(() => encodeCanonicalCbor(accessorArray)).toThrow(/data property/);
    expect(() => encodeCanonicalCbor("\ud800")).toThrow(/Unicode scalar/);
  });

  it("rejects duplicate keys after NFC normalization", () => {
    expect(() => encodeCanonicalCbor({ é: 1, "e\u0301": 2 })).toThrow(
      /duplicate normalized key/,
    );
  });

  it("sorts schema-defined string sets by normalized UTF-8 bytes", () => {
    expect(normalizeStringSet(["z", "é", "a", "e\u0301x"])).toEqual([
      "a",
      "z",
      "é",
      "éx",
    ]);
    expect(() => normalizeStringSet(["é", "e\u0301"])).toThrow(
      ProtocolValidationError,
    );
  });

  it("enforces explicit depth and encoded-size limits", () => {
    expect(() => encodeCanonicalCbor([[0]], { maxDepth: 1 })).toThrow(/depth/);
    expect(() => encodeCanonicalCbor("abcd", { maxBytes: 4 })).toThrow(/size/);
  });
});
