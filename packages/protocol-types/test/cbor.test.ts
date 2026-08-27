import { describe, expect, it } from "vitest";

import golden from "../fixtures/v1alpha-golden.json";
import {
  ProtocolValidationError,
  decodeCanonicalCbor,
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

  it("reserves framing depth when hashing a depth-64 protocol value", async () => {
    const payload: Record<string, unknown> = {};
    let cursor = payload;
    for (let depth = 0; depth < 64; depth += 1) {
      const next: Record<string, unknown> = {};
      cursor.next = next;
      cursor = next;
    }

    expect(() => encodeCanonicalCbor(payload, { maxDepth: 64 })).not.toThrow();
    await expect(
      digestStructuredValue("circulusd.depth-budget", 1, payload),
    ).resolves.toMatch(/^sha256:[0-9a-f]{64}$/);
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

  it("rejects repeated object references before a DAG can expand", () => {
    let dag: unknown = { leaf: "bounded" };
    for (let depth = 0; depth < 18; depth += 1) {
      dag = { left: dag, right: dag };
    }

    expect(() => normalizeProtocolValue(dag)).toThrow(/repeated object reference/);

    const repeatedBytes = new Uint8Array(1_024);
    expect(() =>
      normalizeProtocolValue({ first: repeatedBytes, second: repeatedBytes }),
    ).toThrow(/repeated object reference/);

    const backing = new ArrayBuffer(1_024);
    expect(() =>
      normalizeProtocolValue({ first: new Uint8Array(backing), second: new Uint8Array(backing) }),
    ).toThrow(/repeated byte storage/);
    expect(() => normalizeProtocolValue(new Uint8Array(new SharedArrayBuffer(8)))).toThrow(
      /ordinary ArrayBuffer/,
    );
    expect(() => normalizeProtocolValue(new Uint8Array(new ArrayBuffer(8), 2, 2))).toThrow(
      /full backing buffer/,
    );
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

  it("enforces the same aggregate item budget while encoding as decoding", () => {
    const value = [null, null];

    expect(() => encodeCanonicalCbor(value, { maxItems: 2 })).toThrow(/item limit/);
    expect(encodeCanonicalCbor(value, { maxItems: 3 })).toEqual(
      encodeCanonicalCbor(value),
    );
  });
});

describe("canonical CBOR decoding", () => {
  it("round-trips the supported protocol value subset without byte aliases", () => {
    const encoded = encodeCanonicalCbor({
      array: [null, false, true, 0, 23, 24, -1, -24, -25],
      bytes: decodeHex("0001feff"),
      integerBounds: [Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER],
      text: "é\uFEFF",
    });

    const decoded = decodeCanonicalCbor(encoded);
    expect(decoded).toEqual({
      array: [null, false, true, 0, 23, 24, -1, -24, -25],
      bytes: decodeHex("0001feff"),
      integerBounds: [Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER],
      text: "é\uFEFF",
    });
    expect(encodeCanonicalCbor(decoded)).toEqual(encoded);

    const decodedBytes = (decoded as { bytes: Uint8Array }).bytes;
    const byteStringOffset = encoded.indexOf(0x44) + 1;
    encoded[byteStringOffset] = 0xaa;
    expect(decodedBytes).toEqual(decodeHex("0001feff"));
    decodedBytes[0] = 0xbb;
    expect(encoded[byteStringOffset]).toBe(0xaa);
  });

  it("requires an exact Uint8Array covering an ordinary full backing buffer", () => {
    class ByteSubclass extends Uint8Array {}

    expect(() => decodeCanonicalCbor("f6" as unknown as Uint8Array)).toThrow(
      /exact Uint8Array/,
    );
    expect(() => decodeCanonicalCbor(new ByteSubclass([0xf6]))).toThrow(
      /exact Uint8Array/,
    );
    expect(() => decodeCanonicalCbor(new Uint8Array(new SharedArrayBuffer(1)))).toThrow(
      /ordinary ArrayBuffer/,
    );
    expect(() =>
      decodeCanonicalCbor(new Uint8Array(new ArrayBuffer(4), 1, 1)),
    ).toThrow(/full backing buffer/);
  });

  it.each([
    "1817",
    "1900ff",
    "1a0000ffff",
    "1b00000000ffffffff",
    "3817",
    "5800",
    "7800",
    "9800",
    "b800",
  ])("rejects non-minimal argument encoding %s", (hex) => {
    expect(() => decodeCanonicalCbor(decodeHex(hex))).toThrow(/non-minimal/);
  });

  it("rejects integers outside the JavaScript safe-integer domain", () => {
    expect(() => decodeCanonicalCbor(decodeHex("1b0020000000000000"))).toThrow(
      /safe integer/,
    );
    expect(() => decodeCanonicalCbor(decodeHex("3b001fffffffffffff"))).toThrow(
      /safe integer/,
    );
  });

  it.each([
    "f7",
    "f800",
    "f90000",
    "fa00000000",
    "fb0000000000000000",
    "c0f6",
    "9f00ff",
    "5f40ff",
    "1c",
  ])("rejects unsupported CBOR form %s", (hex) => {
    expect(() => decodeCanonicalCbor(decodeHex(hex))).toThrow(/unsupported|reserved/);
  });

  it("rejects invalid UTF-8, non-NFC text, non-string map keys, and duplicate keys", () => {
    expect(() => decodeCanonicalCbor(decodeHex("61ff"))).toThrow(/UTF-8/);
    expect(() => decodeCanonicalCbor(decodeHex("6365cc81"))).toThrow(/NFC/);
    expect(() => decodeCanonicalCbor(decodeHex("a10000"))).toThrow(
      /map keys must be text/,
    );
    expect(() => decodeCanonicalCbor(decodeHex("a2616100616101"))).toThrow(
      /duplicate map key/,
    );
  });

  it("rejects maps whose encoded text keys are not in deterministic order", () => {
    expect(() => decodeCanonicalCbor(decodeHex("a2616200616101"))).toThrow(
      /map key order/,
    );
    expect(() => decodeCanonicalCbor(decodeHex("a262616100616201"))).toThrow(
      /map key order/,
    );
  });

  it("rejects trailing bytes, truncation, and unsafe declared allocation sizes", () => {
    expect(() => decodeCanonicalCbor(decodeHex("00f6"))).toThrow(/trailing/);
    expect(() => decodeCanonicalCbor(decodeHex("1a0000"))).toThrow(/truncated/);
    expect(() => decodeCanonicalCbor(decodeHex("5b0020000000000000"))).toThrow(
      /length|remaining input/,
    );
    expect(() => decodeCanonicalCbor(decodeHex("9b0020000000000000"))).toThrow(
      /length|item limit|remaining input/,
    );
  });

  it("enforces byte, depth, and aggregate item limits before decoding", () => {
    const nested = encodeCanonicalCbor([[[0]]]);
    expect(() => decodeCanonicalCbor(nested, { maxDepth: 1 })).toThrow(/depth/);
    expect(() => decodeCanonicalCbor(nested, { maxBytes: nested.byteLength - 1 })).toThrow(
      /size/,
    );
    expect(() => decodeCanonicalCbor(decodeHex("83010203"), { maxItems: 3 })).toThrow(
      /item limit/,
    );
    expect(() => decodeCanonicalCbor(decodeHex("f6"), { maxItems: 0 })).toThrow(
      /item limit/,
    );
    expect(() => decodeCanonicalCbor(decodeHex("f6"), { maxDepth: -1 })).toThrow(
      /non-negative safe integer/,
    );
    expect(() => decodeCanonicalCbor(decodeHex("f6"), { maxItems: 1.5 })).toThrow(
      /non-negative safe integer/,
    );
  });
});
