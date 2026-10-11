import { readFileSync } from "node:fs";

import { encodeCanonicalCbor, normalizeProtocolValue, type NormalizedValue } from "@circulusd/protocol-types";
import { describe, expect, it } from "vitest";

import {
  PI_NUMBER_WRAPPER_KEY,
  decodePiJson,
  encodePiJson,
  validatePiJson,
} from "../src/pi-json-codec.ts";

const vectors = JSON.parse(readFileSync(new URL(
  "../../../packages/protocol-types/fixtures/pi-json-numbers-v1.json", import.meta.url,
), "utf8")) as {
  version: number;
  wrapperKey: string;
  numbers: { name: string; bitsHex: string; decimal: string; encoded: NormalizedValue; cborHex: string }[];
  invalidWrappers: { name: string; value: NormalizedValue }[];
  invalidRaw: { name: string; value: unknown }[];
  invalidNumbers: { name: string; bitsHex: string }[];
};

function fromBits(bits: string): number {
  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);
  view.setBigUint64(0, BigInt(`0x${bits}`));
  return view.getFloat64(0);
}

describe("pi JSON fractional-number codec (R3)", () => {
  it.each(vectors.numbers)("matches the Go/TS golden for $name", (vector) => {
    expect(vectors.version).toBe(1);
    expect(vectors.wrapperKey).toBe(PI_NUMBER_WRAPPER_KEY);
    const number = fromBits(vector.bitsHex);
    expect(number.toString()).toBe(vector.decimal);
    expect(encodePiJson(number)).toEqual(vector.encoded);
    expect(Buffer.from(encodeCanonicalCbor(encodePiJson(number))).toString("hex")).toBe(vector.cborHex);
    expect(Object.is(decodePiJson(vector.encoded), number)).toBe(true);
  });

  it.each(vectors.invalidWrappers)("rejects shared invalid wrapper $name", ({ value }) => {
    expect(() => decodePiJson(value)).toThrow();
  });

  it.each(vectors.invalidRaw)("rejects shared invalid raw input $name", ({ value }) => {
    expect(() => encodePiJson(value)).toThrow();
    expect(() => validatePiJson(value)).toThrow();
  });

  it.each(vectors.invalidNumbers)("rejects shared invalid number $name", ({ bitsHex }) => {
    expect(() => encodePiJson(fromBits(bitsHex))).toThrow();
  });

  it("round-trips fractional tool-call arguments through the integer-only boundary", () => {
    const args = { temperature: 1.25, topP: 0.9, maxTokens: 2048, nested: { scale: -0.5 } };
    const encoded = encodePiJson(args);
    // The durable form is canonical, integer-only CBOR (no floats).
    expect(() => encodeCanonicalCbor(encoded)).not.toThrow();
    expect(decodePiJson(encoded)).toEqual(args);
  });

  it("round-trips fractional JSON Schema constraints", () => {
    const schema = {
      type: "object",
      properties: {
        temperature: { type: "number", minimum: 0.1, maximum: 1.5, multipleOf: 0.25, default: 0.7 },
        mode: { enum: ["a", 0.5, 2] },
      },
    };
    expect(decodePiJson(encodePiJson(schema))).toEqual(schema);
  });

  it("is byte-identical to normalizeProtocolValue for integer-only values", () => {
    for (const value of [
      { a: 5, b: [1, 2, 3], c: { d: -7 } },
      { type: "integer", minimum: 0, maximum: 100 },
      [0, 1, 2, { k: "v" }],
    ]) {
      expect(encodeCanonicalCbor(encodePiJson(value))).toEqual(
        encodeCanonicalCbor(normalizeProtocolValue(value)),
      );
    }
  });

  it("encodes fractions as canonical decimal strings and only wraps fractions", () => {
    const encoded = encodePiJson({ frac: 1.25, whole: 4 }) as Record<string, unknown>;
    expect(encoded.frac).toEqual({ [PI_NUMBER_WRAPPER_KEY]: "1.25" });
    expect(encoded.whole).toBe(4);
  });

  it("validatePiJson keeps numbers real for in-process schema validation", () => {
    expect(validatePiJson({ minimum: 0.1, count: 3 })).toEqual({ minimum: 0.1, count: 3 });
  });

  it("rejects non-finite numbers", () => {
    expect(() => encodePiJson({ x: Number.POSITIVE_INFINITY })).toThrow();
    expect(() => encodePiJson({ x: Number.NaN })).toThrow();
    expect(() => encodePiJson({ x: -0 })).toThrow();
  });

  it("fails closed on input that already uses the reserved wrapper key", () => {
    expect(() => encodePiJson({ [PI_NUMBER_WRAPPER_KEY]: "1.25" })).toThrow();
    expect(() => validatePiJson({ nested: { [PI_NUMBER_WRAPPER_KEY]: "x" } })).toThrow();
  });

  it("rejects a malformed number wrapper on decode", () => {
    expect(() => decodePiJson({ [PI_NUMBER_WRAPPER_KEY]: "1.10" })).toThrow(); // non-canonical decimal
    expect(() => decodePiJson({ [PI_NUMBER_WRAPPER_KEY]: "not-a-number" })).toThrow();
    expect(() => decodePiJson({ [PI_NUMBER_WRAPPER_KEY]: "1" })).toThrow();
    expect(() => decodePiJson({ [PI_NUMBER_WRAPPER_KEY]: "0" })).toThrow();
    expect(() => decodePiJson({ [PI_NUMBER_WRAPPER_KEY]: "1.25", extra: true })).toThrow();
  });

  it.each([encodePiJson, validatePiJson, decodePiJson])(
    "rejects ambiguous or non-JSON structure without invoking custom code", (convert) => {
      let calls = 0;
      const getter = Object.defineProperty({}, "value", {
        enumerable: true, get() { calls += 1; return 1.25; },
      });
      const customArray = Object.assign([1.25], { map() { calls += 1; return []; } });
      const child = { value: 1 };
      const sparse: unknown[] = [];
      sparse.length = 2;
      for (const invalid of [
        getter, customArray, sparse, new Uint8Array([1]), new Date(),
        { "e\u0301": 1, "é": 2 }, { lone: "\ud800" },
        { left: child, right: child }, Object.assign({}, { [Symbol("x")]: 1 }),
      ]) {
        expect(() => convert(invalid as never)).toThrow();
      }
      expect(calls).toBe(0);
    },
  );

  it("preserves an own __proto__ key and bounds depth before recursive traversal", () => {
    const value = JSON.parse('{"__proto__":{"fraction":1.25}}');
    const decoded = decodePiJson(encodePiJson(value)) as Record<string, unknown>;
    expect(Object.getPrototypeOf(decoded)).toBe(Object.prototype);
    expect(Object.hasOwn(decoded, "__proto__")).toBe(true);
    expect(decoded.__proto__).toEqual({ fraction: 1.25 });
    let deep: unknown = 1.25;
    for (let index = 0; index < 100; index += 1) deep = [deep];
    expect(() => encodePiJson(deep)).toThrow(/depth/);
    expect(() => validatePiJson(deep)).toThrow(/depth/);
  });
});
