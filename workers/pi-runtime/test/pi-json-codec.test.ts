import { encodeCanonicalCbor, normalizeProtocolValue } from "@circulusd/protocol-types";
import { describe, expect, it } from "vitest";

import {
  PI_NUMBER_WRAPPER_KEY,
  decodePiJson,
  encodePiJson,
  validatePiJson,
} from "../src/pi-json-codec.ts";

describe("pi JSON fractional-number codec (R3)", () => {
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
  });
});
