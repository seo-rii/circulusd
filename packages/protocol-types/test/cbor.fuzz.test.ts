import { env } from "node:process";
import fc from "fast-check";
import { describe, expect, it } from "vitest";

import {
  ProtocolValidationError,
  decodeCanonicalCbor,
  encodeCanonicalCbor,
} from "../src/index.ts";

const parameters = {
  seed: Number(env.CIRCULUSD_FUZZ_SEED ?? 20260905),
  numRuns: Number(env.CIRCULUSD_FUZZ_RUNS ?? 250),
  ...(env.CIRCULUSD_FUZZ_PATH === undefined ? {} : { path: env.CIRCULUSD_FUZZ_PATH }),
};
if (!Number.isSafeInteger(parameters.seed) ||
    !Number.isSafeInteger(parameters.numRuns) || parameters.numRuns < 1) {
  throw new Error("fuzz seed and positive run count must be integers");
}

const values = fc.anything({
  maxDepth: 4,
  maxKeys: 4,
  key: fc.string({ unit: "binary-ascii", maxLength: 8 }),
  values: [
    fc.constant(null),
    fc.boolean(),
    fc.integer({ min: Number.MIN_SAFE_INTEGER, max: Number.MAX_SAFE_INTEGER }),
    fc.string({ unit: "binary", maxLength: 32 }),
    fc.uint8Array({ maxLength: 64 }),
  ],
  withNullPrototype: true,
});

describe("canonical CBOR fuzz properties", () => {
  it("round-trips generated protocol trees without changing canonical bytes", () => {
    fc.assert(fc.property(values, (value) => {
      const encoded = encodeCanonicalCbor(value);
      const decoded = decodeCanonicalCbor(encoded);
      expect(encodeCanonicalCbor(decoded)).toEqual(encoded);
    }), parameters);
  });

  it("accepts arbitrary bytes only when re-encoding preserves every byte", () => {
    fc.assert(fc.property(fc.uint8Array({ maxLength: 512 }), (bytes) => {
      let decoded: unknown;
      try {
        decoded = decodeCanonicalCbor(bytes);
      } catch (error) {
        expect(error).toBeInstanceOf(ProtocolValidationError);
        return;
      }
      expect(encodeCanonicalCbor(decoded)).toEqual(bytes);
    }), parameters);
  });

  it("applies the same depth, item and byte limits in both directions", () => {
    fc.assert(fc.property(
      values,
      fc.record({
        maxDepth: fc.integer({ min: 0, max: 6 }),
        maxItems: fc.integer({ min: 0, max: 128 }),
        maxBytes: fc.integer({ min: 0, max: 512 }),
      }),
      (value, limits) => {
        // First encode without restrictive limits, so neither an invalid
        // generator nor an unconditional rejection can satisfy the property.
        const canonical = encodeCanonicalCbor(value);
        let encoded: Uint8Array | undefined;
        let decoded: unknown;
        let decodedOK = false;
        try {
          encoded = encodeCanonicalCbor(value, limits);
        } catch (error) {
          expect(error).toBeInstanceOf(ProtocolValidationError);
        }
        try {
          decoded = decodeCanonicalCbor(canonical, limits);
          decodedOK = true;
        } catch (error) {
          expect(error).toBeInstanceOf(ProtocolValidationError);
        }
        expect(encoded !== undefined).toBe(decodedOK);
        if (decodedOK) {
          expect(encoded).toEqual(canonical);
          expect(encodeCanonicalCbor(decoded, limits)).toEqual(canonical);
        }
      },
    ), parameters);
  });

  it("never executes methods or getters supplied through an array prototype", () => {
    fc.assert(fc.property(
      fc.array(values, { maxLength: 4 }),
      fc.constantFrom("map", Symbol.iterator),
      fc.boolean(),
      (entries, method, getter) => {
        const array = [...entries];
        const prototype = Object.create(Array.prototype);
        let calls = 0;
        Object.defineProperty(prototype, method, getter ? {
          get: () => { calls += 1; return () => []; },
        } : {
          value: () => { calls += 1; return [Number.MAX_SAFE_INTEGER + 1]; },
        });
        Object.setPrototypeOf(array, prototype);
        expect(() => encodeCanonicalCbor(array)).toThrow(/plain array/);
        expect(calls).toBe(0);
      },
    ), parameters);
  });
});
