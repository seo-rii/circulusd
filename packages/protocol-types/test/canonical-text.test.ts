import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import fixture from "../fixtures/canonical-text-nfc-v1.json";
import {
  ProtocolValidationError,
  decodeCanonicalCbor,
  decodeHex,
  encodeCanonicalCbor,
  encodeHex,
  isCanonicalText,
  normalizeCanonicalText,
  normalizeProtocolValue,
  normalizeStringSet,
} from "../src/index.ts";
import { UNICODE_15_UNASSIGNED_RANGES } from "../src/unicode15-table.ts";

const textDecoder = new TextDecoder("utf-8", { fatal: true });

function text(hex: string): string {
  return textDecoder.decode(decodeHex(hex));
}

function textHead(length: number): string {
  if (length < 24) {
    return (0x60 | length).toString(16);
  }
  if (length <= 0xff) {
    return `78${length.toString(16).padStart(2, "0")}`;
  }
  throw new Error("fixture text is unexpectedly long");
}

describe("canonical text pinned to Unicode 15.0.0 NFC", () => {
  it("encodes and decodes the cross-language golden vectors", () => {
    for (const vector of fixture.text) {
      const input = text(vector.inputHex);
      const canonical = text(vector.canonicalHex);
      const expected = `${textHead(decodeHex(vector.canonicalHex).byteLength)}${vector.canonicalHex}`;
      expect(encodeHex(encodeCanonicalCbor(input)), vector.name).toBe(expected);
      expect(normalizeProtocolValue([input]), vector.name).toEqual([canonical]);
      const encodedInput = decodeHex(
        `${textHead(decodeHex(vector.inputHex).byteLength)}${vector.inputHex}`,
      );
      if (vector.decode === "accept") {
        expect(decodeCanonicalCbor(encodedInput), vector.name).toBe(input);
      } else {
        expect(() => decodeCanonicalCbor(encodedInput), vector.name).toThrow(
          ProtocolValidationError,
        );
      }
    }
    for (const vector of fixture.maps) {
      const value = Object.fromEntries(
        vector.keysHex.map((keyHex, index) => [text(keyHex), index]),
      );
      if (vector.cborHex === null) {
        expect(() => encodeCanonicalCbor(value), vector.name).toThrow(/duplicate normalized key/);
      } else {
        expect(encodeHex(encodeCanonicalCbor(value)), vector.name).toBe(vector.cborHex);
      }
    }
    expect(normalizeStringSet(["\u{105D2}\u0307", "\u{105C9}"])).toHaveLength(2);
  });

  it("exports the pinned normalizer and embeds the shared range table", () => {
    for (const vector of fixture.text) {
      const input = text(vector.inputHex);
      expect(encodeHex(new TextEncoder().encode(normalizeCanonicalText(input))), vector.name)
        .toBe(vector.canonicalHex);
      expect(isCanonicalText(input), vector.name).toBe(vector.decode === "accept");
    }

    let serialized = "";
    let previousLast = -1;
    for (let index = 0; index < UNICODE_15_UNASSIGNED_RANGES.length; index += 2) {
      const first = UNICODE_15_UNASSIGNED_RANGES[index];
      const last = UNICODE_15_UNASSIGNED_RANGES[index + 1];
      if (first === undefined || last === undefined || first <= previousLast || last < first ||
        last > 0x10ffff) {
        throw new Error(`unassigned range ${index / 2} is not ascending and disjoint`);
      }
      previousLast = last;
      const hex = (value: number) => value.toString(16).toUpperCase().padStart(4, "0");
      serialized += `${hex(first)}..${hex(last)}\n`;
    }
    expect(createHash("sha256").update(serialized).digest("hex"))
      .toBe(fixture.unassignedRangesSha256);
  });
});
