import {
  decodeCanonicalCbor,
  decodeHex,
  encodeCanonicalCbor,
  type NormalizedValue,
} from "@circulusd/protocol-types";
import { describe, expect, it } from "vitest";

import { decodeCanonicalCheckpointPayload } from "../src/codec.ts";

const fixtures: { name: string; value: NormalizedValue }[] = [
  { name: "ordinary text", value: { text: "hello" } },
  { name: "a leading U+FEFF value", value: { text: "\uFEFFhello" } },
  { name: "U+FEFF inside a value", value: { text: "a\uFEFFb" } },
  { name: "a leading U+FEFF map key", value: { "\uFEFFkey": "value" } },
  {
    name: "a leading U+FEFF in nested message content",
    value: {
      coreState: {
        messages: [{ role: "user", content: [{ type: "text", text: "\uFEFFhello" }] }],
      },
    },
  },
  { name: "a leading U+FEFF scalar", value: "\uFEFFhello" },
  { name: "a string containing only U+FEFF", value: "\uFEFF" },
  {
    name: "distinct keys with and without a leading U+FEFF",
    value: { key: "plain", "\uFEFFkey": "prefixed" },
  },
];

describe("checkpoint CBOR string preservation", () => {
  it.each(fixtures)("preserves $name like the shared decoder", ({ value }) => {
    const bytes = encodeCanonicalCbor(value);
    const decoded = decodeCanonicalCheckpointPayload(bytes, bytes.byteLength);

    expect(decoded).toEqual(value);
    expect(decoded).toEqual(decodeCanonicalCbor(bytes));
    expect(encodeCanonicalCbor(decoded)).toEqual(bytes);
  });

  it("preserves a leading U+FEFF in independently authored canonical bytes", () => {
    // Canonical map { text: U+FEFFhello }, without using the fixture encoder.
    const bytes = decodeHex("a1647465787468efbbbf68656c6c6f");

    expect(decodeCanonicalCheckpointPayload(bytes, bytes.byteLength)).toEqual({ text: "\uFEFFhello" });
    expect(decodeCanonicalCbor(bytes)).toEqual({ text: "\uFEFFhello" });
  });

  it("continues to reject invalid UTF-8", () => {
    const bytes = Uint8Array.from([0x62, 0xc3, 0x28]);

    expect(() => decodeCanonicalCheckpointPayload(bytes, bytes.byteLength)).toThrowError(
      expect.objectContaining({
        code: "INVALID_CHECKPOINT",
        message: "checkpoint CBOR text is invalid UTF-8",
      }),
    );
    expect(() => decodeCanonicalCbor(bytes)).toThrow();
  });

  it.each([
    { name: "a non-minimal string length", hex: "7808efbbbf68656c6c6f" },
    { name: "non-NFC text", hex: "6365cc81" },
    { name: "out-of-order map keys", hex: "a2616200616100" },
  ])("continues to reject $name", ({ hex }) => {
    const bytes = decodeHex(hex);

    expect(() => decodeCanonicalCheckpointPayload(bytes, bytes.byteLength)).toThrowError(
      expect.objectContaining({ code: "INVALID_CHECKPOINT" }),
    );
    expect(() => decodeCanonicalCbor(bytes)).toThrow();
  });
});
