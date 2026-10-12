import { describe, expect, it } from "vitest";
import { digestStructuredValue, encodeCanonicalCbor, encodeHex } from "@circulusd/protocol-types";
import { digestExtensionJson, encodeExtensionJsonDigestPayload, extensionJsonDigestPayload, normalizeExtensionJson } from "../src/configuration-codec.ts";
import fixture from "../fixtures/configuration-json-v2.json";

describe("extension JSON configuration codec", () => {
  it.each(fixture.cases)("matches Go/TS golden $name", async (entry) => {
    const value = JSON.parse(entry.json) as unknown;
    expect(extensionJsonDigestPayload(value).schemaVersion).toBe(entry.schemaVersion);
    expect(encodeHex(encodeExtensionJsonDigestPayload(value))).toBe(entry.encodedPayloadHex);
    expect(await digestExtensionJson(fixture.domain, value)).toBe(entry.digest);
  });

  it("retains the existing safe-integer digest and normalizes negative zero", async () => {
    const value = { "official/pdf": { scale: 1, prefix: "", items: [null, true, 2] } };
    expect(await digestExtensionJson(fixture.domain, value)).toBe(await digestStructuredValue(fixture.domain, 1, value));
    expect(await digestExtensionJson(fixture.domain, { scale: -0 })).toBe(await digestExtensionJson(fixture.domain, { scale: 0 }));
    expect(() => encodeCanonicalCbor({ scale: 0.5 })).toThrow(/safe integer/i);
  });

  it.each([NaN, Infinity, -Infinity, Number("1e309")])("rejects non-finite JSON value %s", (value) => {
    expect(() => normalizeExtensionJson({ value })).toThrow(/finite/i);
  });

  it("does not interpret user objects or arrays as number wrappers", async () => {
    const number = { scale: 0.5, value: 0.5 };
    const object = { scale: 0.5, value: { "$extension.json.v2": ["number", "3fe0000000000000"] } };
    const array = { scale: 0.5, value: ["number", "3fe0000000000000"] };
    const digests = await Promise.all([number, object, array].map((value) => digestExtensionJson(fixture.domain, value)));
    expect(new Set(digests).size).toBe(3);
  });

  it("bounds nested JSON and rejects normalized key collisions and accessors", () => {
    const collision = { "é": 1, "é": 2 };
    expect(() => normalizeExtensionJson(collision)).toThrow(/duplicate normalized/i);
    expect(() => normalizeExtensionJson(JSON.parse('{"__proto__":{"polluted":true}}'))).toThrow(/dangerous/i);
    const getter = Object.defineProperty({}, "value", { enumerable: true, get: () => 0.5 });
    expect(() => normalizeExtensionJson(getter)).toThrow(/data properties/i);
    let value: unknown = 0.5;
    for (let i = 0; i < 65; i++) value = [value];
    expect(() => normalizeExtensionJson(value)).toThrow(/depth/i);
  });
});
