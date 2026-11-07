import { describe, expect, it } from "vitest";
import fixture from "../fixtures/configuration-multipleof-v1.json";
import type { JsonValue } from "../src/configuration-codec.ts";
import { validateExtensionSchema } from "../src/configuration-schema.ts";
import { compileExtensionManifest, computeExtensionContentDigest, ExtensionManifestError } from "../src/index.ts";

describe("extension configuration decimal multipleOf", () => {
  it.each(fixture.cases)("matches Go/TS decimal validation: $name", ({ multipleOf, value, valid }) => {
    const schema = { type: "object", required: ["value"], properties: { value: { type: "number", multipleOf } }, additionalProperties: false };
    const validate = () => validateExtensionSchema(schema, { value });
    if (valid) expect(validate).not.toThrow();
    else expect(validate).toThrow(/multiple of/);
  });

  it.each([
    ["local reference", { $defs: { step: { type: "number", multipleOf: 0.1 } }, properties: { value: { $ref: "#/$defs/step" } }, unevaluatedProperties: false }, { value: 0.3 }, { value: 0.35 }],
    ["nested array items", { properties: { readings: { type: "array", items: { type: "number", multipleOf: 0.1 } } } }, { readings: [0.2, 0.3] }, { readings: [0.2, 0.35] }],
    ["allOf", { properties: { value: { allOf: [{ type: "number" }, { multipleOf: 0.1 }] } } }, { value: 0.3 }, { value: 0.35 }],
    ["anyOf", { anyOf: [{ properties: { value: { type: "number", multipleOf: 0.1 } } }, { properties: { value: { type: "string" } } }], unevaluatedProperties: false }, { value: 0.3 }, { value: 0.35 }],
    ["oneOf", { properties: { value: { oneOf: [{ multipleOf: 0.1 }, { multipleOf: 0.2 }] } } }, { value: 0.3 }, { value: 0.4 }],
    ["not", { properties: { value: { type: "number", not: { multipleOf: 0.1 } } } }, { value: 0.35 }, { value: 0.3 }],
    // oxlint-disable-next-line unicorn/no-thenable -- JSON Schema conditional keyword.
    ["conditional", { properties: { value: { type: "number", if: { multipleOf: 0.1 }, then: { minimum: 0.3 }, else: false } } }, { value: 0.3 }, { value: 0.35 }],
    ["contains", { properties: { readings: { type: "array", contains: { type: "number", multipleOf: 0.1 }, minContains: 1, maxContains: 1 } } }, { readings: [0.3, 0.35] }, { readings: [0.2, 0.3] }],
    ["unevaluatedItems", { properties: { readings: { type: "array", prefixItems: [{ type: "number", multipleOf: 0.1 }], unevaluatedItems: false } } }, { readings: [0.3] }, { readings: [0.3, 0.2] }],
  ] satisfies [string, JsonValue, JsonValue, JsonValue][])("keeps %s semantics", (_name, schema, valid, invalid) => {
    expect(() => validateExtensionSchema(schema, valid)).not.toThrow();
    expect(() => validateExtensionSchema(schema, invalid)).toThrow(/violate their schema/);
  });

  it.each([0, -0.1, "0.1", null, false])("rejects invalid multipleOf keyword %s without defaults", (multipleOf) => {
    expect(() => validateExtensionSchema({ type: "number", multipleOf })).toThrow();
  });

  it("ignores numeric constraints for nonnumeric instances", () => {
    expect(() => validateExtensionSchema({ multipleOf: 0.1 }, "value")).not.toThrow();
  });

  it("compiles the complete extension with valid decimal defaults", async () => {
    const raw = {
      apiVersion: "pi.platform/v1alpha2", kind: "Extension",
      metadata: { id: "official/probe", version: "1.0.0", publisher: "platform", digest: `sha256:${"0".repeat(64)}` },
      runtime: { compatibility: "worker", entry: "index.mjs", piApiVersion: "v1", priority: 0 },
      configuration: { schema: "config.json", defaults: { value: 0.3 } }, hooks: [], tools: [],
      permissions: { workspace: { read: false, write: false }, execution: { required: false, commands: [], packages: [] }, network: { mode: "none" }, mcp: { servers: [] }, secrets: [] },
      state: { scope: "session", schemaVersion: 1, migrationsFrom: [] },
      execution: { supportedBackends: ["nsjail"] },
      security: { requestedMinimumAgentIsolation: { processScope: "shared", outerIsolation: "none" } },
    };
    const files = {
      "index.mjs": "export const result = 1;",
      "config.json": JSON.stringify({ type: "object", required: ["value"], properties: { value: { type: "number", multipleOf: 0.1 } }, additionalProperties: false }),
    };
    raw.metadata.digest = await computeExtensionContentDigest(raw, files);
    const compiled = await compileExtensionManifest(raw, files);
    expect(compiled.manifest.configuration.defaults).toEqual({ value: 0.3 });
    await expect(computeExtensionContentDigest({ ...raw, configuration: { ...raw.configuration, defaults: { value: 0.35 } } }, files)).rejects.toBeInstanceOf(ExtensionManifestError);
  });
});
