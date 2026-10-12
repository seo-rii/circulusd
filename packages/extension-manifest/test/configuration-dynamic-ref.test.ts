import { describe, expect, it } from "vitest";
import { digestBytes } from "@circulusd/protocol-types";
import fixture from "../fixtures/configuration-dynamicref-v1.json";
import type { JsonValue } from "../src/configuration-codec.ts";
import { validateExtensionSchema } from "../src/configuration-schema.ts";
import { compileExtensionManifest, computeExtensionContentDigest } from "../src/index.ts";

const cases = fixture.cases as readonly {
  name: string;
  schema: JsonValue;
  schemaValid: boolean;
  instances: readonly { name: string; value: JsonValue; valid: boolean }[];
}[];

describe("extension local dynamic references", () => {
  for (const entry of cases) {
    describe(entry.name, () => {
      it("matches the Go schema compilation contract", () => {
        const validate = () => validateExtensionSchema(entry.schema as JsonValue);
        if (entry.schemaValid) expect(validate).not.toThrow();
        else expect(validate).toThrow();
      });
      it.each(entry.instances)("matches the Go instance contract: $name", ({ value, valid }) => {
        const validate = () => validateExtensionSchema(entry.schema as JsonValue, value as JsonValue);
        if (valid) expect(validate).not.toThrow();
        else expect(validate).toThrow(/violate their schema/);
      });
    });
  }

  function manifest(defaults: JsonValue) {
    return {
      apiVersion: "pi.platform/v1alpha2", kind: "Extension",
      metadata: { id: "official/probe", version: "1.0.0", publisher: "platform", digest: `sha256:${"0".repeat(64)}` },
      runtime: { compatibility: "worker", entry: "index.mjs", piApiVersion: "v1", priority: 0 },
      configuration: { schema: "config.json", defaults }, hooks: [], tools: [],
      permissions: { workspace: { read: false, write: false }, execution: { required: false, commands: [], packages: [] }, network: { mode: "none" }, mcp: { servers: [] }, secrets: [] },
      state: { scope: "session", schemaVersion: 1, migrationsFrom: [] }, execution: { supportedBackends: ["nsjail"] },
      security: { requestedMinimumAgentIsolation: { processScope: "shared", outerIsolation: "none" } },
    };
  }

  it("compiles valid defaults without changing the original schema or signed schema digest", async () => {
    const entry = cases[0]!;
    const schemaText = JSON.stringify(entry.schema);
    const raw = manifest({ value: 0.5 });
    const files = { "index.mjs": "export const result = 1;", "config.json": schemaText };
    raw.metadata.digest = await computeExtensionContentDigest(raw, files);
    const compiled = await compileExtensionManifest(raw, files);
    expect(compiled.manifest.configuration.defaults).toEqual({ value: 0.5 });
    expect(compiled.schemaDigests).toEqual([{ path: "config.json", digest: await digestBytes(new TextEncoder().encode(schemaText)) }]);
    expect(JSON.stringify(entry.schema)).toBe(schemaText);
    await expect(computeExtensionContentDigest(manifest({ value: {} }), files)).rejects.toThrow(/defaults violate/);
  });

  it("rejects a missing target in tool schemas without defaults", async () => {
    const raw = { ...manifest({}), tools: [{ name: "probe.run", inputSchema: "input.json", outputSchema: "output.json", replay: { mode: "safe" } }] };
    const files = {
      "index.mjs": "export const result = 1;", "config.json": '{"type":"object"}',
      "input.json": '{"properties":{"value":{"$dynamicRef":"#/$defs/missing"}}}', "output.json": '{"type":"object"}',
    };
    await expect(computeExtensionContentDigest(raw, files)).rejects.toThrow(/reference|resolve/);
  });
});
