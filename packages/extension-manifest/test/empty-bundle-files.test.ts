import { describe, expect, it } from "vitest";

import {
  compileExtensionManifest,
  computeExtensionContentDigest,
  type ExtensionBundleFiles,
} from "../src/index.ts";

function manifest() {
  return {
    apiVersion: "pi.platform/v1alpha2",
    kind: "Extension",
    metadata: {
      id: "official/empty-files",
      version: "1.0.0",
      publisher: "platform",
      digest: `sha256:${"0".repeat(64)}`,
    },
    runtime: { compatibility: "worker", entry: "index.mjs", piApiVersion: "v1", priority: 0 },
    configuration: { schema: "config.json", defaults: {} },
    hooks: [],
    tools: [],
    permissions: {
      workspace: { read: false, write: false },
      execution: { required: false, commands: [], packages: [] },
      network: { mode: "none" },
      mcp: { servers: [] },
      secrets: [],
    },
    state: { scope: "session", schemaVersion: 1, migrationsFrom: [] },
    execution: { supportedBackends: ["nsjail"] },
    security: {
      requestedMinimumAgentIsolation: { processScope: "shared", outerIsolation: "none" },
    },
  };
}

async function compile(modules: ExtensionBundleFiles) {
  const raw = manifest();
  const files = { "config.json": '{"type":"object"}', ...modules };
  raw.metadata.digest = await computeExtensionContentDigest(raw, files);
  return compileExtensionManifest(raw, files);
}

describe("empty bundle file representations", () => {
  it("compiles an empty entry identically as a string and bytes", async () => {
    const bytes = await compile({ "index.mjs": new Uint8Array() });
    const string = await compile({ "index.mjs": "" });

    expect(string).toEqual(bytes);
    expect(string.moduleGraph).toEqual([
      { path: "index.mjs", imports: [], digest: expect.any(String) },
    ]);
  });

  it("compiles an empty imported module identically as a string and bytes", async () => {
    const entry = 'import "./empty.mjs";';
    const bytes = await compile({ "index.mjs": entry, "empty.mjs": new Uint8Array() });
    const string = await compile({ "index.mjs": entry, "empty.mjs": "" });

    expect(string).toEqual(bytes);
    expect(string.moduleGraph.map(({ path, imports }) => ({ path, imports }))).toEqual([
      { path: "empty.mjs", imports: [] },
      { path: "index.mjs", imports: ["empty.mjs"] },
    ]);
  });

  it("includes an empty asset identically as a string and bytes", async () => {
    const entry = "export const answer = 42;";
    const bytes = await compile({ "index.mjs": entry, "empty.txt": new Uint8Array() });
    const string = await compile({ "index.mjs": entry, "empty.txt": "" });

    expect(string).toEqual(bytes);
    expect(string.contentDigest).not.toBe((await compile({ "index.mjs": entry })).contentDigest);
  });

  it("keeps required manifest strings non-empty", async () => {
    const raw = manifest();
    raw.metadata.publisher = "";

    await expect(computeExtensionContentDigest(raw, {
      "index.mjs": "",
      "config.json": '{"type":"object"}',
    })).rejects.toThrow(/publisher.*must be a non-empty string/);
  });

  it("keeps the per-file UTF-8 byte limit for string contents", async () => {
    await expect(compile({
      "index.mjs": "export const answer = 42;",
      "oversized.txt": "é".repeat(524_289),
    })).rejects.toThrow(/must not exceed 1048576/);
  });

  it("keeps rejecting isolated Unicode surrogates in string contents", async () => {
    await expect(compile({
      "index.mjs": "export const answer = 42;",
      "invalid.txt": "\udc00",
    })).rejects.toThrow(/Unicode scalar values/);
  });
});
