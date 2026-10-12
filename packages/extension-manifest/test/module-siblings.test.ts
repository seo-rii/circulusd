import { describe, expect, it } from "vitest";

import {
  compileExtensionManifest,
  computeExtensionContentDigest,
  type ExtensionBundleFiles,
} from "../src/index.ts";

function manifest(entry: string) {
  return {
    apiVersion: "pi.platform/v1alpha2",
    kind: "Extension",
    metadata: {
      id: "official/module-siblings",
      version: "1.0.0",
      publisher: "platform",
      digest: `sha256:${"0".repeat(64)}`,
    },
    runtime: { compatibility: "worker", entry, piApiVersion: "v1", priority: 0 },
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

async function compile(entry: string, modules: ExtensionBundleFiles) {
  const raw = manifest(entry);
  const files = { "config.json": '{"type":"object"}', ...modules };
  raw.metadata.digest = await computeExtensionContentDigest(raw, files);
  return compileExtensionManifest(raw, files);
}

describe("explicit bundle module roots", () => {
  it.each([
    ["index.js", "index.ts", "export const typed: number = 2;"],
    ["index.js", "index.d.ts", "export declare const result: number;"],
    ["index.mjs", "index.mts", "export const typed: number = 2;"],
    ["index.mjs", "index.d.mts", "export declare const result: number;"],
  ])("compiles entry %s alongside %s", async (entry, sibling, siblingSource) => {
    const compiled = await compile(entry, {
      [entry]: 'import "./runtime.mjs"; export const result = 1;',
      [sibling]: siblingSource,
      "runtime.mjs": "export const runtime = true;",
    });

    expect(compiled.manifest.runtime.entry).toBe(entry);
    expect(compiled.moduleGraph.map(({ path, imports }) => ({ path, imports }))).toEqual([
      { path: entry, imports: ["runtime.mjs"] },
      { path: "runtime.mjs", imports: [] },
    ]);
  });

  it.each([
    ["same.js", "same.ts", "export const typed: number = 2;"],
    ["same.js", "same.d.ts", "export declare const result: number;"],
    ["same.mjs", "same.mts", "export const typed: number = 2;"],
    ["same.mjs", "same.d.mts", "export declare const result: number;"],
  ])("follows dependency %s alongside %s", async (dependency, sibling, siblingSource) => {
    const compiled = await compile("index.mjs", {
      "index.mjs": `import "./${dependency}";`,
      [dependency]: 'import "./runtime.mjs"; export const result = 1;',
      [sibling]: siblingSource,
      "runtime.mjs": "export const runtime = true;",
    });

    expect(compiled.moduleGraph.map(({ path, imports }) => ({ path, imports }))).toEqual([
      { path: "index.mjs", imports: [dependency] },
      { path: "runtime.mjs", imports: [] },
      { path: dependency, imports: ["runtime.mjs"] },
    ]);
  });

  it("keeps explicit declaration imports in the validated graph", async () => {
    const compiled = await compile("index.ts", {
      "index.ts": 'import type { Result } from "./types.d.ts"; export const result: Result = { value: 1 };',
      "types.d.ts": "export interface Result { value: number }",
    });

    expect(compiled.moduleGraph.map(({ path, imports }) => ({ path, imports }))).toEqual([
      { path: "index.ts", imports: ["types.d.ts"] },
      { path: "types.d.ts", imports: [] },
    ]);
  });

  it.each([
    ["native addon", 'import "./binding.node";', /native addons are forbidden/],
    ["static builtin import", 'import "node:fs";', /must be relative/],
    ["static builtin re-export", 'export * from "node:fs";', /must be relative/],
    ["missing static import", 'import "./missing.mjs";', /module .* is missing/],
    ["dynamic import", 'import("./runtime.mjs");', /dynamic import is forbidden/],
    ["CommonJS require", 'require("node:fs");', /require is forbidden/],
    ["syntax error", "export const = 1;", /invalid ECMAScript syntax/],
  ])("rejects %s in JavaScript beside a benign TypeScript sibling", async (_label, source, error) => {
    await expect(compile("index.js", {
      "index.js": source,
      "index.ts": "export const safe = true;",
    })).rejects.toThrow(error);
  });

  it("keeps rejecting forbidden imports in declarations", async () => {
    await expect(compile("index.ts", {
      "index.ts": 'import type { Result } from "./types.d.ts";',
      "types.d.ts": 'import type { Stats } from "node:fs"; export type Result = Stats;',
    })).rejects.toThrow(/must be relative/);
  });
});
