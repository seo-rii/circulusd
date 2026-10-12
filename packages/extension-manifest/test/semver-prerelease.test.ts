import { describe, expect, it } from "vitest";

import { compileExtensionManifest, computeExtensionContentDigest } from "../src/index.ts";

function manifest(version: string) {
  return {
    apiVersion: "pi.platform/v1alpha2",
    kind: "Extension",
    metadata: {
      id: "official/prerelease",
      version,
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

const files = { "index.mjs": "export const answer = 42;", "config.json": '{"type":"object"}' };

describe("extension prerelease semantic versions", () => {
  it.each([
    "1.0.0-1alpha",
    "1.0.0-01alpha",
    "1.0.0-123-abc",
    "1.0.0-alpha.1beta+build.01",
    "1.0.0-alpha1",
    "1.0.0-0",
    "1.0.0-1",
    "1.0.0",
  ])("compiles the valid version %s", async (version) => {
    const raw = manifest(version);
    raw.metadata.digest = await computeExtensionContentDigest(raw, files);

    const compiled = await compileExtensionManifest(raw, files);

    expect(compiled.manifest.metadata.version).toBe(version);
    expect(compiled.contentDigest).toBe(raw.metadata.digest);
    expect(compiled.revisionDigest).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it.each([
    "1.0.0-01",
    "1.0.0-alpha.01",
    "01.0.0-alpha",
    "1.0.0-",
    "1.0.0-alpha..1",
    "1.0.0-1_alpha",
  ])("rejects the invalid version %s", async (version) => {
    await expect(computeExtensionContentDigest(manifest(version), files)).rejects.toThrow(
      /strict semantic version/,
    );
  });
});
