import { afterEach, describe, expect, it, vi } from "vitest";

const lifecycle = vi.hoisted(() => ({
  failure: undefined as "updateSnapshot" | "getProjects" | undefined,
  opened: 0,
  closed: 0,
}));

vi.mock("typescript/unstable/sync", async (importOriginal) => {
  const actual = await importOriginal<typeof import("typescript/unstable/sync")>();
  class API extends actual.API {
    constructor(...args: ConstructorParameters<typeof actual.API>) {
      super(...args);
      lifecycle.opened += 1;
    }

    override updateSnapshot(...args: Parameters<InstanceType<typeof actual.API>["updateSnapshot"]>) {
      if (lifecycle.failure === "updateSnapshot") {
        throw new Error("injected updateSnapshot failure");
      }
      const snapshot = super.updateSnapshot(...args);
      if (lifecycle.failure === "getProjects") {
        snapshot.getProjects = () => {
          throw new Error("injected getProjects failure");
        };
      }
      return snapshot;
    }

    override close() {
      lifecycle.closed += 1;
      super.close();
    }
  }
  return { ...actual, API };
});

const { compileExtensionManifest, computeExtensionContentDigest } = await import("../src/index.ts");

function manifest() {
  return {
    apiVersion: "pi.platform/v1alpha2",
    kind: "Extension",
    metadata: {
      id: "official/typescript-lifecycle",
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

const files = {
  "config.json": '{"type":"object"}',
  "index.mjs": "export const result = 1;\n",
};

afterEach(() => {
  lifecycle.failure = undefined;
  lifecycle.opened = 0;
  lifecycle.closed = 0;
});

describe("hermetic TypeScript API lifecycle", () => {
  it("closes the TypeScript API after a successful compile", async () => {
    const raw = manifest();
    raw.metadata.digest = await computeExtensionContentDigest(raw, files);
    await compileExtensionManifest(raw, files);

    expect(lifecycle.opened).toBe(2);
    expect(lifecycle.closed).toBe(lifecycle.opened);
  });

  it.each(["updateSnapshot", "getProjects"] as const)(
    "closes the TypeScript API when %s throws",
    async (failure) => {
      lifecycle.failure = failure;
      await expect(computeExtensionContentDigest(manifest(), files)).rejects.toThrow(
        `injected ${failure} failure`,
      );

      expect(lifecycle.opened).toBe(1);
      expect(lifecycle.closed).toBe(1);
    },
  );
});
