import { describe, expect, it } from "vitest";

import {
  ExtensionManifestError,
  compileExtensionManifest,
  computeExtensionContentDigest,
} from "../src/index.ts";

const ZERO_DIGEST = `sha256:${"0".repeat(64)}`;

function manifest(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    apiVersion: "pi.platform/v1alpha2",
    kind: "Extension",
    metadata: {
      id: "official/pdf",
      version: "1.4.2",
      publisher: "platform",
      digest: ZERO_DIGEST,
    },
    runtime: {
      compatibility: "pi-server",
      entry: "dist/index.mjs",
      piApiVersion: "v1",
      priority: 100,
    },
    configuration: {
      schema: "schemas/config.schema.json",
      defaults: { outputFormat: "pdf" },
    },
    hooks: ["beforeAgentStart", "beforeToolCall", "afterToolCall"],
    tools: [
      {
        name: "pdf.render",
        inputSchema: "schemas/render.input.json",
        outputSchema: "schemas/render.output.json",
        replay: { mode: "idempotency-key" },
      },
    ],
    permissions: {
      workspace: { read: true, write: true },
      execution: {
        required: true,
        commands: ["pandoc", "libreoffice"],
        packages: [{ id: "document-tools", version: ">=3.2.0 <4.0.0" }],
      },
      network: { mode: "none" },
      mcp: { servers: [] },
      secrets: [],
    },
    state: { scope: "workspace", schemaVersion: 3, migrationsFrom: [2] },
    execution: { supportedBackends: ["nsjail", "docker", "firecracker"] },
    security: {
      requestedMinimumAgentIsolation: { processScope: "shared", outerIsolation: "none" },
    },
    ...overrides,
  };
}

function files(
  overrides: Readonly<Record<string, string | Uint8Array>> = {},
): Record<string, string | Uint8Array> {
  return {
    "dist/index.mjs":
      'import { render } from "./render.mjs"; export { render };\n',
    "dist/render.mjs": "export const render = (input) => input;\n",
    "schemas/config.schema.json": JSON.stringify({
      type: "object",
      properties: { outputFormat: { type: "string" } },
      additionalProperties: false,
    }),
    "schemas/render.input.json": JSON.stringify({ type: "object" }),
    "schemas/render.output.json": JSON.stringify({ type: "object" }),
    ...overrides,
  };
}

async function signedManifest(
  raw = manifest(),
  bundleFiles = files(),
): Promise<Record<string, unknown>> {
  const digest = await computeExtensionContentDigest(raw, bundleFiles);
  return {
    ...raw,
    metadata: { ...(raw.metadata as Record<string, unknown>), digest },
  };
}

describe("extension manifest compiler", () => {
  it("compiles a hermetic manifest into a deterministic deeply immutable revision", async () => {
    const bundleFiles = files();
    const raw = await signedManifest(manifest(), bundleFiles);
    const first = await compileExtensionManifest(raw, bundleFiles);
    const shuffledFiles = Object.fromEntries(Object.entries(bundleFiles).reverse());
    const shuffledRaw = {
      tools: raw.tools,
      runtime: raw.runtime,
      metadata: raw.metadata,
      kind: raw.kind,
      apiVersion: raw.apiVersion,
      hooks: raw.hooks,
      configuration: raw.configuration,
      security: raw.security,
      execution: raw.execution,
      state: raw.state,
      permissions: raw.permissions,
    };
    const second = await compileExtensionManifest(shuffledRaw, shuffledFiles);

    expect(first).toEqual(second);
    expect(first.contentDigest).toBe((raw.metadata as Record<string, unknown>).digest);
    expect(first.moduleGraph).toEqual([
      { path: "dist/index.mjs", imports: ["dist/render.mjs"], digest: expect.any(String) },
      { path: "dist/render.mjs", imports: [], digest: expect.any(String) },
    ]);
    expect(first.schemaDigests.map(({ path }) => path)).toEqual([
      "schemas/config.schema.json",
      "schemas/render.input.json",
      "schemas/render.output.json",
    ]);
    expect(first.revisionDigest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(Object.isFrozen(first)).toBe(true);
    expect(Object.isFrozen(first.manifest)).toBe(true);
    expect(Object.isFrozen(first.manifest.permissions.execution.packages[0])).toBe(true);
    expect(Object.isFrozen(first.moduleGraph[0]?.imports)).toBe(true);
    expect(() => {
      (first.manifest.metadata as { id: string }).id = "evil/id";
    }).toThrow(TypeError);
  });

  it("snapshots caller input before hashing", async () => {
    const bundleFiles = files();
    const raw = await signedManifest(manifest(), bundleFiles);
    const pending = compileExtensionManifest(raw, bundleFiles);
    (raw.runtime as Record<string, unknown>).entry = "dist/missing.mjs";
    bundleFiles["dist/index.mjs"] = "eval('changed')";

    const compiled = await pending;
    expect(compiled.manifest.runtime.entry).toBe("dist/index.mjs");
    expect(compiled.moduleGraph[0]?.imports).toEqual(["dist/render.mjs"]);
  });

  it("normalizes set-like manifest fields with locale-independent code-unit ordering", async () => {
    const raw = manifest({
      tools: [
        {
          name: "pdf.z_tool",
          inputSchema: "schemas/render.input.json",
          outputSchema: "schemas/render.output.json",
          replay: { mode: "safe" },
        },
        {
          name: "pdf.z-tool",
          inputSchema: "schemas/render.input.json",
          outputSchema: "schemas/render.output.json",
          replay: { mode: "safe" },
        },
      ],
    });
    const compiled = await compileExtensionManifest(await signedManifest(raw), files());

    expect(compiled.manifest.tools.map(({ name }) => name)).toEqual([
      "pdf.z-tool",
      "pdf.z_tool",
    ]);
  });

  it.each([
    ["wrong api version", { apiVersion: "pi.platform/v1alpha1" }],
    ["unknown top-level field", { surprise: true }],
    ["malformed extension id", { metadata: { id: "../pdf", version: "1.4.2", publisher: "p", digest: ZERO_DIGEST } }],
    ["malformed semantic version", { metadata: { id: "official/pdf", version: "01.4.2", publisher: "p", digest: ZERO_DIGEST } }],
    ["non-canonical digest", { metadata: { id: "official/pdf", version: "1.4.2", publisher: "p", digest: `sha256:${"A".repeat(64)}` } }],
    ["absolute entry", { runtime: { compatibility: "worker", entry: "/index.mjs", piApiVersion: "v1", priority: 0 } }],
    ["unsupported compatibility", { runtime: { compatibility: "node", entry: "dist/index.mjs", piApiVersion: "v1", priority: 0 } }],
    ["unknown hook", { hooks: ["beforeTurn", "shellEscape"] }],
    ["invalid state scope", { state: { scope: "global", schemaVersion: 1, migrationsFrom: [] } }],
    ["unknown backend", { execution: { supportedBackends: ["kubernetes"] } }],
    ["duplicate backend", { execution: { supportedBackends: ["nsjail", "nsjail"] } }],
    ["invalid process scope", { security: { requestedMinimumAgentIsolation: { processScope: "process", outerIsolation: "none" } } }],
    ["invalid outer isolation", { security: { requestedMinimumAgentIsolation: { processScope: "shared", outerIsolation: "bubblewrap" } } }],
    ["raw backend locator", { execution: { supportedBackends: ["docker"], image: "tenant/raw:latest" } }],
    ["invalid permission", { permissions: { workspace: { read: "yes", write: false } } }],
  ])("rejects %s", async (_name, override) => {
    await expect(compileExtensionManifest(manifest(override), files())).rejects.toBeInstanceOf(
      ExtensionManifestError,
    );
  });

  it("rejects exotic objects, accessors, symbol keys, and mutable aliases", async () => {
    await expect(
      compileExtensionManifest(Object.assign(Object.create(null), manifest()), files()),
    ).rejects.toBeInstanceOf(ExtensionManifestError);
    const raw = manifest();
    Object.defineProperty(raw, "hooks", { enumerable: true, get: () => [] });
    await expect(compileExtensionManifest(raw, files())).rejects.toBeInstanceOf(
      ExtensionManifestError,
    );
    const symbolic = manifest();
    Object.defineProperty(symbolic, Symbol("hidden"), { enumerable: true, value: true });
    await expect(compileExtensionManifest(symbolic, files())).rejects.toBeInstanceOf(
      ExtensionManifestError,
    );
    const symbolicArray = manifest();
    const hooks = [...(symbolicArray.hooks as string[])];
    Object.defineProperty(hooks, Symbol.iterator, { value: Array.prototype[Symbol.iterator] });
    symbolicArray.hooks = hooks;
    await expect(compileExtensionManifest(symbolicArray, files())).rejects.toThrow(
      /symbol properties/i,
    );
  });

  it("rejects malformed native package comparator ranges", async () => {
    const raw = manifest();
    const execution = (raw.permissions as Record<string, unknown>).execution as Record<
      string,
      unknown
    >;
    execution.packages = [{ id: "document-tools", version: "=>3.2.0" }];
    await expect(compileExtensionManifest(raw, files())).rejects.toThrow(/comparator range/i);
  });

  it("rejects duplicate tools and incomplete or invalid replay declarations", async () => {
    const tool = (manifest().tools as unknown[])[0];
    await expect(
      compileExtensionManifest(manifest({ tools: [tool, tool] }), files()),
    ).rejects.toThrow(/duplicate tool/i);
    await expect(
      compileExtensionManifest(
        manifest({
          tools: [
            {
              name: "pdf.render",
              inputSchema: "schemas/render.input.json",
              outputSchema: "schemas/render.output.json",
            },
          ],
        }),
        files(),
      ),
    ).rejects.toThrow(/replay/i);
    await expect(
      compileExtensionManifest(
        manifest({
          tools: [
            {
              name: "pdf.render",
              inputSchema: "schemas/render.input.json",
              outputSchema: "schemas/render.output.json",
              replay: { mode: "sometimes" },
            },
          ],
        }),
        files(),
      ),
    ).rejects.toThrow(/replay/i);
  });

  it.each([
    ["bare import", 'import "left-pad";', /relative/i],
    ["Node builtin", 'import "node:fs";', /relative/i],
    ["dynamic import", 'await import("./render.mjs");', /dynamic import/i],
    ["require", 'require("./render.mjs");', /require/i],
    ["aliased require", "const load = require; load('./render.mjs');", /require/i],
    ["eval", 'eval("1 + 1");', /eval/i],
    ["aliased eval", "const indirect = eval; indirect('1 + 1');", /eval/i],
    ["Function constructor", 'new Function("return 1")();', /Function/],
    [
      "aliased Function constructor",
      'const Ctor = globalThis["Function"]; new Ctor("return 1")();',
      /Function/,
    ],
    [
      "template-literal Function alias",
      "const Ctor = globalThis[`Function`]; new Ctor('return 1')();",
      /Function/,
    ],
    ["native addon", 'import "./binding.node";', /native addon/i],
    ["percent-encoded traversal", 'import "./%2e%2e/%2e%2e/outside.mjs";', /canonical/i],
    ["empty path segment", 'import "./nested//module.mjs";', /canonical/i],
    ["path traversal", 'import "../../outside.mjs";', /escapes/i],
    ["missing module", 'import "./missing.mjs";', /missing/i],
  ])("rejects a non-hermetic graph containing %s", async (_name, source, reason) => {
    const bundleFiles = files({ "dist/index.mjs": source });
    await expect(compileExtensionManifest(manifest(), bundleFiles)).rejects.toThrow(reason);
  });

  it("rejects native addons even when they are unreachable", async () => {
    await expect(
      compileExtensionManifest(manifest(), files({ "unused/binding.node": new Uint8Array([1]) })),
    ).rejects.toThrow(/native addon/i);
  });

  it("bounds TypeScript AST size and depth before accepting a module", async () => {
    await expect(
      compileExtensionManifest(
        manifest(),
        files({ "dist/index.mjs": ";".repeat(10_100) }),
      ),
    ).rejects.toThrow(/AST nodes/i);
    await expect(
      compileExtensionManifest(
        manifest(),
        files({ "dist/index.mjs": `${"(".repeat(300)}1${")".repeat(300)};` }),
      ),
    ).rejects.toThrow(/AST depth/i);
  });

  it("rejects re-export escapes and module cycles", async () => {
    await expect(
      compileExtensionManifest(
        manifest(),
        files({ "dist/index.mjs": 'export * from "node:fs";' }),
      ),
    ).rejects.toThrow(/relative/i);
    await expect(
      compileExtensionManifest(
        manifest(),
        files({ "dist/render.mjs": 'import "./index.mjs";' }),
      ),
    ).rejects.toThrow(/cycle/i);
  });

  it.each([
    ["invalid JSON", "{"],
    ["non-object root", "[]"],
    ["oversized schema", `{"description":"${"x".repeat(262_145)}"}`],
  ])("rejects %s schemas", async (_name, schema) => {
    await expect(
      compileExtensionManifest(
        manifest(),
        files({ "schemas/config.schema.json": schema }),
      ),
    ).rejects.toBeInstanceOf(ExtensionManifestError);
  });

  it("rejects an otherwise valid bundle when its declared digest does not match", async () => {
    await expect(compileExtensionManifest(manifest(), files())).rejects.toThrow(/digest/i);
  });
});
