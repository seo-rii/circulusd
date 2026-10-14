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

  it.each(["3.x", "3.2.x"])(
    "accepts the canonical wildcard native package range %s",
    async (version) => {
      const raw = manifest();
      const execution = (raw.permissions as Record<string, unknown>).execution as Record<
        string,
        unknown
      >;
      execution.packages = [{ id: "document-tools", version }];

      const compiled = await compileExtensionManifest(await signedManifest(raw), files());

      expect(compiled.manifest.permissions.execution.packages).toEqual([
        { id: "document-tools", version },
      ]);
    },
  );

  it.each(["3.2.0-beta.1", ">=3.2.0-beta.1"])(
    "rejects the unsupported prerelease native package range %s",
    async (version) => {
      const raw = manifest();
      const execution = (raw.permissions as Record<string, unknown>).execution as Record<
        string,
        unknown
      >;
      execution.packages = [{ id: "document-tools", version }];

      await expect(compileExtensionManifest(raw, files())).rejects.toThrow(/comparator range/i);
    },
  );

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

  it.each([
    ["function constructor access", '(function () {}).constructor("return 1")();', /constructor/],
    ["optional constructor access", "const run = () => 1; run?.constructor;", /constructor/],
    ["literal constructor key", 'const run = () => 1; run["constructor"];', /constructor/],
    ["template constructor key", "const run = () => 1; run[`constructor`];", /constructor/],
    ["destructured constructor", "const { constructor: Ctor } = async () => {};", /constructor/],
    ["constructor lookup call", 'Reflect.get(() => 1, "constructor");', /constructor/],
    ["computed global key", 'const name = "x"; globalThis[name];', /global object/],
    ["computed self key", 'const name = "x"; self[name];', /global object/],
    ["aliased global", "const root = globalThis; root.x;", /global object/],
    ["global argument", 'Reflect.get(globalThis, "x");', /global object/],
    ["global spread", "const copy = { ...globalThis };", /global object/],
    ["global destructuring", "const { x } = globalThis;", /global object/],
    ["global shorthand", "const holder = { globalThis };", /global object/],
    ["nested global alias", 'const name = "x"; globalThis.self[name];', /global object/],
    ["literal global alias", 'globalThis["window"].x;', /global object/],
    ["global valueOf", 'const name = "x"; self.valueOf()[name];', /global object/],
    ["parenthesized global", 'const name = "x"; (globalThis)[name];', /global object/],
  ])("rejects a code-generation route through %s", async (_name, source, reason) => {
    await expect(
      computeExtensionContentDigest(manifest(), files({ "dist/index.mjs": source })),
    ).rejects.toThrow(reason);
  });

  it("keeps constructors, comparisons and static global access allowed", async () => {
    const bundleFiles = files({
      "dist/index.mjs": [
        'import { render } from "./render.mjs";',
        "class Box { constructor(value) { this.value = value; } }",
        'const safeKey = (key) => key !== "__proto__" && key !== "constructor";',
        'const label = (key) => { switch (key) { case "constructor": return 1; default: return 0; } };',
        'const hasFetch = typeof globalThis.fetch === "function" && typeof self !== "undefined";',
        'const log = globalThis.console?.log ?? globalThis["console"].log;',
        "const flags = /x/g.global;",
        "const { window: view, self: owner } = { window: 1, self: 2 };",
        "function bind(self) { return self.value; }",
        "export { Box, safeKey, label, hasFetch, log, flags, view, owner, bind, render };",
        "",
      ].join("\n"),
    });
    const raw = await signedManifest(manifest(), bundleFiles);
    await expect(compileExtensionManifest(raw, bundleFiles)).resolves.toMatchObject({
      contentDigest: (raw.metadata as Record<string, unknown>).digest,
    });
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

  it("supports finite fractional and empty JSON configuration values", async () => {
    const raw = manifest({ configuration: {
      schema: "schemas/config.schema.json",
      defaults: { temperature: 0.5, prefix: "", nested: { values: [0.25, "", -0] } },
    } });
    const bundleFiles = files({ "schemas/config.schema.json": JSON.stringify({
      type: "object", properties: { temperature: { type: "number" }, prefix: { enum: [""] }, nested: { type: "object" } },
    }) });
    const compiled = await compileExtensionManifest(await signedManifest(raw, bundleFiles), bundleFiles);
    expect(compiled.manifest.configuration.defaults).toEqual({ temperature: 0.5, prefix: "", nested: { values: [0.25, "", 0] } });
  });

  it.each([
    ["invalid type", { type: "not-a-json-type" }],
    ["invalid required", { type: "object", required: "temperature" }],
    ["unresolved reference", { $ref: "#/$defs/missing" }],
  ])("rejects semantically malformed JSON Schema: %s", async (_name, schema) => {
    const bundleFiles = files({ "schemas/config.schema.json": JSON.stringify(schema) });
    await expect(computeExtensionContentDigest(manifest(), bundleFiles)).rejects.toBeInstanceOf(ExtensionManifestError);
  });

  it("rejects a supplied default that violates its configuration schema", async () => {
    const raw = manifest({ configuration: { schema: "schemas/config.schema.json", defaults: { temperature: "hot" } } });
    const bundleFiles = files({ "schemas/config.schema.json": JSON.stringify({ type: "object", properties: { temperature: { type: "number" } } }) });
    await expect(computeExtensionContentDigest(raw, bundleFiles)).rejects.toBeInstanceOf(ExtensionManifestError);
  });

  it("requires complete supplied defaults but allows defaults to be omitted", async () => {
    const raw = manifest({ configuration: { schema: "schemas/config.schema.json", defaults: { temperature: 0.5, prefix: "" } } });
    const bundleFiles = files({ "schemas/config.schema.json": JSON.stringify({
      $schema: "https://json-schema.org/draft/2020-12/schema",
      type: "object", required: ["temperature", "apiProfile"], minProperties: 3,
      $defs: { temperature: { type: "number", minimum: 0, maximum: 2 } },
      properties: { temperature: { $ref: "#/$defs/temperature" }, prefix: { enum: [""] }, apiProfile: { type: "string" } },
      additionalProperties: false,
    }) });
    await expect(computeExtensionContentDigest(raw, bundleFiles)).rejects.toThrow(/defaults violate/i);
    const complete = manifest({ configuration: { schema: "schemas/config.schema.json", defaults: { temperature: 0.5, prefix: "", apiProfile: "local" } } });
    const compiled = await compileExtensionManifest(await signedManifest(complete, bundleFiles), bundleFiles);
    expect(compiled.manifest.configuration.defaults).toEqual({ temperature: 0.5, prefix: "", apiProfile: "local" });
    const omitted = manifest({ configuration: { schema: "schemas/config.schema.json" } });
    const withoutDefaults = await compileExtensionManifest(await signedManifest(omitted, bundleFiles), bundleFiles);
    expect(withoutDefaults.manifest.configuration).not.toHaveProperty("defaults");
    const wrong = manifest({ configuration: { schema: "schemas/config.schema.json", defaults: { temperature: 3, prefix: "", apiProfile: "local" } } });
    await expect(computeExtensionContentDigest(wrong, bundleFiles)).rejects.toThrow(/defaults violate/i);
  });

  it.each([
    ["remote reference", { $ref: "https://example.invalid/schema.json" }],
    ["bundle reference", { $ref: "other.schema.json" }],
    ["unsupported dialect", { $schema: "http://json-schema.org/draft-07/schema#", type: "object" }],
    ["custom vocabulary", { $vocabulary: { "https://example.invalid/custom": true } }],
  ])("rejects unsupported offline schema metadata: %s", async (_name, schema) => {
    await expect(computeExtensionContentDigest(manifest(), files({ "schemas/config.schema.json": JSON.stringify(schema) }))).rejects.toBeInstanceOf(ExtensionManifestError);
  });

  it("validates tool schema semantics as well as configuration schemas", async () => {
    await expect(computeExtensionContentDigest(manifest(), files({ "schemas/render.input.json": '{"type":"invalid"}' }))).rejects.toBeInstanceOf(ExtensionManifestError);
  });

  it("enforces original oneOf constraints on supplied defaults", async () => {
    const bundleFiles = files({ "schemas/config.schema.json": JSON.stringify({ type: "object", oneOf: [
      { required: ["mode", "left"], properties: { mode: { const: "left" }, left: { type: "number" } } },
      { required: ["mode", "right"], properties: { mode: { const: "right" }, right: { type: "number" } } },
    ] }) });
    const raw = manifest({ configuration: { schema: "schemas/config.schema.json", defaults: {} } });
    await expect(computeExtensionContentDigest(raw, bundleFiles)).rejects.toThrow(/defaults violate/i);
    const complete = manifest({ configuration: { schema: "schemas/config.schema.json", defaults: { mode: "left", left: 0.5 } } });
    await expect(computeExtensionContentDigest(complete, bundleFiles)).resolves.toMatch(/^sha256:/);
    const invalid = manifest({ configuration: { schema: "schemas/config.schema.json", defaults: { mode: "left", left: "wrong" } } });
    await expect(computeExtensionContentDigest(invalid, bundleFiles)).rejects.toThrow(/defaults violate/i);
  });

  it("enforces original conditional constraints on supplied defaults", async () => {
    const bundleFiles = files({ "schemas/config.schema.json": JSON.stringify({
      type: "object", required: ["mode"], properties: { mode: { type: "string" }, temperature: { type: "number" } },
      if: { required: ["mode"], properties: { mode: { const: "strict" } } },
      // oxlint-disable-next-line unicorn/no-thenable -- JSON Schema conditional keyword.
      ["then"]: { properties: { temperature: { maximum: 1 } } },
      else: { properties: { temperature: { maximum: 10 } } },
    }) });
    const raw = manifest({ configuration: { schema: "schemas/config.schema.json", defaults: { temperature: 5 } } });
    await expect(computeExtensionContentDigest(raw, bundleFiles)).rejects.toThrow(/defaults violate/i);
    const complete = manifest({ configuration: { schema: "schemas/config.schema.json", defaults: { mode: "relaxed", temperature: 5 } } });
    await expect(computeExtensionContentDigest(complete, bundleFiles)).resolves.toMatch(/^sha256:/);
    const invalid = manifest({ configuration: { schema: "schemas/config.schema.json", defaults: { mode: "strict", temperature: 5 } } });
    await expect(computeExtensionContentDigest(invalid, bundleFiles)).rejects.toThrow(/defaults violate/i);
  });

  it("keeps original negation semantics when required properties are absent", async () => {
    const bundleFiles = files({ "schemas/config.schema.json": JSON.stringify({
      type: "object", not: { required: ["blocked"] }, properties: { safe: { type: "boolean" } }, additionalProperties: false,
    }) });
    const raw = manifest({ configuration: { schema: "schemas/config.schema.json", defaults: { safe: true } } });
    await expect(computeExtensionContentDigest(raw, bundleFiles)).resolves.toMatch(/^sha256:/);
    const allowedExtraFiles = files({ "schemas/config.schema.json": JSON.stringify({ type: "object", not: { required: ["blocked"] } }) });
    const invalid = manifest({ configuration: { schema: "schemas/config.schema.json", defaults: { blocked: true } } });
    await expect(computeExtensionContentDigest(invalid, allowedExtraFiles)).rejects.toThrow(/defaults violate/i);
  });
});
