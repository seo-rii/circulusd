import { Buffer } from "node:buffer";
import { build } from "esbuild";
import { digestBytes, digestStructuredValue, encodeCanonicalCbor, type AgentCheckpoint, type Digest, type NormalizedValue } from "@circulusd/protocol-types";
import { beforeAll, describe, expect, it, vi } from "vitest";

import { SessionHost, type AgentEvent } from "../../session-host/src/index.ts";
import {
  CELLD_EXECUTION_COMMIT, CelldPiExecutionEngine, PI_EXECUTION_CORE_MODULE, PI_EXECUTION_ENTRY_MODULE, PI_EXECUTION_ENTRY_SOURCE,
  piExecutionRuntimeArtifactDigest, type CelldExecutionLoader, type CelldExecutionWorker,
  type CelldExecutionWorkerDefinition, type PiExecutionRuntimeDefinition, type PiExecutionRuntimeVerifier,
} from "../src/celld-execution.ts";
import type { PiExecutionEnvironment } from "../src/execution-environment.ts";
import type { PiExecutionRequest } from "../src/execution-rpc.ts";
import { EXECUTION_MAPPING_DOMAIN, SignedPiExecutionRuntimeVerifier } from "../src/execution-runtime-mapping.ts";
import { GENESIS_MAPPING_DOMAIN, SignedPiGenesisRuntimeVerifier } from "../src/genesis-runtime-mapping.ts";
import { PiGenesisGenerator } from "../src/genesis.ts";
import { decodePiAgentCoreModelContext } from "../src/index.ts";
import { decodePiJson } from "../src/pi-json-codec.ts";
import { CONFIGURATION, environment, request, REVISION, SCOPE } from "./genesis-fixtures.ts";

let bundledCore: Uint8Array;
beforeAll(async () => {
  const result = await build({ entryPoints: [new URL("../src/execution-entrypoint.ts", import.meta.url).pathname],
    bundle: true, platform: "browser", format: "esm", target: "es2022", write: false,
    external: ["cloudflare:sockets"], logLevel: "silent" });
  bundledCore = result.outputFiles[0]!.contents;
});
async function runtime(): Promise<PiExecutionRuntimeDefinition> {
  const entry = new TextEncoder().encode(PI_EXECUTION_ENTRY_SOURCE), core = new Uint8Array(bundledCore);
  return { runtimeRevisionDigest: REVISION, adapterAbiVersion: 2, checkpointSchemaVersion: 2,
    mainModule: PI_EXECUTION_ENTRY_MODULE, compatibilityDate: "2026-08-25", compatibilityFlags: [],
    configuration: structuredClone(CONFIGURATION), modules: [
      { specifier: PI_EXECUTION_ENTRY_MODULE, bytes: entry, digest: await digestBytes(entry) },
      { specifier: PI_EXECUTION_CORE_MODULE, bytes: core, digest: await digestBytes(core) },
    ] };
}
async function signed(definition: PiExecutionRuntimeDefinition, purpose: "execution" | "genesis" = "execution") {
  const artifactDigest = await piExecutionRuntimeArtifactDigest(definition);
  const key = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const claims = { schemaVersion: 1, celldCommit: CELLD_EXECUTION_COMMIT, adapterAbiVersion: 2,
    checkpointSchemaVersion: 2, runtimeRevisionDigest: REVISION, artifactDigest, keyId: "test-execution-root" };
  const expectedMappingDigest = await digestStructuredValue(purpose === "execution" ? EXECUTION_MAPPING_DOMAIN : GENESIS_MAPPING_DOMAIN, 1, claims);
  const signature = new Uint8Array(await crypto.subtle.sign("Ed25519", key.privateKey, new TextEncoder().encode(expectedMappingDigest)));
  const config = { document: encodeCanonicalCbor({ claims, algorithm: "ed25519", signature }), expectedMappingDigest,
    trustRoots: [{ keyId: claims.keyId, publicKey: new Uint8Array(await crypto.subtle.exportKey("raw", key.publicKey)) }] };
  // Ephemeral local test signing only: no production mapping/root is created.
  return purpose === "execution" ? SignedPiExecutionRuntimeVerifier.create(config) : SignedPiGenesisRuntimeVerifier.create(config);
}
function dataModule(source: string) { return `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`; }
function fixture() {
  const names: string[] = [], definitions: CelldExecutionWorkerDefinition[] = [], requests: PiExecutionRequest[] = [];
  const propertyPaths: string[][] = [], releases: ReturnType<typeof vi.fn>[] = [];
  const loader: CelldExecutionLoader = { get(name, getCode) {
    names.push(name);
    // Like pinned celld, get() returns a stub before asynchronous compilation.
    const loaded = Promise.resolve().then(async () => {
      const definition = await getCode(); definitions.push(definition);
      const base = dataModule("export class WorkerEntrypoint { constructor(ctx, env) { this.ctx=ctx; this.env=env; } }");
      const core = dataModule(definition.modules[PI_EXECUTION_CORE_MODULE]!);
      const entry = definition.modules[PI_EXECUTION_ENTRY_MODULE]!
        .replace('"cloudflare:workers"', JSON.stringify(base)).replace(JSON.stringify(PI_EXECUTION_CORE_MODULE), JSON.stringify(core));
      const module = await import(/* @vite-ignore */ dataModule(entry)) as { default: new (ctx: object, env: PiExecutionEnvironment) => {
        exchange(value: PiExecutionRequest): Promise<unknown>;
      } };
      return new module.default({ waitUntil() { throw new Error("cross-pull waitUntil would deadlock native RPC"); } }, definition.env);
    });
    void loaded.catch(() => undefined);
    let disposed = false;
    const release = vi.fn(() => { disposed = true; }); releases.push(release);
    const method = (path: string[]): unknown => new Proxy(() => undefined, {
      get(_target, property) { const next = [...path, String(property)]; propertyPaths.push(next); return method(next); },
      apply(_target, _receiver, args) {
        if (path.length !== 1 || path[0] !== "exchange") throw new Error("native Loader accepts one RPC path component");
        if (disposed) throw new Error("owned stub already released");
        const value = structuredClone(args[0]) as PiExecutionRequest; requests.push(value);
        // Already captured in-flight native state may survive disposal.
        return loaded.then((instance) => instance.exchange(value)).then((reply) => structuredClone(reply));
      },
    });
    return { getEntrypoint: () => ({ exchange: method(["exchange"]) }), dispose: release };
  } };
  return { loader, names, definitions, requests, propertyPaths, releases };
}
function host() {
  const capability = { forbidden() { throw new Error("host capability must not cross Loader"); } };
  return new SessionHost({ loader: { async get() { throw new Error("stock Loader must not be used"); } },
    verifier: { async verify() { throw new Error("no native qualification supplied"); } }, bindings: {
      STATE: capability, WORKSPACE: capability, MODEL: capability, MCP: capability,
      EXECUTOR: capability, ARTIFACTS: capability, EVENTS: capability,
    } });
}
async function checkpoint() { return (await (await PiGenesisGenerator.create(await environment())).createGenesis(await request())).checkpoint; }
function context(value: AgentCheckpoint, executionId = "execution-celld-test") {
  return { turnId: value.turnId, executionId, authority: new Uint8Array([1, 2, 3]), checkpoint: value };
}
function options(value: AgentCheckpoint) {
  return { turnId: value.turnId, authority: new Uint8Array([1, 2, 3]), checkpoint: value,
    maximumEvents: 256, ephemeralSink: { async emit() {} }, committer: { async commit() {} } };
}
function effect(event: AgentEvent) {
  if (event.type !== "model_request" && event.type !== "tool_request") throw new Error("expected effect boundary");
  return { checkpoint: event.checkpoint as AgentCheckpoint, request: event.request as {
    service: string; requestDigest: Digest; payload: { toolCall?: { arguments: NormalizedValue }; context?: NormalizedValue };
  } };
}
function settlement(digest: Digest, result: unknown) { return { requestDigest: digest, outcome: { kind: "success", result } }; }
function message(tool: boolean) {
  return { role: "assistant", api: CONFIGURATION.model.api, provider: CONFIGURATION.model.provider, model: CONFIGURATION.model.id,
    content: tool ? [{ type: "text", text: "echo" }, { type: "toolCall", id: "loader-echo", name: "echo", arguments: { value: 1.25 } }] : [{ type: "text", text: "done" }],
    usage: { input: 1, output: 1, cacheRead: 0, cacheWrite: 0, totalTokens: 2,
      cost: { input: 0.000001, output: 0.000001, cacheRead: 0, cacheWrite: 0, total: 0.000002 } },
    stopReason: tool ? "toolUse" : "stop", timestamp: 1_700_000_000_001 };
}
const trusted: PiExecutionRuntimeVerifier = { async verify(binding) { return { ...binding, mappingDomain: EXECUTION_MAPPING_DOMAIN }; } };

describe("signed execution artifact through pinned celld Loader ABI", () => {
  it("runs actual Pi cold model → fractional tool → model → complete through native-shaped callable RPC", async () => {
    const definition = await runtime(), verifier = await signed(definition) as SignedPiExecutionRuntimeVerifier, f = fixture();
    const first = await CelldPiExecutionEngine.create({ loader: f.loader, verifier, scope: SCOPE, runtime: definition });
    const model = effect((await host().startTurn(first, options(await checkpoint()))).boundary); first.dispose();
    const second = await CelldPiExecutionEngine.create({ loader: f.loader, verifier, scope: SCOPE, runtime: definition });
    const tool = effect((await host().resumeTurn(second, { ...options(model.checkpoint),
      settlement: settlement(model.request.requestDigest, { version: 1, message: message(true) }) })).boundary);
    expect(tool.request.service).toBe("external-tool");
    expect(decodePiJson(tool.request.payload.toolCall!.arguments)).toEqual({ value: 1.25 }); second.dispose();
    const third = await CelldPiExecutionEngine.create({ loader: f.loader, verifier, scope: SCOPE, runtime: definition });
    const nextModel = effect((await host().resumeTurn(third, { ...options(tool.checkpoint), settlement: settlement(tool.request.requestDigest, {
      version: 1, toolCallId: "loader-echo", toolName: "echo", content: [{ type: "text", text: "1.25" }], isError: false, timestamp: 1_700_000_000_002,
    }) })).boundary);
    const transcript = decodePiAgentCoreModelContext(nextModel.request.payload.context!);
    expect(transcript.messages).toHaveLength(4); expect(transcript.messages[2]).toMatchObject({ content: message(true).content }); third.dispose();
    const fourth = await CelldPiExecutionEngine.create({ loader: f.loader, verifier, scope: SCOPE, runtime: definition });
    expect((await host().resumeTurn(fourth, { ...options(nextModel.checkpoint),
      settlement: settlement(nextModel.request.requestDigest, { version: 1, message: message(false) }) })).boundary.type).toBe("turn_complete"); fourth.dispose();
    expect(new Set(f.names).size).toBe(4);
    expect(f.names.every((name) => /^pi-execution\/sha256:[0-9a-f]{64}\/[0-9a-f-]{36}$/.test(name))).toBe(true);
    expect(f.propertyPaths).toEqual([]);
    expect(f.releases.every((release) => release.mock.calls.length === 1)).toBe(true);
    for (const loaded of f.definitions) {
      expect(loaded.globalOutbound).toBe(null); expect(loaded.mainModule).toBe(PI_EXECUTION_ENTRY_MODULE);
      expect(JSON.parse(JSON.stringify(loaded.env))).toEqual(loaded.env);
      expect(Object.hasOwn(loaded.env, "authority") || Object.hasOwn(loaded.env, "MODEL")).toBe(false);
    }
    expect(f.requests.filter((value) => value.operation === "resume")[0]).toMatchObject({ authority: new Uint8Array([1, 2, 3]),
      settlement: { outcome: { result: { message: { usage: { cost: { total: 0.000002 } } } } } } });
  });
  it("rejects an independently valid genesis-purpose verifier for the same execution artifact before Loader", async () => {
    const definition = await runtime(), verifier = await signed(definition, "genesis"), f = fixture();
    await expect(CelldPiExecutionEngine.create({ loader: f.loader, verifier: verifier as PiExecutionRuntimeVerifier,
      scope: SCOPE, runtime: definition })).rejects.toMatchObject({ code: "INVALID_CONFIGURATION" });
    expect(f.names).toEqual([]);
  });
  it("owns modules/configuration/flags in the same turn before its first async wait", async () => {
    const definition = await runtime(), verifier = await signed(definition) as SignedPiExecutionRuntimeVerifier, f = fixture();
    const pending = CelldPiExecutionEngine.create({ loader: f.loader, verifier, scope: SCOPE, runtime: definition });
    definition.modules[1]!.bytes.fill(0);
    (definition.configuration as { systemPrompt: string }).systemPrompt = "changed in the same turn";
    (definition.compatibilityFlags as string[]).push("nodejs_compat");
    const engine = await pending;
    expect(effect((await host().startTurn(engine, options(await checkpoint()))).boundary).request.service).toBe("model");
    expect(f.definitions[0]?.compatibilityFlags).toEqual([]);
    expect(f.definitions[0]?.env.configuration).toMatchObject({ systemPrompt: CONFIGURATION.systemPrompt }); engine.dispose();
  });
  it("captures verifier and Loader methods once before asynchronous caller mutation", async () => {
    const definition = await runtime(), f = fixture(), verifier = { ...trusted }, original = f.loader.get;
    const pending = CelldPiExecutionEngine.create({ loader: f.loader, verifier, scope: SCOPE, runtime: definition });
    verifier.verify = async () => { throw new Error("mutated verifier"); };
    f.loader.get = () => { throw new Error("mutated loader"); };
    const engine = await pending;
    expect(f.names).toHaveLength(1); expect(f.loader.get).not.toBe(original); engine.dispose();
  });
  it("binds flags, date, module bytes and configuration to the independently signed artifact", async () => {
    const definition = await runtime(), verifier = await signed(definition) as SignedPiExecutionRuntimeVerifier, f = fixture();
    const changedModule = new TextEncoder().encode(new TextDecoder().decode(definition.modules[1]!.bytes) + "\n// changed\n");
    for (const changed of [{ ...definition, compatibilityDate: "2026-08-26" }, { ...definition, compatibilityFlags: ["js_rpc"] },
      { ...definition, configuration: { ...definition.configuration, systemPrompt: "changed config" } },
      { ...definition, modules: [definition.modules[0]!, { ...definition.modules[1]!, bytes: changedModule, digest: await digestBytes(changedModule) }] }]) {
      await expect(CelldPiExecutionEngine.create({ loader: f.loader, verifier, scope: SCOPE, runtime: changed })).rejects.toThrow("invalid or unverified");
    }
    expect(f.names).toEqual([]);
  });
  it("rejects malformed runtimes and altered fixed wrappers before verifier or Loader", async () => {
    const definition = await runtime(), f = fixture(), verify = vi.fn(trusted.verify), verifier = { verify };
    const wrapper = new TextEncoder().encode(PI_EXECUTION_ENTRY_SOURCE + "\n");
    for (const changed of [{ ...definition, adapterAbiVersion: 1 }, { ...definition, checkpointSchemaVersion: 1 },
      { ...definition, compatibilityDate: "2026-02-30" }, { ...definition, compatibilityFlags: ["js_rpc", "js_rpc"] },
      { ...definition, mainModule: "circulusd/pi-genesis-entry.mjs" }, { ...definition, modules: [...definition.modules, definition.modules[0]!] },
      { ...definition, modules: [{ ...definition.modules[0]!, bytes: wrapper, digest: await digestBytes(wrapper) }, definition.modules[1]!] },
      { ...definition, modules: definition.modules.map((module) => ({ ...module, digest: `sha256:${"0".repeat(64)}` })) }]) {
      await expect(CelldPiExecutionEngine.create({ loader: f.loader, verifier, scope: SCOPE,
        runtime: changed as PiExecutionRuntimeDefinition })).rejects.toThrow();
    }
    expect(verify).not.toHaveBeenCalled(); expect(f.names).toEqual([]);
  });
  it("reads module bytes through intrinsics without invoking caller getters or iterators", async () => {
    const definition = await runtime(), f = fixture(), blocked = () => { throw new Error("caller accessor invoked"); };
    Object.defineProperty(definition.modules[1]!.bytes, "buffer", { get: blocked });
    Object.defineProperty(definition.modules[1]!.bytes, "byteLength", { get: blocked });
    Object.defineProperty(definition.modules[1]!.bytes, Symbol.iterator, { get: blocked });
    const engine = await CelldPiExecutionEngine.create({ loader: f.loader, verifier: trusted, scope: SCOPE, runtime: definition }); engine.dispose();
  });
  it("bounds binary module allocation and rejects invalid UTF-8", async () => {
    const definition = await runtime();
    for (const bytes of [new Uint8Array(8 * 1_048_576 + 1), new Uint8Array([0xff])]) {
      await expect(piExecutionRuntimeArtifactDigest({ ...definition, modules: [definition.modules[0]!, {
        specifier: PI_EXECUTION_CORE_MODULE, bytes, digest: await digestBytes(bytes),
      }] })).rejects.toThrow("invalid or unverified");
    }
  });
  it("cannot bypass verified composition by direct JavaScript construction", () => {
    expect(() => Reflect.construct(CelldPiExecutionEngine, [Symbol("fake"), {}, () => undefined, new AbortController()])).toThrow("invalid or unverified");
  });
});

describe("owned Loader composition lifetime", () => {
  it("observes late rejection when Loader synchronously cancels factory acquisition", async () => {
    const controller = new AbortController(), release = vi.fn(), entry = vi.fn(() => ({}));
    const loader: CelldExecutionLoader = { get() {
      controller.abort("cancel during native stub acquisition");
      return { getEntrypoint: entry, dispose: release };
    } };
    await expect(CelldPiExecutionEngine.create({ loader, verifier: trusted, scope: SCOPE, runtime: await runtime() }, controller.signal))
      .rejects.toMatchObject({ name: "AbortError" });
    await vi.waitFor(() => expect(release).toHaveBeenCalledTimes(1));
    // Give the runtime an event-loop turn to report any unhandled late reject.
    // Vitest fails this gate on such a rejection even if the assertion passed.
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    expect(entry).not.toHaveBeenCalled();
  });
  it.each(["cancel", "timeout"] as const)("discards and releases a late Loader stub after factory %s", async (kind) => {
    const definition = await runtime(), arrived = Promise.withResolvers<CelldExecutionWorker>(), entered = Promise.withResolvers<void>();
    const release = vi.fn(), entry = vi.fn(() => ({ exchange: vi.fn() })), controller = new AbortController();
    const loader: CelldExecutionLoader = { get() { entered.resolve(); return arrived.promise; } };
    const pending = CelldPiExecutionEngine.create({ loader, verifier: trusted, scope: SCOPE, runtime: definition, timeoutMs: 100 }, controller.signal);
    const failed = expect(pending).rejects.toMatchObject(kind === "cancel" ? { name: "AbortError" } : { code: "ENGINE_POISONED" });
    await entered.promise; if (kind === "cancel") controller.abort("private caller reason");
    await failed; arrived.resolve({ getEntrypoint: entry, dispose: release });
    await vi.waitFor(() => expect(release).toHaveBeenCalledTimes(1)); expect(entry).not.toHaveBeenCalled();
  });
  it("rejects a pre-canceled factory without Loader or verifier I/O", async () => {
    const controller = new AbortController(); controller.abort("private reason");
    const f = fixture(), verify = vi.fn(trusted.verify);
    await expect(CelldPiExecutionEngine.create({ loader: f.loader, verifier: { verify }, scope: SCOPE, runtime: await runtime() }, controller.signal))
      .rejects.toMatchObject({ name: "AbortError" });
    expect(verify).not.toHaveBeenCalled(); expect(f.names).toEqual([]);
  });
  it("bounds a noncooperative mapping verifier before native Loader acquisition", async () => {
    const f = fixture();
    await expect(CelldPiExecutionEngine.create({ loader: f.loader, verifier: { verify: () => new Promise(() => {}) },
      scope: SCOPE, runtime: await runtime(), timeoutMs: 100 })).rejects.toThrow("invalid or unverified");
    expect(f.names).toEqual([]);
  });
  it("acquires a synchronous native stub before compile/init; first exchange stays bounded", async () => {
    const remote = vi.fn(() => new Promise(() => {})), release = vi.fn();
    const engine = await CelldPiExecutionEngine.create({ loader: { get: () => ({ getEntrypoint: () => ({ exchange: remote }), dispose: release }) },
      verifier: trusted, scope: SCOPE, runtime: await runtime(), timeoutMs: 100 });
    expect(remote).not.toHaveBeenCalled();
    await expect(engine.startTurn(context(await checkpoint()))[Symbol.asyncIterator]().next()).rejects.toMatchObject({ code: "ENGINE_POISONED" });
    engine.dispose(); expect(release).toHaveBeenCalledTimes(1);
  });
  it("factory cancellation after publication does not cancel the separate engine lifetime", async () => {
    const f = fixture(), controller = new AbortController();
    const engine = await CelldPiExecutionEngine.create({ loader: f.loader, verifier: trusted, scope: SCOPE, runtime: await runtime() }, controller.signal);
    controller.abort("factory is already published");
    expect((await host().startTurn(engine, options(await checkpoint()))).boundary.type).toBe("model_request"); engine.dispose();
  });
  it("disposal rejects existing lazy iterators without RPC and releases the stub once", async () => {
    const f = fixture(), engine = await CelldPiExecutionEngine.create({ loader: f.loader, verifier: trusted, scope: SCOPE, runtime: await runtime() });
    const iterator = engine.startTurn(context(await checkpoint()))[Symbol.asyncIterator](); engine.dispose(); engine.dispose();
    await expect(iterator.next()).rejects.toMatchObject({ code: "ENGINE_POISONED" });
    expect(f.requests).toEqual([]); expect(f.releases[0]).toHaveBeenCalledTimes(1);
    expect(() => engine.startTurn(context({} as AgentCheckpoint))).toThrow("invalid or unavailable");
  });
  it("disposal interrupts a current local RPC wait and discards its late native reply", async () => {
    const arrived = Promise.withResolvers<unknown>(), entered = Promise.withResolvers<void>(), release = vi.fn();
    const remote = vi.fn(() => { entered.resolve(); return arrived.promise; });
    const engine = await CelldPiExecutionEngine.create({ loader: { get: () => ({ getEntrypoint: () => ({ exchange: remote }), dispose: release }) },
      verifier: trusted, scope: SCOPE, runtime: await runtime() });
    const iterator = engine.startTurn(context(await checkpoint()))[Symbol.asyncIterator](), next = iterator.next();
    const failed = expect(next).rejects.toMatchObject({ code: "ENGINE_POISONED" });
    await entered.promise; engine.dispose(); await failed;
    arrived.resolve({ late: true }); await Promise.resolve(); await Promise.resolve();
    expect(remote).toHaveBeenCalledTimes(1); expect(release).toHaveBeenCalledTimes(1);
    await expect(iterator.next()).rejects.toMatchObject({ code: "ENGINE_POISONED" });
  });
  it("releases an owned malformed native entrypoint before rejecting factory publication", async () => {
    const release = vi.fn();
    await expect(CelldPiExecutionEngine.create({ loader: { get: () => ({ getEntrypoint: () => ({}), dispose: release }) },
      verifier: trusted, scope: SCOPE, runtime: await runtime() })).rejects.toMatchObject({ code: "ENGINE_POISONED" });
    expect(release).toHaveBeenCalledTimes(1);
  });
});
