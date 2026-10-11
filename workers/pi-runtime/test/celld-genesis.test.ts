import { Buffer } from "node:buffer";
import { build } from "esbuild";
import { digestBytes } from "@circulusd/protocol-types";
import { beforeAll, describe, expect, it, vi } from "vitest";

import {
  CELLD_GENESIS_COMMIT, CelldPiGenesisSource, PI_GENESIS_CORE_MODULE, PI_GENESIS_ENTRY_MODULE, PI_GENESIS_ENTRY_SOURCE,
  type CelldGenesisLoader, type CelldGenesisWorkerDefinition, type PiGenesisRuntimeDefinition, type PiGenesisRuntimeVerifier,
} from "../src/celld-genesis.ts";
import type { PiGenesisEnvironment, PiGenesisRequest } from "../src/genesis.ts";
import { CONFIGURATION, REVISION, SCOPE, request, assertColdFirstBoundary } from "./genesis-fixtures.ts";

let coreBundle: Uint8Array;
beforeAll(async () => {
  const built = await build({ entryPoints: [new URL("../src/genesis-entrypoint.ts", import.meta.url).pathname],
    bundle: true, platform: "browser", format: "esm", target: "es2022", write: false, external: ["cloudflare:sockets"], logLevel: "silent" });
  coreBundle = built.outputFiles[0]!.contents;
});

async function runtime(): Promise<PiGenesisRuntimeDefinition> {
  const main = new TextEncoder().encode(PI_GENESIS_ENTRY_SOURCE);
  return { runtimeRevisionDigest: REVISION, adapterAbiVersion: 2, checkpointSchemaVersion: 2,
    compatibilityDate: "2026-08-01", compatibilityFlags: ["js_rpc"], mainModule: PI_GENESIS_ENTRY_MODULE,
    modules: [
      { specifier: PI_GENESIS_ENTRY_MODULE, bytes: main, digest: await digestBytes(main) },
      { specifier: PI_GENESIS_CORE_MODULE, bytes: new Uint8Array(coreBundle), digest: await digestBytes(coreBundle) },
    ], configuration: structuredClone(CONFIGURATION) };
}

// The verifier is a contract-test fixture. It exercises the signed-map port and
// intentionally supplies no native runtime proof or production eligibility.
function verifier(): PiGenesisRuntimeVerifier & { calls: number; artifact?: string } {
  return { calls: 0, async verify(binding) { this.calls += 1; this.artifact = binding.artifactDigest; return { ...binding }; } };
}

function dataModule(source: string): string {
  return `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`;
}

// Execute the actual esbuild Pi generator module and its deployment wrapper.
// Only the native WorkerEntrypoint base and Loader transport are test fixtures;
// the checkpoint bytes come from the actual bundled Pi implementation.
function loaderFixture() {
  const definitions: CelldGenesisWorkerDefinition[] = [];
  const names: string[] = [];
  const inputs: PiGenesisRequest[] = [];
  const loader: CelldGenesisLoader = {
    async get(name, getCode) {
      names.push(name);
      const definition = await getCode();
      definitions.push(definition);
      const nativeBase = dataModule("export class WorkerEntrypoint { constructor(context, env) { this.ctx = context; this.env = env; } }");
      const core = dataModule(definition.modules[PI_GENESIS_CORE_MODULE]!);
      const wrapped = definition.modules[PI_GENESIS_ENTRY_MODULE]!
        .replace('"cloudflare:workers"', JSON.stringify(nativeBase))
        .replace(JSON.stringify(PI_GENESIS_CORE_MODULE), JSON.stringify(core));
      const module = await import(/* @vite-ignore */ dataModule(wrapped)) as {
        default: new (context: object, env: PiGenesisEnvironment) => { createGenesis(value: PiGenesisRequest): Promise<unknown> };
      };
      const instance = new module.default({}, definition.env);
      return { getEntrypoint: () => ({ async createGenesis(value) { inputs.push(value); return instance.createGenesis(value); } }) };
    },
  };
  return { loader, definitions, names, inputs };
}

describe("pinned celld actual Pi genesis Loader adapter", () => {
  it("loads real generator bytes through the pinned string-map/single-RPC ABI and cold reconstructs", async () => {
    const fixture = loaderFixture();
    const trusted = verifier();
    const definition = await runtime();
    const source = await CelldPiGenesisSource.create({ loader: fixture.loader, verifier: trusted, scope: SCOPE, runtime: definition });
    const input = await request();
    const result = await source.createGenesis(input);
    expect(trusted.calls).toBe(1);
    expect(CELLD_GENESIS_COMMIT).toBe("89e4ffc53a14ecb496d2ca5014ff9d19b0061ad9");
    expect(fixture.definitions).toHaveLength(1);
    const loaded = fixture.definitions[0]!;
    expect(loaded).toMatchObject({ mainModule: PI_GENESIS_ENTRY_MODULE, globalOutbound: null,
      env: { scope: SCOPE, runtimeRevisionDigest: REVISION, artifactDigest: trusted.artifact } });
    expect(Array.isArray(loaded.modules)).toBe(false);
    expect(Object.values(loaded.modules).every((module) => typeof module === "string")).toBe(true);
    expect(JSON.parse(JSON.stringify(loaded.env))).toEqual(loaded.env);
    expect(fixture.inputs).toEqual([input]);
    await assertColdFirstBoundary(result.checkpoint);
    expect(await source.createGenesis(input)).toEqual(result);
    expect(fixture.names[1]).toBe(fixture.names[0]);
    expect("ProbeProduction" in source).toBe(false);
  });

  it("rejects corrupt modules, unsupported ABI/schema/config and unverified mapping before load", async () => {
    const fixture = loaderFixture();
    for (const mutate of [
      (r: PiGenesisRuntimeDefinition) => ({ ...r, adapterAbiVersion: 1 }),
      (r: PiGenesisRuntimeDefinition) => ({ ...r, checkpointSchemaVersion: 1 }),
      (r: PiGenesisRuntimeDefinition) => ({ ...r, compatibilityDate: "2026-02-30" }),
      (r: PiGenesisRuntimeDefinition) => ({ ...r, modules: r.modules.map((module) => ({ ...module, digest: `sha256:${"0".repeat(64)}` })) }),
      (r: PiGenesisRuntimeDefinition) => ({ ...r, modules: [...r.modules, r.modules[0]!] }),
      (r: PiGenesisRuntimeDefinition) => ({ ...r, configuration: { ...r.configuration, systemPrompt: "x".repeat(262_145) } }),
      (r: PiGenesisRuntimeDefinition) => ({ ...r, configuration: { ...r.configuration, model: { ...r.configuration.model, maxTokens: 4097 } } }),
    ]) {
      const trusted = verifier();
      await expect(CelldPiGenesisSource.create({ loader: fixture.loader, verifier: trusted, scope: SCOPE,
        runtime: mutate(await runtime()) as PiGenesisRuntimeDefinition })).rejects.toThrow();
      expect(trusted.calls).toBe(0);
    }
    for (const trusted of [
      { async verify(binding: { runtimeRevisionDigest: string; artifactDigest: string }) { return { ...binding, artifactDigest: `sha256:${"0".repeat(64)}` }; } },
      { async verify(binding: { runtimeRevisionDigest: string; artifactDigest: string }) { return { ...binding, runtimeRevisionDigest: `sha256:${"0".repeat(64)}` }; } },
      { async verify() { throw new Error("private signing key diagnostic"); } },
    ]) await expect(CelldPiGenesisSource.create({ loader: fixture.loader, verifier: trusted as PiGenesisRuntimeVerifier,
      scope: SCOPE, runtime: await runtime() })).rejects.toThrow("invalid or unverified");
    expect(fixture.names).toHaveLength(0);
  });

  it("binds every module and full configuration to the trusted artifact mapping", async () => {
    const fixture = loaderFixture();
    const trusted = verifier();
    const original = await runtime();
    await CelldPiGenesisSource.create({ loader: fixture.loader, verifier: trusted, scope: SCOPE, runtime: original });
    const pinned = trusted.artifact;
    const checking: PiGenesisRuntimeVerifier = { async verify(binding) {
      if (binding.artifactDigest !== pinned) throw new Error("not the pinned signed artifact");
      return binding;
    } };
    for (const changed of [
      { ...original, configuration: { ...original.configuration, systemPrompt: "altered trusted configuration" } },
      { ...original, compatibilityFlags: ["js_rpc", "nodejs_compat"] },
      { ...original, modules: await Promise.all(original.modules.map(async (module) => {
        if (module.specifier !== PI_GENESIS_CORE_MODULE) return module;
        const bytes = new TextEncoder().encode(new TextDecoder().decode(module.bytes) + "\n// changed artifact\n");
        return { ...module, bytes, digest: await digestBytes(bytes) };
      })) },
    ]) await expect(CelldPiGenesisSource.create({ loader: fixture.loader, verifier: checking, scope: SCOPE, runtime: changed })).rejects.toThrow();
    expect(fixture.names).toHaveLength(0);
  });

  it("rejects malformed or different request scope/runtime/input before loader or generation", async () => {
    const fixture = loaderFixture();
    const source = await CelldPiGenesisSource.create({ loader: fixture.loader, verifier: verifier(), scope: SCOPE, runtime: await runtime() });
    const valid = await request();
    for (const input of [
      { ...valid, tenantId: `tenant_${"B".repeat(25)}A` },
      { ...valid, workspaceId: `ws_${"B".repeat(25)}A` },
      { ...valid, actorSubjectId: `subject_${"B".repeat(25)}A` },
      { ...valid, sessionId: `sess_${"B".repeat(25)}A` },
      { ...valid, runtime: { ...valid.runtime, runtimeRevisionDigest: `sha256:${"0".repeat(64)}` } },
      { ...valid, runtime: { ...valid.runtime, adapterAbiVersion: 1 } },
      { ...valid, input: { messages: [{ role: "user", content: "other full input" }] } },
      { ...valid, input: { messages: [{ role: "user", content: "x".repeat(1_048_577) }] } },
    ]) await expect(source.createGenesis(input as PiGenesisRequest)).rejects.toThrow();
    expect(fixture.names).toHaveLength(0);
    expect(fixture.inputs).toHaveLength(0);
    const controller = new AbortController(); controller.abort("private cancellation reason");
    await expect(source.createGenesis(valid, controller.signal)).rejects.toMatchObject({ name: "AbortError" });
    expect(fixture.names).toHaveLength(0);
  });

  it("owns trusted snapshots even if the verifier mutates caller modules/configuration", async () => {
    const fixture = loaderFixture();
    const definition = await runtime();
    const trusted: PiGenesisRuntimeVerifier = { async verify(binding) {
      definition.modules[1]!.bytes.fill(0);
      (definition.configuration as { systemPrompt: string }).systemPrompt = "mutated after snapshot";
      return binding;
    } };
    const source = await CelldPiGenesisSource.create({ loader: fixture.loader, verifier: trusted, scope: SCOPE, runtime: definition });
    await assertColdFirstBoundary((await source.createGenesis(await request())).checkpoint);
  });

  it("bounds caller cancellation while loader or remote RPC remains pending and removes listeners", async () => {
    for (const waitingAt of ["loader", "rpc"] as const) {
      let started!: () => void;
      const active = new Promise<void>((resolve) => { started = resolve; });
      const never = new Promise<never>(() => {});
      const loader: CelldGenesisLoader = { get() {
        if (waitingAt === "loader") { started(); return never; }
        return { getEntrypoint: () => ({ createGenesis() { started(); return never; } }) };
      } };
      const source = await CelldPiGenesisSource.create({ loader, verifier: verifier(), scope: SCOPE, runtime: await runtime() });
      const controller = new AbortController();
      const remove = vi.spyOn(controller.signal, "removeEventListener");
      const pending = source.createGenesis(await request(), controller.signal);
      await active;
      controller.abort("private remote cancellation reason");
      await expect(pending).rejects.toMatchObject({ name: "AbortError", message: "Pi genesis request canceled" });
      expect(remove).toHaveBeenCalledWith("abort", expect.any(Function));
    }
  });

  it("sanitizes native loader/RPC failures and rejects malformed returned checkpoints", async () => {
    for (const loader of [
      { get() { throw new Error("private loader credentials"); } },
      { get() { return { getEntrypoint: () => ({ async createGenesis() { throw new Error("private remote credential"); } }) }; } },
      { get() { return { getEntrypoint: () => ({ async createGenesis() { return { checkpoint: {} }; } }) }; } },
    ]) {
      const source = await CelldPiGenesisSource.create({ loader, verifier: verifier(), scope: SCOPE, runtime: await runtime() });
      await expect(source.createGenesis(await request())).rejects.toThrow("worker failed or returned an invalid checkpoint");
    }
  });
});
