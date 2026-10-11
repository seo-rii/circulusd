import { Buffer } from "node:buffer";
import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import { build } from "esbuild";
import {
  digestBytes, digestStructuredValue, encodeCanonicalCbor, encodeHex,
  type AgentCheckpoint, type Digest,
} from "@circulusd/protocol-types";
import { beforeAll, describe, expect, it } from "vitest";

import wireFixture from "../../../packages/protocol-types/fixtures/engine-genesis-v1alpha1.json";
import {
  CELLD_GENESIS_COMMIT, CelldPiGenesisSource, PI_GENESIS_CORE_MODULE, PI_GENESIS_ENTRY_MODULE, PI_GENESIS_ENTRY_SOURCE,
  piGenesisRuntimeArtifactDigest, type CelldGenesisLoader, type CelldGenesisWorkerDefinition,
  type PiGenesisRuntimeDefinition,
} from "../src/celld-genesis.ts";
import { SignedPiGenesisRuntimeVerifier } from "../src/genesis-runtime-mapping.ts";
import { createCelldPiGenesisWorker } from "../src/genesis-worker.ts";
import {
  GENESIS_PATH, GENESIS_TYPE, KEY_HEADER, MAXIMUM_REQUEST_BYTES, MAXIMUM_RESPONSE_BYTES,
  SIGNATURE_HEADER, decodeGenesisWire,
} from "../src/genesis-wire.ts";
import type { PiGenesisEnvironment, PiGenesisRequest } from "../src/genesis.ts";
import { LowLevelPiAgentEngine, createOpaqueTurnAuthority, createPiAgentCoreFactory } from "../src/index.ts";
import { CONFIGURATION, REVISION, SCOPE, assertColdFirstBoundary, request } from "./genesis-fixtures.ts";

const MAPPING_DOMAIN = "circulusd.pi.genesis-runtime-mapping";
const SIGNING_KEY_ID = "test-pi-genesis-mapping";
const EMPTY_DIGEST = `sha256:${"0".repeat(64)}` as const;
// Public deterministic TEST fixture seed. No signing key is part of production
// source composition, nor does a signed artifact mapping qualify native celld.
const privateKey = createPrivateKey({ key: Buffer.concat([
  Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.alloc(32, 42),
]), format: "der", type: "pkcs8" });
const publicKey = Uint8Array.from(createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(-32));
let coreBundle: Uint8Array;

beforeAll(async () => {
  const built = await build({ entryPoints: [new URL("../src/genesis-entrypoint.ts", import.meta.url).pathname],
    bundle: true, platform: "browser", format: "esm", target: "es2022", write: false,
    external: ["cloudflare:sockets"], logLevel: "silent" });
  coreBundle = Uint8Array.from(built.outputFiles[0]!.contents);
});

async function runtime(revision: Digest = REVISION): Promise<PiGenesisRuntimeDefinition> {
  const main = new TextEncoder().encode(PI_GENESIS_ENTRY_SOURCE), core = Uint8Array.from(coreBundle);
  return { runtimeRevisionDigest: revision, adapterAbiVersion: 2, checkpointSchemaVersion: 2,
    compatibilityDate: "2026-08-01", compatibilityFlags: ["js_rpc"], mainModule: PI_GENESIS_ENTRY_MODULE,
    modules: [{ specifier: PI_GENESIS_ENTRY_MODULE, bytes: main, digest: await digestBytes(main) },
      { specifier: PI_GENESIS_CORE_MODULE, bytes: core, digest: await digestBytes(core) }],
    configuration: structuredClone(CONFIGURATION) };
}

async function signedMapping(definition: PiGenesisRuntimeDefinition, artifactDigest?: Digest) {
  const claims = { schemaVersion: 1, celldCommit: CELLD_GENESIS_COMMIT, adapterAbiVersion: 2,
    checkpointSchemaVersion: 2, runtimeRevisionDigest: definition.runtimeRevisionDigest,
    artifactDigest: artifactDigest ?? await piGenesisRuntimeArtifactDigest(definition), keyId: SIGNING_KEY_ID };
  const expectedMappingDigest = await digestStructuredValue(MAPPING_DOMAIN, 1, claims);
  const signature = Uint8Array.from(sign(null, Buffer.from(expectedMappingDigest, "ascii"), privateKey));
  const document = encodeCanonicalCbor({ claims, algorithm: "ed25519", signature }, { maxBytes: 4096, maxDepth: 16, maxItems: 64 });
  return { config: { document, expectedMappingDigest,
    trustRoots: [{ keyId: SIGNING_KEY_ID, publicKey: Uint8Array.from(publicKey) }] }, claims, signature };
}

function dataModule(source: string): string { return `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`; }
function fromHex(value: string): Uint8Array<ArrayBuffer> { return Uint8Array.from(Buffer.from(value, "hex")); }

// Only the native WorkerEntrypoint base and Loader transport are fixtures. The
// checkpoint comes from the actual bundled Pi generator and deployment wrapper.
function loaderFixture() {
  const definitions: CelldGenesisWorkerDefinition[] = [], inputs: PiGenesisRequest[] = [];
  const loader: CelldGenesisLoader = { async get(_name, getCode) {
    const definition = await getCode(); definitions.push(definition);
    const base = dataModule("export class WorkerEntrypoint { constructor(context, env) { this.ctx = context; this.env = env; } }");
    const core = dataModule(definition.modules[PI_GENESIS_CORE_MODULE]!);
    const wrapped = definition.modules[PI_GENESIS_ENTRY_MODULE]!
      .replace('"cloudflare:workers"', JSON.stringify(base))
      .replace(JSON.stringify(PI_GENESIS_CORE_MODULE), JSON.stringify(core));
    const module = await import(/* @vite-ignore */ dataModule(wrapped)) as {
      default: new (context: object, env: PiGenesisEnvironment) => { createGenesis(value: PiGenesisRequest): Promise<unknown> };
    };
    const instance = new module.default({}, definition.env);
    return { getEntrypoint: () => ({ async createGenesis(value) { inputs.push(value); return instance.createGenesis(value); } }) };
  } };
  return { loader, definitions, inputs };
}

describe("signed immutable Pi genesis runtime mapping composition", () => {
  it("shares the exact source artifact digest while owning inputs before asynchronous hashing", async () => {
    const definition = await runtime(), expected = await piGenesisRuntimeArtifactDigest(definition);
    const pending = piGenesisRuntimeArtifactDigest(definition);
    definition.modules[1]!.bytes.fill(0);
    (definition.configuration as { systemPrompt: string }).systemPrompt = "mutated while hashing";
    expect(await pending).toBe(expected);

    const fixture = loaderFixture();
    let observed: Digest | undefined;
    await CelldPiGenesisSource.create({ loader: fixture.loader, scope: SCOPE, runtime: await runtime(),
      verifier: { async verify(binding) { observed = binding.artifactDigest; return { ...binding }; } } });
    expect(observed).toBe(expected); expect(fixture.definitions).toHaveLength(0);
  });

  it("applies the existing bounded runtime validation to pure artifact computation", async () => {
    const definition = await runtime();
    for (const value of [
      { ...definition, adapterAbiVersion: 1 },
      { ...definition, checkpointSchemaVersion: 1 },
      { ...definition, compatibilityDate: "2026-02-30" },
      { ...definition, compatibilityFlags: ["js_rpc", "js_rpc"] },
      { ...definition, modules: [...definition.modules, definition.modules[0]!] },
      { ...definition, modules: definition.modules.map((module) => ({ ...module, digest: EMPTY_DIGEST })) },
      { ...definition, modules: [{ ...definition.modules[0]!, bytes: new Uint8Array(8 * 1_048_576 + 1) }, definition.modules[1]!] },
      { ...definition, configuration: { ...definition.configuration, systemPrompt: "x".repeat(262_145) } },
    ]) await expect(piGenesisRuntimeArtifactDigest(value as PiGenesisRuntimeDefinition)).rejects.toThrow();
  });

  it("connects real Ed25519 verification, actual Pi Loader bytes and HTTP to identical Go golden output and cold restore", async () => {
    const semantic = (decodeGenesisWire(fromHex(wireFixture.requestCBORHex), MAXIMUM_REQUEST_BYTES) as { body: PiGenesisRequest }).body;
    const definition = await runtime(semantic.runtime.runtimeRevisionDigest), mapping = await signedMapping(definition);
    const verifier = await SignedPiGenesisRuntimeVerifier.create(mapping.config), fixture = loaderFixture();
    const source = await CelldPiGenesisSource.create({ loader: fixture.loader, verifier,
      scope: { tenantId: semantic.tenantId, workspaceId: semantic.workspaceId,
        actorSubjectId: semantic.actorSubjectId, sessionId: semantic.sessionId }, runtime: definition });
    const worker = createCelldPiGenesisWorker({ source, keyId: wireFixture.keyId,
      rootKey: fromHex(wireFixture.rootKey), now: () => 1_700_000_000_000 });
    const response = await worker.fetch(new Request(`http://native.local${GENESIS_PATH}`, { method: "POST",
      body: fromHex(wireFixture.requestCBORHex), headers: { "content-type": GENESIS_TYPE,
        [KEY_HEADER]: wireFixture.keyId, [SIGNATURE_HEADER]: wireFixture.requestMAC } }));
    const bytes = new Uint8Array(await response.arrayBuffer()), expected = wireFixture.cases.find((value) => value.name === "success")!;
    expect(response.status).toBe(200); expect(encodeHex(bytes)).toBe(expected.responseCBORHex);
    expect(response.headers.get(SIGNATURE_HEADER)).toBe(expected.responseMAC);
    expect(fixture.inputs).toEqual([semantic]); expect(fixture.definitions).toHaveLength(1);
    expect(fixture.definitions[0]!.env.artifactDigest).toBe(mapping.claims.artifactDigest);
    expect(fixture.definitions[0]!.globalOutbound).toBeNull();
    const checkpoint = (decodeGenesisWire(bytes, MAXIMUM_RESPONSE_BYTES) as { payload: { checkpoint: AgentCheckpoint } }).payload.checkpoint;
    const cold = new LowLevelPiAgentEngine({ sessionId: semantic.sessionId,
      runtimeRevisionDigest: semantic.runtime.runtimeRevisionDigest, adapterAbiVersion: 2, checkpointSchemaVersion: 2 },
    createPiAgentCoreFactory(CONFIGURATION));
    const boundary = await cold.step({ authority: createOpaqueTurnAuthority(new Uint8Array([1, 2, 3])), checkpoint });
    expect(boundary).toMatchObject({ kind: "effect_request", request: { service: "model", operation: "complete",
      payload: { context: { systemPrompt: CONFIGURATION.systemPrompt,
        messages: (semantic.input as { messages: { role: "user"; content: string }[] }).messages.map((message) => ({ ...message, timestamp: 0 })) } } } });
    expect("ProbeProduction" in source).toBe(false); expect("ProbeProduction" in verifier).toBe(false);
  });

  it("rejects validly signed wrong artifacts and changed modules, configuration, flags or revision before Loader", async () => {
    const definition = await runtime(), fixture = loaderFixture();
    const verifier = await SignedPiGenesisRuntimeVerifier.create((await signedMapping(definition)).config);
    const core = definition.modules[1]!, bytes = new TextEncoder().encode(new TextDecoder().decode(core.bytes) + "\n// changed artifact\n");
    const changedModule = { ...core, bytes, digest: await digestBytes(bytes) };
    for (const changed of [
      { ...definition, configuration: { ...definition.configuration, systemPrompt: "changed trusted prompt" } },
      { ...definition, compatibilityFlags: ["js_rpc", "nodejs_compat"] },
      { ...definition, modules: [definition.modules[0]!, changedModule] },
      { ...definition, runtimeRevisionDigest: EMPTY_DIGEST },
    ]) await expect(CelldPiGenesisSource.create({ loader: fixture.loader, scope: SCOPE, verifier, runtime: changed })).rejects.toThrow("invalid or unverified");
    const wrongArtifact = await SignedPiGenesisRuntimeVerifier.create((await signedMapping(definition, EMPTY_DIGEST)).config);
    await expect(CelldPiGenesisSource.create({ loader: fixture.loader, scope: SCOPE, verifier: wrongArtifact,
      runtime: definition })).rejects.toThrow("invalid or unverified");
    expect(fixture.definitions).toHaveLength(0); expect(fixture.inputs).toHaveLength(0);
  });

  it("rejects document tampering before a genesis source or Loader can be composed", async () => {
    const definition = await runtime(), mapping = await signedMapping(definition), fixture = loaderFixture();
    const signature = Uint8Array.from(mapping.signature); signature[0] = signature[0]! ^ 1;
    for (const document of [
      encodeCanonicalCbor({ claims: mapping.claims, algorithm: "ed25519", signature }),
      encodeCanonicalCbor({ claims: { ...mapping.claims, artifactDigest: EMPTY_DIGEST }, algorithm: "ed25519", signature: mapping.signature }),
    ]) await expect(SignedPiGenesisRuntimeVerifier.create({ ...mapping.config, document })).rejects.toThrow();
    expect(fixture.definitions).toHaveLength(0);
  });

  it("retains signed modules and configuration if the caller mutates them while the source is hashing", async () => {
    const definition = await runtime(), verifier = await SignedPiGenesisRuntimeVerifier.create((await signedMapping(definition)).config);
    const fixture = loaderFixture();
    const pending = CelldPiGenesisSource.create({ loader: fixture.loader, scope: SCOPE, verifier, runtime: definition });
    definition.modules[1]!.bytes.fill(0);
    (definition.configuration as { systemPrompt: string }).systemPrompt = "mutated after source snapshot";
    const source = await pending;
    await assertColdFirstBoundary((await source.createGenesis(await request())).checkpoint);
    expect(fixture.definitions[0]!.env.configuration).toMatchObject({ systemPrompt: CONFIGURATION.systemPrompt });
  });
});
