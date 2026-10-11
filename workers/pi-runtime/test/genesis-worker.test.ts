import { describe, expect, it, vi } from "vitest";
import { Buffer } from "node:buffer";
import { build } from "esbuild";
import { digestBytes, encodeHex, type AgentCheckpoint } from "@circulusd/protocol-types";
import fixture from "../../../packages/protocol-types/fixtures/engine-genesis-v1alpha1.json";
import { createCelldPiGenesisWorker, type CelldPiGenesisWorkerConfig } from "../src/genesis-worker.ts";
import {
  GENESIS_PATH, GENESIS_PROTOCOL, GENESIS_SCHEMA, GENESIS_TYPE, KEY_HEADER,
  MAXIMUM_REQUEST_BYTES, MAXIMUM_RESPONSE_BYTES, PROBE_PATH, PROBE_PROTOCOL, PROBE_SCHEMA, PROBE_TYPE,
  SIGNATURE_HEADER, decodeGenesisWire, encodeGenesisWire, genesisDirectionalKeys,
  genesisRequestMac, genesisResponseMac,
} from "../src/genesis-wire.ts";
import { PiGenesisGenerator, piGenesisBinding, piGenesisRequestDigest, type PiGenesisRequest, type PiGenesisResult } from "../src/genesis.ts";
import { CelldPiGenesisSource, PI_GENESIS_CORE_MODULE, PI_GENESIS_ENTRY_MODULE, PI_GENESIS_ENTRY_SOURCE,
  type CelldGenesisLoader, type PiGenesisRuntimeDefinition } from "../src/celld-genesis.ts";
import type { PiGenesisEnvironment } from "../src/genesis.ts";
import { LowLevelPiAgentEngine, createOpaqueTurnAuthority, createPiAgentCoreFactory } from "../src/index.ts";
import { CONFIGURATION, assertColdFirstBoundary, environment, request as semanticRequest } from "./genesis-fixtures.ts";

const NOW = 1_700_000_000_000;
const KEY_ID = "test-operational-genesis";
const REQUEST_ID = "req_AAAAAAAAAAAAAAAAAAAAAAAAAA";
const ROOT_KEY = new Uint8Array(32).fill(19);
const EMPTY_DIGEST = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
function fromHex(value: string): Uint8Array<ArrayBuffer> { return Uint8Array.from(value.match(/../g)!, (byte) => Number.parseInt(byte, 16)); }
function deferred<T = void>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((yes) => { resolve = yes; });
  return { promise, resolve };
}
async function fixtureSource() {
  const generator = await PiGenesisGenerator.create(await environment());
  let calls = 0;
  return { generator, source: { createGenesis: async (request: PiGenesisRequest) => { calls++; return generator.createGenesis(request); } },
    calls: () => calls };
}
function worker(source: CelldPiGenesisWorkerConfig["source"], additional: Partial<CelldPiGenesisWorkerConfig> = {}) {
  return createCelldPiGenesisWorker({ keyId: KEY_ID, rootKey: ROOT_KEY, source, now: () => NOW, ...additional });
}
async function envelope(body?: PiGenesisRequest): Promise<Record<string, unknown>> {
  return { protocol: GENESIS_PROTOCOL, major: 1, minor: 0, schemaDigest: GENESIS_SCHEMA,
    requestId: REQUEST_ID, sentAtUnixMs: NOW, body: body ?? await semanticRequest() };
}
async function authenticatedBytes(body: Uint8Array): Promise<Request> {
  const keys = await genesisDirectionalKeys(ROOT_KEY);
  return new Request(`http://native.local${GENESIS_PATH}`, { method: "POST", body: Uint8Array.from(body),
    headers: { "content-type": GENESIS_TYPE, [KEY_HEADER]: KEY_ID,
      [SIGNATURE_HEADER]: await genesisRequestMac(keys.request, KEY_ID, body) } });
}
async function authenticated(value: unknown): Promise<Request> {
  return authenticatedBytes(encodeGenesisWire(value, MAXIMUM_REQUEST_BYTES));
}
async function decoded(response: Response): Promise<Record<string, unknown>> {
  return decodeGenesisWire(new Uint8Array(await response.arrayBuffer()), MAXIMUM_RESPONSE_BYTES) as Record<string, unknown>;
}
async function signedPayload(response: Response, request: Request): Promise<Record<string, unknown>> {
  const input = new Uint8Array(await request.clone().arrayBuffer()), body = new Uint8Array(await response.clone().arrayBuffer());
  const keys = await genesisDirectionalKeys(ROOT_KEY);
  expect(response.headers.get(SIGNATURE_HEADER)).toBe(await genesisResponseMac(keys.response, KEY_ID, REQUEST_ID, input, response.status, body));
  expect(response.headers.get("content-encoding")).toBeNull();
  expect(response.headers.get("cache-control")).toBe("no-store");
  return (await decoded(response)).payload as Record<string, unknown>;
}
function probeRequest(nonce = new Uint8Array(32).fill(12)): Request {
  return new Request(`http://native.local${PROBE_PATH}`, { method: "POST", headers: { "content-type": PROBE_TYPE },
    body: Uint8Array.from(encodeGenesisWire({ protocol: PROBE_PROTOCOL, major: 1, minor: 0, schemaDigest: PROBE_SCHEMA, nonce }, 256)) });
}
function nativeProof(nonce: Uint8Array) {
  return { protocol: PROBE_PROTOCOL, major: 1, minor: 0, schemaDigest: PROBE_SCHEMA, nonce,
    descriptor: { schemaVersion: 1, backendKind: "celld", buildDigest: EMPTY_DIGEST, applicationDigest: EMPTY_DIGEST,
      instanceId: "fixture-instance", transactionDomainId: "fixture-domain", durabilityClass: "crash-durable-rpo0",
      conformanceRunId: "fixture-run", conformanceDigest: EMPTY_DIGEST, runtimeKeyId: "fixture-native-key", probeEpoch: 1,
      productionEligible: true, atomicGroups: ["engine-genesis"] }, keyId: "fixture-native-key", signature: new Uint8Array(64).fill(55) };
}

describe("authenticated actual Pi genesis worker", () => {
  it("matches the existing Go success/unavailable/bad-source golden bytes and MACs", async () => {
    const wire = decodeGenesisWire(fromHex(fixture.requestCBORHex), MAXIMUM_REQUEST_BYTES) as { body: PiGenesisRequest };
    const checkpoint = decodeGenesisWire(fromHex(fixture.checkpointCBORHex), MAXIMUM_RESPONSE_BYTES) as AgentCheckpoint;
    const successful: PiGenesisResult = { requestDigest: fixture.requestDigest as PiGenesisResult["requestDigest"],
      binding: piGenesisBinding(wire.body), checkpoint };
    const rootKey = fromHex(fixture.rootKey), keys = await genesisDirectionalKeys(rootKey);
    expect(encodeHex(keys.request)).toBe(fixture.requestKey); expect(encodeHex(keys.response)).toBe(fixture.responseKey);
    for (const vector of fixture.cases) {
      const source = { createGenesis: async () => {
        if (vector.name === "unavailable") throw new Error("private source error");
        if (vector.name === "bad-source") return { ...successful, checkpoint: { ...checkpoint, payloadBytes: new Uint8Array() } };
        return successful;
      } };
      const adapter = worker(source, { keyId: fixture.keyId, rootKey });
      const request = new Request(`http://native.local${GENESIS_PATH}`, { method: "POST", body: fromHex(fixture.requestCBORHex),
        headers: { "content-type": GENESIS_TYPE, [KEY_HEADER]: fixture.keyId, [SIGNATURE_HEADER]: fixture.requestMAC } });
      const response = await adapter.fetch(request);
      expect(response.status, vector.name).toBe(vector.status);
      expect(encodeHex(new Uint8Array(await response.arrayBuffer())), vector.name).toBe(vector.responseCBORHex);
      expect(response.headers.get(SIGNATURE_HEADER), vector.name).toBe(vector.responseMAC);
    }
  });

  it("calls the actual Pi generator and cold reconstructs distinct ordered input at the first model boundary", async () => {
    const actual = await fixtureSource(), semantic = await semanticRequest();
    const request = await authenticated(await envelope(semantic));
    const response = await worker(actual.source).fetch(request.clone());
    expect(response.status).toBe(200); expect(actual.calls()).toBe(1);
    const payload = await signedPayload(response, request);
    expect(payload.identity).toEqual(piGenesisBinding(semantic));
    await assertColdFirstBoundary(payload.checkpoint as AgentCheckpoint);
  });

  it("connects HTTP through retained CelldPiGenesisSource and the actual bundled Pi entrypoint to identical Go golden bytes", async () => {
    const wire = decodeGenesisWire(fromHex(fixture.requestCBORHex), MAXIMUM_REQUEST_BYTES) as { body: PiGenesisRequest };
    const semantic = wire.body;
    const built = await build({ entryPoints: [new URL("../src/genesis-entrypoint.ts", import.meta.url).pathname],
      bundle: true, platform: "browser", format: "esm", target: "es2022", write: false, external: ["cloudflare:sockets"], logLevel: "silent" });
    const core = Uint8Array.from(built.outputFiles[0]!.contents), main = new TextEncoder().encode(PI_GENESIS_ENTRY_SOURCE);
    const runtime: PiGenesisRuntimeDefinition = { runtimeRevisionDigest: semantic.runtime.runtimeRevisionDigest, adapterAbiVersion: 2,
      checkpointSchemaVersion: 2, compatibilityDate: "2026-08-01", compatibilityFlags: ["js_rpc"], mainModule: PI_GENESIS_ENTRY_MODULE,
      modules: [{ specifier: PI_GENESIS_ENTRY_MODULE, bytes: main, digest: await digestBytes(main) },
        { specifier: PI_GENESIS_CORE_MODULE, bytes: core, digest: await digestBytes(core) }], configuration: structuredClone(CONFIGURATION) };
    let loads = 0;
    const moduleUrl = (value: string) => `data:text/javascript;base64,${Buffer.from(value).toString("base64")}`;
    // Native Loader transport, native WorkerEntrypoint base and signed-map
    // verifier below are local contract fixtures, not qualification evidence.
    // Pi generator/adapter implementation executes its actual bundled module.
    const loader: CelldGenesisLoader = { get: async (_name, getCode) => {
      loads++;
      const definition = await getCode();
      const base = moduleUrl("export class WorkerEntrypoint { constructor(ctx, env) { this.ctx = ctx; this.env = env; } }");
      const wrapped = definition.modules[PI_GENESIS_ENTRY_MODULE]!
        .replace('"cloudflare:workers"', JSON.stringify(base))
        .replace(JSON.stringify(PI_GENESIS_CORE_MODULE), JSON.stringify(moduleUrl(definition.modules[PI_GENESIS_CORE_MODULE]!)));
      const module = await import(/* @vite-ignore */ moduleUrl(wrapped)) as {
        default: new (ctx: object, env: PiGenesisEnvironment) => { createGenesis(request: PiGenesisRequest): Promise<unknown> };
      };
      const entrypoint = new module.default({}, definition.env);
      return { getEntrypoint: () => ({ createGenesis: async (request) => entrypoint.createGenesis(request) }) };
    } };
    const source = await CelldPiGenesisSource.create({ loader, verifier: { verify: async (binding) => ({ ...binding }) },
      scope: { tenantId: semantic.tenantId, workspaceId: semantic.workspaceId, actorSubjectId: semantic.actorSubjectId, sessionId: semantic.sessionId }, runtime });
    const adapter = worker(source, { keyId: fixture.keyId, rootKey: fromHex(fixture.rootKey) });
    const request = new Request(`http://native.local${GENESIS_PATH}`, { method: "POST", body: fromHex(fixture.requestCBORHex),
      headers: { "content-type": GENESIS_TYPE, [KEY_HEADER]: fixture.keyId, [SIGNATURE_HEADER]: fixture.requestMAC } });
    const response = await adapter.fetch(request);
    const returned = new Uint8Array(await response.arrayBuffer()), expected = fixture.cases.find((entry) => entry.name === "success")!;
    expect(response.status).toBe(200); expect(loads).toBe(1);
    expect(encodeHex(returned)).toBe(expected.responseCBORHex); expect(response.headers.get(SIGNATURE_HEADER)).toBe(expected.responseMAC);
    const payload = (decodeGenesisWire(returned, MAXIMUM_RESPONSE_BYTES) as { payload: { checkpoint: AgentCheckpoint } }).payload;
    const cold = new LowLevelPiAgentEngine({ sessionId: semantic.sessionId, runtimeRevisionDigest: semantic.runtime.runtimeRevisionDigest,
      adapterAbiVersion: 2, checkpointSchemaVersion: 2 }, createPiAgentCoreFactory(CONFIGURATION));
    const boundary = await cold.step({ authority: createOpaqueTurnAuthority(new Uint8Array([1, 2, 3])), checkpoint: payload.checkpoint });
    const messages = (semantic.input as { messages: { role: "user"; content: string }[] }).messages.map((message) => ({ ...message, timestamp: 0 }));
    expect(boundary).toMatchObject({ kind: "effect_request", request: { service: "model", operation: "complete",
      payload: { context: { systemPrompt: CONFIGURATION.systemPrompt, messages } } } });
    const changed: PiGenesisRequest = { ...semantic, runtime: { ...semantic.runtime, runtimeRevisionDigest: EMPTY_DIGEST } };
    const mismatch = await authenticated(await envelope(changed));
    expect((await worker(source).fetch(mismatch)).status).toBe(503); expect(loads).toBe(1);
  });

  it("retains the operational key and bound source method despite caller config mutation", async () => {
    const actual = await fixtureSource(), key = Uint8Array.from(ROOT_KEY);
    let method = actual.source.createGenesis, methodReads = 0;
    Object.defineProperty(actual.source, "createGenesis", {
      get: () => { methodReads++; return method; }, set: (value: typeof method) => { method = value; },
    });
    const config = { keyId: KEY_ID, rootKey: key, source: actual.source, now: () => NOW };
    const adapter = createCelldPiGenesisWorker(config);
    key.fill(0); config.keyId = "changed";
    actual.source.createGenesis = async () => { throw new Error("mutated method must not be called"); };
    const request = await authenticated(await envelope());
    expect((await signedPayload(await adapter.fetch(request.clone()), request)).ok).toBe(true);
    expect(actual.calls()).toBe(1); expect(methodReads).toBe(1);
  });

  it("rejects route, method, type, encoding and auth shape before touching the body or source", async () => {
    const actual = await fixtureSource(), adapter = worker(actual.source);
    const attempts = [
      { url: "/unsupported", status: 404 }, { url: `${GENESIS_PATH}?`, status: 404 }, { url: `${GENESIS_PATH}?x=1`, status: 404 },
      { url: GENESIS_PATH, method: "PUT", status: 405 },
      { url: GENESIS_PATH, headers: { "content-encoding": "gzip" }, status: 405 },
      { url: GENESIS_PATH, headers: { "content-type": "application/cbor" }, status: 400 },
      { url: GENESIS_PATH, headers: { [KEY_HEADER]: "wrong" }, status: 401 },
      { url: GENESIS_PATH, headers: { [SIGNATURE_HEADER]: "AB".repeat(32) }, status: 401 },
      { url: GENESIS_PATH, headers: { "content-length": String(MAXIMUM_REQUEST_BYTES + 1) }, status: 400 },
    ];
    for (const attempt of attempts) {
      const request = new Request(`http://native.local${attempt.url}`, { method: attempt.method ?? "POST", body: new Uint8Array([0]),
        headers: { "content-type": GENESIS_TYPE, [KEY_HEADER]: KEY_ID, [SIGNATURE_HEADER]: "0".repeat(64), ...attempt.headers } });
      expect((await adapter.fetch(request)).status).toBe(attempt.status); expect(request.bodyUsed).toBe(false);
    }
    expect(actual.calls()).toBe(0);
  });

  it("rejects wrong MAC and malformed/noncanonical/oversized wire bytes before source I/O", async () => {
    const actual = await fixtureSource(), adapter = worker(actual.source);
    const request = await authenticated(await envelope()); request.headers.set(SIGNATURE_HEADER, "0".repeat(64));
    expect((await adapter.fetch(request)).status).toBe(401);
    const canonical = encodeGenesisWire(await envelope(), MAXIMUM_REQUEST_BYTES), noncanonical = new Uint8Array(canonical.byteLength + 1);
    noncanonical.set([0xb8, 7]); noncanonical.set(canonical.slice(1), 2);
    for (const body of [new Uint8Array([0xff]), noncanonical, new Uint8Array(MAXIMUM_REQUEST_BYTES + 1)]) {
      expect((await adapter.fetch(await authenticatedBytes(body))).status).toBe(400);
    }
    expect(actual.calls()).toBe(0);
  });

  it("rejects envelope and full input identity/digest/schema mismatches before source I/O", async () => {
    const actual = await fixtureSource(), adapter = worker(actual.source), valid = await envelope();
    const semantic = valid.body as PiGenesisRequest;
    for (const value of [
      { ...valid, protocol: "other" }, { ...valid, schemaDigest: EMPTY_DIGEST }, { ...valid, extra: 1 },
      { ...valid, requestId: semantic.turnId }, { ...valid, sentAtUnixMs: NOW - 30_001 },
      { ...valid, body: { ...semantic, sessionId: "invalid" } }, { ...valid, body: { ...semantic, inputDigest: EMPTY_DIGEST } },
      { ...valid, body: { ...semantic, runtime: { ...semantic.runtime, adapterAbiVersion: 3 } } },
      { ...valid, body: { ...semantic, input: { messages: [] } } },
      { ...valid, body: { ...semantic, input: { messages: [{ role: "assistant", content: "wrong role" }] } } },
      { ...valid, body: { ...semantic, input: { messages: [{ role: "user", content: "a".repeat((1 << 20) + 1) }] } } },
    ]) expect((await adapter.fetch(await authenticated(value))).status).toBe(400);
    expect(actual.calls()).toBe(0);
  });

  it("sanitizes immediate source failure and rejects source request mutation with original reply binding", async () => {
    const actual = await fixtureSource(), value = await envelope(), semantic = value.body as PiGenesisRequest;
    const result = await actual.generator.createGenesis(semantic);
    for (const [source, error] of [
      [{ createGenesis: async () => { throw new Error("secret source detail"); } }, "UNAVAILABLE"],
      [{ createGenesis: async (request: PiGenesisRequest) => {
        const changed = { ...request, turnId: `turn_${"B".repeat(25)}A` };
        (request as { turnId: string }).turnId = changed.turnId;
        return { ...result, requestDigest: await piGenesisRequestDigest(changed), binding: piGenesisBinding(changed), checkpoint: { ...result.checkpoint, turnId: changed.turnId } };
      } }, "BAD_SOURCE"],
    ] as const) {
      const request = await authenticated(value), response = await worker(source).fetch(request.clone());
      expect(response.status).toBe(503); expect(await signedPayload(response, request)).toEqual({ ok: false, error });
    }
  });

  it("rejects malformed/oversized/wrong checkpoint and source binding without exposing a success", async () => {
    const actual = await fixtureSource(), semantic = await semanticRequest(), good = await actual.generator.createGenesis(semantic);
    for (const result of [
      { ...good, binding: { ...good.binding, workspaceId: "bad" } },
      { ...good, requestDigest: EMPTY_DIGEST }, { ...good, checkpoint: { ...good.checkpoint, payloadBytes: new Uint8Array() } },
      { ...good, checkpoint: { ...good.checkpoint, payloadBytes: new Uint8Array((4 << 20) + 1) } },
      { ...good, checkpoint: { ...good.checkpoint, checkpointSequence: 1 } },
      { ...good, checkpoint: { ...good.checkpoint, payloadDigest: EMPTY_DIGEST } },
      { ...good, checkpoint: { ...good.checkpoint, runtimeRevisionDigest: EMPTY_DIGEST } },
    ]) {
      const request = await authenticated(await envelope(semantic));
      const response = await worker({ createGenesis: async () => result as PiGenesisResult }).fetch(request.clone());
      expect(await signedPayload(response, request)).toEqual({ ok: false, error: "BAD_SOURCE" });
    }
  });

  it("rejects a rehashed nonexecutable core state from a source", async () => {
    const actual = await fixtureSource(), semantic = await semanticRequest(), good = await actual.generator.createGenesis(semantic);
    const state = decodeGenesisWire(good.checkpoint.payloadBytes, 4 << 20) as Record<string, unknown>;
    const payloadBytes = encodeGenesisWire({ ...state, coreState: null }, 4 << 20);
    const bad = { ...good, checkpoint: { ...good.checkpoint, payloadBytes, payloadDigest: await digestBytes(payloadBytes) } };
    const request = await authenticated(await envelope(semantic));
    expect(await signedPayload(await worker({ createGenesis: async () => bad }).fetch(request.clone()), request)).toEqual({ ok: false, error: "BAD_SOURCE" });
  });

  it("bounds slow body waiting and cancels its reader", async () => {
    const actual = await fixtureSource(); let canceled = false;
    const body = new ReadableStream<Uint8Array>({ pull: () => new Promise(() => undefined), cancel: () => { canceled = true; } });
    const request = new Request(`http://native.local${GENESIS_PATH}`, { method: "POST", body, duplex: "half",
      headers: { "content-type": GENESIS_TYPE, [KEY_HEADER]: KEY_ID, [SIGNATURE_HEADER]: "0".repeat(64) } } as RequestInit);
    expect((await worker(actual.source, { timeoutMs: 10 }).fetch(request)).status).toBe(503);
    expect(canceled).toBe(true); expect(actual.calls()).toBe(0);
  });

  it("bounds pending source wait and forwards abort without asserting isolate termination", async () => {
    let sourceSignal: AbortSignal | undefined;
    const source = { createGenesis: async (_request: PiGenesisRequest, signal?: AbortSignal): Promise<PiGenesisResult> => {
      sourceSignal = signal; return new Promise(() => undefined);
    } };
    const request = await authenticated(await envelope()), response = await worker(source, { timeoutMs: 200 }).fetch(request);
    expect(response.status).toBe(503); expect(response.headers.get(SIGNATURE_HEADER)).toBeNull();
    expect(sourceSignal?.aborted).toBe(true);
  });

  it("handles caller cancellation during pending source generation", async () => {
    const entered = deferred(), abort = new AbortController();
    const source = { createGenesis: async (): Promise<PiGenesisResult> => { entered.resolve(); return new Promise(() => undefined); } };
    const request = await authenticated(await envelope());
    const pending = worker(source).fetch(new Request(request, { signal: abort.signal }));
    await entered.promise; abort.abort();
    const response = await pending;
    expect(response.status).toBe(503); expect(response.headers.get(SIGNATURE_HEADER)).toBeNull();
  });

  it("bounds pending response MAC signing within the complete request deadline", async () => {
    const actual = await fixtureSource(), adapter = worker(actual.source, { timeoutMs: 250 });
    const request = await authenticated(await envelope()), nativeSign = crypto.subtle.sign.bind(crypto.subtle);
    let started = false;
    const sign = vi.spyOn(crypto.subtle, "sign").mockImplementation((algorithm, key, data) => {
      const raw = ArrayBuffer.isView(data) ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength) : new Uint8Array(data);
      if (new TextDecoder().decode(raw).includes("circulusd.engine-genesis.response.v1")) {
        started = true; return new Promise(() => undefined);
      }
      return nativeSign(algorithm, key, data);
    });
    try {
      const response = await adapter.fetch(request);
      expect(started).toBe(true); expect(response.status).toBe(503); expect(response.headers.get(SIGNATURE_HEADER)).toBeNull();
    } finally { sign.mockRestore(); }
  });

  it("returns503 without actual native proof and performs zero operational I/O for malformed challenges", async () => {
    const actual = await fixtureSource(), adapter = worker(actual.source);
    expect((await adapter.fetch(probeRequest())).status).toBe(503);
    let calls = 0;
    const guarded = worker(actual.source, { nativeProbe: async () => { calls++; return new Uint8Array(); } });
    const authHeader = probeRequest(); authHeader.headers.set(KEY_HEADER, KEY_ID);
    expect((await guarded.fetch(authHeader)).status).toBe(400); expect(authHeader.bodyUsed).toBe(false);
    for (const nonce of [new Uint8Array(31), new Uint8Array(33)]) expect((await guarded.fetch(probeRequest(nonce))).status).toBe(400);
    expect(calls).toBe(0); expect(actual.calls()).toBe(0);
  });

  it("forwards exact proof bytes, binds nonce and pins all descriptor fields across probes", async () => {
    const actual = await fixtureSource(); let applicationDigest = EMPTY_DIGEST;
    let returned: Uint8Array | undefined;
    const adapter = worker(actual.source, { nativeProbe: async (request) => {
      const nonce = (decodeGenesisWire(request, 256) as { nonce: Uint8Array }).nonce;
      const proof = nativeProof(nonce); proof.descriptor.applicationDigest = applicationDigest;
      returned = encodeGenesisWire(proof, 32 << 10); return returned;
    } });
    for (const nonce of [new Uint8Array(32).fill(12), new Uint8Array(32).fill(13)]) {
      const response = await adapter.fetch(probeRequest(nonce));
      expect(response.status).toBe(200); expect(new Uint8Array(await response.arrayBuffer())).toEqual(returned);
      expect(response.headers.get(SIGNATURE_HEADER)).toBeNull();
    }
    applicationDigest = `sha256:${"c".repeat(64)}`;
    expect((await adapter.fetch(probeRequest())).status).toBe(503); expect(actual.calls()).toBe(0);
  });

  it("rejects mismatched nonce/key/capability/proof shape and operational/native key collision", async () => {
    const actual = await fixtureSource(), nonce = new Uint8Array(32).fill(12), good = nativeProof(nonce);
    for (const proof of [
      { ...good, nonce: new Uint8Array(32).fill(1) }, { ...good, signature: new Uint8Array(63) }, { ...good, keyId: "other" },
      { ...good, descriptor: { ...good.descriptor, atomicGroups: ["command-receipt"] } },
      { ...good, descriptor: { ...good.descriptor, backendKind: "reference-memory" } },
      { ...good, descriptor: { ...good.descriptor, runtimeKeyId: KEY_ID }, keyId: KEY_ID },
    ]) {
      const response = await worker(actual.source, { nativeProbe: async () => encodeGenesisWire(proof, 32 << 10) }).fetch(probeRequest());
      expect(response.status).toBe(503); expect(response.headers.get(SIGNATURE_HEADER)).toBeNull();
    }
    expect(actual.calls()).toBe(0);
  });

  it("bounds pending native proof generation and accepts only the fixed Go credential/timeout bounds", async () => {
    const actual = await fixtureSource(); let signal: AbortSignal | undefined;
    const adapter = worker(actual.source, { timeoutMs: 20, nativeProbe: async (_request, forwarded) => {
      signal = forwarded; return new Promise(() => undefined);
    } });
    expect((await adapter.fetch(probeRequest())).status).toBe(503); expect(signal?.aborted).toBe(true);
    for (const rootKey of [new Uint8Array(32), new Uint8Array(256)]) expect(() => worker(actual.source, { rootKey })).not.toThrow();
    for (const config of [{ rootKey: new Uint8Array(31) }, { rootKey: new Uint8Array(257) }, { timeoutMs: 0 }, { timeoutMs: 30_001 }, { keyId: "BAD" }]) {
      expect(() => worker(actual.source, config)).toThrow();
    }
  });
});
