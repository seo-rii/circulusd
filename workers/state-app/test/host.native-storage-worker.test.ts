import { describe, expect, it, vi } from "vitest";
import { decodeCanonicalCbor, encodeCanonicalCbor } from "@circulusd/protocol-types";
import fixture from "../../../packages/protocol-types/fixtures/native-storage-v1alpha1.json";
import {
  EMPTY_DIGEST, KEY_HEADER, PROBE_PATH, PROBE_PROTOCOL, PROBE_SCHEMA, PROBE_TYPE, SIGNATURE_HEADER,
  STORAGE_PROTOCOL, STORAGE_SCHEMA, TRANSACTION_PATH, TRANSACTION_TYPE, fromHex, requestDigest,
  storageDirectionalKeys, storageRequestMac, storageResponseMac, toHex,
} from "../src/native-storage/codec.ts";
import { NativeStorageKernel } from "../src/native-storage/kernel.ts";
import { createNativeStorageDurableObjectClass, createNativeStorageWorker, type NativeStorageWorkerConfig } from "../src/native-storage/worker.ts";
import type { NativeStorageState } from "../src/native-storage/types.ts";
import {
  KEY_ID, NOW, NamespaceFixture, OBJECT_ID, ROOT_KEY, StorageFixture,
  authenticatedRequest, deferred, makeCommit, wireEnvelope,
} from "./support/native-storage.ts";

function setup(input: Partial<NativeStorageWorkerConfig> = {}) {
  const storage = new StorageFixture(), namespace = new NamespaceFixture();
  const config = { keyId: KEY_ID, rootKey: ROOT_KEY, now: () => NOW, ...input };
  const worker = createNativeStorageWorker(config);
  class NativeBase { constructor(readonly state: NativeStorageState) {} }
  const Cell = createNativeStorageDurableObjectClass(NativeBase, config);
  namespace.fetcher = async (id, request) => new Cell({ storage, id }, { NATIVE_STORAGE: namespace }).fetch(request);
  const environment = { NATIVE_STORAGE: namespace };
  return { storage, namespace, config, worker, environment, Cell };
}
async function payload(response: Response): Promise<Record<string, unknown>> {
  return (decodeCanonicalCbor(new Uint8Array(await response.arrayBuffer())) as Record<string, unknown>).payload as Record<string, unknown>;
}
async function verifyResponse(response: Response, request: Request): Promise<Record<string, unknown>> {
  const input = new Uint8Array(await request.clone().arrayBuffer());
  const body = new Uint8Array(await response.clone().arrayBuffer()), keys = await storageDirectionalKeys(ROOT_KEY);
  expect(response.headers.get(SIGNATURE_HEADER)).toBe(await storageResponseMac(keys.response, KEY_ID, "req_AAAAAAAAAAAAAAAAAAAAAAAAAA", input, response.status, body));
  expect(response.headers.get("content-encoding")).toBeNull();
  expect(response.headers.get("cache-control")).toBe("no-store");
  return payload(response);
}
function probeRequest(): Request {
  return new Request(`http://native.local${PROBE_PATH}`, { method: "POST", headers: { "content-type": PROBE_TYPE },
    body: encodeCanonicalCbor({ protocol: PROBE_PROTOCOL, major: 1, minor: 0, schemaDigest: PROBE_SCHEMA, nonce: new Uint8Array(32).fill(12) }) });
}
function proof(): Record<string, unknown> {
  return { protocol: PROBE_PROTOCOL, major: 1, minor: 0, schemaDigest: PROBE_SCHEMA, nonce: new Uint8Array(32).fill(12),
    descriptor: { schemaVersion: 1, backendKind: "celld", buildDigest: EMPTY_DIGEST, applicationDigest: EMPTY_DIGEST,
      instanceId: "fixture-instance", transactionDomainId: "fixture-domain", durabilityClass: "crash-durable-rpo0",
      conformanceRunId: "fixture-run", conformanceDigest: EMPTY_DIGEST, runtimeKeyId: "fixture-key", probeEpoch: 1,
      productionEligible: true, atomicGroups: ["command-receipt", "native-storage"] }, keyId: "fixture-key", signature: new Uint8Array(64).fill(33) };
}

describe("authenticated native storage DO fetch adapter", () => {
  it("matches all nine Go golden requests, results and directional MACs through the actual kernel/router", async () => {
    const rootKey = fromHex(fixture.rootKeyHex), keyId = fixture.keyId;
    const { worker, namespace, environment } = setup({ keyId, rootKey, now: () => 1_700_000_000_000 });
    const keys = await storageDirectionalKeys(rootKey);
    expect(toHex(keys.request)).toBe(fixture.requestKeyHex);
    expect(toHex(keys.response)).toBe(fixture.responseKeyHex);
    for (const vector of fixture.cases) {
      const request = new Request(`http://native.local${TRANSACTION_PATH}`, { method: "POST", body: fromHex(vector.requestHex),
        headers: { "content-type": TRANSACTION_TYPE, [KEY_HEADER]: keyId, [SIGNATURE_HEADER]: vector.requestMac } });
      const response = await worker.fetch(request, environment);
      expect(response.status, vector.name).toBe(vector.status);
      expect(toHex(new Uint8Array(await response.arrayBuffer())), vector.name).toBe(vector.responseHex);
      expect(response.headers.get(SIGNATURE_HEADER), vector.name).toBe(vector.responseMac);
    }
    expect(namespace.calls).toBe(9);
  });

  it.each(["commit", "barrier"] as const)("withholds external %s response and signature while the DO fetch output gate is pending", async (operation) => {
    const { worker, namespace, storage, environment, Cell } = setup();
    const kernel = new NativeStorageKernel(namespace.state(storage), namespace);
    const snapshot = (await kernel.readSnapshot({ objectId: OBJECT_ID })).snapshot;
    const body = operation === "commit" ? await makeCommit(snapshot, new Uint8Array([7])) : {
      token: (await kernel.compareAndCommit(await makeCommit(snapshot))).token, marker: new Uint8Array(32).fill(13),
    };
    const request = await authenticatedRequest(wireEnvelope(operation, body));
    const entered = deferred(), gate = deferred();
    namespace.fetcher = async (id, forwarded) => {
      const response = await new Cell({ storage, id }, environment).fetch(forwarded);
      expect(response.headers.get(SIGNATURE_HEADER)).toBeNull();
      entered.resolve();
      await gate.promise;
      return response;
    };
    let settled = false;
    const result = worker.fetch(request.clone(), environment).then((response) => { settled = true; return response; });
    await entered.promise;
    expect(settled).toBe(false);
    expect((await kernel.readSnapshot({ objectId: OBJECT_ID })).snapshot.revision).toBe(1);
    gate.resolve();
    expect((await verifyResponse(await result, request)).ok).toBe(true);
  });

  it("reports a gate or response-loss failure as ambiguous while durable reopening retains the exact commit", async () => {
    const { worker, namespace, storage, environment, Cell } = setup();
    const kernel = new NativeStorageKernel(namespace.state(storage), namespace);
    const snapshot = (await kernel.readSnapshot({ objectId: OBJECT_ID })).snapshot;
    const request = await authenticatedRequest(wireEnvelope("commit", await makeCommit(snapshot, new Uint8Array([4]))));
    namespace.fetcher = async (id, forwarded) => {
      await new Cell({ storage, id }, environment).fetch(forwarded);
      throw new Error("private native gate failure");
    };
    const response = await worker.fetch(request.clone(), environment);
    expect(response.status).toBe(503);
    expect(await verifyResponse(response, request)).toEqual({ ok: false, error: "UNAVAILABLE", notCommitted: false });
    const reopened = new NativeStorageKernel(namespace.state(storage), namespace);
    expect((await reopened.readSnapshot({ objectId: OBJECT_ID })).state).toEqual(new Uint8Array([4]));
    namespace.fetcher = async (id, forwarded) => new Cell({ storage, id }, environment).fetch(forwarded);
    const stale = await worker.fetch(request.clone(), environment);
    expect(stale.status).toBe(409);
    expect(await verifyResponse(stale, request)).toEqual({ ok: false, error: "SNAPSHOT_CONFLICT", notCommitted: true });
  });

  it("rejects malformed key/signature headers without reading a body or invoking a source", async () => {
    const { worker, namespace, environment } = setup();
    for (const headers of [
      { [KEY_HEADER]: "wrong", [SIGNATURE_HEADER]: "0".repeat(64) },
      { [KEY_HEADER]: KEY_ID, [SIGNATURE_HEADER]: "AB".repeat(32) },
      { [KEY_HEADER]: KEY_ID, [SIGNATURE_HEADER]: "bad" },
    ]) {
      const request = new Request(`http://native.local${TRANSACTION_PATH}`, { method: "POST", body: new Uint8Array([9]),
        headers: { "content-type": TRANSACTION_TYPE, ...headers } });
      expect((await worker.fetch(request, environment)).status).toBe(401);
      expect(request.bodyUsed).toBe(false);
    }
    expect(namespace.calls).toBe(0);
  });

  it("rejects bad MACs and canonical or identity/schema mismatches before native calls", async () => {
    const { worker, namespace, environment } = setup();
    const valid = wireEnvelope("snapshot", { objectId: OBJECT_ID });
    const badMac = await authenticatedRequest(valid);
    badMac.headers.set(SIGNATURE_HEADER, "0".repeat(64));
    expect((await worker.fetch(badMac, environment)).status).toBe(401);
    for (const value of [
      { ...valid, schemaDigest: EMPTY_DIGEST }, { ...valid, protocol: "other" }, { ...valid, major: 2 },
      { ...valid, body: { objectId: "" } }, { ...valid, body: { objectId: OBJECT_ID, extra: 1 } },
      { ...valid, sentAtUnixMs: NOW - 60_001 }, { ...valid, extra: "not allowed" },
    ]) {
      const request = await authenticatedRequest(value), response = await worker.fetch(request.clone(), environment);
      expect(response.status).toBe(400);
      expect(await verifyResponse(response, request)).toEqual({ ok: false, error: "INVALID_ARGUMENT", notCommitted: true });
    }
    const malformed = await authenticatedRequest(new Uint8Array([0xff]));
    expect((await worker.fetch(malformed, environment)).status).toBe(400);
    expect(namespace.calls).toBe(0);
  });

  it("bounds slow request-body waiting and cancels its reader", async () => {
    const { worker, namespace, environment } = setup({ timeoutMs: 10 });
    let canceled = false;
    const body = new ReadableStream<Uint8Array>({ pull: () => new Promise(() => undefined), cancel: () => { canceled = true; } });
    const request = new Request(`http://native.local${TRANSACTION_PATH}`, { method: "POST", body, duplex: "half",
      headers: { "content-type": TRANSACTION_TYPE, [KEY_HEADER]: KEY_ID, [SIGNATURE_HEADER]: "0".repeat(64) } } as RequestInit);
    expect((await worker.fetch(request, environment)).status).toBe(503);
    expect(canceled).toBe(true);
    expect(namespace.calls).toBe(0);
  });

  it("rejects authenticated noncanonical bytes, oversized input and incorrect HTTP framing before a source call", async () => {
    const { worker, namespace, environment } = setup({ bounds: { maxTransactionBytes: 1024 } });
    const keys = await storageDirectionalKeys(ROOT_KEY);
    const canonical = encodeCanonicalCbor(wireEnvelope("snapshot", { objectId: OBJECT_ID }));
    // Replace the canonical eight-entry map head by a non-minimal map head.
    const noncanonical = new Uint8Array(canonical.byteLength + 1);
    noncanonical.set([0xb8, 8]); noncanonical.set(canonical.slice(1), 2);
    for (const raw of [new Uint8Array([0xff]), noncanonical, new Uint8Array(1025)]) {
      const request = new Request(`http://native.local${TRANSACTION_PATH}`, { method: "POST", body: raw,
        headers: { "content-type": TRANSACTION_TYPE, [KEY_HEADER]: KEY_ID,
          [SIGNATURE_HEADER]: await storageRequestMac(keys.request, KEY_ID, raw) } });
      expect((await worker.fetch(request, environment)).status).toBe(400);
    }
    for (const mutate of [
      (request: Request) => request.headers.set("content-encoding", "gzip"),
      (request: Request) => request.headers.set("content-type", "application/cbor"),
      (request: Request) => request.headers.set("content-length", "1"),
    ]) {
      const request = await authenticatedRequest(wireEnvelope("snapshot", { objectId: OBJECT_ID }));
      mutate(request);
      expect((await worker.fetch(request, environment)).status).toBe(400);
    }
    expect(namespace.calls).toBe(0);
  });

  it("bounds pending gated fetch waiting without claiming the remote isolate terminated", async () => {
    const { worker, namespace, environment } = setup({ timeoutMs: 10 });
    let signal: AbortSignal | undefined;
    namespace.fetcher = async (_id, request) => { signal = request.signal; return new Promise(() => undefined); };
    const request = await authenticatedRequest(wireEnvelope("snapshot", { objectId: OBJECT_ID }));
    const response = await worker.fetch(request.clone(), environment);
    expect(response.status).toBe(503);
    expect(response.headers.get(SIGNATURE_HEADER)).toBeNull();
    expect(signal?.aborted).toBe(true);
  });

  it("handles caller cancellation while the native fetch remains pending", async () => {
    const { worker, namespace, environment } = setup();
    const entered = deferred(), abort = new AbortController();
    namespace.fetcher = async () => { entered.resolve(); return new Promise(() => undefined); };
    const request = await authenticatedRequest(wireEnvelope("snapshot", { objectId: OBJECT_ID }));
    const pending = worker.fetch(new Request(request.clone(), { signal: abort.signal }), environment);
    await entered.promise; abort.abort();
    const response = await pending;
    expect(response.status).toBe(503); expect(response.headers.get(SIGNATURE_HEADER)).toBeNull();
  });

  it("bounds pending response MAC signing within the whole request deadline", async () => {
    const { worker, environment } = setup({ timeoutMs: 50 });
    const request = await authenticatedRequest(wireEnvelope("snapshot", { objectId: OBJECT_ID }));
    const nativeSign = crypto.subtle.sign.bind(crypto.subtle);
    let responseSigningStarted = false;
    const sign = vi.spyOn(crypto.subtle, "sign").mockImplementation((algorithm, key, data) => {
      const raw = ArrayBuffer.isView(data) ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength) : new Uint8Array(data);
      if (new TextDecoder().decode(raw).includes("circulusd.native-storage.response.v1")) {
        responseSigningStarted = true;
        return new Promise(() => undefined);
      }
      return nativeSign(algorithm, key, data);
    });
    try {
      const response = await worker.fetch(request, environment);
      expect(responseSigningStarted).toBe(true);
      expect(response.status).toBe(503);
      expect(response.headers.get(SIGNATURE_HEADER)).toBeNull();
    } finally { sign.mockRestore(); }
  });

  it("validates returned identities, schema, state hash and notCommitted claims before signing", async () => {
    const { worker, namespace, environment } = setup();
    const value = wireEnvelope("snapshot", { objectId: OBJECT_ID });
    const digest = await requestDigest(value);
    const correct = { protocol: STORAGE_PROTOCOL, major: 1, minor: 0, schemaDigest: STORAGE_SCHEMA,
      requestId: value.requestId, requestDigest: digest, payload: { ok: true, result: {
        snapshot: { objectId: OBJECT_ID, exists: false, revision: 0, stateDigest: EMPTY_DIGEST }, state: new Uint8Array(),
      } } };
    for (const reply of [
      { ...correct, schemaDigest: EMPTY_DIGEST }, { ...correct, requestDigest: EMPTY_DIGEST },
      { ...correct, payload: { ok: true, result: { ...correct.payload.result, state: new Uint8Array([1]) } } },
      { ...correct, payload: { ok: false, error: "SNAPSHOT_CONFLICT", notCommitted: true } },
    ]) {
      namespace.fetcher = async () => new Response(encodeCanonicalCbor(reply), { status: reply.payload.ok ? 200 : 409,
        headers: { "content-type": TRANSACTION_TYPE, "cache-control": "no-store" } });
      const request = await authenticatedRequest(value);
      expect(await verifyResponse(await worker.fetch(request.clone(), environment), request)).toEqual({ ok: false, error: "UNAVAILABLE", notCommitted: false });
    }
  });

  it("rejects wrong physical DO before storage and snapshots mutable deployment config", async () => {
    const mutableKey = Uint8Array.from(ROOT_KEY), bounds = { maxStateBytes: 32 };
    const { worker, namespace, storage, environment, Cell } = setup({ rootKey: mutableKey, bounds });
    mutableKey.fill(0); bounds.maxStateBytes = 1;
    namespace.fetcher = async (_id, request) => new Cell(namespace.state(storage, "wrong-object"), environment).fetch(request);
    const request = await authenticatedRequest(wireEnvelope("snapshot", { objectId: OBJECT_ID }));
    expect(await verifyResponse(await worker.fetch(request.clone(), environment), request)).toEqual({ ok: false, error: "INVALID_ARGUMENT", notCommitted: true });
    expect(storage.calls).toBe(0);
  });

  it("returns503 when actual native production proof forwarding is absent", async () => {
    const { worker, environment, namespace } = setup();
    expect((await worker.fetch(probeRequest(), environment)).status).toBe(503);
    expect(namespace.calls).toBe(0);
  });

  it("forwards native proof bytes unchanged and never substitutes transport MACs for Ed25519", async () => {
    const native = encodeCanonicalCbor(proof());
    let calls = 0;
    const { worker, environment, namespace } = setup({ nativeProbe: async (request) => {
      calls++; expect(decodeCanonicalCbor(request)).toMatchObject({ nonce: new Uint8Array(32).fill(12) });
      return native;
    } });
    const response = await worker.fetch(probeRequest(), environment);
    expect(response.status).toBe(200);
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(native);
    expect(response.headers.get(SIGNATURE_HEADER)).toBeNull();
    expect(calls).toBe(1); expect(namespace.calls).toBe(0);
  });

  it("rejects malformed probe challenges and native proof schema/nonce/capability mismatches", async () => {
    let calls = 0;
    const { worker, environment } = setup({ nativeProbe: async () => { calls++; return encodeCanonicalCbor(proof()); } });
    const bad = probeRequest(); bad.headers.set(KEY_HEADER, KEY_ID);
    expect((await worker.fetch(bad, environment)).status).toBe(400); expect(calls).toBe(0);
    for (const native of [
      { ...proof(), nonce: new Uint8Array(32).fill(7) }, { ...proof(), schemaDigest: EMPTY_DIGEST },
      { ...proof(), signature: new Uint8Array(63) }, { ...proof(), descriptor: { ...(proof().descriptor as object), atomicGroups: ["command-receipt"] } },
      { ...proof(), descriptor: { ...(proof().descriptor as object), backendKind: "reference-memory" } },
    ]) {
      const attempt = setup({ nativeProbe: async () => encodeCanonicalCbor(native) });
      const response = await attempt.worker.fetch(probeRequest(), attempt.environment);
      expect(response.status).toBe(503); expect(response.headers.get(SIGNATURE_HEADER)).toBeNull();
    }
  });

  it("bounds native probe waiting and refuses invalid deployment credentials or budgets", async () => {
    const { worker, environment } = setup({ timeoutMs: 10, nativeProbe: async () => new Promise(() => undefined) });
    expect((await worker.fetch(probeRequest(), environment)).status).toBe(503);
    for (const config of [
      { keyId: "Bad", rootKey: ROOT_KEY }, { keyId: KEY_ID, rootKey: new Uint8Array(31) },
      { keyId: KEY_ID, rootKey: ROOT_KEY, timeoutMs: 30_001 },
      { keyId: KEY_ID, rootKey: ROOT_KEY, bounds: { maxStateBytes: (16 << 20) + 1 } },
    ]) expect(() => createNativeStorageWorker(config)).toThrow();
    expect(() => createNativeStorageDurableObjectClass({}, { keyId: KEY_ID, rootKey: ROOT_KEY })).toThrow();
  });
});
