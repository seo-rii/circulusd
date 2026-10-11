import { decodeCanonicalCbor, digestBytes, isDigest, type Digest } from "@circulusd/protocol-types";
import {
  KEY_HEADER, MAXIMUM_PROBE_BYTES, PROBE_PATH, PROBE_PROTOCOL, PROBE_SCHEMA, PROBE_TYPE,
  REQUEST_ID_PATTERN, SIGNATURE_HEADER, STORAGE_PROTOCOL, STORAGE_SCHEMA, TRANSACTION_PATH, TRANSACTION_TYPE,
  WIRE_OPTIONS, bytes, commitToken, decodeWire, encodeWire, envelopeObjectId, equalMac,
  parseBarrierRequest, parseCommitRequest, parseEnvelope, parseReceiptRequest, record, requestDigest,
  revision, snapshotRef, storageDirectionalKeys, storageRequestMac, storageResponseMac, storedReceipt,
  type StorageEnvelope,
} from "./codec.ts";
import { NativeStorageKernel, nativeStorageObjectName } from "./kernel.ts";
import {
  NativeStorageError, resolveNativeStorageBounds, type NativeStorageBounds,
  type NativeStorageBoundsInput, type NativeStorageEnvironment, type NativeStorageErrorCode,
  type NativeStorageState,
} from "./types.ts";

export interface NativeStorageWorkerConfig {
  readonly keyId: string;
  readonly rootKey: Uint8Array;
  readonly bounds?: NativeStorageBoundsInput;
  readonly timeoutMs?: number;
  readonly now?: () => number;
  // This port must forward the real native challenge response. Its presence
  // grants no qualification: Go still verifies the external Ed25519 proof.
  readonly nativeProbe?: (request: Uint8Array, signal: AbortSignal) => Promise<Uint8Array>;
}
interface RetainedConfig {
  readonly keyId: string;
  readonly keys: ReturnType<typeof storageDirectionalKeys>;
  readonly bounds: NativeStorageBounds;
  readonly timeoutMs: number;
  readonly now: () => number;
  readonly nativeProbe: NativeStorageWorkerConfig["nativeProbe"];
}
interface Scope {
  readonly signal: AbortSignal;
  await<T>(promise: Promise<T>): Promise<T>;
  close(): void;
}
interface AuthContext {
  readonly bytes: Uint8Array;
  readonly digest: Digest;
  readonly requestId: string;
}
interface AuthenticatedRequest extends AuthContext {
  readonly envelope: StorageEnvelope;
}
class InvalidAuthenticatedRequest extends Error {
  constructor(readonly context: AuthContext) { super("Native storage request invalid."); }
}
function configSnapshot(config: NativeStorageWorkerConfig): RetainedConfig {
  if (!config || typeof config.keyId !== "string" || !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(config.keyId) ||
      !(config.rootKey instanceof Uint8Array) || config.rootKey.byteLength !== 32 ||
      (config.now !== undefined && typeof config.now !== "function") ||
      (config.nativeProbe !== undefined && typeof config.nativeProbe !== "function")) {
    throw new NativeStorageError("INVALID_ARGUMENT");
  }
  const timeoutMs = config.timeoutMs ?? 30_000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30_000) throw new NativeStorageError("INVALID_ARGUMENT");
  return Object.freeze({ keyId: config.keyId, keys: storageDirectionalKeys(Uint8Array.from(config.rootKey)),
    bounds: resolveNativeStorageBounds(config.bounds), timeoutMs, now: config.now ?? Date.now, nativeProbe: config.nativeProbe });
}
function scopeFor(request: Request, timeoutMs: number): Scope {
  const controller = new AbortController();
  const abort = () => controller.abort(new NativeStorageError("UNAVAILABLE"));
  if (request.signal.aborted) abort();
  else request.signal.addEventListener("abort", abort, { once: true });
  const timer = setTimeout(abort, timeoutMs);
  return {
    signal: controller.signal,
    await: <T>(promise: Promise<T>) => new Promise<T>((resolve, reject) => {
      const fail = () => reject(new NativeStorageError("UNAVAILABLE"));
      if (controller.signal.aborted) {
        void promise.catch(() => undefined); fail(); return;
      }
      controller.signal.addEventListener("abort", fail, { once: true });
      void promise.then(resolve, reject).finally(() => controller.signal.removeEventListener("abort", fail));
    }),
    close: () => { clearTimeout(timer); request.signal.removeEventListener("abort", abort); },
  };
}
function plain(status: number): Response {
  return new Response("Native storage unavailable.", { status, headers: { "cache-control": "no-store" } });
}
function pathAllowed(request: Request, path: string, contentType: string): boolean {
  const url = new URL(request.url);
  return request.method === "POST" && url.pathname === path && url.search === "" && url.hash === "" &&
    request.headers.get("content-type") === contentType && !request.headers.has("content-encoding");
}
async function readBody(request: Pick<Request, "headers" | "body">, maximum: number, scope: Scope): Promise<Uint8Array> {
  const declared = request.headers.get("content-length");
  if (declared !== null && (!/^(0|[1-9][0-9]*)$/.test(declared) || Number(declared) > maximum)) throw new NativeStorageError("INVALID_ARGUMENT");
  if (request.body === null) return new Uint8Array();
  const reader = request.body.getReader(), pieces: Uint8Array[] = [];
  let length = 0;
  try {
    for (;;) {
      const part = await scope.await(reader.read());
      if (part.done) break;
      if (!(part.value instanceof Uint8Array) || part.value.byteLength > maximum - length) throw new NativeStorageError("INVALID_ARGUMENT");
      pieces.push(Uint8Array.from(part.value)); length += part.value.byteLength;
    }
  } catch (error) {
    void reader.cancel().catch(() => undefined);
    throw error;
  } finally { reader.releaseLock(); }
  if (declared !== null && Number(declared) !== length) throw new NativeStorageError("INVALID_ARGUMENT");
  const result = new Uint8Array(length);
  let offset = 0;
  for (const piece of pieces) { result.set(piece, offset); offset += piece.byteLength; }
  return result;
}
async function authenticate(request: Request, config: RetainedConfig, scope: Scope): Promise<AuthenticatedRequest | Response> {
  if (!pathAllowed(request, TRANSACTION_PATH, TRANSACTION_TYPE)) return plain(400);
  const keyId = request.headers.get(KEY_HEADER), signature = request.headers.get(SIGNATURE_HEADER);
  // Reject malformed credentials before touching the body or native source.
  if (keyId !== config.keyId || signature === null || !/^[0-9a-f]{64}$/.test(signature)) return plain(401);
  const body = await readBody(request, config.bounds.maxTransactionBytes, scope);
  const keys = await scope.await(config.keys);
  if (!equalMac(signature, await scope.await(storageRequestMac(keys.request, config.keyId, body)))) return plain(401);
  const value = decodeWire(body, config.bounds);
  if (typeof value !== "object" || value === null || !Object.hasOwn(value, "requestId") ||
      typeof (value as Record<string, unknown>).requestId !== "string" ||
      !REQUEST_ID_PATTERN.test((value as Record<string, string>).requestId!)) throw new NativeStorageError("INVALID_ARGUMENT");
  const requestId = (value as Record<string, string>).requestId!;
  const digest = await scope.await(requestDigest(value));
  let envelope: StorageEnvelope;
  try { envelope = await scope.await(parseEnvelope(value, config.bounds, config.now())); }
  catch {
    if (scope.signal.aborted) throw new NativeStorageError("UNAVAILABLE");
    throw new InvalidAuthenticatedRequest({ bytes: body, digest, requestId });
  }
  return { bytes: body, digest, requestId, envelope };
}
function failure(error: unknown): { readonly status: number; readonly payload: unknown } {
  const code = error instanceof NativeStorageError ? error.code : "UNAVAILABLE";
  const status = code === "INVALID_ARGUMENT" ? 400 :
    code === "SNAPSHOT_CONFLICT" || code === "RECEIPT_CONFLICT" ? 409 : 503;
  return { status, payload: { ok: false, error: code, notCommitted: code !== "UNAVAILABLE" } };
}
function responseBytes(input: AuthContext, payload: unknown, bounds: NativeStorageBounds): Uint8Array {
  return encodeWire({ protocol: STORAGE_PROTOCOL, major: 1, minor: 0, schemaDigest: STORAGE_SCHEMA,
    requestId: input.requestId, requestDigest: input.digest, payload }, bounds);
}
function unsigned(body: Uint8Array, status: number): Response {
  return new Response(Uint8Array.from(body), { status, headers: { "content-type": TRANSACTION_TYPE, "cache-control": "no-store" } });
}
async function signed(input: AuthContext, config: RetainedConfig, body: Uint8Array, status: number): Promise<Response> {
  const keys = await config.keys;
  const signature = await storageResponseMac(keys.response, config.keyId, input.requestId, input.bytes, status, body);
  return new Response(Uint8Array.from(body), { status, headers: { "content-type": TRANSACTION_TYPE,
    "cache-control": "no-store", [KEY_HEADER]: config.keyId, [SIGNATURE_HEADER]: signature } });
}
async function signedWithinScope(input: AuthContext, config: RetainedConfig, body: Uint8Array,
  status: number, scope: Scope): Promise<Response> {
  if (scope.signal.aborted) return plain(503);
  try { return await scope.await(signed(input, config, body, status)); }
  catch { return plain(503); }
}
function sameRef(left: unknown, right: unknown): boolean {
  const a = snapshotRef(left), b = snapshotRef(right);
  return a.objectId === b.objectId && a.exists === b.exists && a.revision === b.revision && a.stateDigest === b.stateDigest;
}
function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.byteLength === right.byteLength && left.every((value, index) => value === right[index]);
}
async function validateResult(result: unknown, input: StorageEnvelope, bounds: NativeStorageBounds): Promise<void> {
  switch (input.operation) {
    case "snapshot": {
      const value = record(result, ["snapshot", "state"]), snapshot = snapshotRef(value.snapshot);
      const state = bytes(value.state, bounds.maxStateBytes);
      if (snapshot.objectId !== envelopeObjectId(input) || (!snapshot.exists && state.byteLength !== 0) ||
          await digestBytes(state) !== snapshot.stateDigest) throw new NativeStorageError("UNAVAILABLE");
      return;
    }
    case "receipt": {
      const value = record(result, ["snapshot", "commandId", "found", "receipt"]), expected = parseReceiptRequest(input.body);
      if (!sameRef(value.snapshot, expected.snapshot) || value.commandId !== expected.commandId || typeof value.found !== "boolean" ||
          (!value.found && value.receipt !== null)) throw new NativeStorageError("UNAVAILABLE");
      if (value.found) storedReceipt(value.receipt, bounds);
      return;
    }
    case "commit": {
      const value = record(result, ["snapshot", "requestDigest", "token"]), expected = await parseCommitRequest(input.body, bounds);
      const snapshot = snapshotRef(value.snapshot), token = commitToken(value.token);
      const digest = expected.stateWritten ? await digestBytes(expected.state) : expected.snapshot.stateDigest;
      if (!snapshot.exists || snapshot.objectId !== expected.snapshot.objectId || snapshot.revision !== expected.snapshot.revision + 1 ||
          snapshot.stateDigest !== digest || token.objectId !== snapshot.objectId || token.revision !== snapshot.revision ||
          value.requestDigest !== expected.requestDigest) throw new NativeStorageError("UNAVAILABLE");
      return;
    }
    case "barrier": {
      const value = record(result, ["token", "marker", "observedRevision", "barrierSerial"]), expected = parseBarrierRequest(input.body);
      const token = commitToken(value.token), marker = bytes(value.marker, 32);
      if (token.objectId !== expected.token.objectId || token.revision !== expected.token.revision || !sameBytes(marker, expected.marker) ||
          revision(value.observedRevision, 1) < token.revision) throw new NativeStorageError("UNAVAILABLE");
      revision(value.barrierSerial, 1);
      return;
    }
  }
}
async function validateNativeResponse(response: Response, input: AuthenticatedRequest, config: RetainedConfig, scope: Scope): Promise<Uint8Array> {
  if (response.headers.get("content-type") !== TRANSACTION_TYPE || response.headers.has("content-encoding") ||
      response.headers.get("cache-control") !== "no-store") throw new NativeStorageError("UNAVAILABLE");
  const body = await readBody(response, config.bounds.maxTransactionBytes, scope);
  const envelope = record(decodeWire(body, config.bounds), ["protocol", "major", "minor", "schemaDigest", "requestId", "requestDigest", "payload"]);
  if (envelope.protocol !== STORAGE_PROTOCOL || envelope.major !== 1 || envelope.minor !== 0 || envelope.schemaDigest !== STORAGE_SCHEMA ||
      envelope.requestId !== input.envelope.requestId || envelope.requestDigest !== input.digest) throw new NativeStorageError("UNAVAILABLE");
  const payload = envelope.payload;
  if (response.status === 200) {
    const value = record(payload, ["ok", "result"]);
    if (value.ok !== true) throw new NativeStorageError("UNAVAILABLE");
    await validateResult(value.result, input.envelope, config.bounds);
  } else {
    const value = record(payload, ["ok", "error", "notCommitted"]);
    const codes: NativeStorageErrorCode[] = ["INVALID_ARGUMENT", "SNAPSHOT_CONFLICT", "RECEIPT_CONFLICT", "CORRUPT_STATE", "UNAVAILABLE"];
    if (value.ok !== false || !codes.includes(value.error as NativeStorageErrorCode) ||
        (value.error === "SNAPSHOT_CONFLICT" && !["receipt", "commit"].includes(input.envelope.operation)) ||
        (value.error === "RECEIPT_CONFLICT" && input.envelope.operation !== "commit")) throw new NativeStorageError("UNAVAILABLE");
    const expected = failure(new NativeStorageError(value.error as NativeStorageErrorCode));
    if (response.status !== expected.status || value.notCommitted !== (value.error !== "UNAVAILABLE")) throw new NativeStorageError("UNAVAILABLE");
  }
  return body;
}

function probeRequest(body: Uint8Array): Uint8Array {
  const value = record(decodeCanonicalCbor(body, { ...WIRE_OPTIONS, maxBytes: MAXIMUM_PROBE_BYTES }),
    ["protocol", "major", "minor", "schemaDigest", "nonce"]);
  if (value.protocol !== PROBE_PROTOCOL || value.major !== 1 || value.minor !== 0 || value.schemaDigest !== PROBE_SCHEMA) throw new NativeStorageError("INVALID_ARGUMENT");
  const nonce = bytes(value.nonce, 32);
  if (nonce.byteLength !== 32) throw new NativeStorageError("INVALID_ARGUMENT");
  return nonce;
}
function validateProbe(body: Uint8Array, nonce: Uint8Array): void {
  const value = record(decodeCanonicalCbor(body, { ...WIRE_OPTIONS, maxBytes: MAXIMUM_PROBE_BYTES }),
    ["protocol", "major", "minor", "schemaDigest", "nonce", "descriptor", "keyId", "signature"]);
  if (value.protocol !== PROBE_PROTOCOL || value.major !== 1 || value.minor !== 0 || value.schemaDigest !== PROBE_SCHEMA ||
      !sameBytes(bytes(value.nonce, 32), nonce) || bytes(value.signature, 64).byteLength !== 64) throw new NativeStorageError("UNAVAILABLE");
  const descriptor = record(value.descriptor, ["schemaVersion", "backendKind", "buildDigest", "applicationDigest", "instanceId",
    "transactionDomainId", "durabilityClass", "conformanceRunId", "conformanceDigest", "runtimeKeyId", "probeEpoch", "productionEligible", "atomicGroups"]);
  const id = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;
  if (descriptor.schemaVersion !== 1 || descriptor.backendKind !== "celld" || descriptor.durabilityClass !== "crash-durable-rpo0" ||
      descriptor.productionEligible !== true || !isDigest(descriptor.buildDigest) || !isDigest(descriptor.applicationDigest) ||
      !isDigest(descriptor.conformanceDigest) || typeof value.keyId !== "string" || !id.test(value.keyId) || value.keyId !== descriptor.runtimeKeyId ||
      ["instanceId", "transactionDomainId", "conformanceRunId", "runtimeKeyId"].some((key) => typeof descriptor[key] !== "string" || !id.test(descriptor[key])) ||
      !Array.isArray(descriptor.atomicGroups) || descriptor.atomicGroups.length > 64 ||
      !descriptor.atomicGroups.includes("native-storage") || !descriptor.atomicGroups.includes("command-receipt")) throw new NativeStorageError("UNAVAILABLE");
  revision(descriptor.probeEpoch, 1);
  let previous = "";
  for (const group of descriptor.atomicGroups) {
    if (typeof group !== "string" || !id.test(group) || group <= previous) throw new NativeStorageError("UNAVAILABLE");
    previous = group;
  }
}
async function handleProbe(request: Request, config: RetainedConfig, scope: Scope): Promise<Response> {
  if (!pathAllowed(request, PROBE_PATH, PROBE_TYPE) || request.headers.has(KEY_HEADER) || request.headers.has(SIGNATURE_HEADER)) return plain(400);
  let body: Uint8Array, nonce: Uint8Array;
  try { body = await readBody(request, MAXIMUM_PROBE_BYTES, scope); nonce = probeRequest(body); }
  catch { return plain(scope.signal.aborted ? 503 : 400); }
  if (!config.nativeProbe) return plain(503);
  try {
    const result = bytes(await scope.await(config.nativeProbe(Uint8Array.from(body), scope.signal)), MAXIMUM_PROBE_BYTES);
    validateProbe(result, nonce);
    // Preserve actual Ed25519 native bytes; never mint a signature or readiness.
    return new Response(Uint8Array.from(result), { status: 200, headers: { "content-type": PROBE_TYPE, "cache-control": "no-store" } });
  } catch { return plain(503); }
}

export function createNativeStorageWorker(config: NativeStorageWorkerConfig): {
  fetch(request: Request, environment: NativeStorageEnvironment): Promise<Response>;
} {
  const retained = configSnapshot(config);
  return { fetch: async (request, environment) => {
    const scope = scopeFor(request, retained.timeoutMs);
    let authenticated: AuthenticatedRequest | undefined;
    try {
      if (new URL(request.url).pathname === PROBE_PATH) return await handleProbe(request, retained, scope);
      const input = await authenticate(request, retained, scope);
      if (input instanceof Response) return input;
      authenticated = input;
      if (scope.signal.aborted) throw new NativeStorageError("UNAVAILABLE");
      const namespace = environment?.NATIVE_STORAGE;
      if (typeof namespace?.idFromName !== "function" || typeof namespace.get !== "function") throw new NativeStorageError("UNAVAILABLE");
      const id = namespace.idFromName(nativeStorageObjectName(envelopeObjectId(input.envelope)));
      const forwarded = new Request(request.url, { method: "POST", headers: request.headers,
        body: Uint8Array.from(input.bytes), signal: scope.signal });
      // Native stub.fetch includes the inline and routed DO response gate.
      // Never replace it with RPC: pinned inline RPC omits that native gate.
      const response = await scope.await(namespace.get(id).fetch(forwarded));
      const body = await scope.await(validateNativeResponse(response, input, retained, scope));
      return await signedWithinScope(input, retained, body, response.status, scope);
    } catch (error) {
      if (error instanceof InvalidAuthenticatedRequest) {
        const failed = failure(new NativeStorageError("INVALID_ARGUMENT"));
        return await signedWithinScope(error.context, retained, responseBytes(error.context, failed.payload, retained.bounds), failed.status, scope);
      }
      if (!authenticated) return plain(error instanceof NativeStorageError && error.code === "INVALID_ARGUMENT" ? 400 : 503);
      const failed = failure(new NativeStorageError("UNAVAILABLE"));
      return await signedWithinScope(authenticated, retained, responseBytes(authenticated, failed.payload, retained.bounds), failed.status, scope);
    } finally { scope.close(); }
  } };
}

// A small deployment wrapper supplies the actual native DurableObject base,
// credential config and namespace binding. No production proof is constructed.
export function createNativeStorageDurableObjectClass(base: unknown, config: NativeStorageWorkerConfig):
  new (state: NativeStorageState, environment: NativeStorageEnvironment) => { fetch(request: Request): Promise<Response> } {
  if (typeof base !== "function" || !base.prototype) throw new NativeStorageError("INVALID_ARGUMENT");
  const retained = configSnapshot(config);
  const NativeBase = base as new (state: NativeStorageState, environment: NativeStorageEnvironment) => object;
  return class extends NativeBase {
    private readonly kernel: NativeStorageKernel;
    constructor(state: NativeStorageState, environment: NativeStorageEnvironment) {
      super(state, environment);
      this.kernel = new NativeStorageKernel(state, environment.NATIVE_STORAGE, retained.bounds);
    }
    async fetch(request: Request): Promise<Response> {
      const scope = scopeFor(request, retained.timeoutMs);
      let input: AuthenticatedRequest | undefined;
      let operationFinished = false;
      try {
        const authenticated = await authenticate(request, retained, scope);
        if (authenticated instanceof Response) return authenticated;
        input = authenticated;
        if (scope.signal.aborted) throw new NativeStorageError("UNAVAILABLE");
        let result: unknown;
        switch (input.envelope.operation) {
          case "snapshot": result = await scope.await(this.kernel.readSnapshot(input.envelope.body)); break;
          case "receipt": result = await scope.await(this.kernel.lookupReceipt(input.envelope.body)); break;
          case "commit": result = await scope.await(this.kernel.compareAndCommit(input.envelope.body)); break;
          case "barrier": result = await scope.await(this.kernel.confirmBarrier(input.envelope.body)); break;
        }
        operationFinished = true;
        return unsigned(responseBytes(input, { ok: true, result }, retained.bounds), 200);
      } catch (error) {
        if (error instanceof InvalidAuthenticatedRequest) {
          const failed = failure(new NativeStorageError("INVALID_ARGUMENT"));
          return unsigned(responseBytes(error.context, failed.payload, retained.bounds), failed.status);
        }
        if (!input) return plain(error instanceof NativeStorageError && error.code === "INVALID_ARGUMENT" ? 400 : 503);
        const failed = failure(scope.signal.aborted || operationFinished ? new NativeStorageError("UNAVAILABLE") : error);
        return unsigned(responseBytes(input, failed.payload, retained.bounds), failed.status);
      } finally { scope.close(); }
    }
  };
}
