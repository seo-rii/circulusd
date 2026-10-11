import { digestBytes, type Digest } from "@circulusd/protocol-types";
import type { PiGenesisRequest, PiGenesisResult } from "./genesis.ts";
import {
  GENESIS_PATH, GENESIS_TYPE, KEY_HEADER, MAXIMUM_PROBE_BYTES, MAXIMUM_PROBE_REQUEST_BYTES,
  MAXIMUM_REQUEST_BYTES, MAXIMUM_RESPONSE_BYTES, PROBE_PATH, PROBE_TYPE, SIGNATURE_HEADER,
  decodeGenesisWire, encodeGenesisReply, encodeGenesisWire, equalGenesisMac, genesisDirectionalKeys,
  genesisRequestMac, genesisResponseMac, genesisSuccessPayload, parseGenesisEnvelope,
  parseGenesisProbeRequest, validateGenesisProbeResponse,
} from "./genesis-wire.ts";
import { PiRuntimeError } from "./errors.ts";

export interface CelldPiGenesisWorkerConfig {
  readonly keyId: string;
  readonly rootKey: Uint8Array;
  readonly source: {
    createGenesis(request: PiGenesisRequest, signal?: AbortSignal): Promise<PiGenesisResult>;
  };
  readonly timeoutMs?: number;
  readonly now?: () => number;
  readonly nativeProbe?: (request: Uint8Array, signal: AbortSignal) => Promise<Uint8Array>;
}
interface Scope {
  readonly signal: AbortSignal;
  await<T>(promise: Promise<T>): Promise<T>;
  close(): void;
}
interface ReplyBinding { readonly requestId: string; readonly requestDigest: Digest; readonly requestBytes: Uint8Array }
function invalidConfig(): never { throw new PiRuntimeError("INVALID_CONFIGURATION", "invalid Pi genesis worker configuration"); }
function unavailable(): PiRuntimeError { return new PiRuntimeError("INVALID_CONTEXT", "Pi genesis worker unavailable"); }
function plain(status: number): Response {
  return new Response("Pi genesis operation unavailable.", { status, headers: { "cache-control": "no-store" } });
}
function requestScope(request: Request, timeoutMs: number): Scope {
  const controller = new AbortController(), abort = () => controller.abort(unavailable());
  if (request.signal.aborted) abort();
  else request.signal.addEventListener("abort", abort, { once: true });
  const timer = setTimeout(abort, timeoutMs);
  return {
    signal: controller.signal,
    await: <T>(promise: Promise<T>) => new Promise<T>((resolve, reject) => {
      const failed = () => reject(unavailable());
      if (controller.signal.aborted) { void promise.catch(() => undefined); failed(); return; }
      controller.signal.addEventListener("abort", failed, { once: true });
      void promise.then(resolve, reject).finally(() => controller.signal.removeEventListener("abort", failed));
    }),
    close: () => { clearTimeout(timer); request.signal.removeEventListener("abort", abort); },
  };
}
function declaredSize(request: Request, maximum: number): boolean {
  const value = request.headers.get("content-length");
  return value === null || (/^(0|[1-9][0-9]*)$/.test(value) && Number(value) <= maximum);
}
async function readBody(request: Request, maximum: number, scope: Scope): Promise<Uint8Array> {
  if (!request.body) return new Uint8Array();
  const reader = request.body.getReader(), parts: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const next = await scope.await(reader.read());
      if (next.done) break;
      if (!(next.value instanceof Uint8Array) || next.value.byteLength > maximum - size) throw unavailable();
      parts.push(Uint8Array.from(next.value)); size += next.value.byteLength;
    }
  } catch (error) { void reader.cancel().catch(() => undefined); throw error; }
  finally { reader.releaseLock(); }
  const declared = request.headers.get("content-length");
  if (declared !== null && Number(declared) !== size) throw unavailable();
  const body = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) { body.set(part, offset); offset += part.byteLength; }
  return body;
}

// The supplied source must enforce its independently verified immutable runtime
// modules/configuration (for example CelldPiGenesisSource). This HTTP wrapper's
// operational MAC and descriptor pin cannot qualify that source, its native
// Loader/isolation or engine-genesis capability. Go verifies external evidence.
export function createCelldPiGenesisWorker(config: CelldPiGenesisWorkerConfig): { fetch(request: Request): Promise<Response> } {
  const source = config?.source, sourceMethod = source?.createGenesis;
  if (!config || typeof config.keyId !== "string" || !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(config.keyId) ||
      !(config.rootKey instanceof Uint8Array) || config.rootKey.byteLength < 32 || config.rootKey.byteLength > 256 ||
      typeof sourceMethod !== "function" ||
      (config.nativeProbe !== undefined && typeof config.nativeProbe !== "function") ||
      (config.now !== undefined && typeof config.now !== "function")) invalidConfig();
  const timeoutMs = config.timeoutMs ?? 30_000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30_000) invalidConfig();
  const keyId = config.keyId, keys = genesisDirectionalKeys(Uint8Array.from(config.rootKey));
  const createGenesis = sourceMethod.bind(source);
  const nativeProbe = config.nativeProbe, now = config.now ?? Date.now;
  let pinnedDescriptor: Digest | undefined;

  async function reply(binding: ReplyBinding, payload: unknown, status: number, scope: Scope): Promise<Response> {
    if (scope.signal.aborted) return plain(503);
    try {
      const body = encodeGenesisReply(binding.requestId, binding.requestDigest, payload);
      if (body.byteLength > MAXIMUM_RESPONSE_BYTES) return plain(503);
      const directional = await scope.await(keys);
      if (scope.signal.aborted) return plain(503);
      const signature = await scope.await(genesisResponseMac(directional.response, keyId, binding.requestId, binding.requestBytes, status, body));
      if (scope.signal.aborted) return plain(503);
      return new Response(Uint8Array.from(body), { status, headers: { "content-type": GENESIS_TYPE,
        "cache-control": "no-store", [KEY_HEADER]: keyId, [SIGNATURE_HEADER]: signature } });
    } catch { return plain(503); }
  }
  async function probe(request: Request, scope: Scope): Promise<Response> {
    let body: Uint8Array, nonce: Uint8Array;
    try { body = await readBody(request, MAXIMUM_PROBE_REQUEST_BYTES, scope); nonce = parseGenesisProbeRequest(body); }
    catch { return plain(scope.signal.aborted ? 503 : 400); }
    if (!nativeProbe || scope.signal.aborted) return plain(503);
    try {
      const returned = await scope.await(nativeProbe(Uint8Array.from(body), scope.signal));
      if (!(returned instanceof Uint8Array) || returned.byteLength > MAXIMUM_PROBE_BYTES) return plain(503);
      const retained = Uint8Array.from(returned);
      const descriptor = validateGenesisProbeResponse(retained, nonce);
      if (descriptor.runtimeKeyId === keyId) return plain(503);
      const digest = await scope.await(digestBytes(encodeGenesisWire(descriptor, MAXIMUM_PROBE_BYTES)));
      if (scope.signal.aborted) return plain(503);
      // Assignment is synchronous after hashing, so concurrent first probes
      // cannot pin different descriptors. Every complete descriptor field binds.
      if (pinnedDescriptor !== undefined && pinnedDescriptor !== digest) return plain(503);
      pinnedDescriptor = digest;
      if (scope.signal.aborted) return plain(503);
      // Return the actual original native response bytes. No private runtime
      // key, new Ed25519 signature or production eligibility is created here.
      return new Response(retained, { status: 200, headers: { "content-type": PROBE_TYPE, "cache-control": "no-store" } });
    } catch { return plain(503); }
  }
  return { fetch: async (request) => {
    const url = new URL(request.url);
    if ((url.pathname !== GENESIS_PATH && url.pathname !== PROBE_PATH) || url.href.includes("?") || url.href.includes("#")) return plain(404);
    if (request.method !== "POST" || request.headers.has("content-encoding")) return plain(405);
    const isProbe = url.pathname === PROBE_PATH;
    const maximum = isProbe ? MAXIMUM_PROBE_REQUEST_BYTES : MAXIMUM_REQUEST_BYTES;
    const contentType = isProbe ? PROBE_TYPE : GENESIS_TYPE;
    if (isProbe && (request.headers.has(KEY_HEADER) || request.headers.has(SIGNATURE_HEADER))) return plain(400);
    const signature = request.headers.get(SIGNATURE_HEADER);
    if (!isProbe && (request.headers.get(KEY_HEADER) !== keyId || signature === null || !/^[0-9a-f]{64}$/.test(signature))) return plain(401);
    if (request.headers.get("content-type") !== contentType || !declaredSize(request, maximum)) return plain(400);
    const scope = requestScope(request, timeoutMs);
    try {
      if (isProbe) return await probe(request, scope);
      let body: Uint8Array;
      try { body = await readBody(request, maximum, scope); } catch { return plain(scope.signal.aborted ? 503 : 400); }
      const directional = await scope.await(keys);
      const expected = await scope.await(genesisRequestMac(directional.request, keyId, body));
      if (!equalGenesisMac(signature!, expected)) return plain(401);
      let envelope: Awaited<ReturnType<typeof parseGenesisEnvelope>>;
      try { envelope = await scope.await(parseGenesisEnvelope(decodeGenesisWire(body, maximum), now())); }
      catch { return plain(scope.signal.aborted ? 503 : 400); }
      const binding: ReplyBinding = { requestId: envelope.requestId, requestDigest: envelope.requestDigest, requestBytes: body };
      if (scope.signal.aborted) return plain(503);
      const retained = structuredClone(envelope.request);
      let result: unknown;
      try { result = await scope.await(createGenesis(structuredClone(retained), scope.signal)); }
      catch { return await reply(binding, { ok: false, error: "UNAVAILABLE" }, 503, scope); }
      let payload: unknown;
      try { payload = await scope.await(genesisSuccessPayload(result, retained)); }
      catch { return await reply(binding, { ok: false, error: "BAD_SOURCE" }, 503, scope); }
      return await reply(binding, payload, 200, scope);
    } catch { return plain(503); }
    finally { scope.close(); }
  } };
}
