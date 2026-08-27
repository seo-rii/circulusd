import {
  decodeCanonicalCbor,
  encodeCanonicalCbor,
  parseNormalizedValue,
  parseRpcEnvelope,
  PROTOCOL_MAJOR,
  PROTOCOL_MINOR,
  PROTOCOL_NAME,
  ProtocolValidationError,
  type NormalizedValue,
} from "@circulusd/protocol-types";

import { sessionCellName } from "./names.ts";
import {
  HOST_RPC_CONTRACTS,
  HOST_RPC_FALLBACK_REQUEST_ID,
  type HostRpcErrorCode,
} from "./rpc.ts";

const INGRESS_PATH = "/circulusd/state/v1/session-events:read";
const INGRESS_CONTENT_TYPE = "application/vnd.circulusd.state-ingress+cbor";
const INGRESS_PROTOCOL = "circulus.state-ingress.v1alpha1";
const INGRESS_SCHEMA_DIGEST =
  "sha256:6365dfa4e6e73b349508a46688cfcaacdeacece11cd11ed2d7f3e40af49ad3ee";
const INGRESS_REQUEST_FIELDS = Object.freeze([
  "protocol",
  "major",
  "minor",
  "schemaDigest",
  "requestId",
  "sentAtUnixMs",
  "tenantId",
  "actorSubjectId",
  "sessionId",
  "expectedAuthorizationGeneration",
  "afterSequence",
  "limit",
] as const);
const INGRESS_REQUEST_MAX_BYTES = 4_096;
const INGRESS_REQUEST_MAX_DEPTH = 2;
const INGRESS_REQUEST_MAX_ITEMS = 32;
const INGRESS_MAX_CLOCK_SKEW_MS = 30_000;
const INGRESS_MAX_EVENT_LIMIT = 256;
const KEY_ID_HEADER = "x-circulus-state-key-id";
const SIGNATURE_HEADER = "x-circulus-state-signature";
const REQUEST_MAC_DOMAIN = "circulusd.state-ingress.request.v1";
const RESPONSE_MAC_DOMAIN = "circulusd.state-ingress.response.v1";
const REQUEST_KEY_DOMAIN = "circulusd.state-ingress.key.request.v1\0";
const RESPONSE_KEY_DOMAIN = "circulusd.state-ingress.key.response.v1\0";
const KEY_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const SIGNATURE_PATTERN = /^[0-9a-f]{64}$/;
const REQUEST_ID_PATTERN = /^req_[A-Z2-7]{25}[AEIMQUY4]$/;
const TENANT_ID_PATTERN = /^tenant_[A-Z2-7]{25}[AEIMQUY4]$/;
const SUBJECT_ID_PATTERN = /^subject_[A-Z2-7]{25}[AEIMQUY4]$/;
const SESSION_ID_PATTERN = /^sess_[A-Z2-7]{25}[AEIMQUY4]$/;
const HOST_CONTRACT = HOST_RPC_CONTRACTS["session.read-events"];
const textEncoder = new TextEncoder();

const SAFE_HOST_ERROR_MESSAGES = Object.freeze({
  INVALID_ARGUMENT: "The RPC request is invalid.",
  NOT_FOUND: "The requested resource was not found.",
  ALREADY_EXISTS: "The requested resource already exists.",
  CONFLICT: "The operation conflicts with current state.",
  IDEMPOTENCY_CONFLICT: "The idempotency key conflicts with an earlier request.",
  PERMISSION_DENIED: "The operation is not permitted.",
  FAILED_PRECONDITION: "A required precondition was not satisfied.",
  STALE_GENERATION: "The supplied generation is stale.",
  STALE_DISPATCH_ATTEMPT: "The supplied dispatch attempt is stale.",
  DIGEST_MISMATCH: "A supplied digest does not match its value.",
  NEEDS_CONFIRMATION: "The operation requires confirmation.",
  ABORTED: "The operation was aborted.",
  LEASE_EXPIRED: "The supplied lease has expired.",
  RESOURCE_EXHAUSTED: "The RPC response exceeds its operation limit.",
  STORAGE_CONTRACT: "The durable storage contract is unavailable.",
  CELL_ID_MISMATCH: "The request was routed to the wrong durable cell.",
  NOT_INITIALIZED: "The durable aggregate is not initialized.",
  INITIALIZATION_CONFLICT: "The initialization conflicts with stored state.",
  STRUCTURED_CLONE_FAILED: "The value cannot cross the durable storage boundary.",
  CORRUPT_STATE: "The durable aggregate state is invalid.",
  INVALID_AGGREGATE_OUTPUT: "The aggregate produced an invalid result.",
  INTERNAL_ERROR: "The operation could not be completed.",
} as const satisfies Readonly<Record<HostRpcErrorCode, string>>);

type IngressSecretEnvironment = Env & {
  readonly CIRCULUSD_STATE_INGRESS_CURRENT_KEY_ID?: string;
  readonly CIRCULUSD_STATE_INGRESS_CURRENT_KEY?: string;
  readonly CIRCULUSD_STATE_INGRESS_PREVIOUS_KEY_ID?: string;
  readonly CIRCULUSD_STATE_INGRESS_PREVIOUS_KEY?: string;
};

interface ConfiguredKey {
  readonly keyId: string;
  readonly rootKey: Uint8Array;
}

interface CapturedDirectionalKeys {
  readonly keyId: string;
  readonly requestKey: CryptoKey;
  readonly responseKey: CryptoKey;
}

interface AuthenticatedResponseContext {
  readonly keys: CapturedDirectionalKeys;
  readonly requestBodyDigest: Uint8Array;
}

interface IngressRequest {
  readonly requestId: string;
  readonly sentAtUnixMs: number;
  readonly tenantId: string;
  readonly actorSubjectId: string;
  readonly sessionId: string;
  readonly expectedAuthorizationGeneration: number;
  readonly afterSequence: number;
  readonly limit: number;
}

function ordinaryBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function utf8(value: string): Uint8Array {
  return textEncoder.encode(value);
}

function hex(bytes: Uint8Array): string {
  let result = "";
  for (const byte of bytes) {
    result += byte.toString(16).padStart(2, "0");
  }
  return result;
}

function decodeHex(value: string): Uint8Array | undefined {
  if (value.length % 2 !== 0 || !/^[0-9a-f]+$/.test(value)) {
    return undefined;
  }
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < value.length; index += 2) {
    bytes[index / 2] = Number.parseInt(value.slice(index, index + 2), 16);
  }
  return bytes;
}

function lengthPrefixed(parts: readonly Uint8Array[]): Uint8Array {
  const length = parts.reduce((total, part) => total + 4 + part.byteLength, 0);
  const framed = new Uint8Array(length);
  const view = new DataView(framed.buffer);
  let offset = 0;
  for (const part of parts) {
    view.setUint32(offset, part.byteLength, false);
    offset += 4;
    framed.set(part, offset);
    offset += part.byteLength;
  }
  return framed;
}

async function sha256(value: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", ordinaryBuffer(value)));
}

async function hmac(
  key: CryptoKey,
  value: Uint8Array,
): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.sign("HMAC", key, ordinaryBuffer(value)),
  );
}

async function importHmacKey(
  bytes: Uint8Array,
  usages: readonly KeyUsage[],
): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    ordinaryBuffer(bytes),
    { hash: "SHA-256", name: "HMAC" },
    false,
    [...usages],
  );
}

async function captureDirectionalKeys(
  configured: ConfiguredKey,
): Promise<CapturedDirectionalKeys> {
  const rootKey = await importHmacKey(configured.rootKey, ["sign"]);
  const [requestKeyBytes, responseKeyBytes] = await Promise.all([
    hmac(rootKey, utf8(REQUEST_KEY_DOMAIN)),
    hmac(rootKey, utf8(RESPONSE_KEY_DOMAIN)),
  ]);
  const [requestKey, responseKey] = await Promise.all([
    importHmacKey(requestKeyBytes, ["verify"]),
    importHmacKey(responseKeyBytes, ["sign"]),
  ]);
  return Object.freeze({
    keyId: configured.keyId,
    requestKey,
    responseKey,
  });
}

function configuredKey(keyId: unknown, keyHex: unknown): ConfiguredKey | undefined {
  if (
    typeof keyId !== "string" ||
    !KEY_ID_PATTERN.test(keyId) ||
    typeof keyHex !== "string"
  ) {
    return undefined;
  }
  const rootKey = decodeHex(keyHex);
  if (rootKey === undefined || rootKey.byteLength < 32 || rootKey.byteLength > 256) {
    return undefined;
  }
  return Object.freeze({ keyId, rootKey: rootKey.slice() });
}

function selectConfiguredKey(
  environment: IngressSecretEnvironment,
  requestedKeyId: string,
): ConfiguredKey | "invalid-config" | undefined {
  const current = configuredKey(
    environment.CIRCULUSD_STATE_INGRESS_CURRENT_KEY_ID,
    environment.CIRCULUSD_STATE_INGRESS_CURRENT_KEY,
  );
  if (current === undefined) {
    return "invalid-config";
  }

  const previousId = environment.CIRCULUSD_STATE_INGRESS_PREVIOUS_KEY_ID;
  const previousHex = environment.CIRCULUSD_STATE_INGRESS_PREVIOUS_KEY;
  let previous: ConfiguredKey | undefined;
  if (previousId !== undefined || previousHex !== undefined) {
    previous = configuredKey(previousId, previousHex);
    if (previous === undefined || previous.keyId === current.keyId) {
      return "invalid-config";
    }
  }

  if (requestedKeyId === current.keyId) {
    return current;
  }
  if (previous !== undefined && requestedKeyId === previous.keyId) {
    return previous;
  }
  return undefined;
}

function unsignedResponse(status: number): Response {
  return new Response(null, {
    status,
    headers: { "cache-control": "no-store" },
  });
}

function isRecord(
  value: NormalizedValue,
): value is { readonly [key: string]: NormalizedValue } {
  return value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    !(value instanceof Uint8Array);
}

function hasExactFields(
  record: { readonly [key: string]: NormalizedValue },
  fields: readonly string[],
): boolean {
  const keys = Object.keys(record);
  return keys.length === fields.length &&
    fields.every((field) => Object.prototype.hasOwnProperty.call(record, field));
}

function hostFailureEnvelope(
  requestId: string,
  code: HostRpcErrorCode,
): NormalizedValue {
  return {
    protocol: PROTOCOL_NAME,
    major: PROTOCOL_MAJOR,
    minor: PROTOCOL_MINOR,
    schemaDigest: HOST_CONTRACT.schemaDigest,
    requestId,
    payload: {
      ok: false,
      error: { code, message: SAFE_HOST_ERROR_MESSAGES[code] },
    },
  };
}

async function signedEncodedResponse(
  body: Uint8Array,
  status: number,
  requestId: string,
  context: AuthenticatedResponseContext,
): Promise<Response> {
  const bodyDigest = await sha256(body);
  const signature = await hmac(context.keys.responseKey, lengthPrefixed([
    utf8(RESPONSE_MAC_DOMAIN),
    utf8(context.keys.keyId),
    utf8(requestId),
    context.requestBodyDigest,
    utf8(String(status)),
    utf8(INGRESS_CONTENT_TYPE),
    bodyDigest,
  ]));
  return new Response(ordinaryBuffer(body), {
    status,
    headers: {
      "cache-control": "no-store",
      "content-type": INGRESS_CONTENT_TYPE,
      [KEY_ID_HEADER]: context.keys.keyId,
      [SIGNATURE_HEADER]: hex(signature),
    },
  });
}

async function signedFailure(
  status: number,
  requestId: string,
  code: HostRpcErrorCode,
  context: AuthenticatedResponseContext,
): Promise<Response> {
  try {
    const body = encodeCanonicalCbor(hostFailureEnvelope(requestId, code), {
      maxBytes: HOST_CONTRACT.responseMaxEncodedBytes,
      maxDepth: HOST_CONTRACT.responseMaxDepth,
      maxItems: HOST_CONTRACT.responseMaxItems,
    });
    return await signedEncodedResponse(body, status, requestId, context);
  } catch {
    return unsignedResponse(503);
  }
}

function sanitizeHostResponse(
  unknownResponse: unknown,
  requestId: string,
): NormalizedValue {
  const envelope = parseRpcEnvelope(
    unknownResponse,
    parseNormalizedValue,
    {
      expectedSchemaDigest: HOST_CONTRACT.schemaDigest,
      maxEncodedBytes: HOST_CONTRACT.responseMaxEncodedBytes,
      maxDepth: HOST_CONTRACT.responseMaxDepth,
      maxItems: HOST_CONTRACT.responseMaxItems,
    },
  );
  if (envelope.requestId !== requestId || !isRecord(envelope.payload)) {
    throw new Error("invalid Host RPC response");
  }
  const payload = envelope.payload;
  if (
    payload.ok === true &&
    hasExactFields(payload, ["ok", "result"])
  ) {
    return {
      protocol: PROTOCOL_NAME,
      major: PROTOCOL_MAJOR,
      minor: PROTOCOL_MINOR,
      schemaDigest: HOST_CONTRACT.schemaDigest,
      requestId,
      payload: { ok: true, result: payload.result! },
    };
  }
  if (
    payload.ok !== false ||
    !hasExactFields(payload, ["ok", "error"]) ||
    !isRecord(payload.error!) ||
    !hasExactFields(payload.error, ["code", "message"]) ||
    typeof payload.error.code !== "string" ||
    !Object.prototype.hasOwnProperty.call(
      SAFE_HOST_ERROR_MESSAGES,
      payload.error.code,
    )
  ) {
    throw new Error("invalid Host RPC response");
  }
  return hostFailureEnvelope(requestId, payload.error.code as HostRpcErrorCode);
}

function isEncodedSizeFailure(error: unknown): boolean {
  return error instanceof ProtocolValidationError &&
    error.path === "$" &&
    error.message.includes("encoded size exceeds");
}

export async function handleStateIngress(
  request: Request,
  environment: IngressSecretEnvironment,
): Promise<Response> {
  let url: URL;
  try {
    url = new URL(request.url);
  } catch {
    return unsignedResponse(404);
  }
  if (url.pathname !== INGRESS_PATH || url.search !== "" || url.hash !== "") {
    return unsignedResponse(404);
  }
  if (request.method !== "POST") {
    return unsignedResponse(405);
  }
  if (
    request.headers.get("content-type") !== INGRESS_CONTENT_TYPE ||
    request.headers.has("content-encoding")
  ) {
    return unsignedResponse(415);
  }

  const contentLength = request.headers.get("content-length");
  if (contentLength !== null) {
    if (!/^(0|[1-9][0-9]*)$/.test(contentLength)) {
      return unsignedResponse(400);
    }
    if (Number(contentLength) > INGRESS_REQUEST_MAX_BYTES) {
      return unsignedResponse(413);
    }
  }

  const requestedKeyId = request.headers.get(KEY_ID_HEADER);
  const signatureHex = request.headers.get(SIGNATURE_HEADER);
  if (
    requestedKeyId === null ||
    !KEY_ID_PATTERN.test(requestedKeyId) ||
    signatureHex === null ||
    !SIGNATURE_PATTERN.test(signatureHex)
  ) {
    return unsignedResponse(401);
  }

  let selected: ConfiguredKey | "invalid-config" | undefined;
  try {
    selected = selectConfiguredKey(environment, requestedKeyId);
  } catch {
    return unsignedResponse(503);
  }
  if (selected === "invalid-config") {
    return unsignedResponse(503);
  }
  if (selected === undefined) {
    return unsignedResponse(401);
  }

  let keys: CapturedDirectionalKeys;
  try {
    keys = await captureDirectionalKeys(selected);
  } catch {
    return unsignedResponse(503);
  }

  const chunks: Uint8Array[] = [];
  let bodyLength = 0;
  if (request.body !== null) {
    const reader = request.body.getReader();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) {
          break;
        }
        if (bodyLength + value.byteLength > INGRESS_REQUEST_MAX_BYTES) {
          try {
            await reader.cancel();
          } catch {
            // The bounded rejection is authoritative even if cancellation fails.
          }
          return unsignedResponse(413);
        }
        const chunk = new Uint8Array(value.byteLength);
        chunk.set(value);
        chunks.push(chunk);
        bodyLength += chunk.byteLength;
      }
    } catch {
      return unsignedResponse(400);
    } finally {
      reader.releaseLock();
    }
  }
  const requestBody = new Uint8Array(bodyLength);
  let bodyOffset = 0;
  for (const chunk of chunks) {
    requestBody.set(chunk, bodyOffset);
    bodyOffset += chunk.byteLength;
  }

  let requestBodyDigest: Uint8Array;
  let authenticated: boolean;
  try {
    requestBodyDigest = await sha256(requestBody);
    authenticated = await crypto.subtle.verify(
      "HMAC",
      keys.requestKey,
      ordinaryBuffer(decodeHex(signatureHex)!),
      ordinaryBuffer(lengthPrefixed([
        utf8(REQUEST_MAC_DOMAIN),
        utf8(keys.keyId),
        utf8("POST"),
        utf8(INGRESS_PATH),
        requestBodyDigest,
      ])),
    );
  } catch {
    return unsignedResponse(503);
  }
  if (!authenticated) {
    return unsignedResponse(401);
  }
  const responseContext = Object.freeze({
    keys,
    requestBodyDigest,
  });

  let decoded: NormalizedValue;
  try {
    decoded = decodeCanonicalCbor(requestBody, {
      maxBytes: INGRESS_REQUEST_MAX_BYTES,
      maxDepth: INGRESS_REQUEST_MAX_DEPTH,
      maxItems: INGRESS_REQUEST_MAX_ITEMS,
    });
  } catch {
    return signedFailure(
      400,
      HOST_RPC_FALLBACK_REQUEST_ID,
      "INVALID_ARGUMENT",
      responseContext,
    );
  }

  let errorRequestId = HOST_RPC_FALLBACK_REQUEST_ID as string;
  if (isRecord(decoded)) {
    const candidate = decoded.requestId;
    if (
      typeof candidate === "string" &&
      candidate.length > 0 &&
      textEncoder.encode(candidate).byteLength <= 256 &&
      !/\p{Cc}/u.test(candidate)
    ) {
      errorRequestId = candidate;
    }
  }

  let ingress: IngressRequest;
  const now = Date.now();
  if (
    !isRecord(decoded) ||
    !hasExactFields(decoded, INGRESS_REQUEST_FIELDS) ||
    decoded.protocol !== INGRESS_PROTOCOL ||
    decoded.major !== 1 ||
    decoded.minor !== 0 ||
    decoded.schemaDigest !== INGRESS_SCHEMA_DIGEST ||
    typeof decoded.requestId !== "string" ||
    !REQUEST_ID_PATTERN.test(decoded.requestId) ||
    typeof decoded.sentAtUnixMs !== "number" ||
    !Number.isSafeInteger(decoded.sentAtUnixMs) ||
    decoded.sentAtUnixMs < 0 ||
    !Number.isSafeInteger(now) ||
    now < 0 ||
    decoded.sentAtUnixMs < now - INGRESS_MAX_CLOCK_SKEW_MS ||
    decoded.sentAtUnixMs > now + INGRESS_MAX_CLOCK_SKEW_MS ||
    typeof decoded.tenantId !== "string" ||
    !TENANT_ID_PATTERN.test(decoded.tenantId) ||
    typeof decoded.actorSubjectId !== "string" ||
    !SUBJECT_ID_PATTERN.test(decoded.actorSubjectId) ||
    typeof decoded.sessionId !== "string" ||
    !SESSION_ID_PATTERN.test(decoded.sessionId) ||
    typeof decoded.expectedAuthorizationGeneration !== "number" ||
    !Number.isSafeInteger(decoded.expectedAuthorizationGeneration) ||
    decoded.expectedAuthorizationGeneration < 1 ||
    typeof decoded.afterSequence !== "number" ||
    !Number.isSafeInteger(decoded.afterSequence) ||
    decoded.afterSequence < 0 ||
    typeof decoded.limit !== "number" ||
    !Number.isSafeInteger(decoded.limit) ||
    decoded.limit < 1 ||
    decoded.limit > INGRESS_MAX_EVENT_LIMIT
  ) {
    return signedFailure(
      400,
      errorRequestId,
      "INVALID_ARGUMENT",
      responseContext,
    );
  }
  ingress = {
    requestId: decoded.requestId,
    sentAtUnixMs: decoded.sentAtUnixMs,
    tenantId: decoded.tenantId,
    actorSubjectId: decoded.actorSubjectId,
    sessionId: decoded.sessionId,
    expectedAuthorizationGeneration: decoded.expectedAuthorizationGeneration,
    afterSequence: decoded.afterSequence,
    limit: decoded.limit,
  };

  if (!Number.isSafeInteger(now + 1)) {
    return signedFailure(500, ingress.requestId, "INTERNAL_ERROR", responseContext);
  }
  const hostRequest = {
    protocol: PROTOCOL_NAME,
    major: PROTOCOL_MAJOR,
    minor: PROTOCOL_MINOR,
    schemaDigest: HOST_CONTRACT.schemaDigest,
    requestId: ingress.requestId,
    payload: {
      authority: {
        serviceBinding: "state",
        tenantId: ingress.tenantId,
        actorUserId: ingress.actorSubjectId,
        subjectKind: "session",
        subjectId: ingress.sessionId,
        roles: [],
        permissions: ["session.read"],
        authorizationGeneration: ingress.expectedAuthorizationGeneration,
        currentAuthorizationGeneration: ingress.expectedAuthorizationGeneration,
        issuedAt: now,
        expiresAt: now + 1,
      },
      now,
      afterSequence: ingress.afterSequence,
      limit: ingress.limit,
    },
  };

  let sanitizedResponse: NormalizedValue;
  try {
    const session = environment.SESSION_CELL.getByName(
      sessionCellName(ingress.tenantId, ingress.sessionId),
    );
    const unknownResponse = await session.readSessionEvents(hostRequest);
    sanitizedResponse = sanitizeHostResponse(unknownResponse, ingress.requestId);
  } catch (error) {
    return signedFailure(
      502,
      ingress.requestId,
      isEncodedSizeFailure(error) ? "RESOURCE_EXHAUSTED" : "INTERNAL_ERROR",
      responseContext,
    );
  }

  let responseBody: Uint8Array;
  try {
    responseBody = encodeCanonicalCbor(sanitizedResponse, {
      maxBytes: HOST_CONTRACT.responseMaxEncodedBytes,
      maxDepth: HOST_CONTRACT.responseMaxDepth,
      maxItems: HOST_CONTRACT.responseMaxItems,
    });
  } catch (error) {
    return signedFailure(
      502,
      ingress.requestId,
      isEncodedSizeFailure(error) ? "RESOURCE_EXHAUSTED" : "INTERNAL_ERROR",
      responseContext,
    );
  }
  try {
    return await signedEncodedResponse(
      responseBody,
      200,
      ingress.requestId,
      responseContext,
    );
  } catch {
    return unsignedResponse(503);
  }
}
