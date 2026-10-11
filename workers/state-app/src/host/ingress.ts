import {
  decodeCanonicalCbor,
  digestBytes,
  digestStructuredValue,
  parseAgentCheckpoint,
  encodeCanonicalCbor,
  parseDigest,
  parseDispatchPermitClaims,
  parseNormalizedValue,
  parseRpcEnvelope,
  PROTOCOL_MAJOR,
  PROTOCOL_MINOR,
  PROTOCOL_NAME,
  ProtocolValidationError,
  type Digest,
  type DispatchPermitClaims,
  type NormalizedValue,
} from "@circulusd/protocol-types";

import { sessionCellName } from "./names.ts";
import { MAX_BLOB_BYTES } from "./storage.ts";
import { ADMISSION_PLANNING_FIELDS, parseSessionAdmissionPlanningRequest,
  validateSessionAdmissionPlanningDigests } from "./admission.ts";
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
const BLOB_INGRESS_PATH = "/circulusd/state/v1/session-blob:read";
const BLOB_INGRESS_CONTENT_TYPE = "application/vnd.circulusd.state-blob-ingress+cbor";
const BLOB_INGRESS_PROTOCOL = "circulus.state-blob-ingress.v1alpha1";
// SHA-256 of the following UTF-8 descriptor, concatenated without a newline:
// circulus.state-blob-ingress.v1alpha1|major=1|minor=0|requestId:req|sentAtUnixMs:safe-uint|
// tenantId:tenant|actorSubjectId:subject|sessionId:sess|expectedAuthorizationGeneration:positive-safe-uint|
// digest:sha256|fields=protocol,major,minor,schemaDigest,requestId,sentAtUnixMs,tenantId,actorSubjectId,sessionId,
// expectedAuthorizationGeneration,digest|maxBytes=4096|maxDepth=2|maxItems=32
const BLOB_INGRESS_SCHEMA_DIGEST =
  "sha256:d9402c455a2d37e51885684aa26ade9d26ff444cc5a15fb89c2ce2af372e40e5";
const BLOB_INGRESS_REQUEST_FIELDS = Object.freeze([
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
  "digest",
] as const);
const DISPATCH_START_INGRESS_PATH =
  "/circulusd/state/v1/session-dispatch-start:claim";
const DISPATCH_START_INGRESS_CONTENT_TYPE =
  "application/vnd.circulusd.state-dispatch-start-ingress+cbor";
const DISPATCH_START_INGRESS_PROTOCOL =
  "circulus.state-dispatch-start-ingress.v1alpha1";
const DISPATCH_START_INGRESS_SCHEMA_DIGEST =
  "sha256:a86295cc9ad723e50c8729318e4ec4994faa7b4c64c30a718696de8fa6edc724";
const DISPATCH_START_INGRESS_REQUEST_FIELDS = Object.freeze([
  "protocol",
  "major",
  "minor",
  "schemaDigest",
  "requestId",
  "sentAtUnixMs",
  "tenantId",
  "workspaceId",
  "sessionId",
  "commandId",
  "expectedEventSequence",
  "turnId",
  "effectId",
  "invocationId",
  "requestDigest",
  "fence",
  "dispatchAttempt",
  "providerRequestId",
  "providerRouteDigest",
  "dispatchPermitClaims",
  "commandDigest",
] as const);
const DISPATCH_START_FENCE_FIELDS = Object.freeze([
  "turnLeaseGeneration",
  "placementGeneration",
  "sandboxGeneration",
  "authorizationGeneration",
] as const);
const DISPATCH_START_INGRESS_REQUEST_MAX_BYTES = 8_192;
const DISPATCH_START_INGRESS_REQUEST_MAX_DEPTH = 4;
const DISPATCH_START_INGRESS_REQUEST_MAX_ITEMS = 96;
const KEY_ID_HEADER = "x-circulus-state-key-id";
const SIGNATURE_HEADER = "x-circulus-state-signature";
const REQUEST_MAC_DOMAIN = "circulusd.state-ingress.request.v1";
const RESPONSE_MAC_DOMAIN = "circulusd.state-ingress.response.v1";
const DISPATCH_START_REQUEST_MAC_DOMAIN =
  "circulusd.state-dispatch-start-ingress.request.v1";
const DISPATCH_START_RESPONSE_MAC_DOMAIN =
  "circulusd.state-dispatch-start-ingress.response.v1";
const REQUEST_KEY_DOMAIN = "circulusd.state-ingress.key.request.v1\0";
const RESPONSE_KEY_DOMAIN = "circulusd.state-ingress.key.response.v1\0";
const KEY_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const SIGNATURE_PATTERN = /^[0-9a-f]{64}$/;
const REQUEST_ID_PATTERN = /^req_[A-Z2-7]{25}[AEIMQUY4]$/;
const TENANT_ID_PATTERN = /^tenant_[A-Z2-7]{25}[AEIMQUY4]$/;
const WORKSPACE_ID_PATTERN = /^ws_[A-Z2-7]{25}[AEIMQUY4]$/;
const SUBJECT_ID_PATTERN = /^subject_[A-Z2-7]{25}[AEIMQUY4]$/;
const SESSION_ID_PATTERN = /^sess_[A-Z2-7]{25}[AEIMQUY4]$/;
const TURN_ID_PATTERN = /^turn_[A-Z2-7]{25}[AEIMQUY4]$/;
const EFFECT_ID_PATTERN = /^effect_[A-Z2-7]{25}[AEIMQUY4]$/;
const INVOCATION_ID_PATTERN = /^inv_[A-Z2-7]{25}[AEIMQUY4]$/;
const HOST_CONTRACT = HOST_RPC_CONTRACTS["session.read-events"];
const DISPATCH_START_HOST_CONTRACT = HOST_RPC_CONTRACTS["session.execute"];
const ZERO_DIGEST = `sha256:${"0".repeat(64)}` as const;
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
  DISPATCH_ALREADY_STARTED: "The dispatch attempt has already started.",
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
  readonly CIRCULUSD_STATE_BROKER_CURRENT_KEY_ID?: string;
  readonly CIRCULUSD_STATE_BROKER_CURRENT_KEY?: string;
  readonly CIRCULUSD_STATE_BROKER_PREVIOUS_KEY_ID?: string;
  readonly CIRCULUSD_STATE_BROKER_PREVIOUS_KEY?: string;
  readonly CIRCULUSD_STATE_ADMISSION_CURRENT_KEY_ID?: string;
  readonly CIRCULUSD_STATE_ADMISSION_CURRENT_KEY?: string;
  readonly CIRCULUSD_STATE_ADMISSION_PREVIOUS_KEY_ID?: string;
  readonly CIRCULUSD_STATE_ADMISSION_PREVIOUS_KEY?: string;
  readonly CIRCULUSD_STATE_INGRESS_CURRENT_KEY_ID?: string;
  readonly CIRCULUSD_STATE_INGRESS_CURRENT_KEY?: string;
  readonly CIRCULUSD_STATE_INGRESS_PREVIOUS_KEY_ID?: string;
  readonly CIRCULUSD_STATE_INGRESS_PREVIOUS_KEY?: string;
  readonly CIRCULUSD_STATE_DISPATCH_START_CURRENT_KEY_ID?: string;
  readonly CIRCULUSD_STATE_DISPATCH_START_CURRENT_KEY?: string;
  readonly CIRCULUSD_STATE_DISPATCH_START_PREVIOUS_KEY_ID?: string;
  readonly CIRCULUSD_STATE_DISPATCH_START_PREVIOUS_KEY?: string;
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

type HostContract = (typeof HOST_RPC_CONTRACTS)[keyof typeof HOST_RPC_CONTRACTS];

interface IngressWireContract {
  readonly kind: "read-events" | "read-blob" | "claim-dispatch-start" | "admit-turn" | "plan-turn" | "broker";
  readonly path: string;
  readonly contentType: string;
  readonly protocol: string;
  readonly schemaDigest: string;
  readonly requestFields: readonly string[];
  readonly requestMaxBytes: number;
  readonly requestMaxDepth: number;
  readonly requestMaxItems: number;
  readonly requestMacDomain: string;
  readonly responseMacDomain: string;
  readonly hostContract: HostContract;
}

interface AuthenticatedResponseContext {
  readonly keys: CapturedDirectionalKeys;
  readonly requestBodyDigest: Uint8Array;
  readonly ingress: IngressWireContract;
}

interface SessionReadIngressRequest {
  readonly requestId: string;
  readonly sentAtUnixMs: number;
  readonly tenantId: string;
  readonly actorSubjectId: string;
  readonly sessionId: string;
  readonly expectedAuthorizationGeneration: number;
}

interface IngressRequest extends SessionReadIngressRequest {
  readonly afterSequence: number;
  readonly limit: number;
}

interface BlobIngressRequest extends SessionReadIngressRequest {
  readonly digest: Digest;
}

interface DispatchStartIngressRequest {
  readonly requestId: string;
  readonly sentAtUnixMs: number;
  readonly tenantId: string;
  readonly workspaceId: string;
  readonly sessionId: string;
  readonly commandId: string;
  readonly expectedEventSequence: number;
  readonly turnId: string;
  readonly effectId: string;
  readonly invocationId: string;
  readonly requestDigest: Digest;
  readonly fence: {
    readonly turnLeaseGeneration: number;
    readonly placementGeneration: number;
    readonly sandboxGeneration: number;
    readonly authorizationGeneration: number;
  };
  readonly dispatchAttempt: number;
  readonly providerRequestId: string | null;
  readonly providerRouteDigest: Digest;
  readonly dispatchPermitClaims: DispatchPermitClaims;
  readonly commandDigest: Digest;
}

const READ_EVENTS_INGRESS = Object.freeze({
  kind: "read-events",
  path: INGRESS_PATH,
  contentType: INGRESS_CONTENT_TYPE,
  protocol: INGRESS_PROTOCOL,
  schemaDigest: INGRESS_SCHEMA_DIGEST,
  requestFields: INGRESS_REQUEST_FIELDS,
  requestMaxBytes: INGRESS_REQUEST_MAX_BYTES,
  requestMaxDepth: INGRESS_REQUEST_MAX_DEPTH,
  requestMaxItems: INGRESS_REQUEST_MAX_ITEMS,
  requestMacDomain: REQUEST_MAC_DOMAIN,
  responseMacDomain: RESPONSE_MAC_DOMAIN,
  hostContract: HOST_CONTRACT,
} as const satisfies IngressWireContract);

const DISPATCH_START_INGRESS = Object.freeze({
  kind: "claim-dispatch-start",
  path: DISPATCH_START_INGRESS_PATH,
  contentType: DISPATCH_START_INGRESS_CONTENT_TYPE,
  protocol: DISPATCH_START_INGRESS_PROTOCOL,
  schemaDigest: DISPATCH_START_INGRESS_SCHEMA_DIGEST,
  requestFields: DISPATCH_START_INGRESS_REQUEST_FIELDS,
  requestMaxBytes: DISPATCH_START_INGRESS_REQUEST_MAX_BYTES,
  requestMaxDepth: DISPATCH_START_INGRESS_REQUEST_MAX_DEPTH,
  requestMaxItems: DISPATCH_START_INGRESS_REQUEST_MAX_ITEMS,
  requestMacDomain: DISPATCH_START_REQUEST_MAC_DOMAIN,
  responseMacDomain: DISPATCH_START_RESPONSE_MAC_DOMAIN,
  hostContract: DISPATCH_START_HOST_CONTRACT,
} as const satisfies IngressWireContract);

const READ_BLOB_INGRESS = Object.freeze({
  kind: "read-blob",
  path: BLOB_INGRESS_PATH,
  contentType: BLOB_INGRESS_CONTENT_TYPE,
  protocol: BLOB_INGRESS_PROTOCOL,
  schemaDigest: BLOB_INGRESS_SCHEMA_DIGEST,
  requestFields: BLOB_INGRESS_REQUEST_FIELDS,
  requestMaxBytes: INGRESS_REQUEST_MAX_BYTES,
  requestMaxDepth: INGRESS_REQUEST_MAX_DEPTH,
  requestMaxItems: INGRESS_REQUEST_MAX_ITEMS,
  requestMacDomain: "circulusd.state-blob-ingress.request.v1",
  responseMacDomain: "circulusd.state-blob-ingress.response.v1",
  hostContract: HOST_RPC_CONTRACTS["session.read-blob"],
} as const satisfies IngressWireContract);

// SHA-256 of this exact UTF-8 descriptor (without a trailing newline):
// circulus.state-turn-ingress.v1alpha1|major=1|minor=0|enqueue_turn|scoped-public-admission|input=messages(user,content)|fields=protocol,major,minor,schemaDigest,requestId,sentAtUnixMs,tenantId,actorSubjectId,sessionId,expectedAuthorizationGeneration,commandId,expectedEventSequence,turnId,input,inputDigest,genesisCheckpoint,turnLeaseGeneration,leaseExpiresAt,idempotencyKeyDigest,requestDigest|maxBytes=8388608|maxDepth=72|maxItems=1000000
const ADMISSION_INGRESS = Object.freeze({
  kind: "admit-turn",
  path: "/circulusd/state/v1/session-turn:admit",
  contentType: "application/vnd.circulusd.state-turn-ingress+cbor",
  protocol: "circulus.state-turn-ingress.v1alpha1",
  schemaDigest: "sha256:eb2c41bda12d84937ea40811c3ae0d367653fcbf8e44aeebb9fc3a7363bcb228",
  requestFields: ["protocol", "major", "minor", "schemaDigest", "requestId", "sentAtUnixMs", "tenantId", "actorSubjectId", "sessionId", "expectedAuthorizationGeneration", "commandId", "expectedEventSequence", "turnId", "input", "inputDigest", "genesisCheckpoint", "turnLeaseGeneration", "leaseExpiresAt", "idempotencyKeyDigest", "requestDigest"],
  requestMaxBytes: 8 * 1_048_576,
  requestMaxDepth: 72,
  requestMaxItems: 1_000_000,
  requestMacDomain: "circulusd.state-turn-ingress.request.v1",
  responseMacDomain: "circulusd.state-turn-ingress.response.v1",
  hostContract: HOST_RPC_CONTRACTS["session.execute"],
} as const satisfies IngressWireContract);

// Matches internal/stateappclient/broker.go's exact UTF-8 descriptor:
// circulus.state-broker-ingress.v1alpha1|major=1|minor=0|typed-session-broker|operations=read-turn,lookup-operation,acquire-step,commit-step,dispatch,claim-start,confirm,settle,block,prepare-retry,settle-recovery|fields=protocol,major,minor,schemaDigest,requestId,sentAtUnixMs,tenantId,workspaceId,sessionId,actorSubjectId,expectedAuthorizationGeneration,operation,body|maxBytes=9437184|maxDepth=72|maxItems=100000
// Descriptor: circulus.state-turn-plan-ingress.v1alpha1|major=1|minor=0|scoped-session-admission-plan|fields=protocol,major,minor,schemaDigest,requestId,sentAtUnixMs,tenantId,actorSubjectId,sessionId,expectedAuthorizationGeneration,proposedTurnId,input,inputDigest,idempotencyKeyDigest,requestDigest|maxBytes=2097152|maxDepth=72|maxItems=100000
const ADMISSION_PLAN_INGRESS = Object.freeze({
  kind: "plan-turn", path: "/circulusd/state/v1/session-turn:plan",
  contentType: "application/vnd.circulusd.state-turn-plan-ingress+cbor",
  protocol: "circulus.state-turn-plan-ingress.v1alpha1", schemaDigest: "sha256:cac41263233c9e12d45ba30a5c8321a161abfb5b43849ab805b9df98e54a2d08",
  requestFields: ["protocol", "major", "minor", "schemaDigest", "requestId", "sentAtUnixMs", ...ADMISSION_PLANNING_FIELDS],
  requestMaxBytes: 2_097_152, requestMaxDepth: 72, requestMaxItems: 100_000,
  requestMacDomain: "circulusd.state-turn-plan-ingress.request.v1",
  responseMacDomain: "circulusd.state-turn-plan-ingress.response.v1",
  hostContract: DISPATCH_START_HOST_CONTRACT,
} as const satisfies IngressWireContract);

const BROKER_INGRESS = Object.freeze({
  kind: "broker",
  path: "/circulusd/state/v1/session-broker:execute",
  contentType: "application/vnd.circulusd.state-broker-ingress+cbor",
  protocol: "circulus.state-broker-ingress.v1alpha1",
  schemaDigest: "sha256:cf0d52d18c7e797d834fc20d73cf0e8976a7e8eb67f9f28a85d87a5239bc1891",
  requestFields: ["protocol", "major", "minor", "schemaDigest", "requestId", "sentAtUnixMs", "tenantId", "workspaceId", "sessionId", "actorSubjectId", "expectedAuthorizationGeneration", "operation", "body"],
  requestMaxBytes: 9 * 1_048_576, requestMaxDepth: 72, requestMaxItems: 100_000,
  requestMacDomain: "circulusd.state-broker-ingress.request.v1",
  responseMacDomain: "circulusd.state-broker-ingress.response.v1",
  hostContract: DISPATCH_START_HOST_CONTRACT,
} as const satisfies IngressWireContract);

// Body semantics and trusted policy are checked atomically by SessionCell.
// This boundary only admits the fixed union, never a generic aggregate command.
const BROKER_BODY_FIELDS = Object.freeze({
  "read-turn": [],
  "lookup-operation": ["kind", "operationKey", "operationDigest"],
  "acquire-step": ["snapshot", "operationKey", "nowUnixMs", "budget"],
  "commit-step": ["snapshot", "operationKey", "requestDigest", "permitOpaque", "nowUnixMs", "step"],
  dispatch: ["snapshot", "key", "operationKey", "operationDigest", "preparationOpaque", "providerRequestId", "providerRouteDigest", "nowUnixMs", "deadlineUnixMs"],
  "claim-start": ["snapshot", "key", "dispatchOpaque", "commandDigest", "nowUnixMs"],
  confirm: ["snapshot", "key", "operationKey", "operationDigest", "dispatchAttempt", "providerRequestId", "providerRouteDigest", "externalCommitId", "resultRef"],
  settle: ["snapshot", "key", "operationKey", "operationDigest", "dispatchAttempt", "externalCommitId", "resultRef", "error", "settlement"],
  block: ["snapshot", "key", "operationKey", "operationDigest", "reason"],
  "prepare-retry": ["snapshot", "key", "operationKey", "operationDigest", "nowUnixMs", "deadlineUnixMs", "userConfirmed"],
  "settle-recovery": ["snapshot", "key", "operationKey", "operationDigest", "kind", "error"],
} as const);

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
  ingress: IngressWireContract,
): ConfiguredKey | "invalid-config" | undefined {
  const roles = [
    [environment.CIRCULUSD_STATE_INGRESS_CURRENT_KEY_ID, environment.CIRCULUSD_STATE_INGRESS_CURRENT_KEY,
      environment.CIRCULUSD_STATE_INGRESS_PREVIOUS_KEY_ID, environment.CIRCULUSD_STATE_INGRESS_PREVIOUS_KEY],
    [environment.CIRCULUSD_STATE_DISPATCH_START_CURRENT_KEY_ID, environment.CIRCULUSD_STATE_DISPATCH_START_CURRENT_KEY,
      environment.CIRCULUSD_STATE_DISPATCH_START_PREVIOUS_KEY_ID, environment.CIRCULUSD_STATE_DISPATCH_START_PREVIOUS_KEY],
    [environment.CIRCULUSD_STATE_ADMISSION_CURRENT_KEY_ID, environment.CIRCULUSD_STATE_ADMISSION_CURRENT_KEY,
      environment.CIRCULUSD_STATE_ADMISSION_PREVIOUS_KEY_ID, environment.CIRCULUSD_STATE_ADMISSION_PREVIOUS_KEY],
    [environment.CIRCULUSD_STATE_BROKER_CURRENT_KEY_ID, environment.CIRCULUSD_STATE_BROKER_CURRENT_KEY,
      environment.CIRCULUSD_STATE_BROKER_PREVIOUS_KEY_ID, environment.CIRCULUSD_STATE_BROKER_PREVIOUS_KEY],
  ] as const;
  const selectedRole = ingress.kind === "broker" ? 3
    : ingress.kind === "admit-turn" || ingress.kind === "plan-turn" ? 2 : ingress.kind === "claim-dispatch-start" ? 1 : 0;
  const ids = new Set<string>(), materials = new Set<string>();
  let selected: ConfiguredKey | undefined;
  for (const [role, [currentId, currentHex, previousId, previousHex]] of roles.entries()) {
    if (role !== selectedRole && currentId === undefined && currentHex === undefined &&
      previousId === undefined && previousHex === undefined) continue;
    const current = configuredKey(currentId, currentHex);
    if (current === undefined) return "invalid-config";
    const keys = [current];
    if (previousId !== undefined || previousHex !== undefined) {
      const previous = configuredKey(previousId, previousHex);
      if (previous === undefined) return "invalid-config";
      keys.push(previous);
    }
    // Reject aliases from either direction: reader/admission requests also fail
    // closed if their configured credential could exercise broker authority.
    for (const key of keys) {
      const material = hex(key.rootKey);
      if (ids.has(key.keyId) || materials.has(material)) return "invalid-config";
      ids.add(key.keyId); materials.add(material);
      if (role === selectedRole && requestedKeyId === key.keyId) selected = key;
    }
  }
  return selected;
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
  hostContract: HostContract,
): NormalizedValue {
  return {
    protocol: PROTOCOL_NAME,
    major: PROTOCOL_MAJOR,
    minor: PROTOCOL_MINOR,
    schemaDigest: hostContract.schemaDigest,
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
    utf8(context.ingress.responseMacDomain),
    utf8(context.keys.keyId),
    utf8(requestId),
    context.requestBodyDigest,
    utf8(String(status)),
    utf8(context.ingress.contentType),
    bodyDigest,
  ]));
  return new Response(ordinaryBuffer(body), {
    status,
    headers: {
      "cache-control": "no-store",
      "content-type": context.ingress.contentType,
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
    const body = encodeCanonicalCbor(
      hostFailureEnvelope(requestId, code, context.ingress.hostContract),
      {
        maxBytes: context.ingress.hostContract.responseMaxEncodedBytes,
        maxDepth: context.ingress.hostContract.responseMaxDepth,
        maxItems: context.ingress.hostContract.responseMaxItems,
      },
    );
    return await signedEncodedResponse(body, status, requestId, context);
  } catch {
    return unsignedResponse(503);
  }
}

async function sanitizeHostResponse(
  unknownResponse: unknown,
  requestId: string,
  ingress: IngressWireContract,
  expectedDispatchStart?: DispatchStartIngressRequest,
  expectedBlobDigest?: Digest,
  expectedAdmissionTurnId?: string,
): Promise<NormalizedValue> {
  const envelope = parseRpcEnvelope(
    unknownResponse,
    parseNormalizedValue,
    {
      expectedSchemaDigest: ingress.hostContract.schemaDigest,
      maxEncodedBytes: ingress.hostContract.responseMaxEncodedBytes,
      maxDepth: ingress.hostContract.responseMaxDepth,
      maxItems: ingress.hostContract.responseMaxItems,
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
    if (expectedAdmissionTurnId !== undefined) {
      const result = payload.result;
      if (!isRecord(result!) || !hasExactFields(result, ["outcome", "version", "replayed"]) ||
        typeof result.version !== "number" || !Number.isSafeInteger(result.version) || result.version < 1 ||
        typeof result.replayed !== "boolean" || !isRecord(result.outcome!) ||
        !hasExactFields(result.outcome, ["kind", "turnId", "turnSequence", "activated"]) ||
        result.outcome.kind !== "turn_enqueued" || typeof result.outcome.turnId !== "string" ||
        !TURN_ID_PATTERN.test(result.outcome.turnId) ||
        (!result.replayed && result.outcome.turnId !== expectedAdmissionTurnId) ||
        typeof result.outcome.turnSequence !== "number" || !Number.isSafeInteger(result.outcome.turnSequence) ||
        result.outcome.turnSequence < 0 || result.outcome.turnSequence >= result.version ||
        typeof result.outcome.activated !== "boolean") throw new Error("invalid admission Host RPC success");
    }
    if (ingress.kind === "read-blob" && payload.result !== null) {
      const result = payload.result;
      if (
        expectedBlobDigest === undefined ||
        !isRecord(result!) ||
        !hasExactFields(result, ["digest", "encodedBytes", "bytes"]) ||
        result.digest !== expectedBlobDigest ||
        !(result.bytes instanceof Uint8Array) ||
        result.bytes.byteLength < 1 ||
        result.bytes.byteLength > MAX_BLOB_BYTES ||
        result.encodedBytes !== result.bytes.byteLength ||
        await digestBytes(result.bytes) !== expectedBlobDigest
      ) {
        throw new Error("invalid blob Host RPC success");
      }
    }
    if (expectedDispatchStart !== undefined) {
      if (
        !isRecord(payload.result!) ||
        !hasExactFields(payload.result, ["outcome", "version", "replayed"]) ||
        typeof payload.result.version !== "number" ||
        !Number.isSafeInteger(payload.result.version) ||
        payload.result.version < 1 ||
        typeof payload.result.replayed !== "boolean" ||
        !isRecord(payload.result.outcome!) ||
        !hasExactFields(
          payload.result.outcome,
          ["kind", "effectId", "fresh", "startPermit"],
        ) ||
        payload.result.outcome.kind !== "dispatch_start_claimed" ||
        payload.result.outcome.effectId !== expectedDispatchStart.effectId ||
        typeof payload.result.outcome.fresh !== "boolean" ||
        payload.result.outcome.fresh === payload.result.replayed ||
        !isRecord(payload.result.outcome.startPermit!) ||
        !hasExactFields(
          payload.result.outcome.startPermit,
          [
            "dispatchPermitClaims",
            "providerRequestId",
            "commandDigest",
            "claimedEventSequence",
          ],
        ) ||
        payload.result.outcome.startPermit.providerRequestId !==
          expectedDispatchStart.providerRequestId ||
        payload.result.outcome.startPermit.commandDigest !==
          expectedDispatchStart.commandDigest ||
        typeof payload.result.outcome.startPermit.claimedEventSequence !== "number" ||
        !Number.isSafeInteger(
          payload.result.outcome.startPermit.claimedEventSequence,
        ) ||
        payload.result.outcome.startPermit.claimedEventSequence < 1 ||
        payload.result.outcome.startPermit.claimedEventSequence <=
          expectedDispatchStart.expectedEventSequence ||
        payload.result.outcome.startPermit.claimedEventSequence >
          payload.result.version ||
        (payload.result.outcome.fresh &&
          payload.result.outcome.startPermit.claimedEventSequence !==
            payload.result.version)
      ) {
        throw new Error("invalid dispatch-start Host RPC success");
      }
      let dispatchPermitClaims: DispatchPermitClaims;
      try {
        dispatchPermitClaims = parseDispatchPermitClaims(
          payload.result.outcome.startPermit.dispatchPermitClaims,
        );
      } catch {
        throw new Error("invalid dispatch-start Host RPC success");
      }
      const expectedClaims = encodeCanonicalCbor(
        expectedDispatchStart.dispatchPermitClaims,
      );
      const actualClaims = encodeCanonicalCbor(dispatchPermitClaims);
      if (
        expectedClaims.byteLength !== actualClaims.byteLength ||
        expectedClaims.some((byte, index) => byte !== actualClaims[index])
      ) {
        throw new Error("invalid dispatch-start Host RPC success");
      }
      const normalizedDispatchPermitClaims = parseNormalizedValue(
        dispatchPermitClaims,
      );
      return {
        protocol: PROTOCOL_NAME,
        major: PROTOCOL_MAJOR,
        minor: PROTOCOL_MINOR,
        schemaDigest: ingress.hostContract.schemaDigest,
        requestId,
        payload: {
          ok: true,
          result: {
            outcome: {
              kind: "dispatch_start_claimed",
              effectId: expectedDispatchStart.effectId,
              fresh: payload.result.outcome.fresh,
              startPermit: {
                dispatchPermitClaims: normalizedDispatchPermitClaims,
                providerRequestId: expectedDispatchStart.providerRequestId,
                commandDigest: expectedDispatchStart.commandDigest,
                claimedEventSequence:
                  payload.result.outcome.startPermit.claimedEventSequence,
              },
            },
            version: payload.result.version,
            replayed: payload.result.replayed,
          },
        },
      };
    }
    return {
      protocol: PROTOCOL_NAME,
      major: PROTOCOL_MAJOR,
      minor: PROTOCOL_MINOR,
      schemaDigest: ingress.hostContract.schemaDigest,
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
  return hostFailureEnvelope(
    requestId,
    payload.error.code as HostRpcErrorCode,
    ingress.hostContract,
  );
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
  let wireContract: IngressWireContract;
  if (url.pathname === READ_EVENTS_INGRESS.path) {
    wireContract = READ_EVENTS_INGRESS;
  } else if (url.pathname === READ_BLOB_INGRESS.path) {
    wireContract = READ_BLOB_INGRESS;
  } else if (url.pathname === ADMISSION_INGRESS.path) {
    wireContract = ADMISSION_INGRESS;
  } else if (url.pathname === ADMISSION_PLAN_INGRESS.path) {
    wireContract = ADMISSION_PLAN_INGRESS;
  } else if (url.pathname === BROKER_INGRESS.path) {
    wireContract = BROKER_INGRESS;
  } else if (url.pathname === DISPATCH_START_INGRESS.path) {
    wireContract = DISPATCH_START_INGRESS;
  } else {
    return unsignedResponse(404);
  }
  if (url.search !== "" || url.hash !== "") {
    return unsignedResponse(404);
  }
  if (request.method !== "POST") {
    return unsignedResponse(405);
  }
  if (
    request.headers.get("content-type") !== wireContract.contentType ||
    request.headers.has("content-encoding")
  ) {
    return unsignedResponse(415);
  }

  const contentLength = request.headers.get("content-length");
  if (contentLength !== null) {
    if (!/^(0|[1-9][0-9]*)$/.test(contentLength)) {
      return unsignedResponse(400);
    }
    if (Number(contentLength) > wireContract.requestMaxBytes) {
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
    selected = selectConfiguredKey(environment, requestedKeyId, wireContract);
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
        if (bodyLength + value.byteLength > wireContract.requestMaxBytes) {
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
        utf8(wireContract.requestMacDomain),
        utf8(keys.keyId),
        utf8("POST"),
        utf8(wireContract.path),
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
    ingress: wireContract,
  });

  let decoded: NormalizedValue;
  try {
    decoded = decodeCanonicalCbor(requestBody, {
      maxBytes: wireContract.requestMaxBytes,
      maxDepth: wireContract.requestMaxDepth,
      maxItems: wireContract.requestMaxItems,
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

  const now = Date.now();
  if (!Number.isSafeInteger(now) || now < 0) {
    return signedFailure(
      500,
      errorRequestId,
      "INTERNAL_ERROR",
      responseContext,
    );
  }

  let sanitizedResponse: NormalizedValue;
  let responseRequestId: string;
  if (wireContract.kind === "plan-turn") {
    if (!isRecord(decoded) || !hasExactFields(decoded, wireContract.requestFields) ||
      decoded.protocol !== wireContract.protocol || decoded.major !== 1 || decoded.minor !== 0 ||
      decoded.schemaDigest !== wireContract.schemaDigest || typeof decoded.requestId !== "string" ||
      !REQUEST_ID_PATTERN.test(decoded.requestId) || typeof decoded.sentAtUnixMs !== "number" ||
      !Number.isSafeInteger(decoded.sentAtUnixMs) || decoded.sentAtUnixMs < 0 ||
      Math.abs(decoded.sentAtUnixMs - now) > INGRESS_MAX_CLOCK_SKEW_MS) {
      return signedFailure(400, errorRequestId, "INVALID_ARGUMENT", responseContext);
    }
    let input;
    try {
      input = parseSessionAdmissionPlanningRequest(Object.fromEntries(ADMISSION_PLANNING_FIELDS.map((field) => [field, decoded[field]])));
      await validateSessionAdmissionPlanningDigests(input);
    } catch { return signedFailure(400, decoded.requestId, "INVALID_ARGUMENT", responseContext); }
    responseRequestId = decoded.requestId;
    try {
      const cell = environment.SESSION_CELL.getByName(sessionCellName(input.tenantId, input.sessionId)) as unknown as
        { planSessionTurnAdmission(request: unknown): Promise<unknown> };
      const unknownResponse = await cell.planSessionTurnAdmission({ protocol: PROTOCOL_NAME, major: PROTOCOL_MAJOR,
        minor: PROTOCOL_MINOR, schemaDigest: wireContract.hostContract.schemaDigest, requestId: decoded.requestId, payload: input });
      sanitizedResponse = await sanitizeHostResponse(unknownResponse, decoded.requestId, wireContract);
    } catch (error) {
      return signedFailure(502, decoded.requestId,
        isEncodedSizeFailure(error) ? "RESOURCE_EXHAUSTED" : "INTERNAL_ERROR", responseContext);
    }
  } else if (wireContract.kind === "broker") {
    if (!isRecord(decoded) || !hasExactFields(decoded, wireContract.requestFields) ||
      decoded.protocol !== wireContract.protocol || decoded.major !== 1 || decoded.minor !== 0 ||
      decoded.schemaDigest !== wireContract.schemaDigest ||
      typeof decoded.requestId !== "string" || !REQUEST_ID_PATTERN.test(decoded.requestId) ||
      typeof decoded.sentAtUnixMs !== "number" || !Number.isSafeInteger(decoded.sentAtUnixMs) ||
      decoded.sentAtUnixMs < 0 || Math.abs(decoded.sentAtUnixMs - now) > INGRESS_MAX_CLOCK_SKEW_MS ||
      typeof decoded.tenantId !== "string" || !TENANT_ID_PATTERN.test(decoded.tenantId) ||
      typeof decoded.workspaceId !== "string" || !WORKSPACE_ID_PATTERN.test(decoded.workspaceId) ||
      typeof decoded.sessionId !== "string" || !SESSION_ID_PATTERN.test(decoded.sessionId) ||
      typeof decoded.actorSubjectId !== "string" || !SUBJECT_ID_PATTERN.test(decoded.actorSubjectId) ||
      typeof decoded.expectedAuthorizationGeneration !== "number" ||
      !Number.isSafeInteger(decoded.expectedAuthorizationGeneration) || decoded.expectedAuthorizationGeneration < 1 ||
      typeof decoded.operation !== "string" || !Object.hasOwn(BROKER_BODY_FIELDS, decoded.operation) ||
      !isRecord(decoded.body!) ||
      !hasExactFields(decoded.body, BROKER_BODY_FIELDS[decoded.operation as keyof typeof BROKER_BODY_FIELDS])) {
      return signedFailure(400, errorRequestId, "INVALID_ARGUMENT", responseContext);
    }
    responseRequestId = decoded.requestId;
    const hostRequest = {
      protocol: PROTOCOL_NAME, major: PROTOCOL_MAJOR, minor: PROTOCOL_MINOR,
      schemaDigest: wireContract.hostContract.schemaDigest, requestId: decoded.requestId,
      payload: {
        authority: {
          tenantId: decoded.tenantId, workspaceId: decoded.workspaceId, sessionId: decoded.sessionId,
          actorSubjectId: decoded.actorSubjectId, expectedAuthorizationGeneration: decoded.expectedAuthorizationGeneration,
        },
        operation: decoded.operation, body: decoded.body,
      },
    };
    try {
      const session = environment.SESSION_CELL.getByName(sessionCellName(decoded.tenantId, decoded.sessionId));
      const sessionRpc = session as unknown as { brokerSession(request: unknown): Promise<unknown> };
      const unknownResponse = await sessionRpc.brokerSession(hostRequest);
      sanitizedResponse = await sanitizeHostResponse(unknownResponse, decoded.requestId, wireContract);
    } catch (error) {
      return signedFailure(502, decoded.requestId,
        isEncodedSizeFailure(error) ? "RESOURCE_EXHAUSTED" : "INTERNAL_ERROR", responseContext);
    }
  } else if (wireContract.kind === "admit-turn") {
    if (!isRecord(decoded) || !hasExactFields(decoded, wireContract.requestFields) ||
      decoded.protocol !== wireContract.protocol || decoded.major !== 1 || decoded.minor !== 0 ||
      decoded.schemaDigest !== wireContract.schemaDigest ||
      typeof decoded.requestId !== "string" || !REQUEST_ID_PATTERN.test(decoded.requestId) ||
      typeof decoded.sentAtUnixMs !== "number" || !Number.isSafeInteger(decoded.sentAtUnixMs) ||
      decoded.sentAtUnixMs < 0 || Math.abs(decoded.sentAtUnixMs - now) > INGRESS_MAX_CLOCK_SKEW_MS ||
      typeof decoded.tenantId !== "string" || !TENANT_ID_PATTERN.test(decoded.tenantId) ||
      typeof decoded.actorSubjectId !== "string" || !SUBJECT_ID_PATTERN.test(decoded.actorSubjectId) ||
      typeof decoded.sessionId !== "string" || !SESSION_ID_PATTERN.test(decoded.sessionId) ||
      typeof decoded.turnId !== "string" || !TURN_ID_PATTERN.test(decoded.turnId) ||
      typeof decoded.commandId !== "string" || decoded.commandId.length === 0 ||
      textEncoder.encode(decoded.commandId).byteLength > 256 || /\p{Cc}/u.test(decoded.commandId) ||
      typeof decoded.expectedAuthorizationGeneration !== "number" ||
      !Number.isSafeInteger(decoded.expectedAuthorizationGeneration) || decoded.expectedAuthorizationGeneration < 1 ||
      typeof decoded.expectedEventSequence !== "number" || !Number.isSafeInteger(decoded.expectedEventSequence) ||
      decoded.expectedEventSequence < 0 || !Number.isSafeInteger(decoded.expectedEventSequence + 1) ||
      typeof decoded.turnLeaseGeneration !== "number" || !Number.isSafeInteger(decoded.turnLeaseGeneration) || decoded.turnLeaseGeneration < 1 ||
      typeof decoded.leaseExpiresAt !== "number" || !Number.isSafeInteger(decoded.leaseExpiresAt) || decoded.leaseExpiresAt <= now) {
      return signedFailure(400, errorRequestId, "INVALID_ARGUMENT", responseContext);
    }
    let command;
    try {
      const input = decoded.input!;
      if (!isRecord(input) || !hasExactFields(input, ["messages"]) || !Array.isArray(input.messages) ||
        input.messages.length < 1 || input.messages.length > 1024) throw new Error("invalid public input");
      const messages = input.messages.map((message) => {
        if (!isRecord(message) || !hasExactFields(message, ["role", "content"]) || message.role !== "user" ||
          typeof message.content !== "string" || message.content.length === 0) throw new Error("invalid public message");
        return [message.role, message.content];
      });
      encodeCanonicalCbor(input, { maxBytes: 1_048_576, maxDepth: 64, maxItems: 100_000 });
      const inputDigest = parseDigest(decoded.inputDigest);
      const requestDigest = parseDigest(decoded.requestDigest);
      const idempotencyKeyDigest = parseDigest(decoded.idempotencyKeyDigest);
      if (await digestStructuredValue("circulusd.session.turn-input", 1, input) !== inputDigest ||
        await digestStructuredValue("circulusd.public.turn.create", 1, { sessionId: decoded.sessionId, messages }) !== requestDigest) {
        return signedFailure(400, decoded.requestId, "DIGEST_MISMATCH", responseContext);
      }
      const genesisCheckpoint = parseAgentCheckpoint(decoded.genesisCheckpoint);
      if (genesisCheckpoint.sessionId !== decoded.sessionId || genesisCheckpoint.turnId !== decoded.turnId) {
        throw new Error("checkpoint scope mismatch");
      }
      command = {
        kind: "enqueue_turn", commandId: decoded.commandId, expectedEventSequence: decoded.expectedEventSequence,
        transactionTime: 0, turnId: decoded.turnId, input, inputDigest, genesisCheckpoint,
        turnLeaseGeneration: decoded.turnLeaseGeneration, leaseExpiresAt: decoded.leaseExpiresAt,
        publicAdmission: { tenantId: decoded.tenantId, actorSubjectId: decoded.actorSubjectId,
          authorizationGeneration: decoded.expectedAuthorizationGeneration, idempotencyKeyDigest, requestDigest },
      };
    } catch {
      return signedFailure(400, decoded.requestId, "INVALID_ARGUMENT", responseContext);
    }
    responseRequestId = decoded.requestId;
    try {
      const session = environment.SESSION_CELL.getByName(sessionCellName(decoded.tenantId, decoded.sessionId));
      const sessionRpc = session as unknown as { executeSessionCommand(request: unknown): Promise<unknown> };
      const unknownResponse = await sessionRpc.executeSessionCommand({
        protocol: PROTOCOL_NAME, major: PROTOCOL_MAJOR, minor: PROTOCOL_MINOR,
        schemaDigest: wireContract.hostContract.schemaDigest, requestId: decoded.requestId, payload: command,
      });
      sanitizedResponse = await sanitizeHostResponse(unknownResponse, decoded.requestId, wireContract, undefined, undefined, decoded.turnId);
    } catch (error) {
      return signedFailure(502, decoded.requestId, isEncodedSizeFailure(error) ? "RESOURCE_EXHAUSTED" : "INTERNAL_ERROR", responseContext);
    }
  } else if (wireContract.kind === "claim-dispatch-start") {
    let dispatchStart: DispatchStartIngressRequest;
    let requestDigest: Digest;
    let providerRouteDigest: Digest;
    let commandDigest: Digest;
    let dispatchPermitClaims: DispatchPermitClaims;
    if (
      !isRecord(decoded) ||
      !hasExactFields(decoded, wireContract.requestFields) ||
      decoded.protocol !== wireContract.protocol ||
      decoded.major !== 1 ||
      decoded.minor !== 0 ||
      decoded.schemaDigest !== wireContract.schemaDigest ||
      typeof decoded.requestId !== "string" ||
      !REQUEST_ID_PATTERN.test(decoded.requestId) ||
      typeof decoded.sentAtUnixMs !== "number" ||
      !Number.isSafeInteger(decoded.sentAtUnixMs) ||
      decoded.sentAtUnixMs < 0 ||
      decoded.sentAtUnixMs < now - INGRESS_MAX_CLOCK_SKEW_MS ||
      decoded.sentAtUnixMs > now + INGRESS_MAX_CLOCK_SKEW_MS ||
      typeof decoded.tenantId !== "string" ||
      !TENANT_ID_PATTERN.test(decoded.tenantId) ||
      typeof decoded.workspaceId !== "string" ||
      !WORKSPACE_ID_PATTERN.test(decoded.workspaceId) ||
      typeof decoded.sessionId !== "string" ||
      !SESSION_ID_PATTERN.test(decoded.sessionId) ||
      typeof decoded.commandId !== "string" ||
      decoded.commandId.length === 0 ||
      textEncoder.encode(decoded.commandId).byteLength > 256 ||
      /\p{Cc}/u.test(decoded.commandId) ||
      typeof decoded.expectedEventSequence !== "number" ||
      !Number.isSafeInteger(decoded.expectedEventSequence) ||
      decoded.expectedEventSequence < 0 ||
      !Number.isSafeInteger(decoded.expectedEventSequence + 1) ||
      typeof decoded.turnId !== "string" ||
      !TURN_ID_PATTERN.test(decoded.turnId) ||
      typeof decoded.effectId !== "string" ||
      !EFFECT_ID_PATTERN.test(decoded.effectId) ||
      typeof decoded.invocationId !== "string" ||
      !INVOCATION_ID_PATTERN.test(decoded.invocationId) ||
      !isRecord(decoded.fence!) ||
      !hasExactFields(decoded.fence, DISPATCH_START_FENCE_FIELDS) ||
      typeof decoded.fence.turnLeaseGeneration !== "number" ||
      !Number.isSafeInteger(decoded.fence.turnLeaseGeneration) ||
      decoded.fence.turnLeaseGeneration < 0 ||
      typeof decoded.fence.placementGeneration !== "number" ||
      !Number.isSafeInteger(decoded.fence.placementGeneration) ||
      decoded.fence.placementGeneration < 0 ||
      typeof decoded.fence.sandboxGeneration !== "number" ||
      !Number.isSafeInteger(decoded.fence.sandboxGeneration) ||
      decoded.fence.sandboxGeneration < 0 ||
      typeof decoded.fence.authorizationGeneration !== "number" ||
      !Number.isSafeInteger(decoded.fence.authorizationGeneration) ||
      decoded.fence.authorizationGeneration < 0 ||
      typeof decoded.dispatchAttempt !== "number" ||
      !Number.isSafeInteger(decoded.dispatchAttempt) ||
      decoded.dispatchAttempt < 1 ||
      decoded.providerRequestId !== null &&
        (typeof decoded.providerRequestId !== "string" ||
          !REQUEST_ID_PATTERN.test(decoded.providerRequestId))
    ) {
      return signedFailure(
        400,
        errorRequestId,
        "INVALID_ARGUMENT",
        responseContext,
      );
    }
    try {
      requestDigest = parseDigest(decoded.requestDigest, "$ingress.requestDigest");
      providerRouteDigest = parseDigest(
        decoded.providerRouteDigest,
        "$ingress.providerRouteDigest",
      );
      dispatchPermitClaims = parseDispatchPermitClaims(
        decoded.dispatchPermitClaims,
      );
      commandDigest = parseDigest(decoded.commandDigest, "$ingress.commandDigest");
    } catch {
      return signedFailure(
        400,
        errorRequestId,
        "INVALID_ARGUMENT",
        responseContext,
      );
    }
    if (
      requestDigest === ZERO_DIGEST ||
      providerRouteDigest === ZERO_DIGEST ||
      commandDigest === ZERO_DIGEST ||
      dispatchPermitClaims.tenantId !== decoded.tenantId ||
      !SUBJECT_ID_PATTERN.test(dispatchPermitClaims.userId) ||
      dispatchPermitClaims.sessionId !== decoded.sessionId ||
      dispatchPermitClaims.turnId !== decoded.turnId ||
      dispatchPermitClaims.effectId !== decoded.effectId ||
      dispatchPermitClaims.invocationId !== decoded.invocationId ||
      dispatchPermitClaims.requestDigest !== requestDigest ||
      dispatchPermitClaims.turnLeaseGeneration !==
        decoded.fence.turnLeaseGeneration ||
      dispatchPermitClaims.placementGeneration !==
        decoded.fence.placementGeneration ||
      dispatchPermitClaims.sandboxGeneration !==
        decoded.fence.sandboxGeneration ||
      dispatchPermitClaims.authorizationGeneration !==
        decoded.fence.authorizationGeneration ||
      dispatchPermitClaims.dispatchAttempt !== decoded.dispatchAttempt ||
      dispatchPermitClaims.providerRouteDigest !== providerRouteDigest
    ) {
      return signedFailure(
        400,
        errorRequestId,
        "INVALID_ARGUMENT",
        responseContext,
      );
    }
    dispatchStart = {
      requestId: decoded.requestId,
      sentAtUnixMs: decoded.sentAtUnixMs,
      tenantId: decoded.tenantId,
      workspaceId: decoded.workspaceId,
      sessionId: decoded.sessionId,
      commandId: decoded.commandId,
      expectedEventSequence: decoded.expectedEventSequence,
      turnId: decoded.turnId,
      effectId: decoded.effectId,
      invocationId: decoded.invocationId,
      requestDigest,
      fence: {
        turnLeaseGeneration: decoded.fence.turnLeaseGeneration,
        placementGeneration: decoded.fence.placementGeneration,
        sandboxGeneration: decoded.fence.sandboxGeneration,
        authorizationGeneration: decoded.fence.authorizationGeneration,
      },
      dispatchAttempt: decoded.dispatchAttempt,
      providerRequestId: decoded.providerRequestId,
      providerRouteDigest,
      dispatchPermitClaims,
      commandDigest,
    };
    const hostRequest = {
      protocol: PROTOCOL_NAME,
      major: PROTOCOL_MAJOR,
      minor: PROTOCOL_MINOR,
      schemaDigest: wireContract.hostContract.schemaDigest,
      requestId: dispatchStart.requestId,
      payload: {
        kind: "claim_dispatch_start",
        commandId: dispatchStart.commandId,
        expectedEventSequence: dispatchStart.expectedEventSequence,
        workspaceId: dispatchStart.workspaceId,
        turnId: dispatchStart.turnId,
        effectId: dispatchStart.effectId,
        invocationId: dispatchStart.invocationId,
        requestDigest: dispatchStart.requestDigest,
        fence: dispatchStart.fence,
        transactionTime: 0,
        dispatchAttempt: dispatchStart.dispatchAttempt,
        providerRequestId: dispatchStart.providerRequestId,
        providerRouteDigest: dispatchStart.providerRouteDigest,
        dispatchPermitClaims: dispatchStart.dispatchPermitClaims,
        commandDigest: dispatchStart.commandDigest,
      },
    };
    responseRequestId = dispatchStart.requestId;
    try {
      const session = environment.SESSION_CELL.getByName(
        sessionCellName(dispatchStart.tenantId, dispatchStart.sessionId),
      );
      const sessionRpc = session as unknown as {
        executeSessionCommand(request: unknown): Promise<unknown>;
      };
      const unknownResponse = await sessionRpc.executeSessionCommand(hostRequest);
      sanitizedResponse = await sanitizeHostResponse(
        unknownResponse,
        dispatchStart.requestId,
        wireContract,
        dispatchStart,
      );
    } catch (error) {
      return signedFailure(
        502,
        dispatchStart.requestId,
        isEncodedSizeFailure(error) ? "RESOURCE_EXHAUSTED" : "INTERNAL_ERROR",
        responseContext,
      );
    }
  } else {
    let ingress: IngressRequest | BlobIngressRequest;
    if (
      !isRecord(decoded) ||
      !hasExactFields(decoded, wireContract.requestFields) ||
      decoded.protocol !== wireContract.protocol ||
      decoded.major !== 1 ||
      decoded.minor !== 0 ||
      decoded.schemaDigest !== wireContract.schemaDigest ||
      typeof decoded.requestId !== "string" ||
      !REQUEST_ID_PATTERN.test(decoded.requestId) ||
      typeof decoded.sentAtUnixMs !== "number" ||
      !Number.isSafeInteger(decoded.sentAtUnixMs) ||
      decoded.sentAtUnixMs < 0 ||
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
      decoded.expectedAuthorizationGeneration < 1
    ) {
      return signedFailure(
        400,
        errorRequestId,
        "INVALID_ARGUMENT",
        responseContext,
      );
    }
    const common: SessionReadIngressRequest = {
      requestId: decoded.requestId,
      sentAtUnixMs: decoded.sentAtUnixMs,
      tenantId: decoded.tenantId,
      actorSubjectId: decoded.actorSubjectId,
      sessionId: decoded.sessionId,
      expectedAuthorizationGeneration: decoded.expectedAuthorizationGeneration,
    };
    if (wireContract.kind === "read-blob") {
      try {
        const digest = parseDigest(decoded.digest, "$ingress.digest");
        if (digest === ZERO_DIGEST) throw new Error("blob digest must be nonzero");
        ingress = { ...common, digest };
      } catch {
        return signedFailure(400, errorRequestId, "INVALID_ARGUMENT", responseContext);
      }
    } else {
      if (
        typeof decoded.afterSequence !== "number" ||
        !Number.isSafeInteger(decoded.afterSequence) ||
        decoded.afterSequence < 0 ||
        typeof decoded.limit !== "number" ||
        !Number.isSafeInteger(decoded.limit) ||
        decoded.limit < 1 ||
        decoded.limit > INGRESS_MAX_EVENT_LIMIT
      ) {
        return signedFailure(400, errorRequestId, "INVALID_ARGUMENT", responseContext);
      }
      ingress = { ...common, afterSequence: decoded.afterSequence, limit: decoded.limit };
    }
    if (!Number.isSafeInteger(now + 1)) {
      return signedFailure(
        500,
        ingress.requestId,
        "INTERNAL_ERROR",
        responseContext,
      );
    }
    const hostRequest = {
      protocol: PROTOCOL_NAME,
      major: PROTOCOL_MAJOR,
      minor: PROTOCOL_MINOR,
      schemaDigest: wireContract.hostContract.schemaDigest,
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
        ...("digest" in ingress
          ? { digest: ingress.digest }
          : { afterSequence: ingress.afterSequence, limit: ingress.limit }),
      },
    };
    responseRequestId = ingress.requestId;
    try {
      const session = environment.SESSION_CELL.getByName(
        sessionCellName(ingress.tenantId, ingress.sessionId),
      );
      const unknownResponse = "digest" in ingress
        ? await session.readSessionBlob(hostRequest)
        : await session.readSessionEvents(hostRequest);
      sanitizedResponse = await sanitizeHostResponse(
        unknownResponse,
        ingress.requestId,
        wireContract,
        undefined,
        "digest" in ingress ? ingress.digest : undefined,
      );
    } catch (error) {
      return signedFailure(
        502,
        ingress.requestId,
        isEncodedSizeFailure(error) ? "RESOURCE_EXHAUSTED" : "INTERNAL_ERROR",
        responseContext,
      );
    }
  }

  let responseBody: Uint8Array;
  try {
    responseBody = encodeCanonicalCbor(sanitizedResponse, {
      maxBytes: wireContract.hostContract.responseMaxEncodedBytes,
      maxDepth: wireContract.hostContract.responseMaxDepth,
      maxItems: wireContract.hostContract.responseMaxItems,
    });
  } catch (error) {
    return signedFailure(
      502,
      responseRequestId,
      isEncodedSizeFailure(error) ? "RESOURCE_EXHAUSTED" : "INTERNAL_ERROR",
      responseContext,
    );
  }
  try {
    return await signedEncodedResponse(
      responseBody,
      200,
      responseRequestId,
      responseContext,
    );
  } catch {
    return unsignedResponse(503);
  }
}
