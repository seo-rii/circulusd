import {
  decodeCanonicalCbor, encodeCanonicalCbor, isDigest,
  type Digest, type NormalizedValue,
} from "@circulusd/protocol-types";

import { PiRuntimeError } from "./errors.ts";
import {
  piGenesisBinding, piGenesisRequestDigest, snapshotPiGenesisRequest,
  validatePiGenesisResult, type PiGenesisRequest,
} from "./genesis.ts";
import { exactRecord } from "./validation.ts";

// These values are the existing Go enginegenesis wire contract. This codec
// carries operational bytes and external native proofs; it creates no authority.
export const GENESIS_PATH = "/circulusd/engine/v1/genesis:create";
export const PROBE_PATH = "/circulusd/engine/v1/production:probe";
export const GENESIS_TYPE = "application/vnd.circulusd.engine-genesis+cbor";
export const PROBE_TYPE = "application/vnd.circulusd.engine-genesis-probe+cbor";
export const GENESIS_PROTOCOL = "circulus.engine-genesis.v1alpha1";
export const PROBE_PROTOCOL = "circulus.engine-genesis-probe.v1alpha1";
export const GENESIS_SCHEMA = "sha256:c22505f0b66679e1ee81fbb514c26c3f4e44516f620431ad27308dc699727345";
export const PROBE_SCHEMA = "sha256:59b6867a53115e1d759b29dc998dc844022886046f97e1ad837d10a31e26a672";
export const KEY_HEADER = "x-circulus-engine-key-id";
export const SIGNATURE_HEADER = "x-circulus-engine-signature";
export const MAXIMUM_REQUEST_BYTES = 2 << 20;
export const MAXIMUM_RESPONSE_BYTES = (4 << 20) + (64 << 10);
export const MAXIMUM_PROBE_BYTES = 32 << 10;
export const MAXIMUM_PROBE_REQUEST_BYTES = 256;
export const WIRE_OPTIONS = Object.freeze({ maxDepth: 72, maxItems: 100_000 });
const text = new TextEncoder();
const requestIdPattern = /^req_[A-Z2-7]{25}[AEIMQUY4]$/;
const identifierPattern = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;

function invalid(): never {
  throw new PiRuntimeError("INVALID_CONTEXT", "Invalid native genesis wire value");
}
export function exactWireRecord(value: unknown, keys: readonly string[]): Record<string, unknown> {
  return exactRecord(value, keys, [], "genesis.wire", "INVALID_CONTEXT");
}
export function encodeGenesisWire(value: unknown, maximum: number): Uint8Array {
  return encodeCanonicalCbor(value, { ...WIRE_OPTIONS, maxBytes: maximum });
}
export function decodeGenesisWire(value: Uint8Array, maximum: number): unknown {
  return decodeCanonicalCbor(value, { ...WIRE_OPTIONS, maxBytes: maximum });
}

export interface GenesisEnvelope {
  readonly requestId: string;
  readonly requestDigest: Digest;
  readonly request: PiGenesisRequest;
}
export async function parseGenesisEnvelope(value: unknown, now: number): Promise<GenesisEnvelope> {
  const envelope = exactWireRecord(value, ["protocol", "major", "minor", "schemaDigest", "requestId", "sentAtUnixMs", "body"]);
  if (envelope.protocol !== GENESIS_PROTOCOL || envelope.major !== 1 || envelope.minor !== 0 ||
      envelope.schemaDigest !== GENESIS_SCHEMA || typeof envelope.requestId !== "string" ||
      !requestIdPattern.test(envelope.requestId) || !Number.isSafeInteger(now) || now < 0 ||
      typeof envelope.sentAtUnixMs !== "number" || !Number.isSafeInteger(envelope.sentAtUnixMs) ||
      envelope.sentAtUnixMs < 0 || Math.abs(envelope.sentAtUnixMs - now) > 30_000) invalid();
  const request = await snapshotPiGenesisRequest(envelope.body);
  return { requestId: envelope.requestId, requestDigest: await piGenesisRequestDigest(request), request };
}
export function encodeGenesisReply(requestId: string, requestDigest: Digest, payload: unknown): Uint8Array {
  if (!requestIdPattern.test(requestId) || !isDigest(requestDigest)) invalid();
  return encodeGenesisWire({ protocol: GENESIS_PROTOCOL, major: 1, minor: 0, schemaDigest: GENESIS_SCHEMA,
    requestId, requestDigest, payload }, MAXIMUM_RESPONSE_BYTES);
}
export async function genesisSuccessPayload(result: unknown, request: PiGenesisRequest): Promise<NormalizedValue> {
  // Bound and snapshot source-owned data before the first asynchronous hash.
  // In particular, never hash an arbitrary returned binding before comparing
  // its fixed primitive identity to the original bounded request.
  const value = exactWireRecord(result, ["requestDigest", "binding", "checkpoint"]);
  if (!isDigest(value.requestDigest)) invalid();
  const binding = exactWireRecord(value.binding,
    ["tenantId", "workspaceId", "actorSubjectId", "sessionId", "turnId", "runtime", "inputDigest"]);
  const expected = piGenesisBinding(request);
  for (const name of ["tenantId", "workspaceId", "actorSubjectId", "sessionId", "turnId", "inputDigest"] as const) {
    if (binding[name] !== expected[name]) invalid();
  }
  const runtime = exactWireRecord(binding.runtime,
    ["runtimeRevisionDigest", "engineKind", "adapterAbiVersion", "checkpointSchemaVersion"]);
  for (const name of ["runtimeRevisionDigest", "engineKind", "adapterAbiVersion", "checkpointSchemaVersion"] as const) {
    if (runtime[name] !== expected.runtime[name]) invalid();
  }
  const checkpoint = exactWireRecord(value.checkpoint, ["kind", "engineKind", "sessionId", "turnId", "runtimeRevisionDigest",
    "adapterAbiVersion", "checkpointSchemaVersion", "checkpointSequence", "predecessorDigest", "payloadEncoding", "payloadDigest", "payloadBytes"]);
  if (checkpoint.kind !== "genesis" || checkpoint.engineKind !== "low-level" || checkpoint.sessionId !== request.sessionId ||
      checkpoint.turnId !== request.turnId || checkpoint.runtimeRevisionDigest !== request.runtime.runtimeRevisionDigest ||
      checkpoint.adapterAbiVersion !== 2 || checkpoint.checkpointSchemaVersion !== 2 || checkpoint.checkpointSequence !== 0 ||
      checkpoint.predecessorDigest !== null || checkpoint.payloadEncoding !== "canonical-cbor" || !isDigest(checkpoint.payloadDigest) ||
      !(checkpoint.payloadBytes instanceof Uint8Array) || checkpoint.payloadBytes.byteLength < 1 ||
      checkpoint.payloadBytes.byteLength > (4 << 20)) invalid();
  const owned = decodeGenesisWire(encodeGenesisWire(value, MAXIMUM_RESPONSE_BYTES), MAXIMUM_RESPONSE_BYTES);
  const validated = await validatePiGenesisResult(owned, request);
  return { ok: true, identity: piGenesisBinding(request), checkpoint: validated.checkpoint } as unknown as NormalizedValue;
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index++) difference |= left[index]! ^ right[index]!;
  return difference === 0;
}
function exactBytes(value: unknown, size: number): Uint8Array {
  if (!(value instanceof Uint8Array) || Object.getPrototypeOf(value) !== Uint8Array.prototype || value.byteLength !== size) invalid();
  return Uint8Array.from(value);
}
export function parseGenesisProbeRequest(body: Uint8Array): Uint8Array {
  const request = exactWireRecord(decodeGenesisWire(body, MAXIMUM_PROBE_REQUEST_BYTES),
    ["protocol", "major", "minor", "schemaDigest", "nonce"]);
  if (request.protocol !== PROBE_PROTOCOL || request.major !== 1 || request.minor !== 0 || request.schemaDigest !== PROBE_SCHEMA) invalid();
  return exactBytes(request.nonce, 32);
}

// Shape and nonce checks cannot replace Go's independently pinned Ed25519
// signature/evidence verification. Return only the descriptor used for pinning;
// the HTTP worker must forward the original proof bytes unchanged.
export function validateGenesisProbeResponse(body: Uint8Array, nonce: Uint8Array): Record<string, NormalizedValue> {
  const proof = exactWireRecord(decodeGenesisWire(body, MAXIMUM_PROBE_BYTES),
    ["protocol", "major", "minor", "schemaDigest", "nonce", "descriptor", "keyId", "signature"]);
  if (proof.protocol !== PROBE_PROTOCOL || proof.major !== 1 || proof.minor !== 0 || proof.schemaDigest !== PROBE_SCHEMA ||
      !sameBytes(exactBytes(proof.nonce, 32), exactBytes(nonce, 32))) invalid();
  exactBytes(proof.signature, 64);
  const descriptor = exactWireRecord(proof.descriptor, ["schemaVersion", "backendKind", "buildDigest", "applicationDigest",
    "instanceId", "transactionDomainId", "durabilityClass", "conformanceRunId", "conformanceDigest", "runtimeKeyId",
    "probeEpoch", "productionEligible", "atomicGroups"]);
  if (descriptor.schemaVersion !== 1 || descriptor.backendKind !== "celld" || descriptor.durabilityClass !== "crash-durable-rpo0" ||
      descriptor.productionEligible !== true || !isDigest(descriptor.buildDigest) || !isDigest(descriptor.applicationDigest) ||
      !isDigest(descriptor.conformanceDigest) || typeof descriptor.probeEpoch !== "number" ||
      !Number.isSafeInteger(descriptor.probeEpoch) || descriptor.probeEpoch < 1 ||
      typeof proof.keyId !== "string" || !identifierPattern.test(proof.keyId) || proof.keyId !== descriptor.runtimeKeyId ||
      ["instanceId", "transactionDomainId", "conformanceRunId", "runtimeKeyId"].some((key) =>
        typeof descriptor[key] !== "string" || !identifierPattern.test(descriptor[key] as string)) ||
      !Array.isArray(descriptor.atomicGroups) || descriptor.atomicGroups.length > 64 ||
      !descriptor.atomicGroups.includes("engine-genesis")) invalid();
  let previous = "";
  for (const group of descriptor.atomicGroups) {
    if (typeof group !== "string" || !identifierPattern.test(group) || group <= previous) invalid();
    previous = group;
  }
  return descriptor as Record<string, NormalizedValue>;
}

function framed(parts: readonly Uint8Array[]): Uint8Array {
  const length = parts.reduce((total, part) => total + 4 + part.byteLength, 0);
  const result = new Uint8Array(length), view = new DataView(result.buffer);
  let offset = 0;
  for (const part of parts) {
    view.setUint32(offset, part.byteLength, false);
    result.set(part, offset + 4);
    offset += part.byteLength + 4;
  }
  return result;
}
async function hmac(key: Uint8Array, value: Uint8Array): Promise<Uint8Array> {
  const imported = await crypto.subtle.importKey("raw", Uint8Array.from(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", imported, Uint8Array.from(value)));
}
async function rawDigest(value: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", Uint8Array.from(value)));
}
function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
export async function genesisDirectionalKeys(rootKey: Uint8Array): Promise<{ request: Uint8Array; response: Uint8Array }> {
  if (!(rootKey instanceof Uint8Array) || Object.getPrototypeOf(rootKey) !== Uint8Array.prototype ||
      rootKey.byteLength < 32 || rootKey.byteLength > 256) invalid();
  const key = Uint8Array.from(rootKey);
  return { request: await hmac(key, text.encode("circulusd.engine-genesis.key.request.v1\0")),
    response: await hmac(key, text.encode("circulusd.engine-genesis.key.response.v1\0")) };
}
export async function genesisRequestMac(key: Uint8Array, keyId: string, body: Uint8Array): Promise<string> {
  return hex(await hmac(key, framed([text.encode("circulusd.engine-genesis.request.v1"), text.encode(keyId),
    text.encode("POST"), text.encode(GENESIS_PATH), await rawDigest(body)])));
}
export async function genesisResponseMac(key: Uint8Array, keyId: string, requestId: string,
  request: Uint8Array, status: number, response: Uint8Array): Promise<string> {
  return hex(await hmac(key, framed([text.encode("circulusd.engine-genesis.response.v1"), text.encode(keyId),
    text.encode(requestId), await rawDigest(request), text.encode(String(status)), text.encode(GENESIS_TYPE), await rawDigest(response)])));
}
export function equalGenesisMac(left: string, right: string): boolean {
  if (!/^[a-f0-9]{64}$/.test(left) || !/^[a-f0-9]{64}$/.test(right)) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  return difference === 0;
}
