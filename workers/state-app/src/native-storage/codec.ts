import {
  assertUnicodeScalarString, decodeCanonicalCbor, digestBytes,
  encodeCanonicalCbor, isDigest, type Digest,
} from "@circulusd/protocol-types";
import {
  MAXIMUM_BOUNDS, MAXIMUM_REVISION, NativeStorageError, resolveNativeStorageBounds,
  type BarrierRequest, type CommitRequest, type CommitToken, type NativeStorageBounds,
  type ReceiptRequest, type SnapshotRef, type StoredReceipt,
} from "./types.ts";

export const EMPTY_DIGEST: Digest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
export const WIRE_OPTIONS = Object.freeze({ maxDepth: 72, maxItems: 100_000 });
export const TRANSACTION_PATH = "/circulusd/native-storage/v1/transaction";
export const PROBE_PATH = "/circulusd/native-storage/v1/production:probe";
export const TRANSACTION_TYPE = "application/vnd.circulusd.native-storage+cbor";
export const PROBE_TYPE = "application/vnd.circulusd.native-storage-probe+cbor";
export const STORAGE_PROTOCOL = "circulus.native-storage.v1alpha1";
export const STORAGE_SCHEMA: Digest = "sha256:b3222157ec628b63a39ff6dfac172a0128fe2f762bce82db7b9dc4b35f0b9dd8";
export const PROBE_PROTOCOL = "circulus.native-storage-probe.v1alpha1";
export const PROBE_SCHEMA: Digest = "sha256:0a244832949f7a326d4bf83069f58c579a6aada1187cde3d53d46ab740de0b01";
export const KEY_HEADER = "x-circulus-storage-key-id";
export const SIGNATURE_HEADER = "x-circulus-storage-signature";
export const MAXIMUM_PROBE_BYTES = 32 << 10;
export const REQUEST_ID_PATTERN = /^req_[A-Z2-7]{25}[AEIMQUY4]$/;
export type StorageOperation = "snapshot" | "receipt" | "commit" | "barrier";
export interface StorageEnvelope {
  readonly protocol: typeof STORAGE_PROTOCOL;
  readonly major: 1;
  readonly minor: 0;
  readonly schemaDigest: Digest;
  readonly requestId: string;
  readonly sentAtUnixMs: number;
  readonly operation: StorageOperation;
  readonly body: unknown;
}
const encoder = new TextEncoder();
export function invalid(): never { throw new NativeStorageError("INVALID_ARGUMENT"); }
export function record(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value) ||
      (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) ||
      Reflect.ownKeys(value).length !== fields.length || fields.some((key) => !Object.hasOwn(value, key))) invalid();
  for (const key of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !("value" in descriptor)) invalid();
  }
  return value as Record<string, unknown>;
}
export function identifier(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || value.normalize("NFC") !== value || /\p{Cc}/u.test(value)) invalid();
  try { assertUnicodeScalarString(value, "$identifier"); } catch { invalid(); }
  if (encoder.encode(value).byteLength > 256) invalid();
  return value;
}
export function revision(value: unknown, minimum = 0): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum || Object.is(value, -0)) invalid();
  return value;
}
export function bytes(value: unknown, maximum: number): Uint8Array {
  if (!(value instanceof Uint8Array) || value.byteLength > maximum) invalid();
  return Uint8Array.from(value);
}
export function snapshotRef(value: unknown): SnapshotRef {
  const ref = record(value, ["objectId", "exists", "revision", "stateDigest"]);
  const objectId = identifier(ref.objectId);
  const rev = revision(ref.revision);
  if (typeof ref.exists !== "boolean" || !isDigest(ref.stateDigest) ||
      (ref.exists && rev === 0) || (!ref.exists && (rev !== 0 || ref.stateDigest !== EMPTY_DIGEST))) invalid();
  return { objectId, exists: ref.exists, revision: rev, stateDigest: ref.stateDigest };
}
export function commitToken(value: unknown): CommitToken {
  const token = record(value, ["objectId", "revision"]);
  return { objectId: identifier(token.objectId), revision: revision(token.revision, 1) };
}
export function storedReceipt(value: unknown, bounds: NativeStorageBounds = MAXIMUM_BOUNDS): StoredReceipt {
  const receipt = record(value, ["commandDigest", "response", "capabilityClaims"]);
  if (!isDigest(receipt.commandDigest) || !Array.isArray(receipt.capabilityClaims) ||
      receipt.capabilityClaims.length > bounds.maxCapabilityClaims) invalid();
  const response = bytes(receipt.response, bounds.maxReceiptResponseBytes);
  let total = 0;
  const capabilityClaims = receipt.capabilityClaims.map((value) => {
    const claim = record(value, ["kind", "payload"]);
    const kind = identifier(claim.kind);
    const payload = bytes(claim.payload, bounds.maxCapabilityClaimBytes - total);
    total += payload.byteLength;
    return { kind, payload };
  });
  return { commandDigest: receipt.commandDigest, response, capabilityClaims };
}
// Go sorts strings by UTF-8 bytes, which differs from UTF-16 ordering around
// supplementary Unicode characters. Command IDs must use the same ordering.
function compareIdentifiers(left: string, right: string): number {
  const a = encoder.encode(left), b = encoder.encode(right);
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i]! - b[i]!;
  return a.length - b.length;
}
export function parseReceiptRequest(value: unknown): ReceiptRequest {
  const request = record(value, ["snapshot", "commandId"]);
  return { snapshot: snapshotRef(request.snapshot), commandId: identifier(request.commandId) };
}
export async function commitDigest(request: Omit<CommitRequest, "requestDigest">): Promise<Digest> {
  return structuredDigest("circulusd.native.storage.commit", request);
}
export async function parseCommitRequest(value: unknown, bounds: NativeStorageBounds = MAXIMUM_BOUNDS): Promise<CommitRequest> {
  const request = record(value, ["snapshot", "stateWritten", "state", "receipts", "requestDigest"]);
  const snapshot = snapshotRef(request.snapshot);
  if (snapshot.revision === MAXIMUM_REVISION || typeof request.stateWritten !== "boolean" ||
      !Array.isArray(request.receipts) || request.receipts.length > bounds.maxReceiptWrites || !isDigest(request.requestDigest)) invalid();
  const state = bytes(request.state, bounds.maxStateBytes);
  const retainedDigest = request.requestDigest;
  if (!request.stateWritten && state.byteLength !== 0) invalid();
  let previous = "";
  const receipts = request.receipts.map((value) => {
    const write = record(value, ["commandId", "receipt"]);
    const commandId = identifier(write.commandId);
    if (previous !== "" && compareIdentifiers(previous, commandId) >= 0) invalid();
    previous = commandId;
    return { commandId, receipt: storedReceipt(write.receipt, bounds) };
  });
  const body = { snapshot, stateWritten: request.stateWritten, state, receipts };
  encodeWire(body, bounds);
  if (await commitDigest(body) !== retainedDigest) invalid();
  return { ...body, requestDigest: retainedDigest };
}
export function parseBarrierRequest(value: unknown): BarrierRequest {
  const request = record(value, ["token", "marker"]);
  const marker = bytes(request.marker, 32);
  if (marker.byteLength !== 32) invalid();
  return { token: commitToken(request.token), marker };
}
export function encodeWire(value: unknown, bounds: NativeStorageBounds = MAXIMUM_BOUNDS): Uint8Array {
  try { return encodeCanonicalCbor(value, { ...WIRE_OPTIONS, maxBytes: bounds.maxTransactionBytes }); }
  catch { return invalid(); }
}
export function decodeWire(value: Uint8Array, bounds: NativeStorageBounds = MAXIMUM_BOUNDS): unknown {
  try { return decodeCanonicalCbor(value, { ...WIRE_OPTIONS, maxBytes: bounds.maxTransactionBytes }); }
  catch { return invalid(); }
}
export async function validateStateDigest(state: Uint8Array, expected: Digest): Promise<void> {
  if (await digestBytes(state) !== expected) throw new NativeStorageError("UNAVAILABLE");
}
export async function parseEnvelope(value: unknown, bounds: NativeStorageBounds, now: number): Promise<StorageEnvelope> {
  const envelope = record(value, ["protocol", "major", "minor", "schemaDigest", "requestId", "sentAtUnixMs", "operation", "body"]);
  if (envelope.protocol !== STORAGE_PROTOCOL || envelope.major !== 1 || envelope.minor !== 0 ||
      envelope.schemaDigest !== STORAGE_SCHEMA || typeof envelope.requestId !== "string" ||
      !REQUEST_ID_PATTERN.test(envelope.requestId) ||
      Math.abs(revision(envelope.sentAtUnixMs) - now) > 60_000) invalid();
  let body: unknown;
  switch (envelope.operation) {
    case "snapshot": body = { objectId: identifier(record(envelope.body, ["objectId"]).objectId) }; break;
    case "receipt": body = parseReceiptRequest(envelope.body); break;
    case "commit": body = await parseCommitRequest(envelope.body, bounds); break;
    case "barrier": body = parseBarrierRequest(envelope.body); break;
    default: return invalid();
  }
  return { protocol: STORAGE_PROTOCOL, major: 1, minor: 0, schemaDigest: STORAGE_SCHEMA,
    requestId: envelope.requestId, sentAtUnixMs: envelope.sentAtUnixMs as number, operation: envelope.operation, body };
}
export async function requestDigest(envelope: unknown): Promise<Digest> {
  return structuredDigest("circulusd.native.storage.request", envelope);
}
async function structuredDigest(domain: string, value: unknown): Promise<Digest> {
  return digestBytes(encodeWire(["circulusd.hash", 1, domain, 1, value]));
}
export function envelopeObjectId(envelope: StorageEnvelope): string {
  if (envelope.operation === "snapshot") return identifier(record(envelope.body, ["objectId"]).objectId);
  if (envelope.operation === "barrier") return parseBarrierRequest(envelope.body).token.objectId;
  const fields = envelope.operation === "receipt" ? ["snapshot", "commandId"] : ["snapshot", "stateWritten", "state", "receipts", "requestDigest"];
  return snapshotRef(record(envelope.body, fields).snapshot).objectId;
}
export function fromHex(value: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})+$/.test(value)) invalid();
  return Uint8Array.from(value.match(/../g)!, (part) => Number.parseInt(part, 16));
}
export function toHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
async function hmac(key: Uint8Array, input: Uint8Array): Promise<Uint8Array> {
  const imported = await crypto.subtle.importKey("raw", Uint8Array.from(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", imported, Uint8Array.from(input)));
}
function frame(parts: readonly Uint8Array[]): Uint8Array {
  const size = parts.reduce((total, part) => total + 4 + part.byteLength, 0);
  const value = new Uint8Array(size), view = new DataView(value.buffer);
  let offset = 0;
  for (const part of parts) {
    view.setUint32(offset, part.byteLength, false); offset += 4;
    value.set(part, offset); offset += part.byteLength;
  }
  return value;
}
async function sha256(value: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", Uint8Array.from(value)));
}
export async function storageDirectionalKeys(root: Uint8Array): Promise<{ readonly request: Uint8Array; readonly response: Uint8Array }> {
  const [request, response] = await Promise.all([
    hmac(root, encoder.encode("circulusd.native-storage.key.request.v1\0")),
    hmac(root, encoder.encode("circulusd.native-storage.key.response.v1\0")),
  ]);
  return { request, response };
}
export async function storageRequestMac(key: Uint8Array, keyId: string, body: Uint8Array): Promise<string> {
  return toHex(await hmac(key, frame([encoder.encode("circulusd.native-storage.request.v1"), encoder.encode(keyId),
    encoder.encode("POST"), encoder.encode(TRANSACTION_PATH), await sha256(body)])));
}
export async function storageResponseMac(key: Uint8Array, keyId: string, requestId: string, request: Uint8Array,
  status: number, body: Uint8Array): Promise<string> {
  return toHex(await hmac(key, frame([encoder.encode("circulusd.native-storage.response.v1"), encoder.encode(keyId),
    encoder.encode(requestId), await sha256(request), encoder.encode(String(status)), encoder.encode(TRANSACTION_TYPE), await sha256(body)])));
}
export function equalMac(left: string, right: string): boolean {
  if (!/^[0-9a-f]{64}$/.test(left) || !/^[0-9a-f]{64}$/.test(right)) return false;
  let difference = 0;
  for (let i = 0; i < 64; i++) difference |= left.charCodeAt(i) ^ right.charCodeAt(i);
  return difference === 0;
}
export { resolveNativeStorageBounds };
