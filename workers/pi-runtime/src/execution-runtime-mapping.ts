import { Point } from "@noble/ed25519";
import {
  decodeCanonicalCbor, digestBytes, encodeCanonicalCbor, isDigest, type Digest,
} from "@circulusd/protocol-types";

import { CELLD_EXECUTION_COMMIT, type PiExecutionRuntimeVerifier } from "./celld-execution.ts";
import { PiRuntimeError } from "./errors.ts";
import { exactRecord } from "./validation.ts";

export const EXECUTION_MAPPING_DOMAIN = "circulusd.pi.execution-runtime-mapping";
export const EXECUTION_MAPPING_MAXIMUM_BYTES = 4096;
export const EXECUTION_MAPPING_OPTIONS = Object.freeze({ maxBytes: EXECUTION_MAPPING_MAXIMUM_BYTES, maxDepth: 16, maxItems: 64 });
const keyIdPattern = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const verifierSeal = Symbol("verified Pi execution runtime mapping");
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const byteLengthGetter = Object.getOwnPropertyDescriptor(typedArrayPrototype, "byteLength")!.get!;
const byteOffsetGetter = Object.getOwnPropertyDescriptor(typedArrayPrototype, "byteOffset")!.get!;
const bufferGetter = Object.getOwnPropertyDescriptor(typedArrayPrototype, "buffer")!.get!;
interface MappingClaims {
  readonly schemaVersion: 1;
  readonly celldCommit: typeof CELLD_EXECUTION_COMMIT;
  readonly adapterAbiVersion: 2;
  readonly checkpointSchemaVersion: 2;
  readonly runtimeRevisionDigest: Digest;
  readonly artifactDigest: Digest;
  readonly keyId: string;
}
export interface PiExecutionMappingTrustRoot {
  readonly keyId: string;
  readonly publicKey: Uint8Array;
}
export interface SignedPiExecutionRuntimeVerifierConfig {
  readonly document: Uint8Array;
  // Pin the domain-separated claims digest, independently of the document and
  // the signature. A valid signer alone cannot repoint the selected revision.
  readonly expectedMappingDigest: Digest;
  readonly trustRoots: readonly PiExecutionMappingTrustRoot[];
}
function invalid(): never {
  throw new PiRuntimeError("INVALID_CONFIGURATION", "Pi execution runtime mapping is invalid or untrusted");
}
function record(value: unknown, keys: readonly string[]): Record<string, unknown> {
  return exactRecord(value, keys, [], "execution.runtimeMapping", "INVALID_CONFIGURATION");
}
function ownedBytes(value: unknown, minimum: number, maximum: number): Uint8Array {
  if (!(value instanceof Uint8Array) || Object.getPrototypeOf(value) !== Uint8Array.prototype) invalid();
  const buffer = bufferGetter.call(value) as ArrayBuffer;
  const byteLength = byteLengthGetter.call(value) as number;
  const byteOffset = byteOffsetGetter.call(value) as number;
  if (!(buffer instanceof ArrayBuffer) || Object.getPrototypeOf(buffer) !== ArrayBuffer.prototype ||
      byteLength < minimum || byteLength > maximum) invalid();
  return new Uint8Array(new Uint8Array(buffer, byteOffset, byteLength));
}
function claimsSnapshot(value: unknown): MappingClaims {
  const claims = record(value, ["schemaVersion", "celldCommit", "adapterAbiVersion", "checkpointSchemaVersion",
    "runtimeRevisionDigest", "artifactDigest", "keyId"]);
  if (claims.schemaVersion !== 1 || claims.celldCommit !== CELLD_EXECUTION_COMMIT || claims.adapterAbiVersion !== 2 ||
      claims.checkpointSchemaVersion !== 2 || !isDigest(claims.runtimeRevisionDigest) || !isDigest(claims.artifactDigest) ||
      typeof claims.keyId !== "string" || !keyIdPattern.test(claims.keyId)) invalid();
  return { schemaVersion: 1, celldCommit: CELLD_EXECUTION_COMMIT, adapterAbiVersion: 2, checkpointSchemaVersion: 2,
    runtimeRevisionDigest: claims.runtimeRevisionDigest, artifactDigest: claims.artifactDigest, keyId: claims.keyId };
}
function rootsSnapshot(value: unknown): Map<string, Uint8Array> {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length < 1 ||
      value.length > 64 || Reflect.ownKeys(value).length !== value.length + 1) invalid();
  const roots = new Map<string, Uint8Array>(), materials = new Set<string>();
  for (let index = 0; index < value.length; index++) {
    const property = Object.getOwnPropertyDescriptor(value, String(index));
    if (!property?.enumerable || !("value" in property)) invalid();
    const root = record(property.value, ["keyId", "publicKey"]);
    if (typeof root.keyId !== "string" || !keyIdPattern.test(root.keyId) || roots.has(root.keyId)) invalid();
    const key = ownedBytes(root.publicKey, 32, 32);
    // Match the Go dependency root policy using the pinned library's public
    // point operations. Signature verification still belongs to WebCrypto.
    const point = Point.fromBytes(key, false);
    const material = point.toHex();
    if (point.is0() || !point.isTorsionFree() || material !== Array.from(key,
      (byte) => byte.toString(16).padStart(2, "0")).join("") || materials.has(material)) invalid();
    materials.add(material);
    roots.set(root.keyId, key);
  }
  return roots;
}

// The signed document authorizes exactly one immutable revision/artifact pair.
// It contains no expiry or live native claim; revocation/replacement requires a
// newly trusted composition. Original Session replay must retain its mapping.
export class SignedPiExecutionRuntimeVerifier implements PiExecutionRuntimeVerifier {
  readonly #claims: MappingClaims;

  private constructor(seal: typeof verifierSeal, claims: MappingClaims) {
    if (seal !== verifierSeal) invalid();
    this.#claims = Object.freeze(claims);
    Object.freeze(this);
  }
  static async create(value: SignedPiExecutionRuntimeVerifierConfig): Promise<SignedPiExecutionRuntimeVerifier> {
    try {
      const config = record(value, ["document", "expectedMappingDigest", "trustRoots"]);
      if (!isDigest(config.expectedMappingDigest)) invalid();
      const expected = config.expectedMappingDigest;
      const bytes = ownedBytes(config.document, 1, EXECUTION_MAPPING_MAXIMUM_BYTES);
      const roots = rootsSnapshot(config.trustRoots);
      const document = record(decodeCanonicalCbor(bytes, EXECUTION_MAPPING_OPTIONS), ["claims", "algorithm", "signature"]);
      if (document.algorithm !== "ed25519") invalid();
      const claims = claimsSnapshot(document.claims), signature = ownedBytes(document.signature, 64, 64);
      const key = roots.get(claims.keyId);
      if (key === undefined) invalid();
      // Everything mutable is owned before the first asynchronous operation.
      const digest = await digestBytes(encodeCanonicalCbor(["circulusd.hash", 1, EXECUTION_MAPPING_DOMAIN, 1, claims], EXECUTION_MAPPING_OPTIONS));
      if (digest !== expected) invalid();
      const publicKey = await crypto.subtle.importKey("raw", Uint8Array.from(key), { name: "Ed25519" }, false, ["verify"]);
      if (!await crypto.subtle.verify({ name: "Ed25519" }, publicKey, Uint8Array.from(signature), new TextEncoder().encode(digest))) invalid();
      return new SignedPiExecutionRuntimeVerifier(verifierSeal, claims);
    } catch { return invalid(); }
  }
  async verify(value: { readonly runtimeRevisionDigest: Digest; readonly artifactDigest: Digest }):
    Promise<{ readonly runtimeRevisionDigest: Digest; readonly artifactDigest: Digest; readonly mappingDomain: typeof EXECUTION_MAPPING_DOMAIN }> {
    try {
      const binding = record(value, ["runtimeRevisionDigest", "artifactDigest"]);
      if (binding.runtimeRevisionDigest !== this.#claims.runtimeRevisionDigest || binding.artifactDigest !== this.#claims.artifactDigest) invalid();
      return { runtimeRevisionDigest: this.#claims.runtimeRevisionDigest, artifactDigest: this.#claims.artifactDigest,
        mappingDomain: EXECUTION_MAPPING_DOMAIN };
    } catch { return invalid(); }
  }
}
