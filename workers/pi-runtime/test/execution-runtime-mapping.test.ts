import { readFileSync } from "node:fs";
import { digestStructuredValue, encodeCanonicalCbor, decodeCanonicalCbor, type Digest } from "@circulusd/protocol-types";
import { describe, expect, it, vi } from "vitest";

import {
  EXECUTION_MAPPING_DOMAIN, EXECUTION_MAPPING_MAXIMUM_BYTES, EXECUTION_MAPPING_OPTIONS,
  SignedPiExecutionRuntimeVerifier, type SignedPiExecutionRuntimeVerifierConfig,
} from "../src/execution-runtime-mapping.ts";
import { GENESIS_MAPPING_DOMAIN, SignedPiGenesisRuntimeVerifier } from "../src/genesis-runtime-mapping.ts";

interface Fixture {
  testOnly: boolean;
  domain: string;
  claims: { runtimeRevisionDigest: Digest; artifactDigest: Digest; keyId: string };
  publicKeyHex: string;
  claimsCBORHex: string;
  signingDigest: Digest;
  signatureHex: string;
  documentCBORHex: string;
  invalidPublicKeys: { name: string; publicKeyHex: string }[];
  crossPurpose: { domain: string; signingDigest: Digest; signatureHex: string; documentCBORHex: string };
}
function fixture(): Fixture {
  return JSON.parse(readFileSync(new URL("../../../packages/protocol-types/fixtures/pi-execution-runtime-mapping-v1alpha1.json", import.meta.url), "utf8")) as Fixture;
}
function fromHex(value: string): Uint8Array {
  return Uint8Array.from(value.match(/../g)!, (pair) => Number.parseInt(pair, 16));
}
function toHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
function configuration(): SignedPiExecutionRuntimeVerifierConfig {
  const value = fixture();
  return { document: fromHex(value.documentCBORHex), expectedMappingDigest: value.signingDigest,
    trustRoots: [{ keyId: value.claims.keyId, publicKey: fromHex(value.publicKeyHex) }] };
}
function document() {
  return decodeCanonicalCbor(configuration().document, EXECUTION_MAPPING_OPTIONS) as {
    algorithm: string; signature: Uint8Array; claims: Record<string, unknown>;
  };
}
function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((yes) => { resolve = yes; });
  return { promise, resolve };
}

describe("independently pinned signed Pi execution runtime mappings", () => {
  it("verifies the exact Go canonical claim/signature fixture with WebCrypto", async () => {
    const value = fixture();
    expect(value.testOnly).toBe(true);
    expect(value.domain).toBe(EXECUTION_MAPPING_DOMAIN);
    const decoded = document();
    expect(toHex(encodeCanonicalCbor(decoded.claims, EXECUTION_MAPPING_OPTIONS))).toBe(value.claimsCBORHex);
    expect(toHex(decoded.signature)).toBe(value.signatureHex);
    expect(await digestStructuredValue(EXECUTION_MAPPING_DOMAIN, 1, decoded.claims)).toBe(value.signingDigest);
    const verifier = await SignedPiExecutionRuntimeVerifier.create(configuration());
    expect(await verifier.verify({ runtimeRevisionDigest: value.claims.runtimeRevisionDigest, artifactDigest: value.claims.artifactDigest }))
      .toEqual({ runtimeRevisionDigest: value.claims.runtimeRevisionDigest, artifactDigest: value.claims.artifactDigest,
        mappingDomain: EXECUTION_MAPPING_DOMAIN });
    expect("ProbeProduction" in verifier).toBe(false);
    expect(Object.isFrozen(verifier)).toBe(true);
  });
  it.each(["revision", "artifact", "pin", "root", "untrusted-key", "signature"])("rejects independent trust mismatch: %s", async (kind) => {
    const config = configuration(), value = document();
    if (kind === "revision") value.claims.runtimeRevisionDigest = `sha256:${"a".repeat(64)}`;
    if (kind === "artifact") value.claims.artifactDigest = `sha256:${"b".repeat(64)}`;
    if (kind === "signature") value.signature[0] = value.signature[0]! ^ 1;
    const changed: SignedPiExecutionRuntimeVerifierConfig = { ...config,
      document: encodeCanonicalCbor(value, EXECUTION_MAPPING_OPTIONS),
      expectedMappingDigest: kind === "pin" ? `sha256:${"c".repeat(64)}` :
        kind === "revision" || kind === "artifact" ? await digestStructuredValue(EXECUTION_MAPPING_DOMAIN, 1, value.claims) : config.expectedMappingDigest,
      trustRoots: kind === "root" ? [{ keyId: fixture().claims.keyId, publicKey: fromHex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a") }] :
        kind === "untrusted-key" ? [{ ...config.trustRoots[0]!, keyId: "other-root" }] : config.trustRoots };
    await expect(SignedPiExecutionRuntimeVerifier.create(changed)).rejects.toThrow("invalid or untrusted");
  });
  it.each(["schema", "celld", "abi", "checkpoint-schema", "algorithm", "extra-claim", "short-signature"])("rejects unsupported claim/document: %s", async (kind) => {
    const value = document();
    if (kind === "schema") value.claims.schemaVersion = 2;
    if (kind === "celld") value.claims.celldCommit = "0".repeat(40);
    if (kind === "abi") value.claims.adapterAbiVersion = 1;
    if (kind === "checkpoint-schema") value.claims.checkpointSchemaVersion = 3;
    if (kind === "algorithm") value.algorithm = "Ed25519";
    if (kind === "extra-claim") value.claims.productionEligible = true;
    if (kind === "short-signature") value.signature = new Uint8Array(63);
    await expect(SignedPiExecutionRuntimeVerifier.create({ ...configuration(), document: encodeCanonicalCbor(value, EXECUTION_MAPPING_OPTIONS) }))
      .rejects.toThrow("invalid or untrusted");
  });
  it("rejects oversized, trailing, duplicate and noncanonical CBOR before crypto", async () => {
    const config = configuration(), spy = vi.spyOn(crypto.subtle, "digest");
    const trailing = new Uint8Array(config.document.byteLength + 1);
    trailing.set(config.document);
    const nonminimal = new Uint8Array(config.document.byteLength + 1);
    nonminimal.set([0xb8, 3]); nonminimal.set(config.document.slice(1), 2);
    try {
      for (const document of [new Uint8Array(EXECUTION_MAPPING_MAXIMUM_BYTES + 1), trailing, nonminimal,
        fromHex("a266636c61696d730066636c61696d7300")]) {
        await expect(SignedPiExecutionRuntimeVerifier.create({ ...config, document })).rejects.toThrow("invalid or untrusted");
      }
      expect(spy).not.toHaveBeenCalled();
    } finally { spy.mockRestore(); }
  });
  it("rejects weak/noncanonical public keys shared with Go before WebCrypto import", async () => {
    const vectors = fixture().invalidPublicKeys;
    expect(vectors.length).toBeGreaterThanOrEqual(4);
    const importKey = vi.spyOn(crypto.subtle, "importKey");
    try {
      for (const vector of vectors) {
        await expect(SignedPiExecutionRuntimeVerifier.create({ ...configuration(), trustRoots: [
          { keyId: fixture().claims.keyId, publicKey: fromHex(vector.publicKeyHex) },
        ] }), vector.name).rejects.toThrow("invalid or untrusted");
      }
      expect(importKey).not.toHaveBeenCalled();
    } finally { importKey.mockRestore(); }
  });
  it("rejects root aliases, duplicate IDs, missing roots and malformed configurations", async () => {
    const config = configuration(), root = config.trustRoots[0]!;
    for (const trustRoots of [[], [root, root], [root, { ...root, keyId: "alias-root" }],
      [{ ...root, publicKey: new Uint8Array(31) }], Array.from({ length: 65 }, () => root)]) {
      await expect(SignedPiExecutionRuntimeVerifier.create({ ...config, trustRoots })).rejects.toThrow("invalid or untrusted");
    }
    const accessor = { ...config };
    let called = false;
    Object.defineProperty(accessor, "document", { enumerable: true, get() { called = true; return config.document; } });
    await expect(SignedPiExecutionRuntimeVerifier.create(accessor)).rejects.toThrow("invalid or untrusted");
    expect(called).toBe(false);
  });
  it("snapshots caller document, root bytes, array entries and digest before any asynchronous crypto", async () => {
    const config = configuration(), entered = deferred(), release = deferred();
    const original = crypto.subtle.digest.bind(crypto.subtle);
    const spy = vi.spyOn(crypto.subtle, "digest").mockImplementation(async (algorithm, input) => {
      entered.resolve(); await release.promise; return original(algorithm, input);
    });
    try {
      const pending = SignedPiExecutionRuntimeVerifier.create(config);
      await entered.promise;
      config.document.fill(0); config.trustRoots[0]!.publicKey.fill(0);
      (config as { expectedMappingDigest: Digest }).expectedMappingDigest = `sha256:${"f".repeat(64)}`;
      (config.trustRoots as unknown[]).splice(0);
      release.resolve();
      const verifier = await pending, value = fixture();
      const binding = { runtimeRevisionDigest: value.claims.runtimeRevisionDigest, artifactDigest: value.claims.artifactDigest };
      const returned = await verifier.verify(binding);
      (returned as { artifactDigest: Digest }).artifactDigest = `sha256:${"a".repeat(64)}`;
      expect(await verifier.verify(binding)).toEqual({ ...binding, mappingDomain: EXECUTION_MAPPING_DOMAIN });
    } finally { release.resolve(); spy.mockRestore(); }
  });
  it("accepts only the sealed exact revision/artifact pair and rejects fabricated instances", async () => {
    const verifier = await SignedPiExecutionRuntimeVerifier.create(configuration()), value = fixture();
    const binding = { runtimeRevisionDigest: value.claims.runtimeRevisionDigest, artifactDigest: value.claims.artifactDigest };
    for (const bad of [{ ...binding, artifactDigest: `sha256:${"a".repeat(64)}` },
      { ...binding, runtimeRevisionDigest: `sha256:${"b".repeat(64)}` }, { ...binding, extra: true }]) {
      await expect(verifier.verify(bad as { runtimeRevisionDigest: Digest; artifactDigest: Digest })).rejects.toThrow("invalid or untrusted");
    }
    const fabricated = Object.create(SignedPiExecutionRuntimeVerifier.prototype) as SignedPiExecutionRuntimeVerifier;
    await expect(fabricated.verify(binding)).rejects.toThrow("invalid or untrusted");
  });
  it("rejects direct JavaScript construction without verified document provenance", () => {
    const claims = fixture().claims;
    for (const args of [[], [claims], [Symbol("verified Pi execution runtime mapping"), claims]]) {
      expect(() => Reflect.construct(SignedPiExecutionRuntimeVerifier, args)).toThrow("invalid or untrusted");
    }
  });
  it("rejects genesis signatures even for identical claims and trusted public keys", async () => {
    const value = fixture(), config = configuration(), crossed = value.crossPurpose;
    expect(crossed.domain).toBe(GENESIS_MAPPING_DOMAIN);
    const decoded = decodeCanonicalCbor(fromHex(crossed.documentCBORHex), EXECUTION_MAPPING_OPTIONS) as {
      claims: Record<string, unknown>; algorithm: string; signature: Uint8Array;
    };
    expect(decoded.claims).toEqual(value.claims);
    expect(toHex(decoded.signature)).toBe(crossed.signatureHex);
    expect(await digestStructuredValue(GENESIS_MAPPING_DOMAIN, 1, decoded.claims)).toBe(crossed.signingDigest);
    expect(value.signingDigest).not.toBe(crossed.signingDigest);
    const genesis = await SignedPiGenesisRuntimeVerifier.create({ ...config,
      document: fromHex(crossed.documentCBORHex), expectedMappingDigest: crossed.signingDigest });
    const pair = { runtimeRevisionDigest: value.claims.runtimeRevisionDigest, artifactDigest: value.claims.artifactDigest };
    const genesisBinding = await genesis.verify(pair);
    expect(genesisBinding).toEqual(pair);
    expect("mappingDomain" in genesisBinding).toBe(false);
    for (const expectedMappingDigest of [config.expectedMappingDigest, crossed.signingDigest]) {
      await expect(SignedPiExecutionRuntimeVerifier.create({ ...config,
        document: fromHex(crossed.documentCBORHex), expectedMappingDigest })).rejects.toThrow("invalid or untrusted");
    }
    await expect(SignedPiGenesisRuntimeVerifier.create({ ...config, expectedMappingDigest: crossed.signingDigest })).rejects.toThrow("invalid or untrusted");
    const execution = await SignedPiExecutionRuntimeVerifier.create(config);
    expect(await execution.verify(pair)).toEqual({ ...pair, mappingDomain: EXECUTION_MAPPING_DOMAIN });
  });
  it("uses intrinsic byte bounds and snapshots without invoking shadowed accessors or iterators", async () => {
    const config = configuration(), byteGetter = vi.fn(() => 0), iterator = vi.fn(function* () { yield 0; });
    Object.defineProperty(config.document, "byteLength", { get: byteGetter });
    Object.defineProperty(config.document, "buffer", { get: byteGetter });
    Object.defineProperty(config.document, Symbol.iterator, { value: iterator });
    expect(await SignedPiExecutionRuntimeVerifier.create(config)).toBeInstanceOf(SignedPiExecutionRuntimeVerifier);
    expect(byteGetter).not.toHaveBeenCalled(); expect(iterator).not.toHaveBeenCalled();
    const oversized = new Uint8Array(EXECUTION_MAPPING_MAXIMUM_BYTES + 1);
    Object.defineProperty(oversized, "byteLength", { get: byteGetter });
    await expect(SignedPiExecutionRuntimeVerifier.create({ ...configuration(), document: oversized })).rejects.toThrow("invalid or untrusted");
    expect(byteGetter).not.toHaveBeenCalled();
  });
  it("fails closed with sanitized errors when Ed25519 is unsupported or verification fails", async () => {
    const spy = vi.spyOn(crypto.subtle, "importKey").mockRejectedValue(new Error("private native crypto diagnostic"));
    try {
      await expect(SignedPiExecutionRuntimeVerifier.create(configuration())).rejects.toThrow("invalid or untrusted");
    } finally { spy.mockRestore(); }
    const verify = vi.spyOn(crypto.subtle, "verify").mockResolvedValue(false);
    try {
      await expect(SignedPiExecutionRuntimeVerifier.create(configuration())).rejects.toThrow("invalid or untrusted");
    } finally { verify.mockRestore(); }
  });
});
