import { readFileSync } from "node:fs";
import { digestBytes, type NormalizedValue } from "@circulusd/protocol-types";
import { describe, expect, it, vi } from "vitest";

import {
  GENESIS_PATH, GENESIS_PROTOCOL, GENESIS_SCHEMA, GENESIS_TYPE, KEY_HEADER,
  MAXIMUM_PROBE_BYTES, MAXIMUM_PROBE_REQUEST_BYTES, MAXIMUM_REQUEST_BYTES, MAXIMUM_RESPONSE_BYTES,
  PROBE_PROTOCOL, PROBE_SCHEMA, SIGNATURE_HEADER, decodeGenesisWire, encodeGenesisReply, encodeGenesisWire,
  equalGenesisMac, exactWireRecord, genesisDirectionalKeys, genesisRequestMac, genesisResponseMac,
  genesisSuccessPayload, parseGenesisEnvelope, parseGenesisProbeRequest, validateGenesisProbeResponse,
} from "../src/genesis-wire.ts";
import { piGenesisBinding } from "../src/genesis.ts";

interface Fixture {
  testOnly: boolean;
  protocol: string;
  path: string;
  contentType: string;
  headerNames: { keyId: string; signature: string };
  schemaDigests: { genesis: string; probe: string };
  keyId: string;
  rootKey: string;
  requestKey: string;
  responseKey: string;
  requestId: string;
  sentAtUnixMs: number;
  requestCBORHex: string;
  requestMAC: string;
  requestDigest: string;
  checkpointCBORHex: string;
  cases: { name: string; status: number; responseCBORHex: string; responseMAC: string }[];
}
const fixture = JSON.parse(readFileSync(new URL("../../../packages/protocol-types/fixtures/engine-genesis-v1alpha1.json", import.meta.url), "utf8")) as Fixture;
function fromHex(value: string): Uint8Array {
  return Uint8Array.from(value.match(/../g)!, (part) => Number.parseInt(part, 16));
}
function toHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
async function envelope() {
  return parseGenesisEnvelope(decodeGenesisWire(fromHex(fixture.requestCBORHex), MAXIMUM_REQUEST_BYTES), fixture.sentAtUnixMs);
}
async function result() {
  const parsed = await envelope();
  return { requestDigest: parsed.requestDigest, binding: piGenesisBinding(parsed.request),
    checkpoint: decodeGenesisWire(fromHex(fixture.checkpointCBORHex), MAXIMUM_RESPONSE_BYTES) };
}
function proof(nonce = new Uint8Array(32)): Record<string, NormalizedValue> {
  return { protocol: PROBE_PROTOCOL, major: 1, minor: 0, schemaDigest: PROBE_SCHEMA, nonce,
    keyId: "native-runtime-key", signature: new Uint8Array(64),
    descriptor: { schemaVersion: 1, backendKind: "celld", buildDigest: `sha256:${"a".repeat(64)}`,
      applicationDigest: `sha256:${"b".repeat(64)}`, instanceId: "native-instance", transactionDomainId: "native-domain",
      durabilityClass: "crash-durable-rpo0", conformanceRunId: "native-run", conformanceDigest: `sha256:${"c".repeat(64)}`,
      runtimeKeyId: "native-runtime-key", probeEpoch: 1, productionEligible: true, atomicGroups: ["engine-genesis"] } };
}

describe("native genesis Go/TypeScript wire compatibility", () => {
  it("matches existing Go schema, semantic request digest and directional keys", async () => {
    expect(fixture.testOnly).toBe(true);
    expect([fixture.protocol, fixture.path, fixture.contentType, fixture.headerNames.keyId, fixture.headerNames.signature])
      .toEqual([GENESIS_PROTOCOL, GENESIS_PATH, GENESIS_TYPE, KEY_HEADER, SIGNATURE_HEADER]);
    expect(fixture.schemaDigests).toEqual({ genesis: GENESIS_SCHEMA, probe: PROBE_SCHEMA });
    const keys = await genesisDirectionalKeys(fromHex(fixture.rootKey));
    expect(toHex(keys.request)).toBe(fixture.requestKey);
    expect(toHex(keys.response)).toBe(fixture.responseKey);
    expect(await genesisRequestMac(keys.request, fixture.keyId, fromHex(fixture.requestCBORHex))).toBe(fixture.requestMAC);
    expect((await envelope()).requestDigest).toBe(fixture.requestDigest);
  });
  it("matches every exact Go response envelope and MAC including error statuses", async () => {
    const keys = await genesisDirectionalKeys(fromHex(fixture.rootKey));
    const parsed = await envelope();
    for (const vector of fixture.cases) {
      const bytes = fromHex(vector.responseCBORHex);
      const value = exactWireRecord(decodeGenesisWire(bytes, MAXIMUM_RESPONSE_BYTES),
        ["protocol", "major", "minor", "schemaDigest", "requestId", "requestDigest", "payload"]);
      expect([value.requestId, value.requestDigest, value.schemaDigest]).toEqual([parsed.requestId, parsed.requestDigest, GENESIS_SCHEMA]);
      expect(toHex(encodeGenesisReply(parsed.requestId, parsed.requestDigest, value.payload)))
        .toBe(vector.responseCBORHex);
      expect(await genesisResponseMac(keys.response, fixture.keyId, fixture.requestId, fromHex(fixture.requestCBORHex), vector.status, bytes))
        .toBe(vector.responseMAC);
      expect(await genesisResponseMac(keys.response, fixture.keyId, fixture.requestId, fromHex(fixture.requestCBORHex), vector.status + 1, bytes))
        .not.toBe(vector.responseMAC);
    }
  });
  it("validates actual Pi checkpoint bytes into the exact Go success payload", async () => {
    const request = await envelope();
    const payload = await genesisSuccessPayload(await result(), request.request);
    const success = fixture.cases.find((vector) => vector.name === "success")!;
    expect(toHex(encodeGenesisReply(request.requestId, request.requestDigest, payload))).toBe(success.responseCBORHex);
  });
  it("keeps semantic request identity across transport request IDs and timestamps", async () => {
    const value = decodeGenesisWire(fromHex(fixture.requestCBORHex), MAXIMUM_REQUEST_BYTES) as Record<string, unknown>;
    value.requestId = `req_${"B".repeat(25)}A`;
    value.sentAtUnixMs = fixture.sentAtUnixMs + 30_000;
    expect((await parseGenesisEnvelope(value, fixture.sentAtUnixMs)).requestDigest).toBe(fixture.requestDigest);
    value.sentAtUnixMs = fixture.sentAtUnixMs + 30_001;
    await expect(parseGenesisEnvelope(value, fixture.sentAtUnixMs)).rejects.toThrow();
  });
  it("snapshots operational root key bytes before asynchronous key derivation", async () => {
    const key = fromHex(fixture.rootKey);
    const pending = genesisDirectionalKeys(key);
    key.fill(255);
    expect(toHex((await pending).request)).toBe(fixture.requestKey);
    expect(toHex((await pending).response)).toBe(fixture.responseKey);
  });
  it("rejects source identity and payload-size changes before any asynchronous hash", async () => {
    const parsed = await envelope(), valid = await result();
    const spy = vi.spyOn(crypto.subtle, "digest");
    try {
      const wrong = structuredClone(valid);
      wrong.binding = { ...wrong.binding, actorSubjectId: "x".repeat(100_000) };
      await expect(genesisSuccessPayload(wrong, parsed.request)).rejects.toThrow();
      const oversized = structuredClone(valid);
      (oversized.checkpoint as Record<string, unknown>).payloadBytes = new Uint8Array((4 << 20) + 1);
      await expect(genesisSuccessPayload(oversized, parsed.request)).rejects.toThrow();
      expect(spy).not.toHaveBeenCalled();
    } finally { spy.mockRestore(); }
  });
  it("rejects changed original input, request schemas and noncanonical trailing bytes", async () => {
    const value = decodeGenesisWire(fromHex(fixture.requestCBORHex), MAXIMUM_REQUEST_BYTES) as Record<string, unknown>;
    (value.body as { input: { messages: { content: string }[] } }).input.messages[0]!.content = "Changed original input";
    await expect(parseGenesisEnvelope(value, fixture.sentAtUnixMs)).rejects.toThrow();
    value.schemaDigest = PROBE_SCHEMA;
    await expect(parseGenesisEnvelope(value, fixture.sentAtUnixMs)).rejects.toThrow();
    const bytes = fromHex(fixture.requestCBORHex), trailing = new Uint8Array(bytes.byteLength + 1);
    trailing.set(bytes);
    expect(() => decodeGenesisWire(trailing, MAXIMUM_REQUEST_BYTES)).toThrow();
  });
  it("accepts only exact lowercase complete MACs", () => {
    expect(equalGenesisMac(fixture.requestMAC, fixture.requestMAC)).toBe(true);
    expect(equalGenesisMac(fixture.requestMAC.toUpperCase(), fixture.requestMAC)).toBe(false);
    expect(equalGenesisMac(fixture.requestMAC.slice(1), fixture.requestMAC)).toBe(false);
    expect(equalGenesisMac(fixture.requestMAC, fixture.cases[0]!.responseMAC)).toBe(false);
  });
  it("accepts a native probe shape while preserving the exact external proof bytes", async () => {
    const nonce = Uint8Array.from({ length: 32 }, (_, index) => index);
    const request = encodeGenesisWire({ protocol: PROBE_PROTOCOL, major: 1, minor: 0, schemaDigest: PROBE_SCHEMA, nonce }, MAXIMUM_PROBE_REQUEST_BYTES);
    expect(toHex(parseGenesisProbeRequest(request))).toBe(toHex(nonce));
    const bytes = encodeGenesisWire(proof(nonce), MAXIMUM_PROBE_BYTES), digest = await digestBytes(bytes);
    expect(validateGenesisProbeResponse(bytes, nonce).runtimeKeyId).toBe("native-runtime-key");
    expect(await digestBytes(bytes)).toBe(digest);
    expect(() => validateGenesisProbeResponse(bytes, new Uint8Array(32))).toThrow();
  });
  it.each(["reference", "unsorted", "missing-group", "key", "signature", "epoch", "extra"])("rejects invalid native proof: %s", (kind) => {
    const value = proof(), descriptor = value.descriptor as Record<string, NormalizedValue>;
    if (kind === "reference") descriptor.backendKind = "reference-memory";
    if (kind === "unsorted") descriptor.atomicGroups = ["engine-genesis", "account-audit"];
    if (kind === "missing-group") descriptor.atomicGroups = ["command-receipt"];
    if (kind === "key") value.keyId = "other-runtime-key";
    if (kind === "signature") value.signature = new Uint8Array(63);
    if (kind === "epoch") descriptor.probeEpoch = 0;
    if (kind === "extra") value.extra = true;
    expect(() => validateGenesisProbeResponse(encodeGenesisWire(value, MAXIMUM_PROBE_BYTES), new Uint8Array(32))).toThrow();
  });
});
