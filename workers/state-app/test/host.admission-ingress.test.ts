import { createHash, createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";
import { decodeCanonicalCbor, encodeCanonicalCbor, type NormalizedValue } from "@circulusd/protocol-types";
import worker from "../src/host/worker.ts";
import { SessionCell, sessionCellName } from "../src/host/index.ts";
import { HOST_RPC_CONTRACTS, type HostRpcOperation } from "../src/host/rpc.ts";
import type { TransactionalStoragePort, TransactionPort } from "../src/host/contracts.ts";
import type { SessionAggregateState } from "../src/session/index.ts";
import { RestartableDurableStorage } from "./support/restartable-durable-storage.ts";

const fixture = JSON.parse(readFileSync(new URL("../../../packages/protocol-types/fixtures/state-app-admission-v1alpha1.json", import.meta.url), "utf8"));
const root = Buffer.from(fixture.rootKeyHex, "hex");
const hash = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest();
function mac(direction: string, parts: (string | Uint8Array)[], key = root): string {
  const directional = createHmac("sha256", key).update(`circulusd.state-ingress.key.${direction}.v1\0`).digest();
  const frame = Buffer.concat(parts.map((part) => {
    const bytes = typeof part === "string" ? Buffer.from(part) : part;
    const prefix = Buffer.alloc(4); prefix.writeUInt32BE(bytes.length);
    return Buffer.concat([prefix, bytes]);
  }));
  return createHmac("sha256", directional).update(frame).digest("hex");
}
function payload(): Record<string, NormalizedValue> {
  const result = structuredClone(fixture.request);
  result.genesisCheckpoint.payloadBytes = new Uint8Array(Buffer.from(result.genesisCheckpoint.payloadBytes.hex, "hex"));
  return result;
}
function environment(executeSessionCommand: (request: unknown) => Promise<unknown>) {
  return {
    CIRCULUSD_STATE_ADMISSION_CURRENT_KEY_ID: fixture.keyId,
    CIRCULUSD_STATE_ADMISSION_CURRENT_KEY: fixture.rootKeyHex,
    CIRCULUSD_STATE_INGRESS_CURRENT_KEY_ID: "reader-1",
    CIRCULUSD_STATE_INGRESS_CURRENT_KEY: "31".repeat(32),
    CIRCULUSD_STATE_DISPATCH_START_CURRENT_KEY_ID: "dispatch-1",
    CIRCULUSD_STATE_DISPATCH_START_CURRENT_KEY: "91".repeat(32),
    SESSION_CELL: { getByName: vi.fn(() => ({ executeSessionCommand })) },
  };
}
async function send(env: ReturnType<typeof environment>, value = payload(), keyId = fixture.keyId, key = root, domain = "circulusd.state-turn-ingress.request.v1") {
  const body = encodeCanonicalCbor(value, { maxBytes: 8 * 1_048_576, maxDepth: 72, maxItems: 1_000_000 });
  const response = await worker.fetch(new Request(`http://127.0.0.1${fixture.path}`, {
    method: "POST", headers: {
      "content-type": fixture.contentType, "x-circulus-state-key-id": keyId,
      "x-circulus-state-signature": mac("request", [domain, keyId, "POST", fixture.path, hash(body)], key),
    }, body,
  }), env as never);
  const encoded = new Uint8Array(await response.arrayBuffer());
  if (encoded.length === 0) return { response, result: null };
  expect(response.headers.get("x-circulus-state-signature")).toBe(mac("response", [
    "circulusd.state-turn-ingress.response.v1", fixture.keyId, String(value.requestId), hash(body), String(response.status), fixture.contentType, hash(encoded),
  ]));
  return { response, result: decodeCanonicalCbor(encoded) };
}

afterEach(() => vi.restoreAllMocks());
describe("signed public turn admission", () => {
  it("matches the Go golden with a dedicated write credential and exact full input", async () => {
    vi.spyOn(Date, "now").mockReturnValue(fixture.request.sentAtUnixMs);
    const request = payload();
    const bytes = encodeCanonicalCbor(request);
    expect(Buffer.from(bytes).toString("hex")).toBe(fixture.requestCborHex);
    expect(mac("request", ["circulusd.state-turn-ingress.request.v1", fixture.keyId, "POST", fixture.path, hash(bytes)])).toBe(fixture.requestMacHex);
    const execute = vi.fn(async (wire: unknown) => {
      expect(wire).toMatchObject({ payload: { kind: "enqueue_turn", input: request.input, inputDigest: request.inputDigest,
        publicAdmission: { tenantId: request.tenantId, actorSubjectId: request.actorSubjectId, authorizationGeneration: 7 } } });
      return fixture.response;
    });
    const response = await send(environment(execute), request);
    expect(response.result).toEqual(fixture.response);
    expect(response.response.headers.get("x-circulus-state-signature")).toBe(fixture.responseMacHex);
    expect(execute).toHaveBeenCalledTimes(1);
  });

  it("rejects reader/dispatcher keys, cross-operation MAC and key material aliases before routing", async () => {
    vi.spyOn(Date, "now").mockReturnValue(fixture.request.sentAtUnixMs);
    const env = environment(vi.fn());
    for (const [id, key] of [["reader-1", Buffer.alloc(32, 0x31)], ["dispatch-1", Buffer.alloc(32, 0x91)]] as const) {
      expect((await send(env, payload(), id, key)).response.status).toBe(401);
    }
    expect((await send(env, payload(), fixture.keyId, root, "circulusd.state-ingress.request.v1")).response.status).toBe(401);
    expect((await send({ ...env, CIRCULUSD_STATE_INGRESS_CURRENT_KEY: fixture.rootKeyHex })).response.status).toBe(503);
    expect(env.SESSION_CELL.getByName).not.toHaveBeenCalled();
  });

  it("rejects changed input, checkpoint scope, unsigned extra fields and invalid host outcomes", async () => {
    vi.spyOn(Date, "now").mockReturnValue(fixture.request.sentAtUnixMs);
    const env = environment(async () => ({ ...fixture.response, payload: { ok: true, result: { ...fixture.response.payload.result, outcome: { kind: "turn_enqueued" } } } }));
    for (const edit of [
      (value: Record<string, NormalizedValue>) => { value.input = { messages: [{ role: "user", content: "changed" }] }; },
      (value: Record<string, NormalizedValue>) => { (value.genesisCheckpoint as Record<string, NormalizedValue>).turnId = `turn_${"B".repeat(25)}A`; },
      (value: Record<string, NormalizedValue>) => { value.authority = {}; },
    ]) {
      const value = payload(); edit(value);
      expect((await send(env, value)).response.status).toBe(400);
    }
    expect(env.SESSION_CELL.getByName).not.toHaveBeenCalled();
    expect((await send(env)).response.status).toBe(502);
  });

  it("checks current tenant, actor and generation before archived replay and preserves admitted input", async () => {
    vi.spyOn(Date, "now").mockReturnValue(fixture.request.sentAtUnixMs);
    const backing = new RestartableDurableStorage();
    const reads: string[] = [], writes: string[] = [];
    const storage: TransactionalStoragePort = {
      transaction: <Result>(callback: (transaction: TransactionPort) => Promise<Result>) => backing.transaction((transaction) => callback({
        get: <Value>(key: string) => { reads.push(key); return transaction.get<Value>(key); },
        put: async (key, value) => { writes.push(key); await transaction.put(key, value); },
        delete: async (key) => { writes.push(key); return transaction.delete(key); },
      })),
    };
    const id = (name: string) => ({ toString: () => name, equals: (other: unknown) => String(other) === name });
    const cell = new SessionCell({ storage, id: id(sessionCellName(fixture.request.tenantId, fixture.request.sessionId)) } as never,
      { SESSION_CELL: { idFromName: id } } as never, () => fixture.request.sentAtUnixMs);
    const request = (operation: HostRpcOperation, value: unknown) => ({
      protocol: "circulus.v1alpha1", major: 1, minor: 0, schemaDigest: HOST_RPC_CONTRACTS[operation].schemaDigest, requestId: fixture.request.requestId, payload: value,
    });
    const initialized = await cell.initializeSession(request("session.initialize", {
      sessionId: fixture.request.sessionId, tenantId: fixture.request.tenantId, userId: fixture.request.actorSubjectId, workspaceId: "workspace",
      runtimeRevisionDigest: `sha256:${"1".repeat(64)}`, policySnapshotDigest: `sha256:${"2".repeat(64)}`, emergencyOverlayDigest: `sha256:${"3".repeat(64)}`,
      engineKind: "low-level", adapterAbiVersion: 1, checkpointSchemaVersion: 1, placementGeneration: 1, sandboxGeneration: 1, authorizationGeneration: 7,
    }));
    expect(initialized.payload.ok).toBe(true);
    let admittedCommand: Record<string, NormalizedValue> | undefined;
    const env = environment((wire) => {
      admittedCommand = (wire as { payload: Record<string, NormalizedValue> }).payload;
      return cell.executeSessionCommand(wire);
    });
    const admitted = await send(env);
    expect(admitted.result, JSON.stringify(admitted.result)).toMatchObject({ payload: { ok: true, result: { replayed: false } } });
    const authority = {
      serviceBinding: "state", tenantId: fixture.request.tenantId, actorUserId: fixture.request.actorSubjectId,
      subjectKind: "session", subjectId: fixture.request.sessionId, roles: ["user"], permissions: ["session.read"],
      authorizationGeneration: 7, currentAuthorizationGeneration: 7, issuedAt: fixture.request.sentAtUnixMs - 1, expiresAt: fixture.request.leaseExpiresAt,
    };
    const stored = await cell.readSession(request("session.read", { authority, now: fixture.request.sentAtUnixMs }));
    expect(stored.payload.ok).toBe(true);
    if (!stored.payload.ok) throw new Error("expected admitted Session");
    const state = stored.payload.result as SessionAggregateState;
    expect(state.activeTurn?.inputRef).toBeDefined();
    const blob = await cell.readSessionBlob(request("session.read-blob", { authority, now: fixture.request.sentAtUnixMs, digest: state.activeTurn!.inputRef!.digest }));
    expect(blob.payload.ok).toBe(true);
    if (!blob.payload.ok || blob.payload.result === null) throw new Error("expected admitted input blob");
    expect(decodeCanonicalCbor(blob.payload.result.bytes)).toEqual(fixture.request.input);
    const originalCommand = structuredClone(admittedCommand!);
    for (let sequence = 1; sequence < 42; sequence += 1) {
      const rotated = await cell.executeSessionCommand(request("session.execute", { kind: "rotate_generations", commandId: `rotate-${sequence}`, expectedEventSequence: sequence,
        nextPlacementGeneration: sequence + 1, nextSandboxGeneration: 1, nextAuthorizationGeneration: 7, nextEmergencyOverlayDigest: `sha256:${"3".repeat(64)}` }));
      expect(rotated.payload.ok).toBe(true);
    }
    const revision = backing.durableRevision;
    for (const [field, value, code] of [
      ["actorSubjectId", `subject_${"B".repeat(25)}A`, "PERMISSION_DENIED"],
      ["tenantId", `tenant_${"B".repeat(25)}A`, "PERMISSION_DENIED"],
      ["expectedAuthorizationGeneration", 8, "STALE_GENERATION"],
    ] as const) {
      reads.length = 0; writes.length = 0;
      expect((await send(env, { ...payload(), [field]: value })).result).toMatchObject({ payload: { ok: false, error: { code } } });
      expect(reads.filter((key) => key.startsWith("circulusd.state-app.session-history.v1."))).toEqual([]);
      expect(writes).toEqual([]);
    }
    reads.length = 0; writes.length = 0;
    const halfScope = structuredClone(originalCommand);
    delete (halfScope.publicAdmission as Record<string, NormalizedValue>).actorSubjectId;
    const invalidPair = await cell.executeSessionCommand(request("session.execute", halfScope));
    expect(invalidPair.payload).toMatchObject({ ok: false, error: { code: "INVALID_ARGUMENT" } });
    expect(reads.filter((key) => key.startsWith("circulusd.state-app.session-history.v1."))).toEqual([]);
    expect(writes).toEqual([]);
    expect((await send(env)).result).toMatchObject({ payload: { ok: true, result: { replayed: true, outcome: { turnId: fixture.request.turnId } } } });
    expect(backing.durableRevision).toBe(revision);
  });
});
