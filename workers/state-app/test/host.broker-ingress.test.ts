import { createHash, createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { decodeCanonicalCbor, digestStructuredValue, encodeCanonicalCbor, type NormalizedValue } from "@circulusd/protocol-types";

import worker from "../src/host/worker.ts";
import { HOST_RPC_CONTRACTS, HOST_RPC_FALLBACK_REQUEST_ID } from "../src/host/rpc.ts";
import { sessionCellName } from "../src/host/names.ts";
import { SessionCell } from "../src/host/cells.ts";
import type { HostRpcOperation } from "../src/host/rpc.ts";
import type { TransactionalStoragePort, TransactionPort } from "../src/host/contracts.ts";
import type { SessionBrokerTurn } from "../src/session/broker-types.ts";
import { RestartableDurableStorage } from "./support/restartable-durable-storage.ts";

const fixture = JSON.parse(readFileSync(new URL("../../../packages/protocol-types/fixtures/state-app-broker-ingress-v1alpha1.json", import.meta.url), "utf8"));
const root = Buffer.from(fixture.rootKeyHex, "hex");
const hash = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest();
const requestDomain = "circulusd.state-broker-ingress.request.v1";
const responseDomain = "circulusd.state-broker-ingress.response.v1";
const options = { maxBytes: 10 * 1_048_576, maxDepth: 80, maxItems: 120_000 };

function mac(direction: string, parts: (string | Uint8Array)[], key = root): string {
  const directional = createHmac("sha256", key).update(`circulusd.state-ingress.key.${direction}.v1\0`).digest();
  const frame = Buffer.concat(parts.map((part) => {
    const bytes = typeof part === "string" ? Buffer.from(part) : part;
    const prefix = Buffer.alloc(4); prefix.writeUInt32BE(bytes.length);
    return Buffer.concat([prefix, bytes]);
  }));
  return createHmac("sha256", directional).update(frame).digest("hex");
}
function payload(): Record<string, NormalizedValue> { return structuredClone(fixture.request); }
function envelope(result: unknown, requestId = fixture.request.requestId) {
  return { ...fixture.response, schemaDigest: HOST_RPC_CONTRACTS["session.execute"].schemaDigest, requestId, payload: { ok: true, result } };
}
function environment(brokerSession: (request: unknown) => Promise<unknown> = async () => envelope(null)) {
  return {
    CIRCULUSD_STATE_BROKER_CURRENT_KEY_ID: fixture.keyId,
    CIRCULUSD_STATE_BROKER_CURRENT_KEY: fixture.rootKeyHex,
    CIRCULUSD_STATE_INGRESS_CURRENT_KEY_ID: "reader-1", CIRCULUSD_STATE_INGRESS_CURRENT_KEY: "31".repeat(32),
    CIRCULUSD_STATE_DISPATCH_START_CURRENT_KEY_ID: "dispatch-1", CIRCULUSD_STATE_DISPATCH_START_CURRENT_KEY: "91".repeat(32),
    CIRCULUSD_STATE_ADMISSION_CURRENT_KEY_ID: "admission-1", CIRCULUSD_STATE_ADMISSION_CURRENT_KEY: "51".repeat(32),
    SESSION_CELL: { getByName: vi.fn(() => ({ brokerSession })) },
  };
}
interface SendOptions {
  keyId?: string; key?: Buffer; domain?: string; signedPath?: string; body?: Uint8Array;
  signature?: string; path?: string; headers?: Record<string, string>; method?: string;
}
async function send(env: ReturnType<typeof environment>, value = payload(), settings: SendOptions = {}) {
  const body = settings.body ?? encodeCanonicalCbor(value, options);
  const keyId = settings.keyId ?? fixture.keyId, key = settings.key ?? root;
  const response = await worker.fetch(new Request(`http://127.0.0.1${settings.path ?? fixture.path}`, {
    method: settings.method ?? "POST", headers: {
      "content-type": fixture.contentType, "x-circulus-state-key-id": keyId,
      "x-circulus-state-signature": settings.signature ?? mac("request", [settings.domain ?? requestDomain, keyId, "POST", settings.signedPath ?? fixture.path, hash(body)], key),
      ...settings.headers,
    }, body: settings.method === "GET" ? undefined : body,
  }), env as never);
  const encoded = new Uint8Array(await response.arrayBuffer());
  if (encoded.length === 0) return { response, result: null, encoded };
  const result = decodeCanonicalCbor(encoded, options) as Record<string, NormalizedValue>;
  expect(response.headers.get("x-circulus-state-key-id")).toBe(keyId);
  expect(response.headers.get("x-circulus-state-signature")).toBe(mac("response", [
    responseDomain, keyId, String(result.requestId), hash(body), String(response.status), fixture.contentType, hash(encoded),
  ], key));
  expect(response.headers.get("cache-control")).toBe("no-store");
  return { response, result, encoded };
}

beforeEach(() => vi.spyOn(Date, "now").mockReturnValue(fixture.request.sentAtUnixMs));
afterEach(() => vi.restoreAllMocks());

describe("signed typed Session broker ingress", () => {
  it("matches the shared Go bytes and MAC with an exact immutable authority envelope", async () => {
    expect(`sha256:${hash(Buffer.from(fixture.descriptor)).toString("hex")}`).toBe(fixture.schemaDigest);
    const value = payload(), body = encodeCanonicalCbor(value);
    expect(Buffer.from(body).toString("hex")).toBe(fixture.requestCborHex);
    expect(mac("request", [requestDomain, fixture.keyId, "POST", fixture.path, hash(body)])).toBe(fixture.requestMacHex);
    const execute = vi.fn(async (request: unknown) => {
      expect(request).toEqual({
        protocol: "circulus.v1alpha1", major: 1, minor: 0,
        schemaDigest: HOST_RPC_CONTRACTS["session.execute"].schemaDigest, requestId: fixture.request.requestId,
        payload: {
          authority: {
            tenantId: value.tenantId, workspaceId: value.workspaceId, sessionId: value.sessionId,
            actorSubjectId: value.actorSubjectId, expectedAuthorizationGeneration: 7,
          }, operation: "read-turn", body: {},
        },
      });
      return envelope(fixture.response.payload.result);
    });
    const env = environment(execute), result = await send(env);
    expect(result.response.status).toBe(200);
    expect(result.result).toEqual(fixture.response);
    expect(Buffer.from(result.encoded).toString("hex")).toBe(fixture.responseCborHex);
    expect(result.response.headers.get("x-circulus-state-signature")).toBe(fixture.responseMacHex);
    expect(env.SESSION_CELL.getByName).toHaveBeenCalledExactlyOnceWith(sessionCellName(String(value.tenantId), String(value.sessionId)));
    expect(execute).toHaveBeenCalledTimes(1);
  });

  it("admits only the fixed operation union with exactly the Go body fields", async () => {
    const bodyFields = {
      "read-turn": [], "lookup-operation": ["kind", "operationKey", "operationDigest"],
      "acquire-step": ["snapshot", "operationKey", "nowUnixMs", "budget"],
      "commit-step": ["snapshot", "operationKey", "requestDigest", "permitOpaque", "nowUnixMs", "step"],
      dispatch: ["snapshot", "key", "operationKey", "operationDigest", "preparationOpaque", "providerRequestId", "providerRouteDigest", "nowUnixMs", "deadlineUnixMs"],
      "claim-start": ["snapshot", "key", "dispatchOpaque", "commandDigest", "nowUnixMs"],
      confirm: ["snapshot", "key", "operationKey", "operationDigest", "dispatchAttempt", "providerRequestId", "providerRouteDigest", "externalCommitId", "resultRef"],
      settle: ["snapshot", "key", "operationKey", "operationDigest", "dispatchAttempt", "externalCommitId", "resultRef", "error", "settlement"],
      block: ["snapshot", "key", "operationKey", "operationDigest", "reason"],
      "prepare-retry": ["snapshot", "key", "operationKey", "operationDigest", "nowUnixMs", "deadlineUnixMs", "userConfirmed"],
      "settle-recovery": ["snapshot", "key", "operationKey", "operationDigest", "kind", "error"],
    };
    const execute = vi.fn(async () => envelope({ observed: true }));
    const env = environment(execute);
    for (const [operation, fields] of Object.entries(bodyFields)) {
      // Semantic field validation belongs to Cell, and cannot be replaced by an
      // arbitrary session.execute command. Here each allowed shape reaches it.
      const body = Object.fromEntries(fields.map((field) => [field, null]));
      const sent = { ...payload(), operation, body };
      expect((await send(env, sent)).response.status).toBe(200);
      expect(execute).toHaveBeenLastCalledWith(expect.objectContaining({ payload: expect.objectContaining({ operation, body }) }));
      expect((await send(env, { ...sent, body: { ...body, rawCommand: {} } })).response.status).toBe(400);
      if (fields.length > 0) {
        delete body[fields[0]!];
        expect((await send(env, { ...sent, body })).response.status).toBe(400);
      }
    }
    expect(execute).toHaveBeenCalledTimes(11);
    for (const operation of ["execute", "session.execute", "initialize", "rotate_generations", "toString", "__proto__"]) {
      expect((await send(env, { ...payload(), operation })).response.status).toBe(400);
    }
  });

  it("rejects wrong roles, paths, tampering and cross-operation MAC before routing", async () => {
    const env = environment();
    for (const [keyId, fill] of [["reader-1", 0x31], ["dispatch-1", 0x91], ["admission-1", 0x51]] as const) {
      expect((await send(env, payload(), { keyId, key: Buffer.alloc(32, fill) })).response.status).toBe(401);
    }
    for (const domain of ["circulusd.state-ingress.request.v1", "circulusd.state-turn-ingress.request.v1", "circulusd.state-dispatch-start-ingress.request.v1", responseDomain]) {
      expect((await send(env, payload(), { domain })).response.status).toBe(401);
    }
    const body = encodeCanonicalCbor(payload());
    const signature = mac("request", [requestDomain, fixture.keyId, "POST", fixture.path, hash(body)]);
    expect((await send(env, { ...payload(), operation: "claim-start" }, { signature })).response.status).toBe(401);
    expect((await send(env, payload(), { signedPath: "/wrong" })).response.status).toBe(401);
    expect(env.SESSION_CELL.getByName).not.toHaveBeenCalled();
  });

  it("rejects all current/previous credential ID or material aliases across roles", async () => {
    for (const role of ["INGRESS", "DISPATCH_START", "ADMISSION"] as const) {
      for (const era of ["CURRENT", "PREVIOUS"] as const) {
        for (const alias of ["id", "material"] as const) {
          const env = {
            ...environment(),
            [`CIRCULUSD_STATE_${role}_${era}_KEY_ID`]: alias === "id" ? fixture.keyId : `${role.toLowerCase()}-${era.toLowerCase()}-unique`,
            [`CIRCULUSD_STATE_${role}_${era}_KEY`]: alias === "material" ? fixture.rootKeyHex : "f1".repeat(32),
          };
          expect((await send(env)).response.status).toBe(503);
          expect(env.SESSION_CELL.getByName).not.toHaveBeenCalled();
        }
      }
    }
    for (const settings of [
      { CIRCULUSD_STATE_BROKER_PREVIOUS_KEY_ID: "broker-old" },
      { CIRCULUSD_STATE_BROKER_PREVIOUS_KEY_ID: fixture.keyId, CIRCULUSD_STATE_BROKER_PREVIOUS_KEY: "11".repeat(32) },
      { CIRCULUSD_STATE_BROKER_PREVIOUS_KEY_ID: "broker-old", CIRCULUSD_STATE_BROKER_PREVIOUS_KEY: fixture.rootKeyHex },
    ]) expect((await send({ ...environment(), ...settings })).response.status).toBe(503);
  });

  it("retains independent previous-key responses through rotation and rejects retired keys", async () => {
    const key = Buffer.alloc(32, 0x61), keyId = "broker-previous-1";
    const env = { ...environment(), CIRCULUSD_STATE_BROKER_PREVIOUS_KEY_ID: keyId, CIRCULUSD_STATE_BROKER_PREVIOUS_KEY: key.toString("hex") };
    expect((await send(env, payload(), { key, keyId })).response.status).toBe(200);
    expect((await send(environment(), payload(), { key, keyId })).response.status).toBe(401);
  });

  it("also rejects broker credential aliases on the reader route", async () => {
    const read = JSON.parse(readFileSync(new URL("../../../packages/protocol-types/fixtures/state-app-ingress-v1alpha1.json", import.meta.url), "utf8"));
    const body = encodeCanonicalCbor(read.request);
    const keyId = "reader-1", key = Buffer.alloc(32, 0x31);
    const env = { ...environment(), CIRCULUSD_STATE_BROKER_CURRENT_KEY: key.toString("hex") };
    const response = await worker.fetch(new Request(`http://127.0.0.1${read.path}`, {
      method: "POST", headers: {
        "content-type": read.contentType, "x-circulus-state-key-id": keyId,
        "x-circulus-state-signature": mac("request", ["circulusd.state-ingress.request.v1", keyId, "POST", read.path, hash(body)], key),
      }, body,
    }), env as never);
    expect(response.status).toBe(503);
    expect(env.SESSION_CELL.getByName).not.toHaveBeenCalled();
  });

  it("rejects malformed or stale signed scope before looking up any Cell", async () => {
    const env = environment();
    for (const patch of [
      { sentAtUnixMs: fixture.request.sentAtUnixMs - 30_001 }, { sentAtUnixMs: fixture.request.sentAtUnixMs + 30_001 },
      { sentAtUnixMs: -1 }, { tenantId: "tenant_bad" }, { workspaceId: "ws_bad" }, { actorSubjectId: "user_bad" },
      { sessionId: "sess_bad" }, { requestId: "req_bad" }, { expectedAuthorizationGeneration: 0 },
      { expectedAuthorizationGeneration: "7" }, { protocol: "other" }, { schemaDigest: `sha256:${"a".repeat(64)}` },
      { major: 2 }, { minor: 1 }, { authority: {} }, { body: [] },
    ]) expect((await send(env, { ...payload(), ...patch })).response.status).toBe(400);
    const missing = payload(); delete missing.workspaceId;
    expect((await send(env, missing)).response.status).toBe(400);
    expect(env.SESSION_CELL.getByName).not.toHaveBeenCalled();
    for (const offset of [-30_000, 30_000]) expect((await send(env, { ...payload(), sentAtUnixMs: fixture.request.sentAtUnixMs + offset })).response.status).toBe(200);
  });

  it("bounds encoded bytes, depth and items before Cell I/O and signs authenticated parse failures", async () => {
    const env = environment();
    const lookup = { ...payload(), operation: "lookup-operation" };
    const large = { ...lookup, body: { kind: "x".repeat(9 * 1_048_576), operationKey: "a", operationDigest: "b" } };
    expect((await send(env, large)).response.status).toBe(413);
    let deep: NormalizedValue = null;
    for (let depth = 0; depth < 74; depth++) deep = [deep];
    const depthResult = await send(env, { ...lookup, body: { kind: deep, operationKey: "a", operationDigest: "b" } });
    expect(depthResult.response.status).toBe(400);
    expect(depthResult.result?.requestId).toBe(HOST_RPC_FALLBACK_REQUEST_ID);
    expect((await send(env, { ...lookup, body: { kind: Array.from({ length: 100_000 }, () => 0), operationKey: "a", operationDigest: "b" } })).response.status).toBe(400);
    expect((await send(env, payload(), { body: new Uint8Array([0x18, 0x00]) })).response.status).toBe(400);
    expect(env.SESSION_CELL.getByName).not.toHaveBeenCalled();
  });

  it("preserves raw typed results, sanitizes errors and rejects malformed response envelopes", async () => {
    const success = { fresh: false, claim: { opaque: new Uint8Array([1, 2]), eventSequence: 0 } };
    expect((await send(environment(async () => envelope(success)))).result).toMatchObject({ payload: { ok: true, result: success } });
    const error = { ...envelope(null), payload: { ok: false, error: { code: "PERMISSION_DENIED", message: "secret-provider-token" } } };
    const failed = await send(environment(async () => error));
    expect(failed.result).toMatchObject({ payload: { ok: false, error: { code: "PERMISSION_DENIED", message: "The operation is not permitted." } } });
    for (const response of [envelope(null, "wrong-request"), { ...envelope(null), schemaDigest: `sha256:${"0".repeat(64)}` }, { ...envelope(null), payload: { ok: true, result: null, extra: true } }]) {
      expect((await send(environment(async () => response))).response.status).toBe(502);
    }
    const thrown = await send(environment(async () => { throw new Error("secret-provider-token"); }));
    expect(thrown.response.status).toBe(502);
    expect(Buffer.from(thrown.encoded).includes(Buffer.from("secret-provider-token"))).toBe(false);
  });

  it("uses the real SessionCell for scoped reads and exactly one durable fresh dispatch start", async () => {
    const request = payload();
    const clock = () => fixture.request.sentAtUnixMs;
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
    const policy = { engineStepLimits: { maximumEvents: 1, maximumEphemeralBytes: 65_536, maximumWallClockMs: 1_000 }, preparationTTLms: 30_000 };
    const state = { storage, id: id(sessionCellName(String(request.tenantId), String(request.sessionId))) };
    const cellEnvironment = { SESSION_CELL: { idFromName: id }, CIRCULUSD_STATE_BROKER_POLICY: policy };
    const cell = new SessionCell(state as never, cellEnvironment as never, clock);
    const rpc = (operation: HostRpcOperation, body: unknown) => ({
      protocol: "circulus.v1alpha1", major: 1, minor: 0, schemaDigest: HOST_RPC_CONTRACTS[operation].schemaDigest,
      requestId: fixture.request.requestId, payload: body,
    });
    const initialized = await cell.initializeSession(rpc("session.initialize", {
      sessionId: request.sessionId, tenantId: request.tenantId, userId: request.actorSubjectId, workspaceId: request.workspaceId,
      runtimeRevisionDigest: `sha256:${"a".repeat(64)}`, policySnapshotDigest: `sha256:${"2".repeat(64)}`, emergencyOverlayDigest: `sha256:${"3".repeat(64)}`,
      engineKind: "low-level", adapterAbiVersion: 2, checkpointSchemaVersion: 2, placementGeneration: 0, sandboxGeneration: 0, authorizationGeneration: 7,
    }));
    expect(initialized.payload.ok).toBe(true);
    const noPolicyCell = new SessionCell(state as never, { SESSION_CELL: { idFromName: id } } as never, clock);
    reads.length = 0; writes.length = 0;
    expect((await send(environment((wire) => noPolicyCell.brokerSession(wire)))).result)
      .toMatchObject({ payload: { ok: false, error: { code: "FAILED_PRECONDITION" } } });
    expect(reads).toEqual([]); expect(writes).toEqual([]);
    const env = environment((wire) => cell.brokerSession(wire));
    const empty = await send(env);
    expect(empty.result).toEqual(envelope(fixture.response.payload.result));
    const initialRevision = backing.durableRevision;
    for (const [field, value, code] of [
      ["tenantId", `tenant_${"B".repeat(25)}A`, "PERMISSION_DENIED"],
      ["sessionId", `sess_${"B".repeat(25)}A`, "PERMISSION_DENIED"],
      ["workspaceId", `ws_${"B".repeat(25)}A`, "PERMISSION_DENIED"],
      ["actorSubjectId", `subject_${"B".repeat(25)}A`, "PERMISSION_DENIED"],
      ["expectedAuthorizationGeneration", 8, "STALE_GENERATION"],
    ] as const) {
      reads.length = 0; writes.length = 0;
      expect((await send(env, { ...payload(), [field]: value })).result).toMatchObject({ payload: { ok: false, error: { code } } });
      expect(reads.filter((key) => key.startsWith("circulusd.state-app.session-history.v1."))).toEqual([]);
      expect(writes).toEqual([]);
      expect(backing.durableRevision).toBe(initialRevision);
    }
    const pi = JSON.parse(readFileSync(new URL("../../../packages/protocol-types/fixtures/stateapp-pi-codec-v1.json", import.meta.url), "utf8"));
    const genesis = decodeCanonicalCbor(new Uint8Array(Buffer.from(pi.checkpoints[0].wireHex, "hex")));
    const input = { prompt: "Echo 1.25", timestamp: 1_700_000_000_000 };
    const enqueued = await cell.executeSessionCommand(rpc("session.execute", {
      kind: "enqueue_turn", commandId: "broker-ingress-enqueue", expectedEventSequence: 0,
      transactionTime: clock(),
      turnId: `turn_${"A".repeat(26)}`, input, inputDigest: await digestStructuredValue("circulusd.session.turn-input", 1, input),
      genesisCheckpoint: genesis, turnLeaseGeneration: 1, leaseExpiresAt: clock() + 120_000,
    }));
    expect(enqueued.payload, JSON.stringify(enqueued.payload)).toMatchObject({ ok: true });
    async function readTurn() {
      const response = await send(env);
      expect(response.result).toMatchObject({ payload: { ok: true } });
      return (response.result!.payload as { result: unknown }).result as SessionBrokerTurn;
    }
    const snapshot = (turn: SessionBrokerTurn) => ({
      turnId: turn.turnId, eventSequence: turn.eventSequence, checkpointDigest: turn.checkpointDigest, fence: turn.fence,
      activeEffect: turn.activeEffect === null ? null : {
        effectId: turn.activeEffect.effectId, invocationId: turn.activeEffect.invocationId, requestDigest: turn.activeEffect.requestDigest,
        phase: turn.activeEffect.phase, dispatchAttempt: turn.activeEffect.dispatchAttempt,
      },
    });
    async function execute(operation: string, body: unknown) {
      const sent = { ...payload(), operation, body } as Record<string, NormalizedValue>;
      const response = await send(env, sent);
      expect(response.result, JSON.stringify(response.result)).toMatchObject({ payload: { ok: true } });
      return (response.result!.payload as { result: Record<string, NormalizedValue> }).result;
    }
    const active = await readTurn();
    const grant = await execute("acquire-step", { snapshot: snapshot(active), operationKey: "engine-acquire", nowUnixMs: clock(), budget: policy.engineStepLimits });
    const acquired = await readTurn();
    const committed = await execute("commit-step", {
      snapshot: snapshot(acquired), operationKey: "engine-commit", requestDigest: `sha256:${"4".repeat(64)}`,
      permitOpaque: grant.opaque, nowUnixMs: clock(), step: decodeCanonicalCbor(new Uint8Array(Buffer.from(pi.boundaries[0].wireHex, "hex"))),
    });
    expect(committed.preparedEffect).not.toBeNull();
    const prepared = await readTurn(), effect = prepared.activeEffect!;
    const key = { turnId: prepared.turnId, effectId: effect.effectId, invocationId: effect.invocationId, requestDigest: effect.requestDigest };
    const dispatch = await execute("dispatch", {
      snapshot: snapshot(prepared), key, operationKey: "dispatch", operationDigest: `sha256:${"5".repeat(64)}`,
      preparationOpaque: prepared.preparation!.opaque, providerRequestId: `req_${"A".repeat(26)}`,
      providerRouteDigest: `sha256:${"6".repeat(64)}`, nowUnixMs: clock(), deadlineUnixMs: prepared.preparation!.deadline,
    });
    const dispatched = await readTurn();
    const claimBody = { snapshot: snapshot(dispatched), key, dispatchOpaque: dispatch.opaque, commandDigest: `sha256:${"7".repeat(64)}`, nowUnixMs: clock() };
    const first = await execute("claim-start", claimBody);
    expect(first.fresh).toBe(true);
    const revision = backing.durableRevision;
    const replay = await execute("claim-start", claimBody);
    expect(replay).toEqual({ ...first, fresh: false });
    expect(backing.durableRevision).toBe(revision);
    const changed = await send(env, { ...payload(), operation: "claim-start", body: { ...claimBody, commandDigest: `sha256:${"8".repeat(64)}` } } as Record<string, NormalizedValue>);
    expect(changed.result).toMatchObject({ payload: { ok: false, error: { code: "IDEMPOTENCY_CONFLICT" } } });
    expect(backing.durableRevision).toBe(revision);
  });
});
