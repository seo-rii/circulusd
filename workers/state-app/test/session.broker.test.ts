import { describe, expect, it } from "vitest";
import { decodeCanonicalCbor, digestBytes, encodeCanonicalCbor, type AgentCheckpoint, type Digest, type EngineStepResult } from "@circulusd/protocol-types";
import { SessionCell, sessionCellName } from "../src/host/index.ts";
import { HOST_RPC_CONTRACTS, type HostRpcOperation, type HostRpcResponse } from "../src/host/rpc.ts";
import { SESSION_HISTORY_ROW_PREFIX } from "../src/host/session-history-store.ts";
import type { TransactionalStoragePort, TransactionPort } from "../src/host/contracts.ts";
import {
  effectRequestDigest, migrateSessionState, turnInputDigest, type SessionBrokerAcquire,
  type SessionBrokerCommit, type SessionBrokerDispatchPermit, type SessionBrokerDispatchStartClaim,
  type SessionBrokerEngineGrant, type SessionBrokerOperationReceipt, type SessionBrokerPreparationPermit,
  type SessionBrokerPublicError, type SessionBrokerRequest, type SessionBrokerSettlementReceipt,
  type SessionBrokerSnapshot, type SessionBrokerStepReceipt, type SessionBrokerTurn,
} from "../src/session/index.ts";
import { RestartableDurableStorage } from "./support/restartable-durable-storage.ts";

const d = (value: string): Digest => `sha256:${value.repeat(64)}`;
const authority = { tenantId: "tenant", workspaceId: "workspace", sessionId: "session", actorSubjectId: "user", expectedAuthorizationGeneration: 6 };
const policy = { engineStepLimits: { maximumEvents: 1, maximumEphemeralBytes: 65_536, maximumWallClockMs: 5_000 }, preparationTTLms: 20_000 };

class ObservedStorage implements TransactionalStoragePort {
  readonly backing = new RestartableDurableStorage();
  readonly reads: string[] = [];
  readonly writes: number[] = [];
  readonly keys = new Set<string>();
  async transaction<Result>(callback: (transaction: TransactionPort) => Promise<Result>): Promise<Result> {
    const changed = new Set<string>();
    const result = await this.backing.transaction((transaction) => callback({
      get: <Value>(key: string) => { this.reads.push(key); return transaction.get<Value>(key); },
      put: async (key, value) => { changed.add(key); this.keys.add(key); await transaction.put(key, value); },
      delete: async (key) => { changed.add(key); this.keys.delete(key); return transaction.delete(key); },
    }));
    if (changed.size > 0) this.writes.push(changed.size);
    return result;
  }
}

async function fixture() {
  const storage = new ObservedStorage();
  let now = 1_000;
  const id = (name: string) => ({ toString: () => name, equals: (other: unknown) => String(other) === name });
  const create = (configured = true) => new SessionCell({ storage, id: id(sessionCellName("tenant", "session")) } as never,
    { SESSION_CELL: { idFromName: id }, ...(configured ? { CIRCULUSD_STATE_BROKER_POLICY: policy } : {}) } as never, () => now);
  let cell = create();
  async function rpc<Result>(operation: HostRpcOperation, payload: unknown, invoke: (request: unknown) => Promise<HostRpcResponse<Result>>) {
    const response = await invoke({ protocol: "circulus.v1alpha1", major: 1, minor: 0, schemaDigest: HOST_RPC_CONTRACTS[operation].schemaDigest,
      requestId: "broker-test", payload });
    if (!response.payload.ok) throw Object.assign(new Error(response.payload.error.message), { code: response.payload.error.code });
    return response.payload.result as Result;
  }
  const call = <Result>(request: SessionBrokerRequest, overrides = {}) => rpc("session.execute", { authority: { ...authority, ...overrides }, ...request }, (value) => cell.brokerSession(value)) as Promise<Result>;
  const read = () => call<SessionBrokerTurn>({ operation: "read-turn", body: {} });
  const control = { serviceBinding: "state", tenantId: "tenant", actorUserId: "user", subjectKind: "session", subjectId: "session",
    roles: ["user"], permissions: ["session.read"], authorizationGeneration: 6, currentAuthorizationGeneration: 6, issuedAt: 0, expiresAt: 1_000_000 };
  const state = () => rpc("session.read", { authority: control, now }, (request) => cell.readSession(request));
  const executeRaw = (command: unknown) => rpc("session.execute", command, (request) => cell.executeSessionCommand(request));
  const blob = (digest: Digest) => rpc("session.read-blob", { authority: control, now, digest }, (request) => cell.readSessionBlob(request));
  function snapshot(turn: SessionBrokerTurn): SessionBrokerSnapshot {
    return { turnId: turn.turnId!, eventSequence: turn.eventSequence, checkpointDigest: turn.checkpointDigest!, fence: turn.fence,
      activeEffect: turn.activeEffect === null ? null : { effectId: turn.activeEffect.effectId, invocationId: turn.activeEffect.invocationId,
        requestDigest: turn.activeEffect.requestDigest, phase: turn.activeEffect.phase, dispatchAttempt: turn.activeEffect.dispatchAttempt } };
  }
  async function checkpoint(turn?: SessionBrokerTurn): Promise<AgentCheckpoint> {
    const payloadBytes = encodeCanonicalCbor({ sequence: turn === undefined ? 0 : turn.checkpoint!.checkpointSequence + 1 });
    const base = { engineKind: "low-level" as const, adapterAbiVersion: 1, checkpointSchemaVersion: 1, runtimeRevisionDigest: d("1"),
      sessionId: "session", turnId: "turn", payloadEncoding: "canonical-cbor" as const, payloadBytes, payloadDigest: await digestBytes(payloadBytes) };
    return turn === undefined ? { ...base, kind: "genesis", checkpointSequence: 0, predecessorDigest: null } :
      { ...base, kind: "engine", checkpointSequence: turn.checkpoint!.checkpointSequence + 1, predecessorDigest: turn.checkpointDigest! };
  }
  await rpc("session.initialize", { sessionId: "session", tenantId: "tenant", userId: "user", workspaceId: "workspace",
    runtimeRevisionDigest: d("1"), policySnapshotDigest: d("2"), emergencyOverlayDigest: d("3"), engineKind: "low-level", adapterAbiVersion: 1,
    checkpointSchemaVersion: 1, placementGeneration: 4, sandboxGeneration: 5, authorizationGeneration: 6 }, (request) => cell.initializeSession(request));
  await rpc("session.execute", { kind: "enqueue_turn", commandId: "admit", expectedEventSequence: 0, transactionTime: now, turnId: "turn",
    input: { prompt: "broker" }, inputDigest: await turnInputDigest({ prompt: "broker" }), genesisCheckpoint: await checkpoint(),
    turnLeaseGeneration: 10, leaseExpiresAt: 1_000_000,
    publicAdmission: { tenantId: "tenant", actorSubjectId: "user", authorizationGeneration: 6, idempotencyKeyDigest: d("4"), requestDigest: d("5") } }, (request) => cell.executeSessionCommand(request));
  const acquireBody = async (operationKey = "acquire"): Promise<SessionBrokerAcquire> => ({ snapshot: snapshot(await read()), operationKey,
    nowUnixMs: now, budget: { maximumEvents: 1, maximumEphemeralBytes: 1024, maximumWallClockMs: 1_000 } });
  async function acquire(operationKey = "acquire") {
    const body = await acquireBody(operationKey);
    return { body, grant: await call<SessionBrokerEngineGrant>({ operation: "acquire-step", body }) };
  }
  async function commit(grant: SessionBrokerEngineGrant, step: EngineStepResult, operationKey = "commit") {
    const body: SessionBrokerCommit = { snapshot: snapshot(await read()), operationKey, requestDigest: d("6"), permitOpaque: grant.opaque, nowUnixMs: now, step };
    return { body, receipt: await call<SessionBrokerStepReceipt>({ operation: "commit-step", body }) };
  }
  async function prepare(replayPolicy: "safe" | "confirm" | "never" = "safe") {
    const { grant } = await acquire();
    const request = { service: "workspace" as const, operation: "workspace.commit", replayPolicy, payload: { content: "durable" } };
    const step: EngineStepResult = { kind: "effect_request", checkpoint: await checkpoint(await read()),
      request: { ...request, requestDigest: await effectRequestDigest(request) } };
    return (await commit(grant, step)).receipt;
  }
  async function dispatch(preparation: SessionBrokerPreparationPermit, old?: SessionBrokerSnapshot, operationKey = "dispatch") {
    const effect = (await read()).activeEffect!;
    const body = { snapshot: old ?? snapshot(await read()), key: { turnId: effect.turnId, effectId: effect.effectId, invocationId: effect.invocationId, requestDigest: effect.requestDigest },
      operationKey, operationDigest: d("7"), preparationOpaque: preparation.opaque, providerRequestId: "provider-request",
      providerRouteDigest: d("8"), nowUnixMs: now, deadlineUnixMs: preparation.deadline };
    return { body, permit: await call<SessionBrokerDispatchPermit>({ operation: "dispatch", body }) };
  }
  return { storage, call, read, state, blob, snapshot, checkpoint, acquireBody, acquire, commit, prepare, dispatch, executeRaw,
    restart: (configured = true) => { cell = create(configured); }, advance: (elapsed: number) => { now += elapsed; } };
}

describe("Session broker authoritative transaction", () => {
  it("persists one engine grant without advancing the event sequence and replays its original opaque proof", async () => {
    const f = await fixture();
    const before = await f.read();
    const { body, grant } = await f.acquire();
    expect(grant.expectedEventSequence).toBe(before.eventSequence);
    expect((await f.read()).eventSequence).toBe(before.eventSequence);
    expect(grant.opaque).toHaveLength(32);
    const revision = f.storage.backing.durableRevision;
    f.restart();
    expect(await f.call({ operation: "acquire-step", body })).toEqual(grant);
    expect(f.storage.backing.durableRevision).toBe(revision);
    await expect(f.acquire("concurrent")).rejects.toMatchObject({ code: "FAILED_PRECONDITION" });
    await expect(f.call({ operation: "acquire-step", body: { ...body, budget: { ...body.budget, maximumEphemeralBytes: 2048 } } })).rejects.toMatchObject({ code: "IDEMPOTENCY_CONFLICT" });
    f.advance(1_001);
    const replacement = await f.acquire("replacement");
    expect(replacement.grant.opaque).not.toEqual(grant.opaque);
    await expect(f.commit(grant, { kind: "checkpoint", checkpoint: await f.checkpoint(await f.read()) })).rejects.toMatchObject({ code: "FAILED_PRECONDITION" });
  });

  it("atomically consumes the grant and keeps the original preparation after a lost commit response", async () => {
    const f = await fixture();
    const { grant } = await f.acquire();
    const request = { service: "workspace" as const, operation: "workspace.commit", replayPolicy: "safe" as const, payload: { n: 1 } };
    const body: SessionBrokerCommit = { snapshot: f.snapshot(await f.read()), operationKey: "commit", requestDigest: d("6"), permitOpaque: grant.opaque,
      nowUnixMs: 1_000, step: { kind: "effect_request", checkpoint: await f.checkpoint(await f.read()), request: { ...request, requestDigest: await effectRequestDigest(request) } } };
    f.storage.backing.injectCrashOnce("after-commit-before-result");
    await expect(f.call({ operation: "commit-step", body })).rejects.toMatchObject({ code: "INTERNAL_ERROR" });
    f.restart();
    const revision = f.storage.backing.durableRevision;
    const receipt = await f.call<SessionBrokerStepReceipt>({ operation: "commit-step", body });
    expect(receipt.preparedEffect!.effectId).toMatch(/^effect_[A-Z2-7]{26}$/);
    expect(receipt.preparedEffect!.invocationId).toMatch(/^inv_[A-Z2-7]{26}$/);
    expect(receipt.preparedEffect!.dispatchAttempt).toBe(0);
    expect(receipt.preparation!.dispatchAttempt).toBe(1);
    expect(f.storage.backing.durableRevision).toBe(revision);
    expect((await f.state()).broker!.engineGrant).toBeNull();
    expect((await f.read()).preparation).toEqual(receipt.preparation);
  });

  it("reserves retry separately and dispatches with the original source snapshot exactly once", async () => {
    const f = await fixture();
    const prepared = await f.prepare();
    const dispatched = await f.dispatch(prepared.preparation!);
    const before = await f.read();
    const snapshot = f.snapshot(before);
    const retry = { snapshot, key: dispatched.body.key, operationKey: "retry", operationDigest: d("9"), nowUnixMs: 1_000, deadlineUnixMs: 25_000, userConfirmed: false };
    const permit = await f.call<SessionBrokerPreparationPermit>({ operation: "prepare-retry", body: retry });
    const reserved = await f.read();
    expect(reserved.eventSequence).toBe(snapshot.eventSequence + 1);
    expect(reserved.activeEffect!.phase).toBe("dispatched");
    expect(reserved.activeEffect!.dispatchAttempt).toBe(1);
    expect(permit.dispatchAttempt).toBe(2);
    await expect(f.call({ operation: "claim-start", body: { snapshot: f.snapshot(reserved), key: dispatched.body.key,
      dispatchOpaque: dispatched.permit.opaque, commandDigest: d("a"), nowUnixMs: 1_000 } })).rejects.toMatchObject({ code: "FAILED_PRECONDITION" });
    f.restart();
    const replay = await f.call({ operation: "prepare-retry", body: retry });
    expect(replay).toEqual(permit);
    const next = await f.dispatch(permit, snapshot, "retry-dispatch");
    expect(next.permit.dispatchAttempt).toBe(2);
    expect((await f.read()).activeEffect!.dispatchAttempt).toBe(2);
    expect((await f.read()).preparation).toBeNull();
    await expect(f.dispatch(permit, snapshot, "duplicate-dispatch")).rejects.toMatchObject({ code: "CONFLICT" });
  });

  it("preserves start exclusivity and full public error receipts with a null result reference", async () => {
    const f = await fixture();
    const prepared = await f.prepare();
    const dispatched = await f.dispatch(prepared.preparation!);
    const claim = { snapshot: f.snapshot(await f.read()), key: dispatched.body.key, dispatchOpaque: dispatched.permit.opaque, commandDigest: d("a"), nowUnixMs: 1_000 };
    const started = await f.call<SessionBrokerDispatchStartClaim>({ operation: "claim-start", body: claim });
    expect(started.fresh).toBe(true);
    f.restart();
    expect((await f.read()).start).toEqual(started.permit);
    const revision = f.storage.backing.durableRevision;
    expect(await f.call({ operation: "claim-start", body: claim })).toEqual({ ...started, fresh: false });
    expect(f.storage.backing.durableRevision).toBe(revision);
    await expect(f.call({ operation: "prepare-retry", body: { snapshot: f.snapshot(await f.read()), key: dispatched.body.key,
      operationKey: "retry", operationDigest: d("9"), nowUnixMs: 1_000, deadlineUnixMs: 25_000, userConfirmed: false } })).rejects.toMatchObject({ code: "DISPATCH_ALREADY_STARTED" });
    await f.call({ operation: "confirm", body: { snapshot: f.snapshot(await f.read()), key: dispatched.body.key, operationKey: "confirm",
      operationDigest: d("b"), dispatchAttempt: 1, providerRequestId: "provider-request", providerRouteDigest: d("8"), externalCommitId: "external-commit", resultRef: null } });
    const error: SessionBrokerPublicError = { code: 7, reason: "PROVIDER_FAILED", message: "x".repeat(4096), retryable: true,
      retryAfterMs: 500, metadata: { route: "primary", diagnostic: "preserved" }, requestId: "request-original" };
    const settle = { snapshot: f.snapshot(await f.read()), key: dispatched.body.key, operationKey: "settle", operationDigest: d("c"), dispatchAttempt: 1,
      externalCommitId: "external-commit", resultRef: null, error, settlement: { kind: "error" as const, code: error.reason, message: error.message, retryable: error.retryable } };
    const settled = await f.call<SessionBrokerSettlementReceipt>({ operation: "settle", body: settle });
    expect(settled.error).toEqual(error);
    expect(settled.resultRef).toBeNull();
    const lookup = await f.call<SessionBrokerOperationReceipt>({ operation: "lookup-operation", body: { kind: "settlement", operationKey: "settle", operationDigest: d("c") } });
    expect(lookup.receipt).toEqual(settled);
    const resumed = await f.acquire("resume");
    expect(resumed.grant.unconsumedSettlement!.settlement).toEqual(settle.settlement);
    await f.commit(resumed.grant, { kind: "turn_complete", checkpoint: await f.checkpoint(await f.read()), result: { errorObserved: true } }, "complete");
    expect((await f.read()).active).toBe(false);
    expect(await f.call({ operation: "claim-start", body: claim })).toEqual({ ...started, fresh: false });
  });

  it("blocks confirm effects before a distinct user-confirmed retry and settles never-replay recovery", async () => {
    const f = await fixture();
    const prepared = await f.prepare("confirm");
    const dispatch = await f.dispatch(prepared.preparation!);
    const reason: SessionBrokerPublicError = { code: 7, reason: "UNCERTAIN", message: "confirmation needed", retryable: false, retryAfterMs: 0, metadata: {}, requestId: null };
    await f.call({ operation: "block", body: { snapshot: f.snapshot(await f.read()), key: dispatch.body.key, operationKey: "block", operationDigest: d("a"), reason } });
    expect((await f.read()).activeEffect!.phase).toBe("blocked");
    const old = f.snapshot(await f.read());
    const retry = { snapshot: old, key: dispatch.body.key, operationKey: "retry", operationDigest: d("b"), nowUnixMs: 1_000, deadlineUnixMs: 25_000, userConfirmed: false };
    await expect(f.call({ operation: "prepare-retry", body: retry })).rejects.toMatchObject({ code: "FAILED_PRECONDITION" });
    const reservation = await f.call<SessionBrokerPreparationPermit>({ operation: "prepare-retry", body: { ...retry, userConfirmed: true } });
    expect((await f.dispatch(reservation, old, "confirmed-dispatch")).permit.dispatchAttempt).toBe(2);
    const g = await fixture();
    const never = await g.prepare("never");
    const sent = await g.dispatch(never.preparation!);
    const result = await g.call<SessionBrokerSettlementReceipt>({ operation: "settle-recovery", body: { snapshot: g.snapshot(await g.read()), key: sent.body.key,
      operationKey: "interrupt", operationDigest: d("a"), kind: "interrupted_unknown", error: reason } });
    expect(result.recoveryKind).toBe("interrupted_unknown");
    expect((await g.read()).unconsumedSettlement!.settlement.kind).toBe("interrupted_unknown");
  });

  it("archives original grant receipts and payload pins without a second program counter", async () => {
    const f = await fixture();
    const first = await f.acquire("acquire-0");
    await f.commit(first.grant, { kind: "checkpoint", checkpoint: await f.checkpoint(await f.read()) }, "commit-0");
    for (let index = 1; index < 23; index += 1) {
      const grant = await f.acquire(`acquire-${index}`);
      await f.commit(grant.grant, { kind: "checkpoint", checkpoint: await f.checkpoint(await f.read()) }, `commit-${index}`);
    }
    const stored = await f.state();
    expect(stored.broker!.receiptsThrough).toBeGreaterThan(0);
    expect(stored.broker!.receipts.length).toBeLessThanOrEqual(32);
    expect(stored.broker!.receipts.some((receipt) => receipt.operationKey === "acquire-0")).toBe(false);
    expect(Math.max(...f.storage.writes)).toBeLessThanOrEqual(128);
    expect(encodeCanonicalCbor(stored).byteLength).toBeLessThan(128 * 1024);
    f.restart();
    const revision = f.storage.backing.durableRevision;
    expect(await f.call({ operation: "acquire-step", body: first.body })).toEqual(first.grant);
    expect(f.storage.backing.durableRevision).toBe(revision);
    const originalBlob = await f.blob(first.grant.checkpoint.payloadDigest);
    expect(originalBlob).not.toBeNull();
    expect(decodeCanonicalCbor(originalBlob!.bytes)).toEqual({ sequence: 0 });
    f.storage.reads.length = 0;
    await expect(f.call({ operation: "acquire-step", body: first.body }, { actorSubjectId: "other" })).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
    expect(f.storage.reads.some((key) => key.startsWith(SESSION_HISTORY_ROW_PREFIX))).toBe(false);
    expect(f.storage.backing.durableRevision).toBe(revision);
    await expect(f.call({ operation: "acquire-step", body: first.body }, { expectedAuthorizationGeneration: 5 })).rejects.toMatchObject({ code: "STALE_GENERATION" });
  }, 30_000);

  it("rejects malformed body, absent trusted policy, and oversized budget before writes", async () => {
    const f = await fixture();
    const body = await f.acquireBody();
    const revision = f.storage.backing.durableRevision;
    await expect(f.executeRaw({ kind: "broker_operation", operation: "acquire-step", body,
      authority, host: { policy, opaque: new Uint8Array(32), secondaryOpaque: new Uint8Array(32), effectId: "forged", invocationId: "forged" } }))
      .rejects.toMatchObject({ code: "INVALID_ARGUMENT" });
    await expect(f.call({ operation: "acquire-step", body: { ...body, snapshot: undefined } } as unknown as SessionBrokerRequest)).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });
    await expect(f.call({ operation: "acquire-step", body: { ...body, budget: { ...body.budget, maximumEphemeralBytes: 65_537 } } })).rejects.toMatchObject({ code: "FAILED_PRECONDITION" });
    f.restart(false);
    await expect(f.read()).rejects.toMatchObject({ code: "FAILED_PRECONDITION" });
    expect(f.storage.backing.durableRevision).toBe(revision);
  });

  it("allows only one concurrent start or retry and prevents raw command bypass of broker grants", async () => {
    const f = await fixture();
    const prepared = await f.prepare();
    const dispatched = await f.dispatch(prepared.preparation!);
    const snapshot = f.snapshot(await f.read());
    const race = await Promise.allSettled([
      f.call({ operation: "claim-start", body: { snapshot: structuredClone(snapshot), key: dispatched.body.key,
        dispatchOpaque: dispatched.permit.opaque, commandDigest: d("a"), nowUnixMs: 1_000 } }),
      f.call({ operation: "prepare-retry", body: { snapshot: structuredClone(snapshot), key: dispatched.body.key,
        operationKey: "retry", operationDigest: d("b"), nowUnixMs: 1_000, deadlineUnixMs: 25_000, userConfirmed: false } }),
    ]);
    expect(race.filter((entry) => entry.status === "fulfilled")).toHaveLength(1);
    const after = await f.read();
    expect(Number(after.start !== null) + Number(after.preparation !== null)).toBe(1);
    const revision = f.storage.backing.durableRevision;
    await expect(f.executeRaw({ kind: "recover_effect", commandId: "bypass", expectedEventSequence: after.eventSequence,
      ...dispatched.body.key, fence: after.fence, transactionTime: 1_000, deadline: 25_000, providerRouteDigest: d("8") })).rejects.toMatchObject({ code: "FAILED_PRECONDITION" });
    expect(f.storage.backing.durableRevision).toBe(revision);
  });

  it("drains a reserved retry after abort and replaces an expired reservation without reusing its opaque proof", async () => {
    const f = await fixture();
    const prepared = await f.prepare();
    const dispatched = await f.dispatch(prepared.preparation!);
    const retry = { snapshot: f.snapshot(await f.read()), key: dispatched.body.key,
      operationKey: "retry", operationDigest: d("a"), nowUnixMs: 1_000, deadlineUnixMs: 1_500, userConfirmed: false };
    const first = await f.call<SessionBrokerPreparationPermit>({ operation: "prepare-retry", body: retry });
    f.advance(501);
    const second = await f.call<SessionBrokerPreparationPermit>({ operation: "prepare-retry", body: { ...retry,
      snapshot: f.snapshot(await f.read()), operationKey: "retry-after-expiry", nowUnixMs: 1_501, deadlineUnixMs: 3_000 } });
    expect(second.opaque).not.toEqual(first.opaque);
    const current = await f.read();
    await f.executeRaw({ kind: "request_abort", commandId: "abort", expectedEventSequence: current.eventSequence,
      turnId: current.turnId, fence: current.fence, transactionTime: 1_501, reason: "cancel" });
    const error: SessionBrokerPublicError = { code: 7, reason: "ABORTED", message: "cancelled", retryable: false, retryAfterMs: 0, metadata: {}, requestId: null };
    await f.call({ operation: "settle-recovery", body: { snapshot: f.snapshot(await f.read()), key: dispatched.body.key,
      operationKey: "abort-recovery", operationDigest: d("b"), kind: "interrupted_unknown", error } });
    const recovered = await f.read();
    expect(recovered.preparation).toBeNull();
    await f.executeRaw({ kind: "finalize_abort", commandId: "finalize-abort", expectedEventSequence: recovered.eventSequence,
      turnId: recovered.turnId, fence: recovered.fence, transactionTime: 1_501 });
    expect((await f.state()).terminalTurns[0]!.status).toBe("aborted");
  });

  it("migrates schema6 by version only and fails closed on an archived receipt row corruption", async () => {
    const f = await fixture();
    const previous = await f.state();
    const legacy = { ...previous, schemaVersion: 6 };
    const migrated = await migrateSessionState(legacy);
    expect(migrated).toEqual({ state: { ...legacy, schemaVersion: 7 }, migrated: true });
    const first = await f.acquire("original");
    await f.commit(first.grant, { kind: "checkpoint", checkpoint: await f.checkpoint(await f.read()) }, "original-commit");
    for (let index = 0; index < 17; index += 1) {
      const grant = await f.acquire(`later-${index}`);
      await f.commit(grant.grant, { kind: "checkpoint", checkpoint: await f.checkpoint(await f.read()) }, `later-commit-${index}`);
    }
    f.storage.reads.length = 0;
    await f.call({ operation: "acquire-step", body: first.body });
    const row = f.storage.reads.find((key) => key.startsWith(SESSION_HISTORY_ROW_PREFIX) && key.endsWith(".0"));
    expect(row).toBeDefined();
    await f.storage.backing.transaction((transaction) => transaction.put(row!, new Uint8Array([0])));
    f.restart();
    await expect(f.call({ operation: "acquire-step", body: first.body })).rejects.toMatchObject({ code: "CORRUPT_STATE" });
  }, 30_000);
});
