import { describe, expect, it } from "vitest";
import {
  PROTOCOL_MAJOR, PROTOCOL_MINOR, PROTOCOL_NAME,
  decodeCanonicalCbor, digestBytes, encodeCanonicalCbor,
  type AgentCheckpoint, type Digest, type NormalizedValue,
} from "@circulusd/protocol-types";
import { SessionCell, sessionCellName } from "../src/host/index.ts";
import type { TransactionalStoragePort, TransactionPort } from "../src/host/contracts.ts";
import { MAX_TRANSACTION_MUTATED_KEYS } from "../src/host/storage.ts";
import { SESSION_HISTORY_ROW_PREFIX } from "../src/host/session-history-store.ts";
import { HOST_RPC_CONTRACTS, type HostRpcOperation, type HostRpcResponse } from "../src/host/rpc.ts";
import {
  checkpointDigest, effectRequestDigest, turnInputDigest,
  SESSION_HISTORY_HOT_COMMANDS, SESSION_HISTORY_HOT_PUBLIC_EVENTS,
  SESSION_HISTORY_HOT_TERMINAL_TURNS, SESSION_HISTORY_HOT_EFFECTS,
  type SessionAggregateState, type SessionCommand,
} from "../src/session/index.ts";
import { RestartableDurableStorage } from "./support/restartable-durable-storage.ts";

const digest = (character: string): Digest => `sha256:${character.repeat(64)}`;
const bytes = (value: string) => new TextEncoder().encode(value);
const NOW = 200;
const ARCHIVE_TURNS = Math.ceil(SESSION_HISTORY_HOT_COMMANDS / 2) + SESSION_HISTORY_HOT_TERMINAL_TURNS;

// Observe the actual durable key boundary while retaining the shared restartable
// transaction implementation. Mutations below are used only for corruption tests.
class ObservedStorage implements TransactionalStoragePort {
  readonly backing = new RestartableDurableStorage();
  readonly reads: string[] = [];
  readonly keys = new Set<string>();
  readonly writesPerCommit: number[] = [];

  async transaction<Result>(callback: (transaction: TransactionPort) => Promise<Result>): Promise<Result> {
    const changes = new Map<string, boolean>();
    const result = await this.backing.transaction(async (transaction) => {
      changes.clear();
      return callback({
        get: <Value>(key: string) => {
          this.reads.push(key);
          return transaction.get<Value>(key);
        },
        put: async (key, value) => {
          changes.set(key, true);
          await transaction.put(key, value);
        },
        delete: async (key) => {
          changes.set(key, false);
          return transaction.delete(key);
        },
      });
    });
    for (const [key, retained] of changes) {
      if (retained) this.keys.add(key);
      else this.keys.delete(key);
    }
    if (changes.size > 0) this.writesPerCommit.push(changes.size);
    return result;
  }
}

async function fixture() {
  const storage = new ObservedStorage();
  const logicalName = sessionCellName("tenant-history", "session-history");
  const physicalId = (name: string) => ({
    toString: () => `physical:${name}`,
    equals: (other: unknown) => String(other) === `physical:${name}`,
  });
  const createCell = () => new SessionCell(
    { storage, id: physicalId(logicalName) } as never,
    { SESSION_CELL: { idFromName: physicalId } } as never,
    () => NOW,
  );
  let cell = createCell();
  const authority = {
    serviceBinding: "state", tenantId: "tenant-history", actorUserId: "user-history",
    subjectKind: "session", subjectId: "session-history", roles: ["user"],
    permissions: ["session.read"], authorizationGeneration: 6,
    currentAuthorizationGeneration: 6, issuedAt: 1, expiresAt: 100_000,
  };
  async function rpc<Result>(
    operation: HostRpcOperation, payload: unknown,
    invoke: (request: unknown) => Promise<HostRpcResponse<Result>>,
  ): Promise<Result> {
    const response = await invoke({
      protocol: PROTOCOL_NAME, major: PROTOCOL_MAJOR, minor: PROTOCOL_MINOR,
      schemaDigest: HOST_RPC_CONTRACTS[operation].schemaDigest,
      requestId: `history-${operation}`, payload,
    });
    if (!response.payload.ok) {
      throw Object.assign(new Error(response.payload.error.message), { code: response.payload.error.code });
    }
    return response.payload.result as Result;
  }
  await rpc("session.initialize", {
    sessionId: "session-history", tenantId: "tenant-history", userId: "user-history",
    workspaceId: "workspace-history", runtimeRevisionDigest: digest("1"),
    policySnapshotDigest: digest("2"), emergencyOverlayDigest: digest("3"),
    engineKind: "low-level", adapterAbiVersion: 1, checkpointSchemaVersion: 1,
    placementGeneration: 4, sandboxGeneration: 5, authorizationGeneration: 6,
  }, (request) => cell.initializeSession(request));
  const read = () => rpc("session.read", { authority, now: NOW }, (request) => cell.readSession(request));
  const execute = (command: SessionCommand) => rpc("session.execute", command,
    (request) => cell.executeSessionCommand(request));
  const events = (afterSequence = 0, limit = 256, overrides = {}) => rpc("session.read-events",
    { authority: { ...authority, ...overrides }, now: NOW, afterSequence, limit },
    (request) => cell.readSessionEvents(request));
  const blob = (payloadDigest: Digest, overrides = {}) => rpc("session.read-blob",
    { authority: { ...authority, ...overrides }, now: NOW, digest: payloadDigest },
    (request) => cell.readSessionBlob(request));
  const fence = (state: SessionAggregateState) => ({
    turnLeaseGeneration: state.activeTurn!.turnLeaseGeneration,
    placementGeneration: state.placementGeneration, sandboxGeneration: state.sandboxGeneration,
    authorizationGeneration: state.authorizationGeneration,
  });
  async function checkpoint(state: SessionAggregateState, genesisTurnId?: string): Promise<AgentCheckpoint> {
    const turnId = genesisTurnId ?? state.activeTurn!.turnId;
    const sequence = genesisTurnId === undefined ? state.activeTurn!.checkpoint.checkpointSequence + 1 : 0;
    const payloadBytes = bytes(`${turnId}:${sequence}`);
    const common = {
      engineKind: "low-level" as const, adapterAbiVersion: 1, checkpointSchemaVersion: 1,
      runtimeRevisionDigest: state.runtimeRevisionDigest, sessionId: state.sessionId, turnId,
      payloadEncoding: "opaque-v1" as const, payloadBytes, payloadDigest: await digestBytes(payloadBytes),
    };
    if (genesisTurnId !== undefined) {
      return { ...common, kind: "genesis", checkpointSequence: 0, predecessorDigest: null };
    }
    return {
      ...common, kind: "engine", checkpointSequence: sequence,
      predecessorDigest: state.activeTurn!.checkpointChainDigest ??
        await checkpointDigest(state.activeTurn!.checkpoint as AgentCheckpoint),
    };
  }
  async function enqueue(turnId: string, input: NormalizedValue = { prompt: turnId }, publicAdmission = true) {
    const state = await read();
    const command: SessionCommand = {
      kind: "enqueue_turn", commandId: `admit-${turnId}`, expectedEventSequence: state.eventSequence,
      transactionTime: NOW, turnId, input, inputDigest: await turnInputDigest(input),
      genesisCheckpoint: await checkpoint(state, turnId), turnLeaseGeneration: state.nextTurnSequence + 10,
      leaseExpiresAt: 10_000,
      ...(publicAdmission ? { publicAdmission: {
        authorizationGeneration: state.authorizationGeneration,
        idempotencyKeyDigest: await digestBytes(bytes(`public-key:${turnId}`)),
        requestDigest: await digestBytes(bytes(`public-request:${turnId}`)),
      } } : {}),
    };
    return { command, response: await execute(command) };
  }
  async function completion(result: NormalizedValue = { done: true }) {
    const state = await read();
    const turnId = state.activeTurn!.turnId;
    const command: SessionCommand = {
      kind: "commit_engine_step", commandId: `complete-${turnId}`, expectedEventSequence: state.eventSequence,
      turnId, fence: fence(state), transactionTime: NOW,
      consumedSettlementEffectId: state.activeTurn!.activeEffectId, effectIdentity: null,
      step: { kind: "turn_complete", checkpoint: await checkpoint(state), result },
    };
    return { command, response: await execute(command) };
  }
  async function prepare(suffix: string, identity?: { effectId: string; invocationId: string }) {
    const state = await read();
    const request = {
      service: "model" as const, operation: "complete", replayPolicy: "safe" as const,
      payload: { request: suffix },
    };
    const command: SessionCommand = {
      kind: "commit_engine_step", commandId: `prepare-${suffix}`, expectedEventSequence: state.eventSequence,
      turnId: state.activeTurn!.turnId, fence: fence(state), transactionTime: NOW,
      consumedSettlementEffectId: state.activeTurn!.activeEffectId,
      effectIdentity: identity ?? { effectId: `effect-${suffix}`, invocationId: `invocation-${suffix}` },
      step: { kind: "effect_request", checkpoint: await checkpoint(state), request: { ...request, requestDigest: await effectRequestDigest(request) } },
    };
    return { command, response: await execute(command) };
  }
  async function dispatch() {
    const state = await read();
    const effect = state.effects.find((entry) => entry.effectId === state.activeTurn!.activeEffectId)!;
    const command: SessionCommand = {
      kind: "dispatch_effect", commandId: `dispatch-${effect.effectId}`,
      expectedEventSequence: state.eventSequence, turnId: effect.turnId, fence: fence(state),
      effectId: effect.effectId, invocationId: effect.invocationId, requestDigest: effect.requestDigest,
      transactionTime: NOW, deadline: 9_000, providerRequestId: `provider-${effect.effectId}`,
      providerRouteDigest: digest("4"),
    };
    return { command, response: await execute(command) };
  }
  async function settle(result: NormalizedValue = { answer: 42 }) {
    const state = await read();
    const effect = state.effects.find((entry) => entry.effectId === state.activeTurn!.activeEffectId)!;
    const command: SessionCommand = {
      kind: "settle_effect", commandId: `settle-${effect.effectId}`,
      expectedEventSequence: state.eventSequence, turnId: effect.turnId, fence: fence(state),
      effectId: effect.effectId, invocationId: effect.invocationId, requestDigest: effect.requestDigest,
      dispatchAttempt: effect.dispatchAttempt, settlement: { kind: "success", result },
    };
    return { command, response: await execute(command) };
  }
  async function completedTurns(count: number, prefix = "history", withEffects = false) {
    for (let index = 0; index < count; index += 1) {
      await enqueue(`${prefix}-${index}`);
      if (withEffects) {
        await prepare(`${prefix}-${index}`);
        await dispatch();
        await settle({ index });
      }
      await completion({ index });
    }
  }
  return {
    storage, authority, read, execute, events, blob, checkpoint, fence,
    enqueue, completion, prepare, dispatch, settle, completedTurns,
    restart: () => { cell = createCell(); },
  };
}

function assertBoundedHot(state: SessionAggregateState) {
  expect(state.history?.commandThrough).toBeGreaterThan(0);
  expect(state.commandReceipts.length).toBeLessThanOrEqual(SESSION_HISTORY_HOT_COMMANDS);
  expect(state.publicEvents.length).toBeLessThanOrEqual(SESSION_HISTORY_HOT_PUBLIC_EVENTS);
  // Hot public events and start receipts can still pin their related entities.
  // These are bounded dependencies, so the trim targets are not strict caps.
  expect(state.terminalTurns.length).toBeLessThanOrEqual(
    SESSION_HISTORY_HOT_TERMINAL_TURNS + state.publicEvents.length + state.effects.length,
  );
  expect(state.effects.length).toBeLessThanOrEqual(
    SESSION_HISTORY_HOT_EFFECTS + state.publicEvents.length + state.commandReceipts.length + 1,
  );
  expect(state.knownTurnIds.length).toBe(state.terminalTurns.length + state.queuedTurns.length + (state.activeTurn === null ? 0 : 1));
  expect(state.turnAdmissionReceipts.length).toBeLessThanOrEqual(state.knownTurnIds.length);
  expect(encodeCanonicalCbor(state).byteLength).toBeLessThan(128 * 1024);
}

describe("SessionCell archived history", () => {
  // Behavioral cases are below; each first asserts that its target record left
  // the hot state so ordinary retained history cannot satisfy the regression.
  it("replays archived commands and public admissions exactly and rejects conflicting or reused identities", async () => {
    const f = await fixture();
    const admitted = await f.enqueue("original", { prompt: "original input" });
    const completed = await f.completion({ answer: "original result" });
    await f.completedTurns(ARCHIVE_TURNS);
    const state = await f.read();
    assertBoundedHot(state);
    expect(state.history!.turnThrough).toBeGreaterThan(0);
    expect(state.commandReceipts.some((receipt) => receipt.commandId === completed.command.commandId)).toBe(false);
    expect(state.terminalTurns.some((turn) => turn.turnId === "original")).toBe(false);
    expect(state.turnAdmissionReceipts.some((receipt) => receipt.turnId === "original")).toBe(false);
    f.restart();
    const revision = f.storage.backing.durableRevision;
    for (const original of [admitted, completed]) {
      const replay = await f.execute(original.command);
      expect(replay.replayed).toBe(true);
      expect(replay.outcome).toEqual(original.response.outcome);
    }
    if (admitted.command.kind !== "enqueue_turn") throw new Error("enqueue required");
    const publicReplay: SessionCommand = {
      ...admitted.command, commandId: "new-command-same-public-key", expectedEventSequence: state.eventSequence,
      turnId: "replacement-id", genesisCheckpoint: await f.checkpoint(state, "replacement-id"),
    };
    const replay = await f.execute(publicReplay);
    expect(replay.replayed).toBe(true);
    expect(replay.outcome).toEqual(admitted.response.outcome);
    expect(f.storage.backing.durableRevision).toBe(revision);
    expect(await f.read()).toEqual(state);

    if (completed.command.kind !== "commit_engine_step" || completed.command.step.kind !== "turn_complete") {
      throw new Error("completion required");
    }
    await expect(f.execute({
      ...completed.command, step: { ...completed.command.step, result: "conflicting body" },
    })).rejects.toMatchObject({ code: "IDEMPOTENCY_CONFLICT" });
    await expect(f.execute({
      ...publicReplay, publicAdmission: { ...admitted.command.publicAdmission!, requestDigest: digest("9") },
    })).rejects.toMatchObject({ code: "IDEMPOTENCY_CONFLICT" });
    await expect(f.execute({
      ...admitted.command, commandId: "reuse-archived-turn", expectedEventSequence: state.eventSequence,
      publicAdmission: { ...admitted.command.publicAdmission!, idempotencyKeyDigest: digest("8") },
    })).rejects.toMatchObject({ code: "ALREADY_EXISTS" });
    expect(f.storage.backing.durableRevision).toBe(revision);
    expect(await f.read()).toEqual(state);
    expect(Math.max(...f.storage.writesPerCommit)).toBeLessThanOrEqual(MAX_TRANSACTION_MUTATED_KEYS);
  }, 60_000);

  it("replays archived settlement bytes and never issues a fresh archived dispatch start", async () => {
    const f = await fixture();
    await f.enqueue("effect-original");
    await f.prepare("original");
    const dispatched = await f.dispatch();
    if (dispatched.response.outcome.kind !== "effect_dispatched") throw new Error("dispatch required");
    const beforeClaim = await f.read();
    const effect = beforeClaim.effects[0]!;
    const claim: SessionCommand = {
      kind: "claim_dispatch_start", commandId: "claim-original",
      expectedEventSequence: beforeClaim.eventSequence, workspaceId: beforeClaim.workspaceId,
      turnId: effect.turnId, fence: f.fence(beforeClaim), effectId: effect.effectId,
      invocationId: effect.invocationId, requestDigest: effect.requestDigest,
      transactionTime: NOW, dispatchAttempt: 1, providerRequestId: effect.lastDispatch!.providerRequestId,
      providerRouteDigest: digest("4"), dispatchPermitClaims: dispatched.response.outcome.dispatchPermitClaims,
      commandDigest: digest("5"),
    };
    const claimed = await f.execute(claim);
    expect(claimed.outcome).toMatchObject({ kind: "dispatch_start_claimed", fresh: true });
    const settled = await f.settle({ large: "retained".repeat(1024), answer: 42 });
    await f.completion();
    await f.completedTurns(Math.max(SESSION_HISTORY_HOT_EFFECTS, SESSION_HISTORY_HOT_TERMINAL_TURNS) + 1,
      "effect-history", true);
    const archived = await f.read();
    assertBoundedHot(archived);
    expect(archived.commandReceipts.some((receipt) => receipt.commandId === claim.commandId)).toBe(false);
    expect(archived.effects.some((entry) => entry.effectId === effect.effectId)).toBe(false);
    f.restart();
    const revision = f.storage.backing.durableRevision;
    const replay = await f.execute(settled.command);
    expect(replay.replayed).toBe(true);
    expect(replay.outcome).toEqual(settled.response.outcome);
    const startReplay = await f.execute(claim);
    expect(startReplay.replayed).toBe(true);
    expect(startReplay.outcome).toEqual({ ...claimed.outcome, fresh: false });
    await expect(f.execute({
      ...claim, commandId: "fresh-claim-for-archived-effect", expectedEventSequence: archived.eventSequence,
    })).rejects.toMatchObject({ code: "NOT_FOUND" });
    expect(f.storage.backing.durableRevision).toBe(revision);

    await f.enqueue("fresh-turn");
    const beforeReuse = await f.read();
    const reuseRevision = f.storage.backing.durableRevision;
    await expect(f.prepare("reused-effect", { effectId: effect.effectId, invocationId: "fresh-invocation" }))
      .rejects.toMatchObject({ code: "ALREADY_EXISTS" });
    await expect(f.prepare("reused-invocation", { effectId: "fresh-effect", invocationId: effect.invocationId }))
      .rejects.toMatchObject({ code: "ALREADY_EXISTS" });
    expect(f.storage.backing.durableRevision).toBe(reuseRevision);
    expect(await f.read()).toEqual(beforeReuse);
  }, 60_000);

  it("joins archive and hot public-event pages without gaps at every boundary", async () => {
    const f = await fixture();
    await f.completedTurns(ARCHIVE_TURNS + 1);
    const state = await f.read();
    assertBoundedHot(state);
    const boundary = state.history!.publicEventThrough;
    expect(boundary).toBeGreaterThan(0);
    expect(state.publicEvents[0]?.sequence).toBe(boundary + 1);
    f.restart();
    const all = await f.events();
    expect(all.snapshot.lastEventSequence).toBe(state.publicEventSequence);
    expect(all.events.map((event) => event.sequence)).toEqual(
      Array.from({ length: state.publicEventSequence }, (_, index) => index + 1),
    );
    for (let index = 0; index < ARCHIVE_TURNS + 1; index += 1) {
      expect(all.events.slice(index * 2, index * 2 + 2).map((event) => [event.type, event.turnId])).toEqual([
        ["turn.accepted", `history-${index}`], ["turn.completed", `history-${index}`],
      ]);
    }
    for (const cursor of [0, boundary - 1, boundary, boundary + 1, state.publicEventSequence]) {
      for (const limit of [1, 3]) {
        const page = await f.events(cursor, limit);
        expect(page.events).toEqual(all.events.slice(cursor, cursor + limit));
      }
    }
    const paged: unknown[] = [];
    for (let cursor = 0; cursor < state.publicEventSequence;) {
      const page = await f.events(cursor, 3);
      expect(page.events.length).toBeGreaterThan(0);
      paged.push(...page.events);
      cursor = page.events.at(-1)!.sequence;
    }
    expect(paged).toEqual(all.events);
  }, 60_000);

  it("retains archive-owned blobs after hot GC and checks authority before archive reads", async () => {
    const f = await fixture();
    const admitted = await f.enqueue("retained-blob", { prompt: "unique archived input" });
    await f.completion({ answer: "unique archived result" });
    const terminal = (await f.read()).terminalTurns[0]!;
    const inputRef = terminal.inputRef!;
    const resultRef = terminal.resultPayloadRef!;
    const checkpointDigest = terminal.finalCheckpoint.payloadDigest;
    await f.completedTurns(ARCHIVE_TURNS);
    const archived = await f.read();
    assertBoundedHot(archived);
    expect(archived.terminalTurns.some((turn) => turn.turnId === terminal.turnId)).toBe(false);
    for (const value of [inputRef.digest, resultRef.digest, checkpointDigest]) {
      expect(JSON.stringify(archived)).not.toContain(value);
    }
    const manifestKey = [...f.storage.keys].find((key) => key.endsWith(".manifest"))!;
    const manifest = await f.storage.transaction((transaction) => transaction.get<{
      referencedBlobs: { digest: Digest }[]; sessionHistory: { size: number };
    }>(manifestKey));
    expect(manifest!.sessionHistory.size).toBeGreaterThan(0);
    expect(manifest!.referencedBlobs.some((reference) => reference.digest === inputRef.digest)).toBe(false);
    f.restart();
    await f.completedTurns(3, "gc-later");
    for (const [reference, value] of [[inputRef, { prompt: "unique archived input" }], [resultRef, { answer: "unique archived result" }]] as const) {
      const stored = await f.blob(reference.digest);
      expect(stored?.encodedBytes).toBe(reference.encodedBytes);
      expect(await digestBytes(stored!.bytes)).toBe(reference.digest);
      expect(decodeCanonicalCbor(stored!.bytes)).toEqual(value);
    }
    expect((await f.blob(checkpointDigest))?.bytes).toEqual(bytes("retained-blob:1"));

    const revision = f.storage.backing.durableRevision;
    for (const [authority, code] of [
      [{ tenantId: "foreign-tenant" }, "PERMISSION_DENIED"],
      [{ subjectId: "foreign-session" }, "PERMISSION_DENIED"],
      [{ permissions: [] }, "PERMISSION_DENIED"],
      [{ authorizationGeneration: 5, currentAuthorizationGeneration: 5 }, "STALE_GENERATION"],
    ] as const) {
      for (const read of [() => f.events(0, 1, authority), () => f.blob(inputRef.digest, authority)]) {
        f.storage.reads.length = 0;
        await expect(read()).rejects.toMatchObject({ code });
        expect(f.storage.reads.filter((key) => key.startsWith("circulusd.state-app.session-history.v1."))).toEqual([]);
        expect(f.storage.reads.filter((key) => key.includes(".blob."))).toEqual([]);
      }
    }
    expect(f.storage.backing.durableRevision).toBe(revision);
    const beforeRotation = await f.read();
    await f.execute({
      kind: "rotate_generations", commandId: "rotate-after-archive", expectedEventSequence: beforeRotation.eventSequence,
      nextPlacementGeneration: 5, nextSandboxGeneration: 6, nextAuthorizationGeneration: 7,
      nextEmergencyOverlayDigest: digest("7"),
    });
    const rotatedRevision = f.storage.backing.durableRevision;
    await expect(f.execute(admitted.command)).rejects.toMatchObject({ code: "STALE_GENERATION" });
    expect(f.storage.backing.durableRevision).toBe(rotatedRevision);
  }, 60_000);

  it("fails closed on missing or modified archive rows, index pages, and archived payload bytes", async () => {
    const f = await fixture();
    await f.enqueue("corrupt-target");
    const completed = await f.completion({ archived: "original bytes" });
    const resultRef = (await f.read()).terminalTurns[0]!.resultPayloadRef!;
    await f.completedTurns(ARCHIVE_TURNS);
    const archived = await f.read();
    assertBoundedHot(archived);
    expect(archived.commandReceipts.some((receipt) => receipt.commandId === completed.command.commandId)).toBe(false);

    async function accessedRow(kind: string, operation: () => Promise<unknown>) {
      f.storage.reads.length = 0;
      await operation();
      const keys = [...new Set(f.storage.reads)];
      for (const key of keys.filter((key) => key.startsWith(SESSION_HISTORY_ROW_PREFIX) && key.endsWith(".0"))) {
        const stored = await f.storage.transaction((transaction) => transaction.get<Uint8Array>(key));
        const row = decodeCanonicalCbor(stored!) as { kind: string };
        if (row.kind === kind) return { key, keys };
      }
      throw new Error(`operation did not read an archived ${kind} row`);
    }
    const commandRow = await accessedRow("command", () => f.execute(completed.command));
    const eventRow = await accessedRow("public-events", () => f.events(0, 1));
    const indexKey = commandRow.keys.find((key) => key.startsWith("circulusd.state-app.session-history.v1.index."))!;
    expect(indexKey).toBeDefined();
    f.storage.reads.length = 0;
    await f.blob(resultRef.digest);
    const blobKey = f.storage.reads.find((key) => key.includes(".blob.") && key.includes(resultRef.digest))!;
    expect(blobKey).toBeDefined();

    for (const [key, operation] of [
      [commandRow.key, () => f.execute(completed.command)],
      [eventRow.key, () => f.events(0, 1)],
      [indexKey, () => f.execute(completed.command)],
      [blobKey, () => f.blob(resultRef.digest)],
    ] as const) {
      const original = await f.storage.transaction((transaction) => transaction.get<Uint8Array>(key));
      expect(original).toBeInstanceOf(Uint8Array);
      for (const corrupt of [false, true]) {
        await f.storage.transaction(async (transaction) => {
          if (corrupt) {
            const modified = original!.slice();
            modified[0] = modified[0]! ^ 0xff;
            await transaction.put(key, modified);
          } else await transaction.delete(key);
        });
        f.restart();
        const revision = f.storage.backing.durableRevision;
        await expect(operation()).rejects.toMatchObject({ code: "CORRUPT_STATE" });
        expect(f.storage.backing.durableRevision).toBe(revision);
        await f.storage.transaction((transaction) => transaction.put(key, original));
      }
      await operation();
    }
    expect(await f.read()).toEqual(archived);
  }, 60_000);

  it("requires the archive root for a private active turn even before any prefix watermark advances", async () => {
    const f = await fixture();
    await f.enqueue("private-active", { private: true }, false);
    for (let index = 0; index <= SESSION_HISTORY_HOT_EFFECTS; index += 1) {
      await f.prepare(`private-${index}`);
      await f.dispatch();
      await f.settle({ index });
    }
    const state = await f.read();
    expect(state.history).toMatchObject({ commandThrough: 0, publicEventThrough: 0, turnThrough: 0 });
    expect(state.effects.some((effect) => effect.effectId === "effect-private-0")).toBe(false);
    const key = [...f.storage.keys].find((key) => key.endsWith(".manifest"))!;
    const manifest = await f.storage.transaction((transaction) => transaction.get<Record<string, unknown>>(key));
    expect(manifest!.sessionHistory).toMatchObject({ size: expect.any(Number) });
    expect((manifest!.sessionHistory as { size: number }).size).toBeGreaterThan(0);
    for (const root of [undefined, { version: 1, root: null, nextNodeId: 1, size: 0 }]) {
      const damaged = structuredClone(manifest!);
      if (root === undefined) delete damaged.sessionHistory;
      else damaged.sessionHistory = root;
      await f.storage.transaction((transaction) => transaction.put(key, damaged));
      f.restart();
      const revision = f.storage.backing.durableRevision;
      await expect(f.read()).rejects.toMatchObject({ code: "CORRUPT_STATE" });
      expect(f.storage.backing.durableRevision).toBe(revision);
      await f.storage.transaction((transaction) => transaction.put(key, manifest));
    }
    expect(await f.read()).toEqual(state);
  }, 60_000);

  it("compacts consumed effects during an active turn and preserves its current dispatch", async () => {
    const f = await fixture();
    await f.enqueue("long-active-turn");
    let firstSettlement: Awaited<ReturnType<typeof f.settle>> | undefined;
    const effects = SESSION_HISTORY_HOT_EFFECTS + Math.ceil(SESSION_HISTORY_HOT_COMMANDS / 3) + 2;
    for (let index = 0; index < effects; index += 1) {
      await f.prepare(`active-${index}`);
      await f.dispatch();
      const settlement = await f.settle({ index });
      firstSettlement ??= settlement;
    }
    await f.prepare("current-dispatch");
    await f.dispatch();
    const active = await f.read();
    assertBoundedHot(active);
    expect(active.terminalTurns).toEqual([]);
    expect(active.effects.some((effect) => effect.effectId === "effect-active-0")).toBe(false);
    expect(active.effects.find((effect) => effect.effectId === "effect-current-dispatch"))
      .toMatchObject({ phase: "dispatched", consumedAtCheckpointSequence: null });
    expect(active.activeTurn?.activeEffectId).toBe("effect-current-dispatch");
    const checkpointSequence = active.activeTurn!.checkpoint.checkpointSequence;
    f.restart();
    const revision = f.storage.backing.durableRevision;
    expect((await f.execute(firstSettlement!.command)).outcome).toEqual(firstSettlement!.response.outcome);
    expect(f.storage.backing.durableRevision).toBe(revision);
    await f.settle({ resumed: true });
    await f.completion();
    const finished = await f.read();
    expect(finished.activeTurn).toBeNull();
    expect(finished.terminalTurns.at(-1)).toMatchObject({
      turnId: "long-active-turn", status: "completed",
      finalCheckpoint: { checkpointSequence: checkpointSequence + 1 },
    });
    expect(Math.max(...f.storage.writesPerCommit)).toBeLessThanOrEqual(MAX_TRANSACTION_MUTATED_KEYS);
  }, 60_000);

  it("retains runtime pointer history across archived staging, activation, and later rollback", async () => {
    const f = await fixture();
    const original = await f.read();
    const candidateRevision = digest("a");
    await f.execute({
      kind: "stage_runtime_revision", commandId: "stage-original", expectedEventSequence: original.eventSequence,
      candidateRevision,
    });
    const staged = await f.read();
    const activation: SessionCommand = {
      kind: "activate_runtime_revision", commandId: "activate-original", expectedEventSequence: staged.eventSequence,
      expectedActiveRevision: original.runtimeRevisionDigest, expectedCandidateRevision: candidateRevision,
      expectedSwitchGeneration: staged.runtimePointer.switchGeneration,
      healthReceiptDigest: digest("b"), migrationReceiptDigest: digest("c"),
    };
    const activated = await f.execute(activation);
    await f.completedTurns(ARCHIVE_TURNS);
    const archived = await f.read();
    assertBoundedHot(archived);
    expect(archived.commandReceipts.some((receipt) => receipt.commandId === activation.commandId)).toBe(false);
    expect(archived.runtimePointer).toMatchObject({ activeRevision: candidateRevision, previousRevision: original.runtimeRevisionDigest });
    f.restart();
    await f.execute({
      kind: "rollback_runtime_revision", commandId: "rollback-after-archive", expectedEventSequence: archived.eventSequence,
      expectedActiveRevision: candidateRevision, expectedPreviousRevision: original.runtimeRevisionDigest,
      expectedSwitchGeneration: archived.runtimePointer.switchGeneration, failureReceiptDigest: digest("d"),
    });
    const rolledBack = await f.read();
    expect(rolledBack.runtimeRevisionDigest).toBe(original.runtimeRevisionDigest);
    expect(rolledBack.runtimePointer.switchGeneration).toBe(archived.runtimePointer.switchGeneration + 1);
    const revision = f.storage.backing.durableRevision;
    expect((await f.execute(activation)).outcome).toEqual(activated.outcome);
    expect(f.storage.backing.durableRevision).toBe(revision);
    expect(await f.read()).toEqual(rolledBack);
    await f.enqueue("after-rollback");
    await f.completion();
    expect((await f.read()).terminalTurns.at(-1)?.finalCheckpoint.runtimeRevisionDigest).toBe(original.runtimeRevisionDigest);
  }, 60_000);
});
