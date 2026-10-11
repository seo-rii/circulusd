import { describe, expect, it } from "vitest";
import {
  PROTOCOL_MAJOR, PROTOCOL_MINOR, PROTOCOL_NAME,
  decodeCanonicalCbor, digestBytes, encodeCanonicalCbor,
  type AgentCheckpoint, type Digest, type NormalizedValue,
} from "@circulusd/protocol-types";
import { SessionCell, sessionCellName } from "../src/host/index.ts";
import {
  HOST_RPC_CONTRACTS, type HostRpcOperation, type HostRpcResponse,
} from "../src/host/rpc.ts";
import {
  effectRequestDigest, turnInputDigest,
  type SessionAggregateState, type SessionCommand,
} from "../src/session/index.ts";
import {
  SESSION_CAPACITY_RESERVE_UNIT_BYTES,
  SESSION_CAPACITY_RESERVE_UNIT_ITEMS,
  SESSION_STATE_MAX_ENCODED_ITEMS,
  SESSION_TURN_COMPLETION_RESERVE_ITEMS,
  SESSION_VALUE_MAX_ENCODED_BYTES,
} from "../src/session/types.ts";
import { sessionPayloadItems } from "../src/session/payload.ts";
import { RestartableDurableStorage } from "./support/restartable-durable-storage.ts";

const digest = (value: string): Digest => `sha256:${value.repeat(64)}`;
const RUNTIME = digest("1");
// A CBOR string this long occupies exactly the per-value limit minus one byte.
const LARGE_RESULT = "r".repeat(SESSION_VALUE_MAX_ENCODED_BYTES - 6);

async function fixture(maximumIdentifiers = false) {
  const storage = new RestartableDurableStorage();
  let now = 200;
  const tenantId = maximumIdentifiers ? "t".repeat(256) : "tenant-capacity";
  const userId = maximumIdentifiers ? "u".repeat(256) : "user-capacity";
  const sessionId = maximumIdentifiers ? "s".repeat(256) : "session-capacity";
  const workspaceId = maximumIdentifiers ? "w".repeat(256) : "workspace-capacity";
  const logicalName = sessionCellName(tenantId, sessionId);
  const routedIds = new Map<string, string>();
  const physicalId = (name: string) => {
    if (!routedIds.has(name)) routedIds.set(name, `physical:${routedIds.size}`);
    const id = routedIds.get(name)!;
    return { toString: () => id, equals: (other: unknown) => String(other) === id };
  };
  const cell = new SessionCell(
    { storage, id: physicalId(logicalName) } as never,
    { SESSION_CELL: { idFromName: physicalId } } as never,
    () => now,
  );
  const authority = {
    serviceBinding: "state", tenantId, actorUserId: userId,
    subjectKind: "session", subjectId: sessionId, roles: ["user"],
    permissions: ["session.read"], authorizationGeneration: 6,
    currentAuthorizationGeneration: 6, issuedAt: 1, expiresAt: 100_000,
  };
  async function rpc<Result>(
    operation: HostRpcOperation,
    payload: unknown,
    invoke: (request: unknown) => Promise<HostRpcResponse<Result>>,
  ): Promise<Result> {
    const response = await invoke({
      protocol: PROTOCOL_NAME, major: PROTOCOL_MAJOR, minor: PROTOCOL_MINOR,
      schemaDigest: HOST_RPC_CONTRACTS[operation].schemaDigest,
      requestId: `capacity-${operation}`, payload,
    });
    if (!response.payload.ok) {
      throw Object.assign(new Error(response.payload.error.message), { code: response.payload.error.code });
    }
    return response.payload.result as Result;
  }
  await rpc("session.initialize", {
    sessionId, tenantId, userId, workspaceId, runtimeRevisionDigest: RUNTIME,
    policySnapshotDigest: digest("2"), emergencyOverlayDigest: digest("3"),
    engineKind: "low-level", adapterAbiVersion: 1, checkpointSchemaVersion: 1,
    placementGeneration: 4, sandboxGeneration: 5, authorizationGeneration: 6,
  }, (request) => cell.initializeSession(request));
  const read = () => rpc("session.read", { authority, now }, (request) => cell.readSession(request));
  const execute = (command: SessionCommand) => rpc("session.execute", command,
    (request) => cell.executeSessionCommand(request));
  const fence = (state: SessionAggregateState) => ({
    turnLeaseGeneration: state.activeTurn!.turnLeaseGeneration,
    placementGeneration: state.placementGeneration, sandboxGeneration: state.sandboxGeneration,
    authorizationGeneration: state.authorizationGeneration,
  });
  async function checkpoint(state: SessionAggregateState, turnId?: string): Promise<AgentCheckpoint> {
    const genesis = turnId !== undefined;
    const active = state.activeTurn;
    const sequence = genesis ? 0 : active!.checkpoint.checkpointSequence + 1;
    const id = turnId ?? active!.turnId;
    const payloadBytes = new TextEncoder().encode(`${id}:${sequence}`);
    const metadata = {
      engineKind: "low-level" as const, adapterAbiVersion: 1, checkpointSchemaVersion: 1,
      runtimeRevisionDigest: RUNTIME, sessionId: state.sessionId, turnId: id,
      payloadEncoding: "opaque-v1" as const, payloadBytes, payloadDigest: await digestBytes(payloadBytes),
    };
    return genesis
      ? { ...metadata, kind: "genesis", checkpointSequence: 0, predecessorDigest: null }
      : { ...metadata, kind: "engine", checkpointSequence: sequence, predecessorDigest: active!.checkpointChainDigest };
  }
  async function admit(turnId: string, input: NormalizedValue = { prompt: "small" }, expiresAt = 10_000) {
    const state = await read();
    return execute({
      kind: "enqueue_turn", commandId: `admit-${turnId}`.slice(0, 256), expectedEventSequence: state.eventSequence,
      transactionTime: now, turnId, input, inputDigest: await turnInputDigest(input),
      genesisCheckpoint: await checkpoint(state, turnId), turnLeaseGeneration: state.nextTurnSequence + 10,
      leaseExpiresAt: expiresAt,
      publicAdmission: {
        authorizationGeneration: 6,
        idempotencyKeyDigest: await digestBytes(new TextEncoder().encode(`key:${turnId}`)),
        requestDigest: await digestBytes(new TextEncoder().encode(`request:${turnId}`)),
      },
    });
  }
  async function complete(result: NormalizedValue, consumedSettlementEffectId: string | null = null) {
    const state = await read();
    const turnId = state.activeTurn!.turnId;
    return execute({
      kind: "commit_engine_step", commandId: `complete-${turnId}`.slice(0, 256),
      expectedEventSequence: state.eventSequence, turnId, fence: fence(state), transactionTime: now,
      consumedSettlementEffectId, effectIdentity: null,
      step: { kind: "turn_complete", checkpoint: await checkpoint(state), result },
    });
  }
  async function payload(record: unknown, field: string, referenceField: string): Promise<NormalizedValue> {
    const value = record as Record<string, unknown>;
    if (Object.hasOwn(value, field)) return value[field] as NormalizedValue;
    const reference = value[referenceField] as { encoding: string; digest: Digest; encodedBytes: number };
    expect(reference?.encoding).toBe("canonical-cbor-v1");
    const blob = await rpc("session.read-blob", { authority, now, digest: reference.digest },
      (request) => cell.readSessionBlob(request));
    expect(blob).not.toBeNull();
    expect(blob!.encodedBytes).toBe(reference.encodedBytes);
    expect(await digestBytes(blob!.bytes)).toBe(reference.digest);
    return decodeCanonicalCbor(blob!.bytes);
  }
  return { storage, read, execute, admit, complete, payload, checkpoint, fence, setTime: (value: number) => { now = value; } };
}

// Only a pre-admission capacity refusal is acceptable. Every admitted turn must
// subsequently finish; no completion/settlement errors are caught by the tests.
async function admitUpTo(f: Awaited<ReturnType<typeof fixture>>, count: number) {
  const admitted: string[] = [];
  for (let index = 0; index < count; index += 1) {
    const turnId = `turn-${index}`;
    const before = await f.read();
    const revision = f.storage.durableRevision;
    try {
      await f.admit(turnId);
      admitted.push(turnId);
    } catch (error) {
      expect(admitted.length, "an empty Session must admit the first valid turn").toBeGreaterThan(0);
      expect(error).toMatchObject({ code: "FAILED_PRECONDITION" });
      expect(f.storage.durableRevision).toBe(revision);
      expect(await f.read()).toEqual(before);
      break;
    }
  }
  return admitted;
}

describe("SessionCell admitted payload capacity", () => {
  it("finishes every accepted queued turn with a near-limit result", async () => {
    expect(encodeCanonicalCbor(LARGE_RESULT).byteLength).toBe(SESSION_VALUE_MAX_ENCODED_BYTES - 1);
    const f = await fixture();
    const admitted = await admitUpTo(f, 3);
    for (const turnId of admitted) {
      expect((await f.read()).activeTurn?.turnId).toBe(turnId);
      await f.complete(LARGE_RESULT);
    }
    const state = await f.read();
    expect(state.activeTurn).toBeNull();
    expect(state.queuedTurns).toEqual([]);
    expect(state.terminalTurns.map((turn) => turn.turnId)).toEqual(admitted);
    for (const terminal of state.terminalTurns) {
      expect(await f.payload(terminal, "result", "resultPayloadRef")).toBe(LARGE_RESULT);
    }
  });

  it("finishes every accepted queued turn with a dense 50,000-item result", async () => {
    const f = await fixture();
    const admitted = await admitUpTo(f, 2);
    const result = Array<number>(50_000).fill(0);
    for (const turnId of admitted) {
      expect((await f.read()).activeTurn?.turnId).toBe(turnId);
      await f.complete(result);
    }
    const state = await f.read();
    expect(state.activeTurn).toBeNull();
    expect(state.terminalTurns).toHaveLength(admitted.length);
    for (const terminal of state.terminalTurns) {
      const restored = await f.payload(terminal, "result", "resultPayloadRef") as number[];
      expect(restored.length).toBe(50_000);
      expect(restored.every((entry) => entry === 0)).toBe(true);
    }
  });

  it("persists a large dispatched settlement and replays the original raw response after completion", async () => {
    const f = await fixture();
    await f.admit("turn-effect");
    let state = await f.read();
    const requestPayload = "q".repeat(SESSION_VALUE_MAX_ENCODED_BYTES - 6);
    const request = {
      service: "model" as const, operation: "complete", replayPolicy: "safe" as const,
      payload: requestPayload,
    };
    const requestDigest = await effectRequestDigest(request);
    const prepare: SessionCommand = {
      kind: "commit_engine_step", commandId: "prepare-large", expectedEventSequence: state.eventSequence,
      turnId: "turn-effect", fence: f.fence(state), transactionTime: 200,
      consumedSettlementEffectId: null, effectIdentity: { effectId: "effect-large", invocationId: "invocation-large" },
      step: { kind: "effect_request", checkpoint: await f.checkpoint(state), request: { ...request, requestDigest } },
    };
    const revision = f.storage.durableRevision;
    try {
      await f.execute(prepare);
    } catch (error) {
      expect(error).toMatchObject({ code: "FAILED_PRECONDITION" });
      expect(f.storage.durableRevision).toBe(revision);
      expect(await f.read()).toEqual(state);
      // Capacity refusal must happen before issuing an effect/dispatch and must
      // leave the already admitted turn able to record its terminal boundary.
      await f.complete(LARGE_RESULT);
      expect((await f.read()).terminalTurns[0]?.status).toBe("completed");
      return;
    }
    state = await f.read();
    const effectFields = {
      turnId: "turn-effect", fence: f.fence(state), effectId: "effect-large",
      invocationId: "invocation-large", requestDigest,
    };
    await f.execute({
      ...effectFields, kind: "dispatch_effect", commandId: "dispatch-large",
      expectedEventSequence: state.eventSequence, transactionTime: 200,
      deadline: 9_000, providerRouteDigest: digest("4"),
    });
    state = await f.read();
    const settle: SessionCommand = {
      ...effectFields, kind: "settle_effect", commandId: "settle-large",
      expectedEventSequence: state.eventSequence, dispatchAttempt: 1,
      settlement: { kind: "success", result: LARGE_RESULT },
    };
    const committed = await f.execute(settle);
    expect(committed.replayed).toBe(false);
    expect(committed.outcome).toEqual({
      kind: "effect_settled", effectId: "effect-large", settlement: { kind: "success", result: LARGE_RESULT },
    });
    await f.complete({ done: true }, "effect-large");
    const after = await f.read();
    const replayRevision = f.storage.durableRevision;
    const replayed = await f.execute(settle);
    expect(replayed.replayed).toBe(true);
    expect(replayed.outcome).toEqual(committed.outcome);
    expect(f.storage.durableRevision).toBe(replayRevision);
    expect(await f.read()).toEqual(after);
    const effect = after.effects.find((entry) => entry.effectId === "effect-large")!;
    expect(await f.payload(effect, "requestPayload", "requestPayloadRef")).toBe(requestPayload);
    expect(await f.payload(effect.settlement, "result", "resultPayloadRef")).toBe(LARGE_RESULT);
    expect(after.terminalTurns[0]?.status).toBe("completed");
  });

  it("retains closure capacity when a dense queued input expires and the next live turn aborts", async () => {
    const f = await fixture();
    await f.admit("turn-first");
    await f.admit("turn-expired", Array<number>(40_000).fill(0), 300);
    await f.admit("turn-live");
    f.setTime(400);
    await f.complete(LARGE_RESULT);
    let state = await f.read();
    expect(state.activeTurn?.turnId).toBe("turn-live");
    expect(state.terminalTurns.map((turn) => [turn.turnId, turn.status])).toEqual([
      ["turn-first", "completed"], ["turn-expired", "aborted"],
    ]);
    await f.execute({
      kind: "request_abort", commandId: "abort-live", expectedEventSequence: state.eventSequence,
      turnId: "turn-live", fence: f.fence(state), transactionTime: 400, reason: "cancelled",
    });
    state = await f.read();
    expect(state.activeTurn).toBeNull();
    expect(state.queuedTurns).toEqual([]);
    expect(state.terminalTurns[2]?.status).toBe("aborted");
    const restored = await f.payload(state.terminalTurns[1], "input", "inputRef") as number[];
    expect(restored.length).toBe(40_000);
    expect(restored.every((entry) => entry === 0)).toBe(true);
  });

  it("refuses further effect growth before dispatch while preserving reserved abort capacity", async () => {
    const f = await fixture();
    const reservationBound = Math.floor(
      SESSION_STATE_MAX_ENCODED_ITEMS / SESSION_TURN_COMPLETION_RESERVE_ITEMS,
    ) + 1;
    const admitted = await admitUpTo(f, reservationBound);
    expect(admitted.length, "the live-turn reservation must bound pending work").toBeLessThan(reservationBound);
    const before = await f.read();
    const revision = f.storage.durableRevision;
    const request = {
      service: "model" as const, operation: "complete", replayPolicy: "safe" as const,
      payload: { prompt: "small" },
    };
    await expect(f.execute({
      kind: "commit_engine_step", commandId: "prepare-over-capacity",
      expectedEventSequence: before.eventSequence, turnId: before.activeTurn!.turnId,
      fence: f.fence(before), transactionTime: 200, consumedSettlementEffectId: null,
      effectIdentity: { effectId: "effect-over-capacity", invocationId: "invocation-over-capacity" },
      step: {
        kind: "effect_request", checkpoint: await f.checkpoint(before),
        request: { ...request, requestDigest: await effectRequestDigest(request) },
      },
    })).rejects.toMatchObject({ code: "FAILED_PRECONDITION" });
    expect(f.storage.durableRevision).toBe(revision);
    expect(await f.read()).toEqual(before);
    await f.execute({
      kind: "request_abort", commandId: "abort-at-capacity", expectedEventSequence: before.eventSequence,
      turnId: before.activeTurn!.turnId, fence: f.fence(before), transactionTime: 200, reason: "cancelled",
    });
    const after = await f.read();
    expect(after.terminalTurns[0]).toMatchObject({ turnId: admitted[0], status: "aborted" });
    expect(after.activeTurn?.turnId).toBe(admitted[1]);
    expect(after.effects).toEqual([]);
  }, 60_000);

  it("covers maximum identifier and error metadata within each released recovery reservation", async () => {
    const f = await fixture(true);
    const wide = (character: string) => character.repeat(256);
    const turnId = wide("a");
    await f.admit(turnId);
    let state = await f.read();
    const request = {
      service: "model" as const, operation: wide("o"), replayPolicy: "safe" as const,
      parentOperationId: wide("p"), ordinal: Number.MAX_SAFE_INTEGER,
      payload: { prompt: "bounded" },
    };
    const requestDigest = await effectRequestDigest(request);
    const effectId = wide("e");
    const invocationId = wide("i");
    await f.execute({
      kind: "commit_engine_step", commandId: wide("b"), expectedEventSequence: state.eventSequence,
      turnId, fence: f.fence(state), transactionTime: 200, consumedSettlementEffectId: null,
      effectIdentity: { effectId, invocationId },
      step: { kind: "effect_request", checkpoint: await f.checkpoint(state), request: { ...request, requestDigest } },
    });
    state = await f.read();
    const effectFields = { turnId, effectId, invocationId, requestDigest, fence: f.fence(state) };
    const providerRequestId = wide("r");
    const providerRouteDigest = digest("4");

    // Each command consumes exactly the stated phase reservation. Measure the
    // persisted aggregate, including its receipt and public events, at both ends.
    async function release(command: SessionCommand, units: number) {
      const before = state;
      const response = await f.execute(command);
      state = await f.read();
      const byteGrowth = encodeCanonicalCbor(state).byteLength - encodeCanonicalCbor(before).byteLength;
      const itemGrowth = sessionPayloadItems(state as unknown as NormalizedValue) -
        sessionPayloadItems(before as unknown as NormalizedValue);
      expect(byteGrowth, `${command.kind} byte growth`).toBeLessThanOrEqual(units * SESSION_CAPACITY_RESERVE_UNIT_BYTES);
      expect(itemGrowth, `${command.kind} item growth`).toBeLessThanOrEqual(units * SESSION_CAPACITY_RESERVE_UNIT_ITEMS);
      return response;
    }

    const dispatched = await release({
      ...effectFields, kind: "dispatch_effect", commandId: wide("c"),
      expectedEventSequence: state.eventSequence, transactionTime: 200,
      deadline: 9_000, providerRequestId, providerRouteDigest,
    }, 1);
    if (dispatched.outcome.kind !== "effect_dispatched") throw new Error("dispatch permit required");
    const claimed = await release({
      ...effectFields, kind: "claim_dispatch_start", commandId: wide("d"),
      expectedEventSequence: state.eventSequence, workspaceId: state.workspaceId,
      transactionTime: 200, dispatchAttempt: 1, providerRequestId, providerRouteDigest,
      dispatchPermitClaims: dispatched.outcome.dispatchPermitClaims, commandDigest: digest("5"),
    }, 1);
    expect(claimed.outcome).toMatchObject({ kind: "dispatch_start_claimed", fresh: true });
    await release({
      ...effectFields, kind: "record_external_commit", commandId: wide("f"),
      expectedEventSequence: state.eventSequence, dispatchAttempt: 1,
      externalCommitId: wide("x"), resultRef: wide("z"),
    }, 1);
    await release({
      ...effectFields, kind: "settle_effect", commandId: wide("g"),
      expectedEventSequence: state.eventSequence, dispatchAttempt: 1,
      settlement: { kind: "error", code: wide("h"), message: wide("m"), retryable: false },
    }, 1);
    const message = "m".repeat(4096);
    await release({
      kind: "commit_engine_step", commandId: wide("j"), expectedEventSequence: state.eventSequence,
      turnId, fence: f.fence(state), transactionTime: 200,
      consumedSettlementEffectId: effectId, effectIdentity: null,
      step: {
        kind: "turn_error", checkpoint: await f.checkpoint(state),
        error: { code: wide("k"), message, retryable: false, details: LARGE_RESULT },
      },
    }, 2);
    expect(state.activeTurn).toBeNull();
    expect(state.terminalTurns[0]).toMatchObject({ status: "failed", error: { message } });
    expect(await f.payload(state.terminalTurns[0]!.error, "details", "detailsRef")).toBe(LARGE_RESULT);
  });
});
