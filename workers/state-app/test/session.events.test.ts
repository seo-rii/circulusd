import {
  digestBytes,
  type AgentCheckpoint,
  type Digest,
  type EngineAgentCheckpoint,
  type EffectService,
  type ReplayPolicy,
} from "@circulusd/protocol-types";
import { describe, expect, it } from "vitest";

import {
  applySessionCommand,
  checkpointDigest,
  createSessionState,
  effectRequestDigest,
  migrateSessionState,
  replaySessionPublicEvents,
  turnInputDigest,
  validateSessionState,
  type SessionAggregateState,
  type SessionFence,
} from "../src/session/index.ts";

const RUNTIME_DIGEST = `sha256:${"1".repeat(64)}` as Digest;
const POLICY_DIGEST = `sha256:${"2".repeat(64)}` as Digest;
const EMERGENCY_DIGEST = `sha256:${"3".repeat(64)}` as Digest;
const TRANSACTION_TIME = 1_700_000_000_000;

function newSession(): SessionAggregateState {
  return createSessionState({
    sessionId: "session-events",
    tenantId: "tenant-events",
    userId: "user-events",
    workspaceId: "workspace-events",
    runtimeRevisionDigest: RUNTIME_DIGEST,
    policySnapshotDigest: POLICY_DIGEST,
    emergencyOverlayDigest: EMERGENCY_DIGEST,
    engineKind: "low-level",
    adapterAbiVersion: 1,
    checkpointSchemaVersion: 1,
    placementGeneration: 4,
    sandboxGeneration: 5,
    authorizationGeneration: 6,
  });
}

function digest(character: string): Digest {
  return `sha256:${character.repeat(64)}` as Digest;
}

function fence(state: SessionAggregateState): SessionFence {
  if (state.activeTurn === null) {
    throw new Error("test requires an active turn");
  }
  return {
    turnLeaseGeneration: state.activeTurn.turnLeaseGeneration,
    placementGeneration: state.placementGeneration,
    sandboxGeneration: state.sandboxGeneration,
    authorizationGeneration: state.authorizationGeneration,
  };
}

async function genesis(
  state: SessionAggregateState,
  turnId: string,
): Promise<AgentCheckpoint> {
  const payloadBytes = new TextEncoder().encode(`genesis:${turnId}`);
  return {
    kind: "genesis",
    engineKind: state.engineKind,
    adapterAbiVersion: state.adapterAbiVersion,
    checkpointSchemaVersion: state.checkpointSchemaVersion,
    runtimeRevisionDigest: state.runtimeRevisionDigest,
    sessionId: state.sessionId,
    turnId,
    checkpointSequence: 0,
    predecessorDigest: null,
    payloadEncoding: "opaque-v1",
    payloadBytes,
    payloadDigest: await digestBytes(payloadBytes),
  };
}

async function nextCheckpoint(
  state: SessionAggregateState,
): Promise<EngineAgentCheckpoint> {
  if (state.activeTurn === null) {
    throw new Error("test requires an active turn");
  }
  const payloadBytes = new Uint8Array([
    state.activeTurn.checkpoint.checkpointSequence + 1,
  ]);
  return {
    kind: "engine",
    engineKind: state.engineKind,
    adapterAbiVersion: state.adapterAbiVersion,
    checkpointSchemaVersion: state.checkpointSchemaVersion,
    runtimeRevisionDigest: state.runtimeRevisionDigest,
    sessionId: state.sessionId,
    turnId: state.activeTurn.turnId,
    checkpointSequence: state.activeTurn.checkpoint.checkpointSequence + 1,
    predecessorDigest: await checkpointDigest(state.activeTurn.checkpoint),
    payloadEncoding: "opaque-v1",
    payloadBytes,
    payloadDigest: await digestBytes(payloadBytes),
  };
}

async function admit(
  state: SessionAggregateState,
  turnId: string,
  suffix: string,
  options: {
    readonly transactionTime?: number;
    readonly leaseExpiresAt?: number;
  } = {},
) {
  const input = { message: turnId };
  return applySessionCommand(state, {
    kind: "enqueue_turn",
    commandId: `admit-${suffix}`,
    expectedEventSequence: state.eventSequence,
    transactionTime: options.transactionTime ?? TRANSACTION_TIME,
    turnId,
    input,
    inputDigest: await turnInputDigest(input),
    genesisCheckpoint: await genesis(state, turnId),
    turnLeaseGeneration: state.nextTurnSequence + 10,
    leaseExpiresAt: options.leaseExpiresAt ?? TRANSACTION_TIME + 100_000,
    publicAdmission: {
      authorizationGeneration: state.authorizationGeneration,
      idempotencyKeyDigest: digest(suffix),
      requestDigest: digest("8"),
    },
  });
}

async function prepareEffect(
  state: SessionAggregateState,
  service: EffectService,
  replayPolicy: ReplayPolicy,
  suffix: string,
) {
  if (state.activeTurn === null) {
    throw new Error("test requires an active turn");
  }
  const request = {
    service,
    operation: service === "model" ? "complete" : "spawn",
    replayPolicy,
    payload: { request: suffix },
  };
  return applySessionCommand(state, {
    kind: "commit_engine_step",
    commandId: `prepare-${suffix}`,
    expectedEventSequence: state.eventSequence,
    turnId: state.activeTurn.turnId,
    fence: fence(state),
    transactionTime: TRANSACTION_TIME,
    consumedSettlementEffectId: state.activeTurn.activeEffectId,
    effectIdentity: {
      effectId: `effect-${suffix}`,
      invocationId: `invocation-${suffix}`,
    },
    step: {
      kind: "effect_request",
      checkpoint: await nextCheckpoint(state),
      request: {
        ...request,
        requestDigest: await effectRequestDigest(request),
      },
    },
  });
}

function activeEffect(state: SessionAggregateState) {
  const effect = state.effects.find(
    (candidate) => candidate.effectId === state.activeTurn?.activeEffectId,
  );
  if (effect === undefined) {
    throw new Error("test requires an active effect");
  }
  return effect;
}

async function dispatchEffect(state: SessionAggregateState, suffix: string) {
  if (state.activeTurn === null) {
    throw new Error("test requires an active turn");
  }
  const effect = activeEffect(state);
  return applySessionCommand(state, {
    kind: "dispatch_effect",
    commandId: `dispatch-${suffix}`,
    expectedEventSequence: state.eventSequence,
    turnId: state.activeTurn.turnId,
    effectId: effect.effectId,
    invocationId: effect.invocationId,
    requestDigest: effect.requestDigest,
    fence: fence(state),
    transactionTime: TRANSACTION_TIME,
    deadline: TRANSACTION_TIME + 50_000,
  });
}

describe("Session public durable event journal", () => {
  it("does not expose orphan events for a turn admitted without publicAdmission", async () => {
    const initial = newSession();
    const input = { message: "internal turn" };
    const admitted = await applySessionCommand(initial, {
      kind: "enqueue_turn",
      commandId: "admit-internal",
      expectedEventSequence: 0,
      transactionTime: TRANSACTION_TIME,
      turnId: "turn-internal",
      input,
      inputDigest: await turnInputDigest(input),
      genesisCheckpoint: await genesis(initial, "turn-internal"),
      turnLeaseGeneration: 10,
      leaseExpiresAt: TRANSACTION_TIME + 100_000,
    });
    const prepared = await prepareEffect(
      admitted.state,
      "model",
      "idempotency-key",
      "internal",
    );
    const dispatched = await dispatchEffect(prepared.state, "internal");
    const effect = activeEffect(dispatched.state);
    const settled = await applySessionCommand(dispatched.state, {
      kind: "settle_effect",
      commandId: "settle-internal",
      expectedEventSequence: dispatched.state.eventSequence,
      turnId: "turn-internal",
      effectId: effect.effectId,
      invocationId: effect.invocationId,
      requestDigest: effect.requestDigest,
      dispatchAttempt: effect.dispatchAttempt,
      fence: fence(dispatched.state),
      settlement: { kind: "success", result: { responseRef: "internal-result" } },
    });
    const completed = await applySessionCommand(settled.state, {
      kind: "commit_engine_step",
      commandId: "complete-internal",
      expectedEventSequence: settled.state.eventSequence,
      turnId: "turn-internal",
      fence: fence(settled.state),
      transactionTime: TRANSACTION_TIME,
      consumedSettlementEffectId: effect.effectId,
      effectIdentity: null,
      step: {
        kind: "turn_complete",
        checkpoint: await nextCheckpoint(settled.state),
        result: null,
      },
    });

    expect(completed.state.publicEventSequence).toBe(0);
    expect(completed.state.publicEvents).toEqual([]);
    expect(completed.state.turnAdmissionReceipts).toEqual([]);
    expect(replaySessionPublicEvents(completed.state, 0, 16)).toMatchObject({
      snapshot: { lastEventSequence: 0 },
      events: [],
    });
  });

  it("journals the model/tool lifecycle atomically in transition order and replays pages", async () => {
    const admitted = await admit(newSession(), "turn-lifecycle", "a");
    const modelPrepared = await prepareEffect(
      admitted.state,
      "model",
      "idempotency-key",
      "model",
    );
    const modelDispatched = await dispatchEffect(modelPrepared.state, "model");
    const modelEffect = activeEffect(modelDispatched.state);
    const modelSettlementCommand = {
      kind: "settle_effect" as const,
      commandId: "settle-model",
      expectedEventSequence: modelDispatched.state.eventSequence,
      turnId: "turn-lifecycle",
      effectId: modelEffect.effectId,
      invocationId: modelEffect.invocationId,
      requestDigest: modelEffect.requestDigest,
      dispatchAttempt: modelEffect.dispatchAttempt,
      fence: fence(modelDispatched.state),
      settlement: { kind: "success" as const, result: { responseRef: "model-result" } },
    };
    const modelSettled = await applySessionCommand(
      modelDispatched.state,
      modelSettlementCommand,
    );
    const toolPrepared = await prepareEffect(
      modelSettled.state,
      "executor",
      "idempotency-key",
      "tool",
    );
    const toolDispatched = await dispatchEffect(toolPrepared.state, "tool");
    const toolEffect = activeEffect(toolDispatched.state);
    const externallyCommitted = await applySessionCommand(toolDispatched.state, {
      kind: "record_external_commit",
      commandId: "commit-tool-externally",
      expectedEventSequence: toolDispatched.state.eventSequence,
      turnId: "turn-lifecycle",
      effectId: toolEffect.effectId,
      invocationId: toolEffect.invocationId,
      requestDigest: toolEffect.requestDigest,
      dispatchAttempt: toolEffect.dispatchAttempt,
      fence: fence(toolDispatched.state),
      externalCommitId: "external-tool",
      resultRef: "tool-result",
    });
    const toolSettled = await applySessionCommand(externallyCommitted.state, {
      kind: "settle_effect",
      commandId: "settle-tool",
      expectedEventSequence: externallyCommitted.state.eventSequence,
      turnId: "turn-lifecycle",
      effectId: toolEffect.effectId,
      invocationId: toolEffect.invocationId,
      requestDigest: toolEffect.requestDigest,
      dispatchAttempt: toolEffect.dispatchAttempt,
      fence: fence(externallyCommitted.state),
      settlement: { kind: "success", result: { outputRef: "tool-output" } },
    });
    const completed = await applySessionCommand(toolSettled.state, {
      kind: "commit_engine_step",
      commandId: "complete-turn",
      expectedEventSequence: toolSettled.state.eventSequence,
      turnId: "turn-lifecycle",
      fence: fence(toolSettled.state),
      transactionTime: TRANSACTION_TIME,
      consumedSettlementEffectId: toolEffect.effectId,
      effectIdentity: null,
      step: {
        kind: "turn_complete",
        checkpoint: await nextCheckpoint(toolSettled.state),
        result: { messageRef: "assistant-message" },
      },
    });

    expect(completed.state.publicEvents.map(({ sequence, type }) => ({ sequence, type })))
      .toEqual([
        { sequence: 1, type: "turn.accepted" },
        { sequence: 2, type: "model.effect.prepared" },
        { sequence: 3, type: "model.settled" },
        { sequence: 4, type: "tool.effect.prepared" },
        { sequence: 5, type: "tool.externally_committed" },
        { sequence: 6, type: "tool.settled" },
        { sequence: 7, type: "turn.completed" },
      ]);
    expect(completed.state.publicEvents.slice(1, 6)).toEqual([
      expect.objectContaining({
        type: "model.effect.prepared",
        effectId: "effect-model",
        invocationId: "invocation-model",
        service: "model",
      }),
      expect.objectContaining({
        type: "model.settled",
        effectId: "effect-model",
        settlementKind: "success",
      }),
      expect.objectContaining({
        type: "tool.effect.prepared",
        effectId: "effect-tool",
        service: "executor",
      }),
      expect.objectContaining({
        type: "tool.externally_committed",
        effectId: "effect-tool",
        externalCommitId: "external-tool",
        resultRef: "tool-result",
      }),
      expect.objectContaining({
        type: "tool.settled",
        effectId: "effect-tool",
        settlementKind: "success",
      }),
    ]);
    expect(replaySessionPublicEvents(completed.state, 1, 3)).toMatchObject({
      snapshot: { lastEventSequence: 7, activeTurnId: null },
      events: [
        { sequence: 2, type: "model.effect.prepared" },
        { sequence: 3, type: "model.settled" },
        { sequence: 4, type: "tool.effect.prepared" },
      ],
    });

    const replayedSettlement = await applySessionCommand(
      completed.state,
      modelSettlementCommand,
    );
    expect(replayedSettlement.replayed).toBe(true);
    expect(replayedSettlement.state.publicEventSequence).toBe(7);
    expect(replayedSettlement.state.publicEvents).toEqual(completed.state.publicEvents);
  });

  it("journals confirmation, failure, and abort terminal transitions once", async () => {
    const admitted = await admit(newSession(), "turn-confirm", "b");
    const prepared = await prepareEffect(admitted.state, "mcp", "confirm", "confirm");
    const dispatched = await dispatchEffect(prepared.state, "confirm");
    const effect = activeEffect(dispatched.state);
    const recoveryCommand = {
      kind: "recover_effect" as const,
      commandId: "recover-confirm",
      expectedEventSequence: dispatched.state.eventSequence,
      turnId: "turn-confirm",
      effectId: effect.effectId,
      invocationId: effect.invocationId,
      requestDigest: effect.requestDigest,
      fence: fence(dispatched.state),
      transactionTime: TRANSACTION_TIME + 1,
      deadline: TRANSACTION_TIME + 50_001,
    };
    const blocked = await applySessionCommand(dispatched.state, recoveryCommand);
    const replayedBlocked = await applySessionCommand(blocked.state, recoveryCommand);
    expect(replayedBlocked.replayed).toBe(true);
    expect(replayedBlocked.state.publicEventSequence).toBe(3);
    expect(blocked.state.publicEvents.at(-1)).toEqual(expect.objectContaining({
      sequence: 3,
      type: "turn.needs_confirmation",
      turnId: "turn-confirm",
      effectId: "effect-confirm",
    }));

    const abandoned = await applySessionCommand(blocked.state, {
      kind: "resolve_confirmation",
      commandId: "abandon-confirm",
      expectedEventSequence: blocked.state.eventSequence,
      turnId: "turn-confirm",
      effectId: effect.effectId,
      invocationId: effect.invocationId,
      requestDigest: effect.requestDigest,
      fence: fence(blocked.state),
      decision: "abandon",
      transactionTime: null,
      deadline: null,
    });
    expect(abandoned.state.publicEvents.at(-1)).toEqual(expect.objectContaining({
      sequence: 4,
      type: "tool.settled",
      settlementKind: "abandoned",
    }));
    const abortRequested = await applySessionCommand(abandoned.state, {
      kind: "request_abort",
      commandId: "request-abort-confirm",
      expectedEventSequence: abandoned.state.eventSequence,
      turnId: "turn-confirm",
      fence: fence(abandoned.state),
      transactionTime: TRANSACTION_TIME + 2,
      reason: "user requested abort",
    });
    const aborted = await applySessionCommand(abortRequested.state, {
      kind: "finalize_abort",
      commandId: "finalize-abort-confirm",
      expectedEventSequence: abortRequested.state.eventSequence,
      turnId: "turn-confirm",
      fence: fence(abortRequested.state),
      transactionTime: TRANSACTION_TIME + 3,
    });
    expect(aborted.state.publicEvents.at(-1)).toEqual(expect.objectContaining({
      sequence: 5,
      type: "turn.aborted",
      turnId: "turn-confirm",
    }));

    const failedAdmission = await admit(newSession(), "turn-failed", "c");
    const failed = await applySessionCommand(failedAdmission.state, {
      kind: "commit_engine_step",
      commandId: "fail-turn",
      expectedEventSequence: failedAdmission.state.eventSequence,
      turnId: "turn-failed",
      fence: fence(failedAdmission.state),
      transactionTime: TRANSACTION_TIME,
      consumedSettlementEffectId: null,
      effectIdentity: null,
      step: {
        kind: "turn_error",
        checkpoint: await nextCheckpoint(failedAdmission.state),
        error: { code: "MODEL_FAILED", message: "model failed", retryable: false },
      },
    });
    expect(failed.state.publicEvents.at(-1)).toEqual(expect.objectContaining({
      sequence: 2,
      type: "turn.failed",
      turnId: "turn-failed",
    }));
  });

  it("journals every terminal transition when one commit skips expired queued turns", async () => {
    const first = await admit(newSession(), "turn-first", "d", {
      leaseExpiresAt: TRANSACTION_TIME + 100_000,
    });
    const expired = await admit(first.state, "turn-expired", "e", {
      leaseExpiresAt: TRANSACTION_TIME + 5,
    });
    const live = await admit(expired.state, "turn-live", "f", {
      leaseExpiresAt: TRANSACTION_TIME + 100_000,
    });
    const completed = await applySessionCommand(live.state, {
      kind: "commit_engine_step",
      commandId: "complete-and-skip-expired",
      expectedEventSequence: live.state.eventSequence,
      turnId: "turn-first",
      fence: fence(live.state),
      transactionTime: TRANSACTION_TIME + 10,
      consumedSettlementEffectId: null,
      effectIdentity: null,
      step: {
        kind: "turn_complete",
        checkpoint: await nextCheckpoint(live.state),
        result: null,
      },
    });

    expect(completed.state.activeTurn?.turnId).toBe("turn-live");
    expect(completed.state.publicEvents.map(({ sequence, type, turnId }) => ({
      sequence,
      type,
      turnId,
    }))).toEqual([
      { sequence: 1, type: "turn.accepted", turnId: "turn-first" },
      { sequence: 2, type: "turn.accepted", turnId: "turn-expired" },
      { sequence: 3, type: "turn.accepted", turnId: "turn-live" },
      { sequence: 4, type: "turn.completed", turnId: "turn-first" },
      { sequence: 5, type: "turn.aborted", turnId: "turn-expired" },
    ]);
  });

  it("migrates schema-v1 and schema-v2 states without losing prior admission events", async () => {
    const admitted = await admit(newSession(), "turn-migrated", "9");
    const schemaV2 = structuredClone(admitted.state) as unknown as Record<string, unknown>;
    schemaV2.schemaVersion = 2;
    const migratedV2 = migrateSessionState(schemaV2);
    expect(migratedV2).toMatchObject({ migrated: true, state: { schemaVersion: 3 } });
    expect(migratedV2.state.publicEvents).toEqual(admitted.state.publicEvents);
    expect(migratedV2.state.turnAdmissionReceipts).toEqual(
      admitted.state.turnAdmissionReceipts,
    );
    await expect(validateSessionState(migratedV2.state)).resolves.toBeUndefined();
    const continuedV2 = await prepareEffect(
      migratedV2.state,
      "model",
      "idempotency-key",
      "migrated-v2",
    );
    expect(continuedV2.state.publicEvents.map((event) => event.type)).toEqual([
      "turn.accepted",
      "model.effect.prepared",
    ]);

    const schemaV1 = structuredClone(admitted.state) as unknown as Record<string, unknown>;
    schemaV1.schemaVersion = 1;
    delete schemaV1.publicEventSequence;
    delete schemaV1.publicEvents;
    delete schemaV1.turnAdmissionReceipts;
    const migratedV1 = migrateSessionState(schemaV1);
    expect(migratedV1).toMatchObject({
      migrated: true,
      state: {
        schemaVersion: 3,
        publicEventSequence: 0,
        publicEvents: [],
        turnAdmissionReceipts: [],
      },
    });
    await expect(validateSessionState(migratedV1.state)).resolves.toBeUndefined();
    const continuedV1 = await prepareEffect(
      migratedV1.state,
      "model",
      "idempotency-key",
      "migrated-v1",
    );
    expect(continuedV1.state.publicEvents).toEqual([]);
  });

  it("rejects gaps, unknown fields, and model/tool family mismatches in stored events", async () => {
    const admitted = await admit(newSession(), "turn-validation", "7");
    const prepared = await prepareEffect(
      admitted.state,
      "model",
      "idempotency-key",
      "validation",
    );
    const corruptions = [
      (state: SessionAggregateState) => {
        const event = state.publicEvents[1];
        if (event !== undefined) {
          event.sequence = 3;
        }
      },
      (state: SessionAggregateState) => {
        const event = state.publicEvents[1] as unknown as Record<string, unknown>;
        event.unrecognized = true;
      },
      (state: SessionAggregateState) => {
        const event = state.publicEvents[1] as unknown as Record<string, unknown>;
        event.type = "tool.effect.prepared";
      },
      (state: SessionAggregateState) => {
        state.publicEvents.shift();
        state.publicEventSequence = 1;
        state.turnAdmissionReceipts = [];
        const event = state.publicEvents[0];
        if (event !== undefined) {
          event.sequence = 1;
        }
      },
    ];

    for (const corrupt of corruptions) {
      const corrupted = structuredClone(prepared.state);
      corrupt(corrupted);
      await expect(validateSessionState(corrupted)).rejects.toMatchObject({
        code: "FAILED_PRECONDITION",
      });
    }
  });
});
