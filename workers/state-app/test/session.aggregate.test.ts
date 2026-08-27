import {
  digestBytes,
  digestStructuredValue,
  parseDispatchPermitClaims,
  type AgentCheckpoint,
  type Digest,
  type EngineAgentCheckpoint,
  type ReplayPolicy,
} from "@circulusd/protocol-types";
import { describe, expect, it } from "vitest";

import {
  SessionAggregateError,
  applySessionCommand,
  assertSessionInvariants,
  checkpointDigest,
  createSessionState,
  effectRequestDigest,
  turnInputDigest,
  validateSessionState,
  type EffectSettlement,
  type SessionEffect,
  type SessionAggregateState,
  type SessionCommand,
  type SessionFence,
} from "../src/session/index.ts";

const RUNTIME_DIGEST = `sha256:${"1".repeat(64)}` as Digest;
const INPUT_DIGEST = `sha256:${"2".repeat(64)}` as Digest;
const POLICY_DIGEST = `sha256:${"4".repeat(64)}` as Digest;
const EMERGENCY_DIGEST = `sha256:${"5".repeat(64)}` as Digest;
const ROTATED_EMERGENCY_DIGEST = `sha256:${"6".repeat(64)}` as Digest;
const TRANSACTION_TIME = 1_700_000_000_000;

function newSession(): SessionAggregateState {
  return createSessionState({
    sessionId: "sess_01",
    tenantId: "tenant_01",
    userId: "user_01",
    workspaceId: "workspace_01",
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

function currentFence(state: SessionAggregateState): SessionFence {
  const activeTurn = state.activeTurn;
  if (activeTurn === null) {
    throw new Error("test requires an active turn");
  }
  return {
    turnLeaseGeneration: activeTurn.turnLeaseGeneration,
    placementGeneration: state.placementGeneration,
    sandboxGeneration: state.sandboxGeneration,
    authorizationGeneration: state.authorizationGeneration,
  };
}

async function genesisCheckpoint(
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
  overrides: Partial<EngineAgentCheckpoint> = {},
): Promise<EngineAgentCheckpoint> {
  const activeTurn = state.activeTurn;
  if (activeTurn === null) {
    throw new Error("test requires an active turn");
  }
  const payloadBytes = new Uint8Array([activeTurn.checkpoint.checkpointSequence + 1]);
  return {
    kind: "engine",
    engineKind: state.engineKind,
    adapterAbiVersion: state.adapterAbiVersion,
    checkpointSchemaVersion: state.checkpointSchemaVersion,
    runtimeRevisionDigest: state.runtimeRevisionDigest,
    sessionId: state.sessionId,
    turnId: activeTurn.turnId,
    checkpointSequence: activeTurn.checkpoint.checkpointSequence + 1,
    predecessorDigest: await checkpointDigest(activeTurn.checkpoint),
    payloadEncoding: "opaque-v1",
    payloadBytes,
    payloadDigest: await digestBytes(payloadBytes),
    ...overrides,
  };
}

async function enqueueTurn(
  state: SessionAggregateState,
  turnId: string,
  commandId: string,
) {
  const input = { message: turnId };
  return applySessionCommand(state, {
    kind: "enqueue_turn",
    commandId,
    expectedEventSequence: state.eventSequence,
    transactionTime: TRANSACTION_TIME,
    turnId,
    input,
    inputDigest: await turnInputDigest(input),
    genesisCheckpoint: await genesisCheckpoint(state, turnId),
    turnLeaseGeneration: state.nextTurnSequence + 10,
    leaseExpiresAt: 1_900_000_000_000,
  });
}

async function expiredAdmittedState(): Promise<SessionAggregateState> {
  const admitted = await enqueueTurn(newSession(), "turn_expired", "enqueue_expired_owner");
  const expired = structuredClone(admitted.state);
  if (expired.activeTurn === null) {
    throw new Error("test requires an active turn");
  }
  expired.activeTurn.leaseExpiresAt = TRANSACTION_TIME;
  return expired;
}

async function prepareEffect(
  state: SessionAggregateState,
  replayPolicy: ReplayPolicy,
  suffix: string,
) {
  const activeTurn = state.activeTurn;
  if (activeTurn === null) {
    throw new Error("test requires an active turn");
  }
  const request = {
    service: "executor" as const,
    operation: "spawn",
    replayPolicy,
    payload: { argv: ["tool", suffix] },
  };
  return applySessionCommand(state, {
    kind: "commit_engine_step",
    commandId: `prepare_${suffix}`,
    expectedEventSequence: state.eventSequence,
    turnId: activeTurn.turnId,
    fence: currentFence(state),
    transactionTime: TRANSACTION_TIME,
    consumedSettlementEffectId: null,
    effectIdentity: {
      effectId: `effect_${suffix}`,
      invocationId: `invocation_${suffix}`,
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

function activeEffect(state: SessionAggregateState): SessionEffect {
  const activeEffectId = state.activeTurn?.activeEffectId;
  const effect = state.effects.find((candidate) => candidate.effectId === activeEffectId);
  if (effect === undefined) {
    throw new Error("test requires an active effect");
  }
  return effect;
}

async function dispatchActiveEffect(
  state: SessionAggregateState,
  commandId: string,
) {
  const activeTurn = state.activeTurn;
  if (activeTurn === null || activeTurn.activeEffectId === null) {
    throw new Error("test requires an active effect");
  }
  const effect = activeEffect(state);
  return applySessionCommand(state, {
    kind: "dispatch_effect",
    commandId,
    expectedEventSequence: state.eventSequence,
    turnId: activeTurn.turnId,
    effectId: effect.effectId,
    invocationId: effect.invocationId,
    requestDigest: effect.requestDigest,
    fence: currentFence(state),
    transactionTime: TRANSACTION_TIME,
    deadline: 1_800_000_000_000,
  });
}

describe("Session authoritative aggregate", () => {
  it("rejects unknown initialization fields at the aggregate boundary", () => {
    expect(() => createSessionState({
      sessionId: "sess_01",
      tenantId: "tenant_01",
      userId: "user_01",
      workspaceId: "workspace_01",
      runtimeRevisionDigest: RUNTIME_DIGEST,
      policySnapshotDigest: POLICY_DIGEST,
      emergencyOverlayDigest: EMERGENCY_DIGEST,
      engineKind: "low-level",
      adapterAbiVersion: 1,
      checkpointSchemaVersion: 1,
      placementGeneration: 4,
      sandboxGeneration: 5,
      authorizationGeneration: 6,
      unknownField: "must-not-be-ignored",
    } as never)).toThrowError(expect.objectContaining({ code: "INVALID_ARGUMENT" }));
  });

  it("requires trusted admission time, a live lease, and a positive lease generation", async () => {
    const initial = newSession();
    const input = { message: "turn_01" };
    const common = {
      kind: "enqueue_turn" as const,
      expectedEventSequence: initial.eventSequence,
      turnId: "turn_01",
      input,
      inputDigest: await turnInputDigest(input),
      genesisCheckpoint: await genesisCheckpoint(initial, "turn_01"),
    };

    await expect(
      applySessionCommand(initial, {
        ...common,
        commandId: "enqueue_without_time",
        turnLeaseGeneration: 1,
        leaseExpiresAt: TRANSACTION_TIME + 1,
      } as SessionCommand),
    ).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });

    await expect(
      applySessionCommand(initial, {
        ...common,
        commandId: "enqueue_expired_lease",
        transactionTime: TRANSACTION_TIME,
        turnLeaseGeneration: 1,
        leaseExpiresAt: TRANSACTION_TIME,
      }),
    ).rejects.toMatchObject({ code: "FAILED_PRECONDITION" });

    await expect(
      applySessionCommand(initial, {
        ...common,
        commandId: "enqueue_zero_generation",
        transactionTime: TRANSACTION_TIME,
        turnLeaseGeneration: 0,
        leaseExpiresAt: TRANSACTION_TIME + 1,
      }),
    ).rejects.toMatchObject({
      code: "INVALID_ARGUMENT",
      message: expect.stringMatching(/turnLeaseGeneration/),
    });
  });

  it("rejects a checkpoint commit from an expired turn owner", async () => {
    const expired = await expiredAdmittedState();
    await expect(
      applySessionCommand(expired, {
        kind: "commit_engine_step",
        commandId: "expired_checkpoint",
        expectedEventSequence: expired.eventSequence,
        turnId: "turn_expired",
        fence: currentFence(expired),
        transactionTime: TRANSACTION_TIME,
        consumedSettlementEffectId: null,
        effectIdentity: null,
        step: { kind: "checkpoint", checkpoint: await nextCheckpoint(expired) },
      }),
    ).rejects.toMatchObject({ code: "FAILED_PRECONDITION" });
  });

  it("rejects an effect request commit from an expired turn owner", async () => {
    const expired = await expiredAdmittedState();
    const request = {
      service: "executor" as const,
      operation: "spawn",
      replayPolicy: "safe" as const,
      payload: { argv: ["tool"] },
    };
    await expect(
      applySessionCommand(expired, {
        kind: "commit_engine_step",
        commandId: "expired_effect_request",
        expectedEventSequence: expired.eventSequence,
        turnId: "turn_expired",
        fence: currentFence(expired),
        transactionTime: TRANSACTION_TIME,
        consumedSettlementEffectId: null,
        effectIdentity: { effectId: "effect_expired", invocationId: "invocation_expired" },
        step: {
          kind: "effect_request",
          checkpoint: await nextCheckpoint(expired),
          request: { ...request, requestDigest: await effectRequestDigest(request) },
        },
      }),
    ).rejects.toMatchObject({ code: "FAILED_PRECONDITION" });
  });

  it("rejects a terminal commit from an expired turn owner", async () => {
    const expired = await expiredAdmittedState();
    await expect(
      applySessionCommand(expired, {
        kind: "commit_engine_step",
        commandId: "expired_terminal",
        expectedEventSequence: expired.eventSequence,
        turnId: "turn_expired",
        fence: currentFence(expired),
        transactionTime: TRANSACTION_TIME,
        consumedSettlementEffectId: null,
        effectIdentity: null,
        step: {
          kind: "turn_complete",
          checkpoint: await nextCheckpoint(expired),
          result: { messageRef: "must_not_commit" },
        },
      }),
    ).rejects.toMatchObject({ code: "FAILED_PRECONDITION" });
  });

  it("admits turns in strict FIFO order and promotes exactly one active turn", async () => {
    const initial = newSession();
    expect(initial).toMatchObject({
      policySnapshotDigest: POLICY_DIGEST,
      emergencyOverlayDigest: EMERGENCY_DIGEST,
    });
    const first = await enqueueTurn(initial, "turn_01", "enqueue_01");
    const second = await enqueueTurn(first.state, "turn_02", "enqueue_02");

    expect(initial.eventSequence).toBe(0);
    expect(first.state.activeTurn?.turnId).toBe("turn_01");
    expect(first.state.activeTurn?.status).toBe("active");
    expect(second.state.activeTurn?.turnId).toBe("turn_01");
    expect(second.state.queuedTurns.map((turn) => turn.turnId)).toEqual(["turn_02"]);
    expect(second.state.queuedTurns[0]?.status).toBe("queued");
    expect(second.state.queuedTurns[0]?.sequence).toBe(1);

    const finalCheckpoint = await nextCheckpoint(second.state);
    const complete = await applySessionCommand(second.state, {
      kind: "commit_engine_step",
      commandId: "complete_01",
      expectedEventSequence: second.state.eventSequence,
      turnId: "turn_01",
      fence: currentFence(second.state),
      transactionTime: TRANSACTION_TIME,
      consumedSettlementEffectId: null,
      effectIdentity: null,
      step: {
        kind: "turn_complete",
        checkpoint: finalCheckpoint,
        result: { messageRef: "message_01" },
      },
    });

    expect(complete.state.latestSettledTurn).toBe("turn_01");
    expect(complete.state.activeTurn?.turnId).toBe("turn_02");
    expect(complete.state.queuedTurns).toEqual([]);
    expect(complete.state.terminalTurns).toEqual([
      {
        turnId: "turn_01",
        sequence: 0,
        input: { message: "turn_01" },
        inputDigest: await turnInputDigest({ message: "turn_01" }),
        finalCheckpoint,
        turnLeaseGeneration: 10,
        leaseExpiresAt: 1_900_000_000_000,
        status: "completed",
        abortRequested: false,
        abortReason: null,
        result: { messageRef: "message_01" },
        error: null,
      },
    ]);
    expect(complete.state.eventSequence).toBe(3);
    expect(() => assertSessionInvariants(complete.state)).not.toThrow();
  });

  it("uses optimistic sequence checks after deterministic command replay", async () => {
    const initial = newSession();
    const command = {
      kind: "enqueue_turn" as const,
      commandId: "enqueue_idempotent",
      expectedEventSequence: 0,
      transactionTime: TRANSACTION_TIME,
      turnId: "turn_01",
      input: { message: "turn_01" },
      inputDigest: await turnInputDigest({ message: "turn_01" }),
      genesisCheckpoint: await genesisCheckpoint(initial, "turn_01"),
      turnLeaseGeneration: 10,
      leaseExpiresAt: 1_900_000_000_000,
    };
    const applied = await applySessionCommand(initial, command);
    const replayed = await applySessionCommand(applied.state, command);

    expect(replayed.replayed).toBe(true);
    expect(replayed.commandDigest).toBe(applied.commandDigest);
    expect(replayed.outcome).toEqual(applied.outcome);
    expect(replayed.state).toBe(applied.state);
    expect(replayed.state.eventSequence).toBe(1);

    await expect(
      applySessionCommand(applied.state, { ...command, turnId: "turn_other" }),
    ).rejects.toMatchObject({ code: "IDEMPOTENCY_CONFLICT" });
    const commandWithUnknownField = {
      ...command,
      commandId: "enqueue_unknown_field",
      surprise: true,
    };
    await expect(
      applySessionCommand(initial, commandWithUnknownField),
    ).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });
    await expect(
      enqueueTurn(applied.state, "turn_02", "enqueue_stale").then(({ state }) =>
        applySessionCommand(state, {
          ...command,
          commandId: "enqueue_stale_second",
          turnId: "turn_03",
          expectedEventSequence: 0,
        }),
      ),
    ).rejects.toMatchObject({ code: "CONFLICT" });
  });

  it("does not replay dispatch capabilities after their generations become stale", async () => {
    const firstAdmitted = await enqueueTurn(newSession(), "turn_01", "enqueue_01");
    const firstPrepared = await prepareEffect(firstAdmitted.state, "safe", "01");
    const firstEffect = activeEffect(firstPrepared.state);
    const dispatchCommand = {
      kind: "dispatch_effect" as const,
      commandId: "dispatch_capability",
      expectedEventSequence: firstPrepared.state.eventSequence,
      turnId: "turn_01",
      effectId: firstEffect.effectId,
      invocationId: firstEffect.invocationId,
      requestDigest: firstEffect.requestDigest,
      fence: currentFence(firstPrepared.state),
      transactionTime: TRANSACTION_TIME,
      deadline: 1_800_000_000_000,
    };
    const dispatched = await applySessionCommand(firstPrepared.state, dispatchCommand);
    const immediateReplay = await applySessionCommand(dispatched.state, dispatchCommand);
    expect(immediateReplay.replayed).toBe(true);
    const dispatchRotated = await applySessionCommand(dispatched.state, {
      kind: "rotate_generations",
      commandId: "rotate_after_dispatch",
      expectedEventSequence: dispatched.state.eventSequence,
      nextPlacementGeneration: dispatched.state.placementGeneration + 1,
      nextSandboxGeneration: dispatched.state.sandboxGeneration + 1,
      nextAuthorizationGeneration: dispatched.state.authorizationGeneration + 1,
      nextEmergencyOverlayDigest: ROTATED_EMERGENCY_DIGEST,
    });

    const secondAdmitted = await enqueueTurn(newSession(), "turn_02", "enqueue_02");
    const secondPrepared = await prepareEffect(secondAdmitted.state, "safe", "02");
    const secondDispatched = await dispatchActiveEffect(
      secondPrepared.state,
      "dispatch_for_retry",
    );
    const secondEffect = activeEffect(secondDispatched.state);
    const recoverCommand = {
      kind: "recover_effect" as const,
      commandId: "recover_capability",
      expectedEventSequence: secondDispatched.state.eventSequence,
      turnId: "turn_02",
      effectId: secondEffect.effectId,
      invocationId: secondEffect.invocationId,
      requestDigest: secondEffect.requestDigest,
      fence: currentFence(secondDispatched.state),
      transactionTime: TRANSACTION_TIME + 1,
      deadline: 1_800_000_000_001,
    };
    const recovered = await applySessionCommand(secondDispatched.state, recoverCommand);
    const recoveryRotated = await applySessionCommand(recovered.state, {
      kind: "rotate_generations",
      commandId: "rotate_after_recovery",
      expectedEventSequence: recovered.state.eventSequence,
      nextPlacementGeneration: recovered.state.placementGeneration + 1,
      nextSandboxGeneration: recovered.state.sandboxGeneration + 1,
      nextAuthorizationGeneration: recovered.state.authorizationGeneration + 1,
      nextEmergencyOverlayDigest: ROTATED_EMERGENCY_DIGEST,
    });

    const replayAttempts = await Promise.allSettled([
      applySessionCommand(dispatchRotated.state, dispatchCommand),
      applySessionCommand(recoveryRotated.state, recoverCommand),
    ]);
    for (const replay of replayAttempts) {
      expect(replay.status).toBe("rejected");
      if (replay.status === "rejected") {
        expect(replay.reason).toMatchObject({ code: "STALE_GENERATION" });
      }
    }
  });

  it("still replays non-capability terminal and settlement responses after rotation", async () => {
    const admitted = await enqueueTurn(newSession(), "turn_01", "enqueue_01");
    const terminalCommand = {
      kind: "commit_engine_step" as const,
      commandId: "complete_for_replay",
      expectedEventSequence: admitted.state.eventSequence,
      turnId: "turn_01",
      fence: currentFence(admitted.state),
      transactionTime: TRANSACTION_TIME,
      consumedSettlementEffectId: null,
      effectIdentity: null,
      step: {
        kind: "turn_complete" as const,
        checkpoint: await nextCheckpoint(admitted.state),
        result: { messageRef: "message_01" },
      },
    };
    const completed = await applySessionCommand(admitted.state, terminalCommand);
    const terminalRotated = await applySessionCommand(completed.state, {
      kind: "rotate_generations",
      commandId: "rotate_after_terminal",
      expectedEventSequence: completed.state.eventSequence,
      nextPlacementGeneration: completed.state.placementGeneration + 1,
      nextSandboxGeneration: completed.state.sandboxGeneration + 1,
      nextAuthorizationGeneration: completed.state.authorizationGeneration + 1,
      nextEmergencyOverlayDigest: ROTATED_EMERGENCY_DIGEST,
    });
    const terminalReplay = await applySessionCommand(terminalRotated.state, terminalCommand);
    expect(terminalReplay).toMatchObject({ replayed: true, outcome: completed.outcome });

    const effectAdmitted = await enqueueTurn(newSession(), "turn_02", "enqueue_02");
    const prepared = await prepareEffect(effectAdmitted.state, "safe", "02");
    const dispatched = await dispatchActiveEffect(prepared.state, "dispatch_02");
    const effect = activeEffect(dispatched.state);
    const settlementCommand = {
      kind: "settle_effect" as const,
      commandId: "settle_for_replay",
      expectedEventSequence: dispatched.state.eventSequence,
      turnId: "turn_02",
      effectId: effect.effectId,
      invocationId: effect.invocationId,
      requestDigest: effect.requestDigest,
      dispatchAttempt: effect.dispatchAttempt,
      fence: currentFence(dispatched.state),
      settlement: { kind: "success" as const, result: { outputRef: "blob_02" } },
    };
    const settled = await applySessionCommand(dispatched.state, settlementCommand);
    const settlementRotated = await applySessionCommand(settled.state, {
      kind: "rotate_generations",
      commandId: "rotate_after_settlement",
      expectedEventSequence: settled.state.eventSequence,
      nextPlacementGeneration: settled.state.placementGeneration + 1,
      nextSandboxGeneration: settled.state.sandboxGeneration + 1,
      nextAuthorizationGeneration: settled.state.authorizationGeneration + 1,
      nextEmergencyOverlayDigest: ROTATED_EMERGENCY_DIGEST,
    });
    const settlementReplay = await applySessionCommand(
      settlementRotated.state,
      settlementCommand,
    );
    expect(settlementReplay).toMatchObject({ replayed: true, outcome: settled.outcome });
  });

  it("rejects duplicate turn identities without mutating caller state", async () => {
    const first = await enqueueTurn(newSession(), "turn_01", "enqueue_01");
    const before = structuredClone(first.state);
    await expect(
      enqueueTurn(first.state, "turn_01", "enqueue_duplicate"),
    ).rejects.toMatchObject({ code: "ALREADY_EXISTS" });
    expect(first.state).toEqual(before);
  });

  it("rejects a turn input digest that does not bind the normalized input", async () => {
    const initial = newSession();
    await expect(
      applySessionCommand(initial, {
        kind: "enqueue_turn",
        commandId: "enqueue_bad_input_digest",
        expectedEventSequence: initial.eventSequence,
        transactionTime: TRANSACTION_TIME,
        turnId: "turn_digest",
        input: { message: "digest-bound input" },
        inputDigest: await turnInputDigest({ message: "turn_01" }),
        genesisCheckpoint: await genesisCheckpoint(initial, "turn_digest"),
        turnLeaseGeneration: 10,
        leaseExpiresAt: 1_900_000_000_000,
      }),
    ).rejects.toMatchObject({ code: "DIGEST_MISMATCH" });
  });

  it("rejects an effect digest that does not bind the normalized intent", async () => {
    const initial = newSession();
    const input = { message: "turn_digest" };
    const admitted = await applySessionCommand(initial, {
      kind: "enqueue_turn",
      commandId: "enqueue_effect_digest",
      expectedEventSequence: initial.eventSequence,
      transactionTime: TRANSACTION_TIME,
      turnId: "turn_digest",
      input,
      inputDigest: await digestStructuredValue("circulusd.session.turn-input", 1, input),
      genesisCheckpoint: await genesisCheckpoint(initial, "turn_digest"),
      turnLeaseGeneration: 10,
      leaseExpiresAt: 1_900_000_000_000,
    });
    const originalIntent = {
      service: "executor" as const,
      operation: "spawn",
      replayPolicy: "safe" as const,
      payload: { argv: ["tool", "original"] },
    };
    await expect(
      applySessionCommand(admitted.state, {
        kind: "commit_engine_step",
        commandId: "prepare_bad_effect_digest",
        expectedEventSequence: admitted.state.eventSequence,
        turnId: "turn_digest",
        fence: currentFence(admitted.state),
        transactionTime: TRANSACTION_TIME,
        consumedSettlementEffectId: null,
        effectIdentity: { effectId: "effect_digest", invocationId: "invocation_digest" },
        step: {
          kind: "effect_request",
          checkpoint: await nextCheckpoint(admitted.state),
          request: {
            ...originalIntent,
            requestDigest: await digestStructuredValue(
              "circulusd.session.effect-request",
              1,
              originalIntent,
            ),
            payload: { argv: ["tool", "tampered"] },
          },
        },
      }),
    ).rejects.toMatchObject({ code: "DIGEST_MISMATCH" });
  });

  it("cryptographically validates persisted checkpoint payloads", async () => {
    const admitted = await enqueueTurn(newSession(), "turn_01", "enqueue_01");
    const corrupt = structuredClone(admitted.state);
    if (corrupt.activeTurn === null) {
      throw new Error("active turn missing from test state");
    }
    corrupt.activeTurn.checkpoint = {
      ...corrupt.activeTurn.checkpoint,
      payloadDigest: INPUT_DIGEST,
    };
    await expect(validateSessionState(corrupt)).rejects.toThrow(/payloadDigest/);
  });

  it("preserves failed turns with their input, final checkpoint, and exact error", async () => {
    const admitted = await enqueueTurn(newSession(), "turn_01", "enqueue_01");
    const finalCheckpoint = await nextCheckpoint(admitted.state);
    const failed = await applySessionCommand(admitted.state, {
      kind: "commit_engine_step",
      commandId: "fail_01",
      expectedEventSequence: admitted.state.eventSequence,
      turnId: "turn_01",
      fence: currentFence(admitted.state),
      transactionTime: TRANSACTION_TIME,
      consumedSettlementEffectId: null,
      effectIdentity: null,
      step: {
        kind: "turn_error",
        checkpoint: finalCheckpoint,
        error: {
          code: "MODEL_FAILED",
          message: "provider rejected request",
          retryable: false,
          details: { provider: "test" },
        },
      },
    });

    expect(failed.state.activeTurn).toBeNull();
    expect(failed.state.terminalTurns).toEqual([
      {
        turnId: "turn_01",
        sequence: 0,
        input: { message: "turn_01" },
        inputDigest: await turnInputDigest({ message: "turn_01" }),
        finalCheckpoint,
        turnLeaseGeneration: 10,
        leaseExpiresAt: 1_900_000_000_000,
        status: "failed",
        abortRequested: false,
        abortReason: null,
        result: null,
        error: {
          code: "MODEL_FAILED",
          message: "provider rejected request",
          retryable: false,
          details: { provider: "test" },
        },
      },
    ]);
    expect(() => assertSessionInvariants(failed.state)).not.toThrow();

    const corruptTerminalCheckpoint = structuredClone(failed.state);
    const terminal = corruptTerminalCheckpoint.terminalTurns[0];
    if (terminal === undefined) {
      throw new Error("terminal turn missing from test state");
    }
    terminal.finalCheckpoint = await genesisCheckpoint(newSession(), "turn_01");
    expect(() => assertSessionInvariants(corruptTerminalCheckpoint)).toThrow(
      /terminal engine checkpoint/,
    );
  });

  it("requires every admitted turn to occupy exactly one exact ADR status", async () => {
    const first = await enqueueTurn(newSession(), "turn_01", "enqueue_01");
    const second = await enqueueTurn(first.state, "turn_02", "enqueue_02");
    expect(second.state.activeTurn?.status).toBe("active");
    expect(second.state.queuedTurns[0]?.status).toBe("queued");

    const wrongQueuedStatus = structuredClone(second.state);
    const queued = wrongQueuedStatus.queuedTurns[0];
    if (queued === undefined) {
      throw new Error("queued turn missing from test state");
    }
    Reflect.set(queued, "status", "active");
    expect(() => assertSessionInvariants(wrongQueuedStatus)).toThrow(/queued turn status/);

    const missingAdmittedTurn = structuredClone(second.state);
    missingAdmittedTurn.queuedTurns.pop();
    expect(() => assertSessionInvariants(missingAdmittedTurn)).toThrow(
      /exactly one durable status/,
    );
  });

  it("binds engine checkpoints to predecessor, identity, runtime, ABI, and sequence", async () => {
    const admitted = await enqueueTurn(newSession(), "turn_01", "enqueue_01");
    const valid = await nextCheckpoint(admitted.state);
    const corruptions: readonly [string, Partial<EngineAgentCheckpoint>][] = [
      ["sequence", { checkpointSequence: 2 }],
      ["predecessor", { predecessorDigest: INPUT_DIGEST }],
      ["session", { sessionId: "sess_other" }],
      ["turn", { turnId: "turn_other" }],
      ["runtime", { runtimeRevisionDigest: INPUT_DIGEST }],
      ["adapter ABI", { adapterAbiVersion: 2 }],
      ["schema", { checkpointSchemaVersion: 2 }],
    ];

    for (const [label, corruption] of corruptions) {
      const checkpoint = { ...valid, ...corruption };
      await expect(
        applySessionCommand(admitted.state, {
          kind: "commit_engine_step",
          commandId: `bad_${label}`,
          expectedEventSequence: admitted.state.eventSequence,
          turnId: "turn_01",
          fence: currentFence(admitted.state),
          transactionTime: TRANSACTION_TIME,
          consumedSettlementEffectId: null,
          effectIdentity: null,
          step: { kind: "checkpoint", checkpoint },
        }),
        label,
      ).rejects.toBeInstanceOf(SessionAggregateError);
    }
  });

  it("commits a checkpoint and prepares one effect atomically", async () => {
    const admitted = await enqueueTurn(newSession(), "turn_01", "enqueue_01");
    const prepared = await prepareEffect(admitted.state, "safe", "01");
    const effect = prepared.state.effects[0];

    expect(prepared.state.activeTurn?.checkpoint.checkpointSequence).toBe(1);
    expect(prepared.state.activeTurn?.activeEffectId).toBe("effect_01");
    expect(effect).toMatchObject({
      effectId: "effect_01",
      invocationId: "invocation_01",
      phase: "prepared",
      dispatchAttempt: 0,
    });
    expect(Object.hasOwn(effect ?? {}, "dispatchPermit")).toBe(false);
    expect(prepared.outcome).toMatchObject({
      kind: "engine_step_committed",
      preparedEffectId: "effect_01",
    });

    const corrupt = structuredClone(prepared.state);
    const duplicate = structuredClone(corrupt.effects[0]);
    if (duplicate === undefined) {
      throw new Error("prepared effect missing from test state");
    }
    duplicate.effectId = "effect_02";
    duplicate.invocationId = "invocation_02";
    corrupt.effects.push(duplicate);
    expect(() => assertSessionInvariants(corrupt)).toThrow(/more than one external effect/);
  });

  it("rejects externally committed state without durable commit proof", async () => {
    const admitted = await enqueueTurn(newSession(), "turn_01", "enqueue_01");
    const prepared = await prepareEffect(admitted.state, "safe", "01");
    const dispatched = await dispatchActiveEffect(prepared.state, "dispatch_01");
    const corrupt = structuredClone(dispatched.state);
    const effect = corrupt.effects[0];
    if (effect === undefined) {
      throw new Error("effect missing from corrupt test state");
    }
    effect.phase = "externally_committed";

    expect(() => assertSessionInvariants(corrupt)).toThrow(/external commit proof/);
  });

  it("rejects malformed persisted command receipt outcomes", async () => {
    const admitted = await enqueueTurn(newSession(), "turn_01", "enqueue_01");
    const corrupt = structuredClone(admitted.state);
    const receipt = corrupt.commandReceipts[0];
    if (receipt === undefined) {
      throw new Error("receipt missing from corrupt test state");
    }
    Reflect.set(receipt, "outcome", {
      kind: "effect_dispatched",
      effectId: "effect_missing",
      dispatchPermitClaims: {},
    });

    expect(() => assertSessionInvariants(corrupt)).toThrow(/receipt|dispatch/i);
  });

  it("rejects unknown persisted fields and non-canonical strings", async () => {
    const admitted = await enqueueTurn(newSession(), "turn_01", "enqueue_01");
    const unknownField = structuredClone(admitted.state);
    Reflect.set(unknownField, "unexpectedAuthority", "forged");
    expect(() => assertSessionInvariants(unknownField)).toThrow(/unknown field/);

    const nonCanonical = structuredClone(admitted.state);
    if (nonCanonical.activeTurn === null) {
      throw new Error("active turn missing from corrupt test state");
    }
    Reflect.set(nonCanonical.activeTurn.input, "message", "e\u0301");
    expect(() => assertSessionInvariants(nonCanonical)).toThrow(/NFC-normalized/);
  });

  it("rejects an oversized turn input before it can grow durable state", async () => {
    const initial = newSession();
    const input = { message: "x".repeat(1_048_577) };
    await expect(
      applySessionCommand(initial, {
        kind: "enqueue_turn",
        commandId: "enqueue_oversized",
        expectedEventSequence: initial.eventSequence,
        transactionTime: TRANSACTION_TIME,
        turnId: "turn_oversized",
        input,
        inputDigest: await turnInputDigest(input),
        genesisCheckpoint: await genesisCheckpoint(initial, "turn_oversized"),
        turnLeaseGeneration: 10,
        leaseExpiresAt: 1_900_000_000_000,
      }),
    ).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });
  });

  it("dispatches only a prepared effect and binds every claim", async () => {
    const admitted = await enqueueTurn(newSession(), "turn_01", "enqueue_01");
    const prepared = await prepareEffect(admitted.state, "idempotency-key", "01");
    await expect(
      applySessionCommand(prepared.state, {
        kind: "dispatch_effect",
        commandId: "dispatch_beyond_lease",
        expectedEventSequence: prepared.state.eventSequence,
        turnId: "turn_01",
        effectId: "effect_01",
        invocationId: "invocation_01",
        requestDigest: activeEffect(prepared.state).requestDigest,
        fence: currentFence(prepared.state),
        transactionTime: TRANSACTION_TIME,
        deadline: 1_900_000_000_001,
      }),
    ).rejects.toMatchObject({ code: "FAILED_PRECONDITION" });
    await expect(
      applySessionCommand(prepared.state, {
        kind: "dispatch_effect",
        commandId: "dispatch_expired_authority",
        expectedEventSequence: prepared.state.eventSequence,
        turnId: "turn_01",
        effectId: "effect_01",
        invocationId: "invocation_01",
        requestDigest: activeEffect(prepared.state).requestDigest,
        fence: currentFence(prepared.state),
        transactionTime: 1_800_000_000_000,
        deadline: 1_800_000_000_000,
      }),
    ).rejects.toMatchObject({ code: "FAILED_PRECONDITION" });
    const dispatched = await dispatchActiveEffect(prepared.state, "dispatch_01");

    expect(dispatched.state.effects[0]).toMatchObject({
      phase: "dispatched",
      dispatchAttempt: 1,
    });
    if (dispatched.outcome.kind !== "effect_dispatched") {
      throw new Error("unexpected test outcome");
    }
    expect(parseDispatchPermitClaims(dispatched.outcome.dispatchPermitClaims)).toEqual(
      dispatched.outcome.dispatchPermitClaims,
    );
    expect(dispatched.outcome.dispatchPermitClaims).toMatchObject({
      tenantId: "tenant_01",
      userId: "user_01",
      sessionId: "sess_01",
      turnId: "turn_01",
      effectId: "effect_01",
      invocationId: "invocation_01",
      service: "executor",
      operation: "spawn",
      dispatchAttempt: 1,
      turnLeaseGeneration: 10,
      placementGeneration: 4,
      sandboxGeneration: 5,
      authorizationGeneration: 6,
      deadline: 1_800_000_000_000,
    });

    await expect(
      dispatchActiveEffect(dispatched.state, "dispatch_again"),
    ).rejects.toMatchObject({ code: "FAILED_PRECONDITION" });
  });

  it("keeps a settlement active until the next checkpoint consumes it exactly once", async () => {
    const admitted = await enqueueTurn(newSession(), "turn_01", "enqueue_01");
    const prepared = await prepareEffect(admitted.state, "safe", "01");
    const dispatched = await dispatchActiveEffect(prepared.state, "dispatch_01");
    const settled = await applySessionCommand(dispatched.state, {
      kind: "settle_effect",
      commandId: "settle_01",
      expectedEventSequence: dispatched.state.eventSequence,
      turnId: "turn_01",
      effectId: "effect_01",
      invocationId: "invocation_01",
      requestDigest: activeEffect(dispatched.state).requestDigest,
      dispatchAttempt: 1,
      fence: currentFence(dispatched.state),
      settlement: { kind: "success", result: { outputRef: "blob_01" } },
    });

    expect(settled.state.effects[0]?.phase).toBe("settled");
    expect(settled.state.activeTurn?.activeEffectId).toBe("effect_01");
    await expect(
      applySessionCommand(settled.state, {
        kind: "commit_engine_step",
        commandId: "consume_wrong",
        expectedEventSequence: settled.state.eventSequence,
        turnId: "turn_01",
        fence: currentFence(settled.state),
        transactionTime: TRANSACTION_TIME + 1,
        consumedSettlementEffectId: null,
        effectIdentity: null,
        step: { kind: "checkpoint", checkpoint: await nextCheckpoint(settled.state) },
      }),
    ).rejects.toMatchObject({ code: "FAILED_PRECONDITION" });

    const consumedAndPrepared = await applySessionCommand(settled.state, {
      kind: "commit_engine_step",
      commandId: "consume_and_prepare",
      expectedEventSequence: settled.state.eventSequence,
      turnId: "turn_01",
      fence: currentFence(settled.state),
      transactionTime: TRANSACTION_TIME + 1,
      consumedSettlementEffectId: "effect_01",
      effectIdentity: { effectId: "effect_02", invocationId: "invocation_02" },
      step: {
        kind: "effect_request",
        checkpoint: await nextCheckpoint(settled.state),
        request: {
          service: "mcp",
          operation: "tools/call",
          replayPolicy: "confirm",
          requestDigest: await effectRequestDigest({
            service: "mcp",
            operation: "tools/call",
            replayPolicy: "confirm",
            payload: { tool: "mutate" },
          }),
          payload: { tool: "mutate" },
        },
      },
    });

    expect(consumedAndPrepared.state.effects).toHaveLength(2);
    expect(consumedAndPrepared.state.effects[0]).toMatchObject({
      phase: "settled",
      consumedAtCheckpointSequence: 2,
    });
    expect(consumedAndPrepared.state.effects[1]).toMatchObject({
      phase: "prepared",
      effectId: "effect_02",
    });
    expect(consumedAndPrepared.state.activeTurn?.activeEffectId).toBe("effect_02");
  });

  it("rejects success and abandonment before a dispatch permit exists", async () => {
    const admitted = await enqueueTurn(newSession(), "turn_01", "enqueue_01");
    const prepared = await prepareEffect(admitted.state, "safe", "01");
    const effect = activeEffect(prepared.state);
    const invalidSettlements = [
      { kind: "success", result: { forged: true } },
      { kind: "abandoned", reason: "confirmation was never required" },
    ] satisfies readonly EffectSettlement[];

    for (const [index, settlement] of invalidSettlements.entries()) {
      await expect(
        applySessionCommand(prepared.state, {
          kind: "settle_effect",
          commandId: `settle_prepared_${index}`,
          expectedEventSequence: prepared.state.eventSequence,
          turnId: "turn_01",
          effectId: effect.effectId,
          invocationId: effect.invocationId,
          requestDigest: effect.requestDigest,
          dispatchAttempt: null,
          fence: currentFence(prepared.state),
          settlement,
        }),
      ).rejects.toMatchObject({ code: "FAILED_PRECONDITION" });
    }
  });

  it("settles by generation fence even after wall-clock lease expiry", async () => {
    const admitted = await enqueueTurn(newSession(), "turn_01", "enqueue_01");
    const prepared = await prepareEffect(admitted.state, "safe", "01");
    const dispatched = await dispatchActiveEffect(prepared.state, "dispatch_01");
    const afterLeaseExpiry = structuredClone(dispatched.state);
    if (afterLeaseExpiry.activeTurn === null) {
      throw new Error("active turn missing from test state");
    }
    afterLeaseExpiry.activeTurn.leaseExpiresAt = 1;

    const settled = await applySessionCommand(afterLeaseExpiry, {
      kind: "settle_effect",
      commandId: "settle_after_lease_expiry",
      expectedEventSequence: afterLeaseExpiry.eventSequence,
      turnId: "turn_01",
      effectId: "effect_01",
      invocationId: "invocation_01",
      requestDigest: activeEffect(afterLeaseExpiry).requestDigest,
      dispatchAttempt: 1,
      fence: currentFence(afterLeaseExpiry),
      settlement: { kind: "success", result: { outputRef: "blob_after_expiry" } },
    });

    expect(settled.state.effects[0]).toMatchObject({
      phase: "settled",
      settlement: { kind: "success" },
    });
  });

  it("rejects every stale generation independently", async () => {
    const admitted = await enqueueTurn(newSession(), "turn_01", "enqueue_01");
    const prepared = await prepareEffect(admitted.state, "safe", "01");
    const fence = currentFence(prepared.state);

    for (const generation of Object.keys(fence) as (keyof SessionFence)[]) {
      await expect(
        applySessionCommand(prepared.state, {
          kind: "dispatch_effect",
          commandId: `stale_${generation}`,
          expectedEventSequence: prepared.state.eventSequence,
          turnId: "turn_01",
          effectId: "effect_01",
          invocationId: "invocation_01",
          requestDigest: activeEffect(prepared.state).requestDigest,
          fence: { ...fence, [generation]: fence[generation] + 1 },
          transactionTime: TRANSACTION_TIME,
          deadline: 1_800_000_000_000,
        }),
      ).rejects.toMatchObject({ code: "STALE_GENERATION" });
    }
  });

  it("rotates placement, sandbox, and authorization fences monotonically", async () => {
    const admitted = await enqueueTurn(newSession(), "turn_01", "enqueue_01");
    const oldFence = currentFence(admitted.state);
    const rotated = await applySessionCommand(admitted.state, {
      kind: "rotate_generations",
      commandId: "rotate_01",
      expectedEventSequence: admitted.state.eventSequence,
      nextPlacementGeneration: 5,
      nextSandboxGeneration: 6,
      nextAuthorizationGeneration: 7,
      nextEmergencyOverlayDigest: ROTATED_EMERGENCY_DIGEST,
    });
    expect(rotated.state).toMatchObject({
      placementGeneration: 5,
      sandboxGeneration: 6,
      authorizationGeneration: 7,
      emergencyOverlayDigest: ROTATED_EMERGENCY_DIGEST,
    });
    await expect(
      applySessionCommand(rotated.state, {
        kind: "commit_engine_step",
        commandId: "stale_engine_after_rotation",
        expectedEventSequence: rotated.state.eventSequence,
        turnId: "turn_01",
        fence: oldFence,
        transactionTime: TRANSACTION_TIME,
        consumedSettlementEffectId: null,
        effectIdentity: null,
        step: { kind: "checkpoint", checkpoint: await nextCheckpoint(rotated.state) },
      }),
    ).rejects.toMatchObject({ code: "STALE_GENERATION" });
  });

  it("rotates the active turn lease and rejects the prior owner fence", async () => {
    const admitted = await enqueueTurn(newSession(), "turn_01", "enqueue_01");
    const oldFence = currentFence(admitted.state);
    const rotated = await applySessionCommand(admitted.state, {
      kind: "rotate_turn_lease",
      commandId: "rotate_turn_lease_01",
      expectedEventSequence: admitted.state.eventSequence,
      turnId: "turn_01",
      fence: oldFence,
      transactionTime: TRANSACTION_TIME,
      nextTurnLeaseGeneration: oldFence.turnLeaseGeneration + 1,
      nextLeaseExpiresAt: 1_900_000_001_000,
    });

    expect(rotated.state.activeTurn).toMatchObject({
      turnLeaseGeneration: 11,
      leaseExpiresAt: 1_900_000_001_000,
    });
    await expect(
      applySessionCommand(rotated.state, {
        kind: "commit_engine_step",
        commandId: "stale_engine_after_turn_lease_rotation",
        expectedEventSequence: rotated.state.eventSequence,
        turnId: "turn_01",
        fence: oldFence,
        transactionTime: TRANSACTION_TIME,
        consumedSettlementEffectId: null,
        effectIdentity: null,
        step: { kind: "checkpoint", checkpoint: await nextCheckpoint(rotated.state) },
      }),
    ).rejects.toMatchObject({ code: "STALE_GENERATION" });
  });

  it("skips expired queued heads transactionally before promoting the next live turn", async () => {
    const first = await enqueueTurn(newSession(), "turn_01", "enqueue_01");
    const expired = await applySessionCommand(first.state, {
      kind: "enqueue_turn",
      commandId: "enqueue_expired",
      expectedEventSequence: first.state.eventSequence,
      transactionTime: TRANSACTION_TIME - 1,
      turnId: "turn_02",
      input: { message: "turn_02" },
      inputDigest: await turnInputDigest({ message: "turn_02" }),
      genesisCheckpoint: await genesisCheckpoint(first.state, "turn_02"),
      turnLeaseGeneration: 11,
      leaseExpiresAt: TRANSACTION_TIME,
    });
    const live = await applySessionCommand(expired.state, {
      kind: "enqueue_turn",
      commandId: "enqueue_live",
      expectedEventSequence: expired.state.eventSequence,
      transactionTime: TRANSACTION_TIME,
      turnId: "turn_03",
      input: { message: "turn_03" },
      inputDigest: await turnInputDigest({ message: "turn_03" }),
      genesisCheckpoint: await genesisCheckpoint(expired.state, "turn_03"),
      turnLeaseGeneration: 12,
      leaseExpiresAt: TRANSACTION_TIME + 10_000,
    });
    const completed = await applySessionCommand(live.state, {
      kind: "commit_engine_step",
      commandId: "complete_before_expired_head",
      expectedEventSequence: live.state.eventSequence,
      turnId: "turn_01",
      fence: currentFence(live.state),
      consumedSettlementEffectId: null,
      effectIdentity: null,
      transactionTime: TRANSACTION_TIME + 1,
      step: {
        kind: "turn_complete",
        checkpoint: await nextCheckpoint(live.state),
        result: null,
      },
    });

    expect(completed.state.terminalTurns.map(({ turnId, status }) => ({ turnId, status }))).toEqual([
      { turnId: "turn_01", status: "completed" },
      { turnId: "turn_02", status: "aborted" },
    ]);
    expect(completed.state.terminalTurns[1]).toMatchObject({
      abortRequested: true,
      abortReason: "turn lease expired before activation",
    });
    expect(completed.state.activeTurn?.turnId).toBe("turn_03");
    expect(completed.state.queuedTurns).toEqual([]);
  });

  it("records external commit proof before settlement", async () => {
    const admitted = await enqueueTurn(newSession(), "turn_01", "enqueue_01");
    const prepared = await prepareEffect(admitted.state, "safe", "01");
    const dispatched = await dispatchActiveEffect(prepared.state, "dispatch_01");
    const committed = await applySessionCommand(dispatched.state, {
      kind: "record_external_commit",
      commandId: "external_commit_01",
      expectedEventSequence: dispatched.state.eventSequence,
      turnId: "turn_01",
      effectId: "effect_01",
      invocationId: "invocation_01",
      requestDigest: activeEffect(dispatched.state).requestDigest,
      dispatchAttempt: 1,
      fence: currentFence(dispatched.state),
      externalCommitId: "external_01",
      resultRef: "result_01",
    });
    expect(committed.state.effects[0]).toMatchObject({
      phase: "externally_committed",
      externalCommitId: "external_01",
      resultRef: "result_01",
    });
  });

  it("does not admit a later turn while confirmation blocks the active turn", async () => {
    const admitted = await enqueueTurn(newSession(), "turn_01", "enqueue_01");
    const prepared = await prepareEffect(admitted.state, "confirm", "01");
    const dispatched = await dispatchActiveEffect(prepared.state, "dispatch_01");
    const blocked = await applySessionCommand(dispatched.state, {
      kind: "recover_effect",
      commandId: "block_confirm_01",
      expectedEventSequence: dispatched.state.eventSequence,
      turnId: "turn_01",
      effectId: "effect_01",
      invocationId: "invocation_01",
      requestDigest: activeEffect(dispatched.state).requestDigest,
      fence: currentFence(dispatched.state),
      transactionTime: TRANSACTION_TIME,
      deadline: 1_800_000_001_000,
    });
    await expect(
      enqueueTurn(blocked.state, "turn_02", "enqueue_while_blocked"),
    ).rejects.toMatchObject({ code: "NEEDS_CONFIRMATION" });
  });

  it("blocks new effect admission after abort and finalizes after safe settlement", async () => {
    const admitted = await enqueueTurn(newSession(), "turn_01", "enqueue_01");
    const prepared = await prepareEffect(admitted.state, "safe", "01");
    const aborting = await applySessionCommand(prepared.state, {
      kind: "request_abort",
      commandId: "abort_01",
      expectedEventSequence: prepared.state.eventSequence,
      turnId: "turn_01",
      fence: currentFence(prepared.state),
      transactionTime: TRANSACTION_TIME,
      reason: "user request",
    });
    expect(aborting.state.activeTurn).toMatchObject({
      abortRequested: true,
      status: "active",
    });
    await expect(
      dispatchActiveEffect(aborting.state, "dispatch_after_abort"),
    ).rejects.toMatchObject({ code: "ABORTED" });

    await expect(
      applySessionCommand(aborting.state, {
        kind: "commit_engine_step",
        commandId: "effect_after_abort",
        expectedEventSequence: aborting.state.eventSequence,
        turnId: "turn_01",
        fence: currentFence(aborting.state),
        transactionTime: TRANSACTION_TIME + 1,
        consumedSettlementEffectId: null,
        effectIdentity: { effectId: "effect_02", invocationId: "invocation_02" },
        step: {
          kind: "effect_request",
          checkpoint: await nextCheckpoint(aborting.state),
          request: {
            service: "model",
            operation: "complete",
            replayPolicy: "safe",
            requestDigest: await effectRequestDigest({
              service: "model",
              operation: "complete",
              replayPolicy: "safe",
              payload: null,
            }),
            payload: null,
          },
        },
      }),
    ).rejects.toMatchObject({ code: "ABORTED" });

    const settled = await applySessionCommand(aborting.state, {
      kind: "settle_effect",
      commandId: "cancel_effect_01",
      expectedEventSequence: aborting.state.eventSequence,
      turnId: "turn_01",
      effectId: "effect_01",
      invocationId: "invocation_01",
      requestDigest: activeEffect(aborting.state).requestDigest,
      dispatchAttempt: null,
      fence: currentFence(aborting.state),
      settlement: { kind: "interrupted_unknown", reason: "cancelled before dispatch" },
    });
    await expect(
      applySessionCommand(settled.state, {
        kind: "commit_engine_step",
        commandId: "complete_after_abort",
        expectedEventSequence: settled.state.eventSequence,
        turnId: "turn_01",
        fence: currentFence(settled.state),
        transactionTime: TRANSACTION_TIME + 1,
        consumedSettlementEffectId: "effect_01",
        effectIdentity: null,
        step: {
          kind: "turn_complete",
          checkpoint: await nextCheckpoint(settled.state),
          result: { incorrectlyCompleted: true },
        },
      }),
    ).rejects.toMatchObject({ code: "ABORTED" });
    const finalized = await applySessionCommand(settled.state, {
      kind: "finalize_abort",
      commandId: "finalize_abort_01",
      expectedEventSequence: settled.state.eventSequence,
      turnId: "turn_01",
      fence: currentFence(settled.state),
      transactionTime: TRANSACTION_TIME + 1,
    });
    expect(finalized.state.activeTurn).toBeNull();
    expect(finalized.state.latestSettledTurn).toBe("turn_01");
    expect(finalized.outcome).toMatchObject({ status: "aborted" });
    expect(finalized.state.terminalTurns).toEqual([
      expect.objectContaining({
        turnId: "turn_01",
        input: { message: "turn_01" },
        finalCheckpoint: prepared.state.activeTurn?.checkpoint,
        status: "aborted",
        abortRequested: true,
        abortReason: "user request",
        result: null,
        error: null,
      }),
    ]);
  });
});
