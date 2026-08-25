import {
  digestBytes,
  type AgentCheckpoint,
  type Digest,
  type EngineAgentCheckpoint,
  type ReplayPolicy,
} from "@circulusd/protocol-types";
import { describe, expect, it } from "vitest";

import {
  applySessionCommand,
  checkpointDigest,
  createSessionState,
  effectRequestDigest,
  turnInputDigest,
  type SessionAggregateState,
  type SessionFence,
} from "../src/session/index.ts";

const RUNTIME_DIGEST = `sha256:${"a".repeat(64)}` as Digest;
const TRANSACTION_TIME = 1_700_000_000_000;

function freshSession(): SessionAggregateState {
  return createSessionState({
    sessionId: "session_recovery",
    tenantId: "tenant_recovery",
    userId: "user_recovery",
    workspaceId: "workspace_recovery",
    runtimeRevisionDigest: RUNTIME_DIGEST,
    policySnapshotDigest: `sha256:${"d".repeat(64)}`,
    emergencyOverlayDigest: `sha256:${"e".repeat(64)}`,
    engineKind: "low-level",
    adapterAbiVersion: 1,
    checkpointSchemaVersion: 1,
    placementGeneration: 1,
    sandboxGeneration: 2,
    authorizationGeneration: 3,
  });
}

function fence(state: SessionAggregateState): SessionFence {
  if (state.activeTurn === null) {
    throw new Error("active turn required");
  }
  return {
    turnLeaseGeneration: state.activeTurn.turnLeaseGeneration,
    placementGeneration: state.placementGeneration,
    sandboxGeneration: state.sandboxGeneration,
    authorizationGeneration: state.authorizationGeneration,
  };
}

async function genesis(state: SessionAggregateState): Promise<AgentCheckpoint> {
  const payloadBytes = new Uint8Array([0]);
  return {
    kind: "genesis",
    engineKind: state.engineKind,
    adapterAbiVersion: state.adapterAbiVersion,
    checkpointSchemaVersion: state.checkpointSchemaVersion,
    runtimeRevisionDigest: state.runtimeRevisionDigest,
    sessionId: state.sessionId,
    turnId: "turn_recovery",
    checkpointSequence: 0,
    predecessorDigest: null,
    payloadEncoding: "opaque-v1",
    payloadBytes,
    payloadDigest: await digestBytes(payloadBytes),
  };
}

async function nextCheckpoint(state: SessionAggregateState): Promise<EngineAgentCheckpoint> {
  if (state.activeTurn === null) {
    throw new Error("active turn required");
  }
  const payloadBytes = new Uint8Array([state.activeTurn.checkpoint.checkpointSequence + 1]);
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

function requestDigest(state: SessionAggregateState): Digest {
  const effect = state.effects[0];
  if (effect === undefined) {
    throw new Error("effect required");
  }
  return effect.requestDigest;
}

async function dispatchedEffect(replayPolicy: ReplayPolicy): Promise<SessionAggregateState> {
  const initial = freshSession();
  const input = { message: "recover this turn" };
  const admitted = await applySessionCommand(initial, {
    kind: "enqueue_turn",
    commandId: "enqueue_recovery",
    expectedEventSequence: 0,
    transactionTime: TRANSACTION_TIME,
    turnId: "turn_recovery",
    input,
    inputDigest: await turnInputDigest(input),
    genesisCheckpoint: await genesis(initial),
    turnLeaseGeneration: 9,
    leaseExpiresAt: 1_900_000_000_000,
  });
  const request = {
    service: "mcp" as const,
    operation: "tools/call",
    replayPolicy,
    payload: { name: "mutate" },
  };
  const prepared = await applySessionCommand(admitted.state, {
    kind: "commit_engine_step",
    commandId: "prepare_recovery",
    expectedEventSequence: admitted.state.eventSequence,
    turnId: "turn_recovery",
    fence: fence(admitted.state),
    transactionTime: TRANSACTION_TIME,
    consumedSettlementEffectId: null,
    effectIdentity: { effectId: "effect_recovery", invocationId: "invocation_stable" },
    step: {
      kind: "effect_request",
      checkpoint: await nextCheckpoint(admitted.state),
      request: {
        ...request,
        requestDigest: await effectRequestDigest(request),
      },
    },
  });
  const dispatched = await applySessionCommand(prepared.state, {
    kind: "dispatch_effect",
    commandId: "dispatch_recovery",
    expectedEventSequence: prepared.state.eventSequence,
    turnId: "turn_recovery",
    effectId: "effect_recovery",
    invocationId: "invocation_stable",
    requestDigest: requestDigest(prepared.state),
    fence: fence(prepared.state),
    transactionTime: TRANSACTION_TIME,
    deadline: 1_800_000_000_000,
  });
  return dispatched.state;
}

describe("effect recovery policy", () => {
  for (const replayPolicy of ["safe", "idempotency-key"] as const) {
    it(`${replayPolicy} replay preserves invocation and increments attempt`, async () => {
      const dispatched = await dispatchedEffect(replayPolicy);
      const recovered = await applySessionCommand(dispatched, {
        kind: "recover_effect",
        commandId: `recover_${replayPolicy}`,
        expectedEventSequence: dispatched.eventSequence,
        turnId: "turn_recovery",
        effectId: "effect_recovery",
        invocationId: "invocation_stable",
        requestDigest: requestDigest(dispatched),
        fence: fence(dispatched),
        transactionTime: TRANSACTION_TIME,
        deadline: 1_800_000_001_000,
      });

      expect(recovered.state.effects[0]).toMatchObject({
        phase: "dispatched",
        invocationId: "invocation_stable",
        dispatchAttempt: 2,
      });
      expect(recovered.outcome).toMatchObject({
        kind: "effect_recovered",
        action: "retry",
        dispatchPermitClaims: {
          invocationId: "invocation_stable",
          dispatchAttempt: 2,
        },
      });
    });
  }

  it("keeps one invocation stable across repeated safe recovery attempts", async () => {
    let state = await dispatchedEffect("safe");
    for (let retry = 1; retry <= 16; retry += 1) {
      const recovered = await applySessionCommand(state, {
        kind: "recover_effect",
        commandId: `recover_repeat_${retry}`,
        expectedEventSequence: state.eventSequence,
        turnId: "turn_recovery",
        effectId: "effect_recovery",
        invocationId: "invocation_stable",
        requestDigest: requestDigest(state),
        fence: fence(state),
        transactionTime: TRANSACTION_TIME,
        deadline: 1_800_000_010_000 + retry,
      });
      state = recovered.state;
      expect(state.effects[0]).toMatchObject({
        invocationId: "invocation_stable",
        dispatchAttempt: retry + 1,
        phase: "dispatched",
      });
    }
  });

  it("rejects late external commit and settlement from an older dispatch attempt", async () => {
    const dispatched = await dispatchedEffect("safe");
    const recovered = await applySessionCommand(dispatched, {
      kind: "recover_effect",
      commandId: "recover_for_attempt_fence",
      expectedEventSequence: dispatched.eventSequence,
      turnId: "turn_recovery",
      effectId: "effect_recovery",
      invocationId: "invocation_stable",
      requestDigest: requestDigest(dispatched),
      fence: fence(dispatched),
      transactionTime: TRANSACTION_TIME,
      deadline: 1_800_000_001_000,
      providerRequestId: "provider_attempt_2",
    });

    await expect(
      applySessionCommand(recovered.state, {
        kind: "record_external_commit",
        commandId: "late_external_commit",
        expectedEventSequence: recovered.state.eventSequence,
        turnId: "turn_recovery",
        effectId: "effect_recovery",
        invocationId: "invocation_stable",
        requestDigest: requestDigest(recovered.state),
        dispatchAttempt: 1,
        fence: fence(recovered.state),
        externalCommitId: "late_commit",
        resultRef: "late_result",
      }),
    ).rejects.toMatchObject({ code: "STALE_DISPATCH_ATTEMPT" });
    await expect(
      applySessionCommand(recovered.state, {
        kind: "settle_effect",
        commandId: "late_settlement",
        expectedEventSequence: recovered.state.eventSequence,
        turnId: "turn_recovery",
        effectId: "effect_recovery",
        invocationId: "invocation_stable",
        requestDigest: requestDigest(recovered.state),
        dispatchAttempt: 1,
        fence: fence(recovered.state),
        settlement: { kind: "success", result: { source: "attempt_1" } },
      }),
    ).rejects.toMatchObject({ code: "STALE_DISPATCH_ATTEMPT" });

    const committed = await applySessionCommand(recovered.state, {
      kind: "record_external_commit",
      commandId: "current_external_commit",
      expectedEventSequence: recovered.state.eventSequence,
      turnId: "turn_recovery",
      effectId: "effect_recovery",
      invocationId: "invocation_stable",
      requestDigest: requestDigest(recovered.state),
      dispatchAttempt: 2,
      fence: fence(recovered.state),
      externalCommitId: "current_commit",
      resultRef: "current_result",
    });
    const settled = await applySessionCommand(committed.state, {
      kind: "settle_effect",
      commandId: "current_settlement",
      expectedEventSequence: committed.state.eventSequence,
      turnId: "turn_recovery",
      effectId: "effect_recovery",
      invocationId: "invocation_stable",
      requestDigest: requestDigest(committed.state),
      dispatchAttempt: 2,
      fence: fence(committed.state),
      settlement: { kind: "success", result: { source: "attempt_2" } },
    });
    expect(settled.state.effects[0]).toMatchObject({
      phase: "settled",
      dispatchAttempt: 2,
      lastDispatch: {
        dispatchAttempt: 2,
        turnLeaseGeneration: 9,
        placementGeneration: 1,
        sandboxGeneration: 2,
        authorizationGeneration: 3,
        deadline: 1_800_000_001_000,
        providerRequestId: "provider_attempt_2",
      },
    });
  });

  it("rejects recovery when trusted transaction time has reached the deadline", async () => {
    const dispatched = await dispatchedEffect("safe");
    await expect(
      applySessionCommand(dispatched, {
        kind: "recover_effect",
        commandId: "recover_expired",
        expectedEventSequence: dispatched.eventSequence,
        turnId: "turn_recovery",
        effectId: "effect_recovery",
        invocationId: "invocation_stable",
        requestDigest: requestDigest(dispatched),
        fence: fence(dispatched),
        transactionTime: 1_800_000_001_000,
        deadline: 1_800_000_001_000,
      }),
    ).rejects.toMatchObject({ code: "FAILED_PRECONDITION" });
  });

  it("never resolves uncertain dispatch as interrupted without replay", async () => {
    const dispatched = await dispatchedEffect("never");
    const recovered = await applySessionCommand(dispatched, {
      kind: "recover_effect",
      commandId: "recover_never",
      expectedEventSequence: dispatched.eventSequence,
      turnId: "turn_recovery",
      effectId: "effect_recovery",
      invocationId: "invocation_stable",
      requestDigest: requestDigest(dispatched),
      fence: fence(dispatched),
      transactionTime: TRANSACTION_TIME,
      deadline: 1_800_000_001_000,
    });

    expect(recovered.state.effects[0]).toMatchObject({
      phase: "settled",
      dispatchAttempt: 1,
      settlement: { kind: "interrupted_unknown" },
    });
    expect(recovered.state.activeTurn?.activeEffectId).toBe("effect_recovery");
    expect(recovered.outcome).toMatchObject({ action: "interrupted" });
  });

  it("confirm blocks the turn until explicit retry or abandon", async () => {
    const dispatched = await dispatchedEffect("confirm");
    const blocked = await applySessionCommand(dispatched, {
      kind: "recover_effect",
      commandId: "recover_confirm",
      expectedEventSequence: dispatched.eventSequence,
      turnId: "turn_recovery",
      effectId: "effect_recovery",
      invocationId: "invocation_stable",
      requestDigest: requestDigest(dispatched),
      fence: fence(dispatched),
      transactionTime: TRANSACTION_TIME,
      deadline: 1_800_000_001_000,
    });
    expect(blocked.state.activeTurn?.status).toBe("needs_confirmation");
    expect(blocked.state.status).toBe("running");
    expect(blocked.state.effects[0]?.phase).toBe("blocked");

    await expect(
      applySessionCommand(blocked.state, {
        kind: "resolve_confirmation",
        commandId: "confirm_retry_expired",
        expectedEventSequence: blocked.state.eventSequence,
        turnId: "turn_recovery",
        effectId: "effect_recovery",
        invocationId: "invocation_stable",
        requestDigest: requestDigest(blocked.state),
        fence: fence(blocked.state),
        decision: "retry",
        transactionTime: 1_800_000_002_000,
        deadline: 1_800_000_002_000,
      }),
    ).rejects.toMatchObject({ code: "FAILED_PRECONDITION" });

    const retried = await applySessionCommand(blocked.state, {
      kind: "resolve_confirmation",
      commandId: "confirm_retry",
      expectedEventSequence: blocked.state.eventSequence,
      turnId: "turn_recovery",
      effectId: "effect_recovery",
      invocationId: "invocation_stable",
      requestDigest: requestDigest(blocked.state),
      fence: fence(blocked.state),
      decision: "retry",
      transactionTime: TRANSACTION_TIME,
      deadline: 1_800_000_002_000,
    });
    expect(retried.state.activeTurn?.status).toBe("active");
    expect(retried.state.effects[0]).toMatchObject({
      phase: "dispatched",
      dispatchAttempt: 2,
      invocationId: "invocation_stable",
    });

    const blockedAgainState = await dispatchedEffect("confirm");
    const blockedAgain = await applySessionCommand(blockedAgainState, {
      kind: "recover_effect",
      commandId: "recover_confirm_again",
      expectedEventSequence: blockedAgainState.eventSequence,
      turnId: "turn_recovery",
      effectId: "effect_recovery",
      invocationId: "invocation_stable",
      requestDigest: requestDigest(blockedAgainState),
      fence: fence(blockedAgainState),
      transactionTime: TRANSACTION_TIME,
      deadline: 1_800_000_003_000,
    });
    const abandoned = await applySessionCommand(blockedAgain.state, {
      kind: "resolve_confirmation",
      commandId: "confirm_abandon",
      expectedEventSequence: blockedAgain.state.eventSequence,
      turnId: "turn_recovery",
      effectId: "effect_recovery",
      invocationId: "invocation_stable",
      requestDigest: requestDigest(blockedAgain.state),
      fence: fence(blockedAgain.state),
      decision: "abandon",
      transactionTime: null,
      deadline: null,
    });
    expect(abandoned.state.effects[0]).toMatchObject({
      phase: "settled",
      settlement: { kind: "abandoned" },
    });
  });

  it("accepts external proof for a blocked effect without clearing an abort request", async () => {
    const dispatched = await dispatchedEffect("confirm");
    const blocked = await applySessionCommand(dispatched, {
      kind: "recover_effect",
      commandId: "recover_for_external_proof",
      expectedEventSequence: dispatched.eventSequence,
      turnId: "turn_recovery",
      effectId: "effect_recovery",
      invocationId: "invocation_stable",
      requestDigest: requestDigest(dispatched),
      fence: fence(dispatched),
      transactionTime: TRANSACTION_TIME,
      deadline: 1_800_000_001_000,
    });
    const abortRequested = await applySessionCommand(blocked.state, {
      kind: "request_abort",
      commandId: "abort_while_blocked",
      expectedEventSequence: blocked.state.eventSequence,
      turnId: "turn_recovery",
      fence: fence(blocked.state),
      transactionTime: TRANSACTION_TIME,
      reason: "caller disconnected",
    });
    expect(abortRequested.state.activeTurn).toMatchObject({
      status: "needs_confirmation",
      abortRequested: true,
      abortReason: "caller disconnected",
    });

    const proven = await applySessionCommand(abortRequested.state, {
      kind: "record_external_commit",
      commandId: "external_proof_while_blocked",
      expectedEventSequence: abortRequested.state.eventSequence,
      turnId: "turn_recovery",
      effectId: "effect_recovery",
      invocationId: "invocation_stable",
      requestDigest: requestDigest(abortRequested.state),
      dispatchAttempt: 1,
      fence: fence(abortRequested.state),
      externalCommitId: "external_commit_01",
      resultRef: "result_01",
    });
    expect(proven.state.status).toBe("running");
    expect(proven.state.activeTurn).toMatchObject({
      status: "active",
      abortRequested: true,
      abortReason: "caller disconnected",
    });
    expect(proven.state.effects[0]).toMatchObject({
      phase: "externally_committed",
      externalCommitId: "external_commit_01",
      resultRef: "result_01",
    });

    const settled = await applySessionCommand(proven.state, {
      kind: "settle_effect",
      commandId: "settle_proven_effect",
      expectedEventSequence: proven.state.eventSequence,
      turnId: "turn_recovery",
      effectId: "effect_recovery",
      invocationId: "invocation_stable",
      requestDigest: requestDigest(proven.state),
      dispatchAttempt: 1,
      fence: fence(proven.state),
      settlement: { kind: "success", result: { outputRef: "result_01" } },
    });
    const finalized = await applySessionCommand(settled.state, {
      kind: "finalize_abort",
      commandId: "finalize_after_external_proof",
      expectedEventSequence: settled.state.eventSequence,
      turnId: "turn_recovery",
      fence: fence(settled.state),
      transactionTime: TRANSACTION_TIME + 1,
    });
    expect(finalized.state.terminalTurns[0]).toMatchObject({
      status: "aborted",
      abortRequested: true,
      abortReason: "caller disconnected",
    });
  });

  it("classifies an aborted uncertain confirm effect without replaying it", async () => {
    const dispatched = await dispatchedEffect("confirm");
    const aborting = await applySessionCommand(dispatched, {
      kind: "request_abort",
      commandId: "abort_uncertain_confirm",
      expectedEventSequence: dispatched.eventSequence,
      turnId: "turn_recovery",
      fence: fence(dispatched),
      transactionTime: TRANSACTION_TIME,
      reason: "user canceled an uncertain invocation",
    });
    const classified = await applySessionCommand(aborting.state, {
      kind: "recover_effect",
      commandId: "classify_aborted_confirm",
      expectedEventSequence: aborting.state.eventSequence,
      turnId: "turn_recovery",
      effectId: "effect_recovery",
      invocationId: "invocation_stable",
      requestDigest: requestDigest(aborting.state),
      fence: fence(aborting.state),
      transactionTime: TRANSACTION_TIME + 1,
      deadline: 1_800_000_001_000,
    });

    expect(classified.outcome).toMatchObject({
      kind: "effect_recovered",
      action: "blocked",
    });
    expect(classified.state.activeTurn).toMatchObject({
      status: "needs_confirmation",
      abortRequested: true,
    });
    expect(classified.state.effects[0]).toMatchObject({
      phase: "blocked",
      dispatchAttempt: 1,
    });
  });
});
