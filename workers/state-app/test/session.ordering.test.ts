import { digestBytes, type AgentCheckpoint, type Digest } from "@circulusd/protocol-types";
import { describe, expect, it } from "vitest";

import {
  applySessionCommand,
  assertSessionInvariants,
  checkpointDigest,
  createSessionState,
  turnInputDigest,
  type SessionAggregateState,
} from "../src/session/index.ts";

const RUNTIME_DIGEST = `sha256:${"d".repeat(64)}` as Digest;

function makeState(): SessionAggregateState {
  return createSessionState({
    sessionId: "session_ordering",
    tenantId: "tenant_ordering",
    userId: "user_ordering",
    workspaceId: "workspace_ordering",
    runtimeRevisionDigest: RUNTIME_DIGEST,
    policySnapshotDigest: `sha256:${"a".repeat(64)}`,
    emergencyOverlayDigest: `sha256:${"b".repeat(64)}`,
    engineKind: "low-level",
    adapterAbiVersion: 1,
    checkpointSchemaVersion: 1,
    placementGeneration: 1,
    sandboxGeneration: 1,
    authorizationGeneration: 1,
  });
}

async function genesis(
  state: SessionAggregateState,
  turnId: string,
): Promise<AgentCheckpoint> {
  const payloadBytes = new TextEncoder().encode(turnId);
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

describe("session ordering model", () => {
  it("models competing transaction attempts with optimistic retry", async () => {
    const initial = makeState();
    const commandA = {
      kind: "enqueue_turn" as const,
      commandId: "race_a",
      expectedEventSequence: 0,
      transactionTime: 1_700_000_000_000,
      turnId: "turn_a",
      input: { message: "turn_a" },
      inputDigest: await turnInputDigest({ message: "turn_a" }),
      genesisCheckpoint: await genesis(initial, "turn_a"),
      turnLeaseGeneration: 1,
      leaseExpiresAt: 1_900_000_000_000,
    };
    const commandB = {
      ...commandA,
      commandId: "race_b",
      turnId: "turn_b",
      input: { message: "turn_b" },
      inputDigest: await turnInputDigest({ message: "turn_b" }),
      genesisCheckpoint: await genesis(initial, "turn_b"),
    };

    const [candidateA, candidateB] = await Promise.all([
      applySessionCommand(initial, commandA),
      applySessionCommand(initial, commandB),
    ]);
    expect(candidateA.state.eventSequence).toBe(1);
    expect(candidateB.state.eventSequence).toBe(1);
    expect(initial.eventSequence).toBe(0);

    await expect(applySessionCommand(candidateA.state, commandB)).rejects.toMatchObject({
      code: "CONFLICT",
    });
    const retryB = await applySessionCommand(candidateA.state, {
      ...commandB,
      expectedEventSequence: 1,
    });
    expect(retryB.state.activeTurn?.turnId).toBe("turn_a");
    expect(retryB.state.queuedTurns.map((turn) => turn.turnId)).toEqual(["turn_b"]);
  });

  it("preserves FIFO under repeated deterministic admission/completion", async () => {
    for (let trial = 0; trial < 24; trial += 1) {
      let state = makeState();
      const count = (trial % 7) + 2;
      const admitted: string[] = [];
      for (let index = 0; index < count; index += 1) {
        const turnId = `turn_${trial}_${index}`;
        admitted.push(turnId);
        const result = await applySessionCommand(state, {
          kind: "enqueue_turn",
          commandId: `enqueue_${trial}_${index}`,
          expectedEventSequence: state.eventSequence,
          transactionTime: 1_700_000_000_000 + index,
          turnId,
          input: { message: turnId },
          inputDigest: await turnInputDigest({ message: turnId }),
          genesisCheckpoint: await genesis(state, turnId),
          turnLeaseGeneration: index + 1,
          leaseExpiresAt: 1_900_000_000_000 + index,
        });
        state = result.state;
      }

      const observed: string[] = [];
      while (state.activeTurn !== null) {
        const active = state.activeTurn;
        observed.push(active.turnId);
        const payloadBytes = new Uint8Array([trial, active.sequence]);
        const result = await applySessionCommand(state, {
          kind: "commit_engine_step",
          commandId: `complete_${trial}_${active.sequence}`,
          expectedEventSequence: state.eventSequence,
          turnId: active.turnId,
          fence: {
            turnLeaseGeneration: active.turnLeaseGeneration,
            placementGeneration: state.placementGeneration,
            sandboxGeneration: state.sandboxGeneration,
            authorizationGeneration: state.authorizationGeneration,
          },
          transactionTime: 1_700_000_000_000 + active.sequence,
          consumedSettlementEffectId: null,
          effectIdentity: null,
          step: {
            kind: "turn_complete",
            checkpoint: {
              kind: "engine",
              engineKind: state.engineKind,
              adapterAbiVersion: state.adapterAbiVersion,
              checkpointSchemaVersion: state.checkpointSchemaVersion,
              runtimeRevisionDigest: state.runtimeRevisionDigest,
              sessionId: state.sessionId,
              turnId: active.turnId,
              checkpointSequence: 1,
              predecessorDigest: await checkpointDigest(active.checkpoint),
              payloadEncoding: "opaque-v1",
              payloadBytes,
              payloadDigest: await digestBytes(payloadBytes),
            },
            result: null,
          },
        });
        state = result.state;
        expect(() => assertSessionInvariants(state)).not.toThrow();
      }
      expect(observed).toEqual(admitted);
      expect(state.terminalTurns.map((turn) => turn.status)).toEqual(
        admitted.map(() => "completed"),
      );
    }
  });
});
