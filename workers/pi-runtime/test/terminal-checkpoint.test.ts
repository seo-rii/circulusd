import {
  digestStructuredValue,
  encodeCanonicalCbor,
  validateAgentCheckpoint,
  validateEngineStepResult,
} from "@circulusd/protocol-types";
import { describe, expect, it } from "vitest";

import { LowLevelPiAgentEngine, createOpaqueTurnAuthority } from "../src/index.ts";
import { decodeCanonicalCheckpointPayload } from "../src/codec.ts";
import { identity, scriptedCore } from "./helpers.ts";

const authority = () => createOpaqueTurnAuthority(new Uint8Array([19]));
const budgets = [512, 1_048_576];
const scenarios = budgets.flatMap((budget) =>
  (["complete", "invalid"] as const).map((mode) => ({ budget, mode })),
);
const coreStates = new Map<string, string>();

function checkpointState(coreState: string | null, terminal = false) {
  return {
    version: 1,
    status: terminal ? "terminal" : "ready",
    coreState,
    turnInput: null,
    beforeTurnCompleted: true,
    awaiting: null,
    pendingTools: [],
    completedTools: [],
    terminalCode: terminal ? "EXTENSION_OUTPUT_INVALID" : null,
  };
}

function largestCoreState(budget: number, terminal = false): string {
  const key = `${budget}:${terminal}`;
  const cached = coreStates.get(key);
  if (cached !== undefined) return cached;

  // Start with the empty envelope, then correct for the CBOR string length
  // header. The large fixtures need only a few encodes, rather than a binary
  // search repeatedly encoding nearly 1 MiB for every scenario.
  const envelopeBytes = encodeCanonicalCbor(checkpointState("", terminal)).byteLength;
  let state = "x".repeat(budget - envelopeBytes);
  let size = encodeCanonicalCbor(checkpointState(state, terminal)).byteLength;
  while (size > budget) {
    state = state.slice(0, state.length - (size - budget));
    size = encodeCanonicalCbor(checkpointState(state, terminal)).byteLength;
  }
  while (size < budget) {
    const next = `${state}x`;
    const nextSize = encodeCanonicalCbor(checkpointState(next, terminal)).byteLength;
    if (nextSize > budget) break;
    state = next;
    size = nextSize;
  }
  coreStates.set(key, state);
  return state;
}

function coreFor(state: string, mode: "complete" | "invalid") {
  return scriptedCore((context) => {
    if (context.input.kind === "turn_start") return { kind: "checkpoint_only", state };
    return mode === "complete"
      ? { kind: "turn_complete", state: context.state, result: 0 }
      : { kind: "checkpoint_only", state: null, hidden: true } as never;
  });
}

describe("terminal checkpoint capacity", () => {
  it.each(scenarios)("terminates a legacy full $budget-byte checkpoint after $mode output", async ({ budget, mode }) => {
    const state = largestCoreState(budget);
    const core = coreFor(state, mode);
    const runtimeIdentity = identity(`session_legacy_${budget}_${mode}`);
    // This same-ABI checkpoint is produced by the real engine with a larger
    // budget, reproducing already committed checkpoints without new headroom.
    const producer = new LowLevelPiAgentEngine(runtimeIdentity, core.factory, {
      budgets: { maxCheckpointBytes: budget + 256 },
    });
    const produced = await producer.step({
      authority: authority(),
      checkpoint: await producer.createGenesisCheckpoint({
        turnId: "turn_legacy",
        input: 0,
        initialCoreState: null,
      }),
    });
    expect(produced.kind).toBe("checkpoint");
    expect(produced.checkpoint.payloadBytes.byteLength).toBe(budget);
    await validateAgentCheckpoint(produced.checkpoint);

    const consumer = new LowLevelPiAgentEngine(runtimeIdentity, core.factory, {
      budgets: { maxCheckpointBytes: budget },
    });
    const result = await consumer.step({ authority: authority(), checkpoint: produced.checkpoint });
    expect(result).toMatchObject({
      kind: "turn_error",
      error: {
        code: mode === "invalid" ? "CORE_OUTPUT_INVALID" : "CORE_EXECUTION_FAILED",
        retryable: false,
      },
    });
    expect(result.checkpoint.payloadBytes.byteLength).toBeLessThanOrEqual(budget);
    expect(result.checkpoint.checkpointSequence).toBe(produced.checkpoint.checkpointSequence + 1);
    expect(result.checkpoint.predecessorDigest).toBe(
      await digestStructuredValue("circulusd.session.agent-checkpoint", 1, produced.checkpoint),
    );
    expect(decodeCanonicalCheckpointPayload(result.checkpoint.payloadBytes, budget)).toMatchObject({
      status: "terminal",
      coreState: null,
    });
    const validated = await validateEngineStepResult(result);
    expect(validated.checkpoint.payloadDigest).toBe(result.checkpoint.payloadDigest);
    await expect(consumer.step({ authority: authority(), checkpoint: result.checkpoint })).rejects.toMatchObject({
      code: "ENGINE_TERMINAL",
    });
    const replay = new LowLevelPiAgentEngine(runtimeIdentity, core.factory, {
      budgets: { maxCheckpointBytes: budget },
    });
    await expect(replay.step({ authority: authority(), checkpoint: produced.checkpoint })).resolves.toEqual(result);
  }, 30_000);

  it.each(scenarios)("retains committed core state with reserved $budget-byte capacity after $mode output", async ({ budget, mode }) => {
    const state = largestCoreState(budget, true);
    const core = coreFor(state, mode);
    const runtimeIdentity = identity(`session_reserved_${budget}_${mode}`);
    const producer = new LowLevelPiAgentEngine(runtimeIdentity, core.factory, {
      budgets: { maxCheckpointBytes: budget },
    });
    const produced = await producer.step({
      authority: authority(),
      checkpoint: await producer.createGenesisCheckpoint({
        turnId: "turn_reserved",
        input: 0,
        initialCoreState: null,
      }),
    });
    expect(produced.kind).toBe("checkpoint");
    const consumer = new LowLevelPiAgentEngine(runtimeIdentity, core.factory, {
      budgets: { maxCheckpointBytes: budget },
    });
    const result = await consumer.step({ authority: authority(), checkpoint: produced.checkpoint });
    expect(result).toMatchObject(mode === "complete"
      ? { kind: "turn_complete", result: 0 }
      : { kind: "turn_error", error: { code: "CORE_OUTPUT_INVALID", retryable: false } });
    expect(result.checkpoint.payloadBytes.byteLength).toBeLessThanOrEqual(budget);
    expect(decodeCanonicalCheckpointPayload(result.checkpoint.payloadBytes, budget)).toMatchObject({
      status: "terminal",
      coreState: state,
    });
    const validated = await validateEngineStepResult(result);
    expect(validated.checkpoint.payloadDigest).toBe(result.checkpoint.payloadDigest);
  }, 30_000);

  it.each(budgets)("rejects new nonterminal state without terminal headroom at %i bytes", async (budget) => {
    const state = largestCoreState(budget);
    const core = scriptedCore(() => ({ kind: "checkpoint_only", state }));
    const engine = new LowLevelPiAgentEngine(identity(`session_headroom_${budget}`), core.factory, {
      budgets: { maxCheckpointBytes: budget },
    });
    await expect(engine.createGenesisCheckpoint({
      turnId: "turn_headroom",
      input: 0,
      initialCoreState: state,
    })).rejects.toMatchObject({ code: "INVALID_CHECKPOINT" });
    const result = await engine.step({
      authority: authority(),
      checkpoint: await engine.createGenesisCheckpoint({
        turnId: "turn_headroom",
        input: 0,
        initialCoreState: null,
      }),
    });
    expect(result).toMatchObject({ kind: "turn_error", error: { code: "CORE_EXECUTION_FAILED" } });
    expect(decodeCanonicalCheckpointPayload(result.checkpoint.payloadBytes, budget)).toMatchObject({
      status: "terminal",
      coreState: null,
    });
    await validateEngineStepResult(result);
  }, 30_000);

  it("rejects a configured budget that cannot encode a minimal terminal fault", () => {
    const minimum = encodeCanonicalCbor(checkpointState(null, true)).byteLength;
    const core = scriptedCore(() => ({ kind: "checkpoint_only", state: null }));
    expect(() => new LowLevelPiAgentEngine(identity("session_minimum"), core.factory, {
      budgets: { maxCheckpointBytes: minimum - 1 },
    })).toThrow(expect.objectContaining({ code: "INVALID_CONFIGURATION" }));
    expect(() => new LowLevelPiAgentEngine(identity("session_minimum"), core.factory, {
      budgets: { maxCheckpointBytes: minimum },
    })).not.toThrow();
  });
});
