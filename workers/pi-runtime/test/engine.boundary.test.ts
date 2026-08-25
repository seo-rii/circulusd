import {
  digestStructuredValue,
  validateAgentCheckpoint,
  validateEngineStepResult,
} from "@circulusd/protocol-types";
import { describe, expect, it, vi } from "vitest";

import {
  LowLevelPiAgentEngine,
  PiRuntimeError,
  createOpaqueTurnAuthority,
} from "../src/index.ts";
import { genesis, identity, scriptedCore, successSettlement } from "./helpers.ts";

describe("bounded low-level AgentEngine boundary", () => {
  it("reuses a session engine for a later turn after the prior turn is terminal", async () => {
    const core = scriptedCore((context) => ({
      kind: "turn_complete",
      state: { completedTurn: context.turnId },
      result: { turnId: context.turnId },
    }));
    const engine = new LowLevelPiAgentEngine(identity("session_many_turns"), core.factory);

    const first = await engine.step({
      authority: createOpaqueTurnAuthority(new Uint8Array([1])),
      checkpoint: await genesis(engine, "turn_01"),
    });
    expect(first).toMatchObject({ kind: "turn_complete", result: { turnId: "turn_01" } });

    const second = await engine.step({
      authority: createOpaqueTurnAuthority(new Uint8Array([2])),
      checkpoint: await genesis(engine, "turn_02"),
    });
    expect(second).toMatchObject({ kind: "turn_complete", result: { turnId: "turn_02" } });
    expect(core.contexts).toHaveLength(2);
  });

  it("returns one checkpoint and one durable boundary per invocation", async () => {
    const core = scriptedCore((context, call) => {
      if (call === 1) {
        expect(context.input).toEqual({ kind: "turn_start", input: { prompt: "hello" } });
        return {
          kind: "model_request",
          state: { phase: "waiting_model" },
          assistantDeltas: [{ text: "thinking" }],
          request: {
            service: "model",
            operation: "complete",
            replayPolicy: "idempotency-key",
            payload: { messages: ["hello"] },
          },
        };
      }
      expect(context.input.kind).toBe("effect_settlement");
      return {
        kind: "checkpoint_only",
        state: { phase: "after_model" },
      };
    });
    const engine = new LowLevelPiAgentEngine(identity("session_a"), core.factory);
    const checkpoint = await genesis(engine);
    const emitDelta = vi.fn();

    const first = await engine.step({
      authority: createOpaqueTurnAuthority(new Uint8Array([1, 2, 3])),
      checkpoint,
      emitDelta,
    });

    expect(first.kind).toBe("effect_request");
    expect(Reflect.ownKeys(first).sort()).toEqual(["checkpoint", "kind", "request"]);
    expect(emitDelta).toHaveBeenCalledOnce();
    expect(emitDelta).toHaveBeenCalledWith({ text: "thinking" });
    await expect(validateAgentCheckpoint(first.checkpoint)).resolves.toEqual(first.checkpoint);
    await expect(validateEngineStepResult(first)).resolves.toEqual(first);
    expect(first.checkpoint.kind).toBe("engine");
    expect(first.checkpoint.checkpointSequence).toBe(1);
    expect(first.checkpoint.predecessorDigest).toBe(
      await digestStructuredValue("circulusd.session.agent-checkpoint", 1, checkpoint),
    );

    if (first.kind !== "effect_request") {
      throw new Error("expected effect request");
    }
    await expect(
      engine.step({
        authority: createOpaqueTurnAuthority(new Uint8Array([4])),
        checkpoint: first.checkpoint,
      }),
    ).rejects.toMatchObject({ code: "SETTLEMENT_REQUIRED" });

    const second = await engine.step({
      authority: createOpaqueTurnAuthority(new Uint8Array([5])),
      checkpoint: first.checkpoint,
      settlement: successSettlement(first.request.requestDigest, { text: "answer" }),
    });
    expect(second.kind).toBe("checkpoint");
    expect(second.checkpoint.checkpointSequence).toBe(2);
    expect(core.contexts).toHaveLength(2);

    await expect(
      engine.step({
        authority: createOpaqueTurnAuthority(new Uint8Array([6])),
        checkpoint: second.checkpoint,
        settlement: successSettlement(first.request.requestDigest, { text: "answer" }),
      }),
    ).rejects.toMatchObject({ code: "UNEXPECTED_SETTLEMENT" });
  });

  it("rejects a settlement that does not bind the pending request", async () => {
    const core = scriptedCore(() => ({
      kind: "model_request",
      state: null,
      request: {
        service: "model",
        operation: "complete",
        replayPolicy: "safe",
        payload: {},
      },
    }));
    const engine = new LowLevelPiAgentEngine(identity("session_a"), core.factory);
    const first = await engine.step({
      authority: createOpaqueTurnAuthority(new Uint8Array([1])),
      checkpoint: await genesis(engine),
    });
    if (first.kind !== "effect_request") {
      throw new Error("expected effect request");
    }

    await expect(
      engine.step({
        authority: createOpaqueTurnAuthority(new Uint8Array([2])),
        checkpoint: first.checkpoint,
        settlement: successSettlement(`sha256:${"b".repeat(64)}`, {}),
      }),
    ).rejects.toMatchObject({ code: "SETTLEMENT_MISMATCH" });
    expect(core.contexts).toHaveLength(1);
  });

  it("rejects malformed context and checkpoint envelopes before invoking the core", async () => {
    const core = scriptedCore(() => ({ kind: "checkpoint_only", state: null }));
    const engine = new LowLevelPiAgentEngine(identity("session_a"), core.factory);
    const checkpoint = await genesis(engine);

    await expect(
      engine.step({
        authority: createOpaqueTurnAuthority(new Uint8Array([1])),
        checkpoint: { ...checkpoint, sessionId: "session_b" },
      }),
    ).rejects.toBeInstanceOf(PiRuntimeError);
    await expect(
      engine.step({
        authority: createOpaqueTurnAuthority(new Uint8Array([1])),
        checkpoint,
        unexpected: true,
      } as never),
    ).rejects.toMatchObject({ code: "INVALID_CONTEXT" });
    expect(core.contexts).toHaveLength(0);
  });

  it("redacts opaque authority bytes and never passes authority into AgentCore", async () => {
    const core = scriptedCore((context) => {
      expect(Reflect.ownKeys(context)).not.toContain("authority");
      return { kind: "checkpoint_only", state: null };
    });
    const engine = new LowLevelPiAgentEngine(identity("session_a"), core.factory);
    const authority = createOpaqueTurnAuthority(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
    expect(String(authority)).toBe("[OpaqueTurnAuthority REDACTED]");
    expect(JSON.stringify(authority)).not.toContain("deadbeef");

    await engine.step({ authority, checkpoint: await genesis(engine) });
  });
});
