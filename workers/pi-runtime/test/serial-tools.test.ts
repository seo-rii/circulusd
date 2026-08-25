import { describe, expect, it } from "vitest";

import {
  LowLevelPiAgentEngine,
  createOpaqueTurnAuthority,
  type AgentCore,
} from "../src/index.ts";
import { genesis, identity, scriptedCore, successSettlement } from "./helpers.ts";

const authority = () => createOpaqueTurnAuthority(new Uint8Array([7]));

describe("multi-tool serial checkpoint queue", () => {
  it("assigns a unique durable occurrence to byte-identical tool requests", async () => {
    const core = scriptedCore(() => ({
      kind: "tool_requests",
      state: { phase: "tools" },
      requests: [0, 1].map(() => ({
        service: "external-tool" as const,
        operation: "repeat",
        replayPolicy: "idempotency-key" as const,
        payload: { value: "same" },
      })),
    }));
    const engine = new LowLevelPiAgentEngine(identity("session_identical_tools"), core.factory);

    const first = await engine.step({
      authority: authority(),
      checkpoint: await genesis(engine),
    });
    if (first.kind !== "effect_request") throw new Error("expected first request");
    const second = await engine.step({
      authority: authority(),
      checkpoint: first.checkpoint,
      settlement: successSettlement(first.request.requestDigest, { ok: true }),
    });
    if (second.kind !== "effect_request") throw new Error("expected second request");

    expect(first.request.parentOperationId).toBe(second.request.parentOperationId);
    expect([first.request.ordinal, second.request.ordinal]).toEqual([0, 1]);
    expect(first.request.requestDigest).not.toBe(second.request.requestDigest);
    await expect(
      engine.step({
        authority: authority(),
        checkpoint: second.checkpoint,
        settlement: successSettlement(first.request.requestDigest, { replayed: true }),
      }),
    ).rejects.toMatchObject({ code: "SETTLEMENT_MISMATCH" });
  });

  it("emits provider-ordered tool calls one at a time and consumes each settlement once", async () => {
    const core = scriptedCore((context, call) => {
      if (call === 1) {
        return {
          kind: "model_request",
          state: { phase: "model" },
          request: {
            service: "model",
            operation: "complete",
            replayPolicy: "idempotency-key",
            payload: {},
          },
        };
      }
      if (call === 2) {
        expect(context.input.kind).toBe("effect_settlement");
        return {
          kind: "tool_requests",
          state: { phase: "tools" },
          requests: ["alpha", "beta", "gamma"].map((operation, ordinal) => ({
            service: "external-tool" as const,
            operation,
            replayPolicy: "idempotency-key" as const,
            payload: { ordinal },
            parentOperationId: "parallel_group_01",
            ordinal,
          })),
        };
      }
      expect(call).toBe(3);
      expect(context.input).toMatchObject({ kind: "tool_settlements" });
      if (context.input.kind !== "tool_settlements") {
        throw new Error("expected tool settlements");
      }
      expect(context.input.results.map((entry) => entry.request.operation)).toEqual([
        "alpha",
        "beta",
        "gamma",
      ]);
      expect(context.input.results.map((entry) => entry.settlement)).toEqual([
        { kind: "success", result: { value: "A" } },
        { kind: "success", result: { value: "B" } },
        { kind: "success", result: { value: "C" } },
      ]);
      return { kind: "turn_complete", state: { phase: "done" }, result: { ok: true } };
    });
    const engine = new LowLevelPiAgentEngine(identity("session_tools"), core.factory);

    const model = await engine.step({ authority: authority(), checkpoint: await genesis(engine) });
    if (model.kind !== "effect_request") throw new Error("expected model request");
    const alpha = await engine.step({
      authority: authority(),
      checkpoint: model.checkpoint,
      settlement: successSettlement(model.request.requestDigest, { toolCalls: 3 }),
    });
    if (alpha.kind !== "effect_request") throw new Error("expected alpha request");
    expect(alpha.request.operation).toBe("alpha");

    const beta = await engine.step({
      authority: authority(),
      checkpoint: alpha.checkpoint,
      settlement: successSettlement(alpha.request.requestDigest, { value: "A" }),
    });
    if (beta.kind !== "effect_request") throw new Error("expected beta request");
    expect(beta.request.operation).toBe("beta");
    expect(core.contexts).toHaveLength(2);

    await expect(
      engine.step({
        authority: authority(),
        checkpoint: beta.checkpoint,
        settlement: successSettlement(alpha.request.requestDigest, { value: "A" }),
      }),
    ).rejects.toMatchObject({ code: "SETTLEMENT_MISMATCH" });

    const gamma = await engine.step({
      authority: authority(),
      checkpoint: beta.checkpoint,
      settlement: successSettlement(beta.request.requestDigest, { value: "B" }),
    });
    if (gamma.kind !== "effect_request") throw new Error("expected gamma request");
    expect(gamma.request.operation).toBe("gamma");
    expect(core.contexts).toHaveLength(2);

    const complete = await engine.step({
      authority: authority(),
      checkpoint: gamma.checkpoint,
      settlement: successSettlement(gamma.request.requestDigest, { value: "C" }),
    });
    expect(complete.kind).toBe("turn_complete");
    expect(core.contexts).toHaveLength(3);
  });

  it("rejects concurrent steps in one session while allowing Promise.all across sessions", async () => {
    const entered = Promise.withResolvers<void>();
    const gate = Promise.withResolvers<void>();
    let calls = 0;
    const factory = () =>
      ({
        async advance() {
          calls += 1;
          entered.resolve();
          await gate.promise;
          return { kind: "checkpoint_only", state: null } as const;
        },
      }) satisfies AgentCore;
    const engine = new LowLevelPiAgentEngine(identity("session_one"), factory);
    const checkpoint = await genesis(engine);
    const first = engine.step({ authority: authority(), checkpoint });
    const conflicting = engine.step({ authority: authority(), checkpoint });
    const concurrentResultsPromise = Promise.allSettled([first, conflicting]);
    await entered.promise;
    await Promise.resolve();
    gate.resolve();
    const concurrentResults = await concurrentResultsPromise;
    expect(calls).toBe(1);
    expect(concurrentResults).toEqual([
      expect.objectContaining({ status: "fulfilled", value: expect.objectContaining({ kind: "checkpoint" }) }),
      expect.objectContaining({ status: "rejected", reason: expect.objectContaining({ code: "STEP_IN_PROGRESS" }) }),
    ]);

    const makeIndependent = (sessionId: string) => {
      const core = scriptedCore(() => ({ kind: "checkpoint_only", state: { count: 1 } }));
      return new LowLevelPiAgentEngine(identity(sessionId), core.factory);
    };
    const left = makeIndependent("session_left");
    const right = makeIndependent("session_right");
    const [leftResult, rightResult] = await Promise.all([
      left.step({ authority: authority(), checkpoint: await genesis(left) }),
      right.step({ authority: authority(), checkpoint: await genesis(right) }),
    ]);
    expect(leftResult.checkpoint.sessionId).toBe("session_left");
    expect(rightResult.checkpoint.sessionId).toBe("session_right");
  });
});
