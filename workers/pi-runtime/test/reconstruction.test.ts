import { describe, expect, it } from "vitest";

import {
  LowLevelPiAgentEngine,
  createOpaqueTurnAuthority,
  type AgentCoreFactory,
} from "../src/index.ts";
import { genesis, identity, successSettlement } from "./helpers.ts";

const authority = () => createOpaqueTurnAuthority(new Uint8Array([17]));

const replaySafeCore: AgentCoreFactory = () => ({
  async advance(context) {
    if (context.input.kind === "turn_start") {
      return {
        kind: "model_request",
        state: { programCounter: "model_requested" },
        request: {
          service: "model",
          operation: "complete",
          replayPolicy: "idempotency-key",
          payload: { prompt: context.input.input },
        },
      };
    }
    if (
      context.input.kind === "effect_settlement" &&
      (context.state as { programCounter?: unknown }).programCounter === "model_requested"
    ) {
      return {
        kind: "tool_requests",
        state: { programCounter: "tools_requested" },
        requests: [
          {
            service: "external-tool",
            operation: "first",
            replayPolicy: "safe",
            payload: { ordinal: 0 },
          },
          {
            service: "external-tool",
            operation: "second",
            replayPolicy: "safe",
            payload: { ordinal: 1 },
          },
        ],
      };
    }
    if (context.input.kind === "tool_settlements") {
      return {
        kind: "turn_complete",
        state: { programCounter: "done" },
        result: { count: context.input.results.length },
      };
    }
    return {
      kind: "turn_error",
      state: { programCounter: "invalid" },
      error: { code: "INVALID_PROGRAM_COUNTER", message: "invalid state", retryable: false },
    };
  },
});

describe("checkpoint-only Worker reconstruction", () => {
  it("does not let AgentCore instance memory become a second program counter", async () => {
    const factory: AgentCoreFactory = () => {
      let hiddenCalls = 0;
      return {
        async advance() {
          hiddenCalls += 1;
          return {
            kind: "checkpoint_only",
            state: { hiddenCalls },
          };
        },
      };
    };
    const warm = new LowLevelPiAgentEngine(identity("session_hidden_state"), factory);
    const checkpoint = await genesis(warm);
    await warm.step({ authority: authority(), checkpoint });
    const warmReplay = await warm.step({ authority: authority(), checkpoint });

    const cold = new LowLevelPiAgentEngine(identity("session_hidden_state"), factory);
    const coldReplay = await cold.step({ authority: authority(), checkpoint });
    expect(warmReplay).toEqual(coldReplay);
  });

  it("reconstructs the same next durable action without a generator or local journal", async () => {
    const original = new LowLevelPiAgentEngine(identity("session_replay"), replaySafeCore);
    const firstCheckpoint = await genesis(original);
    const first = await original.step({ authority: authority(), checkpoint: firstCheckpoint });
    if (first.kind !== "effect_request") throw new Error("expected model request");

    const coldReplay = new LowLevelPiAgentEngine(identity("session_replay"), replaySafeCore);
    const replayedFirst = await coldReplay.step({
      authority: authority(),
      checkpoint: firstCheckpoint,
    });
    expect(replayedFirst).toEqual(first);

    const settlement = successSettlement(first.request.requestDigest, { toolCalls: 2 });
    const warmNext = await original.step({
      authority: authority(),
      checkpoint: first.checkpoint,
      settlement,
    });
    const coldAfterSettlement = new LowLevelPiAgentEngine(
      identity("session_replay"),
      replaySafeCore,
    );
    const replayedNext = await coldAfterSettlement.step({
      authority: authority(),
      checkpoint: first.checkpoint,
      settlement,
    });
    expect(replayedNext).toEqual(warmNext);
    expect(replayedNext).toMatchObject({
      kind: "effect_request",
      request: { operation: "first" },
    });
  });
});
