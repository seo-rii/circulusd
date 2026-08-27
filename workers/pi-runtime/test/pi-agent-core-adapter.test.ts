import {
  decodeCanonicalCbor,
  type NormalizedValue,
} from "@circulusd/protocol-types";
import { describe, expect, it } from "vitest";

import {
  LowLevelPiAgentEngine,
  createOpaqueTurnAuthority,
  createPiAgentCoreFactory,
  createPiAgentCoreInitialState,
  type PiAgentCoreModelConfiguration,
} from "../src/index.ts";
import { identity, successSettlement } from "./helpers.ts";

const MODEL = {
  id: "circulusd-test-model",
  api: "circulusd-model-gateway",
  provider: "circulusd",
  reasoning: false,
  input: ["text"],
  contextWindow: 8_192,
  maxTokens: 1_024,
} as const;

const USAGE = {
  input: 1,
  output: 1,
  cacheRead: 0,
  cacheWrite: 0,
  totalTokens: 2,
  cost: {
    input: 0,
    output: 0,
    cacheRead: 0,
    cacheWrite: 0,
    total: 0,
  },
} as const;

function makeEngine(
  sessionId: string,
  model: PiAgentCoreModelConfiguration = MODEL,
): LowLevelPiAgentEngine {
  return new LowLevelPiAgentEngine(
    identity(sessionId),
    createPiAgentCoreFactory({
      systemPrompt: "You are a deterministic test agent.",
      model,
    }),
  );
}

async function makeGenesis(engine: LowLevelPiAgentEngine, turnId: string) {
  return engine.createGenesisCheckpoint({
    turnId,
    input: { prompt: "hello", timestamp: 1_700_000_000_000 },
    initialCoreState: createPiAgentCoreInitialState(),
  });
}

function authority() {
  return createOpaqueTurnAuthority(new Uint8Array([1, 2, 3]));
}

function assistantMessage(
  content: readonly NormalizedValue[],
  stopReason: "stop" | "toolUse" | "aborted" | "error" = "stop",
  model: string = MODEL.id,
  usage: NormalizedValue = USAGE,
  metadata: Readonly<Record<string, NormalizedValue>> = {},
): NormalizedValue {
  return {
    version: 1,
    message: {
      role: "assistant",
      content: [...content],
      api: MODEL.api,
      provider: MODEL.provider,
      model,
      usage,
      stopReason,
      timestamp: 1_700_000_000_001,
      ...(stopReason === "aborted" || stopReason === "error"
        ? { errorMessage: `model ${stopReason}` }
        : {}),
      ...metadata,
    },
  };
}

describe("pinned Pi Agent Core bounded adapter", () => {
  it("emits one real Pi model boundary and completes from a durable settlement after reconstruction", async () => {
    const sessionId = "session_real_pi_model";
    const original = makeEngine(sessionId);
    const genesis = await makeGenesis(original, "turn_real_pi_model");

    const first = await original.step({ authority: authority(), checkpoint: genesis });
    expect(first).toMatchObject({
      kind: "effect_request",
      request: {
        service: "model",
        operation: "complete",
        replayPolicy: "never",
        payload: {
          protocol: "pi-agent-core",
          version: 1,
          packageVersion: "0.84.3",
          model: MODEL,
          context: {
            systemPrompt: "You are a deterministic test agent.",
            messages: [{ role: "user", content: "hello", timestamp: 1_700_000_000_000 }],
            tools: [],
          },
        },
      },
    });
    if (first.kind !== "effect_request") throw new Error("expected model request");

    const checkpointPayload = decodeCanonicalCbor(first.checkpoint.payloadBytes) as {
      readonly coreState?: unknown;
    };
    expect(checkpointPayload.coreState).toEqual({
      version: 1,
      phase: "waiting_model",
      messages: [{ role: "user", content: "hello", timestamp: 1_700_000_000_000 }],
    });

    const settlement = successSettlement(
      first.request.requestDigest,
      assistantMessage([{ type: "text", text: "hello back" }]),
    );
    const reconstructed = makeEngine(sessionId);
    const completed = await reconstructed.step({
      authority: authority(),
      checkpoint: first.checkpoint,
      settlement,
    });

    expect(completed).toMatchObject({
      kind: "turn_complete",
      result: {
        version: 1,
        message: {
          role: "assistant",
          content: [{ type: "text", text: "hello back" }],
          stopReason: "stop",
        },
      },
    });
  });

  it("normally drains its internal aborted capture stream and retains no live continuation", async () => {
    const sessionId = "session_real_pi_capture";
    const engine = makeEngine(sessionId);
    const checkpoint = await makeGenesis(engine, "turn_real_pi_capture");

    const first = await engine.step({ authority: authority(), checkpoint });
    expect(first.kind).toBe("effect_request");
    await expect(engine.abortTurn("turn_real_pi_capture")).resolves.toBeUndefined();

    const cold = makeEngine(sessionId);
    await expect(
      cold.step({ authority: authority(), checkpoint }),
    ).resolves.toEqual(first);
  });

  it("produces byte-identical versioned checkpoints for identical replay", async () => {
    const left = makeEngine("session_real_pi_deterministic");
    const right = makeEngine("session_real_pi_deterministic");
    const leftGenesis = await makeGenesis(left, "turn_real_pi_deterministic");
    const rightGenesis = await makeGenesis(right, "turn_real_pi_deterministic");

    const [leftBoundary, rightBoundary] = await Promise.all([
      left.step({ authority: authority(), checkpoint: leftGenesis }),
      right.step({ authority: authority(), checkpoint: rightGenesis }),
    ]);

    expect(rightBoundary).toEqual(leftBoundary);
    expect(rightBoundary.checkpoint.payloadBytes).toEqual(leftBoundary.checkpoint.payloadBytes);
  });

  it("fails closed when a settled Pi response contains a tool call", async () => {
    const sessionId = "session_real_pi_tool_denied";
    const original = makeEngine(sessionId);
    const first = await original.step({
      authority: authority(),
      checkpoint: await makeGenesis(original, "turn_real_pi_tool_denied"),
    });
    if (first.kind !== "effect_request") throw new Error("expected model request");

    const settlement = successSettlement(
      first.request.requestDigest,
      assistantMessage(
        [{ type: "toolCall", id: "call_1", name: "echo", arguments: { text: "hello" } }],
        "toolUse",
      ),
    );
    const denied = await makeEngine(sessionId).step({
      authority: authority(),
      checkpoint: first.checkpoint,
      settlement,
    });

    expect(denied).toMatchObject({
      kind: "turn_error",
      error: {
        code: "PI_TOOL_CALL_UNSUPPORTED",
        retryable: false,
      },
    });
  });

  it("rejects a settlement attributed to a different model", async () => {
    const sessionId = "session_real_pi_model_mismatch";
    const original = makeEngine(sessionId);
    const first = await original.step({
      authority: authority(),
      checkpoint: await makeGenesis(original, "turn_real_pi_model_mismatch"),
    });
    if (first.kind !== "effect_request") throw new Error("expected model request");

    const denied = await makeEngine(sessionId).step({
      authority: authority(),
      checkpoint: first.checkpoint,
      settlement: successSettlement(
        first.request.requestDigest,
        assistantMessage([{ type: "text", text: "wrong model" }], "stop", "other-model"),
      ),
    });

    expect(denied).toMatchObject({
      kind: "turn_error",
      error: {
        code: "PI_MODEL_RESPONSE_MISMATCH",
        retryable: false,
      },
    });
  });

  it("accepts bounded thinking content for a configured reasoning model", async () => {
    const reasoningModel = { ...MODEL, reasoning: true } as const;
    const sessionId = "session_real_pi_reasoning";
    const original = makeEngine(sessionId, reasoningModel);
    const first = await original.step({
      authority: authority(),
      checkpoint: await makeGenesis(original, "turn_real_pi_reasoning"),
    });
    if (first.kind !== "effect_request") throw new Error("expected model request");

    const completed = await makeEngine(sessionId, reasoningModel).step({
      authority: authority(),
      checkpoint: first.checkpoint,
      settlement: successSettlement(
        first.request.requestDigest,
        assistantMessage([
          { type: "thinking", thinking: "bounded reasoning" },
          { type: "text", text: "answer" },
        ]),
      ),
    });

    expect(completed).toMatchObject({
      kind: "turn_complete",
      result: {
        message: {
          content: [
            { type: "thinking", thinking: "bounded reasoning" },
            { type: "text", text: "answer" },
          ],
        },
      },
    });
  });

  it("rejects negative model usage before it reaches durable state", async () => {
    const sessionId = "session_real_pi_usage_invalid";
    const original = makeEngine(sessionId);
    const first = await original.step({
      authority: authority(),
      checkpoint: await makeGenesis(original, "turn_real_pi_usage_invalid"),
    });
    if (first.kind !== "effect_request") throw new Error("expected model request");

    const denied = await makeEngine(sessionId).step({
      authority: authority(),
      checkpoint: first.checkpoint,
      settlement: successSettlement(
        first.request.requestDigest,
        assistantMessage(
          [{ type: "text", text: "invalid usage" }],
          "stop",
          MODEL.id,
          { ...USAGE, totalTokens: -1 },
        ),
      ),
    });

    expect(denied).toMatchObject({
      kind: "turn_error",
      error: {
        code: "PI_MODEL_RESPONSE_INVALID",
        retryable: false,
      },
    });
  });

  it("rejects usage fields outside the pinned Pi response schema", async () => {
    const sessionId = "session_real_pi_usage_unknown";
    const original = makeEngine(sessionId);
    const first = await original.step({
      authority: authority(),
      checkpoint: await makeGenesis(original, "turn_real_pi_usage_unknown"),
    });
    if (first.kind !== "effect_request") throw new Error("expected model request");

    const denied = await makeEngine(sessionId).step({
      authority: authority(),
      checkpoint: first.checkpoint,
      settlement: successSettlement(
        first.request.requestDigest,
        assistantMessage(
          [{ type: "text", text: "unknown usage" }],
          "stop",
          MODEL.id,
          { ...USAGE, cacheRead5m: 1 },
        ),
      ),
    });

    expect(denied).toMatchObject({
      kind: "turn_error",
      error: {
        code: "CORE_OUTPUT_INVALID",
        retryable: false,
      },
    });
  });

  it("rejects malformed optional model metadata before it reaches durable state", async () => {
    const sessionId = "session_real_pi_metadata_invalid";
    const original = makeEngine(sessionId);
    const first = await original.step({
      authority: authority(),
      checkpoint: await makeGenesis(original, "turn_real_pi_metadata_invalid"),
    });
    if (first.kind !== "effect_request") throw new Error("expected model request");

    const denied = await makeEngine(sessionId).step({
      authority: authority(),
      checkpoint: first.checkpoint,
      settlement: successSettlement(
        first.request.requestDigest,
        assistantMessage(
          [{ type: "text", text: "invalid metadata" }],
          "stop",
          MODEL.id,
          USAGE,
          { endTurn: "yes" },
        ),
      ),
    });

    expect(denied).toMatchObject({
      kind: "turn_error",
      error: {
        code: "PI_MODEL_RESPONSE_INVALID",
        retryable: false,
      },
    });
  });

  it.each(["aborted", "error"] as const)(
    "maps a settled Pi %s response to a deterministic terminal error",
    async (stopReason) => {
      const sessionId = `session_real_pi_${stopReason}`;
      const original = makeEngine(sessionId);
      const first = await original.step({
        authority: authority(),
        checkpoint: await makeGenesis(original, `turn_real_pi_${stopReason}`),
      });
      if (first.kind !== "effect_request") throw new Error("expected model request");

      const settlement = successSettlement(
        first.request.requestDigest,
        assistantMessage([], stopReason),
      );
      const cold = makeEngine(sessionId);
      const firstFailure = await cold.step({
        authority: authority(),
        checkpoint: first.checkpoint,
        settlement,
      });
      const replayedFailure = await makeEngine(sessionId).step({
        authority: authority(),
        checkpoint: first.checkpoint,
        settlement,
      });

      expect(firstFailure).toMatchObject({
        kind: "turn_error",
        error: {
          code: stopReason === "aborted" ? "PI_MODEL_ABORTED" : "PI_MODEL_ERROR",
          message: `model ${stopReason}`,
          retryable: false,
        },
      });
      expect(replayedFailure).toEqual(firstFailure);
    },
  );
});
