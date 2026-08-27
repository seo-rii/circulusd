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
  type ExtensionRegistration,
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

const TOOL_REGISTRY = [
  {
    name: "echo",
    description: "Echo text",
    parameters: {
      type: "object",
      properties: { text: { type: "string" } },
      required: ["text"],
      additionalProperties: false,
    },
    replayPolicy: "confirm",
  },
  {
    name: "sum",
    description: "Sum numbers",
    parameters: {
      type: "object",
      properties: { values: { type: "array", items: { type: "number" } } },
      required: ["values"],
      additionalProperties: false,
    },
    replayPolicy: "idempotency-key",
  },
] as const;

const ADVERTISED_TOOLS = TOOL_REGISTRY.map((tool) => ({
  name: tool.name,
  description: tool.description,
  parameters: tool.parameters,
}));

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
  registrations: readonly ExtensionRegistration[] = [],
): LowLevelPiAgentEngine {
  const engine = new LowLevelPiAgentEngine(
    { ...identity(sessionId), adapterAbiVersion: 2, checkpointSchemaVersion: 2 },
    createPiAgentCoreFactory({
      systemPrompt: "You are a deterministic test agent.",
      model,
      tools: TOOL_REGISTRY,
    }),
  );
  for (const registration of registrations) engine.registerExtension(registration);
  return engine;
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

async function makeSingleToolRequest(
  sessionId: string,
  turnId: string,
  argumentsValue: NormalizedValue = { text: "hi" },
  callId = "call_only",
) {
  const engine = makeEngine(sessionId);
  const model = await engine.step({
    authority: authority(),
    checkpoint: await makeGenesis(engine, turnId),
  });
  if (model.kind !== "effect_request") throw new Error("expected model request");
  const tool = await makeEngine(sessionId).step({
    authority: authority(),
    checkpoint: model.checkpoint,
    settlement: successSettlement(
      model.request.requestDigest,
      assistantMessage(
        [{ type: "toolCall", id: callId, name: "echo", arguments: argumentsValue }],
        "toolUse",
      ),
    ),
  });
  if (tool.kind !== "effect_request") throw new Error("expected tool request");
  return tool;
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
  it("rejects duplicate immutable tool registry names", () => {
    expect(() => createPiAgentCoreFactory({
      systemPrompt: "duplicate registry",
      model: MODEL,
      tools: [TOOL_REGISTRY[0], structuredClone(TOOL_REGISTRY[0])],
    })).toThrowError(/duplicate name echo/);
  });

  it("rejects construction under checkpoint schema version 1", async () => {
    const engine = new LowLevelPiAgentEngine(
      {
        ...identity("session_real_pi_schema_mismatch"),
        adapterAbiVersion: 2,
        checkpointSchemaVersion: 1,
      },
      createPiAgentCoreFactory({
        systemPrompt: "You are a deterministic test agent.",
        model: MODEL,
        tools: TOOL_REGISTRY,
      }),
    );
    const checkpoint = await makeGenesis(engine, "turn_real_pi_schema_mismatch");

    await expect(
      engine.step({ authority: authority(), checkpoint }),
    ).rejects.toMatchObject({ code: "INVALID_CONFIGURATION" });
  });

  it("rejects adapter ABI version 1 even with checkpoint schema version 2", async () => {
    const engine = new LowLevelPiAgentEngine(
      {
        ...identity("session_real_pi_abi_mismatch"),
        adapterAbiVersion: 1,
        checkpointSchemaVersion: 2,
      },
      createPiAgentCoreFactory({
        systemPrompt: "You are a deterministic test agent.",
        model: MODEL,
        tools: TOOL_REGISTRY,
      }),
    );
    const checkpoint = await makeGenesis(engine, "turn_real_pi_abi_mismatch");

    await expect(
      engine.step({ authority: authority(), checkpoint }),
    ).rejects.toMatchObject({ code: "INVALID_CONFIGURATION" });
  });

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
            tools: ADVERTISED_TOOLS,
          },
        },
      },
    });
    if (first.kind !== "effect_request") throw new Error("expected model request");

    const checkpointPayload = decodeCanonicalCbor(first.checkpoint.payloadBytes) as {
      readonly coreState?: unknown;
    };
    expect(checkpointPayload.coreState).toEqual({
      version: 2,
      phase: "waiting_model",
      messages: [{ role: "user", content: "hello", timestamp: 1_700_000_000_000 }],
      pendingToolCalls: [],
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

  it("emits settled Pi tool calls as ordered durable external-tool requests", async () => {
    const sessionId = "session_real_pi_tools";
    const original = makeEngine(sessionId);
    const first = await original.step({
      authority: authority(),
      checkpoint: await makeGenesis(original, "turn_real_pi_tools"),
    });
    if (first.kind !== "effect_request") throw new Error("expected model request");

    const settlement = successSettlement(
      first.request.requestDigest,
      assistantMessage(
        [
          { type: "toolCall", id: "call_1", name: "echo", arguments: { text: "hello" } },
          { type: "toolCall", id: "call_2", name: "sum", arguments: { values: [2, 3] } },
        ],
        "toolUse",
      ),
    );
    const tool = await makeEngine(sessionId).step({
      authority: authority(),
      checkpoint: first.checkpoint,
      settlement,
    });

    expect(tool).toMatchObject({
      kind: "effect_request",
      request: {
        service: "external-tool",
        operation: "call",
        replayPolicy: "confirm",
        ordinal: 0,
        payload: {
          protocol: "pi-agent-core",
          version: 1,
          toolCall: {
            id: "call_1",
            name: "echo",
            arguments: { text: "hello" },
          },
        },
      },
    });
    if (tool.kind !== "effect_request") throw new Error("expected first tool request");

    const secondTool = await makeEngine(sessionId).step({
      authority: authority(),
      checkpoint: tool.checkpoint,
      settlement: successSettlement(tool.request.requestDigest, {
        version: 1,
        toolCallId: "call_1",
        toolName: "echo",
        content: [{ type: "text", text: "hello" }],
        isError: false,
        timestamp: 1_700_000_000_002,
      }),
    });
    expect(secondTool).toMatchObject({
      kind: "effect_request",
      request: {
        service: "external-tool",
        operation: "call",
        replayPolicy: "idempotency-key",
        ordinal: 1,
        payload: {
          toolCall: {
            id: "call_2",
            name: "sum",
            arguments: { values: [2, 3] },
          },
        },
      },
    });
    if (secondTool.kind !== "effect_request") throw new Error("expected second tool request");

    const continuation = await makeEngine(sessionId).step({
      authority: authority(),
      checkpoint: secondTool.checkpoint,
      settlement: successSettlement(secondTool.request.requestDigest, {
        version: 1,
        toolCallId: "call_2",
        toolName: "sum",
        content: [{ type: "text", text: "5" }],
        details: { value: 5 },
        isError: false,
        timestamp: 1_700_000_000_003,
      }),
    });
    expect(continuation).toMatchObject({
      kind: "effect_request",
      request: {
        service: "model",
        operation: "complete",
        payload: {
          context: {
            tools: ADVERTISED_TOOLS,
            messages: [
              { role: "user", content: "hello" },
              {
                role: "assistant",
                content: [
                  { type: "toolCall", id: "call_1", name: "echo" },
                  { type: "toolCall", id: "call_2", name: "sum" },
                ],
              },
              {
                role: "toolResult",
                toolCallId: "call_1",
                toolName: "echo",
                content: [{ type: "text", text: "hello" }],
              },
              {
                role: "toolResult",
                toolCallId: "call_2",
                toolName: "sum",
                content: [{ type: "text", text: "5" }],
              },
            ],
          },
        },
      },
    });
    const replayedContinuation = await makeEngine(sessionId).step({
      authority: authority(),
      checkpoint: secondTool.checkpoint,
      settlement: successSettlement(secondTool.request.requestDigest, {
        version: 1,
        toolCallId: "call_2",
        toolName: "sum",
        content: [{ type: "text", text: "5" }],
        details: { value: 5 },
        isError: false,
        timestamp: 1_700_000_000_003,
      }),
    });
    expect(replayedContinuation).toEqual(continuation);
    if (continuation.kind !== "effect_request") throw new Error("expected model continuation");

    const duplicateAcrossBatches = await makeEngine(sessionId).step({
      authority: authority(),
      checkpoint: continuation.checkpoint,
      settlement: successSettlement(
        continuation.request.requestDigest,
        assistantMessage(
          [{ type: "toolCall", id: "call_1", name: "echo", arguments: { text: "again" } }],
          "toolUse",
        ),
      ),
    });
    expect(duplicateAcrossBatches).toMatchObject({
      kind: "turn_error",
      error: { code: "PI_TOOL_CALL_DUPLICATE", retryable: false },
    });

    const completed = await makeEngine(sessionId).step({
      authority: authority(),
      checkpoint: continuation.checkpoint,
      settlement: successSettlement(
        continuation.request.requestDigest,
        assistantMessage([{ type: "text", text: "The result is 5." }]),
      ),
    });
    expect(completed).toMatchObject({
      kind: "turn_complete",
      result: {
        message: {
          content: [{ type: "text", text: "The result is 5." }],
        },
      },
    });
  });

  it("fails closed with a stable error for malformed or duplicate tool call identities", async () => {
    const invalidCases: ReadonlyArray<{
      readonly suffix: string;
      readonly content: NormalizedValue[];
      readonly code: string;
    }> = [
      {
        suffix: "arguments",
        content: [
          { type: "toolCall", id: "call_bad", name: "echo", arguments: ["not", "an", "object"] },
        ],
        code: "PI_TOOL_CALL_INVALID",
      },
      {
        suffix: "binary_arguments",
        content: [
          {
            type: "toolCall",
            id: "call_binary",
            name: "echo",
            arguments: new Uint8Array([1, 2, 3]),
          },
        ],
        code: "PI_TOOL_CALL_INVALID",
      },
      {
        suffix: "duplicate",
        content: [
          { type: "toolCall", id: "call_same", name: "echo", arguments: { text: "one" } },
          { type: "toolCall", id: "call_same", name: "sum", arguments: { values: [2] } },
        ],
        code: "PI_TOOL_CALL_DUPLICATE",
      },
    ];
    for (const { suffix, content, code } of invalidCases) {
      const sessionId = `session_real_pi_tool_${suffix}`;
      const engine = makeEngine(sessionId);
      const model = await engine.step({
        authority: authority(),
        checkpoint: await makeGenesis(engine, `turn_real_pi_tool_${suffix}`),
      });
      if (model.kind !== "effect_request") throw new Error("expected model request");

      const denied = await makeEngine(sessionId).step({
        authority: authority(),
        checkpoint: model.checkpoint,
        settlement: successSettlement(
          model.request.requestDigest,
          assistantMessage(content, "toolUse"),
        ),
      });
      expect(denied).toMatchObject({
        kind: "turn_error",
        error: { code, retryable: false },
      });
    }
  });

  it("rejects an unregistered model tool without emitting an external effect", async () => {
    const sessionId = "session_real_pi_tool_unregistered";
    const original = makeEngine(sessionId);
    const model = await original.step({
      authority: authority(),
      checkpoint: await makeGenesis(original, "turn_real_pi_tool_unregistered"),
    });
    if (model.kind !== "effect_request") throw new Error("expected model request");

    const denied = await makeEngine(sessionId).step({
      authority: authority(),
      checkpoint: model.checkpoint,
      settlement: successSettlement(
        model.request.requestDigest,
        assistantMessage(
          [{ type: "toolCall", id: "call_missing", name: "missing", arguments: {} }],
          "toolUse",
        ),
      ),
    });

    expect(denied).toMatchObject({
      kind: "turn_error",
      error: { code: "PI_TOOL_UNREGISTERED", retryable: false },
    });
  });

  it("uses pinned Pi schema coercion before persisting a tool request", async () => {
    const sessionId = "session_real_pi_tool_coercion";
    const original = makeEngine(sessionId);
    const model = await original.step({
      authority: authority(),
      checkpoint: await makeGenesis(original, "turn_real_pi_tool_coercion"),
    });
    if (model.kind !== "effect_request") throw new Error("expected model request");
    const settlement = successSettlement(
      model.request.requestDigest,
      assistantMessage(
        [{
          type: "toolCall",
          id: "call_coerced",
          name: "echo",
          arguments: { text: 42 },
          thoughtSignature: "provider-signature",
        }],
        "toolUse",
      ),
    );

    const coerced = await makeEngine(sessionId).step({
      authority: authority(),
      checkpoint: model.checkpoint,
      settlement,
    });
    expect(coerced).toMatchObject({
      kind: "effect_request",
      request: {
        payload: {
          toolCall: {
            id: "call_coerced",
            name: "echo",
            arguments: { text: "42" },
          },
        },
      },
    });
    const checkpointPayload = decodeCanonicalCbor(coerced.checkpoint.payloadBytes) as {
      readonly coreState?: {
        readonly messages?: readonly NormalizedValue[];
      };
    };
    expect(checkpointPayload.coreState?.messages).toEqual(expect.arrayContaining([
      expect.objectContaining({
        role: "assistant",
        content: [expect.objectContaining({
          id: "call_coerced",
          arguments: { text: 42 },
          thoughtSignature: "provider-signature",
        })],
      }),
    ]));
    await expect(makeEngine(sessionId).step({
      authority: authority(),
      checkpoint: model.checkpoint,
      settlement,
    })).resolves.toEqual(coerced);
    if (coerced.kind !== "effect_request") throw new Error("expected coerced tool request");

    const continuation = await makeEngine(sessionId).step({
      authority: authority(),
      checkpoint: coerced.checkpoint,
      settlement: successSettlement(coerced.request.requestDigest, {
        version: 1,
        toolCallId: "call_coerced",
        toolName: "echo",
        content: [{ type: "text", text: "42" }],
        isError: false,
        timestamp: 1_700_000_000_002,
      }),
    });
    expect(continuation).toMatchObject({
      kind: "effect_request",
      request: {
        service: "model",
        payload: {
          context: {
            messages: expect.arrayContaining([
              expect.objectContaining({
                role: "assistant",
                content: [expect.objectContaining({
                  id: "call_coerced",
                  arguments: { text: 42 },
                  thoughtSignature: "provider-signature",
                })],
              }),
            ]),
          },
        },
      },
    });
  });

  it("rejects nested binary tool arguments before emitting an external effect", async () => {
    const sessionId = "session_real_pi_tool_nested_binary";
    const original = makeEngine(sessionId);
    const model = await original.step({
      authority: authority(),
      checkpoint: await makeGenesis(original, "turn_real_pi_tool_nested_binary"),
    });
    if (model.kind !== "effect_request") throw new Error("expected model request");

    const denied = await makeEngine(sessionId).step({
      authority: authority(),
      checkpoint: model.checkpoint,
      settlement: successSettlement(
        model.request.requestDigest,
        assistantMessage(
          [{
            type: "toolCall",
            id: "call_nested_binary",
            name: "echo",
            arguments: { text: { bytes: new Uint8Array([1, 2, 3]) } },
          }],
          "toolUse",
        ),
      ),
    });

    expect(denied).toMatchObject({
      kind: "turn_error",
      error: { code: "PI_TOOL_CALL_INVALID", retryable: false },
    });
  });

  it("fails closed with a stable error for unsupported tool result content", async () => {
    const sessionId = "session_real_pi_tool_content";
    const tool = await makeSingleToolRequest(sessionId, "turn_real_pi_tool_content");

    const denied = await makeEngine(sessionId).step({
      authority: authority(),
      checkpoint: tool.checkpoint,
      settlement: successSettlement(tool.request.requestDigest, {
        version: 1,
        toolCallId: "call_only",
        toolName: "echo",
        content: [{ type: "audio", data: "AAAA", mimeType: "audio/wav" }],
        isError: false,
        timestamp: 1_700_000_000_002,
      }),
    });

    expect(denied).toMatchObject({
      kind: "turn_error",
      error: { code: "PI_TOOL_RESULT_INVALID", retryable: false },
    });
  });

  it("rejects a tool result whose durable identity does not match its call", async () => {
    const sessionId = "session_real_pi_tool_identity";
    const tool = await makeSingleToolRequest(sessionId, "turn_real_pi_tool_identity");

    const denied = await makeEngine(sessionId).step({
      authority: authority(),
      checkpoint: tool.checkpoint,
      settlement: successSettlement(tool.request.requestDigest, {
        version: 1,
        toolCallId: "call_other",
        toolName: "echo",
        content: [{ type: "text", text: "wrong" }],
        isError: false,
        timestamp: 1_700_000_000_002,
      }),
    });

    expect(denied).toMatchObject({
      kind: "turn_error",
      error: { code: "PI_TOOL_RESULT_INVALID", retryable: false },
    });
  });

  it("accepts a large durable tool input at the settlement boundary", async () => {
    const sessionId = "session_real_pi_tool_large_input";
    const tool = await makeSingleToolRequest(
      sessionId,
      "turn_real_pi_tool_large_input",
      { text: "x".repeat(128 * 1_024) },
    );

    const continuation = await makeEngine(sessionId).step({
      authority: authority(),
      checkpoint: tool.checkpoint,
      settlement: successSettlement(tool.request.requestDigest, {
        version: 1,
        toolCallId: "call_only",
        toolName: "echo",
        content: [{ type: "text", text: "ok" }],
        isError: false,
        timestamp: 1_700_000_000_002,
      }),
    });

    expect(continuation).toMatchObject({
      kind: "effect_request",
      request: { service: "model", operation: "complete" },
    });
  });

  it("accepts settlement after a beforeToolCall hook patches the dispatched payload", async () => {
    const registration: ExtensionRegistration = {
      manifest: {
        id: "tool-router",
        priority: 0,
        tools: [],
        patchableFields: { beforeToolCall: ["payload"] },
      },
      create: () => ({
        async beforeToolCall() {
          return { payload: { routedBy: "tool-router" } };
        },
      }),
    };
    const sessionId = "session_real_pi_tool_hook_patch";
    const original = makeEngine(sessionId, MODEL, [registration]);
    const model = await original.step({
      authority: authority(),
      checkpoint: await makeGenesis(original, "turn_real_pi_tool_hook_patch"),
    });
    if (model.kind !== "effect_request") throw new Error("expected model request");
    const tool = await makeEngine(sessionId, MODEL, [registration]).step({
      authority: authority(),
      checkpoint: model.checkpoint,
      settlement: successSettlement(
        model.request.requestDigest,
        assistantMessage(
          [{ type: "toolCall", id: "call_routed", name: "echo", arguments: { text: "hi" } }],
          "toolUse",
        ),
      ),
    });
    expect(tool).toMatchObject({
      kind: "effect_request",
      request: { payload: { routedBy: "tool-router" } },
    });
    if (tool.kind !== "effect_request") throw new Error("expected tool request");

    const continuation = await makeEngine(sessionId, MODEL, [registration]).step({
      authority: authority(),
      checkpoint: tool.checkpoint,
      settlement: successSettlement(tool.request.requestDigest, {
        version: 1,
        toolCallId: "call_routed",
        toolName: "echo",
        content: [{ type: "text", text: "hi" }],
        isError: false,
        timestamp: 1_700_000_000_002,
      }),
    });

    expect(continuation).toMatchObject({
      kind: "effect_request",
      request: { service: "model", operation: "complete" },
    });
  });

  it("rejects a beforeToolCall hook that weakens the configured replay policy", async () => {
    const registration: ExtensionRegistration = {
      manifest: {
        id: "unsafe-replay",
        priority: 0,
        tools: [],
        patchableFields: { beforeToolCall: ["replayPolicy"] },
      },
      create: () => ({
        async beforeToolCall() {
          return { replayPolicy: "safe" as const };
        },
      }),
    };
    const sessionId = "session_real_pi_tool_replay_clamp";
    const original = makeEngine(sessionId, MODEL, [registration]);
    const model = await original.step({
      authority: authority(),
      checkpoint: await makeGenesis(original, "turn_real_pi_tool_replay_clamp"),
    });
    if (model.kind !== "effect_request") throw new Error("expected model request");

    const denied = await makeEngine(sessionId, MODEL, [registration]).step({
      authority: authority(),
      checkpoint: model.checkpoint,
      settlement: successSettlement(
        model.request.requestDigest,
        assistantMessage(
          [{ type: "toolCall", id: "call_clamped", name: "echo", arguments: { text: "hi" } }],
          "toolUse",
        ),
      ),
    });

    expect(denied).toMatchObject({
      kind: "turn_error",
      error: { code: "EXTENSION_OUTPUT_INVALID", retryable: false },
    });
  });

  it("preserves a long OpenAI Responses tool-call id through cold result correlation", async () => {
    const callId = `call_${"r".repeat(480)}`;
    const sessionId = "session_real_pi_long_tool_id";
    const tool = await makeSingleToolRequest(
      sessionId,
      "turn_real_pi_long_tool_id",
      { text: "long id" },
      callId,
    );

    const continuation = await makeEngine(sessionId).step({
      authority: authority(),
      checkpoint: tool.checkpoint,
      settlement: successSettlement(tool.request.requestDigest, {
        version: 1,
        toolCallId: callId,
        toolName: "echo",
        content: [{ type: "text", text: "ok" }],
        isError: false,
        timestamp: 1_700_000_000_002,
      }),
    });

    expect(continuation).toMatchObject({
      kind: "effect_request",
      request: {
        service: "model",
        payload: {
          context: {
            messages: expect.arrayContaining([
              expect.objectContaining({
                role: "toolResult",
                toolCallId: callId,
                toolName: "echo",
              }),
            ]),
          },
        },
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
