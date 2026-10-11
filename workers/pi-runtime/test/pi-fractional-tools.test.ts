import type { AssistantMessage, Context } from "@earendil-works/pi-ai";
import {
  decodeCanonicalCbor,
  encodeCanonicalCbor,
  type NormalizedValue,
} from "@circulusd/protocol-types";
import { describe, expect, it } from "vitest";

import {
  LowLevelPiAgentEngine,
  createOpaqueTurnAuthority,
  createPiAgentCoreFactory,
  createPiAgentCoreInitialState,
  decodePiAgentCoreModelContext,
  decodePiAgentCoreModelSettlement,
  encodePiAgentCoreModelContext,
  encodePiAgentCoreModelSettlement,
} from "../src/index.ts";
import { decodePiJson, encodePiJson } from "../src/pi-json-codec.ts";
import { identity, successSettlement } from "./helpers.ts";

const MODEL = {
  id: "fractional-tool-model", api: "openai-responses", provider: "openai", reasoning: false,
  input: ["text"], contextWindow: 8192, maxTokens: 1024,
} as const;
const SCHEMA = {
  type: "object",
  properties: {
    value: { type: "number", minimum: -1.5, maximum: 2.5, multipleOf: 0.25 },
    offset: { type: "number", default: 0.125 },
  },
  required: ["value"], additionalProperties: false,
};
const TOOLS = [{ name: "scale", description: "Scale a number", parameters: SCHEMA, replayPolicy: "safe" }] as const;
const SESSION_ID = "session_fractional_tools";
const authority = () => createOpaqueTurnAuthority(new Uint8Array([1, 2, 3]));

function engine() {
  return new LowLevelPiAgentEngine(
    { ...identity(SESSION_ID), adapterAbiVersion: 2, checkpointSchemaVersion: 2 },
    createPiAgentCoreFactory({ systemPrompt: "Keep exact numbers", model: MODEL, tools: TOOLS }),
  );
}

function message(cost = 0): AssistantMessage {
  return {
    role: "assistant", api: MODEL.api, provider: MODEL.provider, model: MODEL.id,
    content: [
      { type: "toolCall", id: "call_fraction_one", name: "scale", arguments: { value: 1.25 } },
      { type: "toolCall", id: "call_fraction_two", name: "scale", arguments: { value: -0.75 } },
    ],
    usage: {
      input: 1, output: 1, cacheRead: 0, cacheWrite: 0, totalTokens: 2,
      cost: { input: cost, output: cost, cacheRead: 0, cacheWrite: 0, total: cost * 2 },
    },
    stopReason: "toolUse", timestamp: 1_700_000_000_001,
  };
}

async function start() {
  const first = engine();
  const genesis = await first.createGenesisCheckpoint({
    turnId: "turn_fractional_tools", input: { prompt: "scale", timestamp: 1_700_000_000_000 },
    initialCoreState: createPiAgentCoreInitialState(),
  });
  const request = await first.step({ authority: authority(), checkpoint: genesis });
  if (request.kind !== "effect_request") throw new Error("expected model boundary");
  return request;
}

describe("Pi fractional tool arguments across durable boundaries", () => {
  it.each([0, 0.000001])("encodes provider arguments and costs %s exactly once", (cost) => {
    const provider = message(cost);
    const encoded = encodePiAgentCoreModelSettlement(provider);
    const durable = decodeCanonicalCbor(encodeCanonicalCbor(encoded));
    expect(durable).toMatchObject({ message: { content: [
      { arguments: { value: { "$pi.number.v1": "1.25" } } },
      { arguments: { value: { "$pi.number.v1": "-0.75" } } },
    ] } });
    expect(decodePiAgentCoreModelSettlement(durable)).toEqual(provider);
    expect(() => encodePiAgentCoreModelSettlement(
      (durable as { message: NormalizedValue }).message,
    )).toThrow();
  });

  it("restores provider context schemas and assistant arguments without wrapper objects", () => {
    const context: Context = {
      messages: [message(0.000001)],
      tools: [{ name: "scale", description: "Scale", parameters: SCHEMA }],
    };
    const durable = decodeCanonicalCbor(encodeCanonicalCbor(encodePiAgentCoreModelContext(context)));
    expect(decodePiAgentCoreModelContext(durable)).toEqual(context);
  });

  it.each(["encoded", "raw integer costs", "raw fractional costs"])(
    "preserves two numeric tool calls through fresh engines: %s", async (kind) => {
      const first = await start();
      const provider = message(kind === "raw fractional costs" ? 0.000001 : 0);
      const settlement = kind === "encoded"
        ? encodePiAgentCoreModelSettlement(provider)
        : { version: 1, message: provider } as unknown as NormalizedValue;
      let step = await engine().step({
        authority: authority(), checkpoint: first.checkpoint,
        settlement: successSettlement(first.request.requestDigest, settlement),
      });
      for (const [index, value] of [1.25, -0.75].entries()) {
        if (step.kind !== "effect_request") throw new Error("expected tool boundary");
        expect(step.request.service).toBe("external-tool");
        const toolCall = (step.request.payload as { toolCall: { arguments: NormalizedValue } }).toolCall;
        // Pinned Pi validates/coerces arguments without inserting schema defaults.
        // The default remains numeric metadata in the provider schema below.
        expect(decodePiJson(toolCall.arguments)).toEqual({ value });
        expect(toolCall.arguments).toEqual(encodePiJson({ value }));
        const checkpoint = decodeCanonicalCbor(step.checkpoint.payloadBytes) as {
          coreState: { messages: NormalizedValue[]; pendingToolCalls: NormalizedValue[] };
        };
        expect(checkpoint.coreState.pendingToolCalls).toMatchObject([
          { arguments: { value: { "$pi.number.v1": "1.25" } } },
          { arguments: { value: { "$pi.number.v1": "-0.75" } } },
        ]);
        step = await engine().step({
          authority: authority(), checkpoint: step.checkpoint,
          settlement: successSettlement(step.request.requestDigest, {
            version: 1, toolCallId: index === 0 ? "call_fraction_one" : "call_fraction_two",
            toolName: "scale", content: [{ type: "text", text: String(value) }],
            isError: false, timestamp: 1_700_000_000_002 + index,
          }),
        });
      }
      if (step.kind !== "effect_request") throw new Error("expected next model boundary");
      expect(step.request.service).toBe("model");
      const context = decodePiAgentCoreModelContext((step.request.payload as { context: NormalizedValue }).context);
      expect(context.tools).toEqual([{ name: "scale", description: "Scale a number", parameters: SCHEMA }]);
      expect((context.messages[1] as AssistantMessage).content).toEqual(provider.content);
      const final = { ...message(), content: [{ type: "text" as const, text: "done" }], stopReason: "stop" as const };
      const complete = await engine().step({
        authority: authority(), checkpoint: step.checkpoint,
        settlement: successSettlement(step.request.requestDigest, encodePiAgentCoreModelSettlement(final)),
      });
      expect(complete.kind).toBe("turn_complete");
    },
  );

  it("validates decoded numbers against fractional schema constraints before dispatch", async () => {
    const first = await start();
    const provider = message();
    provider.content = [{ type: "toolCall", id: "bad", name: "scale", arguments: { value: 1.1 } }];
    const denied = await engine().step({
      authority: authority(), checkpoint: first.checkpoint,
      settlement: successSettlement(first.request.requestDigest, encodePiAgentCoreModelSettlement(provider)),
    });
    expect(denied).toMatchObject({ kind: "turn_error", error: { code: "PI_TOOL_CALL_INVALID" } });
  });
});
