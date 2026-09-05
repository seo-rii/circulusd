import { calculateCost, type AssistantMessage } from "@earendil-works/pi-ai";
import { decodeCanonicalCbor, digestBytes, encodeCanonicalCbor, type NormalizedValue } from "@circulusd/protocol-types";
import { describe, expect, it } from "vitest";

import {
  LowLevelPiAgentEngine,
  LowLevelPiSessionHostAdapter,
  PI_AGENT_CORE_COST_ENCODING,
  createOpaqueTurnAuthority,
  createPiAgentCoreFactory,
  createPiAgentCoreInitialState,
  decodePiAgentCoreModelContext,
  decodePiAgentCoreModelSettlement,
  encodePiAgentCoreModelSettlement,
} from "../src/index.ts";
import { identity, successSettlement } from "./helpers.ts";

const model = {
  id: "pi-cost-test", api: "openai-responses", provider: "openai", reasoning: false,
  input: ["text"], contextWindow: 8192, maxTokens: 1024,
} as const;
const sessionId = "session_fractional_costs";
const authority = () => createOpaqueTurnAuthority(new Uint8Array([1, 2, 3]));

function engine() {
  return new LowLevelPiAgentEngine(
    { ...identity(sessionId), adapterAbiVersion: 2, checkpointSchemaVersion: 2 },
    createPiAgentCoreFactory({
      systemPrompt: "Preserve all usage costs.", model,
      tools: [{
        name: "echo", description: "Echo text", replayPolicy: "safe",
        parameters: { type: "object", properties: { text: { type: "string" } }, required: ["text"] },
      }],
    }),
  );
}

function providerMessage(tool = false): AssistantMessage {
  const usage = {
    input: 10, output: 1, cacheRead: 0, cacheWrite: 0, totalTokens: 11,
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
  };
  calculateCost({
    ...model, input: ["text"], name: model.id, baseUrl: "",
    cost: { input: 1, output: 2, cacheRead: 0, cacheWrite: 0 },
  }, usage);
  return {
    role: "assistant", api: model.api, provider: model.provider, model: model.id,
    content: tool
      ? [{ type: "toolCall", id: "cost_echo", name: "echo", arguments: { text: "hello" } }]
      : [{ type: "text", text: "done" }],
    usage, stopReason: tool ? "toolUse" : "stop", timestamp: 1700000000001,
  };
}

async function firstModel() {
  const initial = engine();
  const checkpoint = await initial.createGenesisCheckpoint({
    turnId: "turn_fractional_costs", input: { prompt: "hello", timestamp: 1700000000000 },
    initialCoreState: createPiAgentCoreInitialState(),
  });
  const step = await initial.step({ authority: authority(), checkpoint });
  if (step.kind !== "effect_request") throw new Error("expected model boundary");
  return step;
}

describe("Pi decimal cost boundary", () => {
  it("round-trips actual pinned Pi calculateCost values through canonical durable bytes", () => {
    const message = providerMessage();
    expect(message.usage.cost.input).toBeGreaterThan(0);
    expect(Number.isInteger(message.usage.cost.input)).toBe(false);
    const durable = encodePiAgentCoreModelSettlement(message);
    expect(durable).toMatchObject({ version: 2, message: { usage: { cost: {
      encoding: PI_AGENT_CORE_COST_ENCODING, input: message.usage.cost.input.toString(),
    } } } });
    const decoded = decodePiAgentCoreModelSettlement(decodeCanonicalCbor(encodeCanonicalCbor(durable)));
    expect(decoded).toEqual(message);
  });

  it.each([Number.MIN_VALUE, Number.MAX_VALUE, 0.1, 1.2345678901234567, 0, 1e21])(
    "preserves the exact original Number %s without scaling or rounding", (value) => {
      const message = providerMessage();
      message.usage.cost.input = value;
      message.usage.cost.total = value;
      const restored = decodePiAgentCoreModelSettlement(encodePiAgentCoreModelSettlement(message));
      expect(Object.is(restored.usage.cost.input, value)).toBe(true);
      expect(Object.is(restored.usage.cost.total, value)).toBe(true);
    },
  );

  it.each([NaN, Infinity, -Infinity, -1, -0])("rejects invalid raw costs %s", (value) => {
    const message = providerMessage();
    message.usage.cost.total = value;
    expect(() => encodePiAgentCoreModelSettlement(message)).toThrow(/Pi cost must/);
  });

  it.each(["-0", "-1", "NaN", "Infinity", "1.0", "01", "1e0", "1e309", "1e-9999", " 1", "", 1])(
    "rejects noncanonical encoded costs %s", (value) => {
      const wire = encodePiAgentCoreModelSettlement(providerMessage()) as {
        message: { usage: { cost: Record<string, unknown> } };
      };
      wire.message.usage.cost.input = value;
      expect(() => decodePiAgentCoreModelSettlement(wire)).toThrow();
    },
  );

  it("reads legacy v1 integer costs and rejects unversioned or mismatched encodings", () => {
    const message = providerMessage();
    message.usage.cost = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 };
    expect(decodePiAgentCoreModelSettlement({ version: 1, message })).toEqual(message);
    expect(() => decodePiAgentCoreModelSettlement({ version: 2, message })).toThrow(/version and cost encoding/);
    const encoded = encodePiAgentCoreModelSettlement(message) as Record<string, NormalizedValue>;
    expect(() => decodePiAgentCoreModelSettlement({ ...encoded, version: 1 })).toThrow(/version and cost encoding/);
    expect(() => decodePiAgentCoreModelSettlement({ ...encoded, version: 3 })).toThrow(/version and cost encoding/);
  });

  it("automatically adapts raw Pi responses through a tool cycle and four reconstructed engines", async () => {
    const first = await firstModel();
    const toolMessage = providerMessage(true);
    const tool = await engine().step({
      authority: authority(), checkpoint: first.checkpoint,
      settlement: successSettlement(first.request.requestDigest, { version: 1, message: toolMessage } as unknown as NormalizedValue),
    });
    if (tool.kind !== "effect_request") throw new Error("expected tool boundary");
    const payload = decodeCanonicalCbor(tool.checkpoint.payloadBytes) as {
      coreState: { messages: NormalizedValue[] };
    };
    expect(payload.coreState.messages[1]).toMatchObject({ usage: { cost: { encoding: PI_AGENT_CORE_COST_ENCODING } } });
    const resumed = await engine().step({
      authority: authority(), checkpoint: tool.checkpoint,
      settlement: successSettlement(tool.request.requestDigest, {
        version: 1, toolCallId: "cost_echo", toolName: "echo", content: [{ type: "text", text: "hello" }],
        isError: false, timestamp: 1700000000002,
      }),
    });
    if (resumed.kind !== "effect_request") throw new Error("expected second model boundary");
    const request = resumed.request.payload as { version: number; context: NormalizedValue };
    expect(request.version).toBe(2);
    const piContext = decodePiAgentCoreModelContext(request.context);
    expect((piContext.messages[1] as AssistantMessage).usage.cost).toEqual(toolMessage.usage.cost);
    const finalMessage = providerMessage();
    const completed = await engine().step({
      authority: authority(), checkpoint: resumed.checkpoint,
      settlement: successSettlement(resumed.request.requestDigest, { version: 1, message: finalMessage } as unknown as NormalizedValue),
    });
    if (completed.kind !== "turn_complete") throw new Error("expected complete boundary");
    expect(decodePiAgentCoreModelSettlement(completed.result).usage.cost).toEqual(finalMessage.usage.cost);
    const finalPayload = decodeCanonicalCbor(completed.checkpoint.payloadBytes) as { coreState: { messages: NormalizedValue[] } };
    const transcript = decodePiAgentCoreModelContext({ messages: finalPayload.coreState.messages });
    expect((transcript.messages[1] as AssistantMessage).usage.cost).toEqual(toolMessage.usage.cost);
    expect((transcript.messages[3] as AssistantMessage).usage.cost).toEqual(finalMessage.usage.cost);
  });

  it("continues an existing ABI/state-v2 checkpoint containing legacy numeric transcript costs", async () => {
    const first = await firstModel();
    const message = providerMessage(true);
    message.usage.cost = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 };
    const tool = await engine().step({
      authority: authority(), checkpoint: first.checkpoint,
      settlement: successSettlement(first.request.requestDigest, { version: 1, message } as unknown as NormalizedValue),
    });
    if (tool.kind !== "effect_request") throw new Error("expected tool boundary");
    const payload = decodeCanonicalCbor(tool.checkpoint.payloadBytes) as { coreState: { messages: NormalizedValue[] } };
    payload.coreState.messages[1] = message as unknown as NormalizedValue;
    const payloadBytes = encodeCanonicalCbor(payload);
    const checkpoint = { ...tool.checkpoint, payloadBytes, payloadDigest: await digestBytes(payloadBytes) };
    const resumed = await engine().step({
      authority: authority(), checkpoint,
      settlement: successSettlement(tool.request.requestDigest, {
        version: 1, toolCallId: "cost_echo", toolName: "echo", content: [{ type: "text", text: "hello" }],
        isError: false, timestamp: 1700000000002,
      }),
    });
    expect(resumed.kind).toBe("effect_request");
  });

  it("adapts normal raw Pi responses through the public SessionHost bridge", async () => {
    const first = await firstModel();
    const adapter = new LowLevelPiSessionHostAdapter(engine());
    const events = adapter.resumeTurn({
      turnId: first.checkpoint.turnId, executionId: "execution_cost_bridge",
      authority: new Uint8Array([1]), checkpoint: first.checkpoint,
      settlement: successSettlement(first.request.requestDigest, { version: 1, message: providerMessage() } as unknown as NormalizedValue),
    });
    const result = await events[Symbol.asyncIterator]().next();
    expect(result.value).toMatchObject({ type: "turn_complete", result: { version: 2 } });
    if (result.value?.type !== "turn_complete") throw new Error("expected complete event");
    expect(decodePiAgentCoreModelSettlement(result.value.result).usage.cost).toEqual(providerMessage().usage.cost);
  });

  it("keeps ordinary cores and the shared canonical protocol integer-only", async () => {
    const generic = new LowLevelPiAgentEngine(identity("generic_cost_guard"), () => ({
      async advance() {
        return {
          kind: "model_request", state: {},
          request: { service: "model", operation: "complete", replayPolicy: "never", payload: { protocol: "pi-agent-core", version: 2 } },
        };
      },
    }));
    const checkpoint = await generic.createGenesisCheckpoint({ turnId: "turn_generic_cost_guard", input: {}, initialCoreState: {} });
    const first = await generic.step({ authority: authority(), checkpoint });
    if (first.kind !== "effect_request") throw new Error("expected model boundary");
    await expect(generic.step({
      authority: authority(), checkpoint: first.checkpoint,
      settlement: successSettlement(first.request.requestDigest, { version: 1, message: providerMessage() } as unknown as NormalizedValue),
    })).rejects.toMatchObject({ code: "INVALID_CONTEXT" });
    expect(() => encodeCanonicalCbor({ cost: 0.1 })).toThrow(/safe integers/);
  });
});
