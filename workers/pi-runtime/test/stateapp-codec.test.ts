import {
  decodeCanonicalCbor,
  digestBytes,
  digestStructuredValue,
  encodeCanonicalCbor,
  externalizeAgentCheckpoint,
  rehydrateAgentCheckpoint,
  validateAgentCheckpoint,
  type AgentCheckpoint,
  type Digest,
  type NormalizedValue,
} from "@circulusd/protocol-types";
import { describe, expect, it } from "vitest";

import golden from "../../../packages/protocol-types/fixtures/stateapp-pi-codec-v1.json";
import {
  LowLevelPiAgentEngine,
  createOpaqueTurnAuthority,
  createPiAgentCoreFactory,
  createPiAgentCoreInitialState,
  decodePiAgentCoreModelContext,
  decodePiJson,
  encodePiAgentCoreModelSettlement,
  type EngineSettlement,
} from "../src/index.ts";

const sessionId = "sess_AAAAAAAAAAAAAAAAAAAAAAAAAA";
const turnId = "turn_AAAAAAAAAAAAAAAAAAAAAAAAAA";
const runtimeRevisionDigest = `sha256:${"a".repeat(64)}` as const;
const model = {
  id: "codec-test-model", api: "circulusd-model-gateway", provider: "circulusd",
  reasoning: false, input: ["text"], contextWindow: 8_192, maxTokens: 1_024,
} as const;

function engine() {
  return new LowLevelPiAgentEngine(
    { sessionId, runtimeRevisionDigest, adapterAbiVersion: 2, checkpointSchemaVersion: 2 },
    createPiAgentCoreFactory({
      systemPrompt: "Test canonical transport without provider I/O.", model,
      tools: [{
        name: "echo_number", description: "Echo a finite number", replayPolicy: "safe",
        parameters: {
          type: "object", properties: { value: { type: "number", minimum: 0.25 } },
          required: ["value"], additionalProperties: false,
        },
      }],
    }),
  );
}

function hex(value: Uint8Array): string {
  return [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
function bytes(value: string): Uint8Array {
  return Uint8Array.from(value.match(/../g) ?? [], (byte) => Number.parseInt(byte, 16));
}
function items(value: NormalizedValue): number {
  if (Array.isArray(value)) return 1 + value.reduce<number>((total, item) => total + items(item), 0);
  if (value !== null && typeof value === "object" && !(value instanceof Uint8Array)) {
    return 1 + Object.values(value).reduce<number>((total, item) => total + 1 + items(item), 0);
  }
  return 1;
}
function assistant(content: unknown[], stopReason: "toolUse" | "stop") {
  return {
    role: "assistant", content, api: model.api, provider: model.provider, model: model.id,
    stopReason, timestamp: 1_700_000_000_001,
    usage: {
      input: 1, output: 2, cacheRead: 0, cacheWrite: 0, totalTokens: 3,
      cost: { input: 0.00000125, output: 0.0000025, cacheRead: 0, cacheWrite: 0, total: 0.00000375 },
    },
  };
}

async function vectors() {
  const checkpoints: { name: string; wireHex: string; externalHex: string; payloadHex: string; chainDigest: Digest }[] = [];
  const settlements: { name: string; wireHex: string; storedHex: string; payloadHex: string; digest: Digest }[] = [];
  const boundaries: { name: string; wireHex: string }[] = [];
  async function checkpoint(name: string, value: AgentCheckpoint) {
    const external = externalizeAgentCheckpoint(value);
    checkpoints.push({
      name, wireHex: hex(encodeCanonicalCbor(value)), externalHex: hex(encodeCanonicalCbor(external.checkpoint)),
      payloadHex: hex(value.payloadBytes),
      chainDigest: await digestStructuredValue("circulusd.session.agent-checkpoint", 1, value),
    });
    // Execute reconstructed payloads after every cold engine boundary.
    return rehydrateAgentCheckpoint(external.checkpoint, external.payloadBytes);
  }
  async function settlement(name: string, requestDigest: Digest, result: NormalizedValue): Promise<EngineSettlement> {
    const payload = encodeCanonicalCbor(result);
    const digest = await digestBytes(payload);
    const wire: EngineSettlement = { requestDigest, outcome: { kind: "success", result } };
    const stored = {
      kind: "success", resultPayloadRef: {
        encoding: "canonical-cbor-v1", digest, encodedBytes: payload.byteLength, encodedItems: items(result),
      },
    };
    settlements.push({ name, wireHex: hex(encodeCanonicalCbor(wire)), storedHex: hex(encodeCanonicalCbor(stored)), payloadHex: hex(payload), digest });
    return { requestDigest, outcome: { kind: "success", result: decodeCanonicalCbor(payload) } };
  }
  const authority = createOpaqueTurnAuthority(new Uint8Array([1, 2, 3]));
  const genesis = await checkpoint("genesis", await engine().createGenesisCheckpoint({
    turnId, input: { prompt: "Echo 1.25", timestamp: 1_700_000_000_000 }, initialCoreState: createPiAgentCoreInitialState(),
  }));
  const first = await engine().step({ authority, checkpoint: genesis });
  if (first.kind !== "effect_request") throw new Error("expected first model request");
  boundaries.push({ name: "model", wireHex: hex(encodeCanonicalCbor(first)) });
  const firstCheckpoint = await checkpoint("model", first.checkpoint);
  const modelSettlement = await settlement("model_tool_call", first.request.requestDigest,
    encodePiAgentCoreModelSettlement(assistant([{ type: "toolCall", id: "call_number", name: "echo_number", arguments: { value: 1.25 } }], "toolUse")));
  const tool = await engine().step({ authority, checkpoint: firstCheckpoint, settlement: modelSettlement });
  if (tool.kind !== "effect_request" || tool.request.service !== "external-tool") throw new Error("expected tool request");
  boundaries.push({ name: "tool", wireHex: hex(encodeCanonicalCbor(tool)) });
  const toolPayload = tool.request.payload as { toolCall: { arguments: NormalizedValue } };
  const decoded = decodePiJson(toolPayload.toolCall.arguments) as { value: number };
  if (decoded.value !== 1.25 || typeof decoded.value !== "number") throw new Error("fractional tool argument changed");
  const toolCheckpoint = await checkpoint("tool", tool.checkpoint);
  const toolSettlement = await settlement("tool_result", tool.request.requestDigest, {
    version: 1, toolCallId: "call_number", toolName: "echo_number",
    content: [{ type: "text", text: String(decoded.value) }], isError: false, timestamp: 1_700_000_000_002,
  });
  const next = await engine().step({ authority, checkpoint: toolCheckpoint, settlement: toolSettlement });
  if (next.kind !== "effect_request" || next.request.service !== "model") throw new Error("expected next model request");
  boundaries.push({ name: "next_model", wireHex: hex(encodeCanonicalCbor(next)) });
  const context = decodePiAgentCoreModelContext((next.request.payload as { context: NormalizedValue }).context);
  const messages = context.messages as { role: string; content: { type: string; arguments?: { value: number }; text?: string }[] }[];
  if (!messages.some((message) => Array.isArray(message.content) && message.content.some((block) => block.arguments?.value === 1.25))) throw new Error("provider transcript lost numeric argument");
  const nextCheckpoint = await checkpoint("next_model", next.checkpoint);
  const finalSettlement = await settlement("model_final", next.request.requestDigest,
    encodePiAgentCoreModelSettlement(assistant([{ type: "text", text: "1.25" }], "stop")));
  const final = await engine().step({ authority, checkpoint: nextCheckpoint, settlement: finalSettlement });
  if (final.kind !== "turn_complete") throw new Error("expected completion");
  boundaries.push({ name: "complete", wireHex: hex(encodeCanonicalCbor(final)) });
  await checkpoint("complete", final.checkpoint);
  return { version: 1, checkpoints, settlements, boundaries };
}

describe("Go/Session actual Pi state-v2 canonical codec", () => {
  it("reconstructs each real engine boundary and preserves fractional results against shared goldens", async () => {
    expect(await vectors()).toEqual(golden);
  });

  it("validates every shared wire checkpoint and distinguishes chain and payload hashes", async () => {
    for (const vector of golden.checkpoints) {
      const checkpoint = await validateAgentCheckpoint(decodeCanonicalCbor(bytes(vector.wireHex)));
      expect(checkpoint.payloadDigest).not.toBe(vector.chainDigest);
      expect(await digestStructuredValue("circulusd.session.agent-checkpoint", 1, checkpoint)).toBe(vector.chainDigest);
      expect(checkpoint.adapterAbiVersion).toBe(2);
      expect(checkpoint.checkpointSchemaVersion).toBe(2);
      expect(decodeCanonicalCbor(checkpoint.payloadBytes)).toMatchObject({ version: 1, coreState: { version: 2 } });
    }
  });
});
