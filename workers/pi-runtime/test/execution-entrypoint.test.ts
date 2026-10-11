import { decodeCanonicalCbor, digestStructuredValue, parseAgentCheckpoint, type AgentCheckpoint, type EffectIntent, type NormalizedValue } from "@circulusd/protocol-types";
import { describe, expect, it, vi } from "vitest";

import { LowLevelPiAgentEngine } from "../src/engine.ts";
import { createPiExecutionEntrypointClass } from "../src/execution-entrypoint.ts";
import {
  PI_EXECUTION_CONFIGURATION_DOMAIN, snapshotPiExecutionEnvironment, type PiExecutionEnvironment,
} from "../src/execution-environment.ts";
import { PI_EXECUTION_PROTOCOL, type PiExecutionReply, type PiExecutionRequest } from "../src/execution-rpc.ts";
import { PiGenesisGenerator } from "../src/genesis.ts";
import { decodePiAgentCoreAssistantMessage } from "../src/pi-cost-codec.ts";
import { decodePiJson } from "../src/pi-json-codec.ts";
import { CONFIGURATION, environment as genesisEnvironment, request as genesisRequest, SCOPE } from "./genesis-fixtures.ts";

const failure = { code: "INVALID_CONTEXT", message: "Pi execution RPC is invalid or unavailable" };
class NativeBase { constructor(readonly context: object, readonly env: unknown) {} }
const Entry = createPiExecutionEntrypointClass(NativeBase);

async function environment(): Promise<PiExecutionEnvironment> {
  const environment = await genesisEnvironment();
  return { ...environment, configurationDigest: await digestStructuredValue(PI_EXECUTION_CONFIGURATION_DOMAIN, 1, environment.configuration) };
}
async function genesis(): Promise<AgentCheckpoint> {
  return (await (await PiGenesisGenerator.create(await genesisEnvironment())).createGenesis(await genesisRequest())).checkpoint;
}
function request(environment: PiExecutionEnvironment, checkpoint: AgentCheckpoint,
  operation: "start" | "resume", executionId = "execution_first", settlement?: unknown): PiExecutionRequest {
  const header = { protocol: PI_EXECUTION_PROTOCOL, version: 1 as const, binding: { scope: { ...environment.scope },
    runtimeRevisionDigest: environment.runtimeRevisionDigest, artifactDigest: environment.artifactDigest },
  turnId: checkpoint.turnId, executionId, sequence: 0 } as const;
  const value = { ...header, authority: new Uint8Array([17, 23, 31]), checkpoint: structuredClone(checkpoint) };
  return operation === "start" ? { ...value, operation } : { ...value, operation, settlement };
}
function control(open: PiExecutionRequest, operation: "pull" | "close" | "abort", sequence = 0): PiExecutionRequest {
  const { protocol, version, binding, turnId, executionId } = open;
  return { protocol, version, binding, turnId, executionId, operation, sequence };
}
function effect(reply: PiExecutionReply) {
  if (reply.status !== "event" || (reply.event.type !== "model_request" && reply.event.type !== "tool_request")) {
    throw new Error("expected effect boundary");
  }
  return { checkpoint: parseAgentCheckpoint(reply.event.checkpoint), request: reply.event.request as EffectIntent };
}
function modelMessage(tool: boolean) {
  return { role: "assistant", api: CONFIGURATION.model.api, provider: CONFIGURATION.model.provider, model: CONFIGURATION.model.id,
    content: tool ? [{ type: "toolCall", id: "entrypoint-echo", name: "echo", arguments: { value: 1.25 } }] :
      [{ type: "text", text: "done" }],
    usage: { input: 1, output: 1, cacheRead: 0, cacheWrite: 0, totalTokens: 2,
      cost: { input: 0.000001, output: 0.000001, cacheRead: 0, cacheWrite: 0, total: 0.000002 } },
    stopReason: tool ? "toolUse" : "stop", timestamp: 1_700_000_000_001 };
}
function settlement(request: EffectIntent, result: unknown) {
  return { requestDigest: request.requestDigest, outcome: { kind: "success", result } };
}

describe("actual Pi execution entrypoint", () => {
  it("exposes only exchange and cold-reconstructs fractional model/tool settlements through the full Pi loop", async () => {
    const env = await environment(), initial = await genesis(), waitUntil = vi.fn();
    const first = new Entry({ waitUntil }, env);
    expect(first).toBeInstanceOf(NativeBase);
    expect(Object.getOwnPropertyNames(Entry.prototype)).toEqual(["constructor", "exchange"]);
    const start = request(env, initial, "start");
    const step = vi.spyOn(LowLevelPiAgentEngine.prototype, "step");
    try {
      expect((await first.exchange(start)).status).toBe("opened");
      expect(step).not.toHaveBeenCalled();
      const model = effect(await first.exchange(control(start, "pull", 1)));
      expect(model.request).toMatchObject({ service: "model", operation: "complete", payload: { context: {
        systemPrompt: CONFIGURATION.systemPrompt, messages: [
          { role: "user", content: "첫 번째 메시지", timestamp: 0 }, { role: "user", content: "second message", timestamp: 0 },
        ],
      } } });
      await first.exchange(control(start, "close"));

      const second = new Entry({ waitUntil }, env);
      const resume = request(env, model.checkpoint, "resume", "execution_tool", settlement(model.request, { version: 1, message: modelMessage(true) }));
      await second.exchange(resume);
      const tool = effect(await second.exchange(control(resume, "pull", 1)));
      expect(tool.request.service).toBe("external-tool");
      expect(decodePiJson((tool.request.payload as { toolCall: { arguments: NormalizedValue } }).toolCall.arguments)).toEqual({ value: 1.25 });
      expect(tool.checkpoint.checkpointSequence).toBe(2);
      const state = decodeCanonicalCbor(tool.checkpoint.payloadBytes) as { coreState: { messages: NormalizedValue[] } };
      expect(decodePiAgentCoreAssistantMessage(state.coreState.messages.at(-1))).toMatchObject({
        usage: { cost: { input: 0.000001, output: 0.000001, total: 0.000002 } },
      });
      await second.exchange(control(resume, "close"));

      const third = new Entry({ waitUntil }, env);
      const continuation = request(env, tool.checkpoint, "resume", "execution_continuation", settlement(tool.request, {
        version: 1, toolCallId: "entrypoint-echo", toolName: "echo", content: [{ type: "text", text: "1.25" }],
        isError: false, timestamp: 1_700_000_000_002,
      }));
      await third.exchange(continuation);
      const nextModel = effect(await third.exchange(control(continuation, "pull", 1)));
      expect(nextModel.request.service).toBe("model");
      await third.exchange(control(continuation, "close"));

      const fourth = new Entry({ waitUntil }, env);
      const complete = request(env, nextModel.checkpoint, "resume", "execution_complete",
        settlement(nextModel.request, { version: 1, message: modelMessage(false) }));
      await fourth.exchange(complete);
      const completed = await fourth.exchange(control(complete, "pull", 1));
      expect(completed).toMatchObject({ status: "event", event: { type: "turn_complete", checkpoint: { checkpointSequence: 4 } } });
      await fourth.exchange(control(complete, "close"));
      expect(step).toHaveBeenCalledTimes(4);
      expect(waitUntil).not.toHaveBeenCalled();
    } finally { step.mockRestore(); }
  });

  it("owns constructor environment and start input before delayed configuration hashing", async () => {
    const env = await environment(), checkpoint = await genesis(), entry = new Entry({}, env);
    const nativeDigest = crypto.subtle.digest.bind(crypto.subtle), entered = Promise.withResolvers<void>(), release = Promise.withResolvers<void>();
    const hashing = vi.spyOn(crypto.subtle, "digest").mockImplementation(async (algorithm, data) => {
      entered.resolve(); await release.promise; return nativeDigest(algorithm, data);
    });
    const open = request(env, checkpoint, "start");
    try {
      const pending = entry.exchange(open);
      await entered.promise;
      Object.assign(env.scope, { actorSubjectId: `subject_${"B".repeat(25)}A` });
      Object.assign(env.configuration as object, { systemPrompt: "caller mutation" });
      if (open.operation !== "start") throw new Error("test fixture");
      open.authority.fill(0);
      (open.checkpoint as AgentCheckpoint).payloadBytes.fill(0);
      release.resolve();
      expect((await pending).status).toBe("opened");
      hashing.mockRestore();
      const model = effect(await entry.exchange(control(open, "pull", 1)));
      expect(model.request.payload).toMatchObject({ context: { systemPrompt: CONFIGURATION.systemPrompt } });
      await entry.exchange(control(open, "close"));
    } finally { release.resolve(); hashing.mockRestore(); }
  });

  it("memoizes initialization before overlapping RPC and shares one execution ownership registry", async () => {
    const env = await environment(), checkpoint = await genesis(), entry = new Entry({}, env);
    const open = request(env, checkpoint, "start"), nativeDigest = crypto.subtle.digest.bind(crypto.subtle);
    const entered = Promise.withResolvers<void>(), release = Promise.withResolvers<void>();
    const hashing = vi.spyOn(crypto.subtle, "digest").mockImplementation(async (algorithm, data) => {
      entered.resolve(); await release.promise; return nativeDigest(algorithm, data);
    });
    try {
      const first = entry.exchange(open), second = entry.exchange(structuredClone(open));
      const outcomes = Promise.allSettled([first, second]);
      await entered.promise;
      expect(hashing).toHaveBeenCalledTimes(1);
      release.resolve();
      const result = await outcomes;
      expect(result[0]).toMatchObject({ status: "fulfilled", value: { status: "opened" } });
      expect(result[1]).toMatchObject({ status: "rejected", reason: failure });
      hashing.mockRestore();
      await entry.exchange(control(open, "close"));
    } finally { release.resolve(); hashing.mockRestore(); }
  });

  it.each(["tenantId", "workspaceId", "actorSubjectId", "sessionId", "runtimeRevisionDigest", "artifactDigest"])(
    "checks exact %s before initialization or engine work", async (field) => {
      const env = await environment(), entry = new Entry({}, env), open = request(env, await genesis(), "start");
      if (field === "runtimeRevisionDigest" || field === "artifactDigest") Object.assign(open.binding, { [field]: `sha256:${"c".repeat(64)}` });
      else Object.assign(open.binding.scope, { [field]: `${({ tenantId: "tenant", workspaceId: "ws", actorSubjectId: "subject", sessionId: "sess" })[field]}_${"B".repeat(25)}A` });
      const hashing = vi.spyOn(crypto.subtle, "digest"), step = vi.spyOn(LowLevelPiAgentEngine.prototype, "step");
      try {
        await expect(entry.exchange(open)).rejects.toMatchObject(failure);
        expect(hashing).not.toHaveBeenCalled(); expect(step).not.toHaveBeenCalled();
      } finally { hashing.mockRestore(); step.mockRestore(); }
    });

  it("rejects wrong domain/digest and permanently caches failed initialization", async () => {
    const env = await genesisEnvironment(), entry = new Entry({}, env), open = request(env, await genesis(), "start");
    const hashing = vi.spyOn(crypto.subtle, "digest"), step = vi.spyOn(LowLevelPiAgentEngine.prototype, "step");
    try {
      await expect(entry.exchange(open)).rejects.toMatchObject(failure);
      await expect(entry.exchange(open)).rejects.toMatchObject(failure);
      expect(hashing).toHaveBeenCalledTimes(1); expect(step).not.toHaveBeenCalled();
    } finally { hashing.mockRestore(); step.mockRestore(); }
  });

  it("rejects a digest-valid unsupported Pi configuration without exposing its diagnostics", async () => {
    const env = await environment();
    const configuration = { ...(env.configuration as object), model: { ...CONFIGURATION.model,
      input: [...CONFIGURATION.model.input], contextWindow: 0 } };
    const invalid = { ...env, configuration, configurationDigest: await digestStructuredValue(PI_EXECUTION_CONFIGURATION_DOMAIN, 1, configuration) };
    const entry = new Entry({}, invalid), step = vi.spyOn(LowLevelPiAgentEngine.prototype, "step");
    try {
      await expect(entry.exchange(request(env, await genesis(), "start"))).rejects.toMatchObject(failure);
      expect(step).not.toHaveBeenCalled();
    } finally { step.mockRestore(); }
  });

  it("preserves preemptive cleanup tombstones and fences stale controls from a replacement execution", async () => {
    const env = await environment(), entry = new Entry({}, env), checkpoint = await genesis();
    const late = request(env, checkpoint, "start", "late_execution");
    expect((await entry.exchange(control(late, "close"))).status).toBe("closed");
    await expect(entry.exchange(late)).rejects.toMatchObject(failure);
    const active = request(env, checkpoint, "start", "active_execution");
    await entry.exchange(active);
    expect((await entry.exchange(control(late, "abort"))).status).toBe("aborted");
    const step = vi.spyOn(LowLevelPiAgentEngine.prototype, "step");
    try {
      const boundary = effect(await entry.exchange(control(active, "pull", 1)));
      expect(boundary.request.service).toBe("model");
      expect(step).toHaveBeenCalledTimes(1);
      await entry.exchange(control(active, "close"));
    } finally { step.mockRestore(); }
  });

  it("rejects capability-bearing RPC and configuration attempts before any engine work", async () => {
    const env = await environment(), checkpoint = await genesis(), entry = new Entry({}, env);
    const open = request(env, checkpoint, "start"), step = vi.spyOn(LowLevelPiAgentEngine.prototype, "step");
    try {
      const capabilityAttempt: unknown = { ...open, broker: { fetch() {} } };
      await expect(entry.exchange(capabilityAttempt as PiExecutionRequest)).rejects.toMatchObject(failure);
      const getter = vi.fn(() => "private capability");
      await expect(entry.exchange({ ...open, get checkpoint() { return getter(); } } as PiExecutionRequest)).rejects.toMatchObject(failure);
      expect(getter).not.toHaveBeenCalled(); expect(step).not.toHaveBeenCalled();
    } finally { step.mockRestore(); }
    for (const configuration of [new Uint8Array([1]), { MODEL: { fetch() {} } }, { capability: new Map() }]) {
      expect(() => new Entry({}, { ...env, configuration } as PiExecutionEnvironment)).toThrow("Pi execution environment is invalid or unverified");
    }
  });
});

describe("bounded JSON execution environment", () => {
  it("owns its exact JSON configuration and preserves canonical fractional wrappers", async () => {
    const env = await environment(), snapshot = snapshotPiExecutionEnvironment(env);
    Object.assign(env.scope, { sessionId: `sess_${"B".repeat(25)}A` });
    Object.assign(env.configuration as object, { systemPrompt: "changed" });
    expect(snapshot.scope).toEqual(SCOPE);
    expect(decodePiJson(snapshot.configuration)).toMatchObject({ tools: [{ parameters: { properties: { value: { minimum: 0.1 } } } }] });
    expect(decodeCanonicalCbor((await genesis()).payloadBytes)).toMatchObject({ coreState: { phase: "ready" } });
  });

  it("rejects extra limits, wrong scope/digest, accessors, oversized configuration and non-JSON values", async () => {
    const env = await environment(), getter = vi.fn(() => "accessor should never run");
    const values = [
      { ...env, maximumExecutions: 1 }, { ...env, scope: { ...env.scope, actorSubjectId: "invalid" } },
      { ...env, runtimeRevisionDigest: "SHA256:INVALID" }, { ...env, configurationDigest: "invalid" },
      { ...env, configuration: { text: "x".repeat(262_145) } }, { ...env, configuration: { number: 0.1 } },
      { ...env, configuration: { get secret() { return getter(); } } },
      { ...env, configuration: [undefined] }, { ...env, configuration: { value: Number.NaN } },
    ];
    for (const value of values) expect(() => snapshotPiExecutionEnvironment(value)).toThrow("Pi execution environment is invalid or unverified");
    expect(getter).not.toHaveBeenCalled();
    expect(() => createPiExecutionEntrypointClass(null)).toThrow("Pi execution entrypoint base is invalid");
  });
});
