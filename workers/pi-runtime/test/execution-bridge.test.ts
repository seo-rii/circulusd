import { Buffer } from "node:buffer";
import { build } from "esbuild";
import {
  parseAgentCheckpoint, type AgentCheckpoint, type EffectIntent, type NormalizedValue,
} from "@circulusd/protocol-types";
import { beforeAll, describe, expect, it } from "vitest";

import { SessionHost, type AgentEvent, type DriveTurnOptions } from "../../session-host/src/index.ts";
import type { PiExecutionEndpoint } from "../src/execution-endpoint.ts";
import { PiExecutionProxy } from "../src/execution-proxy.ts";
import type { PiExecutionBinding, PiExecutionRequest } from "../src/execution-rpc.ts";
import { PiGenesisGenerator } from "../src/genesis.ts";
import { decodePiAgentCoreModelContext, type PiAgentCoreAdapterConfiguration } from "../src/index.ts";
import { decodePiJson } from "../src/pi-json-codec.ts";
import { CONFIGURATION, environment, request, REVISION, SCOPE } from "./genesis-fixtures.ts";

interface BundledExecution {
  createEndpoint(binding: PiExecutionBinding, configuration: PiAgentCoreAdapterConfiguration): PiExecutionEndpoint;
  createDeltaFixtureEndpoint(binding: PiExecutionBinding): PiExecutionEndpoint;
  createCheckpointFixture(binding: PiExecutionBinding): { endpoint: PiExecutionEndpoint; advances(): number };
}
let remote: BundledExecution;
beforeAll(async () => {
  // Actual-Pi cases execute the pinned bundled core; explicit bounded-core
  // fixtures exercise delta/checkpoint paths. The primitive RPC transport is
  // local, and these tests create no celld/native qualification.
  const built = await build({ stdin: { resolveDir: new URL("../src/", import.meta.url).pathname,
    contents: `import { PiExecutionEndpoint } from "./execution-endpoint.ts";
import { LowLevelPiAgentEngine, createPiAgentCoreFactory } from "./index.ts";
import { LowLevelPiSessionHostAdapter } from "./session-host-adapter.ts";
function endpoint(binding, factory) {
  return new PiExecutionEndpoint({binding, createEngine: () => new LowLevelPiSessionHostAdapter(
    new LowLevelPiAgentEngine({sessionId:binding.scope.sessionId,
      runtimeRevisionDigest:binding.runtimeRevisionDigest, adapterAbiVersion:2, checkpointSchemaVersion:2},
      factory))});
}
export function createEndpoint(binding, configuration) {
  return endpoint(binding, createPiAgentCoreFactory(configuration));
}
// The pinned Pi adapter does not emit assistant deltas from a completed model
// settlement. A bounded core fixture exercises that existing engine event path.
export function createDeltaFixtureEndpoint(binding) {
  return endpoint(binding, () => ({advance: async () => ({kind:"model_request",
    state:{phase:"waiting-model"}, assistantDeltas:["first", "second"],
    request:{service:"model", operation:"complete", replayPolicy:"idempotency-key",
      payload:{prompt:"hello"}}})}));
}
export function createCheckpointFixture(binding) {
  let advances = 0;
  return {advances: () => advances, endpoint: endpoint(binding, () => ({advance: async (context) => {
    advances++;
    if(context.input.kind === "turn_start") return {kind:"checkpoint_only", state:{phase:"continued"}};
    if(context.input.kind !== "continue") throw new Error("unexpected fixture input");
    return {kind:"tool_requests", state:{phase:"waiting-tool"}, requests:[{service:"external-tool",
      operation:"lookup", replayPolicy:"safe", payload:{}}]};
  }}))};
}` }, bundle: true, platform: "browser", format: "esm", target: "es2022", write: false,
    external: ["cloudflare:sockets"], logLevel: "silent" });
  remote = await import(/* @vite-ignore */ `data:text/javascript;base64,${Buffer.from(built.outputFiles[0]!.contents).toString("base64")}`) as BundledExecution;
});

const binding: PiExecutionBinding = { scope: { ...SCOPE }, runtimeRevisionDigest: REVISION,
  // Test-only endpoint identity. This is not the existing genesis entrypoint's
  // signed artifact mapping and must not authorize an execution deployment.
  artifactDigest: `sha256:${"c".repeat(64)}` };
function bridge(core: "pi" | "delta" | "checkpoint" = "pi", beforeClose?: () => Promise<void>) {
  const checkpointFixture = core === "checkpoint" ? remote.createCheckpointFixture(structuredClone(binding)) : null;
  const endpoint = checkpointFixture?.endpoint ?? (core === "delta" ? remote.createDeltaFixtureEndpoint(structuredClone(binding)) :
    remote.createEndpoint(structuredClone(binding), structuredClone(CONFIGURATION)));
  const requests: PiExecutionRequest[] = [];
  const proxy = new PiExecutionProxy({ binding, transport: { async exchange(value) {
    requests.push(structuredClone(value));
    if (value.operation === "close") await beforeClose?.();
    return structuredClone(await endpoint.exchange(structuredClone(value)));
  } } });
  return { endpoint, requests, proxy, advances: checkpointFixture?.advances };
}
function host() {
  const capability = Object.freeze({ privilegedCall() { throw new Error("capability must remain on host"); } });
  return new SessionHost({ loader: { async get() { throw new Error("stock WorkerLoader is not this transport"); } },
    verifier: { async verify() { throw new Error("native execution qualification is not supplied"); } },
    bindings: { STATE: capability, WORKSPACE: capability, MODEL: capability, MCP: capability,
      EXECUTOR: capability, ARTIFACTS: capability, EVENTS: capability } });
}
async function genesis(): Promise<AgentCheckpoint> {
  return (await (await PiGenesisGenerator.create(await environment())).createGenesis(await request())).checkpoint;
}
function options(checkpoint: AgentCheckpoint, overrides: Partial<DriveTurnOptions> = {}): DriveTurnOptions {
  return { turnId: checkpoint.turnId, authority: new Uint8Array([1, 2, 3]), checkpoint,
    maximumEvents: 256, committer: { async commit() {} }, ephemeralSink: { async emit() {} }, ...overrides };
}
function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((yes) => { resolve = yes; });
  return { promise, resolve };
}
function effect(event: AgentEvent): { checkpoint: AgentCheckpoint; request: EffectIntent } {
  if (event.type !== "model_request" && event.type !== "tool_request") throw new Error("expected effect boundary");
  return { checkpoint: parseAgentCheckpoint(event.checkpoint), request: event.request as EffectIntent };
}
function settlement(digest: string, result: unknown) {
  return { requestDigest: digest, outcome: { kind: "success", result } };
}
function modelMessage(tool: boolean) {
  return { role: "assistant", api: CONFIGURATION.model.api, provider: CONFIGURATION.model.provider,
    model: CONFIGURATION.model.id, content: tool ? [
      { type: "text", text: "calling echo" },
      { type: "toolCall", id: "execution-echo-call", name: "echo", arguments: { value: 1.25 } },
    ] : [{ type: "text", text: "done" }],
    usage: { input: 1, output: 1, cacheRead: 0, cacheWrite: 0, totalTokens: 2,
      cost: { input: 0.000001, output: 0.000001, cacheRead: 0, cacheWrite: 0, total: 0.000002 } },
    stopReason: tool ? "toolUse" : "stop", timestamp: 1_700_000_000_001 };
}

describe("actual bundled Pi execution through primitive pull RPC", () => {
  it("resumes immediately on one composition while its committed boundary close is pending", async () => {
    const closeEntered = deferred(), releaseClose = deferred();
    const fixture = bridge("pi", async () => { closeEntered.resolve(); await releaseClose.promise; });
    const local = host();
    try {
      const first = effect((await local.startTurn(fixture.proxy, options(await genesis()))).boundary);
      await closeEntered.promise;
      let resumed = false;
      const continuation = local.resumeTurn(fixture.proxy, { ...options(first.checkpoint),
        settlement: settlement(first.request.requestDigest, { version: 1, message: modelMessage(true) }) });
      void continuation.then(() => { resumed = true; }, () => { resumed = true; });
      await new Promise<void>((resolve) => setTimeout(resolve, 0));
      expect(resumed).toBe(false);
      expect(fixture.requests.map((value) => value.operation)).toEqual(["start", "pull", "close"]);

      releaseClose.resolve();
      const tool = effect((await continuation).boundary);
      expect(tool.request.service).toBe("external-tool");
      const nextModel = effect((await local.resumeTurn(fixture.proxy, { ...options(tool.checkpoint),
        settlement: settlement(tool.request.requestDigest, { version: 1, toolCallId: "execution-echo-call",
          toolName: "echo", content: [{ type: "text", text: "1.25" }], isError: false,
          timestamp: 1_700_000_000_002 }) })).boundary);
      const result = await local.resumeTurn(fixture.proxy, { ...options(nextModel.checkpoint),
        settlement: settlement(nextModel.request.requestDigest, { version: 1, message: modelMessage(false) }) });
      expect(result.boundary.type).toBe("turn_complete");
      expect(parseAgentCheckpoint(result.boundary.checkpoint).checkpointSequence).toBe(4);
      expect(fixture.requests.filter((value) => value.operation === "resume")).toHaveLength(3);
    } finally {
      releaseClose.resolve();
      await fixture.endpoint.dispose();
    }
  });

  it("cold-reconstructs model → fractional tool → model → complete using committed checkpoints", async () => {
    const checkpoint = await genesis(), first = bridge(), firstHost = host();
    const firstBoundary = effect((await firstHost.startTurn(first.proxy, options(checkpoint))).boundary);
    expect(firstBoundary.request.service).toBe("model");
    await first.endpoint.dispose();

    const second = bridge(), secondHost = host();
    const toolBoundary = effect((await secondHost.resumeTurn(second.proxy, { ...options(firstBoundary.checkpoint),
      settlement: settlement(firstBoundary.request.requestDigest, { version: 1, message: modelMessage(true) }) })).boundary);
    expect(toolBoundary.request.service).toBe("external-tool");
    const payload = toolBoundary.request.payload as { toolCall: { arguments: NormalizedValue } };
    expect(decodePiJson(payload.toolCall.arguments)).toEqual({ value: 1.25 });
    await second.endpoint.dispose();

    const third = bridge(), thirdHost = host();
    const nextModel = effect((await thirdHost.resumeTurn(third.proxy, { ...options(toolBoundary.checkpoint),
      settlement: settlement(toolBoundary.request.requestDigest, { version: 1, toolCallId: "execution-echo-call",
        toolName: "echo", content: [{ type: "text", text: "1.25" }], isError: false, timestamp: 1_700_000_000_002 }) })).boundary);
    expect(nextModel.request.service).toBe("model");
    const context = decodePiAgentCoreModelContext((nextModel.request.payload as { context: NormalizedValue }).context);
    expect(context.messages).toHaveLength(4);
    expect(context.messages[2]).toMatchObject({ content: modelMessage(true).content });
    await third.endpoint.dispose();

    const fourth = bridge();
    const result = await host().resumeTurn(fourth.proxy, { ...options(nextModel.checkpoint),
      settlement: settlement(nextModel.request.requestDigest, { version: 1, message: modelMessage(false) }) });
    expect(result.boundary.type).toBe("turn_complete");
    expect(parseAgentCheckpoint(result.boundary.checkpoint).checkpointSequence).toBe(4);
    expect([...first.requests, ...second.requests, ...third.requests, ...fourth.requests]
      .some((value) => Object.hasOwn(value, "MODEL") || Object.hasOwn(value, "broker"))).toBe(false);
    await fourth.endpoint.dispose();
  });
  it("keeps the first durable model boundary pending until host commit completes", async () => {
    const checkpoint = await genesis(), fixture = bridge(), entered = deferred(), release = deferred();
    const pending = host().startTurn(fixture.proxy, options(checkpoint, { committer: { async commit() {
      entered.resolve(); await release.promise;
    } } }));
    await entered.promise;
    expect(fixture.requests.map((value) => value.operation)).toEqual(["start", "pull"]);
    release.resolve();
    expect((await pending).boundary.type).toBe("model_request");
    expect(fixture.requests.at(-1)?.operation).toBe("close");
    await fixture.endpoint.dispose();
  });
  it("aborts the owned remote execution when durable commit fails", async () => {
    const fixture = bridge();
    await expect(host().startTurn(fixture.proxy, options(await genesis(), { committer: { async commit() {
      throw new Error("test durable commit failed");
    } } }))).rejects.toMatchObject({ code: "DURABLE_COMMIT_FAILED" });
    expect(fixture.requests.filter((value) => value.operation === "pull")).toHaveLength(1);
    expect(fixture.requests.map((value) => value.operation)).toContain("abort");
    await fixture.endpoint.dispose();
  });
});

describe("bounded core fixtures through the bundled execution bridge", () => {
  it("does not pull the next event while the host's assistant delta sink is blocked", async () => {
    const fixture = bridge("delta"), entered = deferred(), release = deferred(), deltas: unknown[] = [];
    const pending = host().startTurn(fixture.proxy, options(await genesis(), { ephemeralSink: { async emit(event) {
      deltas.push(event.delta); entered.resolve(); await release.promise;
    } } }));
    await Promise.race([entered.promise, pending.then(() => { throw new Error("delta fixture ended without an event"); })]);
    expect(deltas).toEqual(["first"]);
    expect(fixture.requests.map((value) => value.operation)).toEqual(["start", "pull"]);
    await Promise.resolve(); await Promise.resolve();
    expect(fixture.requests.filter((value) => value.operation === "pull")).toHaveLength(1);
    release.resolve();
    expect((await pending).boundary.type).toBe("model_request");
    expect(deltas).toEqual(["first", "second"]);
    expect(fixture.requests.filter((value) => value.operation === "pull")).toHaveLength(3);
    await fixture.endpoint.dispose();
  });
  it("does not advance past an intermediate checkpoint until the host commits it", async () => {
    const fixture = bridge("checkpoint"), entered = deferred(), release = deferred(), commits: AgentEvent[] = [];
    const pending = host().startTurn(fixture.proxy, options(await genesis(), { committer: { async commit(event) {
      commits.push(event);
      if (event.type === "checkpoint") { entered.resolve(); await release.promise; }
    } } }));
    await Promise.race([entered.promise, pending.then(() => { throw new Error("checkpoint fixture ended without a checkpoint"); })]);
    expect(commits).toMatchObject([{ type: "checkpoint", checkpoint: { checkpointSequence: 1 } }]);
    expect(fixture.advances?.()).toBe(1);
    expect(fixture.requests.map((value) => value.operation)).toEqual(["start", "pull"]);
    await Promise.resolve(); await Promise.resolve();
    expect(fixture.advances?.()).toBe(1);
    release.resolve();
    expect((await pending).boundary.type).toBe("tool_request");
    expect(fixture.advances?.()).toBe(2);
    expect(commits).toMatchObject([{ type: "checkpoint" }, { type: "tool_request", checkpoint: { checkpointSequence: 2 } }]);
    expect(fixture.requests.filter((value) => value.operation === "pull")).toHaveLength(2);
    await fixture.endpoint.dispose();
  });
  it("aborts without a second advance when the intermediate checkpoint commit fails", async () => {
    const fixture = bridge("checkpoint");
    await expect(host().startTurn(fixture.proxy, options(await genesis(), { committer: { async commit(event) {
      expect(event.type).toBe("checkpoint");
      throw new Error("intermediate checkpoint commit failed");
    } } }))).rejects.toMatchObject({ code: "DURABLE_COMMIT_FAILED" });
    expect(fixture.advances?.()).toBe(1);
    expect(fixture.requests.map((value) => value.operation)).toEqual(["start", "pull", "abort"]);
    await fixture.endpoint.dispose();
  });
});
