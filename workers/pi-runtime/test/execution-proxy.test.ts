import { describe, expect, it, vi } from "vitest";
import { digestStructuredValue, type AgentCheckpoint } from "@circulusd/protocol-types";
import type { AgentEvent, StartTurnContext } from "../../session-host/src/index.ts";

import { createOpaqueTurnAuthority } from "../src/authority.ts";
import { LowLevelPiAgentEngine } from "../src/engine.ts";
import { PiExecutionProxy } from "../src/execution-proxy.ts";
import {
  snapshotExecutionRequest, type PiExecutionBinding, type PiExecutionReply, type PiExecutionRequest,
} from "../src/execution-rpc.ts";
import { SCOPE, REVISION } from "./genesis-fixtures.ts";

const binding = (): PiExecutionBinding => ({ scope: { ...SCOPE }, runtimeRevisionDigest: REVISION,
  artifactDigest: `sha256:${"b".repeat(64)}` });
type Mutable<T> = { -readonly [Key in keyof T]: T[Key] };
const header = (request: PiExecutionRequest) => ({ protocol: request.protocol, version: request.version,
  binding: request.binding, turnId: request.turnId, executionId: request.executionId,
  sequence: request.sequence, operation: request.operation });
function reply(request: PiExecutionRequest, event?: AgentEvent): PiExecutionReply {
  if (request.operation === "start" || request.operation === "resume") return { ...header(request), status: "opened" };
  if (request.operation === "close") return { ...header(request), status: "closed" };
  if (request.operation === "abort") return { ...header(request), status: "aborted" };
  return event === undefined ? { ...header(request), status: "done" } : { ...header(request), status: "event", event };
}
async function fixture(turnId = "turn_proxy") {
  const engine = new LowLevelPiAgentEngine({ sessionId: SCOPE.sessionId, runtimeRevisionDigest: REVISION,
    adapterAbiVersion: 2, checkpointSchemaVersion: 2 }, () => ({
    async advance() {
      return { kind: "model_request", state: { phase: "waiting" }, assistantDeltas: ["first", "second"],
        request: { service: "model", operation: "complete", replayPolicy: "idempotency-key", payload: { prompt: "hello" } } };
    },
  }));
  const checkpoint = await engine.createGenesisCheckpoint({ turnId, input: { prompt: "hello" }, initialCoreState: {} });
  const boundary = await engine.step({ authority: createOpaqueTurnAuthority(new Uint8Array([1])), checkpoint });
  if (boundary.kind !== "effect_request") throw new Error("invalid test boundary");
  const event: AgentEvent = { type: "model_request", checkpoint: boundary.checkpoint, request: boundary.request };
  const context: StartTurnContext = { turnId, executionId: "exec_proxy", authority: new Uint8Array([1, 2, 3]), checkpoint };
  return { checkpoint, event, context };
}
function transport(events: AgentEvent[] = []) {
  const requests: PiExecutionRequest[] = [];
  const exchange = vi.fn(async (input: PiExecutionRequest) => {
    const request = snapshotExecutionRequest(input);
    requests.push(request);
    return reply(request, request.operation === "pull" ? events.shift() : undefined);
  });
  return { requests, exchange };
}
const iterator = (proxy: PiExecutionProxy, context: StartTurnContext) => proxy.startTurn(context)[Symbol.asyncIterator]();

describe("Pi execution host proxy", () => {
  it("opens lazily and transports one event for each numbered pull without prefetch", async () => {
    const source = await fixture();
    const wire = transport([{ type: "assistant_delta", delta: "first" }, { type: "assistant_delta", delta: "second" }, source.event]);
    const proxy = new PiExecutionProxy({ binding: binding(), transport: wire });
    const stream = iterator(proxy, source.context);
    expect(wire.requests).toEqual([]);
    expect(await stream.next()).toEqual({ done: false, value: { type: "assistant_delta", delta: "first" } });
    await Promise.resolve();
    expect(wire.requests.map((value) => value.operation)).toEqual(["start", "pull"]);
    expect(await stream.next()).toEqual({ done: false, value: { type: "assistant_delta", delta: "second" } });
    expect((await stream.next()).value).toEqual(source.event);
    expect(wire.requests.filter((value) => value.operation === "pull").map((value) => value.sequence)).toEqual([1, 2, 3]);
    await stream.return?.();
    expect(wire.requests.at(-1)?.operation).toBe("close");
    expect(await stream.next()).toEqual({ done: true, value: undefined });
  });

  it("snapshots constructor bindings, raw context bytes and captured exchange before any await", async () => {
    const source = await fixture();
    const mutableBinding = binding();
    const wire = transport([{ type: "assistant_delta", delta: "first" }]);
    const proxy = new PiExecutionProxy({ binding: mutableBinding, transport: wire });
    const stream = iterator(proxy, source.context);
    (mutableBinding.scope as { actorSubjectId: string }).actorSubjectId = `subject_${"B".repeat(25)}A`;
    source.context.authority.fill(255);
    (source.context.checkpoint as AgentCheckpoint).payloadBytes.fill(255);
    wire.exchange = vi.fn(async () => { throw new Error("mutated transport secret"); });
    expect((await stream.next()).value).toEqual({ type: "assistant_delta", delta: "first" });
    const opened = wire.requests[0];
    expect(opened?.binding).toEqual(binding());
    expect(opened?.operation === "start" && Array.from(opened.authority)).toEqual([1, 2, 3]);
    expect(Reflect.ownKeys(stream)).toEqual([]);
    await stream.return?.();
  });

  it("preserves finite fractional raw resume settlements for remote Pi normalization", async () => {
    const source = await fixture();
    const wire = transport();
    const proxy = new PiExecutionProxy({ binding: binding(), transport: wire });
    const settlement = { requestDigest: "test-raw", outcome: { kind: "success", result: { price: 0.125, temperature: -0.25 } } };
    const stream = proxy.resumeTurn({ ...source.context, settlement })[Symbol.asyncIterator]();
    settlement.outcome.result.price = 999;
    await stream.next();
    expect(wire.requests[0]).toMatchObject({ operation: "resume", settlement: { outcome: { result: { price: 0.125, temperature: -0.25 } } } });
  });

  it("rejects concurrent pulls before sending a second transport operation", async () => {
    const source = await fixture();
    const gate = Promise.withResolvers<unknown>();
    const requests: PiExecutionRequest[] = [];
    const proxy = new PiExecutionProxy({ binding: binding(), transport: { exchange: async (request) => {
      requests.push(request);
      return request.operation === "pull" ? gate.promise : reply(request);
    } } });
    const stream = iterator(proxy, source.context);
    const first = stream.next();
    await vi.waitFor(() => expect(requests).toHaveLength(2));
    await expect(stream.next()).rejects.toMatchObject({ code: "STEP_IN_PROGRESS" });
    expect(requests).toHaveLength(2);
    gate.resolve(reply(requests[1]!, { type: "assistant_delta", delta: "one" }));
    expect((await first).value).toMatchObject({ delta: "one" });
    await stream.return?.();
  });

  it("rejects duplicate active turn ownership without poisoning its current iterator", async () => {
    const source = await fixture();
    const wire = transport([{ type: "assistant_delta", delta: "one" }, { type: "assistant_delta", delta: "two" }]);
    const proxy = new PiExecutionProxy({ binding: binding(), transport: wire });
    const first = iterator(proxy, source.context);
    await first.next();
    const second = iterator(proxy, { ...source.context, executionId: "exec_duplicate" });
    await expect(second.next()).rejects.toMatchObject({ code: "STEP_IN_PROGRESS" });
    expect((await first.next()).value).toMatchObject({ delta: "two" });
    await first.return?.();
  });

  it("closes only the owned execution and ignores stale abort and repeated return after replacement", async () => {
    const source = await fixture();
    const wire = transport([{ type: "assistant_delta", delta: "old" }, { type: "assistant_delta", delta: "new" }]);
    const proxy = new PiExecutionProxy({ binding: binding(), transport: wire });
    const old = iterator(proxy, source.context);
    await old.next();
    await old.return?.();
    const current = iterator(proxy, { ...source.context, executionId: "exec_replacement" });
    await current.next();
    const before = wire.requests.length;
    await proxy.abortTurn(source.context.turnId, source.context.executionId);
    await old.return?.();
    expect(wire.requests).toHaveLength(before);
    await proxy.abortTurn(source.context.turnId, "exec_replacement");
    expect(wire.requests.at(-1)).toMatchObject({ operation: "abort", executionId: "exec_replacement" });
    expect(await current.next()).toEqual({ done: true, value: undefined });
  });

  it("does not send close or abort for an iterator that never opened", async () => {
    const source = await fixture();
    const wire = transport();
    const proxy = new PiExecutionProxy({ binding: binding(), transport: wire });
    const stream = iterator(proxy, source.context);
    await stream.return?.();
    await proxy.abortTurn(source.context.turnId, source.context.executionId);
    expect(wire.requests).toEqual([]);
  });

  for (const name of ["protocol", "version", "actor", "tenant", "workspace", "session", "revision", "artifact", "turn", "execution", "operation", "sequence"] as const) {
    it(`poisons the proxy before exposing a reply with mismatched ${name}`, async () => {
      const source = await fixture();
      const requests: PiExecutionRequest[] = [];
      const proxy = new PiExecutionProxy({ binding: binding(), transport: { exchange: async (request) => {
        requests.push(request);
        const value = structuredClone(reply(request, source.event)) as unknown as Record<string, unknown>;
        if (request.operation !== "pull") return value;
        const pinned = value.binding as { scope: Record<string, string>; runtimeRevisionDigest: string; artifactDigest: string };
        if (name === "protocol") value.protocol = "different";
        if (name === "version") value.version = 2;
        if (name === "actor") pinned.scope.actorSubjectId = `subject_${"B".repeat(25)}A`;
        if (name === "tenant") pinned.scope.tenantId = `tenant_${"B".repeat(25)}A`;
        if (name === "workspace") pinned.scope.workspaceId = `ws_${"B".repeat(25)}A`;
        if (name === "session") pinned.scope.sessionId = `sess_${"B".repeat(25)}A`;
        if (name === "revision") pinned.runtimeRevisionDigest = `sha256:${"c".repeat(64)}`;
        if (name === "artifact") pinned.artifactDigest = `sha256:${"c".repeat(64)}`;
        if (name === "turn") value.turnId = "turn_other";
        if (name === "execution") value.executionId = "exec_other";
        if (name === "operation") { value.operation = "close"; value.sequence = 0; value.status = "closed"; delete value.event; }
        if (name === "sequence") value.sequence = 99;
        return value;
      } } });
      const stream = iterator(proxy, source.context);
      await expect(stream.next()).rejects.toMatchObject({ code: "ENGINE_POISONED" });
      expect(() => proxy.startTurn({ ...source.context, executionId: "exec_again" })).toThrow("invalid or unavailable");
      await expect(stream.next()).rejects.toMatchObject({ code: "ENGINE_POISONED" });
      await vi.waitFor(() => expect(requests.some((value) => value.operation === "abort")).toBe(true));
      expect(requests.filter((value) => value.operation === "pull")).toHaveLength(1);
    });
  }

  for (const change of ["sequence", "predecessor", "session", "turn", "revision", "abi", "schema", "payload", "effect-digest", "event-service"] as const) {
    it(`rejects a durable event with invalid ${change} before exposure`, async () => {
      const source = await fixture();
      const event = structuredClone(source.event) as Extract<AgentEvent, { type: "model_request" }>;
      const checkpoint = event.checkpoint as Mutable<AgentCheckpoint>;
      if (change === "sequence") checkpoint.checkpointSequence += 1;
      if (change === "predecessor") checkpoint.predecessorDigest = `sha256:${"f".repeat(64)}`;
      if (change === "session") checkpoint.sessionId = "session_other";
      if (change === "turn") checkpoint.turnId = "turn_other";
      if (change === "revision") checkpoint.runtimeRevisionDigest = `sha256:${"f".repeat(64)}`;
      if (change === "abi") checkpoint.adapterAbiVersion = 3;
      if (change === "schema") checkpoint.checkpointSchemaVersion = 3;
      if (change === "payload") checkpoint.payloadBytes[0] = (checkpoint.payloadBytes[0] ?? 0) ^ 255;
      if (change === "effect-digest") (event.request as { requestDigest: string }).requestDigest = `sha256:${"f".repeat(64)}`;
      if (change === "event-service") (event as { type: string }).type = "tool_request";
      const proxy = new PiExecutionProxy({ binding: binding(), transport: transport([event]) });
      await expect(iterator(proxy, source.context).next()).rejects.toMatchObject({ code: "ENGINE_POISONED" });
    });
  }

  it("verifies a checkpoint event and uses its full digest as the next predecessor", async () => {
    const source = await fixture();
    const first = structuredClone(source.event.checkpoint) as AgentCheckpoint;
    const second = structuredClone(first) as Mutable<AgentCheckpoint>;
    second.checkpointSequence += 1;
    second.predecessorDigest = await digestStructuredValue("circulusd.session.agent-checkpoint", 1, first);
    const wire = transport([{ type: "checkpoint", checkpoint: first }, { ...source.event, checkpoint: second }]);
    const stream = iterator(new PiExecutionProxy({ binding: binding(), transport: wire }), source.context);
    const emitted = await stream.next();
    (emitted.value as { checkpoint: AgentCheckpoint }).checkpoint.payloadBytes.fill(255);
    expect((await stream.next()).value).toMatchObject({ type: "model_request", checkpoint: { checkpointSequence: 2 } });
    await stream.return?.();
  });

  for (const event of [{ type: "assistant_delta", delta: "x".repeat(65_537) },
    { type: "assistant_delta", delta: 1.5 }, { type: "assistant_delta", delta: "one", hidden: true },
    { type: "unknown", checkpoint: {} }] as const) {
    it("rejects malformed or oversized events", async () => {
      const source = await fixture();
      const proxy = new PiExecutionProxy({ binding: binding(), transport: transport([event as AgentEvent]) });
      await expect(iterator(proxy, source.context).next()).rejects.toMatchObject({ code: "ENGINE_POISONED" });
    });
  }

  it("sanitizes transport failures, performs no retries and poisons every active iterator", async () => {
    const source = await fixture();
    const other = await fixture("turn_other");
    const requests: PiExecutionRequest[] = [];
    let failing = false;
    const proxy = new PiExecutionProxy({ binding: binding(), transport: { exchange: async (request) => {
      requests.push(request);
      if (request.operation === "pull" && failing) throw new Error("provider credential secret");
      return reply(request, { type: "assistant_delta", delta: "one" });
    } } });
    const first = iterator(proxy, source.context);
    const second = iterator(proxy, { ...other.context, executionId: "exec_other" });
    await first.next();
    await second.next();
    failing = true;
    const failure = await first.next().catch((error: unknown) => error);
    expect(failure).toMatchObject({ message: "Pi execution proxy is invalid or unavailable", code: "ENGINE_POISONED" });
    expect((failure as Error).cause).toBeUndefined();
    await expect(second.next()).rejects.toMatchObject({ code: "ENGINE_POISONED" });
    await vi.waitFor(() => expect(requests.filter((value) => value.operation === "abort")).toHaveLength(2));
    expect(requests.filter((value) => value.operation === "pull")).toHaveLength(3);
  });

  it("times out ambiguous pull, rejects late events and forbids reuse", async () => {
    const source = await fixture();
    const gate = Promise.withResolvers<unknown>();
    const requests: PiExecutionRequest[] = [];
    const proxy = new PiExecutionProxy({ binding: binding(), timeoutMs: 1_000, transport: { exchange: async (request) => {
      requests.push(request);
      return request.operation === "pull" && request.sequence === 2 ? gate.promise : reply(request, { type: "assistant_delta", delta: "first" });
    } } });
    const stream = iterator(proxy, source.context);
    await stream.next();
    vi.useFakeTimers();
    try {
      const pending = stream.next();
      const assertion = expect(pending).rejects.toMatchObject({ code: "ENGINE_POISONED" });
      await vi.advanceTimersByTimeAsync(1_000);
      await assertion;
      const pull = requests.find((value) => value.operation === "pull" && value.sequence === 2);
      expect(pull).toBeDefined();
      gate.resolve(reply(pull!, source.event));
      await Promise.resolve();
      await expect(stream.next()).rejects.toMatchObject({ code: "ENGINE_POISONED" });
      expect(() => proxy.startTurn(source.context)).toThrow("invalid or unavailable");
    } finally { vi.useRealTimers(); }
  });

  it("bounds return cleanup even when the remote close never replies", async () => {
    const source = await fixture();
    const requests: PiExecutionRequest[] = [];
    const proxy = new PiExecutionProxy({ binding: binding(), timeoutMs: 1_000, transport: { exchange: async (request) => {
      requests.push(request);
      return request.operation === "close" ? new Promise<never>(() => {}) : reply(request, { type: "assistant_delta", delta: "one" });
    } } });
    const stream = iterator(proxy, source.context);
    await stream.next();
    vi.useFakeTimers();
    try {
      const closed = stream.return?.();
      await vi.advanceTimersByTimeAsync(1_000);
      expect(await closed).toEqual({ done: true, value: undefined });
      expect(() => proxy.startTurn(source.context)).toThrow("invalid or unavailable");
    } finally { vi.useRealTimers(); }
  });

  it("discards an in-flight event after caller return and sends only one close", async () => {
    const source = await fixture();
    const gate = Promise.withResolvers<unknown>();
    const requests: PiExecutionRequest[] = [];
    const proxy = new PiExecutionProxy({ binding: binding(), transport: { exchange: async (request) => {
      requests.push(request);
      return request.operation === "pull" ? gate.promise : reply(request);
    } } });
    const stream = iterator(proxy, source.context);
    const pending = stream.next();
    await vi.waitFor(() => expect(requests).toHaveLength(2));
    await stream.return?.();
    await stream.return?.();
    gate.resolve(reply(requests[1]!, source.event));
    expect(await pending).toEqual({ done: true, value: undefined });
    expect(requests.filter((value) => value.operation === "close")).toHaveLength(1);
  });

  it("never resurrects a closed execution when its delayed open is rejected", async () => {
    const source = await fixture();
    const gate = Promise.withResolvers<unknown>();
    const requests: PiExecutionRequest[] = [];
    const proxy = new PiExecutionProxy({ binding: binding(), transport: { exchange: async (request) => {
      requests.push(request);
      return request.operation === "start" ? gate.promise : reply(request);
    } } });
    const stream = iterator(proxy, source.context);
    const pending = stream.next();
    await vi.waitFor(() => expect(requests[0]?.operation).toBe("start"));
    await stream.return?.();
    const assertion = expect(pending).rejects.toMatchObject({ code: "ENGINE_POISONED" });
    gate.reject(new Error("execution was already closed"));
    await assertion;
    expect(requests.some((value) => value.operation === "pull")).toBe(false);
    expect(() => proxy.startTurn({ ...source.context, executionId: "exec_after_late_open" })).toThrow("invalid or unavailable");
  });

  it("bounds resident executions before sending delayed opens", async () => {
    const source = await fixture();
    const gates = new Map<string, ReturnType<typeof Promise.withResolvers<unknown>>>();
    const requests: PiExecutionRequest[] = [];
    const proxy = new PiExecutionProxy({ binding: binding(), transport: { exchange: async (request) => {
      requests.push(request);
      if (request.operation !== "start") return reply(request);
      const gate = Promise.withResolvers<unknown>(); gates.set(request.executionId, gate);
      return gate.promise;
    } } });
    const streams = Array.from({ length: 65 }, (_, index) => iterator(proxy, { ...source.context,
      turnId: `turn_capacity_${index}`, executionId: `exec_capacity_${index}`,
      checkpoint: { ...source.checkpoint, turnId: `turn_capacity_${index}` } }));
    const pending = streams.slice(0, 64).map((stream) => stream.next());
    await vi.waitFor(() => expect(requests.filter((value) => value.operation === "start")).toHaveLength(64));
    await expect(streams[64]!.next()).rejects.toMatchObject({ code: "STEP_IN_PROGRESS" });
    expect(requests.filter((value) => value.operation === "start")).toHaveLength(64);
    await Promise.all(streams.slice(0, 64).map((stream) => stream.return?.()));
    for (const request of requests.filter((value) => value.operation === "start")) gates.get(request.executionId)?.resolve(reply(request));
    expect(await Promise.all(pending)).toEqual(Array.from({ length: 64 }, () => ({ done: true, value: undefined })));
  });

  for (const timeoutMs of [0, -1, 0.5, 30_001, Infinity]) {
    it(`rejects invalid timeout ${timeoutMs}`, () => {
      expect(() => new PiExecutionProxy({ binding: binding(), transport: transport(), timeoutMs })).toThrow("configuration is invalid");
    });
  }

  it("rejects accessor, cyclic, oversized and mismatched context before transport", async () => {
    const source = await fixture();
    const wire = transport();
    const proxy = new PiExecutionProxy({ binding: binding(), transport: wire });
    const getter = vi.fn(() => source.context.authority);
    const accessed = { ...source.context };
    Object.defineProperty(accessed, "authority", { enumerable: true, get: getter });
    expect(() => proxy.startTurn(accessed)).toThrow("context is invalid");
    expect(getter).not.toHaveBeenCalled();
    expect(() => proxy.startTurn({ ...source.context, authority: new Uint8Array(4097) })).toThrow("context is invalid");
    expect(() => proxy.startTurn({ ...source.context, checkpoint: { ...source.checkpoint, sessionId: "wrong" } })).toThrow("context is invalid");
    const cyclic: Record<string, unknown> = {}; cyclic.self = cyclic;
    expect(() => proxy.resumeTurn({ ...source.context, settlement: cyclic })).toThrow("context is invalid");
    expect(() => proxy.resumeTurn({ ...source.context, settlement: { text: "x".repeat(6 * 1_048_576) } })).toThrow("context is invalid");
    expect(wire.requests).toEqual([]);
  });
});
