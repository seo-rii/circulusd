import { describe, expect, it, vi } from "vitest";
import type { AgentEngine, AgentEvent, ResumeTurnContext, StartTurnContext } from "../../session-host/src/index.ts";
import { LowLevelPiAgentEngine } from "../src/engine.ts";
import { PiExecutionEndpoint } from "../src/execution-endpoint.ts";
import { PI_EXECUTION_PROTOCOL, type PiExecutionBinding, type PiExecutionRequest } from "../src/execution-rpc.ts";

const binding = (): PiExecutionBinding => ({
  scope: { tenantId: `tenant_${"A".repeat(26)}`, workspaceId: `ws_${"A".repeat(26)}`,
    actorSubjectId: `subject_${"A".repeat(26)}`, sessionId: `sess_${"A".repeat(26)}` },
  runtimeRevisionDigest: `sha256:${"1".repeat(64)}`, artifactDigest: `sha256:${"2".repeat(64)}`,
});
const failure = { name: "PiRuntimeError", code: "INVALID_CONTEXT", message: "Pi execution RPC is invalid or unavailable" };

async function fixture(options: { maximumExecutions?: number; maximumLifetimeExecutions?: number } = {}) {
  const scope = binding();
  const low = new LowLevelPiAgentEngine({ sessionId: scope.scope.sessionId,
    runtimeRevisionDigest: scope.runtimeRevisionDigest, adapterAbiVersion: 2, checkpointSchemaVersion: 2 },
  () => ({ advance: async () => ({ kind: "turn_complete", state: {}, result: {} }) }));
  const checkpoint = await low.createGenesisCheckpoint({ turnId: "turn_a", input: {}, initialCoreState: {} });
  const next = vi.fn<() => Promise<IteratorResult<AgentEvent>>>(async () => ({ done: true, value: undefined }));
  const close = vi.fn(async () => ({ done: true as const, value: undefined }));
  const abort = vi.fn(async (_turnId: string, _executionId?: string) => {});
  const contexts: Array<StartTurnContext | ResumeTurnContext> = [];
  const create = vi.fn((): AgentEngine => ({
    startTurn(context) { contexts.push(context); return { [Symbol.asyncIterator]: () => ({ next, return: close }) }; },
    resumeTurn(context) { contexts.push(context); return { [Symbol.asyncIterator]: () => ({ next, return: close }) }; },
    abortTurn: abort,
  }));
  const endpoint = new PiExecutionEndpoint({ binding: scope, createEngine: create, ...options });
  const request = (operation: PiExecutionRequest["operation"], executionId = "execution_a", sequence = 0): PiExecutionRequest => {
    const header = { protocol: PI_EXECUTION_PROTOCOL, version: 1, binding: binding(),
      turnId: "turn_a", executionId, sequence } as const;
    return operation === "start" ? { ...header, operation, authority: new Uint8Array([17, 23]), checkpoint: structuredClone(checkpoint) } :
      operation === "resume" ? { ...header, operation, authority: new Uint8Array([17, 23]), checkpoint: structuredClone(checkpoint),
        settlement: { fraction: 0.0001 } } : { ...header, operation };
  };
  return { endpoint, request, contexts, next, close, abort, create, checkpoint };
}

describe("PiExecutionEndpoint", () => {
  it("registers without advancing and returns only the explicit opened header", async () => {
    const f = await fixture();
    const request = f.request("start");
    const opened = await f.endpoint.exchange(request);
    expect(opened).toEqual({ protocol: PI_EXECUTION_PROTOCOL, version: 1, binding: binding(),
      turnId: "turn_a", executionId: "execution_a", sequence: 0, operation: "start", status: "opened" });
    expect(f.next).not.toHaveBeenCalled();
    if (request.operation !== "start") throw new Error("test fixture");
    request.authority.fill(0);
    expect(f.contexts[0]?.authority).toEqual(new Uint8Array([17, 23]));
    await f.endpoint.exchange(f.request("close"));
  });

  it("preserves finite fractional settlement until the adapter normalizes it", async () => {
    const f = await fixture();
    await f.endpoint.exchange(f.request("resume"));
    expect(f.contexts[0]).toMatchObject({ settlement: { fraction: 0.0001 } });
    expect(f.next).not.toHaveBeenCalled();
    await f.endpoint.dispose();
  });

  it("advances exactly one event per ordered pull and owns returned event values", async () => {
    const f = await fixture();
    const event: AgentEvent = { type: "assistant_delta", delta: { text: "first" } };
    f.next.mockResolvedValueOnce({ done: false, value: event });
    await f.endpoint.exchange(f.request("start"));
    const reply = await f.endpoint.exchange(f.request("pull", "execution_a", 1));
    expect(reply).toMatchObject({ status: "event", sequence: 1, event });
    if (event.type !== "assistant_delta") throw new Error("test fixture");
    (event.delta as { text: string }).text = "changed";
    expect(reply).toMatchObject({ event: { delta: { text: "first" } } });
    expect(f.next).toHaveBeenCalledTimes(1);
    await expect(f.endpoint.exchange(f.request("pull", "execution_a", 2))).resolves.toMatchObject({ status: "done" });
    expect(f.close).toHaveBeenCalledTimes(1);
  });

  it("rejects duplicate opens and duplicate/out-of-order/simultaneous pulls before advance", async () => {
    const f = await fixture();
    await f.endpoint.exchange(f.request("start"));
    await expect(f.endpoint.exchange(f.request("start"))).rejects.toMatchObject(failure);
    await expect(f.endpoint.exchange(f.request("pull", "execution_a", 2))).rejects.toMatchObject(failure);
    const gate = Promise.withResolvers<IteratorResult<AgentEvent>>();
    f.next.mockReturnValueOnce(gate.promise);
    const pulling = f.endpoint.exchange(f.request("pull", "execution_a", 1));
    await Promise.resolve();
    await expect(f.endpoint.exchange(f.request("pull", "execution_a", 1))).rejects.toMatchObject(failure);
    await expect(f.endpoint.exchange(f.request("pull", "execution_a", 2))).rejects.toMatchObject(failure);
    expect(f.next).toHaveBeenCalledTimes(1);
    gate.resolve({ done: false, value: { type: "assistant_delta", delta: "first" } });
    await pulling;
    await expect(f.endpoint.exchange(f.request("pull", "execution_a", 1))).rejects.toMatchObject(failure);
    await f.endpoint.dispose();
  });

  it.each(["tenantId", "workspaceId", "actorSubjectId", "sessionId", "runtimeRevisionDigest", "artifactDigest"])(
    "rejects a changed %s binding before factory I/O", async (field) => {
      const f = await fixture();
      const request = structuredClone(f.request("start"));
      if (field === "runtimeRevisionDigest" || field === "artifactDigest") {
        Object.assign(request.binding, { [field]: `sha256:${"3".repeat(64)}` });
      } else {
        const prefix = { tenantId: "tenant", workspaceId: "ws", actorSubjectId: "subject", sessionId: "sess" }[field];
        Object.assign(request.binding.scope, { [field]: `${prefix}_${"B".repeat(25)}A` });
      }
      await expect(f.endpoint.exchange(request)).rejects.toMatchObject(failure);
      expect(f.create).not.toHaveBeenCalled();
    });

  it("fences turn ownership and stale controls while allowing a fresh replacement execution", async () => {
    const f = await fixture();
    await f.endpoint.exchange(f.request("start"));
    await expect(f.endpoint.exchange(f.request("start", "replacement"))).rejects.toMatchObject(failure);
    await expect(f.endpoint.exchange({ ...f.request("abort"), turnId: "other_turn" })).rejects.toMatchObject(failure);
    expect(f.abort).not.toHaveBeenCalled();
    await f.endpoint.exchange(f.request("close"));
    await f.endpoint.exchange(f.request("start", "replacement"));
    await f.endpoint.exchange(f.request("abort"));
    expect(f.abort).not.toHaveBeenCalled();
    expect(f.create).toHaveBeenCalledTimes(2);
    await f.endpoint.exchange(f.request("abort", "replacement"));
    expect(f.abort).toHaveBeenCalledWith("turn_a", "replacement");
  });

  it.each(["close", "abort"] as const)("retains a preemptive %s tombstone before delayed open arrives", async (operation) => {
    const f = await fixture();
    await f.endpoint.exchange(f.request(operation));
    await expect(f.endpoint.exchange(f.request("start"))).rejects.toMatchObject(failure);
    await expect(f.endpoint.exchange(f.request("resume"))).rejects.toMatchObject(failure);
    expect(f.create).not.toHaveBeenCalled();
    expect(f.abort).not.toHaveBeenCalled();
  });

  it("does not evict retired identities when the lifetime identity budget is exhausted", async () => {
    const f = await fixture({ maximumLifetimeExecutions: 2 });
    await f.endpoint.exchange(f.request("close", "old_a"));
    await f.endpoint.exchange(f.request("abort", "old_b"));
    await expect(f.endpoint.exchange(f.request("start", "new_c"))).rejects.toMatchObject(failure);
    await expect(f.endpoint.exchange(f.request("start", "old_a"))).rejects.toMatchObject(failure);
    await expect(f.endpoint.exchange(f.request("close", "old_a"))).resolves.toMatchObject({ status: "closed" });
    expect(f.create).not.toHaveBeenCalled();
  });

  it("bounds live executions and releases the slot after cooperative closure", async () => {
    const f = await fixture({ maximumExecutions: 1 });
    await f.endpoint.exchange(f.request("start"));
    const second = f.request("start", "execution_b");
    if (second.operation !== "start") throw new Error("test fixture");
    Object.assign(second, { turnId: "turn_b", checkpoint: { ...f.checkpoint, turnId: "turn_b" } });
    await expect(f.endpoint.exchange(second)).rejects.toMatchObject(failure);
    await f.endpoint.exchange(f.request("close"));
    await expect(f.endpoint.exchange(second)).resolves.toMatchObject({ status: "opened" });
    await f.endpoint.dispose();
  });

  it("unblocks a pending pull before cooperative close settles and discards its late event", async () => {
    const f = await fixture();
    const next = Promise.withResolvers<IteratorResult<AgentEvent>>();
    const cleanup = Promise.withResolvers<{ done: true; value: undefined }>();
    f.next.mockReturnValueOnce(next.promise);
    f.close.mockReturnValueOnce(cleanup.promise);
    await f.endpoint.exchange(f.request("start"));
    const pulling = f.endpoint.exchange(f.request("pull", "execution_a", 1));
    await Promise.resolve();
    const closing = f.endpoint.exchange(f.request("close"));
    await expect(pulling).resolves.toMatchObject({ status: "done" });
    next.resolve({ done: false, value: { type: "assistant_delta", delta: "late" } });
    cleanup.resolve({ done: true, value: undefined });
    await expect(closing).resolves.toMatchObject({ status: "closed" });
    await expect(f.endpoint.exchange(f.request("pull", "execution_a", 2))).rejects.toMatchObject(failure);
  });

  it("retains resident capacity until blocked cleanup settles and permits owned abort escalation", async () => {
    const f = await fixture({ maximumExecutions: 1 });
    const cleanup = Promise.withResolvers<{ done: true; value: undefined }>();
    f.close.mockReturnValueOnce(cleanup.promise);
    await f.endpoint.exchange(f.request("start"));
    const closing = f.endpoint.exchange(f.request("close"));
    await Promise.resolve();
    const second = f.request("start", "execution_b");
    if (second.operation !== "start") throw new Error("test fixture");
    Object.assign(second, { turnId: "turn_b", checkpoint: { ...f.checkpoint, turnId: "turn_b" } });
    await expect(f.endpoint.exchange(second)).rejects.toMatchObject(failure);
    const aborting = f.endpoint.exchange(f.request("abort"));
    await Promise.resolve();
    expect(f.abort).toHaveBeenCalledWith("turn_a", "execution_a");
    cleanup.resolve({ done: true, value: undefined });
    await closing;
    await aborting;
    await expect(f.endpoint.exchange(second)).resolves.toMatchObject({ status: "opened" });
    await f.endpoint.dispose();
  });

  it("aborts only the owned execution and closes its iterator exactly once", async () => {
    const f = await fixture();
    await f.endpoint.exchange(f.request("start"));
    await f.endpoint.exchange(f.request("abort"));
    await f.endpoint.exchange(f.request("abort"));
    expect(f.abort).toHaveBeenCalledTimes(1);
    expect(f.abort).toHaveBeenCalledWith("turn_a", "execution_a");
    expect(f.close).toHaveBeenCalledTimes(1);
  });

  it("disposes cooperatively, unblocks pending pulls and rejects subsequent exchanges", async () => {
    const f = await fixture();
    const gate = Promise.withResolvers<IteratorResult<AgentEvent>>();
    f.next.mockReturnValueOnce(gate.promise);
    await f.endpoint.exchange(f.request("start"));
    const pulling = f.endpoint.exchange(f.request("pull", "execution_a", 1));
    await Promise.resolve();
    await f.endpoint.dispose();
    await expect(pulling).resolves.toMatchObject({ status: "done" });
    gate.resolve({ done: false, value: { type: "assistant_delta", delta: "late" } });
    await expect(f.endpoint.exchange(f.request("start", "replacement"))).rejects.toMatchObject(failure);
    await f.endpoint.dispose();
    expect(f.abort).toHaveBeenCalledTimes(1);
  });

  it.each(["iterator failure", "unknown event", "oversized event"])("sanitizes %s and cleans its suspended producer", async (kind) => {
    const f = await fixture();
    if (kind === "iterator failure") f.next.mockRejectedValueOnce(new Error("private diagnostic / credential"));
    else f.next.mockResolvedValueOnce({ done: false, value: kind === "unknown event" ?
      { type: "unknown", authority: "private" } as unknown as AgentEvent :
      { type: "assistant_delta", delta: "x".repeat(2 * 1_048_576) } });
    await f.endpoint.exchange(f.request("start"));
    await expect(f.endpoint.exchange(f.request("pull", "execution_a", 1))).rejects.toMatchObject(failure);
    await f.endpoint.exchange(f.request("close"));
    expect(f.close).toHaveBeenCalledTimes(1);
    expect(f.abort).toHaveBeenCalledTimes(1);
    await expect(f.endpoint.exchange(f.request("start"))).rejects.toMatchObject(failure);
  });

  it("retires a failed open and cooperatively aborts acquired engine ownership", async () => {
    const f = await fixture();
    f.create.mockReturnValueOnce({ startTurn: () => { throw new Error("private detail"); },
      resumeTurn: () => { throw new Error("private detail"); }, abortTurn: f.abort });
    await expect(f.endpoint.exchange(f.request("start"))).rejects.toMatchObject(failure);
    await f.endpoint.exchange(f.request("close"));
    expect(f.abort).toHaveBeenCalledWith("turn_a", "execution_a");
    await expect(f.endpoint.exchange(f.request("start"))).rejects.toMatchObject(failure);
  });

  it("requires a fresh endpoint after failed cooperative cleanup", async () => {
    const f = await fixture();
    f.close.mockRejectedValueOnce(new Error("private teardown error"));
    await f.endpoint.exchange(f.request("start"));
    await expect(f.endpoint.exchange(f.request("close"))).rejects.toMatchObject(failure);
    await expect(f.endpoint.exchange(f.request("start", "replacement"))).rejects.toMatchObject(failure);
    expect(f.create).toHaveBeenCalledTimes(1);
  });

  it("retires and cleans peer executions after one cleanup fails while permitting owned controls", async () => {
    const f = await fixture();
    await f.endpoint.exchange(f.request("start"));
    const second = f.request("start", "execution_b");
    if (second.operation !== "start") throw new Error("test fixture");
    Object.assign(second, { turnId: "turn_b", checkpoint: { ...f.checkpoint, turnId: "turn_b" } });
    await f.endpoint.exchange(second);
    const late = Promise.withResolvers<IteratorResult<AgentEvent>>();
    f.next.mockReturnValueOnce(late.promise);
    const pulling = f.endpoint.exchange({ ...f.request("pull", "execution_b", 1), turnId: "turn_b" });
    await Promise.resolve();
    f.close.mockRejectedValueOnce(new Error("private teardown error"));
    await expect(f.endpoint.exchange(f.request("close"))).rejects.toMatchObject(failure);
    await expect(pulling).resolves.toMatchObject({ status: "done" });
    await expect(f.endpoint.exchange({ ...f.request("abort", "execution_b"), turnId: "turn_b" }))
      .resolves.toMatchObject({ status: "aborted" });
    expect(f.close).toHaveBeenCalledTimes(2);
    expect(f.abort).toHaveBeenCalledTimes(2);
    expect(f.abort).toHaveBeenCalledWith("turn_a", "execution_a");
    expect(f.abort).toHaveBeenCalledWith("turn_b", "execution_b");
    late.resolve({ done: false, value: { type: "assistant_delta", delta: "late peer event" } });
    await expect(f.endpoint.exchange(f.request("start", "replacement"))).rejects.toMatchObject(failure);
    await expect(f.endpoint.exchange(f.request("abort", "unknown_identity"))).rejects.toMatchObject(failure);
    expect(f.create).toHaveBeenCalledTimes(2);
  });

  it("escalates an already closing peer when another execution cleanup fails", async () => {
    const f = await fixture();
    await f.endpoint.exchange(f.request("start"));
    const second = f.request("start", "execution_b");
    if (second.operation !== "start") throw new Error("test fixture");
    Object.assign(second, { turnId: "turn_b", checkpoint: { ...f.checkpoint, turnId: "turn_b" } });
    await f.endpoint.exchange(second);
    const pending = Promise.withResolvers<{ done: true; value: undefined }>();
    f.close.mockReturnValueOnce(pending.promise).mockRejectedValueOnce(new Error("private teardown error"));
    f.abort.mockImplementation(async (_turnId, executionId) => {
      if (executionId === "execution_b") pending.resolve({ done: true, value: undefined });
    });
    const closingPeer = f.endpoint.exchange({ ...f.request("close", "execution_b"), turnId: "turn_b" });
    await Promise.resolve();
    await expect(f.endpoint.exchange(f.request("close"))).rejects.toMatchObject(failure);
    await expect(closingPeer).resolves.toMatchObject({ status: "closed" });
    expect(f.abort).toHaveBeenCalledWith("turn_b", "execution_b");
    expect(f.close).toHaveBeenCalledTimes(2);
    await expect(f.endpoint.exchange(f.request("start", "replacement"))).rejects.toMatchObject(failure);
  });

  it("rejects constructor accessors and invalid resource bounds with fixed diagnostics", () => {
    const getter = vi.fn(() => binding());
    expect(() => new PiExecutionEndpoint({ get binding() { return getter(); }, createEngine: () => { throw new Error("unused"); } }))
      .toThrow(failure.message);
    expect(getter).not.toHaveBeenCalled();
    for (const config of [{ maximumExecutions: 0 }, { maximumExecutions: 65 },
      { maximumLifetimeExecutions: 0 }, { maximumLifetimeExecutions: 4097 }]) {
      expect(() => new PiExecutionEndpoint({ binding: binding(), createEngine: () => { throw new Error("unused"); }, ...config }))
        .toThrow(failure.message);
    }
  });
});
