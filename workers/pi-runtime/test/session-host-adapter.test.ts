import { describe, expect, it, vi } from "vitest";
import { digestStructuredValue } from "@circulusd/protocol-types";

import {
  SessionHost,
  type BrokerBindings,
  type DurableAgentEvent,
  type EphemeralAgentEvent,
} from "../../session-host/src/index.ts";
import {
  LowLevelPiAgentEngine,
  LowLevelPiSessionHostAdapter,
  createOpaqueTurnAuthority,
  type AgentCoreFactory,
  type EngineStepContext,
} from "../src/index.ts";
import { genesis, identity, successSettlement } from "./helpers.ts";

const authorityBytes = () => new Uint8Array([31, 41, 59]);

function makeHost(): SessionHost {
  const scoped = (service: string) => ({ scope: "adapter-test", service });
  const bindings: BrokerBindings = {
    STATE: scoped("state"),
    WORKSPACE: scoped("workspace"),
    MODEL: scoped("model"),
    MCP: scoped("mcp"),
    EXECUTOR: scoped("executor"),
    ARTIFACTS: scoped("artifacts"),
    EVENTS: scoped("events"),
  };
  return new SessionHost({
    bindings,
    loader: { get: async () => ({}) },
    verifier: { verify: async () => ({ revisionDigest: `sha256:${"0".repeat(64)}` }) },
  });
}

describe("LowLevelPiAgentEngine SessionHost adapter", () => {
  it("rendezvous-backpressures assistant deltas and commits the checkpointed effect atomically", async () => {
    const factory: AgentCoreFactory = () => ({
      async advance(context) {
        expect(context.input.kind).toBe("turn_start");
        return {
          kind: "model_request",
          state: { phase: "waiting-model" },
          assistantDeltas: ["first", "second"],
          request: {
            service: "model",
            operation: "complete",
            replayPolicy: "idempotency-key",
            payload: { prompt: "hello" },
          },
        };
      },
    });
    const engine = new LowLevelPiAgentEngine(identity("session_adapter_deltas"), factory);
    const adapter = new LowLevelPiSessionHostAdapter(engine);
    const checkpoint = await genesis(engine);
    const ephemeral: EphemeralAgentEvent[] = [];
    const ephemeralGates: Array<ReturnType<typeof Promise.withResolvers<void>>> = [];
    const committed: DurableAgentEvent[] = [];
    const commitGates: Array<ReturnType<typeof Promise.withResolvers<void>>> = [];

    const driving = makeHost().startTurn(adapter, {
      turnId: checkpoint.turnId,
      authority: authorityBytes(),
      checkpoint,
      ephemeralSink: {
        emit: async (event) => {
          ephemeral.push(structuredClone(event));
          const gate = Promise.withResolvers<void>();
          ephemeralGates.push(gate);
          await gate.promise;
        },
      },
      committer: {
        commit: async (event) => {
          committed.push(structuredClone(event));
          const gate = Promise.withResolvers<void>();
          commitGates.push(gate);
          await gate.promise;
        },
      },
      maximumEvents: 8,
    });

    await vi.waitFor(() => expect(ephemeral).toHaveLength(1));
    await Promise.resolve();
    expect(ephemeral).toEqual([{ type: "assistant_delta", delta: "first" }]);
    expect(committed).toHaveLength(0);

    ephemeralGates[0]?.resolve();
    await vi.waitFor(() => expect(ephemeral).toHaveLength(2));
    expect(ephemeral).toEqual([
      { type: "assistant_delta", delta: "first" },
      { type: "assistant_delta", delta: "second" },
    ]);
    expect(committed).toHaveLength(0);

    ephemeralGates[1]?.resolve();
    await vi.waitFor(() => expect(committed).toHaveLength(1));
    expect(committed[0]).toMatchObject({
      type: "model_request",
      checkpoint: { checkpointSequence: 1 },
      request: { service: "model", operation: "complete" },
    });
    expect(Reflect.ownKeys(committed[0] ?? {}).sort()).toEqual([
      "checkpoint",
      "request",
      "type",
    ]);

    commitGates[0]?.resolve();
    await expect(driving).resolves.toMatchObject({
      boundary: { type: "model_request", checkpoint: { checkpointSequence: 1 } },
      eventsObserved: 3,
    });
  });

  it("does not execute past a checkpoint-only boundary before its commit is acknowledged", async () => {
    let advances = 0;
    const factory: AgentCoreFactory = () => ({
      async advance(context) {
        advances += 1;
        if (context.input.kind === "turn_start") {
          return { kind: "checkpoint_only", state: { phase: "continued" } };
        }
        expect(context.input.kind).toBe("continue");
        return {
          kind: "tool_requests",
          state: { phase: "waiting-tool" },
          requests: [
            {
              service: "external-tool",
              operation: "lookup",
              replayPolicy: "safe",
              payload: {},
            },
          ],
        };
      },
    });
    const engine = new LowLevelPiAgentEngine(identity("session_adapter_checkpoint"), factory);
    const adapter = new LowLevelPiSessionHostAdapter(engine);
    const checkpoint = await genesis(engine);
    const committed: DurableAgentEvent[] = [];
    const gates: Array<ReturnType<typeof Promise.withResolvers<void>>> = [];

    const driving = makeHost().startTurn(adapter, {
      turnId: checkpoint.turnId,
      authority: authorityBytes(),
      checkpoint,
      ephemeralSink: { emit: async () => undefined },
      committer: {
        commit: async (event) => {
          committed.push(structuredClone(event));
          const gate = Promise.withResolvers<void>();
          gates.push(gate);
          await gate.promise;
        },
      },
      maximumEvents: 4,
    });

    await vi.waitFor(() => expect(committed).toHaveLength(1));
    expect(committed[0]).toMatchObject({
      type: "checkpoint",
      checkpoint: { checkpointSequence: 1 },
    });
    expect(advances).toBe(1);

    gates[0]?.resolve();
    await vi.waitFor(() => expect(committed).toHaveLength(2));
    expect(advances).toBe(2);
    expect(committed[1]).toMatchObject({
      type: "tool_request",
      checkpoint: { checkpointSequence: 2 },
      request: { operation: "lookup" },
    });
    gates[1]?.resolve();
    await expect(driving).resolves.toMatchObject({ boundary: { type: "tool_request" } });
  });

  it("resumes with the exact settlement and rejects a mismatched settlement before core execution", async () => {
    let advances = 0;
    const factory: AgentCoreFactory = () => ({
      async advance(context) {
        advances += 1;
        if (context.input.kind === "turn_start") {
          return {
            kind: "model_request",
            state: { phase: "waiting-model" },
            request: {
              service: "model",
              operation: "complete",
              replayPolicy: "safe",
              payload: {},
            },
          };
        }
        expect(context.input.kind).toBe("effect_settlement");
        return { kind: "turn_complete", state: { phase: "done" }, result: { ok: true } };
      },
    });
    const engine = new LowLevelPiAgentEngine(identity("session_adapter_resume"), factory);
    const checkpoint = await genesis(engine);
    const requested = await engine.step({
      authority: createOpaqueTurnAuthority(authorityBytes()),
      checkpoint,
    });
    if (requested.kind !== "effect_request") throw new Error("expected model request");
    const adapter = new LowLevelPiSessionHostAdapter(engine);
    const committed: DurableAgentEvent[] = [];

    await expect(
      makeHost().resumeTurn(adapter, {
        turnId: checkpoint.turnId,
        authority: authorityBytes(),
        checkpoint: requested.checkpoint,
        settlement: successSettlement(requested.request.requestDigest, { answer: 42 }),
        committer: { commit: async (event) => void committed.push(structuredClone(event)) },
        ephemeralSink: { emit: async () => undefined },
        maximumEvents: 2,
      }),
    ).resolves.toMatchObject({ boundary: { type: "turn_complete" } });
    expect(committed[0]).toMatchObject({
      type: "turn_complete",
      checkpoint: { checkpointSequence: 2 },
      result: { ok: true },
    });

    await expect(
      makeHost().resumeTurn(adapter, {
        turnId: checkpoint.turnId,
        authority: authorityBytes(),
        checkpoint: requested.checkpoint,
        settlement: successSettlement(`sha256:${"f".repeat(64)}`, { forged: true }),
        committer: { commit: async () => undefined },
        ephemeralSink: { emit: async () => undefined },
        maximumEvents: 2,
      }),
    ).rejects.toMatchObject({ code: "INVALID_AGENT_EVENT" });
    expect(advances).toBe(2);
  });

  it("recovers from a committed boundary whose old iterator was never closed", async () => {
    let advances = 0;
    const factory: AgentCoreFactory = () => ({
      async advance(context) {
        advances += 1;
        if (context.input.kind === "turn_start") {
          return {
            kind: "model_request",
            state: { phase: "waiting-model" },
            request: {
              service: "model",
              operation: "complete",
              replayPolicy: "safe",
              payload: {},
            },
          };
        }
        expect(context.input.kind).toBe("effect_settlement");
        return { kind: "turn_complete", state: { phase: "done" }, result: { recovered: true } };
      },
    });
    const engine = new LowLevelPiAgentEngine(identity("session_adapter_crash_recovery"), factory);
    const checkpoint = await genesis(engine);
    const staleIterator = new LowLevelPiSessionHostAdapter(engine)
      .startTurn({
        turnId: checkpoint.turnId,
        executionId: "exec_before_host_crash",
        authority: authorityBytes(),
        checkpoint,
      })
      [Symbol.asyncIterator]();
    const boundary = await staleIterator.next();
    if (boundary.done || boundary.value.type !== "model_request") {
      throw new Error("expected a durable model boundary");
    }
    const request = boundary.value.request as { readonly requestDigest: `sha256:${string}` };

    try {
      await expect(
        makeHost().resumeTurn(new LowLevelPiSessionHostAdapter(engine), {
          turnId: checkpoint.turnId,
          authority: authorityBytes(),
          checkpoint: boundary.value.checkpoint,
          settlement: successSettlement(request.requestDigest, { answer: 42 }),
          committer: { commit: async () => undefined },
          ephemeralSink: { emit: async () => undefined },
          maximumEvents: 2,
        }),
      ).resolves.toMatchObject({
        boundary: { type: "turn_complete", result: { recovered: true } },
      });
      expect(advances).toBe(2);
    } finally {
      await staleIterator.return?.();
    }
  });

  it("interrupts active work but fences a stale abort after a returned boundary", async () => {
    const factory: AgentCoreFactory = () => ({
      async advance() {
        return {
          kind: "model_request",
          state: { phase: "waiting" },
          assistantDeltas: ["partial"],
          request: {
            service: "model",
            operation: "complete",
            replayPolicy: "safe",
            payload: {},
          },
        };
      },
    });
    const engine = new LowLevelPiAgentEngine(identity("session_adapter_abort"), factory);
    const abort = vi.spyOn(engine, "abortTurn");
    const adapter = new LowLevelPiSessionHostAdapter(engine);
    const checkpoint = await genesis(engine);

    const iterable = adapter.startTurn({
      turnId: checkpoint.turnId,
      executionId: "exec_direct_abort",
      authority: authorityBytes(),
      checkpoint,
    });
    const iterator = iterable[Symbol.asyncIterator]();
    await expect(iterator.next()).resolves.toEqual({
      done: false,
      value: { type: "assistant_delta", delta: "partial" },
    });
    await iterator.return?.();
    expect(abort).toHaveBeenCalledWith(checkpoint.turnId);

    const retryEngine = new LowLevelPiAgentEngine(identity("session_adapter_commit_abort"), factory);
    const retryAbort = vi.spyOn(retryEngine, "abortTurn");
    const retryAdapter = new LowLevelPiSessionHostAdapter(retryEngine);
    const retryAdapterAbort = vi.spyOn(retryAdapter, "abortTurn");
    const retryCheckpoint = await genesis(retryEngine);
    await expect(
      makeHost().startTurn(retryAdapter, {
        turnId: retryCheckpoint.turnId,
        authority: authorityBytes(),
        checkpoint: retryCheckpoint,
        committer: { commit: async () => Promise.reject(new Error("commit failed")) },
        ephemeralSink: { emit: async () => undefined },
        maximumEvents: 3,
      }),
    ).rejects.toMatchObject({ code: "DURABLE_COMMIT_FAILED" });
    expect(retryAdapterAbort).toHaveBeenCalledWith(
      retryCheckpoint.turnId,
      expect.stringMatching(/^exec_[0-9a-f]{32}$/),
    );
    expect(retryAbort).not.toHaveBeenCalled();
  });

  it("settles the pending pull when cloning an emitted event fails", async () => {
    const checkpointSource = new LowLevelPiAgentEngine(
      identity("session_adapter_clone_failure"),
      () => ({
        async advance() {
          return { kind: "turn_complete", state: {}, result: null };
        },
      }),
    );
    const checkpoint = await genesis(checkpointSource);

    for (const kind of ["delta", "terminal"] as const) {
      const aborts: string[] = [];
      const invalidEngine = {
        step: async (context: {
          emitDelta: (delta: unknown) => Promise<void>;
        }) => {
          if (kind === "delta") {
            await context.emitDelta(() => undefined);
            throw new Error("unreachable after invalid delta");
          }
          return {
            kind: "turn_complete",
            checkpoint,
            result: () => undefined,
          };
        },
        abortTurn: async (turnId: string) => {
          aborts.push(turnId);
        },
      } as unknown as ConstructorParameters<typeof LowLevelPiSessionHostAdapter>[0];
      const iterator = new LowLevelPiSessionHostAdapter(invalidEngine)
        .startTurn({
          turnId: checkpoint.turnId,
          executionId: `exec_clone_failure_${kind}`,
          authority: authorityBytes(),
          checkpoint,
        })
        [Symbol.asyncIterator]();

      const outcome = await Promise.race([
        iterator.next().then(
          () => "resolved",
          () => "rejected",
        ),
        new Promise<"timed-out">((resolve) => {
          setTimeout(() => resolve("timed-out"), 25);
        }),
      ]);
      expect(outcome, `${kind} clone failure left next() pending`).toBe("rejected");
      expect(aborts).toEqual([]);
    }
  });

  it("rejects an unknown bounded-engine result without executing another step", async () => {
    const checkpointSource = new LowLevelPiAgentEngine(
      identity("session_adapter_unknown_step"),
      () => ({
        async advance() {
          return { kind: "turn_complete", state: {}, result: null };
        },
      }),
    );
    const checkpoint = await genesis(checkpointSource);
    let steps = 0;
    const aborts: string[] = [];
    const invalidEngine = {
      step: async () => {
        steps += 1;
        if (steps > 100) throw new Error("sentinel after repeated invalid steps");
        return { kind: "unknown", checkpoint };
      },
      abortTurn: async (turnId: string) => {
        aborts.push(turnId);
      },
    } as unknown as ConstructorParameters<typeof LowLevelPiSessionHostAdapter>[0];
    const iterator = new LowLevelPiSessionHostAdapter(invalidEngine)
      .startTurn({
        turnId: checkpoint.turnId,
        executionId: "exec_unknown_step",
        authority: authorityBytes(),
        checkpoint,
      })
      [Symbol.asyncIterator]();

    await expect(iterator.next()).rejects.toThrow();
    expect(steps).toBe(1);
    expect(aborts).toEqual([]);
  });

  it("rejects a returned checkpoint that is not the exact successor", async () => {
    const checkpointSource = new LowLevelPiAgentEngine(
      identity("session_adapter_forged_successor"),
      () => ({
        async advance() {
          return { kind: "turn_complete", state: {}, result: null };
        },
      }),
    );
    const checkpoint = await genesis(checkpointSource);
    const aborts: string[] = [];
    const invalidEngine = {
      step: async () => ({
        kind: "checkpoint",
        checkpoint: { ...checkpoint, turnId: "turn_other" },
      }),
      abortTurn: async (turnId: string) => {
        aborts.push(turnId);
      },
    } as unknown as ConstructorParameters<typeof LowLevelPiSessionHostAdapter>[0];
    const iterator = new LowLevelPiSessionHostAdapter(invalidEngine)
      .startTurn({
        turnId: checkpoint.turnId,
        executionId: "exec_forged_successor",
        authority: authorityBytes(),
        checkpoint,
      })
      [Symbol.asyncIterator]();

    await expect(iterator.next()).rejects.toThrow();
    expect(aborts).toEqual([]);
  });

  it("binds successor validation to an immutable predecessor snapshot", async () => {
    const source = new LowLevelPiAgentEngine(
      identity("session_adapter_mutated_predecessor"),
      () => ({
        async advance() {
          return { kind: "checkpoint_only", state: { phase: "next" } };
        },
      }),
    );
    const checkpoint = await genesis(source);
    const genuine = await source.step({
      authority: createOpaqueTurnAuthority(authorityBytes()),
      checkpoint,
    });
    if (genuine.kind !== "checkpoint") throw new Error("expected checkpoint boundary");
    const aborts: string[] = [];
    const invalidEngine = {
      step: async (context: EngineStepContext) => {
        const mutable = context.checkpoint as { turnId: string };
        mutable.turnId = "turn_other";
        return {
          kind: "checkpoint" as const,
          checkpoint: {
            ...genuine.checkpoint,
            turnId: "turn_other",
            predecessorDigest: await digestStructuredValue(
              "circulusd.session.agent-checkpoint",
              1,
              context.checkpoint,
            ),
          },
        };
      },
      abortTurn: async (turnId: string) => {
        aborts.push(turnId);
      },
    } as unknown as ConstructorParameters<typeof LowLevelPiSessionHostAdapter>[0];
    const iterator = new LowLevelPiSessionHostAdapter(invalidEngine)
      .startTurn({
        turnId: checkpoint.turnId,
        executionId: "exec_mutated_predecessor",
        authority: authorityBytes(),
        checkpoint,
      })
      [Symbol.asyncIterator]();

    await expect(iterator.next()).rejects.toThrow();
    expect(aborts).toEqual([]);
  });

  it("rejects an effect request whose digest does not bind its payload", async () => {
    const source = new LowLevelPiAgentEngine(
      identity("session_adapter_forged_request_digest"),
      () => ({
        async advance() {
          return {
            kind: "model_request",
            state: { phase: "waiting" },
            request: {
              service: "model",
              operation: "complete",
              replayPolicy: "safe",
              payload: { prompt: "bound" },
            },
          };
        },
      }),
    );
    const checkpoint = await genesis(source);
    const genuine = await source.step({
      authority: createOpaqueTurnAuthority(authorityBytes()),
      checkpoint,
    });
    if (genuine.kind !== "effect_request") throw new Error("expected effect request");
    const aborts: string[] = [];
    const invalidEngine = {
      step: async () => ({
        ...genuine,
        request: { ...genuine.request, requestDigest: `sha256:${"f".repeat(64)}` },
      }),
      abortTurn: async (turnId: string) => {
        aborts.push(turnId);
      },
    } as unknown as ConstructorParameters<typeof LowLevelPiSessionHostAdapter>[0];
    const iterator = new LowLevelPiSessionHostAdapter(invalidEngine)
      .startTurn({
        turnId: checkpoint.turnId,
        executionId: "exec_forged_request_digest",
        authority: authorityBytes(),
        checkpoint,
      })
      [Symbol.asyncIterator]();

    await expect(iterator.next()).rejects.toThrow();
    expect(aborts).toEqual([]);
  });

  it("does not let a duplicate drive abort the admitted core step", async () => {
    const started = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    const factory: AgentCoreFactory = () => ({
      async advance() {
        started.resolve();
        await release.promise;
        return {
          kind: "model_request",
          state: { phase: "waiting" },
          request: {
            service: "model",
            operation: "complete",
            replayPolicy: "safe",
            payload: {},
          },
        };
      },
    });
    const engine = new LowLevelPiAgentEngine(identity("session_adapter_duplicate"), factory);
    const abort = vi.spyOn(engine, "abortTurn");
    const adapter = new LowLevelPiSessionHostAdapter(engine);
    const duplicateAdapter = new LowLevelPiSessionHostAdapter(engine);
    const checkpoint = await genesis(engine);
    const firstHost = makeHost();
    const duplicateHost = makeHost();
    const options = {
      turnId: checkpoint.turnId,
      authority: authorityBytes(),
      checkpoint,
      committer: { commit: async () => undefined },
      ephemeralSink: { emit: async () => undefined },
      maximumEvents: 1,
    } as const;

    const first = firstHost.startTurn(adapter, options);
    await started.promise;
    await expect(duplicateHost.startTurn(duplicateAdapter, options)).rejects.toMatchObject({
      code: "INVALID_AGENT_EVENT",
    });
    expect(abort).not.toHaveBeenCalled();

    release.resolve();
    await expect(first).resolves.toMatchObject({ boundary: { type: "model_request" } });
    expect(abort).not.toHaveBeenCalled();
  });

  it("holds execution ownership until an in-flight abort finishes", async () => {
    const source = new LowLevelPiAgentEngine(
      identity("session_adapter_abort_fence_source"),
      () => ({
        async advance() {
          return { kind: "checkpoint_only", state: { phase: "next" } };
        },
      }),
    );
    const checkpoint = await genesis(source);
    const genuine = await source.step({
      authority: createOpaqueTurnAuthority(authorityBytes()),
      checkpoint,
    });
    const firstStepStarted = Promise.withResolvers<void>();
    const firstStepRelease = Promise.withResolvers<void>();
    const abortStarted = Promise.withResolvers<void>();
    const abortRelease = Promise.withResolvers<void>();
    let stepCalls = 0;
    const engine = {
      step: async () => {
        stepCalls += 1;
        if (stepCalls === 1) {
          firstStepStarted.resolve();
          await firstStepRelease.promise;
        }
        return genuine;
      },
      abortTurn: async () => {
        abortStarted.resolve();
        await abortRelease.promise;
      },
    } as ConstructorParameters<typeof LowLevelPiSessionHostAdapter>[0];
    const first = new LowLevelPiSessionHostAdapter(engine)
      .startTurn({
        turnId: checkpoint.turnId,
        executionId: "exec_abort_fence_first",
        authority: authorityBytes(),
        checkpoint,
      })
      [Symbol.asyncIterator]();
    const firstPull = first.next();
    await firstStepStarted.promise;
    const closing = first.return?.();
    await abortStarted.promise;
    firstStepRelease.resolve();
    await expect(firstPull).resolves.toEqual({ done: true, value: undefined });

    const competing = new LowLevelPiSessionHostAdapter(engine)
      .startTurn({
        turnId: checkpoint.turnId,
        executionId: "exec_abort_fence_competing",
        authority: authorityBytes(),
        checkpoint,
      })
      [Symbol.asyncIterator]();
    try {
      await expect(competing.next()).rejects.toMatchObject({ code: "STEP_IN_PROGRESS" });
      expect(stepCalls).toBe(1);
    } finally {
      abortRelease.resolve();
      await closing;
      await competing.return?.();
    }

    const recovered = new LowLevelPiSessionHostAdapter(engine)
      .startTurn({
        turnId: checkpoint.turnId,
        executionId: "exec_abort_fence_recovered",
        authority: authorityBytes(),
        checkpoint,
      })
      [Symbol.asyncIterator]();
    await expect(recovered.next()).resolves.toMatchObject({
      done: false,
      value: { type: "checkpoint" },
    });
    await recovered.return?.();
    expect(stepCalls).toBe(2);
  });

  it("holds execution ownership until an aborted step itself finishes", async () => {
    const source = new LowLevelPiAgentEngine(
      identity("session_adapter_step_fence_source"),
      () => ({
        async advance() {
          return { kind: "checkpoint_only", state: { phase: "next" } };
        },
      }),
    );
    const checkpoint = await genesis(source);
    const genuine = await source.step({
      authority: createOpaqueTurnAuthority(authorityBytes()),
      checkpoint,
    });
    const firstStepStarted = Promise.withResolvers<void>();
    const firstStepRelease = Promise.withResolvers<void>();
    let stepCalls = 0;
    let aborts = 0;
    const engine = {
      step: async () => {
        stepCalls += 1;
        if (stepCalls === 1) {
          firstStepStarted.resolve();
          await firstStepRelease.promise;
        }
        return genuine;
      },
      abortTurn: async () => {
        aborts += 1;
      },
    } as ConstructorParameters<typeof LowLevelPiSessionHostAdapter>[0];
    const first = new LowLevelPiSessionHostAdapter(engine)
      .startTurn({
        turnId: checkpoint.turnId,
        executionId: "exec_step_fence_first",
        authority: authorityBytes(),
        checkpoint,
      })
      [Symbol.asyncIterator]();
    const firstPull = first.next();
    await firstStepStarted.promise;
    const closing = first.return?.();
    expect(aborts).toBe(1);
    await closing;

    const competing = new LowLevelPiSessionHostAdapter(engine)
      .startTurn({
        turnId: checkpoint.turnId,
        executionId: "exec_step_fence_competing",
        authority: authorityBytes(),
        checkpoint,
      })
      [Symbol.asyncIterator]();
    try {
      await expect(competing.next()).rejects.toMatchObject({ code: "STEP_IN_PROGRESS" });
      expect(stepCalls).toBe(1);
    } finally {
      firstStepRelease.resolve();
      await firstPull;
      await competing.return?.();
    }

    const recovered = new LowLevelPiSessionHostAdapter(engine)
      .startTurn({
        turnId: checkpoint.turnId,
        executionId: "exec_step_fence_recovered",
        authority: authorityBytes(),
        checkpoint,
      })
      [Symbol.asyncIterator]();
    await expect(recovered.next()).resolves.toMatchObject({
      done: false,
      value: { type: "checkpoint" },
    });
    await recovered.return?.();
    expect(stepCalls).toBe(2);
  });
});
