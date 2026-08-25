import { describe, expect, it, vi } from "vitest";

import {
  LowLevelPiAgentEngine,
  createOpaqueTurnAuthority,
  getPiWorkerdConformanceStatus,
  type AgentCore,
  type EngineClock,
} from "../src/index.ts";
import { genesis, identity, scriptedCore } from "./helpers.ts";

const authority = () => createOpaqueTurnAuthority(new Uint8Array([11]));

class ManualClock implements EngineClock {
  #now = 0;
  #nextHandle = 1;
  readonly #timers = new Map<number, () => void>();

  now(): number {
    return this.#now;
  }

  setTimeout(callback: () => void): number {
    const handle = this.#nextHandle;
    this.#nextHandle += 1;
    this.#timers.set(handle, callback);
    return handle;
  }

  clearTimeout(handle: unknown): void {
    if (typeof handle === "number") this.#timers.delete(handle);
  }

  expire(): void {
    this.#now += 1_000;
    for (const callback of this.#timers.values()) callback();
    this.#timers.clear();
  }
}

describe("bounded output, event, and wallclock enforcement", () => {
  it("does not apply the smaller extension-patch budget to an unpatched core request", async () => {
    const core = scriptedCore(() => ({
      kind: "model_request",
      state: null,
      request: {
        service: "model",
        operation: "complete",
        replayPolicy: "safe",
        payload: { text: "x".repeat(512) },
      },
    }));
    const engine = new LowLevelPiAgentEngine(identity("session_distinct_budgets"), core.factory, {
      budgets: { maxCoreOutputBytes: 4_096, maxExtensionOutputBytes: 128 },
    });
    const result = await engine.step({ authority: authority(), checkpoint: await genesis(engine) });
    expect(result).toMatchObject({
      kind: "effect_request",
      request: { payload: { text: "x".repeat(512) } },
    });
  });

  it("fails closed when extension initialization exceeds the wallclock budget", async () => {
    const clock = new ManualClock();
    const entered = Promise.withResolvers<void>();
    const never = Promise.withResolvers<void>();
    const core = scriptedCore(() => ({ kind: "checkpoint_only", state: null }));
    const engine = new LowLevelPiAgentEngine(identity("session_init_timeout"), core.factory, {
      budgets: { maxWallClockMs: 10 },
      clock,
    });
    engine.registerExtension({
      manifest: { id: "slow", priority: 1, tools: [], patchableFields: {} },
      create: () => ({
        async initialize() {
          entered.resolve();
          await never.promise;
        },
      }),
    });
    let outcome: "pending" | "rejected" = "pending";
    const initialization = engine.initialize().catch((error: unknown) => {
      expect(error).toMatchObject({ code: "INITIALIZATION_FAILED" });
      outcome = "rejected";
    });
    await entered.promise;
    clock.expire();
    await initialization;
    expect(outcome).toBe("rejected");
  });

  it("does not lose an abort while a lazy extension initialization is pending", async () => {
    const clock = new ManualClock();
    const entered = Promise.withResolvers<void>();
    const never = Promise.withResolvers<void>();
    const core: AgentCore = {
      advance: vi.fn(async () => ({ kind: "checkpoint_only", state: null })),
      abortTurn: vi.fn(async () => undefined),
    };
    const engine = new LowLevelPiAgentEngine(identity("session_abort_initializing"), () => core, {
      budgets: { maxWallClockMs: 10 },
      clock,
    });
    engine.registerExtension({
      manifest: { id: "slow", priority: 1, tools: [], patchableFields: {} },
      create: () => ({
        async initialize() {
          entered.resolve();
          await never.promise;
        },
      }),
    });
    let outcome = "pending";
    const pending = engine.step({ authority: authority(), checkpoint: await genesis(engine) }).then(
      (result) => {
        outcome = result.kind === "turn_error" ? result.error.code : result.kind;
      },
      (error: { readonly code?: unknown }) => {
        outcome = `rejected:${String(error.code)}`;
      },
    );
    await entered.promise;
    await engine.abortTurn("turn_01");
    const settledBeforeDeadline = await Promise.race([
      pending.then(() => true),
      new Promise<boolean>((resolve) => globalThis.setTimeout(() => resolve(false), 100)),
    ]);
    clock.expire();
    await pending;

    expect(settledBeforeDeadline).toBe(true);
    expect(outcome).toBe("TURN_ABORTED");
    expect(core.advance).not.toHaveBeenCalled();
    expect(core.abortTurn).toHaveBeenCalledWith("turn_01");
  });

  it("does not lose an abort while an untrusted checkpoint is being validated", async () => {
    const core: AgentCore = {
      advance: vi.fn(async () => ({ kind: "checkpoint_only", state: null })),
      abortTurn: vi.fn(async () => undefined),
    };
    const engine = new LowLevelPiAgentEngine(
      identity("session_abort_checkpoint_validation"),
      () => core,
    );
    const checkpoint = await genesis(engine);

    const pending = engine.step({ authority: authority(), checkpoint });
    await engine.abortTurn(checkpoint.turnId);
    const result = await pending;

    expect(result).toMatchObject({ kind: "turn_error", error: { code: "TURN_ABORTED" } });
    expect(core.advance).not.toHaveBeenCalled();
    expect(core.abortTurn).toHaveBeenCalledWith(checkpoint.turnId);
  });

  it("does not lose an abort while the successor checkpoint is being hashed", async () => {
    const enteredSuccessorHash = Promise.withResolvers<void>();
    const releaseSuccessorHash = Promise.withResolvers<void>();
    const core = scriptedCore(() => ({ kind: "checkpoint_only", state: { advanced: true } }));
    const engine = new LowLevelPiAgentEngine(identity("session_abort_successor_hash"), core.factory);
    const checkpoint = await genesis(engine);
    const originalDigest = globalThis.crypto.subtle.digest.bind(globalThis.crypto.subtle);
    let digestCalls = 0;
    const digestSpy = vi.spyOn(globalThis.crypto.subtle, "digest").mockImplementation(
      async (algorithm, data) => {
        digestCalls += 1;
        if (digestCalls === 2) {
          enteredSuccessorHash.resolve();
          await releaseSuccessorHash.promise;
        }
        return originalDigest(algorithm, data);
      },
    );

    try {
      const pending = engine.step({ authority: authority(), checkpoint });
      await enteredSuccessorHash.promise;
      await engine.abortTurn(checkpoint.turnId);
      releaseSuccessorHash.resolve();

      await expect(pending).resolves.toMatchObject({
        kind: "turn_error",
        error: { code: "TURN_ABORTED" },
      });
    } finally {
      digestSpy.mockRestore();
      releaseSuccessorHash.resolve();
    }
  });

  it.each([
    {
      name: "unknown core field",
      transition: { kind: "checkpoint_only", state: null, hidden: true },
      code: "CORE_OUTPUT_INVALID",
    },
    {
      name: "oversized core output",
      transition: { kind: "checkpoint_only", state: { text: "x".repeat(2_000) } },
      code: "CORE_OUTPUT_INVALID",
    },
    {
      name: "too many assistant events",
      transition: {
        kind: "checkpoint_only",
        state: null,
        assistantDeltas: [{ n: 1 }, { n: 2 }, { n: 3 }],
      },
      code: "EVENT_BUDGET_EXCEEDED",
    },
  ])("turns hostile $name into one durable turn_error", async ({ transition, code }) => {
    const core = scriptedCore(() => transition as never);
    const engine = new LowLevelPiAgentEngine(identity("session_budget"), core.factory, {
      budgets: { maxCoreOutputBytes: 512, maxEventsPerStep: 2 },
    });
    const result = await engine.step({ authority: authority(), checkpoint: await genesis(engine) });
    expect(result.kind).toBe("turn_error");
    if (result.kind !== "turn_error") throw new Error("expected turn error");
    expect(result.error.code).toBe(code);
    expect(result.checkpoint.checkpointSequence).toBe(1);
  });

  it("rejects exact-shape and size violations from hostile extension output", async () => {
    const core = scriptedCore(() => ({
      kind: "model_request",
      state: null,
      request: {
        service: "model",
        operation: "complete",
        replayPolicy: "safe",
        payload: {},
      },
    }));
    const engine = new LowLevelPiAgentEngine(identity("session_hostile_extension"), core.factory, {
      budgets: { maxExtensionOutputBytes: 128 },
    });
    engine.registerExtension({
      manifest: {
        id: "hostile",
        priority: 1,
        tools: [],
        patchableFields: { beforeModelRequest: ["payload"] },
      },
      create: () => ({
        async beforeModelRequest() {
          return { payload: { text: "x".repeat(1_000) }, authority: "forged" } as never;
        },
      }),
    });
    const result = await engine.step({ authority: authority(), checkpoint: await genesis(engine) });
    expect(result).toMatchObject({
      kind: "turn_error",
      error: { code: "EXTENSION_OUTPUT_INVALID", retryable: false },
    });
  });

  it("enforces a step wallclock deadline and ignores a late core result", async () => {
    const clock = new ManualClock();
    const entered = Promise.withResolvers<void>();
    const late = Promise.withResolvers<never>();
    let calls = 0;
    const core: AgentCore = {
      async advance() {
        calls += 1;
        if (calls > 1) {
          return { kind: "checkpoint_only", state: null };
        }
        entered.resolve();
        return late.promise;
      },
      abortTurn: vi.fn(async () => undefined),
    };
    const engine = new LowLevelPiAgentEngine(identity("session_timeout"), () => core, {
      budgets: { maxWallClockMs: 10 },
      clock,
    });
    const pending = engine.step({ authority: authority(), checkpoint: await genesis(engine) });
    await entered.promise;
    clock.expire();
    const result = await pending;
    expect(result).toMatchObject({ kind: "turn_error", error: { code: "STEP_TIMEOUT" } });
    await expect(
      engine.step({ authority: authority(), checkpoint: result.checkpoint }),
    ).rejects.toMatchObject({ code: "ENGINE_POISONED" });
    await expect(
      engine.step({
        authority: authority(),
        checkpoint: await genesis(engine, "turn_after_timeout"),
      }),
    ).rejects.toMatchObject({ code: "ENGINE_POISONED" });
    expect(calls).toBe(1);
    expect(core.abortTurn).toHaveBeenCalledOnce();
    expect(core.abortTurn).toHaveBeenCalledWith("turn_01");
  });

  it("emits an abort checkpoint and calls the best-effort core interrupt", async () => {
    const entered = Promise.withResolvers<void>();
    const core: AgentCore = {
      async advance({ signal }) {
        entered.resolve();
        await new Promise<void>((_resolve, reject) => {
          signal.addEventListener("abort", () => reject(signal.reason), { once: true });
        });
        return { kind: "checkpoint_only", state: null };
      },
      abortTurn: vi.fn(async () => undefined),
    };
    const engine = new LowLevelPiAgentEngine(identity("session_abort"), () => core);
    const pending = engine.step({ authority: authority(), checkpoint: await genesis(engine) });
    await entered.promise;
    await engine.abortTurn("turn_01");
    const result = await pending;
    expect(result).toMatchObject({ kind: "turn_error", error: { code: "TURN_ABORTED" } });
    expect(core.abortTurn).toHaveBeenCalledWith("turn_01");
  });

  it("reports real Pi/workerd qualification as unavailable instead of promoting unit doubles", () => {
    expect(getPiWorkerdConformanceStatus()).toEqual({
      status: "UNAVAILABLE",
      reason:
        "Pi Agent Core 0.84.3 and stock workerd 1.20260825.1 have not passed the real dynamic-worker, outbound-denial, and isolate-separation gate",
    });
  });
});
