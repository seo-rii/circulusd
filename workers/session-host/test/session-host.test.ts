import { describe, expect, it, vi } from "vitest";

import {
  SessionHost,
  SessionHostError,
  type AgentEngine,
  type AgentEvent,
  type BrokerBindings,
  type DurableEventCommitter,
  type EphemeralEventSink,
  type RuntimeRevision,
  type RuntimeVerifier,
  type WorkerDefinition,
  type WorkerLoader,
} from "../src/index.ts";

const digest = (character: string): string => `sha256:${character.repeat(64)}`;

class FakeLoader implements WorkerLoader {
  readonly definitions = new Map<string, WorkerDefinition>();
  readonly workers = new Map<string, object>();
  calls = 0;

  async get(workerId: string, factory: () => Promise<WorkerDefinition>): Promise<object> {
    this.calls += 1;
    const existing = this.workers.get(workerId);
    if (existing !== undefined) {
      return existing;
    }
    const definition = await factory();
    this.definitions.set(workerId, definition);
    const worker = { workerId };
    this.workers.set(workerId, worker);
    return worker;
  }
}

class FakeVerifier implements RuntimeVerifier {
  calls = 0;
  fail = false;
  started: (() => void) | null = null;
  release: (() => void) | null = null;

  async verify(revision: RuntimeRevision): Promise<{ revisionDigest: string }> {
    this.calls += 1;
    this.started?.();
    if (this.started !== null) {
      await new Promise<void>((resolve) => {
        this.release = resolve;
      });
    }
    if (this.fail) {
      throw new Error("signature rejected");
    }
    return { revisionDigest: revision.runtimeRevisionDigest };
  }
}

const bindings = (scope: string): BrokerBindings => ({
  STATE: { scope, service: "state" },
  WORKSPACE: { scope, service: "workspace" },
  MODEL: { scope, service: "model" },
  MCP: { scope, service: "mcp" },
  EXECUTOR: { scope, service: "executor" },
  ARTIFACTS: { scope, service: "artifacts" },
  EVENTS: { scope, service: "events" },
});

async function sha256(bytes: Uint8Array): Promise<string> {
  const result = await crypto.subtle.digest("SHA-256", bytes);
  return `sha256:${Array.from(new Uint8Array(result), (value) =>
    value.toString(16).padStart(2, "0"),
  ).join("")}`;
}

async function revision(overrides: Partial<RuntimeRevision> = {}): Promise<RuntimeRevision> {
  const main = new TextEncoder().encode("export default { fetch() {} };");
  const extension = new TextEncoder().encode("export const value = 1;");
  return {
    sessionId: "sess_0123456789ABCDEFGHJKMNPQRS",
    runtimeRevisionDigest: digest("a"),
    runtimeIdentityDigest: digest("b"),
    piAdapterAbi: 1,
    compatibilityDate: "2026-08-26",
    compatibilityFlags: ["nodejs_compat", "streams_enable_constructors"],
    mainModule: "runtime/main.mjs",
    modules: [
      { specifier: "extension/one.mjs", bytes: extension, digest: await sha256(extension) },
      { specifier: "runtime/main.mjs", bytes: main, digest: await sha256(main) },
    ],
    limits: { cpuMs: 1_000, subRequests: 0 },
    ...overrides,
  };
}

describe("SessionHost Worker Loader boundary", () => {
  it("rejects incomplete stable binding sets during construction", () => {
    expect(
      () =>
        new SessionHost({
          loader: new FakeLoader(),
          verifier: new FakeVerifier(),
          bindings: { STATE: {} } as BrokerBindings,
        }),
    ).toThrowError(SessionHostError);
  });

  it("verifies and loads a content-addressed worker with only stable scoped bindings", async () => {
    const loader = new FakeLoader();
    const verifier = new FakeVerifier();
    const scopedBindings = bindings("session-a");
    const host = new SessionHost({ loader, verifier, bindings: scopedBindings });
    const runtime = await revision();

    const loaded = await host.load(runtime);
    expect(loaded.workerId).toBe(
      `pi/${runtime.sessionId}/${runtime.runtimeIdentityDigest.replace("sha256:", "sha256-")}`,
    );
    expect(verifier.calls).toBe(1);
    const definition = loader.definitions.get(loaded.workerId);
    expect(definition).toMatchObject({
      compatibilityDate: "2026-08-26",
      compatibilityFlags: ["nodejs_compat", "streams_enable_constructors"],
      mainModule: "runtime/main.mjs",
      limits: { cpuMs: 1_000, subRequests: 0 },
      globalOutbound: null,
    });
    expect(definition?.env).toEqual(scopedBindings);
    expect(Object.keys(definition?.env ?? {}).sort()).toEqual([
      "ARTIFACTS",
      "EVENTS",
      "EXECUTOR",
      "MCP",
      "MODEL",
      "STATE",
      "WORKSPACE",
    ]);
    expect(JSON.stringify(definition?.env)).not.toContain("authority");

    runtime.modules[0]!.bytes[0] ^= 0xff;
    expect(definition?.modules[0]?.bytes[0]).not.toBe(runtime.modules[0]?.bytes[0]);
  });

  it("rejects unverified, corrupt, ambiguous, and unbounded worker definitions", async () => {
    const cases: Array<{
      name: string;
      mutate: (runtime: RuntimeRevision, verifier: FakeVerifier) => void;
      code: string;
    }> = [
      {
        name: "signature",
        mutate: (_runtime, verifier) => {
          verifier.fail = true;
        },
        code: "RUNTIME_UNVERIFIED",
      },
      {
        name: "module digest",
        mutate: (runtime) => {
          runtime.modules[0]!.digest = digest("f");
        },
        code: "MODULE_DIGEST_MISMATCH",
      },
      {
        name: "duplicate module",
        mutate: (runtime) => {
          runtime.modules.push(structuredClone(runtime.modules[0]!));
        },
        code: "INVALID_RUNTIME",
      },
      {
        name: "missing main",
        mutate: (runtime) => {
          runtime.mainModule = "missing.mjs";
        },
        code: "INVALID_RUNTIME",
      },
      {
        name: "unsorted flags",
        mutate: (runtime) => {
          runtime.compatibilityFlags = ["z", "a"];
        },
        code: "INVALID_RUNTIME",
      },
      {
        name: "module size",
        mutate: (runtime) => {
          runtime.modules[0]!.bytes = new Uint8Array(129);
        },
        code: "RUNTIME_TOO_LARGE",
      },
      {
        name: "module count",
        mutate: (runtime) => {
          runtime.modules.push(
            structuredClone(runtime.modules[0]!),
            structuredClone(runtime.modules[0]!),
            structuredClone(runtime.modules[0]!),
          );
        },
        code: "RUNTIME_TOO_LARGE",
      },
    ];
    for (const test of cases) {
      const loader = new FakeLoader();
      const verifier = new FakeVerifier();
      const host = new SessionHost({
        loader,
        verifier,
        bindings: bindings(test.name),
        limits: { maximumModules: 4, maximumModuleBytes: 128, maximumBundleBytes: 256 },
      });
      const runtime = await revision();
      test.mutate(runtime, verifier);
      await expect(host.load(runtime)).rejects.toMatchObject({ code: test.code });
      expect(loader.calls).toBe(0);
    }
  });

  it("keeps two sessions' broker bindings and module bytes isolated", async () => {
    const loader = new FakeLoader();
    const verifier = new FakeVerifier();
    const first = new SessionHost({ loader, verifier, bindings: bindings("first") });
    const second = new SessionHost({ loader, verifier, bindings: bindings("second") });
    const firstRuntime = await revision();
    const secondRuntime = await revision({
      sessionId: "sess_ZYXWVUTSRQPONMLKJHGFEDCBA1",
      runtimeIdentityDigest: digest("c"),
    });
    const [firstWorker, secondWorker] = await Promise.all([
      first.load(firstRuntime),
      second.load(secondRuntime),
    ]);
    expect(firstWorker.workerId).not.toBe(secondWorker.workerId);
    expect(loader.definitions.get(firstWorker.workerId)?.env.STATE).toEqual({
      scope: "first",
      service: "state",
    });
    expect(loader.definitions.get(secondWorker.workerId)?.env.STATE).toEqual({
      scope: "second",
      service: "state",
    });
  });

  it("snapshots the runtime before asynchronous verification to close mutation races", async () => {
    const loader = new FakeLoader();
    const verifier = new FakeVerifier();
    const host = new SessionHost({ loader, verifier, bindings: bindings("snapshot") });
    const runtime = await revision();
    const originalByte = runtime.modules[0]!.bytes[0];
    const replacement = new Uint8Array([0, 1, 2, 3]);
    const replacementDigest = await sha256(replacement);
    const started = new Promise<void>((resolve) => {
      verifier.started = resolve;
    });

    const loading = host.load(runtime);
    await started;
    runtime.modules[0]!.bytes = replacement;
    runtime.modules[0]!.digest = replacementDigest;
    verifier.release?.();
    const loaded = await loading;
    expect(loader.definitions.get(loaded.workerId)?.modules[0]?.bytes[0]).toBe(originalByte);
  });

  it("rejects nested runtime accessors without executing them", async () => {
    let getterCalls = 0;
    const loader = new FakeLoader();
    const verifier = new FakeVerifier();
    const host = new SessionHost({ loader, verifier, bindings: bindings("runtime-accessor") });
    const runtime = await revision();
    Object.defineProperty(runtime.modules[0], "specifier", {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return "extension/one.mjs";
      },
    });

    await expect(host.load(runtime)).rejects.toMatchObject({ code: "INVALID_RUNTIME" });
    expect(getterCalls).toBe(0);
    expect(verifier.calls).toBe(0);
    expect(loader.calls).toBe(0);
  });
});

class SequenceEngine implements AgentEngine {
  readonly events: AgentEvent[];
  pulls = 0;
  returns = 0;
  aborts: string[] = [];
  seenAuthority: Uint8Array | null = null;
  seenCheckpoint: unknown = null;

  constructor(events: AgentEvent[]) {
    this.events = events;
  }

  startTurn(context: {
    turnId: string;
    authority: Uint8Array;
    checkpoint: unknown;
  }): AsyncIterable<AgentEvent> {
    this.seenAuthority = context.authority;
    this.seenCheckpoint = context.checkpoint;
    let index = 0;
    return {
      [Symbol.asyncIterator]: () => ({
        next: async () => {
          this.pulls += 1;
          const event = this.events[index];
          index += 1;
          return event === undefined
            ? { done: true, value: undefined }
            : { done: false, value: event };
        },
        return: async () => {
          this.returns += 1;
          return { done: true, value: undefined };
        },
      }),
    };
  }

  resumeTurn(context: {
    turnId: string;
    authority: Uint8Array;
    checkpoint: unknown;
    settlement: unknown;
  }): AsyncIterable<AgentEvent> {
    return this.startTurn(context);
  }

  async abortTurn(turnId: string): Promise<void> {
    this.aborts.push(turnId);
  }
}

class GatedCommitter implements DurableEventCommitter {
  readonly events: AgentEvent[] = [];
  started: (() => void) | null = null;
  release: (() => void) | null = null;
  fail = false;

  async commit(event: AgentEvent): Promise<void> {
    this.events.push(structuredClone(event));
    this.started?.();
    await new Promise<void>((resolve) => {
      this.release = resolve;
    });
    if (this.fail) {
      throw new Error("durable commit failed");
    }
  }
}

class RecordingSink implements EphemeralEventSink {
  readonly events: AgentEvent[] = [];

  async emit(event: AgentEvent): Promise<void> {
    this.events.push(structuredClone(event));
  }
}

describe("SessionHost durable event driving", () => {
  it("passes the current checkpoint and commits each next durable boundary atomically", async () => {
    const currentCheckpoint = { sequence: 0 };
    const nextCheckpoint = { sequence: 1 };
    const event = {
      type: "tool_request",
      checkpoint: nextCheckpoint,
      request: { invocationId: "inv-atomic" },
    } as AgentEvent;
    const engine = new SequenceEngine([event]);
    const committed: AgentEvent[] = [];
    const host = new SessionHost({
      loader: new FakeLoader(),
      verifier: new FakeVerifier(),
      bindings: bindings("atomic-boundary"),
    });

    const result = await host.startTurn(engine, {
      turnId: "turn-atomic",
      authority: new Uint8Array([1, 2, 3]),
      checkpoint: currentCheckpoint,
      committer: {
        commit: async (durableEvent) => {
          committed.push(structuredClone(durableEvent));
        },
      },
      ephemeralSink: new RecordingSink(),
      maximumEvents: 2,
    });

    expect(engine.seenCheckpoint).toEqual(currentCheckpoint);
    expect(committed).toEqual([event]);
    expect(result.boundary).toEqual(event);
    currentCheckpoint.sequence = 99;
    expect(engine.seenCheckpoint).toEqual({ sequence: 0 });
  });

  it("returns the exact committed snapshot when iterator cleanup mutates its source event", async () => {
    const event: Extract<AgentEvent, { type: "turn_complete" }> = {
      type: "turn_complete",
      checkpoint: { sequence: 1 },
      result: { value: "committed" },
    };
    const events: AsyncIterable<AgentEvent> = {
      [Symbol.asyncIterator]: () => ({
        next: async () => ({ done: false, value: event }),
        return: async () => {
          (event.result as { value: string }).value = "mutated-during-cleanup";
          return { done: true, value: undefined };
        },
      }),
    };
    const engine: AgentEngine = {
      startTurn: () => events,
      resumeTurn: () => events,
      abortTurn: async () => undefined,
    };
    const committed: AgentEvent[] = [];
    const host = new SessionHost({
      loader: new FakeLoader(),
      verifier: new FakeVerifier(),
      bindings: bindings("committed-snapshot"),
    });

    const result = await host.startTurn(engine, {
      turnId: "turn-committed-snapshot",
      authority: new Uint8Array([1]),
      checkpoint: { sequence: 0 },
      committer: {
        commit: async (durableEvent) => {
          committed.push(structuredClone(durableEvent));
        },
      },
      ephemeralSink: new RecordingSink(),
      maximumEvents: 1,
    });

    expect(committed).toEqual([
      {
        type: "turn_complete",
        checkpoint: { sequence: 1 },
        result: { value: "committed" },
      },
    ]);
    expect(result.boundary).toEqual(committed[0]);
    expect(event.result).toEqual({ value: "mutated-during-cleanup" });
  });

  it("retains the committed boundary when the committer mutates its call argument", async () => {
    const event: Extract<AgentEvent, { type: "turn_complete" }> = {
      type: "turn_complete",
      checkpoint: { sequence: 1 },
      result: { value: "committed" },
    };
    const committed: AgentEvent[] = [];
    const host = new SessionHost({
      loader: new FakeLoader(),
      verifier: new FakeVerifier(),
      bindings: bindings("committer-snapshot"),
    });

    const result = await host.startTurn(new SequenceEngine([event]), {
      turnId: "turn-committer-snapshot",
      authority: new Uint8Array([1]),
      checkpoint: { sequence: 0 },
      committer: {
        commit: async (durableEvent) => {
          committed.push(structuredClone(durableEvent));
          if (durableEvent.type === "turn_complete") {
            (durableEvent.result as { value: string }).value = "mutated-by-committer";
          }
        },
      },
      ephemeralSink: new RecordingSink(),
      maximumEvents: 1,
    });

    expect(committed[0]).toMatchObject({ result: { value: "committed" } });
    expect(result.boundary).toEqual(committed[0]);
  });

  it("routes from the committed snapshot when the engine mutates its yielded event", async () => {
    const checkpointEvent = {
      type: "checkpoint",
      checkpoint: { sequence: 1 },
    } as { type: AgentEvent["type"]; checkpoint: unknown };
    const engine = new SequenceEngine([
      checkpointEvent as AgentEvent,
      { type: "turn_complete", checkpoint: { sequence: 2 }, result: { ok: true } },
    ]);
    const committed: AgentEvent[] = [];
    const host = new SessionHost({
      loader: new FakeLoader(),
      verifier: new FakeVerifier(),
      bindings: bindings("source-event-mutation"),
    });

    const result = await host.startTurn(engine, {
      turnId: "turn-source-event-mutation",
      authority: new Uint8Array([1]),
      checkpoint: { sequence: 0 },
      committer: {
        commit: async (event) => {
          committed.push(structuredClone(event));
          if (committed.length === 1) checkpointEvent.type = "turn_complete";
        },
      },
      ephemeralSink: new RecordingSink(),
      maximumEvents: 2,
    });

    expect(committed.map((event) => event.type)).toEqual(["checkpoint", "turn_complete"]);
    expect(result.boundary).toMatchObject({ type: "turn_complete", checkpoint: { sequence: 2 } });
    expect(engine.pulls).toBe(2);
  });

  it("fails closed and aborts when an engine cannot create a valid event stream", async () => {
    for (const startTurn of [
      () => {
        throw new Error("engine initialization failed");
      },
      () => ({}) as AsyncIterable<AgentEvent>,
    ]) {
      const aborts: string[] = [];
      const engine: AgentEngine = {
        startTurn,
        resumeTurn: startTurn,
        abortTurn: async (turnId) => {
          aborts.push(turnId);
        },
      };
      const host = new SessionHost({
        loader: new FakeLoader(),
        verifier: new FakeVerifier(),
        bindings: bindings("invalid-stream"),
      });

      await expect(
        host.startTurn(engine, {
          turnId: "turn-invalid-stream",
          authority: new Uint8Array([1]),
          checkpoint: { sequence: 0 },
          committer: { commit: async () => undefined },
          ephemeralSink: new RecordingSink(),
          maximumEvents: 1,
        }),
      ).rejects.toMatchObject({ code: "INVALID_AGENT_EVENT" });
      expect(aborts).toEqual(["turn-invalid-stream"]);
    }
  });

  it("releases turn admission when binding abortTurn throws", async () => {
    const host = new SessionHost({
      loader: new FakeLoader(),
      verifier: new FakeVerifier(),
      bindings: bindings("abort-binding-failure"),
    });
    const events = new SequenceEngine([
      { type: "turn_complete", checkpoint: { sequence: 1 }, result: {} },
    ]);
    const hostile = {
      startTurn: events.startTurn.bind(events),
      resumeTurn: events.resumeTurn.bind(events),
    } as Partial<AgentEngine>;
    Object.defineProperty(hostile, "abortTurn", {
      get: () => {
        throw new Error("hostile abort accessor");
      },
    });
    const options = {
      turnId: "turn-abort-binding-failure",
      authority: new Uint8Array([1]),
      checkpoint: { sequence: 0 },
      committer: { commit: async () => undefined },
      ephemeralSink: new RecordingSink(),
      maximumEvents: 1,
    };

    await expect(host.startTurn(hostile as AgentEngine, options)).rejects.toThrow(
      "hostile abort accessor",
    );
    await expect(host.startTurn(events, options)).resolves.toMatchObject({
      boundary: { type: "turn_complete" },
    });
  });

  it("validates turn authority before invoking the AgentEngine", async () => {
    const engine = new SequenceEngine([
      { type: "turn_complete", checkpoint: { sequence: 1 }, result: {} },
    ]);
    const host = new SessionHost({
      loader: new FakeLoader(),
      verifier: new FakeVerifier(),
      bindings: bindings("invalid-turn"),
    });
    await expect(
      host.startTurn(engine, {
        turnId: "turn-invalid",
        authority: new Uint8Array(),
        checkpoint: { sequence: 0 },
        committer: { commit: async () => undefined },
        ephemeralSink: new RecordingSink(),
        maximumEvents: 1,
      }),
    ).rejects.toMatchObject({ code: "INVALID_TURN" });
    expect(engine.seenAuthority).toBeNull();
    expect(engine.pulls).toBe(0);
  });

  it("rejects shared, partial, derived, or augmented turn authority byte views", async () => {
    const host = new SessionHost({
      loader: new FakeLoader(),
      verifier: new FakeVerifier(),
      bindings: bindings("authority-storage"),
    });
    const shared = new Uint8Array(new SharedArrayBuffer(2));
    shared.set([1, 2]);
    const partial = new Uint8Array(new ArrayBuffer(8), 2, 2);
    partial.set([1, 2]);
    class DerivedAuthority extends Uint8Array {}
    const derived = new DerivedAuthority([1, 2]);
    const augmented = new Uint8Array([1, 2]) as Uint8Array & { label?: string };
    augmented.label = "mutable metadata";

    for (const [name, authority] of [
      ["shared", shared],
      ["partial", partial],
      ["derived", derived],
      ["augmented", augmented],
    ] as const) {
      const engine = new SequenceEngine([
        { type: "turn_complete", checkpoint: { sequence: 1 }, result: {} },
      ]);
      await expect(
        host.startTurn(engine, {
          turnId: `turn-${name}-authority`,
          authority,
          checkpoint: { sequence: 0 },
          committer: { commit: async () => undefined },
          ephemeralSink: new RecordingSink(),
          maximumEvents: 1,
        }),
      ).rejects.toMatchObject({ code: "INVALID_TURN" });
      expect(engine.pulls).toBe(0);
    }
  });

  it("requires record-shaped current and emitted checkpoints", async () => {
    const host = new SessionHost({
      loader: new FakeLoader(),
      verifier: new FakeVerifier(),
      bindings: bindings("checkpoint-shape"),
    });
    const invalidCurrent = new SequenceEngine([
      { type: "turn_complete", checkpoint: { sequence: 1 }, result: {} },
    ]);
    await expect(
      host.startTurn(invalidCurrent, {
        turnId: "turn-invalid-current-checkpoint",
        authority: new Uint8Array([1]),
        checkpoint: [],
        committer: { commit: async () => undefined },
        ephemeralSink: new RecordingSink(),
        maximumEvents: 1,
      }),
    ).rejects.toMatchObject({ code: "INVALID_TURN" });
    expect(invalidCurrent.pulls).toBe(0);

    let commits = 0;
    const invalidNext = new SequenceEngine([
      { type: "turn_complete", checkpoint: [], result: {} },
    ]);
    await expect(
      host.startTurn(invalidNext, {
        turnId: "turn-invalid-next-checkpoint",
        authority: new Uint8Array([1]),
        checkpoint: { sequence: 0 },
        committer: {
          commit: async () => {
            commits += 1;
          },
        },
        ephemeralSink: new RecordingSink(),
        maximumEvents: 1,
      }),
    ).rejects.toMatchObject({ code: "INVALID_AGENT_EVENT" });
    expect(commits).toBe(0);
    expect(invalidNext.aborts).toEqual(["turn-invalid-next-checkpoint"]);
  });

  it("does not pull the next event until the current durable commit completes", async () => {
    const engine = new SequenceEngine([
      { type: "checkpoint", checkpoint: { sequence: 1 } },
      { type: "assistant_delta", delta: "hello" },
      {
        type: "tool_request",
        checkpoint: { sequence: 2 },
        request: { invocationId: "inv-1" },
      },
    ]);
    const committer = new GatedCommitter();
    const sink = new RecordingSink();
    const host = new SessionHost({
      loader: new FakeLoader(),
      verifier: new FakeVerifier(),
      bindings: bindings("events"),
    });
    const started = new Promise<void>((resolve) => {
      committer.started = resolve;
    });
    const authority = new Uint8Array([1, 2, 3]);
    const driving = host.startTurn(engine, {
      turnId: "turn-1",
      authority,
      checkpoint: { sequence: 0 },
      committer: committer as DurableEventCommitter,
      ephemeralSink: sink,
      maximumEvents: 10,
    });
    await started;
    expect(engine.pulls).toBe(1);
    committer.release?.();

    while (committer.events.length < 2) {
      await Promise.resolve();
    }
    expect(engine.pulls).toBe(3);
    committer.release?.();
    const result = await driving;
    expect(result.boundary).toMatchObject({ type: "tool_request" });
    expect(sink.events).toEqual([{ type: "assistant_delta", delta: "hello" }]);
    expect(engine.returns).toBe(1);
    authority[0] = 99;
    expect(engine.seenAuthority?.[0]).toBe(1);
  });

  it("rejects a duplicate drive without aborting the admitted execution", async () => {
    const engine = new SequenceEngine([
      { type: "turn_complete", checkpoint: { sequence: 1 }, result: { ok: true } },
    ]);
    const firstCommit = new GatedCommitter();
    const host = new SessionHost({
      loader: new FakeLoader(),
      verifier: new FakeVerifier(),
      bindings: bindings("duplicate-drive"),
    });
    const commitStarted = new Promise<void>((resolve) => {
      firstCommit.started = resolve;
    });
    const options = {
      turnId: "turn-duplicate-drive",
      authority: new Uint8Array([1, 2, 3]),
      checkpoint: { sequence: 0 },
      ephemeralSink: new RecordingSink(),
      maximumEvents: 1,
    } as const;

    const first = host.startTurn(engine, { ...options, committer: firstCommit });
    await commitStarted;
    await expect(
      host.startTurn(engine, {
        ...options,
        committer: { commit: async () => undefined },
      }),
    ).rejects.toMatchObject({ code: "INVALID_TURN" });
    expect(engine.pulls).toBe(1);
    expect(engine.aborts).toEqual([]);

    firstCommit.release?.();
    await expect(first).resolves.toMatchObject({ boundary: { type: "turn_complete" } });
    expect(engine.aborts).toEqual([]);
  });

  it("admits the same turn identifier concurrently on independent engines", async () => {
    const firstEngine = new SequenceEngine([
      { type: "turn_complete", checkpoint: { sequence: 1 }, result: { engine: "first" } },
    ]);
    const secondEngine = new SequenceEngine([
      { type: "turn_complete", checkpoint: { sequence: 1 }, result: { engine: "second" } },
    ]);
    const firstCommit = new GatedCommitter();
    const firstCommitStarted = Promise.withResolvers<void>();
    firstCommit.started = () => firstCommitStarted.resolve();
    const host = new SessionHost({
      loader: new FakeLoader(),
      verifier: new FakeVerifier(),
      bindings: bindings("independent-engines"),
    });
    const options = {
      turnId: "turn-shared-local-name",
      authority: new Uint8Array([1]),
      checkpoint: { sequence: 0 },
      ephemeralSink: new RecordingSink(),
      maximumEvents: 1,
    } as const;

    const first = host.startTurn(firstEngine, { ...options, committer: firstCommit });
    await firstCommitStarted.promise;
    await expect(
      host.startTurn(secondEngine, {
        ...options,
        committer: { commit: async () => undefined },
      }),
    ).resolves.toMatchObject({
      boundary: { type: "turn_complete", result: { engine: "second" } },
    });

    firstCommit.release?.();
    await expect(first).resolves.toMatchObject({
      boundary: { type: "turn_complete", result: { engine: "first" } },
    });
  });

  it("snapshots the admitted turn identity before caller mutation", async () => {
    const engine = new SequenceEngine([
      { type: "turn_complete", checkpoint: { sequence: 1 }, result: {} },
    ]);
    const committer = new GatedCommitter();
    const host = new SessionHost({
      loader: new FakeLoader(),
      verifier: new FakeVerifier(),
      bindings: bindings("turn-option-snapshot"),
    });
    const commitStarted = new Promise<void>((resolve) => {
      committer.started = resolve;
    });
    const options = {
      turnId: "turn-option-snapshot",
      authority: new Uint8Array([1]),
      checkpoint: { sequence: 0 },
      committer,
      ephemeralSink: new RecordingSink(),
      maximumEvents: 1,
    };

    const first = host.startTurn(engine, options);
    await commitStarted;
    options.turnId = "turn-mutated-by-caller";
    committer.release?.();
    await expect(first).resolves.toMatchObject({ boundary: { type: "turn_complete" } });

    options.turnId = "turn-option-snapshot";
    options.committer = { commit: async () => undefined };
    await expect(host.startTurn(engine, options)).resolves.toMatchObject({
      boundary: { type: "turn_complete" },
    });
  });

  it("does not let caller mutation raise an admitted event budget", async () => {
    const engine = new SequenceEngine([
      { type: "assistant_delta", delta: "first" },
      { type: "turn_complete", checkpoint: { sequence: 1 }, result: {} },
    ]);
    const emitted = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    const host = new SessionHost({
      loader: new FakeLoader(),
      verifier: new FakeVerifier(),
      bindings: bindings("event-budget-snapshot"),
    });
    const options = {
      turnId: "turn-event-budget-snapshot",
      authority: new Uint8Array([1]),
      checkpoint: { sequence: 0 },
      committer: { commit: async () => undefined },
      ephemeralSink: {
        emit: async () => {
          emitted.resolve();
          await release.promise;
        },
      },
      maximumEvents: 1,
    };

    const driving = host.startTurn(engine, options);
    await emitted.promise;
    options.maximumEvents = 2;
    release.resolve();
    await expect(driving).rejects.toMatchObject({ code: "EVENT_BUDGET_EXCEEDED" });
    expect(engine.aborts).toEqual(["turn-event-budget-snapshot"]);
  });

  it("aborts and closes iteration when a durable commit fails", async () => {
    const engine = new SequenceEngine([
      { type: "checkpoint", checkpoint: { sequence: 1 } },
      {
        type: "tool_request",
        checkpoint: { sequence: 2 },
        request: { invocationId: "must-not-pull" },
      },
    ]);
    const committer = new GatedCommitter();
    committer.fail = true;
    const host = new SessionHost({
      loader: new FakeLoader(),
      verifier: new FakeVerifier(),
      bindings: bindings("failure"),
    });
    const driving = host.startTurn(engine, {
      turnId: "turn-failure",
      authority: new Uint8Array([4]),
      checkpoint: { sequence: 0 },
      committer,
      ephemeralSink: new RecordingSink(),
      maximumEvents: 10,
    });
    while (committer.events.length === 0) {
      await Promise.resolve();
    }
    committer.release?.();
    await expect(driving).rejects.toMatchObject({ code: "DURABLE_COMMIT_FAILED" });
    expect(engine.pulls).toBe(1);
    expect(engine.aborts).toEqual(["turn-failure"]);
    expect(engine.returns).toBe(1);
  });

  it("aborts even when an invalid iterator has a throwing return accessor", async () => {
    const aborts: string[] = [];
    const iterator = {
      next: async () => ({ done: false as const, value: null as unknown as AgentEvent }),
    } as AsyncIterator<AgentEvent>;
    Object.defineProperty(iterator, "return", {
      get: () => {
        throw new Error("hostile return accessor");
      },
    });
    const events: AsyncIterable<AgentEvent> = {
      [Symbol.asyncIterator]: () => iterator,
    };
    const engine: AgentEngine = {
      startTurn: () => events,
      resumeTurn: () => events,
      abortTurn: async (turnId) => {
        aborts.push(turnId);
      },
    };
    const host = new SessionHost({
      loader: new FakeLoader(),
      verifier: new FakeVerifier(),
      bindings: bindings("throwing-return-accessor"),
    });

    await expect(
      host.startTurn(engine, {
        turnId: "turn-throwing-return-accessor",
        authority: new Uint8Array([1]),
        checkpoint: { sequence: 0 },
        committer: { commit: async () => undefined },
        ephemeralSink: new RecordingSink(),
        maximumEvents: 1,
      }),
    ).rejects.toMatchObject({ code: "INVALID_AGENT_EVENT" });
    expect(aborts).toEqual(["turn-throwing-return-accessor"]);
  });

  it("does not let a stalled iterator cleanup delay abort and failure", async () => {
    const aborts: string[] = [];
    const events: AsyncIterable<AgentEvent> = {
      [Symbol.asyncIterator]: () => ({
        next: async () => ({ done: false, value: null as unknown as AgentEvent }),
        return: async () => new Promise<IteratorResult<AgentEvent>>(() => undefined),
      }),
    };
    const engine: AgentEngine = {
      startTurn: () => events,
      resumeTurn: () => events,
      abortTurn: async (turnId) => {
        aborts.push(turnId);
      },
    };
    const host = new SessionHost({
      loader: new FakeLoader(),
      verifier: new FakeVerifier(),
      bindings: bindings("stalled-return"),
    });
    const driving = host.startTurn(engine, {
      turnId: "turn-stalled-return",
      authority: new Uint8Array([1]),
      checkpoint: { sequence: 0 },
      committer: { commit: async () => undefined },
      ephemeralSink: new RecordingSink(),
      maximumEvents: 1,
    });

    const outcome = await Promise.race([
      driving.then(
        () => "resolved",
        () => "rejected",
      ),
      new Promise<"timed-out">((resolve) => {
        setTimeout(() => resolve("timed-out"), 25);
      }),
    ]);
    expect(outcome).toBe("rejected");
    expect(aborts).toEqual(["turn-stalled-return"]);
  });

  it("keeps a committed terminal result authoritative when cleanup fails", async () => {
    let commits = 0;
    let aborts = 0;
    const events: AsyncIterable<AgentEvent> = {
      [Symbol.asyncIterator]: () => ({
        next: async () => ({
          done: false,
          value: { type: "turn_complete", checkpoint: { sequence: 1 }, result: {} },
        }),
        return: async () => {
          throw new Error("terminal cleanup failed");
        },
      }),
    };
    const engine: AgentEngine = {
      startTurn: () => events,
      resumeTurn: () => events,
      abortTurn: async () => {
        aborts += 1;
      },
    };
    const host = new SessionHost({
      loader: new FakeLoader(),
      verifier: new FakeVerifier(),
      bindings: bindings("terminal-cleanup-failure"),
    });

    await expect(
      host.startTurn(engine, {
        turnId: "turn-terminal-cleanup-failure",
        authority: new Uint8Array([1]),
        checkpoint: { sequence: 0 },
        committer: {
          commit: async () => {
            commits += 1;
          },
        },
        ephemeralSink: new RecordingSink(),
        maximumEvents: 1,
      }),
    ).resolves.toMatchObject({ boundary: { type: "turn_complete" } });
    expect(commits).toBe(1);
    expect(aborts).toBe(0);
  });

  it("fails closed and aborts when an engine exceeds the bounded event budget", async () => {
    const engine = new SequenceEngine([
      { type: "assistant_delta", delta: 1 },
      { type: "assistant_delta", delta: 2 },
      { type: "assistant_delta", delta: 3 },
    ]);
    const host = new SessionHost({
      loader: new FakeLoader(),
      verifier: new FakeVerifier(),
      bindings: bindings("budget"),
    });
    await expect(
      host.startTurn(engine, {
        turnId: "turn-budget",
        authority: new Uint8Array([5]),
        checkpoint: { sequence: 0 },
        committer: { commit: async () => undefined },
        ephemeralSink: new RecordingSink(),
        maximumEvents: 2,
      }),
    ).rejects.toMatchObject({ code: "EVENT_BUDGET_EXCEEDED" });
    expect(engine.aborts).toEqual(["turn-budget"]);
    expect(engine.returns).toBe(1);
  });

  it("rejects malformed events before forwarding or committing them", async () => {
    const engine = new SequenceEngine([
      { type: "assistant_delta", delta: "ok", extra: true } as unknown as AgentEvent,
    ]);
    const sink = new RecordingSink();
    const host = new SessionHost({
      loader: new FakeLoader(),
      verifier: new FakeVerifier(),
      bindings: bindings("shape"),
    });
    await expect(
      host.startTurn(engine, {
        turnId: "turn-shape",
        authority: new Uint8Array([6]),
        checkpoint: { sequence: 0 },
        committer: { commit: async () => undefined },
        ephemeralSink: sink,
        maximumEvents: 2,
      }),
    ).rejects.toBeInstanceOf(SessionHostError);
    expect(sink.events).toHaveLength(0);
    expect(engine.aborts).toEqual(["turn-shape"]);
  });

  it("rejects accessor-backed hostile events without invoking their getters", async () => {
    let getterCalls = 0;
    const event = {} as AgentEvent;
    Object.defineProperties(event, {
      type: {
        enumerable: true,
        get: () => {
          getterCalls += 1;
          return "assistant_delta";
        },
      },
      delta: { enumerable: true, value: "secret" },
    });
    const engine = new SequenceEngine([event]);
    const host = new SessionHost({
      loader: new FakeLoader(),
      verifier: new FakeVerifier(),
      bindings: bindings("accessor"),
    });
    await expect(
      host.startTurn(engine, {
        turnId: "turn-accessor",
        authority: new Uint8Array([7]),
        checkpoint: { sequence: 0 },
        committer: { commit: async () => undefined },
        ephemeralSink: new RecordingSink(),
        maximumEvents: 1,
      }),
    ).rejects.toMatchObject({ code: "INVALID_AGENT_EVENT" });
    expect(getterCalls).toBe(0);
  });

  it("rejects nested checkpoint accessors without executing or committing them", async () => {
    let getterCalls = 0;
    let commits = 0;
    const checkpoint = {};
    Object.defineProperty(checkpoint, "checkpointSequence", {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return 1;
      },
    });
    const engine = new SequenceEngine([
      { type: "tool_request", checkpoint, request: {} },
    ]);
    const host = new SessionHost({
      loader: new FakeLoader(),
      verifier: new FakeVerifier(),
      bindings: bindings("nested-accessor"),
    });

    await expect(
      host.startTurn(engine, {
        turnId: "turn-nested-accessor",
        authority: new Uint8Array([8]),
        checkpoint: { sequence: 0 },
        committer: {
          commit: async () => {
            commits += 1;
          },
        },
        ephemeralSink: new RecordingSink(),
        maximumEvents: 1,
      }),
    ).rejects.toMatchObject({ code: "INVALID_AGENT_EVENT" });
    expect(getterCalls).toBe(0);
    expect(commits).toBe(0);
  });

  it("rejects non-enumerable durable fields before structured cloning", async () => {
    let commits = 0;
    const event = { type: "tool_request", request: {} } as unknown as AgentEvent;
    Object.defineProperty(event, "checkpoint", {
      enumerable: false,
      value: { checkpointSequence: 1 },
    });
    const engine = new SequenceEngine([event]);
    const host = new SessionHost({
      loader: new FakeLoader(),
      verifier: new FakeVerifier(),
      bindings: bindings("non-enumerable-boundary"),
    });

    await expect(
      host.startTurn(engine, {
        turnId: "turn-non-enumerable",
        authority: new Uint8Array([9]),
        checkpoint: { sequence: 0 },
        committer: {
          commit: async () => {
            commits += 1;
          },
        },
        ephemeralSink: new RecordingSink(),
        maximumEvents: 1,
      }),
    ).rejects.toMatchObject({ code: "INVALID_AGENT_EVENT" });
    expect(commits).toBe(0);
  });

  it("rejects byte-buffer and non-canonical array payloads before size checks or commits", async () => {
    const sparse: unknown[] = [];
    sparse.length = 3;
    sparse[0] = "present";
    const augmented = ["value"] as unknown[] & { extra?: boolean };
    augmented.extra = true;
    const augmentedBytes = new Uint8Array([1, 2, 3]) as Uint8Array & {
      extra?: ArrayBuffer;
    };
    augmentedBytes.extra = new ArrayBuffer(4_096);
    const sharedBytes = new Uint8Array(new SharedArrayBuffer(3));
    sharedBytes.set([1, 2, 3]);
    const partialBackingView = new Uint8Array(new ArrayBuffer(4_096), 0, 1);

    for (const [name, payload] of [
      ["raw ArrayBuffer", { bytes: new ArrayBuffer(4_096) }],
      ["sparse array", sparse],
      ["array with extra field", augmented],
      ["byte view with extra field", augmentedBytes],
      ["shared-buffer byte view", sharedBytes],
      ["partial backing-buffer byte view", partialBackingView],
      ["non-finite number", { value: Number.POSITIVE_INFINITY }],
      ["negative zero", { value: -0 }],
    ] as const) {
      let commits = 0;
      const engine = new SequenceEngine([
        {
          type: "turn_complete",
          checkpoint: { sequence: 1 },
          result: payload,
        },
      ]);
      const host = new SessionHost({
        loader: new FakeLoader(),
        verifier: new FakeVerifier(),
        bindings: bindings(`hostile-${name}`),
        limits: { maximumEventBytes: 128 },
      });

      await expect(
        host.startTurn(engine, {
          turnId: `turn-hostile-${name}`,
          authority: new Uint8Array([10]),
          checkpoint: { sequence: 0 },
          committer: {
            commit: async () => {
              commits += 1;
            },
          },
          ephemeralSink: new RecordingSink(),
          maximumEvents: 1,
        }),
      ).rejects.toMatchObject({ code: "INVALID_AGENT_EVENT" });
      expect(commits).toBe(0);
      expect(engine.aborts).toEqual([`turn-hostile-${name}`]);
    }
  });

  it("rejects an oversized byte view before cloning the event", async () => {
    const clone = vi.spyOn(globalThis, "structuredClone");
    const engine = new SequenceEngine([
      {
        type: "turn_complete",
        checkpoint: { sequence: 1 },
        result: { bytes: new Uint8Array(1_024) },
      },
    ]);
    const host = new SessionHost({
      loader: new FakeLoader(),
      verifier: new FakeVerifier(),
      bindings: bindings("oversized-byte-view"),
      limits: { maximumEventBytes: 64 },
    });

    try {
      await expect(
        host.startTurn(engine, {
          turnId: "turn-oversized-byte-view",
          authority: new Uint8Array([1]),
          checkpoint: { sequence: 0 },
          committer: { commit: async () => undefined },
          ephemeralSink: new RecordingSink(),
          maximumEvents: 1,
        }),
      ).rejects.toMatchObject({ code: "INVALID_AGENT_EVENT" });
      expect(clone).toHaveBeenCalledTimes(1);
      expect(engine.aborts).toEqual(["turn-oversized-byte-view"]);
    } finally {
      clone.mockRestore();
    }
  });
});
