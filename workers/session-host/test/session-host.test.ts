import { describe, expect, it } from "vitest";

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

  constructor(events: AgentEvent[]) {
    this.events = events;
  }

  startTurn(context: { turnId: string; authority: Uint8Array }): AsyncIterable<AgentEvent> {
    this.seenAuthority = context.authority;
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

  resumeTurn(context: { turnId: string; authority: Uint8Array }): AsyncIterable<AgentEvent> {
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
          committer: { commit: async () => undefined },
          ephemeralSink: new RecordingSink(),
          maximumEvents: 1,
        }),
      ).rejects.toMatchObject({ code: "INVALID_AGENT_EVENT" });
      expect(aborts).toEqual(["turn-invalid-stream"]);
    }
  });

  it("validates turn authority before invoking the AgentEngine", async () => {
    const engine = new SequenceEngine([{ type: "turn_complete", result: {} }]);
    const host = new SessionHost({
      loader: new FakeLoader(),
      verifier: new FakeVerifier(),
      bindings: bindings("invalid-turn"),
    });
    await expect(
      host.startTurn(engine, {
        turnId: "turn-invalid",
        authority: new Uint8Array(),
        committer: { commit: async () => undefined },
        ephemeralSink: new RecordingSink(),
        maximumEvents: 1,
      }),
    ).rejects.toMatchObject({ code: "INVALID_TURN" });
    expect(engine.seenAuthority).toBeNull();
    expect(engine.pulls).toBe(0);
  });

  it("does not pull the next event until the current durable commit completes", async () => {
    const engine = new SequenceEngine([
      { type: "checkpoint", checkpoint: { sequence: 1 } },
      { type: "assistant_delta", delta: "hello" },
      { type: "tool_request", request: { invocationId: "inv-1" } },
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
      committer,
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

  it("aborts and closes iteration when a durable commit fails", async () => {
    const engine = new SequenceEngine([
      { type: "checkpoint", checkpoint: { sequence: 1 } },
      { type: "tool_request", request: { invocationId: "must-not-pull" } },
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
        committer: { commit: async () => undefined },
        ephemeralSink: new RecordingSink(),
        maximumEvents: 1,
      }),
    ).rejects.toMatchObject({ code: "INVALID_AGENT_EVENT" });
    expect(getterCalls).toBe(0);
  });
});
