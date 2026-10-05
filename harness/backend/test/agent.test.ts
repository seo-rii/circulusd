import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { rm } from "node:fs/promises";
import { createServer, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { test } from "node:test";

import { buildAdapterConfiguration, engineIdentity, runtimeRevisionDigest } from "../src/agent-config.ts";
import {
  MOCK_MODEL,
  MockModelProvider,
  ModelProviderError,
  defaultOllamaBaseUrl,
  planToolCall,
  resolveModelProvider,
  type ModelProvider,
} from "../src/providers/index.ts";
import { CirculusdSandboxExecutor } from "../src/sandbox/executor.ts";
import type { SandboxProcess, SandboxReady } from "../src/sandbox/launcher.ts";
import { PiAiModelProvider } from "../src/providers/pi-ai.ts";
import { createApp } from "../src/server.ts";
import {
  MAX_EVENTS_PER_SESSION,
  MAX_TRANSCRIPT_ENTRIES,
  MAX_TURNS_PER_SESSION,
  Session,
  SessionStore,
  type DurableEvent,
  type TranscriptEntry,
} from "../src/session.ts";
import {
  HostPythonExecutor,
  createPythonTool,
  resolvePythonInterpreter,
  runPython,
  sessionWorkspace,
  unescapeNewlines,
} from "../src/python-tool.ts";
import { createToolDefinitions, evaluateArithmetic, executeTool, type ToolContext } from "../src/tools.ts";
import { MAX_TOOL_CALLS_PER_TURN, createTurnRuntime, fitHistory, historyBudgetChars, runTurn } from "../src/turn-runner.ts";

const hostInterpreter = resolvePythonInterpreter();
// Tests exercise the python tool on the host executor; the circulusd sandbox has its own live test.
const testTools = createToolDefinitions(
  hostInterpreter === null ? [] : [createPythonTool(new HostPythonExecutor(hostInterpreter))],
);

function toolContext(sessionId: string, toolCallId: string, signal = new AbortController().signal): ToolContext {
  return {
    sessionId,
    turnId: "turn_test",
    toolCallId,
    signal,
    effect: { requestDigest: `sha256:${"0".repeat(64)}`, replayPolicy: "never", operation: "external-tool.call" },
  };
}

interface ParsedSseEvent {
  readonly id: number | null;
  readonly type: string;
  readonly data: { readonly turnId: string | null; readonly data: Record<string, unknown> };
}

function testRuntime() {
  const provider = new MockModelProvider({ deltaDelayMs: 0 });
  const configuration = buildAdapterConfiguration(provider.configuration, testTools);
  const digest = runtimeRevisionDigest(configuration);
  return {
    provider,
    digest,
    runtime: createTurnRuntime({
      provider,
      tools: testTools,
      configuration,
      identity: (sessionId) => engineIdentity(sessionId, digest),
      historyInjection: true,
    }),
  };
}

test("calculator tool evaluates arithmetic without eval", () => {
  assert.equal(evaluateArithmetic("12*(3+4)"), 84);
  assert.equal(evaluateArithmetic("2^10 - 24"), 1000);
  assert.equal(evaluateArithmetic("-(1+2)*3"), -9);
  assert.equal(evaluateArithmetic("-2^2"), -4, "unary minus binds looser than ^");
  assert.equal(evaluateArithmetic("2^-1"), 0.5);
  assert.equal(evaluateArithmetic("2^3^2"), 512, "^ is right-associative");
  assert.throws(() => evaluateArithmetic("1/0"), /division by zero/);
  assert.throws(() => evaluateArithmetic("1+"), /unexpected token/);
});

test("mock model routes prompts to tools deterministically", () => {
  assert.deepEqual(planToolCall("12*(3+4) 계산해줘"), {
    name: "calculator",
    arguments: { expression: "12*(3+4)" },
  });
  assert.deepEqual(planToolCall("echo hello"), { name: "echo", arguments: { text: "hello" } });
  assert.deepEqual(planToolCall("지금 몇 시야?"), { name: "now", arguments: {} });
  assert.equal(planToolCall("안녕하세요"), null);
});

test("ollama spec resolves against the Ollama tag listing without a real server", async () => {
  assert.equal(defaultOllamaBaseUrl(undefined), "http://127.0.0.1:11434/v1");
  assert.equal(defaultOllamaBaseUrl("127.0.0.1:11434"), "http://127.0.0.1:11434/v1");
  assert.equal(defaultOllamaBaseUrl("http://gpu-box:11434/"), "http://gpu-box:11434/v1");

  const requested: string[] = [];
  const fakeFetch = (async (input: string | URL | Request) => {
    requested.push(String(input));
    return new Response(
      JSON.stringify({
        models: [
          {
            name: "qwen3:8b",
            details: { context_length: 40960 },
            capabilities: ["completion", "tools", "thinking"],
          },
          { name: "tinyllama:latest", details: { context_length: 2048 }, capabilities: ["completion"] },
        ],
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  }) as typeof fetch;

  const provider = await resolveModelProvider("ollama:qwen3:8b", { fetch: fakeFetch });
  assert.deepEqual(requested, ["http://127.0.0.1:11434/api/tags"]);
  assert.deepEqual(provider.configuration, {
    id: "qwen3:8b",
    api: "openai-completions",
    provider: "ollama",
    reasoning: true,
    input: ["text"],
    contextWindow: 40960,
    maxTokens: 8192,
  });
  const description = provider.describe();
  assert.equal(description.kind, "ollama");
  assert.equal(description.baseUrl, "http://127.0.0.1:11434/v1");
  assert.equal(description.supportsTools, true);

  const warnings: string[] = [];
  const noTools = await resolveModelProvider("ollama:tinyllama@http://gpu-box:11434/v1", {
    fetch: fakeFetch,
    log: (line) => warnings.push(line),
  });
  assert.equal(noTools.describe().supportsTools, false);
  assert.equal(noTools.configuration.contextWindow, 2048);
  assert.equal(requested.at(-1), "http://gpu-box:11434/api/tags");
  assert.match(warnings[0] ?? "", /does not advertise the "tools" capability/);

  await assert.rejects(
    resolveModelProvider("ollama:missing-model", { fetch: fakeFetch }),
    /has no model "missing-model"; available: qwen3:8b, tinyllama:latest/,
  );
  const mock = await resolveModelProvider(undefined);
  assert.equal(mock.describe().kind, "mock");
});

test("mock provider drives the circulusd engine through model -> tool -> model -> turn_complete", async () => {
  const { runtime, digest } = testRuntime();
  const session = new Session(digest);
  const turn = session.beginTurn("12*(3+4) 계산해줘");
  await runTurn(session, turn, runtime);

  assert.equal(turn.status, "completed");
  assert.equal(turn.error, null);
  assert.match(turn.result ?? "", /84/);
  assert.equal(session.activeTurn, null);

  const types = session.events.filter((event) => event.type !== "checkpoint").map((event) => event.type);
  assert.deepEqual(types, [
    "turn.accepted",
    "model.started",
    "model.settled",
    "tool.started",
    "tool.completed",
    "model.started",
    "model.settled",
    "turn.completed",
  ]);

  // Every durable event id is strictly increasing and the checkpoint chain
  // advances one sequence per bounded step.
  let previousId = 0;
  let previousSequence = -1;
  for (const event of session.events) {
    assert.ok(event.id > previousId);
    previousId = event.id;
    const checkpoint = (event.data as { checkpoint?: { sequence: number } }).checkpoint;
    if (checkpoint !== undefined) {
      assert.ok(checkpoint.sequence >= previousSequence);
      previousSequence = checkpoint.sequence;
    }
  }
  assert.ok(previousSequence >= 3, `expected at least three successor checkpoints, saw ${previousSequence}`);

  const toolCompleted = session.events.find((event) => event.type === "tool.completed") as DurableEvent;
  assert.deepEqual(
    { name: (toolCompleted.data as { name: string }).name, text: (toolCompleted.data as { text: string }).text },
    { name: "calculator", text: "84" },
  );

  // A second turn sees the earlier exchange through history injection.
  const second = session.beginTurn("고마워");
  await runTurn(session, second, runtime);
  assert.equal(second.status, "completed");
  const secondModelStart = session.events.filter((event) => event.type === "model.started").at(-1) as DurableEvent;
  assert.equal((secondModelStart.data as { historyInjected: number }).historyInjected, 2);
});

test("aborting a running turn settles it as turn.aborted", async () => {
  const provider = new MockModelProvider({ deltaDelayMs: 20 });
  const configuration = buildAdapterConfiguration(provider.configuration, testTools);
  const digest = runtimeRevisionDigest(configuration);
  const runtime = createTurnRuntime({
    provider,
    tools: testTools,
    configuration,
    identity: (sessionId) => engineIdentity(sessionId, digest),
    historyInjection: false,
  });
  const session = new Session(digest);
  const turn = session.beginTurn("안녕하세요");
  const unsubscribe = session.subscribe((event) => {
    if (event.type === "model.delta") turn.controller.abort();
  });
  await runTurn(session, turn, runtime);
  unsubscribe();
  assert.equal(turn.status, "aborted");
  assert.equal(session.events.at(-1)?.type, "turn.aborted");
});

test("HTTP API: session creation, idempotent turn submission, SSE replay with Last-Event-ID", async () => {
  const app = createApp({
    provider: new MockModelProvider({ deltaDelayMs: 0 }),
    tools: testTools,
    frontendDirectory: null,
    historyInjection: true,
    log: () => undefined,
  });
  const { port } = await app.listen("127.0.0.1", 0);
  const base = `http://127.0.0.1:${port}`;
  try {
    const capabilities = (await (await fetch(`${base}/v1/capabilities`)).json()) as {
      model: { kind: string };
      tools: { name: string }[];
    };
    assert.equal(capabilities.model.kind, "mock");
    assert.deepEqual(
      capabilities.tools.map((tool) => tool.name),
      ["echo", "now", "calculator", "python"],
    );

    const created = (await (
      await fetch(`${base}/v1/sessions`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      })
    ).json()) as { sessionId: string };
    assert.match(created.sessionId, /^sess_/);

    const submit = async (): Promise<{ turnId: string; replayed: boolean }> =>
      (await (
        await fetch(`${base}/v1/sessions/${created.sessionId}/turns`, {
          method: "POST",
          headers: { "content-type": "application/json", "idempotency-key": "turn-key-1" },
          body: JSON.stringify({ messages: [{ role: "user", content: "echo hello circulusd" }] }),
        })
      ).json()) as { turnId: string; replayed: boolean };
    const tooLong = await fetch(`${base}/v1/sessions/${created.sessionId}/turns`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ prompt: "x".repeat(64 * 1024 + 1) }),
    });
    assert.equal(tooLong.status, 400);
    assert.equal(((await tooLong.json()) as { error: { code: string } }).error.code, "PROMPT_TOO_LONG");

    const accepted = await submit();
    assert.match(accepted.turnId, /^turn_/);
    assert.equal(accepted.replayed, false);
    const replayed = await submit();
    assert.deepEqual(replayed, { ...replayed, turnId: accepted.turnId, replayed: true });

    const events = await readSse(
      `${base}/v1/sessions/${created.sessionId}/events`,
      (event) => event.type === "turn.completed",
    );
    const durable = events.filter((event) => event.id !== null);
    assert.ok(durable.length >= 6);
    const toolCompleted = events.find((event) => event.type === "tool.completed");
    assert.equal(toolCompleted?.data.data.text, "hello circulusd");
    const completed = events.at(-1);
    assert.equal(completed?.data.turnId, accepted.turnId);

    // Reconnecting with Last-Event-ID replays only the newer durable events.
    const cursor = durable[2]?.id ?? 0;
    const replay = await readSse(
      `${base}/v1/sessions/${created.sessionId}/events`,
      (event) => event.type === "turn.completed",
      cursor,
    );
    const replayedDurable = replay.filter((event) => event.id !== null);
    assert.equal(replayedDurable[0]?.id, cursor + 1);
    assert.equal(replayedDurable.length, durable.length - 3);

    const snapshot = (await (await fetch(`${base}/v1/sessions/${created.sessionId}`)).json()) as {
      turns: { status: string; result: string }[];
    };
    assert.equal(snapshot.turns[0]?.status, "completed");
    assert.match(snapshot.turns[0]?.result ?? "", /hello circulusd/);
    const listing = (await (await fetch(`${base}/v1/sessions`)).json()) as { sessions: { sessionId: string; turns: number }[] };
    assert.deepEqual(listing.sessions.map((entry) => [entry.sessionId, entry.turns]), [[created.sessionId, 1]]);

    const deleted = await fetch(`${base}/v1/sessions/${created.sessionId}`, { method: "DELETE" });
    assert.equal(deleted.status, 204);
    const missing = await fetch(`${base}/v1/sessions/${created.sessionId}`);
    assert.equal(missing.status, 404);
  } finally {
    await app.close();
  }
});

test("a turn whose model keeps calling tools is stopped at the tool-call budget", async () => {
  // A model that answers every context with one more echo call, forever.
  const looping: ModelProvider = {
    configuration: MOCK_MODEL,
    describe: () => new MockModelProvider().describe(),
    complete: async () => ({
      role: "assistant",
      content: [{ type: "toolCall", id: `call_${randomUUID().slice(0, 8)}`, name: "echo", arguments: { text: "again" } }],
      api: MOCK_MODEL.api,
      provider: MOCK_MODEL.provider,
      model: MOCK_MODEL.id,
      usage: { input: 1, output: 1, cacheRead: 0, cacheWrite: 0, totalTokens: 2, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } },
      stopReason: "toolUse",
      timestamp: Date.now(),
    }),
  };
  const configuration = buildAdapterConfiguration(looping.configuration, testTools);
  const digest = runtimeRevisionDigest(configuration);
  const runtime = createTurnRuntime({
    provider: looping,
    tools: testTools,
    configuration,
    identity: (sessionId) => engineIdentity(sessionId, digest),
    historyInjection: false,
  });
  const session = new Session(digest);
  const turn = session.beginTurn("loop");
  await runTurn(session, turn, runtime);
  assert.equal(turn.status, "failed");
  assert.equal(session.events.filter((event) => event.type === "tool.started").length, MAX_TOOL_CALLS_PER_TURN);
  const rejected = session.events.find((event) => event.type === "effect.rejected");
  assert.equal((rejected?.data as { error: { code: string } }).error.code, "TOOL_CALL_LIMIT");
  assert.equal(session.events.at(-1)?.type, "turn.failed");
});

test("a session retains a bounded tail of its log and transcript", () => {
  const session = new Session("sha256:x");
  for (let index = 0; index < MAX_EVENTS_PER_SESSION + 10; index += 1) session.commit("checkpoint", null, index);
  assert.equal(session.events.length, MAX_EVENTS_PER_SESSION);
  assert.equal(session.lastEventId, MAX_EVENTS_PER_SESSION + 10);
  assert.equal(session.firstEventId, 11, "the ten oldest events were dropped");
  const replayed: number[] = [];
  session.subscribe((event) => replayed.push(event.id ?? -1), 5)();
  assert.equal(replayed[0], 11, "replay from before the window starts at the window");
  assert.equal(replayed.length, MAX_EVENTS_PER_SESSION);

  for (let index = 0; index < MAX_TRANSCRIPT_ENTRIES / 2 + 3; index += 1) {
    session.remember({ role: "user", text: `q${index}`, turnId: `t${index}` }, { role: "assistant", text: `a${index}`, turnId: `t${index}` });
  }
  assert.equal(session.transcript.length, MAX_TRANSCRIPT_ENTRIES);
  assert.equal(session.transcript[0]?.role, "user", "the retained transcript starts with a user turn");
  assert.equal(session.transcript[0]?.turnId, "t3");
});

test("a session keeps a bounded number of turn records and forgets their idempotency keys", () => {
  const session = new Session("sha256:x");
  const firstTurnId = session.beginTurn("first").turnId;
  session.rememberIdempotency("key-first", firstTurnId);
  session.activeTurn = null;
  for (let index = 0; index < MAX_TURNS_PER_SESSION; index += 1) {
    session.beginTurn(`turn ${index}`);
    session.activeTurn = null;
  }
  assert.equal(session.turns.length, MAX_TURNS_PER_SESSION);
  assert.equal(session.findTurn(firstTurnId), undefined, "the oldest turn was dropped");
  assert.equal(session.idempotentTurnId("key-first"), undefined, "its key no longer replays a missing turn");
  assert.equal(session.turns[session.turns.length - 1]?.prompt, `turn ${MAX_TURNS_PER_SESSION - 1}`);
});

test("session store evicts the longest-idle session at its limit, never one with a running turn", () => {
  const evicted: string[] = [];
  const store = new SessionStore({ limit: 2, onEvict: (session) => evicted.push(session.id) });
  const first = store.create("sha256:x");
  const second = store.create("sha256:x");
  assert.ok(first !== null && second !== null);
  second.commit("turn.accepted", null, {}); // newer activity than `first`
  const third = store.create("sha256:x");
  assert.ok(third !== null);
  assert.deepEqual(evicted, [first.id]);
  assert.equal(store.get(first.id), undefined);
  assert.equal(store.list().length, 2);

  second.beginTurn("busy");
  third.beginTurn("busy");
  assert.equal(store.create("sha256:x"), null, "every slot has a running turn");
  assert.deepEqual(evicted, [first.id]);
});

test("history injection keeps the newest whole turns that fit the context window", () => {
  const transcript: TranscriptEntry[] = [
    { role: "user", text: "a".repeat(100), turnId: "t1" },
    { role: "assistant", text: "b".repeat(100), turnId: "t1" },
    { role: "user", text: "c".repeat(100), turnId: "t2" },
    { role: "assistant", text: "d".repeat(100), turnId: "t2" },
  ];
  assert.equal(fitHistory(transcript, 1_000).length, 4, "everything fits");
  assert.deepEqual(
    fitHistory(transcript, 250).map((entry) => entry.turnId),
    ["t2", "t2"],
    "oldest entries go first",
  );
  assert.deepEqual(
    fitHistory(transcript, 350).map((entry) => entry.turnId),
    ["t2", "t2"],
    "a dangling assistant entry is dropped so the history starts at a user turn",
  );
  assert.equal(fitHistory(transcript, 50).length, 0);
  // The mock window is 32768 tokens with 4096 reserved for the answer: 28672 tokens of room.
  const budget = historyBudgetChars({ messages: [] }, MOCK_MODEL);
  assert.ok(budget > 100_000 && budget < 28_672 * 4, `budget ${budget}`);
});

test("HTTP API: deleting or evicting a session ends its event streams and runs the cleanup hook", async () => {
  const cleaned: string[] = [];
  const app = createApp({
    provider: new MockModelProvider({ deltaDelayMs: 0 }),
    tools: testTools,
    frontendDirectory: null,
    historyInjection: false,
    log: () => undefined,
    maxSessions: 1,
    onSessionDeleted: async (sessionId) => {
      cleaned.push(sessionId);
    },
  });
  const { port } = await app.listen("127.0.0.1", 0);
  const base = `http://127.0.0.1:${port}`;
  const createSession = async (): Promise<string> =>
    ((await (await fetch(`${base}/v1/sessions`, { method: "POST", body: "{}" })).json()) as { sessionId: string }).sessionId;
  try {
    const first = await createSession();
    const firstSession = app.store.get(first)!;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10_000);
    const stream = await fetch(`${base}/v1/sessions/${first}/events`, { signal: controller.signal });
    const reader = stream.body!.getReader();
    await reader.read(); // stream.open
    // A running turn is aborted when its session goes; the runner then still
    // commits the turn's final events. The stream must already be detached so
    // nothing is written to the ended response (a write after end raises
    // ERR_STREAM_WRITE_AFTER_END, fatal when unhandled). Stand in for the
    // runner with a listener that commits right after the abort.
    const pending = firstSession.beginTurn("pending");
    pending.controller.signal.addEventListener("abort", () => {
      queueMicrotask(() => {
        firstSession.commit("turn.aborted", pending.turnId, { late: true });
        firstSession.emit("model.delta", pending.turnId, { text: "late" });
      });
    });
    assert.equal((await fetch(`${base}/v1/sessions/${first}`, { method: "DELETE" })).status, 204);
    // The stream must end on its own instead of hanging on a dead session.
    for (;;) {
      const { done } = await reader.read();
      if (done) break;
    }
    clearTimeout(timer);
    assert.deepEqual(cleaned, [first]);
    assert.equal((await fetch(`${base}/v1/capabilities`)).status, 200, "the backend is still up");

    // With one slot, a new session evicts the idle one and cleans up after it.
    const second = await createSession();
    const third = await createSession();
    assert.equal((await fetch(`${base}/v1/sessions/${second}`)).status, 404);
    assert.equal((await fetch(`${base}/v1/sessions/${third}`)).status, 200);
    assert.deepEqual(cleaned, [first, second]);
  } finally {
    await app.close();
  }
});

async function readSse(
  url: string,
  until: (event: ParsedSseEvent) => boolean,
  lastEventId?: number,
): Promise<ParsedSseEvent[]> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);
  const response = await fetch(url, {
    signal: controller.signal,
    headers: lastEventId === undefined ? {} : { "last-event-id": String(lastEventId) },
  });
  assert.equal(response.headers.get("content-type"), "text/event-stream; charset=utf-8");
  const reader = response.body!.getReader();
  const decoder = new TextDecoder();
  const events: ParsedSseEvent[] = [];
  let buffer = "";
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let boundary = buffer.indexOf("\n\n");
      while (boundary !== -1) {
        const block = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + 2);
        boundary = buffer.indexOf("\n\n");
        const parsed = parseSseBlock(block);
        if (parsed === null) continue;
        events.push(parsed);
        if (until(parsed)) return events;
      }
    }
    return events;
  } finally {
    clearTimeout(timeout);
    controller.abort();
  }
}

function parseSseBlock(block: string): ParsedSseEvent | null {
  let id: number | null = null;
  let type = "message";
  let data = "";
  for (const line of block.split("\n")) {
    if (line.startsWith("id: ")) id = Number(line.slice(4));
    else if (line.startsWith("event: ")) type = line.slice(7);
    else if (line.startsWith("data: ")) data += line.slice(6);
  }
  if (data === "") return null;
  return { id, type, data: JSON.parse(data) as ParsedSseEvent["data"] };
}

const pythonInterpreter = resolvePythonInterpreter();

test(
  "python tool runs scripts on the host with stdin, failures, timeouts, and a per-session workspace",
  { skip: pythonInterpreter === null ? "no Python 3 interpreter on this host" : false },
  async () => {
    const context = toolContext(`test_${randomUUID().slice(0, 8)}`, "call_py");
    const workspace = sessionWorkspace(context.sessionId);
    try {
      const ok = await executeTool(
        testTools,
        "python",
        { code: "import sys\nprint(sum(range(10)))\nprint(sys.stdin.read().upper())", stdin: "hi" },
        context,
      );
      assert.equal(ok.isError, false, ok.text);
      assert.equal(ok.text, "45\nHI");

      const failed = await executeTool(testTools, "python",{ code: "print('before')\nraise ValueError('boom')" }, context);
      assert.equal(failed.isError, true);
      assert.match(failed.text, /^exit code 1\n/);
      assert.match(failed.text, /before/);
      assert.match(failed.text, /ValueError: boom/);
      assert.doesNotMatch(failed.text, /\.run-[0-9a-f]+\.py/, "script path is rewritten in tracebacks");

      const timedOut = await runPython(pythonInterpreter!, {
        code: "import time\nprint('tick', flush=True)\ntime.sleep(30)",
        workspace,
        timeoutMs: 1_000,
      });
      assert.equal(timedOut.isError, true);
      assert.match(timedOut.text, /timed out after 1000 ms/);
      assert.match(timedOut.text, /tick/);

      const controller = new AbortController();
      setTimeout(() => controller.abort(), 300);
      const abortStarted = Date.now();
      const cancelled = await executeTool(
        testTools,
        "python",
        { code: "import time\nprint('tick', flush=True)\ntime.sleep(30)" },
        toolContext(context.sessionId, "call_abort", controller.signal),
      );
      assert.equal(cancelled.isError, true);
      assert.match(cancelled.text, /the process was cancelled/);
      assert.ok(Date.now() - abortStarted < 10_000, "abort kills the process instead of waiting for the timeout");

      await executeTool(testTools, "python",{ code: "open('note.txt', 'w').write('kept')" }, context);
      const readBack = await executeTool(testTools, "python",{ code: "print(open('note.txt').read())" }, context);
      assert.equal(readBack.text, "kept", "workspace persists across calls in one session");

      const empty = await executeTool(testTools, "python",{ code: "   " }, context);
      assert.equal(empty.isError, true);
      assert.match(empty.text, /non-empty/);

      const flood = await executeTool(testTools, "python",{ code: "print('x' * 100000)" }, context);
      assert.equal(flood.isError, false);
      assert.match(flood.text, /\[truncated at \d+ characters\]$/);
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  },
);

test("mock model routes python code to the python tool", () => {
  assert.deepEqual(planToolCall("이거 실행해줘\n```python\nprint(1+1)\n```"), {
    name: "python",
    arguments: { code: "print(1+1)\n" },
  });
  assert.deepEqual(planToolCall("python: print('x')"), { name: "python", arguments: { code: "print('x')" } });
  assert.deepEqual(planToolCall("12*(3+4) 계산해줘"), {
    name: "calculator",
    arguments: { expression: "12*(3+4)" },
  });
});

test(
  "python tool re-runs code that arrived on one line with literal \\n escapes",
  { skip: pythonInterpreter === null ? "no Python 3 interpreter on this host" : false },
  async () => {
    assert.equal(unescapeNewlines("print(1)\nprint(2)"), null);
    assert.equal(unescapeNewlines("print(1)"), null);
    assert.equal(unescapeNewlines("a = 1\\nprint(a)"), "a = 1\nprint(a)");
    // Escapes inside string literals (and their closing quotes) are left alone.
    assert.equal(
      unescapeNewlines(String.raw`print("x\ny")\nprint('a\'b\n')\n# note\nprint(f"{1}\n")`),
      `print("x\\ny")\nprint('a\\'b\\n')\n# note\nprint(f"{1}\\n")`,
    );
    assert.equal(unescapeNewlines(String.raw`s = """multi\nline"""\nprint(s)`), `s = """multi\\nline"""\nprint(s)`);

    const context = toolContext(`test_${randomUUID().slice(0, 8)}`, "call_esc");
    try {
      const escaped = "with open('x.txt', 'w') as f:\\n    f.write('ok')\\nprint(open('x.txt').read())";
      const result = await executeTool(testTools, "python",{ code: escaped }, context);
      assert.equal(result.isError, false, result.text);
      assert.match(result.text, /^note: the code arrived on a single line/);
      assert.match(result.text, /\nok$/);

      // A genuine syntax error in properly formatted code is reported as-is.
      const broken = await executeTool(testTools, "python",{ code: "print('a'\nprint('b')" }, context);
      assert.equal(broken.isError, true);
      assert.doesNotMatch(broken.text, /^note:/);
    } finally {
      await rm(sessionWorkspace(context.sessionId), { recursive: true, force: true });
    }
  },
);

test("circulusd sandbox executor starts the agent again after it died, at most once per interval", async () => {
  // Stand-ins for sandbox/agent: each fake agent answers the JSON API from
  // its own HTTP server and prints its launch number, and can be made to die.
  interface FakeAgent {
    readonly process: SandboxProcess;
    readonly server: Server;
    die(code: number): void;
  }
  const agents: FakeAgent[] = [];
  const launch = async (): Promise<SandboxProcess> => {
    const number = agents.length + 1;
    const server = createServer((request, response) => {
      const body =
        request.url === "/v1/ready"
          ? { ready: true }
          : {
              stdout: `agent ${number}\n`,
              stderr: "",
              stdoutTruncated: false,
              stderrTruncated: false,
              exitCode: 0,
              timedOut: false,
              cancelled: false,
              outputTruncated: false,
              signal: "",
              sandboxId: "sb",
              generation: 1,
            };
      response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(body));
    });
    await new Promise<void>((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
    const { port } = server.address() as AddressInfo;
    let exitStatus: number | null | undefined;
    let resolveExit: (code: number | null) => void = () => undefined;
    const exited = new Promise<number | null>((resolveExited) => {
      resolveExit = resolveExited;
    });
    const die = (code: number): void => {
      if (exitStatus !== undefined) return;
      exitStatus = code;
      resolveExit(code);
      server.close();
    };
    const process: SandboxProcess = {
      ready: { host: "127.0.0.1", port, token: `token-${number}` } as unknown as SandboxReady,
      exited,
      exitStatus: () => exitStatus,
      close: async () => die(0),
    };
    agents.push({ process, server, die });
    return process;
  };
  const logs: string[] = [];
  const executor = await CirculusdSandboxExecutor.start({
    distro: null,
    sandboxDirectory: ".",
    launcher: "auto",
    python: "python3",
    workspaceSize: "64m",
    log: (line) => logs.push(line),
    launch,
    relaunchMinIntervalMs: 300,
  });
  const run = (callId: string): Promise<{ text: string; isError: boolean }> =>
    executor.run({ code: "print(1)", stdin: "", timeoutMs: 1_000, context: toolContext("sess_x", callId) });
  try {
    assert.match((await run("c1")).text, /agent 1/);
    assert.equal(executor.describe().agentAlive, true);

    // The agent dies right after starting: no relaunch yet, a clear error instead.
    agents[0]!.die(137);
    await new Promise((resolveTick) => setTimeout(resolveTick, 10));
    assert.equal(executor.describe().agentAlive, false);
    await assert.rejects(run("c2"), /exited \(status 137\).*started again at most every/);
    assert.equal(agents.length, 1);

    // Past the interval the next call starts a new agent; concurrent calls share that launch.
    await new Promise((resolveWait) => setTimeout(resolveWait, 350));
    const [a, b] = await Promise.all([run("c3"), run("c4")]);
    assert.match(a.text, /agent 2/);
    assert.match(b.text, /agent 2/);
    assert.equal(agents.length, 2, "one relaunch served both calls");
    assert.equal(executor.relaunches, 1);
    assert.equal(executor.describe().agentRelaunches, 1);
    assert.ok(logs.some((line) => /agent is back/.test(line)), logs.join("\n"));
  } finally {
    await executor.close();
    for (const agent of agents) agent.die(0);
  }
  assert.ok(agents.every((agent) => agent.process.exitStatus() !== undefined), "close() stopped the live agent");
});

test("a model server that accepts the request and never answers is given up as MODEL_STALLED", async () => {
  // An OpenAI-compatible endpoint that opens the stream and then says nothing.
  const held: ServerResponse[] = [];
  const server = createServer((request, response) => {
    response.writeHead(200, { "content-type": "text/event-stream" });
    response.write(": open\n\n");
    held.push(response);
  });
  await new Promise<void>((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
  const { port } = server.address() as AddressInfo;
  const provider = new PiAiModelProvider({
    kind: "openai-compatible",
    modelId: "wedged",
    baseUrl: `http://127.0.0.1:${port}/v1`,
    apiKeyEnv: "CIRCULUSD_TEST_NO_SUCH_KEY",
    apiKeyRequired: false,
    placeholderApiKey: "none",
    stallTimeoutMs: 300,
  });
  const started = Date.now();
  try {
    await assert.rejects(
      provider.complete({
        context: { messages: [{ role: "user", content: "hello", timestamp: Date.now() }] },
        signal: new AbortController().signal,
        onDelta: () => undefined,
      }),
      (error: unknown) => error instanceof ModelProviderError && error.code === "MODEL_STALLED" && /300 ms/.test(error.message),
    );
    assert.ok(Date.now() - started < 10_000, "gave up on the stall timer, not on some other timeout");
  } finally {
    for (const response of held) response.destroy();
    server.close();
  }
});
