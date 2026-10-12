import assert from "node:assert/strict";
import { request } from "node:http";
import { test } from "node:test";

import { MockModelProvider } from "../src/providers/mock.ts";
import { createApp, type App } from "../src/server.ts";
import type { Session } from "../src/session.ts";
import { BASE_TOOL_DEFINITIONS } from "../src/tools.ts";

function terminalEvent(session: Session): Promise<string> {
  return new Promise((resolveEvent, rejectEvent) => {
    const timer = setTimeout(() => { unsubscribe(); rejectEvent(new Error("terminal event did not arrive")); }, 5_000);
    const unsubscribe = session.subscribe((event) => {
      if (!["turn.completed", "turn.failed", "turn.aborted"].includes(event.type)) return;
      clearTimeout(timer);
      unsubscribe();
      resolveEvent(event.type);
    });
  });
}

async function pendingUpload(app: App, base: string, sessionId: string) {
  const path = `/v1/sessions/${sessionId}/turns`;
  let requestStarted: () => void = () => undefined;
  const started = new Promise<void>((resolveStarted) => { requestStarted = resolveStarted; });
  const onRequest = (incoming: { readonly url?: string; readonly method?: string }): void => {
    if (incoming.url === path && incoming.method === "POST") requestStarted();
  };
  app.server.on("request", onRequest);
  let resolveResponse: (response: { status: number; body: { turnId?: string; error?: { code: string } } }) => void = () => undefined;
  let rejectResponse: (error: Error) => void = () => undefined;
  const response = new Promise<{ status: number; body: { turnId?: string; error?: { code: string } } }>((resolve, reject) => {
    resolveResponse = resolve;
    rejectResponse = reject;
  });
  const client = request(`${base}${path}`, { method: "POST", headers: { "content-type": "application/json" } }, (incoming) => {
    let body = "";
    incoming.on("data", (chunk: Buffer) => { body += chunk.toString(); });
    incoming.on("error", rejectResponse);
    incoming.on("end", () => {
      try {
        resolveResponse({ status: incoming.statusCode ?? 0, body: JSON.parse(body) });
      } catch (error) {
        rejectResponse(error as Error);
      }
    });
  });
  client.on("error", rejectResponse);
  client.write('{"prompt":"echo late ');
  await started;
  app.server.off("request", onRequest);
  return { response, finish: () => client.end('valid body"}') };
}

function appFixture() {
  let modelCalls = 0;
  let toolCalls = 0;
  let holdModel = false;
  let modelStarted: () => void = () => undefined;
  let releaseModel: () => void = () => undefined;
  const started = new Promise<void>((resolveStarted) => { modelStarted = resolveStarted; });
  const gate = new Promise<void>((resolveGate) => { releaseModel = resolveGate; });
  const provider = new MockModelProvider({ deltaDelayMs: 0 });
  const complete = provider.complete.bind(provider);
  provider.complete = async (input) => {
    modelCalls += 1;
    modelStarted();
    if (holdModel) await gate;
    return complete(input);
  };
  const cleaned: string[] = [];
  const app = createApp({
    provider,
    tools: BASE_TOOL_DEFINITIONS.map((tool) => ({ ...tool, run: (args, context) => {
      toolCalls += 1;
      return tool.run(args, context);
    } })),
    frontendDirectory: null,
    historyInjection: true,
    maxSessions: 1,
    log: () => undefined,
    onSessionDeleted: async (sessionId) => { cleaned.push(sessionId); },
  });
  return { app, cleaned, started, releaseModel, hold: () => { holdModel = true; }, counts: () => ({ modelCalls, toolCalls }) };
}

for (const removal of ["delete", "evict"] as const) {
  test(`a valid upload completing after session ${removal} is rejected before model/tool work`, async () => {
    const fixture = appFixture();
    const { app } = fixture;
    const { port } = await app.listen("127.0.0.1", 0);
    const base = `http://127.0.0.1:${port}`;
    try {
      const created = await fetch(`${base}/v1/sessions`, { method: "POST", body: "{}" });
      const { sessionId } = await created.json() as { sessionId: string };
      const oldSession = app.store.get(sessionId)!;
      const upload = await pendingUpload(app, base, sessionId);
      assert.equal(oldSession.activeTurn, null);
      if (removal === "delete") {
        assert.equal((await fetch(`${base}/v1/sessions/${sessionId}`, { method: "DELETE" })).status, 204);
      } else {
        assert.equal((await fetch(`${base}/v1/sessions`, { method: "POST", body: "{}" })).status, 201);
      }
      assert.deepEqual(fixture.cleaned, [sessionId]);
      assert.equal(app.store.get(sessionId), undefined);
      upload.finish();
      const rejected = await upload.response;
      assert.equal(rejected.status, 404);
      assert.equal(rejected.body.error?.code, "SESSION_NOT_FOUND");
      assert.equal(oldSession.activeTurn, null);
      assert.equal(oldSession.turns.length, 0);
      assert.deepEqual(fixture.counts(), { modelCalls: 0, toolCalls: 0 });
      assert.equal((await fetch(`${base}/v1/sessions/${sessionId}`)).status, 404);
    } finally {
      fixture.releaseModel();
      await app.close();
    }
  });
}

test("a retained session accepts a valid chunked upload and delivers the tool result", async () => {
  const fixture = appFixture();
  const { app } = fixture;
  const { port } = await app.listen("127.0.0.1", 0);
  const base = `http://127.0.0.1:${port}`;
  try {
    const created = await fetch(`${base}/v1/sessions`, { method: "POST", body: "{}" });
    const { sessionId } = await created.json() as { sessionId: string };
    const session = app.store.get(sessionId)!;
    const upload = await pendingUpload(app, base, sessionId);
    const terminal = terminalEvent(session);
    upload.finish();
    assert.equal((await upload.response).status, 202);
    assert.equal(await terminal, "turn.completed");
    assert.match(session.turns[0]!.result ?? "", /echo: late valid body/);
    assert.deepEqual(fixture.counts(), { modelCalls: 2, toolCalls: 1 });
    assert.deepEqual(fixture.cleaned, []);
    assert.equal((await fetch(`${base}/v1/sessions/${sessionId}`)).status, 200);
  } finally {
    fixture.releaseModel();
    await app.close();
  }
});

test("DELETE after an accepted turn starts still cancels model work before its tool executes", async () => {
  const fixture = appFixture();
  const { app } = fixture;
  fixture.hold();
  const { port } = await app.listen("127.0.0.1", 0);
  const base = `http://127.0.0.1:${port}`;
  try {
    const created = await fetch(`${base}/v1/sessions`, { method: "POST", body: "{}" });
    const { sessionId } = await created.json() as { sessionId: string };
    const session = app.store.get(sessionId)!;
    const terminal = terminalEvent(session);
    const accepted = await fetch(`${base}/v1/sessions/${sessionId}/turns`, {
      method: "POST", body: JSON.stringify({ prompt: "echo cancellation control" }),
    });
    assert.equal(accepted.status, 202);
    await fixture.started;
    const turn = session.activeTurn!;
    assert.equal(turn.controller.signal.aborted, false);
    assert.equal((await fetch(`${base}/v1/sessions/${sessionId}`, { method: "DELETE" })).status, 204);
    assert.equal(turn.controller.signal.aborted, true);
    fixture.releaseModel();
    assert.equal(await terminal, "turn.aborted");
    assert.deepEqual(fixture.counts(), { modelCalls: 1, toolCalls: 0 });
    assert.deepEqual(fixture.cleaned, [sessionId]);
  } finally {
    fixture.releaseModel();
    await app.close();
  }
});
