import assert from "node:assert/strict";
import test from "node:test";
import { frontend } from "./support/frontend.mjs";

test("a late turn acceptance cannot populate or lock a new session", async () => {
  const app = frontend();
  app.select("A");
  const old = app.submit();
  const request = app.requests.shift();
  await app.create("B");
  app.respond(request, { turnId: "turn_A" });
  await old;
  assert.equal(app.state.sessionId, "B");
  assert.equal(app.state.activeTurnId, null);
  assert.equal(app.state.bubbles.size, 0);
  assert.equal(app.ui.messages.children.length, 0);
  assert.equal(app.ui.send.disabled, false);
  await app.abortTurn();
  assert.equal(app.requests.length, 0);
});

for (const status of [500, 404]) {
  test(`a late ${status} failure cannot clear the new session's active turn`, async () => {
    const app = frontend();
    app.select("A");
    const old = app.submit();
    const request = app.requests.shift();
    await app.create("B");
    const current = app.submit("prompt B");
    app.respond(app.requests.shift(), { turnId: "turn_B" });
    await current;
    app.respond(request, { error: { message: "old request failed" } }, status);
    await old;
    assert.equal(app.state.activeTurnId, "turn_B");
    assert.equal(app.ui.send.disabled, true);
    assert.equal(app.ui.abort.disabled, false);
    assert.equal(app.state.bubbles.size, 1);
    const abort = app.abortTurn();
    const abortRequest = app.requests.shift();
    assert.equal(abortRequest.url, "/v1/sessions/B/turns/turn_B/abort");
    app.respond(abortRequest, null, 204);
    await abort;
    assert.equal(app.requests.length, 0);
  });
}

test("returning to the same session cannot revive requests from its old view", async () => {
  const app = frontend();
  app.select("A");
  const old = app.submit();
  const request = app.requests.shift();
  await app.create("B");
  app.location.hash = "#A";
  const resume = app.resumeOrCreate();
  app.respond(app.requests.shift(), { sessionId: "A", runtimeRevisionDigest: "sha256:revision" });
  await resume;
  app.respond(request, { turnId: "old_turn_A" });
  await old;
  assert.equal(app.state.sessionId, "A");
  assert.equal(app.state.activeTurnId, null);
  assert.equal(app.state.bubbles.size, 0);
});

test("reordered session creation selects the latest invocation", async () => {
  const app = frontend();
  const first = app.newSession();
  const request = app.requests.shift();
  await app.create("B");
  app.respond(request, { sessionId: "A" });
  await first;
  assert.equal(app.state.sessionId, "B");
  assert.equal(app.ui.sessionId.textContent, "B");
  assert.equal(app.location.hash, "#B");
  assert.equal(app.streams.length, 1);
});

test("a stale session creation failure is ignored", async () => {
  const app = frontend();
  const first = app.newSession();
  const request = app.requests.shift();
  await app.create("B");
  request.reject(new Error("old network failure"));
  await first;
  assert.equal(app.state.sessionId, "B");
});

for (const status of [200, 404]) {
  test(`a late session resume (${status}) cannot replace the latest view`, async () => {
    const app = frontend();
    app.location.hash = "#A";
    const resume = app.resumeOrCreate();
    const request = app.requests.shift();
    await app.create("B");
    app.respond(request, { sessionId: "A" }, status);
    await resume;
    assert.equal(app.state.sessionId, "B");
    assert.equal(app.requests.length, 0);
    assert.equal(app.streams.length, 1);
  });
}

test("events and error callbacks from a closed view cannot change the new view", async () => {
  const app = frontend();
  app.select("A");
  const oldSource = app.state.source;
  await app.create("B");
  oldSource.emit({ id: 1, type: "turn.accepted", turnId: "turn_A", data: { prompt: "A" } }, "1");
  oldSource.onerror();
  assert.equal(oldSource.closed, true);
  assert.equal(app.state.activeTurnId, null);
  assert.equal(app.state.eventCount, 0);
  assert.equal(app.requests.length, 0);
});

test("a terminal SSE event arriving before acceptance keeps the composer unlocked", async () => {
  const app = frontend();
  app.select("A");
  const submit = app.submit();
  app.state.source.emit({ id: 1, type: "turn.completed", turnId: "turn_A", data: {} }, "1");
  app.respond(app.requests.shift(), { turnId: "turn_A" });
  await submit;
  assert.equal(app.state.activeTurnId, null);
  assert.equal(app.ui.send.disabled, false);
});
