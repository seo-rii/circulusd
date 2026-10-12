import assert from "node:assert/strict";
import { test } from "node:test";

import { frontend } from "./support/frontend.mjs";

function event(app, type, turnId, data, id) {
  app.streams.at(-1).emit({ id, type, sessionId: app.state.sessionId, turnId, at: Date.now(), data }, String(id));
}

test("a pending submission owns its bubble and blocks another Enter until acceptance", async () => {
  const app = frontend();
  app.select("sess_same");
  const first = app.submit("first prompt");
  const request = app.requests.shift();
  const bubble = app.state.pendingUserBubble;
  assert.equal(app.ui.send.disabled, true);

  app.ui.prompt.value = "second prompt";
  app.ui.prompt.listeners.get("keydown")({ key: "Enter", preventDefault() {} });
  assert.equal(app.requests.length, 0, "Enter must not start a second request while acceptance is pending");
  assert.equal(app.state.pendingUserBubble, bubble);
  assert.equal(app.ui.prompt.value, "second prompt", "blocked submission keeps the next prompt in the composer");

  event(app, "turn.accepted", "turn_first", { prompt: "first prompt" }, 1);
  app.respond(request, { turnId: "turn_first" }, 202);
  await first;
  assert.equal(app.state.userBubbles.get("turn_first"), bubble);
  assert.equal(app.state.activeTurnId, "turn_first");
  assert.equal(app.ui.abort.disabled, false);
  assert.equal(app.ui.send.disabled, true);
  assert.deepEqual(app.ui.messages.children.filter((element) => element.className === "bubble user").map((element) => element.textContent), ["first prompt"]);

  event(app, "turn.completed", "turn_first", { message: { text: "done" }, steps: 1 }, 2);
  assert.equal(app.ui.send.disabled, false);
  const second = app.submitPrompt();
  const secondRequest = app.requests.shift();
  assert.match(secondRequest.init.body, /second prompt/);
  app.respond(secondRequest, { turnId: "turn_second" }, 202);
  await second;
  assert.equal(app.state.activeTurnId, "turn_second");
});

test("a terminal event before acceptance keeps pending ownership until the response settles", async () => {
  const app = frontend();
  app.select("sess_fast");
  const submission = app.submit("first prompt");
  const request = app.requests.shift();
  event(app, "turn.accepted", "turn_first", { prompt: "first prompt" }, 1);
  event(app, "turn.completed", "turn_first", { message: { text: "done" }, steps: 1 }, 2);
  const blocked = app.submit("second prompt");
  assert.equal(app.requests.length, 0, "the unresolved first response still owns the pending submission");
  await blocked;
  assert.equal(app.ui.send.disabled, true);
  app.respond(request, { turnId: "turn_first" }, 202);
  await submission;
  assert.equal(app.state.activeTurnId, null);
  assert.equal(app.ui.send.disabled, false);
  const next = app.submitPrompt();
  app.respond(app.requests.shift(), { turnId: "turn_second" }, 202);
  await next;
  assert.equal(app.state.activeTurnId, "turn_second");
});

test("a failed POST after SSE acceptance preserves the active turn and Abort control", async () => {
  const app = frontend();
  app.select("sess_same");
  const submission = app.submit("first prompt");
  const request = app.requests.shift();
  const bubble = app.state.pendingUserBubble;
  event(app, "turn.accepted", "turn_first", { prompt: "first prompt" }, 1);
  app.respond(request, { error: { message: "response failed" } }, 500);
  await submission;
  assert.equal(app.state.userBubbles.get("turn_first"), bubble);
  assert.equal(app.state.activeTurnId, "turn_first");
  assert.equal(app.ui.abort.disabled, false);
  assert.equal(app.ui.send.disabled, true);
  event(app, "turn.completed", "turn_first", { message: { text: "done" }, steps: 1 }, 2);
  assert.equal(app.ui.send.disabled, false);
});

test("a rejected pending submission releases the composer for a normal retry", async () => {
  const app = frontend();
  app.select("sess_same");
  const submission = app.submit("first prompt");
  app.respond(app.requests.shift(), { error: { message: "request failed" } }, 500);
  await submission;
  assert.equal(app.state.pendingUserBubble, null);
  assert.equal(app.state.activeTurnId, null);
  assert.equal(app.ui.send.disabled, false);
  const retry = app.submit("retry prompt");
  app.respond(app.requests.shift(), { turnId: "turn_retry" }, 202);
  await retry;
  assert.equal(app.state.activeTurnId, "turn_retry");
});

test("a stale submission cannot release a new view's pending submission", async () => {
  const app = frontend();
  app.select("sess_old");
  const oldSubmission = app.submit("old prompt");
  const oldRequest = app.requests.shift();
  const creation = app.newSession();
  app.respond(app.requests.shift(), { sessionId: "sess_new", runtimeRevisionDigest: "sha256:new" });
  await creation;
  const currentSubmission = app.submit("current prompt");
  const currentRequest = app.requests.shift();
  const currentBubble = app.state.pendingUserBubble;
  app.respond(oldRequest, { error: { message: "old response failed" } }, 500);
  await oldSubmission;
  assert.equal(app.state.pendingUserBubble, currentBubble);
  assert.equal(app.ui.send.disabled, true);
  app.respond(currentRequest, { turnId: "turn_current" }, 202);
  await currentSubmission;
  assert.equal(app.state.userBubbles.get("turn_current"), currentBubble);
  assert.equal(app.state.activeTurnId, "turn_current");
  assert.equal(app.ui.abort.disabled, false);
});
