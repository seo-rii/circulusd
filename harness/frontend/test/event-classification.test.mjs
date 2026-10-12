import assert from "node:assert/strict";
import test from "node:test";
import { frontend } from "./support/frontend.mjs";

test("ephemeral payload ids retain their classification when EventSource retains a durable cursor", () => {
  const app = frontend();
  app.select("A");
  const source = app.state.source;
  source.emit({ id: 7, type: "model.started", turnId: "turn_A", data: {} }, "7");
  source.emit({ id: null, type: "model.delta", turnId: "turn_A", data: { text: "delta" } }, "7");
  source.emit({ id: null, type: "tool.stdout", turnId: "turn_A", data: { text: "stdout" } }, "7");
  assert.equal(app.state.eventCount, 1);
  assert.equal(app.state.ephemeralCount, 2);
  assert.equal(app.ui.eventList.children.length, 1);
  assert.equal(app.state.lastEventId, 7);
  assert.equal(app.ui.lastId.textContent, "7");
});

test("stream.open remains visible while ephemeral streaming stays out of the log", () => {
  const app = frontend();
  app.select("A");
  app.state.source.emit({ id: null, type: "stream.open", data: {} });
  for (let i = 0; i < 500; i++) {
    app.state.source.emit({ id: null, type: "model.delta", turnId: "turn_A", data: { text: "x" } }, "7");
  }
  assert.equal(app.state.eventCount, 0);
  assert.equal(app.state.ephemeralCount, 501);
  assert.equal(app.ui.eventList.children.length, 1);
  assert.equal(app.state.lastEventId, 0);
});

test("invalid payload ids cannot corrupt counters or the displayed cursor", () => {
  const app = frontend();
  app.select("A");
  for (const id of [undefined, "7", -1, 0, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    app.state.source.emit({ id, type: "model.started", turnId: "turn_A", data: {} }, "7");
  }
  assert.equal(app.state.eventCount, 0);
  assert.equal(app.state.ephemeralCount, 0);
  assert.equal(app.state.lastEventId, 0);
  assert.equal(app.state.bubbles.size, 0);
});
