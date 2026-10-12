import assert from "node:assert/strict";
import { once } from "node:events";
import { get, type ServerResponse } from "node:http";
import { test } from "node:test";

import { MockModelProvider } from "../src/providers/mock.ts";
import { createApp, type App } from "../src/server.ts";
import type { Session, SessionEvent } from "../src/session.ts";

function testApp(log: (line: string) => void = () => undefined): App {
  return createApp({
    provider: new MockModelProvider({ deltaDelayMs: 0 }),
    tools: [],
    frontendDirectory: null,
    historyInjection: false,
    log,
  });
}

function seed(app: App, count = 100): Session {
  const session = app.store.create(app.runtimeRevisionDigest);
  assert.ok(session);
  for (let index = 1; index <= count; index += 1) {
    session.commit("turn.accepted", `turn_${index}`, { prompt: "p".repeat(60_000) });
  }
  return session;
}

interface StreamResult {
  readonly events: SessionEvent[];
  readonly error: Error | null;
}

function readStream(
  port: number,
  session: Session,
  done: (events: readonly SessionEvent[]) => boolean,
  afterEventId = 0,
): Promise<StreamResult> {
  return new Promise((resolve, reject) => {
    let completed = false;
    let buffer = "";
    const events: SessionEvent[] = [];
    const request = get({
      hostname: "127.0.0.1",
      port,
      path: `/v1/sessions/${session.id}/events`,
      headers: { "last-event-id": String(afterEventId) },
    }, (response) => {
      assert.equal(response.statusCode, 200);
      response.setEncoding("utf8");
      response.on("data", (chunk: string) => {
        buffer += chunk;
        let end: number;
        while ((end = buffer.indexOf("\n\n")) !== -1) {
          const frame = buffer.slice(0, end);
          buffer = buffer.slice(end + 2);
          const data = frame.split("\n").find((line) => line.startsWith("data: "));
          if (data === undefined) continue;
          events.push(JSON.parse(data.slice(6)) as SessionEvent);
          if (done(events)) {
            finish(null);
            response.destroy();
            return;
          }
        }
      });
      response.on("error", (error) => finish(error));
      response.on("end", () => finish(null));
      response.on("close", () => finish(null));
    });
    request.on("error", (error) => finish(error));
    const timeout = setTimeout(() => {
      request.destroy();
      reject(new Error("SSE test timed out"));
    }, 5_000);
    function finish(error: Error | null): void {
      if (completed) return;
      completed = true;
      clearTimeout(timeout);
      request.destroy();
      resolve({ events, error });
    }
  });
}

function durableIds(events: readonly SessionEvent[]): number[] {
  return events.flatMap((event) => event.id === null ? [] : [event.id]);
}

test("SSE replays 100 large retained events on one reading HTTP connection", { timeout: 10_000 }, async () => {
  const logs: string[] = [];
  const app = testApp((line) => logs.push(line));
  const session = seed(app);
  const { port } = await app.listen("127.0.0.1", 0);
  try {
    const result = await readStream(port, session, (events) => durableIds(events).length === 100);
    assert.equal(result.error, null);
    assert.deepEqual(durableIds(result.events), Array.from({ length: 100 }, (_, index) => index + 1));
    assert.equal(logs.some((line) => line.includes("client is not reading")), false);
    assert.equal(result.events[0]?.type, "stream.open");
  } finally {
    await app.close();
  }
});

test("SSE resumes only retained events after Last-Event-ID", { timeout: 10_000 }, async () => {
  const app = testApp();
  const session = seed(app);
  const { port } = await app.listen("127.0.0.1", 0);
  try {
    const result = await readStream(port, session, (events) => durableIds(events).length === 35, 65);
    assert.equal(result.error, null);
    assert.deepEqual(durableIds(result.events), Array.from({ length: 35 }, (_, index) => index + 66));
    assert.deepEqual(result.events[0]?.data, { resumeFrom: 65, firstEventId: 1, lastEventId: 100 });
  } finally {
    await app.close();
  }
});

test("SSE delivers durable and ephemeral live events once after replay blocked on real HTTP backpressure", { timeout: 10_000 }, async () => {
  const app = testApp();
  const session = seed(app);
  let injected = false;
  app.server.prependListener("request", (_request, response) => {
    const originalWrite = response.write;
    response.write = function (this: ServerResponse, chunk: unknown, ...args: unknown[]): boolean {
      const accepted = Reflect.apply(originalWrite, this, [chunk, ...args]) as boolean;
      if (!accepted && !injected && String(chunk).startsWith("id: ")) {
        injected = true;
        assert.equal(response.writableNeedDrain, true);
        session.commit("turn.completed", null, { result: "live-durable-101" });
        session.emit("model.delta", null, { text: "live-ephemeral" });
        session.commit("turn.completed", null, { result: "live-durable-102" });
      }
      return accepted;
    };
  });
  const { port } = await app.listen("127.0.0.1", 0);
  try {
    const result = await readStream(port, session, (events) => events.at(-1)?.id === 102);
    assert.equal(result.error, null);
    assert.equal(injected, true, "test must cross actual write(false)");
    assert.deepEqual(durableIds(result.events), Array.from({ length: 102 }, (_, index) => index + 1));
    assert.deepEqual(result.events.slice(-3).map((event) => [event.type, event.id]), [
      ["turn.completed", 101], ["model.delta", null], ["turn.completed", 102],
    ]);
    assert.deepEqual(result.events[0]?.data, { resumeFrom: 0, firstEventId: 1, lastEventId: 100 });
  } finally {
    await app.close();
  }
});

/** Make one accepted replay write stay backpressured until close, using a real HTTP response. */
function stallReplay(app: App): Promise<ServerResponse> {
  return new Promise((resolveBlocked) => {
    app.server.prependListener("request", (_request, response) => {
      const originalWrite = response.write;
      const originalEmit = response.emit;
      let stalled = false;
      response.emit = function (this: ServerResponse, type: string | symbol, ...args: unknown[]): boolean {
        if (stalled && type === "drain") return false;
        return Reflect.apply(originalEmit, this, [type, ...args]) as boolean;
      };
      response.write = function (this: ServerResponse, chunk: unknown, ...args: unknown[]): boolean {
        const accepted = Reflect.apply(originalWrite, this, [chunk, ...args]) as boolean;
        if (!stalled && String(chunk).startsWith("id: ")) {
          stalled = true;
          resolveBlocked(response);
          return false;
        }
        return accepted;
      };
    });
  });
}

function countSubscriptions(session: Session): () => number {
  const original = session.captureReplaySubscription.bind(session);
  let active = 0;
  session.captureReplaySubscription = (listener, afterEventId) => {
    const captured = original(listener, afterEventId);
    active += 1;
    let subscribed = true;
    return {
      ...captured,
      unsubscribe: () => {
        if (!subscribed) return;
        subscribed = false;
        active -= 1;
        captured.unsubscribe();
      },
    };
  };
  return () => active;
}

test("SSE disconnect releases a pending drain, heartbeat and live subscription", { timeout: 10_000 }, async (context) => {
  const app = testApp();
  const session = seed(app);
  const activeSubscriptions = countSubscriptions(session);
  const blocked = stallReplay(app);
  const clearHeartbeat = context.mock.method(globalThis, "clearInterval");
  const { port } = await app.listen("127.0.0.1", 0);
  const request = get(`http://127.0.0.1:${port}/v1/sessions/${session.id}/events`);
  request.on("error", () => undefined);
  try {
    const response = await blocked;
    assert.equal(activeSubscriptions(), 1);
    assert.equal(response.listenerCount("drain"), 1);
    const closed = once(response, "close");
    request.destroy();
    await closed;
    assert.equal(activeSubscriptions(), 0);
    assert.equal(response.listenerCount("drain"), 0);
    assert.equal(clearHeartbeat.mock.callCount(), 1);
    session.emit("model.delta", null, { text: "after-close" });
    assert.equal(activeSubscriptions(), 0);
  } finally {
    request.destroy();
    await app.close();
  }
});

test("SSE still drops a stalled writable when live events exceed the 4 MiB budget", { timeout: 10_000 }, async () => {
  const logs: string[] = [];
  const app = testApp((line) => logs.push(line));
  const session = seed(app);
  const activeSubscriptions = countSubscriptions(session);
  const blocked = stallReplay(app);
  const { port } = await app.listen("127.0.0.1", 0);
  const request = get(`http://127.0.0.1:${port}/v1/sessions/${session.id}/events`, (response) => {
    response.on("error", () => undefined);
    response.resume();
  });
  request.on("error", () => undefined);
  try {
    const response = await blocked;
    assert.equal(response.listenerCount("drain"), 1);
    const closed = once(response, "close");
    for (let index = 0; index < 80; index += 1) {
      session.emit("model.delta", null, { text: "p".repeat(60_000) });
    }
    await closed;
    assert.equal(response.destroyed, true);
    assert.equal(activeSubscriptions(), 0);
    assert.equal(response.listenerCount("drain"), 0);
    const drops = logs.filter((line) => line.includes("client is not reading"));
    assert.equal(drops.length, 1);
    const matched = /\((\d+) bytes pending\)/.exec(drops[0] ?? "");
    assert.ok(matched);
    assert.ok(Number(matched[1]) > 4 * 1024 * 1024);
    assert.ok(Number(matched[1]) < 4 * 1024 * 1024 + 64 * 1024);
  } finally {
    request.destroy();
    await app.close();
  }
});
