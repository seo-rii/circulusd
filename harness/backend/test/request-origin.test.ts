import assert from "node:assert/strict";
import { request } from "node:http";
import { test } from "node:test";

import { MockModelProvider } from "../src/providers/mock.ts";
import { createApp, type App, type AppOptions } from "../src/server.ts";
import { BASE_TOOL_DEFINITIONS } from "../src/tools.ts";

interface Sent {
  readonly method?: string;
  readonly path: string;
  readonly headers?: Record<string, string>;
  readonly body?: string;
}

async function withApp(
  run: (app: App, port: number) => Promise<void>,
  options: Partial<AppOptions> = {},
): Promise<void> {
  const app = createApp({
    provider: new MockModelProvider({ deltaDelayMs: 0 }),
    tools: BASE_TOOL_DEFINITIONS,
    frontendDirectory: null,
    historyInjection: false,
    log: () => undefined,
    ...options,
  });
  const { port } = await app.listen("127.0.0.1", 0);
  try {
    await run(app, port);
  } finally {
    await app.close();
  }
}

/** Sends one request with exactly these headers (node:http, so Host and Origin can be set freely). */
function send(port: number, sent: Sent): Promise<{ readonly status: number; readonly code: string | null }> {
  return new Promise((resolveSend, rejectSend) => {
    const client = request({
      host: "127.0.0.1",
      port,
      method: sent.method ?? "GET",
      path: sent.path,
      headers: { host: `127.0.0.1:${port}`, ...sent.headers },
    }, (response) => {
      let text = "";
      response.setEncoding("utf8");
      response.on("data", (chunk: string) => { text += chunk; });
      response.on("error", rejectSend);
      response.on("end", () => {
        let code: string | null = null;
        try {
          code = (JSON.parse(text) as { error?: { code?: string } }).error?.code ?? null;
        } catch {
          code = null;
        }
        resolveSend({ status: response.statusCode ?? 0, code });
      });
    });
    client.on("error", rejectSend);
    client.end(sent.body);
  });
}

const json = { "content-type": "application/json" };

test("HTTP API: a Host outside the loopback allowlist is rejected (DNS rebinding)", async () => {
  await withApp(async (app, port) => {
    for (const host of [`rebind.example:${port}`, "localhost:1", "127.0.0.1", `localhost.:${port}`, `user@127.0.0.1:${port}`]) {
      assert.deepEqual(await send(port, { path: "/v1/capabilities", headers: { host } }), { status: 403, code: "HOST_NOT_ALLOWED" }, host);
      assert.deepEqual(
        await send(port, { method: "POST", path: "/v1/sessions", headers: { ...json, host }, body: "{}" }),
        { status: 403, code: "HOST_NOT_ALLOWED" },
        host,
      );
    }
    assert.equal(app.store.list().length, 0, "no session was created for a foreign Host");
    for (const host of [`localhost:${port}`, `127.0.0.1:${port}`, `[::1]:${port}`, `LocalHost:${port}`]) {
      assert.equal((await send(port, { path: "/v1/capabilities", headers: { host } })).status, 200, host);
    }
  });
});

test("HTTP API: configured extra hosts are matched exactly", async () => {
  await withApp(async (_app, port) => {
    assert.equal((await send(port, { path: "/v1/capabilities", headers: { host: "devbox.lan:8443" } })).status, 200);
    assert.equal((await send(port, { path: "/v1/capabilities", headers: { host: "DevBox.LAN:8443" } })).status, 200);
    assert.equal((await send(port, { path: "/v1/capabilities", headers: { host: `devbox.lan:${port}` } })).status, 403);
    assert.equal((await send(port, { path: "/v1/capabilities", headers: { host: "devbox.lan" } })).status, 403);
  }, { allowedHosts: ["devbox.lan:8443"] });
});

test("HTTP API: state-changing requests from another origin are rejected (CSRF)", async () => {
  await withApp(async (app, port) => {
    for (const origin of ["http://attacker.example", "null", `http://localhost:${port}`, `https://attacker.example:${port}`]) {
      assert.deepEqual(
        await send(port, { method: "POST", path: "/v1/sessions", headers: { ...json, origin }, body: "{}" }),
        { status: 403, code: "ORIGIN_NOT_ALLOWED" },
        origin,
      );
    }
    assert.equal(app.store.list().length, 0, "no session was created cross-origin");

    const sameOrigin = { ...json, origin: `http://127.0.0.1:${port}` };
    assert.equal((await send(port, { method: "POST", path: "/v1/sessions", headers: sameOrigin, body: "{}" })).status, 201);
    const session = app.store.list()[0];
    assert.ok(session);
    const crossOrigin = { ...json, origin: "http://attacker.example" };
    assert.deepEqual(
      await send(port, {
        method: "POST",
        path: `/v1/sessions/${session.id}/turns`,
        headers: crossOrigin,
        body: JSON.stringify({ prompt: "python print(1)" }),
      }),
      { status: 403, code: "ORIGIN_NOT_ALLOWED" },
    );
    assert.equal(session.turns.length, 0, "no turn was started cross-origin");
    assert.deepEqual(
      await send(port, { method: "DELETE", path: `/v1/sessions/${session.id}`, headers: { origin: "http://attacker.example" } }),
      { status: 403, code: "ORIGIN_NOT_ALLOWED" },
    );
    assert.equal(app.store.get(session.id), session, "the session survived a cross-origin DELETE");
    // Reads carry no CORS headers, so another origin cannot read them anyway.
    assert.equal((await send(port, { path: `/v1/sessions/${session.id}`, headers: crossOrigin })).status, 200);
  });
});

test("HTTP API: request bodies must be declared as application/json", async () => {
  await withApp(async (app, port) => {
    for (const contentType of ["text/plain;charset=UTF-8", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x", null]) {
      const headers: Record<string, string> = contentType === null ? {} : { "content-type": contentType };
      assert.deepEqual(
        await send(port, { method: "POST", path: "/v1/sessions", headers, body: "{}" }),
        { status: 415, code: "UNSUPPORTED_MEDIA_TYPE" },
        String(contentType),
      );
    }
    assert.equal(app.store.list().length, 0, "no session was created from a non-JSON body");

    for (const contentType of ["application/json", "Application/JSON; charset=utf-8"]) {
      assert.equal(
        (await send(port, { method: "POST", path: "/v1/sessions", headers: { "content-type": contentType }, body: "{}" })).status,
        201,
        contentType,
      );
    }
    // A request without a body has nothing to declare.
    assert.equal((await send(port, { method: "POST", path: "/v1/sessions", headers: { "content-length": "0" } })).status, 201);

    const session = app.store.list()[0];
    assert.ok(session);
    assert.deepEqual(
      await send(port, {
        method: "POST",
        path: `/v1/sessions/${session.id}/turns`,
        headers: { "content-type": "text/plain" },
        body: JSON.stringify({ prompt: "python print(1)" }),
      }),
      { status: 415, code: "UNSUPPORTED_MEDIA_TYPE" },
    );
    assert.equal(session.turns.length, 0, "no turn was started from a non-JSON body");
  });
});
