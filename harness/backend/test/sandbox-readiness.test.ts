import assert from "node:assert/strict";
import { createServer, type RequestListener } from "node:http";
import type { AddressInfo } from "node:net";
import { test, type TestContext } from "node:test";

import { waitForApi, type SandboxReady } from "../src/sandbox/launcher.ts";

async function readinessServer(t: TestContext, listener: RequestListener): Promise<SandboxReady> {
  const server = createServer(listener);
  t.after(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { host: "127.0.0.1", port: (server.address() as AddressInfo).port, token: "local-test" } as SandboxReady;
}

test("readiness deadline aborts a peer that never sends response headers", { timeout: 2_000 }, async (t) => {
  const entered = Promise.withResolvers<void>();
  const disconnected = Promise.withResolvers<void>();
  const ready = await readinessServer(t, (request) => {
    entered.resolve();
    request.on("close", () => disconnected.resolve());
  });
  const probe = waitForApi(ready, 100);
  const rejected = assert.rejects(probe, /sandbox agent API .* is unreachable/);
  await entered.promise;
  await rejected;
  await disconnected.promise;
});

test("readiness retries non-success responses until the same deadline", { timeout: 2_000 }, async (t) => {
  let requests = 0;
  const ready = await readinessServer(t, (request, response) => {
    requests += 1;
    assert.equal(request.headers.authorization, "Bearer local-test");
    response.writeHead(requests === 1 ? 503 : 200).end();
  });
  await waitForApi(ready, 1_000);
  assert.equal(requests, 2);
});

test("readiness retry delay does not exceed a short overall deadline", { timeout: 2_000 }, async (t) => {
  const ready = await readinessServer(t, (_request, response) => response.writeHead(503).end());
  const started = performance.now();
  await assert.rejects(waitForApi(ready, 20), /is unreachable/);
  assert.ok(performance.now() - started < 200, "the fixed 250 ms retry delay exceeded the deadline");
});
