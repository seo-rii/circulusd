import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { launchSandbox } from "../src/sandbox/launcher.ts";
import { createLiveDiagnostics, runSelectedLiveSandbox, selectLiveSandbox } from "./support/live-sandbox.ts";

test("live sandbox is not started unless explicitly requested", async () => {
  for (const environment of [{}, { CIRCULUSD_TEST_SANDBOX_LIVE: "0" }]) {
    const selection = selectLiveSandbox(environment, "linux");
    assert.equal(selection.enabled, false);
    let starts = 0;
    const skipped: string[] = [];
    assert.equal(await runSelectedLiveSandbox(selection, (reason) => skipped.push(reason), async () => { starts += 1; return {}; }, createLiveDiagnostics()), null);
    assert.equal(starts, 0);
    assert.equal(skipped.length, 1);
    assert.match(skipped[0]!, /not requested|explicitly disabled/);
  }
});

test("launcher and WSL distribution selection opt into the live gate", () => {
  assert.deepEqual(selectLiveSandbox({ CIRCULUSD_TEST_SANDBOX_LIVE: "1" }, "linux"), { enabled: true, launcher: "auto", distro: null });
  assert.deepEqual(selectLiveSandbox({ CIRCULUSD_TEST_SANDBOX_LAUNCHER: "nsjail" }, "linux"), { enabled: true, launcher: "nsjail", distro: null });
  assert.deepEqual(selectLiveSandbox({ CIRCULUSD_TEST_SANDBOX_DISTRO: "Ubuntu-24.04" }, "win32"), { enabled: true, launcher: "auto", distro: "Ubuntu-24.04" });
  for (const environment of [
    { CIRCULUSD_TEST_SANDBOX_LIVE: "yes" },
    { CIRCULUSD_TEST_SANDBOX_LAUNCHER: "not-a-launcher" },
    { CIRCULUSD_TEST_SANDBOX_LAUNCHER: "" },
    { CIRCULUSD_TEST_SANDBOX_DISTRO: "" },
    { CIRCULUSD_TEST_SANDBOX_DISTRO: "Ubuntu\nsecret" },
    { CIRCULUSD_TEST_SANDBOX_LIVE: "0", CIRCULUSD_TEST_SANDBOX_LAUNCHER: "docker" },
  ]) assert.throws(() => selectLiveSandbox(environment, "win32"), /live sandbox configuration/);
  assert.throws(() => selectLiveSandbox({ CIRCULUSD_TEST_SANDBOX_DISTRO: "Ubuntu" }, "linux"), /WSL/);
  assert.throws(() => selectLiveSandbox({ CIRCULUSD_TEST_SANDBOX_LIVE: "1" }, "darwin"), /Linux or Windows/);
});

test("selected startup failures propagate with bounded diagnostics and no secret cause", async () => {
  const selection = selectLiveSandbox({ CIRCULUSD_TEST_SANDBOX_LAUNCHER: "docker" }, "linux");
  const diagnostics = createLiveDiagnostics();
  const secret = "never-print-this-credential";
  for (let count = 0; count < 200; count += 1) diagnostics.log(`Authorization: Bearer ${secret} ${"x".repeat(20_000)}`);
  diagnostics.log(`sandbox agent exited with status 17: token=${secret}`);
  diagnostics.log(`permission denied password=${secret}`);
  let skips = 0;
  await assert.rejects(runSelectedLiveSandbox(selection, () => { skips += 1; }, async () => {
    throw new Error(`sandbox agent exited with status 17: token=${secret}`, { cause: new Error(secret) });
  }, diagnostics), (error: unknown) => {
    assert.ok(error instanceof Error);
    assert.match(error.message, /explicit live sandbox startup failed/);
    assert.match(error.message, /status 17/);
    assert.match(error.message, /permissions/);
    assert.ok(error.message.length <= 2_048);
    assert.doesNotMatch(error.stack ?? "", new RegExp(secret));
    assert.equal(error.cause, undefined);
    return true;
  });
  assert.equal(skips, 0);
  assert.ok(diagnostics.lines().length <= 8);
});

test("selected success is returned and bounded lifecycle diagnostics remain useful", async () => {
  const selection = selectLiveSandbox({ CIRCULUSD_TEST_SANDBOX_LIVE: "1" }, "linux");
  const diagnostics = createLiveDiagnostics();
  const sandbox = { close: async () => undefined };
  assert.equal(await runSelectedLiveSandbox(selection, () => assert.fail("selected success skipped"), async () => sandbox, diagnostics), sandbox);
  diagnostics.log(`rotating sandboxd sandbox_${"A".repeat(26)} gen 1 -> 2; token=not-for-output`);
  assert.deepEqual(diagnostics.lines(), [`rotating sandboxd sandbox_${"A".repeat(26)} gen 1 -> 2`]);
});

test("selected missing binaries fail before process launch and name the current build command", async () => {
  const directory = await mkdtemp(join(tmpdir(), "circulusd-live-gate-"));
  try {
    const selection = selectLiveSandbox({ CIRCULUSD_TEST_SANDBOX_LAUNCHER: "nsjail" }, "linux");
    const diagnostics = createLiveDiagnostics();
    const options = { distro: null, sandboxDirectory: directory, launcher: "nsjail" as const, python: "/usr/bin/python3", workspaceSize: "64m", log: diagnostics.log };
    await assert.rejects(launchSandbox(options), /corepack pnpm harness:sandbox:build/);
    await assert.rejects(runSelectedLiveSandbox(selection, () => assert.fail("selected failure skipped"), () => launchSandbox(options), diagnostics), /required sandbox binary is missing; run `corepack pnpm harness:sandbox:build`/);
    // A separate explicitly selected invocation must exit nonzero. Its empty
    // directory makes reaching spawn impossible even if a concurrent build
    // populates the repository's normal bin directory.
    const program = `
      import { launchSandbox } from ${JSON.stringify(new URL("../src/sandbox/launcher.ts", import.meta.url).href)};
      import { createLiveDiagnostics, runSelectedLiveSandbox, selectLiveSandbox } from ${JSON.stringify(new URL("./support/live-sandbox.ts", import.meta.url).href)};
      const diagnostics = createLiveDiagnostics();
      await runSelectedLiveSandbox(selectLiveSandbox({ CIRCULUSD_TEST_SANDBOX_LAUNCHER: "nsjail" }, "linux"),
        () => { throw new Error("unexpected skip"); },
        () => launchSandbox({ sandboxDirectory: process.argv[1], distro: null, launcher: "nsjail", python: "/usr/bin/python3", workspaceSize: "64m", log: diagnostics.log }),
        diagnostics);
    `;
    const child = spawnSync(process.execPath, ["--input-type=module", "-e", program, directory], { encoding: "utf8", timeout: 10_000, maxBuffer: 16_384 });
    assert.equal(child.error, undefined);
    assert.equal(child.status, 1, "explicitly selected missing binaries must fail the process");
    assert.match(child.stderr, /explicit live sandbox startup failed/);
    assert.doesNotMatch(child.stderr, /unexpected skip/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
