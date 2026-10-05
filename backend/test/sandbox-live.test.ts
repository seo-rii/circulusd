import assert from "node:assert/strict";
import { resolve } from "node:path";
import { test } from "node:test";

import { createPythonTool } from "../src/python-tool.ts";
import { CirculusdSandboxExecutor } from "../src/sandbox/executor.ts";
import { toWslPath, type SandboxLauncherKind } from "../src/sandbox/launcher.ts";
import { executeTool, type ToolContext } from "../src/tools.ts";

// Starts the real sandbox agent inside WSL2 (or on a Linux host), which runs
// one sandboxd per session through nsjail/docker/unshare, and drives it over
// SandboxProcessService. Skipped when the sandbox cannot start (no WSL, no
// built binaries, ...) with the reason.

function toolContext(sessionId: string, toolCallId: string, signal = new AbortController().signal): ToolContext {
  return {
    sessionId,
    turnId: "turn_live",
    toolCallId,
    signal,
    effect: { requestDigest: `sha256:${"ab".repeat(32)}`, replayPolicy: "never", operation: "external-tool.call" },
  };
}

test("wsl path conversion", () => {
  assert.equal(toWslPath("C:\\Users\\me\\dev\\x.py"), "/mnt/c/Users/me/dev/x.py");
  assert.equal(toWslPath("d:/work/a b/c"), "/mnt/d/work/a b/c");
  assert.equal(toWslPath("/home/me/agent"), "/home/me/agent");
});

test("circulusd sandbox: python runs inside a per-session sandboxd with kernel isolation", { timeout: 240_000 }, async (t) => {
  const logs: string[] = [];
  let sandbox: CirculusdSandboxExecutor;
  try {
    sandbox = await CirculusdSandboxExecutor.start({
      distro: process.env.CIRCULUSD_TEST_SANDBOX_DISTRO ?? null,
      sandboxDirectory: resolve(import.meta.dirname, "../../sandbox"),
      // CIRCULUSD_TEST_SANDBOX_LAUNCHER=docker runs the same checks against the docker launcher.
      launcher: (process.env.CIRCULUSD_TEST_SANDBOX_LAUNCHER as SandboxLauncherKind | undefined) ?? "auto",
      python: "/usr/bin/python3",
      workspaceSize: "64m",
      // Tiny idempotency budget so the generation rotation is exercised below
      // (each run costs one keyed RPC, plus two more when it has stdin).
      ledgerBudget: 9,
      maxSessions: 4,
      log: (line) => logs.push(line),
      startupTimeoutMs: 120_000,
    });
  } catch (error) {
    t.skip(`sandbox unavailable: ${error instanceof Error ? error.message : String(error)}`);
    return;
  }
  try {
    const ready = sandbox.ready;
    assert.match(ready.environmentDigest, /^sha256:[0-9a-f]{64}$/);
    assert.match(ready.token, /^[0-9a-f]{64}$/);
    assert.equal(ready.ledgerBudget, 9);
    assert.ok(ready.probeMs > 0, "the agent probed the launcher at startup");
    const tools = [createPythonTool(sandbox)];
    const session = `sess_live_${Date.now().toString(36)}`;
    const context = toolContext(session, "call_1");

    // 1: spawn + stdin chunk + close-stdin = 3 keyed RPCs
    const hello = await executeTool(tools, "python", { code: "import sys\nprint('hello', sum(range(5)))\nprint(sys.stdin.read().upper())", stdin: "in" }, context);
    assert.equal(hello.isError, false, hello.text);
    assert.equal(hello.text, "hello 10\nIN");

    // 2
    const facts = await executeTool(
      tools,
      "python",
      {
        code: [
          "import os, socket, sys",
          "print('uid', os.getuid())",
          "print('cwd', os.getcwd())",
          "print('root', sorted(os.listdir('/')))",
          // A container image may carry an empty /home of its own; what must not appear is the host's.
          "print('home', sorted(os.listdir('/home')) if os.path.isdir('/home') else 'absent', 'mnt', os.path.exists('/mnt/c'))",
          "try:",
          "    open('/usr/bin/probe', 'w'); print('usr writable')",
          "except OSError as e: print('usr', e.strerror)",
          "try:",
          "    socket.create_connection(('1.1.1.1', 53), timeout=2); print('net reachable')",
          "except OSError as e: print('net', type(e).__name__)",
          "print('env', dict(os.environ))",
          "print('pids', sorted(int(p) for p in os.listdir('/proc') if p.isdigit()))",
          "import resource",
          "print('nproc', resource.getrlimit(resource.RLIMIT_NPROC)[0], 'as', resource.getrlimit(resource.RLIMIT_AS)[0])",
        ].join("\n"),
      },
      context,
    );
    assert.equal(facts.isError, false, facts.text);
    if (ready.launcher !== "docker") {
      // nsjail sets these for the jail; the unshare launcher's python wrapper sets them with prlimit.
      // (docker bounds pids and memory with cgroups instead, which rlimits do not show.)
      assert.match(facts.text, /^nproc 256 as 2147483648$/m, "per-process rlimits apply to the model's python");
    }
    assert.match(facts.text, /^uid \d+$/m);
    assert.doesNotMatch(facts.text, /^uid 0$/m, "python never runs as root");
    assert.match(facts.text, /^cwd \/workspace$/m, "the session owns the whole /workspace of its sandbox");
    assert.match(facts.text, /^home (absent|\[\]) mnt False$/m, "host filesystem is not visible");
    assert.match(facts.text, /^usr Read-only file system$/m);
    assert.match(facts.text, /^net (OSError|TimeoutError|ConnectionRefusedError)$/m, "no network");
    // sandboxd starts commands with an empty environment; only what the
    // /bin/sh wrapper and Python's locale coercion add themselves may remain.
    const environment = /^env (\{.*\})$/m.exec(facts.text)?.[1] ?? "";
    assert.ok(!/'(PATH|HOME|USER|SHELL|WSL_[A-Z_]+)'/.test(environment), `host environment leaked: ${environment}`);

    // 3, 4
    await executeTool(tools, "python", { code: "open('kept.txt', 'w').write('persisted')" }, toolContext(session, "call_2"));
    const readBack = await executeTool(tools, "python", { code: "print(open('kept.txt').read())" }, toolContext(session, "call_3"));
    assert.equal(readBack.text, "persisted", "workspace persists across calls within a session");

    // Another session gets its own sandbox: nothing of the first one is visible.
    const other = await executeTool(
      tools,
      "python",
      { code: "import os\nprint(os.path.exists('/workspace/kept.txt'), os.listdir('/workspace'), os.getcwd())" },
      toolContext(`${session}_b`, "call_4"),
    );
    assert.equal(other.isError, false, other.text);
    assert.equal(other.text, "False [] /workspace", "sessions do not share a workspace");

    // 5
    const failed = await executeTool(tools, "python", { code: "raise SystemExit(3)" }, toolContext(session, "call_5"));
    assert.equal(failed.isError, true);
    assert.match(failed.text, /^exit code 3/);

    // 6
    const started = Date.now();
    const timedOut = await sandbox.run({ code: "import time\nprint('tick', flush=True)\ntime.sleep(60)", stdin: "", timeoutMs: 2_000, context: toolContext(session, "call_6") });
    assert.equal(timedOut.isError, true);
    assert.match(timedOut.text, /timed out after 2000 ms/);
    assert.match(timedOut.text, /tick/);
    assert.ok(Date.now() - started < 30_000, "deadline is enforced by sandboxd");

    // 7: a plain run still works after a timeout, and reaches the budget of 9.
    const sanity = await sandbox.run({ code: "print(1)", stdin: "", timeoutMs: 5_000, context: toolContext(session, "call_7") });
    assert.equal(sanity.isError, false, sanity.text);
    assert.equal(sanity.text, "1");

    // Budget spent: the next run relaunches sandboxd as generation 2 with a
    // fresh /workspace, and says so.
    const rotated = await executeTool(tools, "python", { code: "import os\nprint(os.path.exists('kept.txt'))" }, toolContext(session, "call_8"));
    assert.equal(rotated.isError, false, rotated.text);
    assert.match(rotated.text, /^note: .*relaunched \(generation 2; idempotency budget of 9 keyed RPCs used\)/);
    assert.match(rotated.text, /\nFalse$/);
    assert.ok(logs.some((line) => /rotating sandboxd sandbox_[A-Z2-7]{26} gen 1 -> 2/.test(line)), logs.join("\n"));

    // Aborting the turn cancels the run instead of waiting for the timeout.
    const controller = new AbortController();
    const abortStarted = Date.now();
    setTimeout(() => controller.abort(), 1_500);
    const aborted = await sandbox.run({
      code: "import time\nprint('tick', flush=True)\ntime.sleep(60)",
      stdin: "",
      timeoutMs: 60_000,
      context: toolContext(session, "call_9", controller.signal),
    });
    assert.equal(aborted.isError, true);
    assert.match(aborted.text, /cancelled/);
    assert.ok(Date.now() - abortStarted < 15_000, "abort does not wait for the process deadline");

    // A script that exits without draining a large stdin (more than one 64 KiB
    // chunk) still yields its output: the failed later write is not an error.
    const partial = await executeTool(
      tools,
      "python",
      { code: "import sys\nprint(sys.stdin.readline().strip())", stdin: `first\n${"x".repeat(200_000)}` },
      toolContext(`${session}_c`, "call_10"),
    );
    assert.equal(partial.isError, false, partial.text);
    assert.equal(partial.text, "first");
    // Whether a later chunk actually fails depends on how fast the interpreter
    // exits (it does on nsjail, rarely on docker); either way the run succeeds.

    await sandbox.closeSession(`${session}_b`);
    await sandbox.closeSession(`${session}_c`);
    await sandbox.closeSession("never-ran"); // 404 from the agent is not an error
  } finally {
    await sandbox.close();
  }
});
