import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { test } from "node:test";

import {
  HostPythonExecutor,
  PYTHON_CODE_LIMIT_BYTES,
  PYTHON_STDIN_LIMIT_BYTES,
  PYTHON_TIMEOUT_MS,
  createPythonTool,
  resolvePythonInterpreter,
  sessionWorkspace,
  type PythonExecutor,
  type PythonRunRequest,
} from "../src/python-tool.ts";
import { CirculusdSandboxExecutor } from "../src/sandbox/executor.ts";
import type { SandboxProcess, SandboxReady } from "../src/sandbox/launcher.ts";
import { executeTool, type ToolContext } from "../src/tools.ts";

const interpreter = resolvePythonInterpreter();
const pythonAvailable = { skip: interpreter === null ? "no Python 3 interpreter on this host" : false };

function context(signal = new AbortController().signal): ToolContext {
  return {
    sessionId: `python_repair_${randomUUID().replaceAll("-", "_")}`,
    turnId: "turn_repair",
    toolCallId: "call_repair",
    signal,
    effect: { requestDigest: `sha256:${"ab".repeat(32)}`, replayPolicy: "never", operation: "external-tool.call" },
  };
}

function counted(executor: PythonExecutor): { readonly executor: PythonExecutor; readonly requests: PythonRunRequest[] } {
  const requests: PythonRunRequest[] = [];
  return {
    requests,
    executor: {
      kind: executor.kind,
      describe: () => executor.describe(),
      run: (request) => {
        requests.push(request);
        return executor.run(request);
      },
      closeSession: (sessionId) => executor.closeSession(sessionId),
      close: () => executor.close(),
    },
  };
}

async function waitForFile(path: string): Promise<void> {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    try {
      await stat(path);
      return;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`Python did not reach the expected file write: ${path}`);
}

test("python repair does not replay a valid program after a dynamic compile failure", pythonAvailable, async (t) => {
  const host = new HostPythonExecutor(interpreter!);
  for (const suffix of ["", String.raw` # repairable\n# tail`]) {
    await t.test(suffix === "" ? "unchanged repair candidate" : "changed comment candidate", async () => {
      const call = context();
      const observed = counted(host);
      try {
        const result = await executeTool([createPythonTool(observed.executor)], "python", {
          code: String.raw`open("counter.txt", "a").write("x"); exec(r"x = 1\ny = 2")` + suffix,
        }, call);
        assert.equal(result.isError, true);
        assert.match(result.text, /line continuation character/);
        assert.doesNotMatch(result.text, /note: the code arrived/);
        assert.equal(observed.requests.length, 1);
        assert.equal(await readFile(join(sessionWorkspace(call.sessionId), "counter.txt"), "utf8"), "x");
      } finally {
        await host.closeSession(call.sessionId);
      }
    });
  }
});

test("python repairs top-level escaped newlines before its only execution and preserves strings and stdin", pythonAvailable, async () => {
  const host = new HostPythonExecutor(interpreter!);
  const observed = counted(host);
  const call = context();
  try {
    const result = await executeTool([createPythonTool(observed.executor)], "python", {
      code: String.raw`from __future__ import annotations\nimport sys\nopen("counter.txt", "a").write("x")\nprint("a\nb")\nprint('a\'b')\nprint("""multi\nline""")\nprint(__name__, "__circulusd_prepare_python" in globals())\nprint(sys.stdin.read())`,
      stdin: "input 한글",
    }, call);
    assert.equal(result.isError, false, result.text);
    assert.match(result.text, /^note: the code arrived/);
    assert.match(result.text, /\na\nb\na'b\nmulti\nline\n__main__ False\ninput 한글$/);
    assert.equal(await readFile(join(sessionWorkspace(call.sessionId), "counter.txt"), "utf8"), "x");
    assert.equal(observed.requests.length, 1);
    assert.equal(observed.requests[0]?.context, call);
    assert.equal(observed.requests[0]?.stdin, "input 한글");
    assert.equal(observed.requests[0]?.timeoutMs, PYTHON_TIMEOUT_MS);
  } finally {
    await host.closeSession(call.sessionId);
  }
});

test("python keeps a valid source unchanged even when its comment could be repaired", pythonAvailable, async () => {
  const host = new HostPythonExecutor(interpreter!);
  const call = context();
  try {
    const result = await executeTool([createPythonTool(host)], "python", {
      code: String.raw`print("original") # note\nopen("counter.txt", "a").write("x")`,
    }, call);
    assert.equal(result.isError, false, result.text);
    assert.equal(result.text, "original");
    await assert.rejects(readFile(join(sessionWorkspace(call.sessionId), "counter.txt")), { code: "ENOENT" });
  } finally {
    await host.closeSession(call.sessionId);
  }
});

test("python executes neither source when the original and repair candidate both fail compilation", pythonAvailable, async () => {
  const host = new HostPythonExecutor(interpreter!);
  const observed = counted(host);
  const call = context();
  try {
    const result = await executeTool([createPythonTool(observed.executor)], "python", {
      code: String.raw`open("counter.txt", "a").write("x")\nif:`,
    }, call);
    assert.equal(result.isError, true);
    assert.match(result.text, /SyntaxError/);
    assert.doesNotMatch(result.text, /note: the code arrived/);
    assert.equal(observed.requests.length, 1);
    await assert.rejects(readFile(join(sessionWorkspace(call.sessionId), "counter.txt")), { code: "ENOENT" });
  } finally {
    await host.closeSession(call.sessionId);
  }
});

test("python accepts its complete 64 KiB source budget within the sandbox's 100 KiB argv limit", pythonAvailable, async () => {
  const host = new HostPythonExecutor(interpreter!);
  const observed = counted(host);
  const call = context();
  const prefix = String.raw`open("counter.txt", "a").write("x")\r\nprint("한글")\n#`;
  const code = prefix + "a".repeat(PYTHON_CODE_LIMIT_BYTES - Buffer.byteLength(prefix, "utf8"));
  try {
    assert.equal(Buffer.byteLength(code, "utf8"), PYTHON_CODE_LIMIT_BYTES);
    const result = await executeTool([createPythonTool(observed.executor)], "python", { code }, call);
    assert.equal(result.isError, false, result.text);
    assert.match(result.text, /\n한글$/);
    assert.equal(observed.requests.length, 1);
    assert.ok(Buffer.byteLength(observed.requests[0]!.code, "utf8") < 100 * 1024);
    assert.equal(await readFile(join(sessionWorkspace(call.sessionId), "counter.txt"), "utf8"), "x");
  } finally {
    await host.closeSession(call.sessionId);
  }
});

test("python validates source and stdin budgets and does not dispatch an already cancelled call", async () => {
  const requests: PythonRunRequest[] = [];
  const executor: PythonExecutor = {
    kind: "circulusd-sandbox",
    describe: () => ({}),
    run: async (request) => {
      requests.push(request);
      return { text: "unexpected dispatch", isError: false };
    },
    closeSession: async () => undefined,
    close: async () => undefined,
  };
  const tools = [createPythonTool(executor)];
  const tooMuchCode = await executeTool(tools, "python", { code: "x".repeat(PYTHON_CODE_LIMIT_BYTES + 1) }, context());
  assert.equal(tooMuchCode.isError, true);
  assert.match(tooMuchCode.text, /code exceeds/);
  const tooMuchInput = await executeTool(tools, "python", { code: "pass", stdin: "x".repeat(PYTHON_STDIN_LIMIT_BYTES + 1) }, context());
  assert.equal(tooMuchInput.isError, true);
  assert.match(tooMuchInput.text, /stdin exceeds/);
  const controller = new AbortController();
  controller.abort();
  const cancelled = await executeTool(tools, "python", { code: String.raw`print(1)\nprint(2)` }, context(controller.signal));
  assert.equal(cancelled.isError, true);
  assert.match(cancelled.text, /cancelled/);
  assert.equal(requests.length, 0);
});

test("python cancellation stops the sole repaired execution without a retry", pythonAvailable, async () => {
  const host = new HostPythonExecutor(interpreter!);
  const observed = counted(host);
  const controller = new AbortController();
  const call = context(controller.signal);
  try {
    const pending = executeTool([createPythonTool(observed.executor)], "python", {
      code: String.raw`import time\nopen("started.txt", "w").write("ready")\ntime.sleep(30)\nopen("counter.txt", "a").write("x")`,
    }, call);
    await waitForFile(join(sessionWorkspace(call.sessionId), "started.txt"));
    controller.abort();
    const result = await pending;
    assert.equal(result.isError, true);
    assert.match(result.text, /cancelled/);
    assert.equal(observed.requests.length, 1);
    await assert.rejects(readFile(join(sessionWorkspace(call.sessionId), "counter.txt")), { code: "ENOENT" });
  } finally {
    controller.abort();
    await host.closeSession(call.sessionId);
  }
});

interface AgentRequest {
  readonly sessionId: string;
  readonly turnId: string;
  readonly toolCallId: string;
  readonly requestDigest: string;
  readonly replayPolicy: "never";
  readonly code: string;
  readonly stdin: string;
  readonly timeoutMs: number;
}

/** Local adapter fixture, not a real sandboxd: run its received source in Python. */
async function fakePythonAgent(host: HostPythonExecutor): Promise<{
  readonly process: SandboxProcess;
  readonly requests: AgentRequest[];
  readonly server: Server;
}> {
  const requests: AgentRequest[] = [];
  const running = new Set<Promise<void>>();
  const server = createServer((request, response) => {
    const controller = new AbortController();
    response.once("close", () => controller.abort());
    const handling = (async () => {
      try {
        const chunks: Buffer[] = [];
        for await (const chunk of request) chunks.push(Buffer.from(chunk));
        const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as AgentRequest;
        assert.equal(request.url, "/v1/run");
        assert.equal(request.method, "POST");
        assert.equal(request.headers.authorization, "Bearer test-python-repair-agent");
        requests.push(body);
        const result = await host.run({
          code: body.code, stdin: body.stdin, timeoutMs: body.timeoutMs,
          context: {
            sessionId: body.sessionId, turnId: body.turnId, toolCallId: body.toolCallId,
            signal: controller.signal,
            effect: { requestDigest: body.requestDigest, replayPolicy: body.replayPolicy, operation: "external-tool.call" },
          },
        });
        if (!response.destroyed) response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({
          stdout: result.isError ? "" : result.text,
          stderr: result.isError ? result.text : "",
          stdoutTruncated: false, stderrTruncated: false,
          exitCode: result.isError ? 1 : 0, timedOut: false, cancelled: controller.signal.aborted,
          outputTruncated: false, signal: "", sandboxId: "fixture", generation: 1,
        }));
      } catch (error) {
        if (!response.destroyed) response.writeHead(500).end(String(error));
      }
    })();
    running.add(handling);
    void handling.finally(() => running.delete(handling));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  let exitStatus: number | undefined;
  let finishExit: (status: number) => void = () => undefined;
  const exited = new Promise<number>((resolve) => { finishExit = resolve; });
  const process: SandboxProcess = {
    ready: {
      host: "127.0.0.1", port: (server.address() as AddressInfo).port, token: "test-python-repair-agent",
    } as SandboxReady,
    exited,
    exitStatus: () => exitStatus,
    close: async () => {
      server.closeAllConnections();
      await Promise.all(running);
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
      exitStatus = 0;
      finishExit(0);
    },
  };
  return { process, requests, server };
}

test("sandbox executor sends one fenced RPC for each original or repaired body and cancels it", pythonAvailable, async () => {
  const host = new HostPythonExecutor(interpreter!);
  const agent = await fakePythonAgent(host);
  const sandbox = await CirculusdSandboxExecutor.start({
    distro: null, sandboxDirectory: "unused-fixture", launcher: "auto", python: interpreter!.executable,
    workspaceSize: "64m", log: () => undefined, launch: async () => agent.process,
  });
  const sessions: string[] = [];
  const controller = new AbortController();
  try {
    for (const code of [
      String.raw`open("counter.txt", "a").write("x"); exec(r"x = 1\ny = 2") # comment\n# tail`,
      String.raw`open("counter.txt", "a").write("x")\nprint("repaired")`,
    ]) {
      const call = context();
      sessions.push(call.sessionId);
      const before = agent.requests.length;
      const result = await executeTool([createPythonTool(sandbox)], "python", { code, stdin: "kept input" }, call);
      assert.equal(agent.requests.length, before + 1);
      const wire = agent.requests.at(-1)!;
      assert.equal(wire.sessionId, call.sessionId);
      assert.equal(wire.turnId, call.turnId);
      assert.equal(wire.toolCallId, call.toolCallId);
      assert.equal(wire.requestDigest, call.effect.requestDigest);
      assert.equal(wire.replayPolicy, "never");
      assert.equal(wire.timeoutMs, PYTHON_TIMEOUT_MS);
      assert.equal(wire.stdin, "kept input");
      assert.ok(Buffer.byteLength(wire.code, "utf8") < 100 * 1024);
      assert.equal(await readFile(join(sessionWorkspace(call.sessionId), "counter.txt"), "utf8"), "x");
      assert.equal(result.isError, code.includes("exec("));
      if (result.isError) assert.doesNotMatch(result.text, /note: the code arrived/);
      else assert.match(result.text, /^note: the code arrived/);
    }
    const call = context(controller.signal);
    sessions.push(call.sessionId);
    const pending = executeTool([createPythonTool(sandbox)], "python", {
      code: String.raw`import time\nopen("started.txt", "w").write("ready")\ntime.sleep(30)\nopen("counter.txt", "a").write("x")`,
    }, call);
    await waitForFile(join(sessionWorkspace(call.sessionId), "started.txt"));
    controller.abort();
    const result = await pending;
    assert.equal(result.isError, true);
    assert.match(result.text, /cancelled/);
    assert.equal(agent.requests.length, 3);
  } finally {
    controller.abort();
    await sandbox.close();
    for (const sessionId of sessions) await host.closeSession(sessionId);
  }
});

test("host python workspaces live in a private per-process directory", async () => {
  const root = dirname(sessionWorkspace("private_root_probe"));
  assert.equal(dirname(root), tmpdir());
  assert.match(basename(root), /^circulusd-test-workspaces-/);
  assert.equal(dirname(sessionWorkspace("another_session")), root);
  const info = await stat(root);
  assert.ok(info.isDirectory());
  if (process.platform !== "win32") {
    assert.equal(info.mode & 0o777, 0o700);
    assert.equal(info.uid, process.getuid?.());
  }
});
