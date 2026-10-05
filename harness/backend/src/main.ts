import { resolve } from "node:path";

import { resolveModelProvider } from "./providers/index.ts";
import {
  HostPythonExecutor,
  PYTHON_TIMEOUT_MS,
  createPythonTool,
  resolvePythonInterpreter,
  type PythonExecutor,
} from "./python-tool.ts";
import { CirculusdSandboxExecutor } from "./sandbox/executor.ts";
import { SANDBOX_LAUNCHER_KINDS, type SandboxLauncherKind } from "./sandbox/launcher.ts";
import { createApp } from "./server.ts";
import { DEFAULT_SESSION_LIMIT } from "./session.ts";
import { createToolDefinitions } from "./tools.ts";

const host = process.env.CIRCULUSD_TEST_HOST ?? "127.0.0.1";
const port = Number(process.env.CIRCULUSD_TEST_PORT ?? "8090");
if (!Number.isInteger(port) || port < 0 || port > 65_535) {
  console.error(`CIRCULUSD_TEST_PORT must be an integer in 0..65535, got ${process.env.CIRCULUSD_TEST_PORT}`);
  process.exit(2);
}
const historyInjection = (process.env.CIRCULUSD_TEST_HISTORY ?? "1") !== "0";
const sandboxMode = process.env.CIRCULUSD_TEST_SANDBOX ?? "circulusd";
if (!["circulusd", "host", "off"].includes(sandboxMode)) {
  console.error(`CIRCULUSD_TEST_SANDBOX must be circulusd, host, or off, got ${sandboxMode}`);
  process.exit(2);
}
const launcher = (process.env.CIRCULUSD_TEST_SANDBOX_LAUNCHER ?? "auto") as SandboxLauncherKind;
if (!SANDBOX_LAUNCHER_KINDS.includes(launcher)) {
  console.error(`CIRCULUSD_TEST_SANDBOX_LAUNCHER must be one of ${SANDBOX_LAUNCHER_KINDS.join(", ")}, got ${launcher}`);
  process.exit(2);
}
const maxSessions = optionalPositiveInteger("CIRCULUSD_TEST_SANDBOX_MAX_SESSIONS");
const maxChatSessions = optionalPositiveInteger("CIRCULUSD_TEST_MAX_SESSIONS");
const sandboxStartupTimeoutMs = optionalPositiveInteger("CIRCULUSD_TEST_SANDBOX_STARTUP_TIMEOUT_MS");
const modelStallTimeoutMs = optionalPositiveInteger("CIRCULUSD_TEST_MODEL_STALL_TIMEOUT_MS");
const sessionIdle = process.env.CIRCULUSD_TEST_SANDBOX_SESSION_IDLE?.trim();
if (sessionIdle !== undefined && sessionIdle !== "" && !/^(0|\d+(\.\d+)?(ns|us|µs|ms|s|m|h))+$/.test(sessionIdle)) {
  console.error(`CIRCULUSD_TEST_SANDBOX_SESSION_IDLE must be a Go duration such as 30m, 1h, or 0, got ${sessionIdle}`);
  process.exit(2);
}

let provider;
try {
  provider = await resolveModelProvider(process.env.CIRCULUSD_TEST_MODEL, {
    log: (line) => console.warn(line),
    ...(modelStallTimeoutMs === undefined ? {} : { stallTimeoutMs: modelStallTimeoutMs }),
  });
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(2);
}

const log = (line: string): void => console.log(`[${new Date().toISOString()}] ${line}`);

// The python tool never falls back silently: circulusd mode either starts
// the sandbox agent (which proves the launcher works with a probe run) or
// leaves the tool out, and host mode must be chosen explicitly.
let python: PythonExecutor | null = null;
const pythonNotes: string[] = [];
if (sandboxMode === "circulusd") {
  try {
    python = await CirculusdSandboxExecutor.start({
      distro: process.env.CIRCULUSD_TEST_SANDBOX_DISTRO ?? null,
      sandboxDirectory: resolve(import.meta.dirname, "../../sandbox"),
      launcher,
      python: process.env.CIRCULUSD_TEST_SANDBOX_PYTHON ?? "/usr/bin/python3",
      image: process.env.CIRCULUSD_TEST_SANDBOX_IMAGE ?? null,
      workspaceSize: process.env.CIRCULUSD_TEST_SANDBOX_WORKSPACE_SIZE ?? "256m",
      ...(maxSessions === undefined ? {} : { maxSessions }),
      ...(sessionIdle === undefined || sessionIdle === "" ? {} : { sessionIdle }),
      ...(sandboxStartupTimeoutMs === undefined ? {} : { startupTimeoutMs: sandboxStartupTimeoutMs }),
      log,
    });
  } catch (error) {
    pythonNotes.push(`circulusd sandbox failed to start: ${error instanceof Error ? error.message : String(error)}`);
    pythonNotes.push("the python tool is DISABLED; fix the sandbox, or set CIRCULUSD_TEST_SANDBOX=host to run python on this host without isolation (unsafe)");
  }
} else if (sandboxMode === "host") {
  const interpreter = resolvePythonInterpreter();
  if (interpreter === null) {
    pythonNotes.push("no host Python 3 interpreter found; the python tool is DISABLED (install Python 3 or set CIRCULUSD_TEST_PYTHON)");
  } else {
    python = new HostPythonExecutor(interpreter);
    pythonNotes.push("WARNING: CIRCULUSD_TEST_SANDBOX=host runs model-written Python directly on this machine with no isolation");
  }
} else {
  pythonNotes.push("the python tool is off (CIRCULUSD_TEST_SANDBOX=off)");
}

const tools = createToolDefinitions(python === null ? [] : [createPythonTool(python)]);
const frontendDirectory = resolve(import.meta.dirname, "../../frontend");
const pythonExecutor = python;
const app = createApp({
  provider,
  tools,
  // Evaluated per request: the sandbox description changes (agent relaunched, agent dead).
  execution: () => (pythonExecutor === null ? { mode: "disabled", notes: pythonNotes } : { ...pythonExecutor.describe(), notes: pythonNotes }),
  frontendDirectory,
  historyInjection,
  log,
  ...(maxChatSessions === undefined ? {} : { maxSessions: maxChatSessions }),
  ...(pythonExecutor === null ? {} : { onSessionDeleted: (sessionId: string) => pythonExecutor.closeSession(sessionId) }),
});

let address;
try {
  address = await app.listen(host, port);
} catch (error) {
  console.error(`cannot listen on ${host}:${port}: ${error instanceof Error ? error.message : String(error)}`);
  await python?.close();
  process.exit(1);
}
const description = provider.describe();
console.log(`circulusd-test backend listening on http://${address.host}:${address.port}`);
if (!["127.0.0.1", "::1", "localhost"].includes(host)) {
  console.warn(`  WARNING: bound to ${host}; the API has no authentication, so anyone who can reach it can run turns (and python)`);
}
console.log(`  model: ${description.kind} (${description.modelId} via ${description.api}` +
  `${description.baseUrl === null ? "" : ` at ${description.baseUrl}`})` +
  `, context ${description.contextWindow}, tools ${description.supportsTools ? "yes" : "NO"}, thinking ${description.reasoning ? "yes" : "no"}` +
  (description.apiKeyEnv === null ? "" : `, ${description.apiKeyEnv} ${description.apiKeyPresent ? "present" : "unset"}`));
console.log(`  tools: ${tools.map((tool) => tool.name).join(", ")}`);
if (python === null) {
  console.log("  python: DISABLED");
} else if (python.kind === "circulusd-sandbox") {
  const ready = (python as CirculusdSandboxExecutor).ready;
  console.log(
    `  python: circulusd sandboxd per session (backend label ${ready.backend}, launcher ${ready.launcher}, ${ready.distro} ${ready.kernel}, probe ${ready.probeMs} ms)`,
  );
  console.log(`          agent ${ready.host}:${ready.port}, environment ${ready.environmentDigest}`);
  console.log(`          up to ${ready.maxSessions} session sandboxes, idle stop after ${ready.sessionIdleMs === 0 ? "never" : `${ready.sessionIdleMs} ms`}, relaunch after ${ready.ledgerBudget} keyed RPCs`);
  if (ready.launcher === "docker") {
    console.log(`          image ${String(ready.extra?.image)} (${String(ready.extra?.imageId)}), docker ${String(ready.extra?.docker)}`);
  }
  console.log(`          ${ready.python.path} ${ready.python.version} inside the sandbox, timeout ${PYTHON_TIMEOUT_MS} ms`);
} else {
  const details = python.describe();
  console.log(`  python: HOST ${String(details.interpreter)} (${String(details.version)}), timeout ${PYTHON_TIMEOUT_MS} ms, workspaces under ${String(details.workspaces)}`);
}
for (const note of pythonNotes) console.log(`  python: ${note}`);
console.log(`  runtime revision: ${app.runtimeRevisionDigest}`);
console.log(`  history injection: ${historyInjection ? "on" : "off"}`);
console.log(`  sessions kept in memory: ${maxChatSessions ?? DEFAULT_SESSION_LIMIT} (longest idle evicted beyond that)`);
console.log(`  frontend: ${frontendDirectory}`);

let shuttingDown = false;
const shutdown = (signal: string): void => {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`${signal} received, shutting down`);
  // A stuck close (a hung SSE client, an unresponsive WSL) must not keep the process alive.
  setTimeout(() => {
    console.error("shutdown timed out; exiting");
    process.exit(1);
  }, 20_000).unref();
  Promise.allSettled([app.close(), python?.close() ?? Promise.resolve()]).finally(() => process.exit(0));
};
process.once("SIGINT", () => shutdown("SIGINT"));
process.once("SIGTERM", () => shutdown("SIGTERM"));

function optionalPositiveInteger(name: string): number | undefined {
  const raw = process.env[name]?.trim();
  if (raw === undefined || raw === "") return undefined;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < 1) {
    console.error(`${name} must be a positive integer, got ${raw}`);
    process.exit(2);
  }
  return value;
}
