import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { StringDecoder } from "node:string_decoder";

import type { ToolContext, ToolDefinition, ToolExecution } from "./tools.ts";

/**
 * The `python` tool. Two executors exist:
 *   - CirculusdSandboxExecutor (sandbox/executor.ts): runs the script inside
 *     circulusd's sandboxd through SandboxProcessService. This is the default.
 *   - HostPythonExecutor (below): runs the host interpreter as a child
 *     process with no isolation at all. Opt-in via CIRCULUSD_TEST_SANDBOX=host.
 * The tool itself only shapes the request, applies the one-line-code repair,
 * and renders the outcome.
 */
export interface PythonRunRequest {
  readonly code: string;
  readonly stdin: string;
  readonly timeoutMs: number;
  readonly context: ToolContext;
}

export interface PythonExecutor {
  readonly kind: "host" | "circulusd-sandbox";
  describe(): Record<string, unknown>;
  run(request: PythonRunRequest): Promise<ToolExecution>;
  /** Releases whatever the executor keeps for a session (its workspace, its sandbox). */
  closeSession(sessionId: string): Promise<void>;
  close(): Promise<void>;
}

export interface PythonInterpreter {
  /** Command as spawned (`python`, `py`, or the configured path). */
  readonly command: string;
  /** `sys.executable` as reported by the interpreter. */
  readonly executable: string;
  readonly version: string;
}

export interface PythonRunOptions {
  readonly code: string;
  readonly stdin?: string;
  /** Directory the script runs in; created when missing. */
  readonly workspace: string;
  readonly timeoutMs?: number;
  /** Kills the process when it fires (the turn was aborted). */
  readonly signal?: AbortSignal;
}

export const PYTHON_TIMEOUT_MS = positiveInteger(process.env.CIRCULUSD_TEST_PYTHON_TIMEOUT_MS, 30_000);
/** Per-stream cap on captured output, in UTF-16 code units. */
export const PYTHON_OUTPUT_LIMIT = 16 * 1024;
export const PYTHON_CODE_LIMIT_BYTES = 64 * 1024;
export const PYTHON_STDIN_LIMIT_BYTES = 256 * 1024;
export const PYTHON_WORKSPACE_ROOT = join(tmpdir(), "circulusd-test", "workspaces");

const PROBE_SCRIPT = "import sys; print(sys.version.split()[0]); print(sys.executable)";

let resolved: PythonInterpreter | null | undefined;

/**
 * Find a usable host interpreter once per process. `CIRCULUSD_TEST_PYTHON`
 * wins; otherwise the usual command names are probed in platform order (on
 * Windows `python3` is often the Microsoft Store stub, so it is not tried).
 */
export function resolvePythonInterpreter(): PythonInterpreter | null {
  if (resolved !== undefined) return resolved;
  const configured = process.env.CIRCULUSD_TEST_PYTHON?.trim();
  const candidates =
    configured !== undefined && configured !== ""
      ? [configured]
      : process.platform === "win32"
        ? ["python", "py"]
        : ["python3", "python"];
  resolved = null;
  for (const command of candidates) {
    const probe = spawnSync(command, ["-I", "-c", PROBE_SCRIPT], {
      encoding: "utf8",
      timeout: 10_000,
      windowsHide: true,
      env: pythonEnvironment(),
    });
    const [version = "", executable = ""] = (probe.stdout ?? "").split(/\r?\n/);
    if (probe.status === 0 && /^\d+\.\d+/.test(version)) {
      resolved = { command, executable: executable.trim() || command, version: version.trim() };
      break;
    }
  }
  return resolved;
}

export function sessionWorkspace(sessionId: string): string {
  const safe = sessionId.replace(/[^A-Za-z0-9_-]/g, "_").slice(0, 96) || "session";
  return join(PYTHON_WORKSPACE_ROOT, safe);
}

/** Runs one script with the host interpreter (no sandbox). */
export async function runPython(interpreter: PythonInterpreter, options: PythonRunOptions): Promise<ToolExecution> {
  const timeoutMs = options.timeoutMs ?? PYTHON_TIMEOUT_MS;
  await mkdir(options.workspace, { recursive: true });
  const scriptPath = join(options.workspace, `.run-${randomUUID().slice(0, 8)}.py`);
  await writeFile(scriptPath, options.code, "utf8");
  try {
    const result = await spawnCollect(interpreter.command, ["-I", "-B", "-X", "utf8", scriptPath], {
      cwd: options.workspace,
      stdin: options.stdin ?? "",
      timeoutMs,
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
    return formatOutcome({
      stdout: result.stdout.text,
      stderr: result.stderr.text,
      stdoutTruncated: result.stdout.truncated,
      stderrTruncated: result.stderr.truncated,
      exitCode: result.exitCode ?? -1,
      timedOut: result.timedOut,
      cancelled: result.cancelled,
      outputLimitExceeded: false,
      signal: result.exitCode === null ? (result.signal ?? "unknown signal") : null,
      timeoutMs,
      scriptPath,
    });
  } finally {
    await rm(scriptPath, { force: true });
  }
}

/**
 * Turn `\n` escape sequences into newlines when the code has no real line
 * breaks at all; returns null when the code does not look like that.
 */
export function unescapeNewlines(code: string): string | null {
  if (code.includes("\n") || !code.includes("\\n")) return null;
  // Only escapes outside string literals are line breaks; a `\n` inside a
  // string (print("a\nb")) is a genuine escape sequence and must stay.
  let output = "";
  let quote: string | null = null;
  let index = 0;
  while (index < code.length) {
    const char = code[index] as string;
    if (quote !== null) {
      if (char === "\\") {
        output += char + (code[index + 1] ?? "");
        index += 2;
      } else if (code.startsWith(quote, index)) {
        output += quote;
        index += quote.length;
        quote = null;
      } else {
        output += char;
        index += 1;
      }
      continue;
    }
    if (char === "'" || char === '"') {
      quote = code.startsWith(char.repeat(3), index) ? char.repeat(3) : char;
      output += quote;
      index += quote.length;
    } else if (char === "#") {
      const end = code.indexOf("\\n", index);
      output += end === -1 ? code.slice(index) : `${code.slice(index, end)}\n`;
      index = end === -1 ? code.length : end + 2;
    } else if (char === "\\" && code.startsWith("\\r\\n", index)) {
      output += "\n";
      index += 4;
    } else if (char === "\\" && code[index + 1] === "n") {
      output += "\n";
      index += 2;
    } else if (char === "\\" && code[index + 1] === "t") {
      output += "\t";
      index += 2;
    } else {
      output += char;
      index += 1;
    }
  }
  return output;
}

export class HostPythonExecutor implements PythonExecutor {
  readonly kind = "host" as const;
  readonly #interpreter: PythonInterpreter;

  constructor(interpreter: PythonInterpreter) {
    this.#interpreter = interpreter;
  }

  describe(): Record<string, unknown> {
    return {
      mode: "host",
      isolation: "none: the host interpreter runs as the backend user with a scrubbed environment and a per-session temp directory",
      interpreter: this.#interpreter.executable,
      version: this.#interpreter.version,
      workspaces: PYTHON_WORKSPACE_ROOT,
    };
  }

  run(request: PythonRunRequest): Promise<ToolExecution> {
    return runPython(this.#interpreter, {
      code: request.code,
      stdin: request.stdin,
      workspace: sessionWorkspace(request.context.sessionId),
      timeoutMs: request.timeoutMs,
      signal: request.context.signal,
    });
  }

  closeSession(sessionId: string): Promise<void> {
    return rm(sessionWorkspace(sessionId), { recursive: true, force: true });
  }

  close(): Promise<void> {
    return Promise.resolve();
  }
}

export function createPythonTool(executor: PythonExecutor): ToolDefinition {
  const where =
    executor.kind === "circulusd-sandbox"
      ? "inside an isolated Linux sandbox (circulusd sandboxd): no network, read-only system, a private /workspace"
      : "on the backend host with no isolation (keep scripts small and non-destructive)";
  return {
    name: "python",
    description:
      `Run a Python 3 script ${where} and return what it prints. Only stdout/stderr come back, so print() ` +
      "anything you want to see; the value of the last expression is not shown. Write the code with real line breaks, " +
      "not escaped \\n sequences. Standard library only. The working directory persists across calls within the same " +
      "session, so a file written by one call can be read by a later one. " +
      `Wall-clock limit ${Math.round(PYTHON_TIMEOUT_MS / 1000)} s; output is capped at ${PYTHON_OUTPUT_LIMIT} characters per stream.`,
    parameters: {
      type: "object",
      properties: {
        code: { type: "string", description: "Python 3 source code to execute as a script" },
        stdin: { type: "string", description: "Optional text made available on standard input" },
      },
      required: ["code"],
      additionalProperties: false,
    },
    replayPolicy: "never",
    run: async (args, context) => {
      const code = typeof args.code === "string" ? args.code : "";
      if (code.trim() === "") throw new Error("code must be a non-empty string of Python source");
      if (Buffer.byteLength(code, "utf8") > PYTHON_CODE_LIMIT_BYTES) {
        throw new Error(`code exceeds ${PYTHON_CODE_LIMIT_BYTES} bytes`);
      }
      const stdin = typeof args.stdin === "string" ? args.stdin : "";
      if (Buffer.byteLength(stdin, "utf8") > PYTHON_STDIN_LIMIT_BYTES) {
        throw new Error(`stdin exceeds ${PYTHON_STDIN_LIMIT_BYTES} bytes`);
      }
      const first = await executor.run({ code, stdin, timeoutMs: PYTHON_TIMEOUT_MS, context });
      // Small models sometimes emit the whole script on one line with literal
      // "\n" two-character escapes. Python then fails on the first backslash;
      // rather than let the model loop on the same broken call, run the
      // unescaped script once and say so in the result.
      const repaired = unescapeNewlines(code);
      if (repaired === null || !first.isError || context.signal.aborted || !/line continuation character/.test(first.text)) {
        return first;
      }
      const second = await executor.run({ code: repaired, stdin, timeoutMs: PYTHON_TIMEOUT_MS, context });
      return {
        ...second,
        text:
          'note: the code arrived on a single line with literal "\\n" escapes; they were converted to real newlines before running.\n' +
          second.text,
      };
    },
  };
}

// ------------------------------------------------------------- host process

interface SpawnResult {
  readonly stdout: CapturedStream;
  readonly stderr: CapturedStream;
  readonly exitCode: number | null;
  readonly signal: NodeJS.Signals | null;
  readonly timedOut: boolean;
  readonly cancelled: boolean;
  readonly durationMs: number;
}

interface CapturedStream {
  readonly text: string;
  readonly truncated: boolean;
}

class StreamCapture {
  #decoder = new StringDecoder("utf8");
  #text = "";
  #truncated = false;
  readonly #limit: number;

  constructor(limit: number) {
    this.#limit = limit;
  }

  push(chunk: Buffer): void {
    if (this.#truncated) return;
    this.#text += this.#decoder.write(chunk);
    if (this.#text.length > this.#limit) {
      this.#text = truncateText(this.#text, this.#limit);
      this.#truncated = true;
    }
  }

  finish(): CapturedStream {
    if (!this.#truncated) this.#text += this.#decoder.end();
    return { text: this.#text, truncated: this.#truncated };
  }
}

/** Cuts `text` to `limit` UTF-16 units without leaving half a surrogate pair. */
export function truncateText(text: string, limit: number): string {
  let cut = text.slice(0, limit);
  const last = cut.charCodeAt(cut.length - 1);
  if (last >= 0xd800 && last <= 0xdbff) cut = cut.slice(0, -1);
  return cut;
}

function spawnCollect(
  command: string,
  args: readonly string[],
  options: { readonly cwd: string; readonly stdin: string; readonly timeoutMs: number; readonly signal?: AbortSignal },
): Promise<SpawnResult> {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: pythonEnvironment(),
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
      // A new process group on POSIX so the timeout can kill descendants too.
      detached: process.platform !== "win32",
    });
    const stdout = new StreamCapture(PYTHON_OUTPUT_LIMIT);
    const stderr = new StreamCapture(PYTHON_OUTPUT_LIMIT);
    let timedOut = false;
    let cancelled = false;
    const timer = setTimeout(() => {
      timedOut = true;
      killTree(child);
    }, options.timeoutMs);
    const onAbort = (): void => {
      cancelled = true;
      killTree(child);
    };
    if (options.signal?.aborted) onAbort();
    else options.signal?.addEventListener("abort", onAbort, { once: true });
    const settle = (): void => {
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", onAbort);
    };

    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    child.on("error", (error) => {
      settle();
      reject(error);
    });
    child.on("close", (exitCode, signal) => {
      settle();
      resolve({
        stdout: stdout.finish(),
        stderr: stderr.finish(),
        exitCode,
        signal,
        timedOut,
        cancelled,
        durationMs: Date.now() - started,
      });
    });
    // EPIPE when the script exits without reading stdin is not an error.
    child.stdin.on("error", () => {});
    child.stdin.end(options.stdin);
  });
}

function killTree(child: ChildProcess): void {
  if (child.pid === undefined) return;
  if (process.platform === "win32") {
    spawn("taskkill", ["/pid", String(child.pid), "/T", "/F"], { windowsHide: true, stdio: "ignore" }).on(
      "error",
      () => child.kill(),
    );
    return;
  }
  try {
    process.kill(-child.pid, "SIGKILL");
  } catch {
    child.kill("SIGKILL");
  }
}

export interface ProcessOutcome {
  readonly stdout: string;
  readonly stderr: string;
  readonly stdoutTruncated: boolean;
  readonly stderrTruncated: boolean;
  readonly exitCode: number;
  readonly timedOut: boolean;
  readonly cancelled: boolean;
  readonly outputLimitExceeded: boolean;
  readonly signal: string | null;
  readonly timeoutMs: number;
  /** Host script path to hide from tracebacks; null when the script ran from argv. */
  readonly scriptPath: string | null;
}

/** Renders a finished process the same way for every executor. */
export function formatOutcome(outcome: ProcessOutcome): ToolExecution {
  const render = (text: string, truncated: boolean): string => {
    let rendered = outcome.scriptPath === null ? text : text.replaceAll(outcome.scriptPath, "script.py");
    rendered = rendered.replaceAll("\r\n", "\n").replace(/\s+$/, "");
    return rendered + (truncated ? `\n[truncated at ${PYTHON_OUTPUT_LIMIT} characters]` : "");
  };
  const stdout = render(outcome.stdout, outcome.stdoutTruncated);
  const stderr = render(outcome.stderr, outcome.stderrTruncated);
  const failed = outcome.timedOut || outcome.cancelled || outcome.outputLimitExceeded || outcome.exitCode !== 0;
  if (!failed) {
    const body = stdout === "" ? "(no output)" : stdout;
    return { text: stderr === "" ? body : `${body}\n--- stderr ---\n${stderr}`, isError: false };
  }
  const reason = outcome.timedOut
    ? `timed out after ${outcome.timeoutMs} ms; the process was killed`
    : outcome.outputLimitExceeded
      ? "output limit exceeded; the process was killed"
      : outcome.cancelled
        ? "the process was cancelled"
        : outcome.signal !== null
          ? `killed by ${outcome.signal}`
          : `exit code ${outcome.exitCode}`;
  return {
    text: `${reason}\n--- stdout ---\n${stdout === "" ? "(empty)" : stdout}\n--- stderr ---\n${stderr === "" ? "(empty)" : stderr}`,
    isError: true,
  };
}

function pythonEnvironment(): NodeJS.ProcessEnv {
  const keep =
    process.platform === "win32"
      ? ["PATH", "SYSTEMROOT", "SYSTEMDRIVE", "TEMP", "TMP", "COMSPEC", "PATHEXT"]
      : ["PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "TERM"];
  const env: NodeJS.ProcessEnv = {};
  for (const key of keep) {
    const value = process.env[key];
    if (value !== undefined) env[key] = value;
  }
  env.PYTHONIOENCODING = "utf-8";
  env.PYTHONUNBUFFERED = "1";
  env.PYTHONDONTWRITEBYTECODE = "1";
  return env;
}

function positiveInteger(raw: string | undefined, fallback: number): number {
  const value = Number(raw);
  return raw !== undefined && Number.isInteger(value) && value > 0 ? value : fallback;
}
