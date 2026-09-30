/**
 * Runs the `python` tool inside circulusd's sandboxd. The protocol work
 * (SandboxProcessService over sandboxd's private socket, permits, nonce
 * handshake) lives in sandbox/agent, a Go program built on circulusd's own
 * generated packages; this side only launches it and posts JSON run requests.
 * The agent keeps one sandboxd (one jail, one /workspace) per session.
 */
import { PYTHON_OUTPUT_LIMIT, formatOutcome, truncateText, type PythonExecutor, type PythonRunRequest } from "../python-tool.ts";
import type { ToolExecution } from "../tools.ts";
import { agentHeaders, launchSandbox, type SandboxLaunchOptions, type SandboxProcess, type SandboxReady } from "./launcher.ts";

export interface CirculusdSandboxOptions extends Omit<SandboxLaunchOptions, "log"> {
  readonly log: (line: string) => void;
}

interface AgentRunResult {
  readonly stdout: string;
  readonly stderr: string;
  readonly stdoutTruncated: boolean;
  readonly stderrTruncated: boolean;
  readonly exitCode: number;
  readonly timedOut: boolean;
  readonly cancelled: boolean;
  readonly outputTruncated: boolean;
  readonly signal: string;
  readonly sandboxId: string;
  readonly generation: number;
  readonly note?: string;
}

const ISOLATION: Readonly<Record<string, string>> = {
  nsjail:
    "NsJail per session: user/mount/pid/net/ipc/uts namespaces, tmpfs root with read-only /usr, no network, rlimits, no_new_privs; sandboxd as inner root with CAP_SETUID/SETGID/KILL only, python as an unprivileged uid",
  docker:
    "Docker container per session: --network none, read-only rootfs, all capabilities dropped, no-new-privileges, pid/memory limits, tmpfs /workspace; sandboxd and python share one unprivileged uid inside the container (python can disturb its own session's sandboxd, nothing else)",
  unshare:
    "Linux user/mount/pid/net/ipc/uts namespaces per session (util-linux unshare); read-only /usr, private tmpfs /workspace, no network; python runs as an unprivileged uid",
};

export class CirculusdSandboxExecutor implements PythonExecutor {
  readonly kind = "circulusd-sandbox" as const;
  readonly #process: SandboxProcess;
  readonly #log: (line: string) => void;
  #closed = false;

  private constructor(process: SandboxProcess, log: (line: string) => void) {
    this.#process = process;
    this.#log = log;
    void process.exited.then((code) => {
      if (!this.#closed) this.#log(`[sandbox] agent exited unexpectedly with status ${code ?? "unknown"}; python tool calls will fail`);
    });
  }

  static async start(options: CirculusdSandboxOptions): Promise<CirculusdSandboxExecutor> {
    const process = await launchSandbox(options);
    return new CirculusdSandboxExecutor(process, options.log);
  }

  get ready(): SandboxReady {
    return this.#process.ready;
  }

  describe(): Record<string, unknown> {
    const ready = this.#process.ready;
    return {
      mode: "circulusd-sandbox",
      protocol: "circulus.api.v1alpha.SandboxProcessService via sandboxd (sandbox/agent, Go, circulusd's generated connect client)",
      backend: ready.backend,
      launcher: ready.launcher,
      isolation: ISOLATION[ready.launcher] ?? ready.launcher,
      scope: "one sandboxd instance (own jail and /workspace) per session; relaunched with a new generation when sandboxd exits or its idempotency ledger nears the cap",
      sessions: { max: ready.maxSessions, idleMs: ready.sessionIdleMs, ledgerBudget: ready.ledgerBudget },
      environmentDigest: ready.environmentDigest,
      sandboxdDigest: `sha256:${ready.sandboxdDigest}`,
      agent: `${ready.host}:${ready.port}`,
      distro: ready.distro,
      kernel: ready.kernel,
      python: ready.python,
      permits: "harness-signed DispatchPermit + WorkspaceProtectionPermit (field bindings only; not state-issued)",
      ...(ready.extra ?? {}),
    };
  }

  async close(): Promise<void> {
    this.#closed = true;
    await this.#process.close();
  }

  async closeSession(sessionId: string): Promise<void> {
    if (this.#closed || this.#process.exitStatus() !== undefined) return;
    const ready = this.#process.ready;
    const response = await fetch(`http://${ready.host}:${ready.port}/v1/sessions/${encodeURIComponent(sessionId)}`, {
      method: "DELETE",
      headers: agentHeaders(ready),
      signal: AbortSignal.timeout(10_000),
    });
    // 404 just means the session never ran python.
    if (!response.ok && response.status !== 404) {
      throw new Error(`sandbox agent: HTTP ${response.status} closing session ${sessionId}`);
    }
  }

  async run(request: PythonRunRequest): Promise<ToolExecution> {
    if (this.#closed) throw new Error("circulusd sandbox is closed");
    const exitStatus = this.#process.exitStatus();
    if (exitStatus !== undefined) {
      throw new Error(`circulusd sandbox agent is no longer running (exit status ${exitStatus ?? "unknown"}); restart the backend`);
    }
    const { context } = request;
    const timeoutMs = Math.max(1, Math.trunc(request.timeoutMs));
    const ready = this.#process.ready;
    // The agent cancels the sandbox process when the HTTP request is aborted.
    const signal = AbortSignal.any([context.signal, AbortSignal.timeout(timeoutMs + 5 * 60_000)]);
    let response: Response;
    try {
      response = await fetch(`http://${ready.host}:${ready.port}/v1/run`, {
        method: "POST",
        headers: { "content-type": "application/json", ...agentHeaders(ready) },
        body: JSON.stringify({
          sessionId: context.sessionId,
          turnId: context.turnId,
          toolCallId: context.toolCallId,
          requestDigest: context.effect.requestDigest,
          replayPolicy: context.effect.replayPolicy,
          code: request.code,
          stdin: request.stdin,
          timeoutMs,
        }),
        signal,
      });
    } catch (error) {
      if (context.signal.aborted) {
        return formatOutcome({
          stdout: "",
          stderr: "",
          stdoutTruncated: false,
          stderrTruncated: false,
          exitCode: -1,
          timedOut: false,
          cancelled: true,
          outputLimitExceeded: false,
          signal: null,
          timeoutMs,
          scriptPath: null,
        });
      }
      throw new Error(`sandbox agent unreachable: ${error instanceof Error ? error.message : String(error)}`);
    }
    const body = await readAgentJson(response);
    if (!response.ok || body.error !== undefined) {
      throw new Error(`sandbox agent: ${body.error ?? `HTTP ${response.status}`}`);
    }
    const result = body as unknown as AgentRunResult;
    if (typeof result.stdout !== "string" || typeof result.stderr !== "string" || typeof result.exitCode !== "number") {
      throw new Error(`sandbox agent returned an unexpected run result: ${JSON.stringify(body).slice(0, 200)}`);
    }
    if (result.note !== undefined) {
      this.#log(`[sandbox] session ${context.sessionId}: ${result.note}`);
    }
    const cap = (text: string, truncated: boolean): [string, boolean] =>
      text.length > PYTHON_OUTPUT_LIMIT ? [truncateText(text, PYTHON_OUTPUT_LIMIT), true] : [text, truncated];
    const [stdout, stdoutTruncated] = cap(result.stdout, result.stdoutTruncated);
    const [stderr, stderrTruncated] = cap(result.stderr, result.stderrTruncated);
    const outcome = formatOutcome({
      stdout,
      stderr,
      stdoutTruncated,
      stderrTruncated,
      exitCode: result.exitCode,
      timedOut: result.timedOut,
      cancelled: result.cancelled,
      outputLimitExceeded: result.outputTruncated,
      signal: result.signal === "" ? null : result.signal,
      timeoutMs,
      scriptPath: null,
    });
    return result.note === undefined ? outcome : { ...outcome, text: `note: ${result.note}\n${outcome.text}` };
  }
}

async function readAgentJson(response: Response): Promise<{ readonly error?: string } & Record<string, unknown>> {
  const text = await response.text();
  try {
    const parsed = JSON.parse(text) as unknown;
    if (parsed !== null && typeof parsed === "object") return parsed as Record<string, unknown>;
  } catch {
    // fall through
  }
  return { error: `HTTP ${response.status}: ${text.trim().slice(0, 200) || "empty response"}` };
}
