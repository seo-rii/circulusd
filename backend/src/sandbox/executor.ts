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
  /** Starts the agent process; tests substitute a fake. */
  readonly launch?: (options: SandboxLaunchOptions) => Promise<SandboxProcess>;
  /** Overrides AGENT_RELAUNCH_MIN_INTERVAL_MS (tests). */
  readonly relaunchMinIntervalMs?: number;
}

/**
 * After the agent dies it is started again on the next python call, but not
 * more often than this: an agent that dies right after starting (a broken
 * launcher, a WSL distro shutting down) would otherwise cost a full launch
 * and probe per tool call.
 */
export const AGENT_RELAUNCH_MIN_INTERVAL_MS = 30_000;

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
  readonly #options: CirculusdSandboxOptions;
  readonly #log: (line: string) => void;
  #process: SandboxProcess;
  #relaunch: Promise<SandboxProcess> | null = null;
  #launchedAt: number;
  #relaunches = 0;
  #closed = false;

  private constructor(process: SandboxProcess, options: CirculusdSandboxOptions, launchedAt: number) {
    this.#options = options;
    this.#log = options.log;
    this.#process = process;
    this.#launchedAt = launchedAt;
    this.#watch(process);
  }

  static async start(options: CirculusdSandboxOptions): Promise<CirculusdSandboxExecutor> {
    const launchedAt = Date.now();
    const process = await (options.launch ?? launchSandbox)(options);
    return new CirculusdSandboxExecutor(process, options, launchedAt);
  }

  get ready(): SandboxReady {
    return this.#process.ready;
  }

  /** Times the agent was started again after dying (see #current). */
  get relaunches(): number {
    return this.#relaunches;
  }

  #watch(process: SandboxProcess): void {
    void process.exited.then((code) => {
      if (this.#closed || this.#process !== process) return;
      this.#log(
        `[sandbox] agent exited unexpectedly with status ${code ?? "unknown"}; ` +
          "it is started again on the next python call (every session's /workspace is gone)",
      );
    });
  }

  /**
   * The running agent, started again if the previous one died. One relaunch
   * at a time; concurrent callers share it. Without this a dead agent (WSL
   * shut down, OOM-killed, crashed) left the python tool broken until the
   * backend was restarted.
   */
  async #current(): Promise<SandboxProcess> {
    if (this.#closed) throw new Error("circulusd sandbox is closed");
    if (this.#process.exitStatus() === undefined) return this.#process;
    if (this.#relaunch === null) {
      const exitStatus = this.#process.exitStatus();
      const minInterval = this.#options.relaunchMinIntervalMs ?? AGENT_RELAUNCH_MIN_INTERVAL_MS;
      const sinceLaunch = Date.now() - this.#launchedAt;
      if (sinceLaunch < minInterval) {
        throw new Error(
          `circulusd sandbox agent exited (status ${exitStatus ?? "unknown"}) ${Math.round(sinceLaunch / 1000)} s after starting; ` +
            `it is started again at most every ${Math.round(minInterval / 1000)} s, try later`,
        );
      }
      this.#relaunch = (async () => {
        this.#log(`[sandbox] agent exited (status ${exitStatus ?? "unknown"}); starting it again`);
        this.#launchedAt = Date.now();
        const next = await (this.#options.launch ?? launchSandbox)(this.#options);
        if (this.#closed) {
          await next.close();
          throw new Error("circulusd sandbox is closed");
        }
        this.#process = next;
        this.#relaunches += 1;
        this.#watch(next);
        this.#log(`[sandbox] agent is back at ${next.ready.host}:${next.ready.port} (relaunch ${this.#relaunches})`);
        return next;
      })().finally(() => {
        this.#relaunch = null;
      });
    }
    return this.#relaunch;
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
      agentRelaunches: this.#relaunches,
      agentAlive: this.#process.exitStatus() === undefined,
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
    // A relaunch in flight closes its own process once it sees #closed.
    await this.#relaunch?.catch(() => undefined);
    await this.#process.close();
  }

  async closeSession(sessionId: string): Promise<void> {
    // A dead agent took every session with it; nothing is left to close.
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
    const { context } = request;
    const timeoutMs = Math.max(1, Math.trunc(request.timeoutMs));
    const ready = (await this.#current()).ready;
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
