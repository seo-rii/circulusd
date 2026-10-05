/**
 * Starts sandbox/bin/sandbox-agent inside WSL2 (or directly on a Linux host)
 * and keeps it alive for the lifetime of the backend. The agent is a small
 * Go program built on circulusd's generated protobuf/connect packages; it
 * launches one sandboxd per session in a jail, performs the nonce handshake,
 * and serves a local JSON API guarded by a token it only prints to us. It
 * prints one JSON "ready" line with the API port and token; every other line
 * it prints goes to the log.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { createInterface } from "node:readline";

export type SandboxLauncherKind = "auto" | "unshare" | "docker" | "nsjail";
export const DEFAULT_STARTUP_TIMEOUT_MS = 180_000;
export const SANDBOX_LAUNCHER_KINDS: readonly SandboxLauncherKind[] = ["auto", "unshare", "docker", "nsjail"];

export interface SandboxLaunchOptions {
  /** WSL distribution name; null uses the default distribution or a native Linux host. */
  readonly distro: string | null;
  /** Windows path of the sandbox directory holding bin/sandbox-agent and bin/sandboxd. */
  readonly sandboxDirectory: string;
  readonly launcher: SandboxLauncherKind;
  readonly python: string;
  /** Container image for the docker launcher; null keeps the agent default. */
  readonly image?: string | null;
  readonly workspaceSize: string;
  /** Session sandboxes kept at once; the least recently used idle one is evicted beyond this. */
  readonly maxSessions?: number;
  /** Go duration (e.g. "1h", "30m", "0" = never) after which an idle session's sandbox is stopped. */
  readonly sessionIdle?: string;
  /** Keyed RPCs per sandboxd generation before the agent relaunches it (testing knob). */
  readonly ledgerBudget?: number;
  readonly log: (line: string) => void;
  readonly startupTimeoutMs?: number;
}

export interface SandboxReady {
  readonly host: string;
  readonly port: number;
  /** Bearer token for the agent API; never leaves this process. */
  readonly token: string;
  readonly backend: string;
  readonly launcher: string;
  readonly environmentDigest: string;
  readonly sandboxdDigest: string;
  readonly python: { readonly path: string; readonly version: string; readonly command: string };
  readonly kernel: string;
  readonly distro: string;
  readonly stateDir: string;
  readonly maxSessions: number;
  readonly sessionIdleMs: number;
  readonly ledgerBudget: number;
  readonly probeMs: number;
  /** Launcher-specific details (docker image, daemon version). */
  readonly extra?: Record<string, unknown>;
}

export interface SandboxProcess {
  readonly ready: SandboxReady;
  readonly exited: Promise<number | null>;
  /** Resolved exit status once the agent is gone; null while it runs. */
  readonly exitStatus: () => number | null | undefined;
  close(): Promise<void>;
}

/** Converts a Windows path to the WSL `/mnt/<drive>/...` form; passes POSIX paths through. */
export function toWslPath(path: string): string {
  const match = /^([A-Za-z]):[\\/](.*)$/.exec(path);
  if (match === null) return path.replaceAll("\\", "/");
  return `/mnt/${(match[1] as string).toLowerCase()}/${(match[2] as string).replaceAll("\\", "/")}`;
}

export async function launchSandbox(options: SandboxLaunchOptions): Promise<SandboxProcess> {
  const sandboxDirectory = resolve(options.sandboxDirectory);
  const agent = resolve(sandboxDirectory, "bin", "sandbox-agent");
  const sandboxd = resolve(sandboxDirectory, "bin", "sandboxd");
  for (const binary of [agent, sandboxd]) {
    if (!existsSync(binary)) {
      throw new Error(`${binary} is missing; run \`corepack pnpm sandbox:build\` first`);
    }
  }
  const agentArguments = [
    "serve",
    "--sandboxd",
    toWslPath(sandboxd),
    "--launcher",
    options.launcher,
    "--python",
    options.python,
    "--workspace-size",
    options.workspaceSize,
    ...(options.image ? ["--image", options.image] : []),
    ...(options.maxSessions === undefined ? [] : ["--max-sessions", String(options.maxSessions)]),
    ...(options.sessionIdle === undefined ? [] : ["--session-idle", options.sessionIdle]),
    ...(options.ledgerBudget === undefined ? [] : ["--ledger-budget", String(options.ledgerBudget)]),
  ];
  const useWsl = process.platform === "win32";
  const command = useWsl ? "wsl.exe" : agent;
  const args = useWsl ? [...(options.distro === null ? [] : ["-d", options.distro]), "--", toWslPath(agent), ...agentArguments] : agentArguments;

  const child = spawn(command, args, { stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
  let exitStatus: number | null | undefined;
  const exited = new Promise<number | null>((resolveExit) => {
    child.once("exit", (code) => {
      exitStatus = code;
      resolveExit(code);
    });
  });
  // Writing to (or ending) stdin after the agent died would otherwise surface
  // as an unhandled 'error' event and take the backend down with it.
  child.stdin?.on("error", () => undefined);
  const recent: string[] = [];
  createInterface({ input: child.stderr as NodeJS.ReadableStream }).on("line", (line) => {
    recent.push(line);
    if (recent.length > 40) recent.shift();
    options.log(`[sandbox] ${line}`);
  });

  // The agent probes a real sandbox before reporting ready, and the docker
  // launcher may first have to pull its image; give that room by default.
  const timeoutMs = options.startupTimeoutMs ?? DEFAULT_STARTUP_TIMEOUT_MS;
  const ready = await new Promise<SandboxReady>((resolveReady, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`sandbox agent did not report ready within ${timeoutMs} ms`));
      child.kill();
    }, timeoutMs);
    createInterface({ input: child.stdout as NodeJS.ReadableStream }).on("line", (line) => {
      if (!line.startsWith("{")) {
        options.log(`[sandbox] ${line}`);
        return;
      }
      try {
        const parsed = JSON.parse(line) as Partial<SandboxReady> & { readonly ready?: boolean };
        if (parsed.ready === true) {
          clearTimeout(timer);
          if (typeof parsed.host !== "string" || typeof parsed.port !== "number" || typeof parsed.token !== "string" || parsed.token === "") {
            reject(new Error(`sandbox agent ready line lacks host/port/token: ${line.slice(0, 200)}`));
            child.kill();
            return;
          }
          resolveReady(parsed as SandboxReady);
        }
      } catch (error) {
        options.log(`[sandbox] unparsable agent output: ${line} (${error instanceof Error ? error.message : String(error)})`);
      }
    });
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(new Error(`cannot start ${command}: ${error.message}`));
    });
    void exited.then((code) => {
      clearTimeout(timer);
      reject(new Error(`sandbox agent exited with status ${code ?? "unknown"}: ${recent.slice(-5).join(" | ")}`));
    });
  });

  const close = (): Promise<void> => closeChild(child, exited, () => exitStatus !== undefined);
  try {
    // The WSL2 localhost relay publishes a new listener with a short delay.
    await waitForApi(ready, 15_000);
  } catch (error) {
    await close();
    throw error;
  }
  return {
    ready,
    exited,
    exitStatus: () => exitStatus,
    close,
  };
}

export function agentHeaders(ready: SandboxReady): Record<string, string> {
  return { authorization: `Bearer ${ready.token}` };
}

export async function waitForApi(ready: SandboxReady, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let lastError = "";
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`http://${ready.host}:${ready.port}/v1/ready`, { headers: agentHeaders(ready) });
      if (response.ok) return;
      lastError = `HTTP ${response.status}`;
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
    }
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 250));
  }
  throw new Error(`sandbox agent API at ${ready.host}:${ready.port} is unreachable: ${lastError}`);
}

async function closeChild(child: ChildProcess, exited: Promise<number | null>, hasExited: () => boolean): Promise<void> {
  // exitCode stays null for a signal death, so ask the exit tracker instead.
  if (hasExited()) return;
  // Closing stdin tells the agent to stop every sandbox and exit.
  child.stdin?.end();
  const timeout = new Promise<void>((resolveTimeout) => setTimeout(resolveTimeout, 8_000).unref());
  await Promise.race([exited.then(() => undefined), timeout]);
  if (!hasExited()) child.kill();
}
