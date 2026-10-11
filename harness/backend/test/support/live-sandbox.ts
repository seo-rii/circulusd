import { SANDBOX_LAUNCHER_KINDS, type SandboxLauncherKind } from "../../src/sandbox/launcher.ts";

export type LiveSandboxSelection =
  | { readonly enabled: false; readonly reason: string }
  | { readonly enabled: true; readonly launcher: SandboxLauncherKind; readonly distro: string | null };

/** Selection is explicit; probing for availability could itself start a jail. */
export function selectLiveSandbox(
  environment: Readonly<Record<string, string | undefined>>,
  platform: NodeJS.Platform = process.platform,
): LiveSandboxSelection {
  const enabled = environment.CIRCULUSD_TEST_SANDBOX_LIVE;
  const launcher = environment.CIRCULUSD_TEST_SANDBOX_LAUNCHER;
  const distro = environment.CIRCULUSD_TEST_SANDBOX_DISTRO;
  if (enabled !== undefined && enabled !== "0" && enabled !== "1") {
    throw new Error("invalid live sandbox configuration: CIRCULUSD_TEST_SANDBOX_LIVE must be 0 or 1");
  }
  if (launcher !== undefined && !SANDBOX_LAUNCHER_KINDS.includes(launcher as SandboxLauncherKind)) {
    throw new Error("invalid live sandbox configuration: launcher must be auto, nsjail, docker or unshare");
  }
  if (distro !== undefined && !/^[A-Za-z0-9](?:[A-Za-z0-9._ -]{0,126}[A-Za-z0-9._-])?$/.test(distro)) {
    throw new Error("invalid live sandbox configuration: WSL distribution must be a nonempty name without control characters");
  }
  const configured = launcher !== undefined || distro !== undefined;
  if (enabled === "0" && configured) {
    throw new Error("invalid live sandbox configuration: LIVE=0 conflicts with an explicit launcher or WSL distribution");
  }
  if (enabled === "0") return { enabled: false, reason: "live sandbox explicitly disabled (CIRCULUSD_TEST_SANDBOX_LIVE=0)" };
  if (enabled === undefined && !configured) {
    return { enabled: false, reason: "live sandbox not requested; set CIRCULUSD_TEST_SANDBOX_LIVE=1 on a provisioned host" };
  }
  if (platform !== "linux" && platform !== "win32") {
    throw new Error("explicit live sandbox requires Linux or Windows with WSL2");
  }
  if (distro !== undefined && platform !== "win32") {
    throw new Error("explicit WSL distribution requires a Windows test host; native Linux does not use WSL");
  }
  return { enabled: true, launcher: (launcher ?? "auto") as SandboxLauncherKind, distro: distro ?? null };
}

export interface LiveDiagnostics {
  log(line: string): void;
  lines(): readonly string[];
}

// Startup output may contain the API ready token, credentials in an error or
// an environment dump. Only fixed categories and narrow lifecycle fields are
// released; raw text and Error.cause never become TAP diagnostics.
function safeDiagnostic(input: string): string {
  const text = input.slice(0, 4_096);
  const rotation = /rotating sandboxd sandbox_[A-Z2-7]{26} gen [0-9]{1,9} -> [0-9]{1,9}\b/.exec(text);
  if (rotation !== null) return rotation[0];
  if (/is missing; run/.test(text)) return "required sandbox binary is missing; run `corepack pnpm harness:sandbox:build`";
  const exited = /sandbox agent exited with status (-?[0-9]{1,9}|unknown)\b/.exec(text);
  if (exited !== null) return `sandbox agent exited with status ${exited[1]}`;
  if (/permission denied|operation not permitted|\bEACCES\b|\bEPERM\b/i.test(text)) return "host permissions rejected sandbox startup";
  if (/did not report ready|timed out|\bETIMEDOUT\b/i.test(text)) return "sandbox startup timed out";
  if (/unreachable|\bECONNREFUSED\b/i.test(text)) return "sandbox agent API was unreachable";
  if (/not found|\bENOENT\b|no usable launcher|no working launcher/i.test(text)) return "required sandbox launcher or executable was unavailable";
  if (/ready line lacks|unparsable agent output/i.test(text)) return "sandbox agent returned invalid startup output";
  return "sandbox emitted a diagnostic (details suppressed)";
}

export function createLiveDiagnostics(): LiveDiagnostics {
  const recent: string[] = [];
  return {
    log(line) {
      recent.push(safeDiagnostic(line));
      if (recent.length > 8) recent.shift();
    },
    lines: () => [...recent],
  };
}

/** Unrequested gates skip; every selected startup error fails the test. */
export async function runSelectedLiveSandbox<Value>(
  selection: LiveSandboxSelection,
  skip: (reason: string) => void,
  start: () => Promise<Value>,
  diagnostics: LiveDiagnostics,
): Promise<Value | null> {
  if (!selection.enabled) {
    skip(selection.reason);
    return null;
  }
  try {
    return await start();
  } catch (error) {
    const failure = safeDiagnostic(error instanceof Error ? error.message : "");
    throw new Error([
      `explicit live sandbox startup failed (launcher=${selection.launcher})`,
      failure,
      ...diagnostics.lines(),
    ].join("\n").slice(0, 2_048));
  }
}
