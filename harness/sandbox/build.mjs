#!/usr/bin/env node
// Cross-compiles the two Linux binaries the python sandbox needs:
//   bin/sandboxd       circulusd's cmd/sandboxd, from the sibling checkout (unmodified)
//   bin/sandbox-agent  sandbox/agent, circulusd-test's executord stand-in
//   node sandbox/build.mjs [--circulusd <path>]   build both binaries
//   node sandbox/build.mjs --test                  run the agent's Go tests with the same toolchain
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const circulusdArgument = argv.indexOf("--circulusd");
if (circulusdArgument !== -1 && (argv[circulusdArgument + 1] === undefined || argv[circulusdArgument + 1].startsWith("--"))) {
  console.error("--circulusd needs a path");
  process.exit(2);
}
const circulusd = resolve(circulusdArgument === -1 ? resolve(here, "../../circulusd") : argv[circulusdArgument + 1]);
const binDirectory = resolve(here, "bin");

if (!existsSync(resolve(circulusd, "cmd", "sandboxd", "main_linux.go"))) {
  console.error(`circulusd checkout not found at ${circulusd} (expected cmd/sandboxd/main_linux.go)`);
  process.exit(2);
}

function findGo() {
  const candidates = ["go"];
  if (process.platform === "win32" && process.env.LOCALAPPDATA) {
    candidates.push(resolve(process.env.LOCALAPPDATA, "go-toolchain", "go", "bin", "go.exe"));
  }
  for (const candidate of candidates) {
    const probe = spawnSync(candidate, ["version"], { encoding: "utf8", windowsHide: true });
    if (probe.status === 0) return { command: candidate, version: probe.stdout.trim() };
  }
  return null;
}

const go = findGo();
if (go === null) {
  console.error("Go toolchain not found on PATH (or %LOCALAPPDATA%\\go-toolchain\\go\\bin\\go.exe)");
  process.exit(2);
}
if (argv.includes("--test")) {
  // Host-OS tests (protocol vectors, text helpers); the Linux-only files are vetted at build time.
  const result = spawnSync(go.command, ["test", "./..."], { cwd: resolve(here, "agent"), stdio: "inherit", windowsHide: true });
  process.exit(result.status ?? 1);
}
mkdirSync(binDirectory, { recursive: true });
const env = { ...process.env, GOOS: "linux", GOARCH: "amd64", CGO_ENABLED: "0" };

function build(name, cwd, target) {
  const output = resolve(binDirectory, name);
  console.log(`building ${name} with ${go.version} in ${cwd}`);
  const result = spawnSync(go.command, ["build", "-trimpath", "-o", output, target], { cwd, stdio: "inherit", windowsHide: true, env });
  if (result.status !== 0) process.exit(result.status ?? 1);
  const digest = createHash("sha256").update(readFileSync(output)).digest("hex");
  console.log(`  ${output}\n  sha256 ${digest}`);
}

build("sandboxd", circulusd, "./cmd/sandboxd");
build("sandbox-agent", resolve(here, "agent"), ".");
const revision = spawnSync("git", ["rev-parse", "--short", "HEAD"], { cwd: circulusd, encoding: "utf8", windowsHide: true });
console.log(`circulusd ${revision.status === 0 ? revision.stdout.trim() : "unknown revision"}`);
