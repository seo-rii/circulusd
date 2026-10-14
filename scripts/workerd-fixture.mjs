#!/usr/bin/env node
// Regenerate or check the committed workerd conformance fixture bundle.
//
//   node scripts/workerd-fixture.mjs          rebuild pi-worker.mjs and re-pin its digest
//   node scripts/workerd-fixture.mjs --check  fail when the committed bundle or pin is stale
//
// The bundle is built from the repository sources with a fixed esbuild
// configuration and no network access, so the same sources and lockfile always
// produce the same bytes. session-host.mjs names the stable-broker Dynamic
// Workers after sha256(pi-worker.mjs); the Go harness tests require that pin.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const fixture = "internal/conformance/workerd/fixture";
const bundlePath = path.join(repository, fixture, "pi-worker.mjs");
const hostPath = path.join(repository, fixture, "session-host.mjs");
const pin = /stable-broker\/sha256-([0-9a-f]{64})\//g;

const args = process.argv.slice(2);
if (args.length > 1 || (args.length === 1 && args[0] !== "--check")) {
  console.error("usage: node scripts/workerd-fixture.mjs [--check]");
  process.exit(2);
}

// Paths in the bundle's module comments are relative to absWorkingDir.
const result = await build({
  absWorkingDir: repository,
  entryPoints: [`${fixture}/pi-worker.entry.ts`],
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "es2022",
  external: ["cloudflare:sockets"],
  write: false,
  logLevel: "warning",
});
const bundle = result.outputFiles[0].contents;
const digest = createHash("sha256").update(bundle).digest("hex");
const host = readFileSync(hostPath, "utf8");
const pins = Array.from(host.matchAll(pin), (match) => match[1]);
if (pins.length === 0) {
  console.error(`${fixture}/session-host.mjs no longer contains a stable-broker/sha256-<digest>/ pin`);
  process.exit(1);
}

if (args[0] === "--check") {
  const committed = readFileSync(bundlePath);
  const committedDigest = createHash("sha256").update(committed).digest("hex");
  const problems = [];
  if (!committed.equals(bundle)) {
    problems.push(`pi-worker.mjs is stale: committed sha256-${committedDigest}, rebuilt sha256-${digest}`);
  }
  if (pins.some((value) => value !== digest)) {
    problems.push(`session-host.mjs pins sha256-${[...new Set(pins)].join(", sha256-")}, want sha256-${digest}`);
  }
  if (problems.length > 0) {
    console.error(`workerd fixture is out of date:\n  ${problems.join("\n  ")}\n` +
      "Run `pnpm generate:workerd-fixture` and commit both fixture files.");
    process.exit(1);
  }
  console.log(`workerd fixture is current (sha256-${digest})`);
} else {
  writeFileSync(bundlePath, bundle);
  writeFileSync(hostPath, host.replace(pin, `stable-broker/sha256-${digest}/`));
  console.log(`wrote ${fixture}/pi-worker.mjs and pinned sha256-${digest} in session-host.mjs`);
}
