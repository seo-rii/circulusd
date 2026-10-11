#!/usr/bin/env node
// Prepare exact Loader artifacts. Signing, deployment and qualification are
// separate operator steps; this command has no provider or network access.
import { createHash } from "node:crypto";
import { constants, closeSync, fchmodSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const commit = "89e4ffc53a14ecb496d2ca5014ff9d19b0061ad9";
const maximumInputBytes = 1 << 20;
const supportedFlags = new Set(["delete_all_deletes_alarm", "fetcher_no_get_put_delete", "js_rpc", "sqlite_vec", "websocket_standard_binary_type"]);
const digest = (data) => `sha256:${createHash("sha256").update(data).digest("hex")}`;
function invalid() { throw new Error("Invalid native Pi preparation input."); }
function canonicalPath(value) {
  if (typeof value !== "string" || !path.isAbsolute(value) || path.normalize(value) !== value ||
    value === path.parse(value).root || Array.from(value).some((character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127)) invalid();
  return value;
}
function options(args) {
  if (args.length !== 4) invalid();
  const result = {};
  for (let i = 0; i < args.length; i += 2) {
    if (!["--config", "--output"].includes(args[i]) || Object.hasOwn(result, args[i])) invalid();
    result[args[i]] = canonicalPath(args[i + 1]);
  }
  if (!result["--config"] || !result["--output"]) invalid();
  return result;
}
function readConfiguration(filename) {
  const fd = openSync(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = fstatSync(fd, { bigint: true });
    if (!before.isFile() || before.uid !== BigInt(process.getuid()) || before.nlink !== 1n ||
      ![0o400, 0o600].includes(Number(before.mode & 0o7777n)) || before.size <= 0n || before.size > BigInt(maximumInputBytes)) invalid();
    const data = Buffer.alloc(maximumInputBytes + 1);
    let offset = 0;
    while (offset < data.byteLength) {
      const size = readSync(fd, data, offset, data.byteLength - offset, null);
      if (size === 0) break;
      offset += size;
    }
    const after = fstatSync(fd, { bigint: true });
    if (BigInt(offset) !== before.size || before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size ||
      before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) invalid();
    const bytes = data.subarray(0, offset);
    const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    const fields = ["schemaVersion", "runtimeRevisionDigest", "compatibilityDate", "compatibilityFlags", "configuration"];
    if (!value || Array.isArray(value) || typeof value !== "object" || Object.keys(value).length !== fields.length ||
      fields.some((name) => !Object.hasOwn(value, name)) || value.schemaVersion !== 1 ||
      !/^sha256:[0-9a-f]{64}$/u.test(value.runtimeRevisionDigest) || !Array.isArray(value.compatibilityFlags)) invalid();
    let previous = "";
    for (const flag of value.compatibilityFlags) {
      if (typeof flag !== "string" || !supportedFlags.has(flag) || flag <= previous) invalid();
      previous = flag;
    }
    return { value, configurationDigest: digest(bytes) };
  } finally { closeSync(fd); }
}
async function library() {
  const result = await build({ stdin: { contents:
    'export * from "./workers/pi-runtime/src/celld-genesis.ts";\n' +
    'export * from "./workers/pi-runtime/src/celld-execution.ts";\n',
    resolveDir: repository, sourcefile: "native-pi-artifacts.ts" }, bundle: true, format: "esm",
    platform: "browser", target: "es2022", write: false, logLevel: "silent", external: ["cloudflare:sockets"] });
  return import(`data:text/javascript;base64,${Buffer.from(result.outputFiles[0].contents).toString("base64")}`);
}
async function prepare(args) {
  const input = options(args), output = input["--output"];
  try { lstatSync(output); invalid(); } catch (error) { if (error.code !== "ENOENT") throw error; }
  const parent = lstatSync(path.dirname(output));
  if (!parent.isDirectory() || parent.isSymbolicLink() || parent.uid !== process.getuid() || (parent.mode & 0o022) !== 0) invalid();
  const { value, configurationDigest } = readConfiguration(input["--config"]);
  const api = await library();
  const files = {}, runtimes = {};
  let totalBytes = 0;
  for (const purpose of ["genesis", "execution"]) {
    const upper = purpose.toUpperCase();
    const source = api[`PI_${upper}_ENTRY_SOURCE`];
    const bundled = await build({ entryPoints: [path.join(repository, "workers/pi-runtime/src", `${purpose}-entrypoint.ts`)],
      bundle: true, format: "esm", platform: "browser", target: "es2022", write: false,
      external: ["cloudflare:sockets"], legalComments: "none", metafile: true, logLevel: "silent" });
    if (bundled.outputFiles.length !== 1) invalid();
    for (const entry of Object.values(bundled.metafile.outputs)) {
      if (entry.imports.some((item) => item.external && item.path !== "cloudflare:sockets")) invalid();
    }
    const core = bundled.outputFiles[0].contents, wrapper = new TextEncoder().encode(source);
    if (core.byteLength < 1 || core.byteLength > (8 << 20)) invalid();
    totalBytes += core.byteLength + wrapper.byteLength;
    if (totalBytes > (32 << 20)) invalid();
    const modules = [
      { specifier: api[`PI_${upper}_ENTRY_MODULE`], bytes: wrapper, digest: digest(wrapper) },
      { specifier: api[`PI_${upper}_CORE_MODULE`], bytes: core, digest: digest(core) },
    ];
    const runtime = { runtimeRevisionDigest: value.runtimeRevisionDigest, adapterAbiVersion: 2, checkpointSchemaVersion: 2,
      compatibilityDate: value.compatibilityDate, compatibilityFlags: value.compatibilityFlags,
      mainModule: modules[0].specifier, modules, configuration: value.configuration };
    const artifactDigest = await api[purpose === "genesis" ? "piGenesisRuntimeArtifactDigest" : "piExecutionRuntimeArtifactDigest"](runtime);
    const prepared = { schemaVersion: 1, purpose, celldCommit: commit, artifactDigest,
      ...runtime, modules: modules.map((module, index) => {
        const filename = `${purpose}-${index === 0 ? "entry" : "core"}.mjs`;
        files[filename] = module.bytes;
        return { specifier: module.specifier, file: filename, digest: module.digest, sizeBytes: module.bytes.byteLength };
      }) };
    files[`${purpose}-runtime.json`] = `${JSON.stringify(prepared)}\n`;
    runtimes[purpose] = { artifactDigest, runtimeRevisionDigest: runtime.runtimeRevisionDigest,
      mappingDomain: `circulusd.pi.${purpose}-runtime-mapping`, runtimeFile: `${purpose}-runtime.json` };
  }
  const manifest = { schemaVersion: 1, celldCommit: commit, configurationDigest,
    qualification: "PREPARATION_ONLY", admissionReady: false, independentlySignedMappingsRequired: true, runtimes };
  files["manifest.json"] = `${JSON.stringify(manifest)}\n`;
  let directory;
  try {
    mkdirSync(output, { mode: 0o700 });
    const created = lstatSync(output);
    directory = openSync(output, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    const held = fstatSync(directory);
    if (created.dev !== held.dev || created.ino !== held.ino || held.uid !== process.getuid()) invalid();
    fchmodSync(directory, 0o700);
    for (const [name, content] of Object.entries(files)) {
      const fd = openSync(`/proc/self/fd/${directory}/${name}`, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      try { fchmodSync(fd, 0o600); writeFileSync(fd, content); fsyncSync(fd); } finally { closeSync(fd); }
    }
    fsyncSync(directory);
  } finally { if (directory !== undefined) closeSync(directory); }
  return { runtimes, qualification: "PREPARATION_ONLY", admissionReady: false };
}
try {
  process.umask(0o077);
  console.log(JSON.stringify(await prepare(process.argv.slice(2))));
} catch {
  console.error("Native Pi preparation failed; no deployment or qualification was performed.");
  process.exitCode = 1;
}
