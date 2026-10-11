#!/usr/bin/env node
// Prepare a local deployment project only. No credentials, target service or
// bucket are discovered, and this command never deploys or grants admission.
import { createHash } from "node:crypto";
import { constants, closeSync, fchmodSync, fstatSync, lstatSync, mkdirSync, openSync, readSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const celldCommit = "89e4ffc53a14ecb496d2ca5014ff9d19b0061ad9";
const wrapperVersion = "circulusd.native-storage-qualification-wrapper/v1";
const maximumConfigurationBytes = 65536;
const maxima = Object.freeze({ maxStateBytes: 16 << 20, maxReceiptResponseBytes: 4 << 20,
  maxCapabilityClaims: 64, maxCapabilityClaimBytes: 1 << 20, maxReceiptLookups: 64,
  maxReceiptWrites: 64, maxTransactionBytes: 32 << 20 });
// Exact modeled flags from the pinned celld cloudflare-compat contract. An
// accepted but ignored compatibility flag must not silently enter this bundle.
const supportedFlags = new Set(["delete_all_deletes_alarm", "fetcher_no_get_put_delete", "js_rpc",
  "sqlite_vec", "websocket_standard_binary_type"]);
const configurationFields = ["schemaVersion", "keyId", "rootKeyHex", "bounds", "timeoutMs",
  "compatibilityDate", "compatibilityFlags"];
const reservedProbePaths = ["/circulusd/native-storage/v1/production:probe", "/circulusd/state/v1/production:probe"];
const sha256 = (value) => `sha256:${createHash("sha256").update(value).digest("hex")}`;
function invalid() { throw new Error("Invalid preparation input."); }
function exactObject(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype ||
      Object.keys(value).length !== fields.length || fields.some((key) => !Object.hasOwn(value, key))) invalid();
}
function canonicalFilePath(value) {
  if (typeof value !== "string" || !path.isAbsolute(value) || path.normalize(value) !== value ||
      value === path.parse(value).root || [...value].some((character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127)) invalid();
  return value;
}
function argumentsFrom(input) {
  if (input.length !== 4) invalid();
  const retained = {};
  for (let index = 0; index < input.length; index += 2) {
    const flag = input[index];
    if (!["--config", "--output"].includes(flag) || Object.hasOwn(retained, flag)) invalid();
    retained[flag] = canonicalFilePath(input[index + 1]);
  }
  if (!retained["--config"] || !retained["--output"]) invalid();
  return { configuration: retained["--config"], output: retained["--output"] };
}
function statIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size &&
    left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}
function readPrivateConfiguration(filename) {
  const fd = openSync(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  const bytes = Buffer.alloc(maximumConfigurationBytes + 1);
  try {
    const before = fstatSync(fd, { bigint: true });
    if (!before.isFile() || before.uid !== BigInt(process.getuid()) || before.nlink !== 1n ||
        ![0o400, 0o600].includes(Number(before.mode & 0o7777n)) || before.size > BigInt(maximumConfigurationBytes)) invalid();
    let offset = 0;
    while (offset < bytes.byteLength) {
      const amount = readSync(fd, bytes, offset, bytes.byteLength - offset, null);
      if (amount === 0) break;
      offset += amount;
    }
    if (offset > maximumConfigurationBytes || BigInt(offset) !== before.size ||
        !statIdentity(before, fstatSync(fd, { bigint: true }))) invalid();
    const ownedBytes = bytes.subarray(0, offset);
    const configurationDigest = sha256(ownedBytes);
    const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(ownedBytes));
    exactObject(value, configurationFields);
    if (value.schemaVersion !== 1 || typeof value.keyId !== "string" || !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(value.keyId) ||
        typeof value.rootKeyHex !== "string" || !/^[0-9a-f]{64}$/.test(value.rootKeyHex) ||
        !Number.isSafeInteger(value.timeoutMs) || value.timeoutMs < 1 || value.timeoutMs > 30000) invalid();
    exactObject(value.bounds, Object.keys(maxima));
    const bounds = {};
    for (const [key, maximum] of Object.entries(maxima)) {
      const bound = value.bounds[key];
      if (!Number.isSafeInteger(bound) || bound < 1 || bound > maximum) invalid();
      bounds[key] = bound;
    }
    if (typeof value.compatibilityDate !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value.compatibilityDate)) invalid();
    const date = new Date(`${value.compatibilityDate}T00:00:00.000Z`);
    if (!Number.isFinite(date.getTime()) || date.toISOString().slice(0, 10) !== value.compatibilityDate) invalid();
    if (!Array.isArray(value.compatibilityFlags) || value.compatibilityFlags.length > supportedFlags.size) invalid();
    let previous = "";
    const flags = [];
    for (const flag of value.compatibilityFlags) {
      if (typeof flag !== "string" || !supportedFlags.has(flag) || flag <= previous) invalid();
      previous = flag; flags.push(flag);
    }
    return { configurationDigest, keyId: value.keyId, rootKey: Array.from(Buffer.from(value.rootKeyHex, "hex")),
      bounds: Object.freeze(bounds), timeoutMs: value.timeoutMs, compatibilityDate: value.compatibilityDate,
      compatibilityFlags: Object.freeze(flags) };
  } finally { bytes.fill(0); closeSync(fd); }
}
function wrapperSource(config) {
  // These static values are intentionally private. No native signing key,
  // descriptor, proof fixture, or caller-supplied module enters the wrapper.
  return `import { DurableObject } from "cloudflare:workers";
import { createNativeStorageWorker, createNativeStorageDurableObjectClass } from "./workers/state-app/src/native-storage/worker.ts";
const config = Object.freeze({ keyId: ${JSON.stringify(config.keyId)}, rootKey: new Uint8Array(${JSON.stringify(config.rootKey)}), bounds: Object.freeze(${JSON.stringify(config.bounds)}), timeoutMs: ${config.timeoutMs} });
const worker = createNativeStorageWorker(config);
export const NativeStorageQualificationCell = createNativeStorageDurableObjectClass(DurableObject, config);
export default { fetch(request, environment) {
  if (${JSON.stringify(reservedProbePaths)}.includes(new URL(request.url).pathname)) {
    return Promise.resolve(new Response(null, { status: 404, headers: { "cache-control": "no-store" } }));
  }
  return worker.fetch(request, environment);
} };
`;
}
function absentOutput(output) {
  try { lstatSync(output); invalid(); }
  catch (error) { if (error.code !== "ENOENT") throw error; }
  const parent = lstatSync(path.dirname(output));
  if (!parent.isDirectory() || parent.isSymbolicLink() || parent.uid !== process.getuid() ||
      (parent.mode & 0o022) !== 0) invalid();
}
async function prepare(input) {
  // Every input and the complete in-memory bundle are validated before any
  // output directory is created. Existing outputs are never overwritten.
  const config = readPrivateConfiguration(input.configuration);
  absentOutput(input.output);
  let result;
  try {
    result = await build({ stdin: { contents: wrapperSource(config), resolveDir: repository,
      sourcefile: "native-storage-qualification-wrapper.mjs", loader: "js" }, bundle: true, format: "esm",
      platform: "browser", target: "es2022", external: ["cloudflare:workers"], write: false,
      sourcemap: false, metafile: true, logLevel: "silent", legalComments: "none" });
  } finally { config.rootKey.fill(0); }
  if (result.outputFiles.length !== 1 || result.outputFiles[0].contents.byteLength > (32 << 20)) invalid();
  for (const output of Object.values(result.metafile.outputs)) {
    if (output.imports.some((entry) => entry.external && entry.path !== "cloudflare:workers")) invalid();
  }
  const bundle = result.outputFiles[0].contents, bundleDigest = sha256(bundle);
  const wrangler = { name: "circulusd-native-storage-qualification", main: "native-storage.mjs",
    compatibility_date: config.compatibilityDate, compatibility_flags: config.compatibilityFlags,
    durable_objects: { bindings: [{ name: "NATIVE_STORAGE", class_name: "NativeStorageQualificationCell" }] },
    migrations: [{ tag: "v1-native-storage-qualification", new_sqlite_classes: ["NativeStorageQualificationCell"] }] };
  const manifest = { schemaVersion: 1, wrapperVersion, celldCommit, configurationDigest: config.configurationDigest,
    bundleDigest, qualification: "PREPARATION_ONLY", admissionReady: false, stockCelldSufficient: false,
    nativeProbe: "NATIVE_HOST_REQUIRED_WORKER_RETURNS_UNSIGNED_404" };
  const files = { "native-storage.mjs": bundle, "wrangler.json": `${JSON.stringify(wrangler, null, 2)}\n`,
    "manifest.json": `${JSON.stringify(manifest, null, 2)}\n` };
  let directoryFd, directoryIdentity;
  try {
    mkdirSync(input.output, { mode: 0o700 });
    directoryIdentity = lstatSync(input.output);
    directoryFd = openSync(input.output, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    const retained = fstatSync(directoryFd);
    if (!retained.isDirectory() || retained.uid !== process.getuid() ||
        retained.dev !== directoryIdentity.dev || retained.ino !== directoryIdentity.ino) invalid();
    fchmodSync(directoryFd, 0o700);
    for (const [name, contents] of Object.entries(files)) {
      // Pin the created directory while writing. A renamed path must not send
      // the secret-bearing bundle into a substituted directory.
      const fd = openSync(`/proc/self/fd/${directoryFd}/${name}`,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      try { fchmodSync(fd, 0o600); writeFileSync(fd, contents); }
      finally { closeSync(fd); }
    }
  } catch (error) {
    if (directoryIdentity) {
      try {
        const current = lstatSync(input.output);
        if (current.dev === directoryIdentity.dev && current.ino === directoryIdentity.ino) {
          rmSync(input.output, { recursive: true, force: true });
        }
      } catch { /* A changed output path must never be removed. */ }
    }
    throw error;
  } finally { if (directoryFd !== undefined) closeSync(directoryFd); }
  return { bundleDigest, qualification: "PREPARATION_ONLY", admissionReady: false };
}

try {
  if (process.platform !== "linux") invalid();
  const result = await prepare(argumentsFrom(process.argv.slice(2)));
  process.stdout.write(`${JSON.stringify(result)}\n`);
} catch {
  // Do not print argv, config, esbuild diagnostics, stack traces or underlying
  // filesystem errors: any of them may contain private paths or key material.
  process.stderr.write("Native storage preparation failed. Use --config <private-json-file> --output <new-directory>.\n");
  process.exitCode = 1;
}
