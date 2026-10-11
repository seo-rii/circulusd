#!/usr/bin/env node
// Prepare one private local project. This command discovers no services,
// deploys nothing, and cannot sign or grant native production authority.
import { createHash } from "node:crypto";
import { constants, closeSync, fchmodSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const celldCommit = "89e4ffc53a14ecb496d2ca5014ff9d19b0061ad9";
const wrapperVersion = "circulusd.native-state-app-preparation-wrapper/v1";
const maximumConfigurationBytes = 65536;
const maxima = Object.freeze({ maxStateBytes: 16 << 20, maxReceiptResponseBytes: 4 << 20,
  maxCapabilityClaims: 64, maxCapabilityClaimBytes: 1 << 20, maxReceiptLookups: 64,
  maxReceiptWrites: 64, maxTransactionBytes: 32 << 20 });
const supportedFlags = new Set(["delete_all_deletes_alarm", "fetcher_no_get_put_delete", "js_rpc",
  "sqlite_vec", "websocket_standard_binary_type"]);
const roles = Object.freeze({ read: "INGRESS", dispatchStart: "DISPATCH_START", admission: "ADMISSION", broker: "BROKER" });
const bindings = Object.freeze([
  { name: "SESSION_CELL", class_name: "SessionCell" },
  { name: "WORKSPACE_CELL", class_name: "WorkspaceCell" },
  { name: "USER_CELL", class_name: "UserCell" },
  { name: "EXTENSION_STATE_CELL", class_name: "ExtensionStateCell" },
  { name: "CAPABILITY_GENERATION_CELL", class_name: "CapabilityGenerationCell" },
  { name: "AUDIT_CELL", class_name: "AuditCell" },
  { name: "NATIVE_STORAGE", class_name: "NativeStorageQualificationCell" },
]);
const reservedProbePaths = ["/circulusd/native-storage/v1/production:probe", "/circulusd/state/v1/production:probe"];
const sha256 = (value) => `sha256:${createHash("sha256").update(value).digest("hex")}`;
function invalid() { throw new Error("Invalid preparation input."); }
function exactObject(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype ||
      Object.keys(value).length !== fields.length || fields.some((key) => !Object.hasOwn(value, key))) invalid();
}
function integer(value, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) invalid();
}
function canonicalPath(value) {
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
    retained[flag] = canonicalPath(input[index + 1]);
  }
  if (!retained["--config"] || !retained["--output"]) invalid();
  return { configuration: retained["--config"], output: retained["--output"] };
}
function statIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size &&
    left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}
function credential(value, ids, materials, storage = false) {
  exactObject(value, ["keyId", "rootKeyHex"]);
  if (typeof value.keyId !== "string" || !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(value.keyId) ||
      typeof value.rootKeyHex !== "string" || !/^[0-9a-f]+$/.test(value.rootKeyHex) ||
      value.rootKeyHex.length % 2 !== 0 || value.rootKeyHex.length < 64 || value.rootKeyHex.length > (storage ? 64 : 512) ||
      ids.has(value.keyId) || materials.has(value.rootKeyHex)) invalid();
  ids.add(value.keyId); materials.add(value.rootKeyHex);
  return { keyId: value.keyId, rootKeyHex: value.rootKeyHex };
}
function validateConfiguration(value, configurationDigest) {
  exactObject(value, ["schemaVersion", "compatibilityDate", "compatibilityFlags", "ingressCredentials",
    "admissionPolicy", "brokerPolicy", "nativeStorage"]);
  if (value.schemaVersion !== 1) invalid();
  if (typeof value.compatibilityDate !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value.compatibilityDate)) invalid();
  const date = new Date(`${value.compatibilityDate}T00:00:00.000Z`);
  if (!Number.isFinite(date.getTime()) || date.toISOString().slice(0, 10) !== value.compatibilityDate) invalid();
  if (!Array.isArray(value.compatibilityFlags) || value.compatibilityFlags.length > supportedFlags.size) invalid();
  let previous = "";
  for (const flag of value.compatibilityFlags) {
    if (typeof flag !== "string" || !supportedFlags.has(flag) || flag <= previous) invalid();
    previous = flag;
  }
  // The served ingress invokes existing CELL RPC methods, not fetch adapters.
  if (!value.compatibilityFlags.includes("js_rpc")) invalid();
  exactObject(value.ingressCredentials, Object.keys(roles));
  const ids = new Set(), materials = new Set(), ingressEnvironment = {};
  for (const [role, suffix] of Object.entries(roles)) {
    const configured = value.ingressCredentials[role];
    exactObject(configured, ["current", "previous"]);
    for (const [generation, key] of Object.entries(configured)) {
      if (generation === "previous" && key === null) continue;
      const retained = credential(key, ids, materials);
      const prefix = `CIRCULUSD_STATE_${suffix}_${generation.toUpperCase()}`;
      ingressEnvironment[`${prefix}_KEY_ID`] = retained.keyId;
      ingressEnvironment[`${prefix}_KEY`] = retained.rootKeyHex;
    }
  }
  exactObject(value.admissionPolicy, ["turnLeaseTTLms"]);
  integer(value.admissionPolicy.turnLeaseTTLms, 300000);
  exactObject(value.brokerPolicy, ["engineStepLimits", "preparationTTLms"]);
  exactObject(value.brokerPolicy.engineStepLimits, ["maximumEvents", "maximumEphemeralBytes", "maximumWallClockMs"]);
  if (value.brokerPolicy.engineStepLimits.maximumEvents !== 1) invalid();
  integer(value.brokerPolicy.engineStepLimits.maximumEphemeralBytes);
  integer(value.brokerPolicy.engineStepLimits.maximumWallClockMs);
  integer(value.brokerPolicy.preparationTTLms);
  exactObject(value.nativeStorage, ["keyId", "rootKeyHex", "bounds", "timeoutMs"]);
  const storageCredential = credential({ keyId: value.nativeStorage.keyId, rootKeyHex: value.nativeStorage.rootKeyHex }, ids, materials, true);
  integer(value.nativeStorage.timeoutMs, 30000);
  exactObject(value.nativeStorage.bounds, Object.keys(maxima));
  for (const [key, maximum] of Object.entries(maxima)) integer(value.nativeStorage.bounds[key], maximum);
  return { configurationDigest, compatibilityDate: value.compatibilityDate,
    compatibilityFlags: [...value.compatibilityFlags], ingressEnvironment,
    admissionPolicy: structuredClone(value.admissionPolicy), brokerPolicy: structuredClone(value.brokerPolicy),
    nativeStorage: { keyId: storageCredential.keyId, rootKey: Array.from(Buffer.from(storageCredential.rootKeyHex, "hex")),
      bounds: structuredClone(value.nativeStorage.bounds), timeoutMs: value.nativeStorage.timeoutMs } };
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
    return validateConfiguration(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(ownedBytes)), sha256(ownedBytes));
  } finally { bytes.fill(0); closeSync(fd); }
}
function wrapperSource(config) {
  return `import { DurableObject } from "cloudflare:workers";
import stateWorker from "./workers/state-app/src/host/worker.ts";
export { AuditCell, CapabilityGenerationCell, ExtensionStateCell, SessionCell, UserCell, WorkspaceCell } from "./workers/state-app/src/host/worker.ts";
import { createNativeStorageWorker, createNativeStorageDurableObjectClass } from "./workers/state-app/src/native-storage/worker.ts";
import { TRANSACTION_PATH } from "./workers/state-app/src/native-storage/codec.ts";
const ingressCredentials = Object.freeze(${JSON.stringify(config.ingressEnvironment)});
const storageConfig = Object.freeze({ keyId: ${JSON.stringify(config.nativeStorage.keyId)}, rootKey: new Uint8Array(${JSON.stringify(config.nativeStorage.rootKey)}), bounds: Object.freeze(${JSON.stringify(config.nativeStorage.bounds)}), timeoutMs: ${config.nativeStorage.timeoutMs} });
const storageWorker = createNativeStorageWorker(storageConfig);
export const NativeStorageQualificationCell = createNativeStorageDurableObjectClass(DurableObject, storageConfig);
function namespaceSnapshot(environment) {
  if (!environment || typeof environment !== "object") return null;
  const retained = Object.create(null), identities = new Set();
  for (const name of ${JSON.stringify(bindings.map((binding) => binding.name))}) {
    const namespace = environment[name];
    if (!namespace || typeof namespace !== "object" || typeof namespace.idFromName !== "function" ||
        typeof namespace.get !== "function" || identities.has(namespace)) return null;
    identities.add(namespace); retained[name] = namespace;
  }
  if (typeof retained.SESSION_CELL.getByName !== "function") return null;
  return Object.freeze(retained);
}
export default { fetch(request, environment) {
  const pathname = new URL(request.url).pathname;
  if (${JSON.stringify(reservedProbePaths)}.includes(pathname)) {
    return Promise.resolve(new Response(null, { status: 404, headers: { "cache-control": "no-store" } }));
  }
  const namespaces = namespaceSnapshot(environment);
  if (namespaces === null) return Promise.resolve(new Response(null, { status: 503, headers: { "cache-control": "no-store" } }));
  if (pathname === TRANSACTION_PATH) return storageWorker.fetch(request, Object.freeze({ NATIVE_STORAGE: namespaces.NATIVE_STORAGE }));
  return stateWorker.fetch(request, Object.freeze({ ...ingressCredentials, SESSION_CELL: namespaces.SESSION_CELL }));
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
  const config = readPrivateConfiguration(input.configuration);
  absentOutput(input.output);
  let result;
  try {
    result = await build({ stdin: { contents: wrapperSource(config), resolveDir: repository,
      sourcefile: "native-state-app-preparation-wrapper.mjs", loader: "js" }, bundle: true, format: "esm",
      platform: "browser", target: "es2022", external: ["cloudflare:workers"], write: false,
      sourcemap: false, metafile: true, logLevel: "silent", legalComments: "none" });
  } finally { config.nativeStorage.rootKey.fill(0); }
  if (result.outputFiles.length !== 1 || result.outputFiles[0].contents.byteLength > (32 << 20)) invalid();
  for (const output of Object.values(result.metafile.outputs)) {
    if (output.imports.some((entry) => entry.external && entry.path !== "cloudflare:workers")) invalid();
  }
  const bundle = result.outputFiles[0].contents, bundleDigest = sha256(bundle);
  const wrangler = { name: "circulusd-native-state-app", main: "native-state-app.mjs",
    compatibility_date: config.compatibilityDate, compatibility_flags: config.compatibilityFlags,
    vars: { CIRCULUSD_STATE_ADMISSION_POLICY: JSON.stringify(config.admissionPolicy),
      CIRCULUSD_STATE_BROKER_POLICY: JSON.stringify(config.brokerPolicy) },
    durable_objects: { bindings },
    migrations: [{ tag: "v1-native-state-app-qualification", new_sqlite_classes: bindings.map((binding) => binding.class_name) }] };
  const manifest = { schemaVersion: 1, wrapperVersion, celldCommit, configurationDigest: config.configurationDigest,
    bundleDigest, qualification: "PREPARATION_ONLY", admissionReady: false, stockCelldSufficient: false,
    nativeProbe: "NATIVE_HOST_REQUIRED_WORKER_RETURNS_UNSIGNED_404", cells: bindings.map((binding) => binding.class_name),
    ingressRoles: Object.keys(roles), nativeStorageQualificationIncluded: true };
  const files = { "native-state-app.mjs": bundle, "wrangler.json": `${JSON.stringify(wrangler, null, 2)}\n`,
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
      const fd = openSync(`/proc/self/fd/${directoryFd}/${name}`,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      try { fchmodSync(fd, 0o600); writeFileSync(fd, contents); fsyncSync(fd); }
      finally { closeSync(fd); }
    }
    fsyncSync(directoryFd);
  } catch (error) {
    if (directoryIdentity) {
      try {
        const current = lstatSync(input.output);
        if (current.dev === directoryIdentity.dev && current.ino === directoryIdentity.ino) rmSync(input.output, { recursive: true, force: true });
      } catch { /* Never remove a changed output path. */ }
    }
    throw error;
  } finally { if (directoryFd !== undefined) closeSync(directoryFd); }
  return { bundleDigest, qualification: "PREPARATION_ONLY", admissionReady: false };
}

try {
  if (process.platform !== "linux") invalid();
  process.stdout.write(`${JSON.stringify(await prepare(argumentsFrom(process.argv.slice(2))))}\n`);
} catch {
  // No argv, configuration, bundler diagnostic or filesystem error is printed.
  process.stderr.write("Native state-app preparation failed. Use --config <private-json-file> --output <new-directory>.\n");
  process.exitCode = 1;
}
