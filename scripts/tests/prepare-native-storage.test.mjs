import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const script = path.join(repository, "scripts/prepare-native-storage.mjs");
const rootKeyHex = "25".repeat(32);
const bounds = { maxStateBytes: 1024, maxReceiptResponseBytes: 1024, maxCapabilityClaims: 4,
  maxCapabilityClaimBytes: 1024, maxReceiptLookups: 4, maxReceiptWrites: 4, maxTransactionBytes: 32768 };
const validConfig = () => ({ schemaVersion: 1, keyId: "native-storage-test", rootKeyHex, bounds: { ...bounds },
  timeoutMs: 1000, compatibilityDate: "2026-08-01", compatibilityFlags: [] });
function fixture(t, config = validConfig()) {
  const directory = mkdtempSync(path.join(tmpdir(), "circulusd-native-storage-builder-"));
  chmodSync(directory, 0o700);
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const configuration = path.join(directory, "private.json"), output = path.join(directory, "project");
  writeFileSync(configuration, JSON.stringify(config), { mode: 0o600 });
  return { directory, configuration, output };
}
function run(input, extra = []) {
  try {
    return { status: 0, stdout: execFileSync(process.execPath,
      [script, "--config", input.configuration, "--output", input.output, ...extra],
      { cwd: repository, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }), stderr: "" };
  } catch (error) {
    return { status: error.status, stdout: String(error.stdout ?? ""), stderr: String(error.stderr ?? "") };
  }
}
function rejected(input) {
  const result = run(input);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /^Native storage preparation failed\./);
  assert.equal(result.stdout, "");
  assert.equal(existsSync(input.output), false);
  assert.equal((result.stdout + result.stderr).includes(rootKeyHex), false);
}
const digest = (value) => `sha256:${createHash("sha256").update(value).digest("hex")}`;

test("rejects unknown/private-proof fields and malformed exact configuration before output writes", (t) => {
  const changes = [
    (config) => { config.nativePrivateKey = rootKeyHex; },
    (config) => { config.descriptor = { productionEligible: true }; },
    (config) => { delete config.bounds; },
    (config) => { config.bounds.extra = 1; },
    (config) => { delete config.bounds.maxReceiptWrites; },
    (config) => { config.schemaVersion = 2; },
    (config) => { config.keyId = "Invalid/key"; },
    (config) => { config.rootKeyHex = "25".repeat(31); },
    (config) => { config.rootKeyHex = "AB".repeat(32); },
    (config) => { config.timeoutMs = 30001; },
    (config) => { config.compatibilityDate = "2026-02-30"; },
    (config) => { config.compatibilityFlags = ["nodejs_compat"]; },
    (config) => { config.compatibilityFlags = ["js_rpc", "delete_all_deletes_alarm"]; },
    (config) => { config.compatibilityFlags = ["js_rpc", "js_rpc"]; },
  ];
  for (const change of changes) {
    const config = validConfig(); change(config); rejected(fixture(t, config));
  }
});

test("rejects zero, fraction and over-limit bounds without creating output", (t) => {
  const maxima = { maxStateBytes: 16 << 20, maxReceiptResponseBytes: 4 << 20, maxCapabilityClaims: 64,
    maxCapabilityClaimBytes: 1 << 20, maxReceiptLookups: 64, maxReceiptWrites: 64, maxTransactionBytes: 32 << 20 };
  for (const [key, maximum] of Object.entries(maxima)) {
    for (const value of [0, 1.5, maximum + 1]) {
      const config = validConfig(); config.bounds[key] = value; rejected(fixture(t, config));
    }
  }
});

test("rejects public, symlinked and oversized input files without touching output", (t) => {
  const publicInput = fixture(t); chmodSync(publicInput.configuration, 0o644); rejected(publicInput);
  const linkedInput = fixture(t), link = path.join(linkedInput.directory, "linked.json");
  symlinkSync(linkedInput.configuration, link); rejected({ ...linkedInput, configuration: link });
  const hardlinked = fixture(t); linkSync(hardlinked.configuration, path.join(hardlinked.directory, "hardlink.json")); rejected(hardlinked);
  const oversized = fixture(t); writeFileSync(oversized.configuration, " ".repeat(65537)); rejected(oversized);
  const malformed = fixture(t); writeFileSync(malformed.configuration, `{ "rootKeyHex": "${rootKeyHex}", broken`); rejected(malformed);
});

test("refuses an existing output directory and preserves its contents", (t) => {
  const input = fixture(t); mkdirSync(input.output, { mode: 0o700 });
  const marker = path.join(input.output, "unrelated.txt");
  writeFileSync(marker, "existing unrelated file", { mode: 0o600 });
  const result = run(input);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, "");
  assert.equal(readFileSync(marker, "utf8"), "existing unrelated file");
  assert.deepEqual(readdirSync(input.output), ["unrelated.txt"]);
  assert.equal((result.stdout + result.stderr).includes(rootKeyHex), false);
});

test("refuses nonexclusive output parents and symlink output paths before writing", (t) => {
  const writableParent = fixture(t); chmodSync(writableParent.directory, 0o777); rejected(writableParent);
  const linked = fixture(t), destination = path.join(linked.directory, "existing");
  mkdirSync(destination, { mode: 0o700 }); symlinkSync(destination, linked.output);
  const result = run(linked); assert.equal(result.status, 1); assert.deepEqual(readdirSync(destination), []);
  assert.equal((result.stdout + result.stderr).includes(rootKeyHex), false);
});

test("accepts only path arguments and never reflects invalid arguments into logs", (t) => {
  const input = fixture(t);
  const result = run(input, ["--native-private-key", rootKeyHex]);
  assert.equal(result.status, 1);
  assert.equal(existsSync(input.output), false);
  assert.equal((result.stdout + result.stderr).includes(rootKeyHex), false);
});

test("creates private self-contained deployment files and digest-only public metadata", (t) => {
  const config = validConfig(); config.compatibilityFlags = ["delete_all_deletes_alarm", "js_rpc"];
  const input = fixture(t, config), result = run(input);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(readdirSync(input.output).sort(), ["manifest.json", "native-storage.mjs", "wrangler.json"]);
  assert.equal(statSync(input.output).mode & 0o777, 0o700);
  for (const file of readdirSync(input.output)) assert.equal(statSync(path.join(input.output, file)).mode & 0o777, 0o600);
  const bundle = readFileSync(path.join(input.output, "native-storage.mjs"));
  const configuration = JSON.parse(readFileSync(path.join(input.output, "wrangler.json"), "utf8"));
  assert.deepEqual(configuration, { name: "circulusd-native-storage-qualification", main: "native-storage.mjs",
    compatibility_date: config.compatibilityDate, compatibility_flags: config.compatibilityFlags,
    durable_objects: { bindings: [{ name: "NATIVE_STORAGE", class_name: "NativeStorageQualificationCell" }] },
    migrations: [{ tag: "v1-native-storage-qualification", new_sqlite_classes: ["NativeStorageQualificationCell"] }] });
  const manifest = JSON.parse(readFileSync(path.join(input.output, "manifest.json"), "utf8"));
  assert.equal(manifest.schemaVersion, 1);
  assert.equal(manifest.wrapperVersion, "circulusd.native-storage-qualification-wrapper/v1");
  assert.equal(manifest.celldCommit, "89e4ffc53a14ecb496d2ca5014ff9d19b0061ad9");
  assert.equal(manifest.configurationDigest, digest(readFileSync(input.configuration)));
  assert.equal(manifest.bundleDigest, digest(bundle));
  assert.equal(manifest.admissionReady, false);
  assert.equal(manifest.qualification, "PREPARATION_ONLY");
  assert.equal(manifest.nativeProbe, "NATIVE_HOST_REQUIRED_WORKER_RETURNS_UNSIGNED_404");
  assert.equal(manifest.stockCelldSufficient, false);
  assert.deepEqual(JSON.parse(result.stdout), { bundleDigest: digest(bundle), qualification: "PREPARATION_ONLY", admissionReady: false });
  for (const publicText of [result.stdout, result.stderr, JSON.stringify(manifest), JSON.stringify(configuration)]) {
    assert.equal(publicText.includes(rootKeyHex), false);
    assert.equal(publicText.includes(input.configuration), false);
    assert.equal(publicText.includes(config.keyId), false);
  }
});

test("generated actual Worker/DO bundle authenticates native kernel operations and leaves both probe routes unsigned 404", async (t) => {
  const input = fixture(t), result = run(input);
  assert.equal(result.status, 0, result.stderr);
  const base = `data:text/javascript;base64,${Buffer.from("export class DurableObject { constructor(ctx, env) { this.ctx = ctx; this.env = env; } }").toString("base64")}`;
  const source = readFileSync(path.join(input.output, "native-storage.mjs"), "utf8");
  assert.match(source, /from "cloudflare:workers"/);
  const executable = source.replaceAll('"cloudflare:workers"', JSON.stringify(base));
  const generated = await import(`data:text/javascript;base64,${Buffer.from(executable).toString("base64")}`);
  assert.deepEqual(Object.keys(generated).sort(), ["NativeStorageQualificationCell", "default"]);
  const helper = await build({ stdin: { contents: `export * from "./workers/state-app/src/native-storage/codec.ts";`,
    resolveDir: repository, sourcefile: "codec-test.ts" }, bundle: true, format: "esm", platform: "browser", target: "es2022", write: false, logLevel: "silent" });
  const codec = await import(`data:text/javascript;base64,${Buffer.from(helper.outputFiles[0].contents).toString("base64")}`);
  const id = { equals: (other) => other === id, toString: () => "physical-native-fixture" };
  const values = new Map(); let transactions = 0, routes = 0;
  const state = { id, storage: { transaction: async (callback) => {
    transactions++; const staged = structuredClone(values);
    const tx = { get: async (key) => structuredClone(staged.get(key)), put: async (key, value) => staged.set(key, structuredClone(value)), delete: async (key) => staged.delete(key) };
    const returned = await callback(tx); values.clear(); for (const [key, value] of staged) values.set(key, value); return returned;
  } } };
  let cell;
  const namespace = { idFromName: () => id, get: (candidate) => {
    assert.equal(candidate, id); routes++; return { fetch: (request) => cell.fetch(request) };
  } };
  const environment = { NATIVE_STORAGE: namespace };
  cell = new generated.NativeStorageQualificationCell(state, environment);
  assert.equal(cell.ctx, state); assert.equal(cell.env, environment);
  for (const probe of ["/circulusd/native-storage/v1/production:probe", "/circulusd/state/v1/production:probe"]) {
    const response = await generated.default.fetch(new Request(`http://native.local${probe}`, { method: "POST", body: new Uint8Array([1]) }), environment);
    assert.equal(response.status, 404); assert.equal(response.headers.get(codec.SIGNATURE_HEADER), null);
    assert.equal(response.headers.get("cache-control"), "no-store");
  }
  assert.equal(transactions, 0); assert.equal(routes, 0);
  const keys = await codec.storageDirectionalKeys(Uint8Array.from(Buffer.from(rootKeyHex, "hex")));
  async function exchange(operation, body) {
    const envelope = { protocol: codec.STORAGE_PROTOCOL, major: 1, minor: 0, schemaDigest: codec.STORAGE_SCHEMA,
      requestId: "req_AAAAAAAAAAAAAAAAAAAAAAAAAA", sentAtUnixMs: Date.now(), operation, body };
    const bytes = codec.encodeWire(envelope);
    const request = new Request(`http://native.local${codec.TRANSACTION_PATH}`, { method: "POST", body: bytes,
      headers: { "content-type": codec.TRANSACTION_TYPE, [codec.KEY_HEADER]: "native-storage-test",
        [codec.SIGNATURE_HEADER]: await codec.storageRequestMac(keys.request, "native-storage-test", bytes) } });
    const response = await generated.default.fetch(request, environment);
    const returned = new Uint8Array(await response.arrayBuffer());
    assert.equal(response.headers.get(codec.SIGNATURE_HEADER), await codec.storageResponseMac(keys.response, "native-storage-test", envelope.requestId, bytes, response.status, returned));
    assert.equal(response.status, 200); return codec.decodeWire(returned).payload.result;
  }
  const first = await exchange("snapshot", { objectId: "native-test-object" });
  assert.equal(first.snapshot.exists, false);
  const commit = { snapshot: first.snapshot, stateWritten: true, state: new Uint8Array([1, 9, 3]), receipts: [] };
  commit.requestDigest = await codec.commitDigest(commit);
  const committed = await exchange("commit", commit);
  assert.equal(committed.snapshot.revision, 1);
  const barrier = await exchange("barrier", { token: committed.token, marker: new Uint8Array(32).fill(7) });
  assert.equal(barrier.observedRevision, 1);
  assert.equal(barrier.barrierSerial, 1);
  const snapshot = await exchange("snapshot", { objectId: "native-test-object" });
  assert.deepEqual(snapshot.state, new Uint8Array([1, 9, 3]));
  assert.equal(routes, 4); assert.ok(transactions >= 4); assert.ok(values.size > 0);
});
