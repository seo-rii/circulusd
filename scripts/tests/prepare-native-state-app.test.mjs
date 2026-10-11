import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, createHmac } from "node:crypto";
import { chmodSync, existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const script = path.join(repository, "scripts/prepare-native-state-app.mjs");
const roleNames = ["read", "dispatchStart", "admission", "broker"];
const bindingNames = ["SESSION_CELL", "WORKSPACE_CELL", "USER_CELL", "EXTENSION_STATE_CELL", "CAPABILITY_GENERATION_CELL", "AUDIT_CELL", "NATIVE_STORAGE"];
const classNames = ["SessionCell", "WorkspaceCell", "UserCell", "ExtensionStateCell", "CapabilityGenerationCell", "AuditCell", "NativeStorageQualificationCell"];
const digest = (bytes) => `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
const identity = (kind) => `${kind}_${"A".repeat(26)}`;
function validConfig() {
  return { schemaVersion: 1, compatibilityDate: "2026-08-01", compatibilityFlags: ["js_rpc"],
    ingressCredentials: Object.fromEntries(roleNames.map((role, index) => [role,
      { current: { keyId: `private-${role.toLowerCase()}-current`, rootKeyHex: (0x31 + index).toString(16).repeat(32) }, previous: null }])),
    admissionPolicy: { turnLeaseTTLms: 15000 },
    brokerPolicy: { engineStepLimits: { maximumEvents: 1, maximumEphemeralBytes: 65536, maximumWallClockMs: 1000 }, preparationTTLms: 30000 },
    nativeStorage: { keyId: "private-native-storage", rootKeyHex: "79".repeat(32), timeoutMs: 1000,
      bounds: { maxStateBytes: 1024, maxReceiptResponseBytes: 1024, maxCapabilityClaims: 4,
        maxCapabilityClaimBytes: 1024, maxReceiptLookups: 4, maxReceiptWrites: 4, maxTransactionBytes: 32768 } } };
}
function fixture(t, config = validConfig()) {
  const directory = mkdtempSync(path.join(tmpdir(), "circulusd-native-state-app-builder-"));
  chmodSync(directory, 0o700);
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const configuration = path.join(directory, "private.json"), output = path.join(directory, "project");
  writeFileSync(configuration, JSON.stringify(config), { mode: 0o600 });
  return { directory, configuration, output, config };
}
function run(input, extra = []) {
  try {
    return { status: 0, stdout: execFileSync(process.execPath, [script, "--config", input.configuration, "--output", input.output, ...extra],
      { cwd: repository, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }), stderr: "" };
  } catch (error) { return { status: error.status, stdout: String(error.stdout ?? ""), stderr: String(error.stderr ?? "") }; }
}
function noSecrets(text, input) {
  for (const role of roleNames) {
    for (const key of Object.values(input.config.ingressCredentials[role] ?? {})) {
      if (key) { assert.equal(text.includes(key.rootKeyHex), false); assert.equal(text.includes(key.keyId), false); }
    }
  }
  assert.equal(text.includes(input.config.nativeStorage.rootKeyHex), false);
  assert.equal(text.includes(input.config.nativeStorage.keyId), false);
  assert.equal(text.includes(input.configuration), false);
}
function rejected(input, extra = []) {
  const result = run(input, extra);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, "");
  assert.match(result.stderr, /^Native state-app preparation failed\./);
  assert.equal(existsSync(input.output), false);
  noSecrets(result.stdout + result.stderr, input);
}

test("rejects caller proof authority, namespace overrides, invalid policies and unsupported compatibility flags before writing", (t) => {
  for (const change of [
    (c) => { c.nativePrivateKey = "ff".repeat(32); }, (c) => { c.descriptor = { productionEligible: true }; },
    (c) => { c.SESSION_CELL = "shadow"; }, (c) => { c.nativeStorage.nativeProbe = {}; },
    (c) => { c.ingressCredentials.read.SESSION_CELL = "shadow"; }, (c) => { delete c.ingressCredentials.broker; },
    (c) => { c.ingressCredentials.read.current.keyId = "bad/key"; }, (c) => { c.ingressCredentials.read.current.rootKeyHex = "AB".repeat(32); },
    (c) => { c.compatibilityFlags = []; }, (c) => { c.compatibilityFlags = ["nodejs_compat"]; },
    (c) => { c.compatibilityFlags = ["js_rpc", "delete_all_deletes_alarm"]; }, (c) => { c.compatibilityFlags = ["js_rpc", "js_rpc"]; },
    (c) => { c.compatibilityDate = "2026-02-30"; }, (c) => { c.admissionPolicy.turnLeaseTTLms = 300001; },
    (c) => { c.brokerPolicy.engineStepLimits.maximumEvents = 2; }, (c) => { c.brokerPolicy.preparationTTLms = 0; },
    (c) => { c.nativeStorage.timeoutMs = 30001; }, (c) => { c.nativeStorage.bounds.maxStateBytes = (16 << 20) + 1; },
  ]) { const config = validConfig(); change(config); rejected(fixture(t, config)); }
});

test("rejects credential aliases across all current/previous ingress roles and native storage", (t) => {
  for (const change of [
    (c) => { c.ingressCredentials.broker.current.keyId = c.ingressCredentials.read.current.keyId; },
    (c) => { c.ingressCredentials.admission.current.rootKeyHex = c.ingressCredentials.dispatchStart.current.rootKeyHex; },
    (c) => { c.ingressCredentials.read.previous = { ...c.ingressCredentials.broker.current }; },
    (c) => { c.ingressCredentials.read.previous = { ...c.ingressCredentials.read.current }; },
    (c) => { c.nativeStorage.rootKeyHex = c.ingressCredentials.read.current.rootKeyHex; },
    (c) => { c.nativeStorage.keyId = c.ingressCredentials.broker.current.keyId; },
  ]) { const config = validConfig(); change(config); rejected(fixture(t, config)); }
});

test("refuses unsafe input files, extra arguments and nonexclusive output parents", (t) => {
  const publicInput = fixture(t); chmodSync(publicInput.configuration, 0o644); rejected(publicInput);
  const linked = fixture(t), link = path.join(linked.directory, "link.json"); symlinkSync(linked.configuration, link); rejected({ ...linked, configuration: link });
  const hardlinked = fixture(t); linkSync(hardlinked.configuration, path.join(hardlinked.directory, "other.json")); rejected(hardlinked);
  const oversized = fixture(t); writeFileSync(oversized.configuration, " ".repeat(65537)); rejected(oversized);
  const invalidUtf8 = fixture(t); writeFileSync(invalidUtf8.configuration, Buffer.from([0xff])); rejected(invalidUtf8);
  const publicParent = fixture(t); chmodSync(publicParent.directory, 0o777); rejected(publicParent);
  const invalidArgs = fixture(t); rejected(invalidArgs, ["--private-key", "ff".repeat(32)]);
});

test("retains private exact graph files and digest-only metadata without overwriting an existing project", (t) => {
  const input = fixture(t), result = run(input);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(readdirSync(input.output).sort(), ["manifest.json", "native-state-app.mjs", "wrangler.json"]);
  assert.equal(statSync(input.output).mode & 0o7777, 0o700);
  for (const file of readdirSync(input.output)) assert.equal(statSync(path.join(input.output, file)).mode & 0o7777, 0o600);
  const bundle = readFileSync(path.join(input.output, "native-state-app.mjs"));
  const wrangler = JSON.parse(readFileSync(path.join(input.output, "wrangler.json"))), manifest = JSON.parse(readFileSync(path.join(input.output, "manifest.json")));
  assert.deepEqual(wrangler.durable_objects.bindings, bindingNames.map((name, index) => ({ name, class_name: classNames[index] })));
  assert.deepEqual(wrangler.migrations[0].new_sqlite_classes, classNames);
  assert.deepEqual(JSON.parse(wrangler.vars.CIRCULUSD_STATE_ADMISSION_POLICY), input.config.admissionPolicy);
  assert.deepEqual(JSON.parse(wrangler.vars.CIRCULUSD_STATE_BROKER_POLICY), input.config.brokerPolicy);
  assert.deepEqual(wrangler.compatibility_flags, ["js_rpc"]);
  assert.equal(manifest.bundleDigest, digest(bundle));
  assert.equal(manifest.configurationDigest, digest(readFileSync(input.configuration)));
  assert.equal(manifest.nativeStorageQualificationIncluded, true);
  assert.equal(manifest.qualification, "PREPARATION_ONLY"); assert.equal(manifest.admissionReady, false);
  assert.deepEqual(JSON.parse(result.stdout), { bundleDigest: digest(bundle), qualification: "PREPARATION_ONLY", admissionReady: false });
  noSecrets(result.stdout + result.stderr + JSON.stringify(wrangler) + JSON.stringify(manifest), input);
  const again = run(input); assert.equal(again.status, 1); assert.equal(readFileSync(path.join(input.output, "native-state-app.mjs")).equals(bundle), true);
  const existing = fixture(t); mkdirSync(existing.output, { mode: 0o700 }); writeFileSync(path.join(existing.output, "marker"), "preserve");
  assert.equal(run(existing).status, 1); assert.deepEqual(readdirSync(existing.output), ["marker"]);
});

async function loadBundle(input) {
  assert.equal(run(input).status, 0);
  const base = `data:text/javascript;base64,${Buffer.from("export class DurableObject { constructor(ctx, env) { this.ctx = ctx; this.env = env; } }").toString("base64")}`;
  const source = readFileSync(path.join(input.output, "native-state-app.mjs"), "utf8").replaceAll('"cloudflare:workers"', JSON.stringify(base));
  return import(`data:text/javascript;base64,${Buffer.from(source).toString("base64")}`);
}
async function helpers() {
  const result = await build({ stdin: { contents: `export { encodeCanonicalCbor, decodeCanonicalCbor } from "./packages/protocol-types/src/index.ts";
export { HOST_RPC_CONTRACTS } from "./workers/state-app/src/host/rpc.ts";
export { sessionCellName } from "./workers/state-app/src/host/names.ts";
export * as storage from "./workers/state-app/src/native-storage/codec.ts";`, resolveDir: repository, sourcefile: "state-app-test.ts" },
    bundle: true, format: "esm", platform: "browser", target: "es2022", write: false, logLevel: "silent" });
  return import(`data:text/javascript;base64,${Buffer.from(result.outputFiles[0].contents).toString("base64")}`);
}
function transactionalState(id) {
  const values = new Map();
  return { id, values, storage: { transaction: async (callback) => {
    const staged = structuredClone(values);
    const result = await callback({ get: async (key) => structuredClone(staged.get(key)),
      put: async (key, value) => staged.set(key, structuredClone(value)), delete: async (key) => staged.delete(key) });
    values.clear(); for (const [key, value] of staged) values.set(key, value); return result;
  } } };
}
function environment(input) {
  const env = JSON.parse(readFileSync(path.join(input.output, "wrangler.json"))).vars;
  for (const name of bindingNames) {
    const idFromName = (value) => ({ toString: () => value, equals: (other) => String(other) === value });
    env[name] = { idFromName, get: () => { throw new Error("Unexpected fixture route"); }, getByName: () => { throw new Error("Unexpected fixture route"); } };
  }
  return env;
}
function framed(parts) {
  return Buffer.concat(parts.flatMap((part) => { const bytes = Buffer.from(part), length = Buffer.alloc(4); length.writeUInt32BE(bytes.byteLength); return [length, bytes]; }));
}
function ingressMac(key, direction, parts) {
  const directional = createHmac("sha256", Buffer.from(key.rootKeyHex, "hex")).update(`circulusd.state-ingress.key.${direction}.v1\0`).digest();
  return createHmac("sha256", directional).update(framed(parts)).digest("hex");
}
function readRequest(helper, key, overrides = {}) {
  const pathname = "/circulusd/state/v1/session-events:read";
  const value = { protocol: "circulus.state-ingress.v1alpha1", major: 1, minor: 0,
    schemaDigest: "sha256:6365dfa4e6e73b349508a46688cfcaacdeacece11cd11ed2d7f3e40af49ad3ee",
    requestId: identity("req"), sentAtUnixMs: Date.now(), tenantId: identity("tenant"), actorSubjectId: identity("subject"),
    sessionId: identity("sess"), expectedAuthorizationGeneration: 7, afterSequence: 0, limit: 16, ...overrides };
  const body = helper.encodeCanonicalCbor(value);
  const mac = ingressMac(key, "request", ["circulusd.state-ingress.request.v1", key.keyId, "POST", pathname, createHash("sha256").update(body).digest()]);
  return { value, body, request: new Request(`http://native.local${pathname}`, { method: "POST", body,
    headers: { "content-type": "application/vnd.circulusd.state-ingress+cbor", "x-circulus-state-key-id": key.keyId, "x-circulus-state-signature": mac } }) };
}

test("actual bundle preserves six CELL classes, existing Session initialization/read RPC and unsigned native probe ownership", async (t) => {
  const config = validConfig(); config.ingressCredentials.read.previous = { keyId: "private-read-previous", rootKeyHex: "42".repeat(48) };
  const input = fixture(t, config), generated = await loadBundle(input), helper = await helpers(), env = environment(input);
  assert.deepEqual(Object.keys(generated).sort(), [...classNames, "default"].sort());
  const state = transactionalState(env.SESSION_CELL.idFromName(helper.sessionCellName(identity("tenant"), identity("sess"))));
  const cell = new generated.SessionCell(state, env);
  for (const index of [1, 2, 3, 4, 5]) {
    const other = new generated[classNames[index]](transactionalState(env[bindingNames[index]].idFromName(`physical-${index}`)), env);
    assert.equal(other.env, env);
  }
  const initialized = await cell.initializeSession({ protocol: "circulus.v1alpha1", major: 1, minor: 0,
    schemaDigest: helper.HOST_RPC_CONTRACTS["session.initialize"].schemaDigest, requestId: identity("req"), payload: {
      sessionId: identity("sess"), tenantId: identity("tenant"), userId: identity("subject"), workspaceId: identity("ws"),
      runtimeRevisionDigest: `sha256:${"a".repeat(64)}`, policySnapshotDigest: `sha256:${"2".repeat(64)}`, emergencyOverlayDigest: `sha256:${"3".repeat(64)}`,
      engineKind: "low-level", adapterAbiVersion: 2, checkpointSchemaVersion: 2, placementGeneration: 0, sandboxGeneration: 0, authorizationGeneration: 7,
    } });
  assert.equal(initialized.payload.ok, true, JSON.stringify(initialized));
  let hostCalls = 0;
  env.SESSION_CELL.getByName = (name) => { assert.equal(name, String(state.id)); hostCalls++; return cell; };
  // Caller environment credentials are ignored; the private immutable snapshot wins.
  env.CIRCULUSD_STATE_INGRESS_CURRENT_KEY_ID = config.ingressCredentials.broker.current.keyId;
  env.CIRCULUSD_STATE_INGRESS_CURRENT_KEY = config.ingressCredentials.broker.current.rootKeyHex;
  for (const key of [config.ingressCredentials.read.current, config.ingressCredentials.read.previous]) {
    const signed = readRequest(helper, key), response = await generated.default.fetch(signed.request, env), bytes = new Uint8Array(await response.arrayBuffer());
    assert.equal(response.status, 200); assert.equal(helper.decodeCanonicalCbor(bytes).payload.ok, true);
    const mac = ingressMac(key, "response", ["circulusd.state-ingress.response.v1", key.keyId, signed.value.requestId,
      createHash("sha256").update(signed.body).digest(), "200", "application/vnd.circulusd.state-ingress+cbor", createHash("sha256").update(bytes).digest()]);
    assert.equal(response.headers.get("x-circulus-state-signature"), mac);
  }
  assert.equal(hostCalls, 2);
  for (const role of ["dispatchStart", "admission", "broker"]) {
    const response = await generated.default.fetch(readRequest(helper, config.ingressCredentials[role].current).request, env);
    assert.equal(response.status, 401); assert.equal(response.headers.get("x-circulus-state-signature"), null);
  }
  assert.equal(hostCalls, 2);
  for (const probe of ["/circulusd/native-storage/v1/production:probe", "/circulusd/state/v1/production:probe"]) {
    const response = await generated.default.fetch(new Request(`http://native.local${probe}`, { method: "POST", body: new Uint8Array([1]) }), {});
    assert.equal(response.status, 404); assert.equal(response.headers.get("x-circulus-state-signature"), null);
    assert.equal(response.headers.get("cache-control"), "no-store");
  }
  const alias = { ...env, AUDIT_CELL: env.SESSION_CELL };
  assert.equal((await generated.default.fetch(readRequest(helper, config.ingressCredentials.read.current).request, alias)).status, 503);
  assert.equal(hostCalls, 2);
});

test("actual full bundle keeps native qualification snapshot/commit/barrier in its separate physical namespace", async (t) => {
  const input = fixture(t), generated = await loadBundle(input), { storage: codec } = await helpers(), env = environment(input);
  const state = transactionalState(env.NATIVE_STORAGE.idFromName("native-object"));
  const nativeCell = new generated.NativeStorageQualificationCell(state, env);
  let calls = 0;
  env.NATIVE_STORAGE.idFromName = () => state.id;
  env.NATIVE_STORAGE.get = (id) => { assert.equal(id, state.id); calls++; return { fetch: (request) => nativeCell.fetch(request) }; };
  const key = input.config.nativeStorage, keys = await codec.storageDirectionalKeys(Uint8Array.from(Buffer.from(key.rootKeyHex, "hex")));
  async function exchange(operation, body) {
    const envelope = { protocol: codec.STORAGE_PROTOCOL, major: 1, minor: 0, schemaDigest: codec.STORAGE_SCHEMA,
      requestId: identity("req"), sentAtUnixMs: Date.now(), operation, body }, raw = codec.encodeWire(envelope);
    const response = await generated.default.fetch(new Request(`http://native.local${codec.TRANSACTION_PATH}`, { method: "POST", body: raw,
      headers: { "content-type": codec.TRANSACTION_TYPE, [codec.KEY_HEADER]: key.keyId,
        [codec.SIGNATURE_HEADER]: await codec.storageRequestMac(keys.request, key.keyId, raw) } }), env);
    const returned = new Uint8Array(await response.arrayBuffer());
    assert.equal(response.status, 200); assert.equal(response.headers.get(codec.SIGNATURE_HEADER),
      await codec.storageResponseMac(keys.response, key.keyId, envelope.requestId, raw, response.status, returned));
    return codec.decodeWire(returned).payload.result;
  }
  const first = await exchange("snapshot", { objectId: "native-object" }); assert.equal(first.snapshot.exists, false);
  const commit = { snapshot: first.snapshot, stateWritten: true, state: new Uint8Array([9, 4, 2]), receipts: [] };
  commit.requestDigest = await codec.commitDigest(commit);
  const committed = await exchange("commit", commit); assert.equal(committed.snapshot.revision, 1);
  assert.equal((await exchange("barrier", { token: committed.token, marker: new Uint8Array(32).fill(7) })).barrierSerial, 1);
  assert.deepEqual((await exchange("snapshot", { objectId: "native-object" })).state, new Uint8Array([9, 4, 2]));
  assert.equal(calls, 4); assert.ok(state.values.size > 0);
});
