import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const script = path.join(repository, "scripts/prepare-native-pi.mjs");
const sha = (data) => `sha256:${createHash("sha256").update(data).digest("hex")}`;
const moduleURL = (data) => `data:text/javascript;base64,${Buffer.from(data).toString("base64")}`;
function configuration() {
  return { schemaVersion: 1, runtimeRevisionDigest: `sha256:${"a".repeat(64)}`,
    compatibilityDate: "2026-08-25", compatibilityFlags: [], configuration: {
      systemPrompt: "Native artifact preparation test.",
      model: { id: "local-model", api: "circulusd-model-gateway", provider: "circulusd", reasoning: false,
        input: ["text"], contextWindow: 4096, maxTokens: 256 },
      tools: [{ name: "echo", description: "Echo", replayPolicy: "safe",
        parameters: { type: "object", properties: { value: { type: "number", minimum: 0.1 } } } }],
    } };
}
function fixture(t, value = configuration()) {
  const directory = mkdtempSync(path.join(tmpdir(), "circulusd-native-pi-"));
  chmodSync(directory, 0o700); t.after(() => rmSync(directory, { recursive: true, force: true }));
  const config = path.join(directory, "configuration.json"), output = path.join(directory, "prepared");
  writeFileSync(config, JSON.stringify(value), { mode: 0o600 });
  return { directory, config, output, value };
}
function run(input) {
  return spawnSync(process.execPath, [script, "--config", input.config, "--output", input.output],
    { cwd: repository, encoding: "utf8", timeout: 60000, maxBuffer: 1 << 20 });
}
function rejected(input) {
  const result = run(input);
  assert.equal(result.status, 1); assert.equal(result.stdout, "");
  assert.match(result.stderr, /^Native Pi preparation failed;/u);
  assert.equal(existsSync(input.output), false);
  assert.equal(result.stderr.includes(input.config), false);
}
async function helpers() {
  const result = await build({ stdin: { contents:
    'export { digestStructuredValue } from "./packages/protocol-types/src/index.ts";\n' +
    'export { encodePiGenesisConfiguration } from "./workers/pi-runtime/src/genesis.ts";\n' +
    'export { piGenesisRuntimeArtifactDigest } from "./workers/pi-runtime/src/celld-genesis.ts";\n' +
    'export { piExecutionRuntimeArtifactDigest } from "./workers/pi-runtime/src/celld-execution.ts";\n',
    resolveDir: repository, sourcefile: "native-pi-test.ts" }, bundle: true, format: "esm", platform: "browser",
    target: "es2022", write: false, external: ["cloudflare:sockets"], logLevel: "silent" });
  return import(moduleURL(result.outputFiles[0].contents));
}
test("rejects public, symlink, hardlink, oversized and invalid private inputs", (t) => {
  const publicFile = fixture(t); chmodSync(publicFile.config, 0o644); rejected(publicFile);
  const symbolic = fixture(t), link = path.join(symbolic.directory, "link.json");
  symlinkSync(symbolic.config, link); rejected({ ...symbolic, config: link });
  const linked = fixture(t); linkSync(linked.config, path.join(linked.directory, "second.json")); rejected(linked);
  const oversized = fixture(t); writeFileSync(oversized.config, " ".repeat((1 << 20) + 1)); rejected(oversized);
  const malformed = fixture(t); writeFileSync(malformed.config, "{invalid"); rejected(malformed);
  for (const change of [
    (c) => { c.signingKey = "private-key-must-not-be-accepted"; },
    (c) => { c.schemaVersion = 2; },
    (c) => { c.runtimeRevisionDigest = "arbitrary"; },
    (c) => { c.compatibilityFlags = ["js_rpc", "js_rpc"]; },
    (c) => { c.compatibilityFlags = ["nodejs_compat"]; },
    (c) => { c.compatibilityDate = "2026-02-30"; },
    (c) => { c.configuration.model.apiKey = "private-key-must-not-be-accepted"; },
  ]) { const value = configuration(); change(value); rejected(fixture(t, value)); }
});
test("preserves existing output and refuses writable or linked parents", (t) => {
  const existing = fixture(t); mkdirSync(existing.output, { mode: 0o700 });
  writeFileSync(path.join(existing.output, "keep.txt"), "keep", { mode: 0o600 });
  assert.equal(run(existing).status, 1);
  assert.deepEqual(readdirSync(existing.output), ["keep.txt"]);
  assert.equal(readFileSync(path.join(existing.output, "keep.txt"), "utf8"), "keep");
  const writable = fixture(t); chmodSync(writable.directory, 0o777); rejected(writable);
  const linked = fixture(t), parent = `${linked.directory}-link`;
  symlinkSync(linked.directory, parent); t.after(() => rmSync(parent));
  rejected({ ...linked, output: path.join(parent, "prepared") });
});
test("exact prepared modules cold-create genesis and execute the actual first model boundary", async (t) => {
  const input = fixture(t), result = run(input); assert.equal(result.status, 0, result.stderr);
  const api = await helpers(), manifest = JSON.parse(readFileSync(path.join(input.output, "manifest.json"), "utf8"));
  assert.equal(statSync(input.output).mode & 0o777, 0o700);
  assert.equal(manifest.qualification, "PREPARATION_ONLY"); assert.equal(manifest.admissionReady, false);
  assert.equal(manifest.independentlySignedMappingsRequired, true);
  assert.equal(manifest.configurationDigest, sha(readFileSync(input.config)));
  assert.deepEqual(JSON.parse(result.stdout).runtimes, manifest.runtimes);
  const definitions = {};
  for (const purpose of ["genesis", "execution"]) {
    const runtime = JSON.parse(readFileSync(path.join(input.output, `${purpose}-runtime.json`), "utf8"));
    definitions[purpose] = runtime;
    const modules = runtime.modules.map((entry) => {
      const file = path.join(input.output, entry.file), bytes = new Uint8Array(readFileSync(file));
      assert.equal(statSync(file).mode & 0o777, 0o600); assert.equal(sha(bytes), entry.digest);
      assert.equal(bytes.byteLength, entry.sizeBytes);
      return { specifier: entry.specifier, bytes, digest: entry.digest };
    });
    const definition = { runtimeRevisionDigest: runtime.runtimeRevisionDigest, adapterAbiVersion: 2, checkpointSchemaVersion: 2,
      compatibilityDate: runtime.compatibilityDate, compatibilityFlags: runtime.compatibilityFlags,
      mainModule: runtime.mainModule, modules, configuration: runtime.configuration };
    const compute = purpose === "genesis" ? api.piGenesisRuntimeArtifactDigest : api.piExecutionRuntimeArtifactDigest;
    assert.equal(await compute(definition), runtime.artifactDigest);
    const changed = { ...definition, configuration: { ...definition.configuration, systemPrompt: "changed" } };
    assert.notEqual(await compute(changed), runtime.artifactDigest);
  }
  assert.notEqual(definitions.genesis.artifactDigest, definitions.execution.artifactDigest);
  assert.notEqual(manifest.runtimes.genesis.mappingDomain, manifest.runtimes.execution.mappingDomain);
  const scope = { tenantId: `tenant_${"A".repeat(26)}`, workspaceId: `ws_${"A".repeat(26)}`,
    actorSubjectId: `subject_${"A".repeat(26)}`, sessionId: `sess_${"A".repeat(26)}` };
  const turnId = `turn_${"A".repeat(26)}`, normalized = api.encodePiGenesisConfiguration(input.value.configuration);
  async function instance(purpose) {
    const definition = definitions[purpose], core = moduleURL(readFileSync(path.join(input.output, `${purpose}-core.mjs`)));
    const base = moduleURL("export class WorkerEntrypoint { constructor(ctx, env) { this.ctx=ctx; this.env=env; } }");
    const source = readFileSync(path.join(input.output, `${purpose}-entry.mjs`), "utf8")
      .replace('"cloudflare:workers"', JSON.stringify(base)).replace(JSON.stringify(definition.modules[1].specifier), JSON.stringify(core));
    const module = await import(moduleURL(source));
    return new module.default({}, { scope, runtimeRevisionDigest: definition.runtimeRevisionDigest,
      artifactDigest: definition.artifactDigest, configuration: normalized,
      configurationDigest: await api.digestStructuredValue(`circulusd.pi.${purpose}-configuration`, 1, normalized) });
  }
  const inputMessages = { messages: [{ role: "user", content: "첫 번째 입력" }, { role: "user", content: "second input" }] };
  const genesis = await (await instance("genesis")).createGenesis({ ...scope, turnId,
    runtime: { runtimeRevisionDigest: input.value.runtimeRevisionDigest, engineKind: "low-level", adapterAbiVersion: 2, checkpointSchemaVersion: 2 },
    input: inputMessages, inputDigest: await api.digestStructuredValue("circulusd.session.turn-input", 1, inputMessages) });
  const engine = await instance("execution");
  const header = { protocol: "circulusd.pi.execution", version: 1, binding: { scope,
    runtimeRevisionDigest: input.value.runtimeRevisionDigest, artifactDigest: definitions.execution.artifactDigest },
    turnId, executionId: "prepared-native-test" };
  const opened = await engine.exchange({ ...header, operation: "start", sequence: 0,
    authority: new Uint8Array([1, 2, 3]), checkpoint: genesis.checkpoint });
  assert.equal(opened.status, "opened");
  const reply = await engine.exchange({ ...header, operation: "pull", sequence: 1 });
  assert.equal(reply.status, "event"); assert.equal(reply.event.type, "model_request");
  assert.equal(reply.event.request.service, "model");
  assert.deepEqual(reply.event.request.payload.context.messages, inputMessages.messages.map((m) => ({ ...m, timestamp: 0 })));
  await engine.exchange({ ...header, operation: "abort", sequence: 0 });
});
