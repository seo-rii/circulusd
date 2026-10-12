import { Buffer } from "node:buffer";
import type { Context } from "@earendil-works/pi-ai";
import { build } from "esbuild";
import {
  decodeCanonicalCbor, digestBytes, digestStructuredValue, encodeCanonicalCbor, parsePortableConversationMessages,
  type AgentCheckpoint, type Digest, type EffectIntent, type NormalizedValue,
} from "@circulusd/protocol-types";
import { beforeAll, describe, expect, it } from "vitest";

import { SessionHost, type AgentEvent, type DriveTurnOptions } from "../../session-host/src/index.ts";
import {
  CELLD_EXECUTION_COMMIT, CelldPiExecutionEngine, PI_EXECUTION_CORE_MODULE,
  PI_EXECUTION_ENTRY_MODULE, PI_EXECUTION_ENTRY_SOURCE, piExecutionRuntimeArtifactDigest,
  type CelldExecutionLoader, type PiExecutionRuntimeDefinition,
} from "../src/celld-execution.ts";
import type { PiExecutionEnvironment } from "../src/execution-environment.ts";
import { EXECUTION_MAPPING_DOMAIN, SignedPiExecutionRuntimeVerifier } from "../src/execution-runtime-mapping.ts";
import type { PiExecutionRequest } from "../src/execution-rpc.ts";
import { PiGenesisGenerator, type PiGenesisRequest } from "../src/genesis.ts";
import {
  PI_AGENT_CORE_TOOL_DETAILS_ENCODING, decodePiAgentCoreModelContext,
  encodePiAgentCoreModelContext, encodePiAgentCoreModelSettlement, encodePiAgentCoreToolResult,
} from "../src/index.ts";
import { CONFIGURATION, environment, REVISION, SCOPE } from "./genesis-fixtures.ts";

let definition: PiExecutionRuntimeDefinition;
let verifier: SignedPiExecutionRuntimeVerifier;
beforeAll(async () => {
  const bundled = await build({ entryPoints: [new URL("../src/execution-entrypoint.ts", import.meta.url).pathname],
    bundle: true, platform: "browser", format: "esm", target: "es2022", write: false,
    external: ["cloudflare:sockets"], logLevel: "silent" });
  const entry = new TextEncoder().encode(PI_EXECUTION_ENTRY_SOURCE), core = bundled.outputFiles[0]!.contents;
  definition = { runtimeRevisionDigest: REVISION, adapterAbiVersion: 2, checkpointSchemaVersion: 2,
    mainModule: PI_EXECUTION_ENTRY_MODULE, compatibilityDate: "2026-08-25", compatibilityFlags: [],
    configuration: structuredClone(CONFIGURATION), modules: [
      { specifier: PI_EXECUTION_ENTRY_MODULE, bytes: entry, digest: await digestBytes(entry) },
      { specifier: PI_EXECUTION_CORE_MODULE, bytes: core, digest: await digestBytes(core) },
    ] };
  // Ephemeral test signing exercises the real verifier and artifact binding.
  // The Loader below is a local ABI fixture, not native isolation evidence.
  const claims = { schemaVersion: 1, celldCommit: CELLD_EXECUTION_COMMIT, adapterAbiVersion: 2,
    checkpointSchemaVersion: 2, runtimeRevisionDigest: REVISION,
    artifactDigest: await piExecutionRuntimeArtifactDigest(definition), keyId: "test-details-root" };
  const key = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const expectedMappingDigest = await digestStructuredValue(EXECUTION_MAPPING_DOMAIN, 1, claims);
  const signature = new Uint8Array(await crypto.subtle.sign("Ed25519", key.privateKey, new TextEncoder().encode(expectedMappingDigest)));
  verifier = await SignedPiExecutionRuntimeVerifier.create({ expectedMappingDigest,
    document: encodeCanonicalCbor({ claims, algorithm: "ed25519", signature }),
    trustRoots: [{ keyId: claims.keyId, publicKey: new Uint8Array(await crypto.subtle.exportKey("raw", key.publicKey)) }] });
});

function fixture() {
  const names: string[] = [], requests: PiExecutionRequest[] = [];
  let releases = 0, commits = 0, aborts = 0;
  const dataModule = (source: string) => `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`;
  const loader: CelldExecutionLoader = { get(name, getCode) {
    names.push(name);
    const loaded = Promise.resolve().then(async () => {
      const worker = await getCode();
      const base = dataModule("export class WorkerEntrypoint { constructor(ctx, env) {} }");
      const core = dataModule(worker.modules[PI_EXECUTION_CORE_MODULE]!);
      const entry = worker.modules[PI_EXECUTION_ENTRY_MODULE]!
        .replace('"cloudflare:workers"', JSON.stringify(base)).replace(JSON.stringify(PI_EXECUTION_CORE_MODULE), JSON.stringify(core));
      const module = await import(/* @vite-ignore */ dataModule(entry)) as { default: new (context: object,
        environment: PiExecutionEnvironment) => { exchange(request: PiExecutionRequest): Promise<unknown> } };
      return new module.default({}, worker.env);
    });
    return { getEntrypoint: () => ({ async exchange(request: PiExecutionRequest) {
      const owned = structuredClone(request); requests.push(owned);
      if (request.operation === "abort") aborts += 1;
      return structuredClone(await (await loaded).exchange(owned));
    } }), dispose() { releases += 1; } };
  } };
  const host = new SessionHost({ bindings: { STATE: {}, WORKSPACE: {}, MODEL: {}, MCP: {}, EXECUTOR: {}, ARTIFACTS: {}, EVENTS: {} },
    loader: { async get() { throw new Error("use the signed execution Loader fixture"); } },
    verifier: { async verify() { throw new Error("native runtime qualification is not supplied"); } } });
  async function drive(checkpoint: AgentCheckpoint, settlement?: unknown) {
    const engine = await CelldPiExecutionEngine.create({ loader, verifier, scope: SCOPE, runtime: definition });
    const options: DriveTurnOptions = { turnId: checkpoint.turnId, checkpoint, authority: new Uint8Array([1, 2, 3]),
      maximumEvents: 4, committer: { async commit() { commits += 1; } }, ephemeralSink: { async emit() {} } };
    try {
      return settlement === undefined ? await host.startTurn(engine, options) :
        await host.resumeTurn(engine, { ...options, settlement });
    } finally { engine.dispose(); }
  }
  return { names, requests, drive, counts: () => ({ releases, commits, aborts }) };
}

async function genesis(character = "A") {
  const input = { messages: [{ role: "user", content: "Preserve my tool metadata." }] };
  const request: PiGenesisRequest = { ...SCOPE, turnId: `turn_${character.repeat(25)}A`,
    runtime: { runtimeRevisionDigest: REVISION, engineKind: "low-level", adapterAbiVersion: 2, checkpointSchemaVersion: 2 },
    input, inputDigest: await digestStructuredValue("circulusd.session.turn-input", 1, input) };
  const checkpoint = (await (await PiGenesisGenerator.create(await environment())).createGenesis(request)).checkpoint;
  return { request, checkpoint };
}
function effect(event: AgentEvent): { checkpoint: AgentCheckpoint; request: EffectIntent } {
  if (event.type !== "model_request" && event.type !== "tool_request") throw new Error("expected effect boundary");
  return { checkpoint: event.checkpoint as AgentCheckpoint, request: event.request as EffectIntent };
}
function success(requestDigest: Digest, result: unknown) { return { requestDigest, outcome: { kind: "success", result } }; }
function modelResult(tool: boolean) {
  return encodePiAgentCoreModelSettlement({ role: "assistant", api: CONFIGURATION.model.api,
    provider: CONFIGURATION.model.provider, model: CONFIGURATION.model.id,
    content: tool ? [{ type: "toolCall", id: "details-call", name: "echo", arguments: { value: 1 } }] : [{ type: "text", text: "done" }],
    usage: { input: 1, output: 1, cacheRead: 0, cacheWrite: 0, totalTokens: 2,
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } },
    stopReason: tool ? "toolUse" : "stop", timestamp: tool ? 1 : 3 });
}
const toolResult = (details: unknown) => ({ version: 1, toolCallId: "details-call", toolName: "echo",
  content: [{ type: "text", text: "done" }], isError: false, timestamp: 2, details });
function detailsFromRequest(request: EffectIntent) {
  const context = decodePiAgentCoreModelContext((request.payload as { context: NormalizedValue }).context);
  const message = context.messages.find((message) => (message as { role: string }).role === "toolResult") as {
    details: unknown; detailsEncoding?: string;
  };
  return message;
}

describe("tool metadata through actual Pi and signed execution RPC", () => {
  for (const producer of ["raw", "encoded"] as const) it(`${producer} nested details survive four cold engines and commit once per boundary`, async () => {
    const f = fixture(), initial = await genesis();
    const first = effect((await f.drive(initial.checkpoint)).boundary);
    const tool = effect((await f.drive(first.checkpoint, success(first.request.requestDigest, modelResult(true)))).boundary);
    const details = { scale: 0.5, nested: [null, "metadata", { minimum: Number.MIN_VALUE, maximum: Number.MAX_VALUE }], negative: -0.125 };
    const next = effect((await f.drive(tool.checkpoint, success(tool.request.requestDigest,
      producer === "raw" ? toolResult(details) : encodePiAgentCoreToolResult(toolResult(details))))).boundary);
    expect(detailsFromRequest(next.request)).toMatchObject({ details, detailsEncoding: PI_AGENT_CORE_TOOL_DETAILS_ENCODING });
    const complete = (await f.drive(next.checkpoint, success(next.request.requestDigest, modelResult(false)))).boundary;
    expect(complete.type).toBe("turn_complete");
    const state = (decodeCanonicalCbor((complete.checkpoint as AgentCheckpoint).payloadBytes) as {
      coreState: { messages: NormalizedValue[] };
    }).coreState;
    expect(decodePiAgentCoreModelContext({ messages: state.messages }).messages[2]).toMatchObject({ details });
    expect(f.counts()).toEqual({ commits: 4, releases: 4, aborts: 0 });
    expect(new Set(f.names).size).toBe(4);
    const resume = f.requests.filter((request) => request.operation === "resume")[1];
    expect(resume).toMatchObject({ settlement: { outcome: { result: producer === "raw" ? { details: { scale: 0.5 } } : {
      detailsEncoding: PI_AGENT_CORE_TOOL_DETAILS_ENCODING, details: { scale: { "$pi.number.v1": "0.5" } },
    } } } });
  });

  it("restores completed checkpoint metadata through the portable history parser and Pi context import", async () => {
    const f = fixture(), source = await genesis();
    const first = effect((await f.drive(source.checkpoint)).boundary);
    const tool = effect((await f.drive(first.checkpoint, success(first.request.requestDigest, modelResult(true)))).boundary);
    const details = [0.5, { nested: [null, "receipt", -0.125] }];
    const next = effect((await f.drive(tool.checkpoint, success(tool.request.requestDigest, toolResult(details)))).boundary);
    const complete = (await f.drive(next.checkpoint, success(next.request.requestDigest, modelResult(false)))).boundary;
    expect(complete.type).toBe("turn_complete");
    const state = (decodeCanonicalCbor((complete.checkpoint as AgentCheckpoint).payloadBytes) as {
      coreState: { messages: NormalizedValue[] };
    }).coreState;
    const imported = parsePortableConversationMessages(state.messages, true);
    const decoded = decodePiAgentCoreModelContext({ messages: imported });
    expect(decoded.messages[2]).toMatchObject({ details, detailsEncoding: PI_AGENT_CORE_TOOL_DETAILS_ENCODING });
    const recaptured = encodePiAgentCoreModelContext(structuredClone(decoded) as unknown as Context) as { messages: NormalizedValue[] };
    expect(parsePortableConversationMessages(recaptured.messages, true)).toEqual(imported);
    expect(encodeCanonicalCbor(recaptured)).toEqual(encodeCanonicalCbor({ messages: imported }));
    expect(f.counts()).toEqual({ commits: 4, releases: 4, aborts: 0 });
  });
});
