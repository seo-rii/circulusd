import {
  assertUnicodeScalarString,
  decodeCanonicalCbor,
  digestStructuredValue,
  encodeCanonicalCbor,
  parseDigest,
  validateAgentCheckpoint,
  type AgentCheckpoint,
  type Digest,
  type NormalizedValue,
} from "@circulusd/protocol-types";

import { LowLevelPiAgentEngine } from "./engine.ts";
import { PiRuntimeError } from "./errors.ts";
import {
  createPiAgentCoreFactory,
  createPiAgentCoreInitialState,
  type PiAgentCoreAdapterConfiguration,
} from "./pi-agent-core-adapter.ts";
import { decodePiJson, encodePiJson } from "./pi-json-codec.ts";
import { boundedProtocolValue, exactRecord } from "./validation.ts";
import type { AgentCoreFactory } from "./types.ts";

export interface PiGenesisScope {
  readonly tenantId: string;
  readonly workspaceId: string;
  readonly actorSubjectId: string;
  readonly sessionId: string;
}

export interface PiGenesisRequest extends PiGenesisScope {
  readonly turnId: string;
  readonly runtime: {
    readonly runtimeRevisionDigest: Digest;
    readonly engineKind: "low-level";
    readonly adapterAbiVersion: 2;
    readonly checkpointSchemaVersion: 2;
  };
  readonly input: NormalizedValue;
  readonly inputDigest: Digest;
}

// Environment values are plain JSON, without credentials or capability stubs.
// The trusted loader verifies the module/config artifact before injecting them.
// This environment is a runtime input, never native qualification evidence.
export interface PiGenesisEnvironment {
  readonly scope: PiGenesisScope;
  readonly runtimeRevisionDigest: Digest;
  readonly artifactDigest: Digest;
  readonly configurationDigest: Digest;
  readonly configuration: NormalizedValue;
}

export interface PiGenesisResult {
  readonly requestDigest: Digest;
  readonly binding: Omit<PiGenesisRequest, "input">;
  readonly checkpoint: AgentCheckpoint;
}

const maximumInputBytes = 1_048_576;
const maximumCheckpointBytes = 4 * 1_048_576;
export const MAXIMUM_GENESIS_CONFIGURATION_BYTES = 262_144;

function invalid(): never {
  throw new PiRuntimeError("INVALID_CONTEXT", "invalid Pi genesis request or binding");
}

export function snapshotPiGenesisScope(value: unknown): PiGenesisScope {
  const record = exactRecord(value, ["tenantId", "workspaceId", "actorSubjectId", "sessionId"], [], "genesis.scope", "INVALID_CONTEXT");
  for (const [name, prefix] of [["tenantId", "tenant"], ["workspaceId", "ws"], ["actorSubjectId", "subject"], ["sessionId", "sess"]] as const) {
    if (typeof record[name] !== "string" || !new RegExp(`^${prefix}_[A-Z2-7]{25}[AEIMQUY4]$`).test(record[name])) invalid();
  }
  return { tenantId: record.tenantId as string, workspaceId: record.workspaceId as string,
    actorSubjectId: record.actorSubjectId as string, sessionId: record.sessionId as string };
}

export function snapshotPiGenesisEnvironment(value: unknown): PiGenesisEnvironment {
  const record = exactRecord(value, ["scope", "runtimeRevisionDigest", "artifactDigest", "configurationDigest", "configuration"], [], "genesis.environment", "INVALID_CONFIGURATION");
  return {
    scope: snapshotPiGenesisScope(record.scope), runtimeRevisionDigest: parseDigest(record.runtimeRevisionDigest),
    artifactDigest: parseDigest(record.artifactDigest), configurationDigest: parseDigest(record.configurationDigest),
    configuration: boundedProtocolValue(record.configuration, MAXIMUM_GENESIS_CONFIGURATION_BYTES, "genesis.configuration", "INVALID_CONFIGURATION"),
  };
}

// Snapshot and bound before the first asynchronous dependency call. Request
// identity includes the complete ordered public input, not concatenated text.
export async function snapshotPiGenesisRequest(value: unknown): Promise<PiGenesisRequest> {
  const record = exactRecord(value, ["tenantId", "workspaceId", "actorSubjectId", "sessionId", "turnId", "runtime", "input", "inputDigest"], [], "genesis.request", "INVALID_CONTEXT");
  const scope = snapshotPiGenesisScope({ tenantId: record.tenantId, workspaceId: record.workspaceId,
    actorSubjectId: record.actorSubjectId, sessionId: record.sessionId });
  if (typeof record.turnId !== "string" || !/^turn_[A-Z2-7]{25}[AEIMQUY4]$/.test(record.turnId)) invalid();
  const runtime = exactRecord(record.runtime, ["runtimeRevisionDigest", "engineKind", "adapterAbiVersion", "checkpointSchemaVersion"], [], "genesis.runtime", "INVALID_CONTEXT");
  if (runtime.engineKind !== "low-level" || runtime.adapterAbiVersion !== 2 || runtime.checkpointSchemaVersion !== 2) invalid();
  const inputRecord = exactRecord(record.input, ["messages"], [], "genesis.input", "INVALID_CONTEXT");
  const messages = inputRecord.messages;
  if (!Array.isArray(messages) || Object.getPrototypeOf(messages) !== Array.prototype ||
    messages.length < 1 || messages.length > 1024 || Reflect.ownKeys(messages).length !== messages.length + 1) invalid();
  let totalBytes = 0;
  const snapshot: NormalizedValue[] = [];
  const encoder = new TextEncoder();
  for (let index = 0; index < messages.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(messages, String(index));
    if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor)) invalid();
    const message = exactRecord(descriptor.value, ["role", "content"], [], "genesis.message", "INVALID_CONTEXT");
    if (message.role !== "user" || typeof message.content !== "string" || message.content.length < 1 ||
      message.content.length > maximumInputBytes - totalBytes || message.content !== message.content.normalize("NFC")) invalid();
    assertUnicodeScalarString(message.content, "genesis.message.content");
    totalBytes += encoder.encode(message.content).byteLength;
    if (totalBytes > maximumInputBytes) invalid();
    snapshot.push({ role: "user", content: message.content });
  }
  const input: NormalizedValue = { messages: snapshot };
  encodeCanonicalCbor(input, { maxBytes: maximumInputBytes, maxDepth: 64, maxItems: 100_000 });
  const inputDigest = parseDigest(record.inputDigest);
  const request: PiGenesisRequest = {
    ...scope, turnId: record.turnId,
    runtime: { runtimeRevisionDigest: parseDigest(runtime.runtimeRevisionDigest), engineKind: "low-level", adapterAbiVersion: 2, checkpointSchemaVersion: 2 },
    input, inputDigest,
  };
  if (await digestStructuredValue("circulusd.session.turn-input", 1, input) !== inputDigest) invalid();
  return request;
}

export function assertPiGenesisBinding(request: PiGenesisRequest, environment: PiGenesisEnvironment): void {
  if (request.tenantId !== environment.scope.tenantId || request.workspaceId !== environment.scope.workspaceId ||
    request.actorSubjectId !== environment.scope.actorSubjectId || request.sessionId !== environment.scope.sessionId ||
    request.runtime.runtimeRevisionDigest !== environment.runtimeRevisionDigest) invalid();
}

export function piGenesisBinding(request: PiGenesisRequest): PiGenesisResult["binding"] {
  return { tenantId: request.tenantId, workspaceId: request.workspaceId, actorSubjectId: request.actorSubjectId,
    sessionId: request.sessionId, turnId: request.turnId, runtime: { ...request.runtime }, inputDigest: request.inputDigest };
}

export async function piGenesisRequestDigest(request: PiGenesisRequest): Promise<Digest> {
  return digestStructuredValue("circulusd.engine.genesis-request", 1, request);
}

// This generator calls the actual Pi engine. It owns no native probe, signing
// key or eligibility flag and cannot qualify itself as a production source.
export class PiGenesisGenerator {
  readonly #environment: PiGenesisEnvironment;
  readonly #coreFactory: AgentCoreFactory;

  private constructor(environment: PiGenesisEnvironment, coreFactory: AgentCoreFactory) {
    this.#environment = environment;
    this.#coreFactory = coreFactory;
  }

  static async create(value: PiGenesisEnvironment): Promise<PiGenesisGenerator> {
    const environment = snapshotPiGenesisEnvironment(value);
    if (await digestStructuredValue("circulusd.pi.genesis-configuration", 1, environment.configuration) !== environment.configurationDigest) {
      throw new PiRuntimeError("INVALID_CONFIGURATION", "Pi genesis configuration digest mismatch");
    }
    const configuration = decodePiJson(environment.configuration) as PiAgentCoreAdapterConfiguration;
    return new PiGenesisGenerator(environment, createPiAgentCoreFactory(configuration));
  }

  async createGenesis(value: PiGenesisRequest): Promise<PiGenesisResult> {
    const request = await snapshotPiGenesisRequest(value);
    assertPiGenesisBinding(request, this.#environment);
    const engine = new LowLevelPiAgentEngine({
      sessionId: request.sessionId, runtimeRevisionDigest: this.#environment.runtimeRevisionDigest,
      adapterAbiVersion: 2, checkpointSchemaVersion: 2,
    }, this.#coreFactory);
    const checkpoint = await engine.createGenesisCheckpoint({
      turnId: request.turnId, input: request.input, initialCoreState: createPiAgentCoreInitialState(),
    });
    return { requestDigest: await piGenesisRequestDigest(request), binding: piGenesisBinding(request), checkpoint };
  }
}

export async function validatePiGenesisResult(value: unknown, request: PiGenesisRequest): Promise<PiGenesisResult> {
  const record = exactRecord(value, ["requestDigest", "binding", "checkpoint"], [], "genesis.result", "INVALID_CHECKPOINT");
  const binding = exactRecord(record.binding, ["tenantId", "workspaceId", "actorSubjectId", "sessionId", "turnId", "runtime", "inputDigest"], [], "genesis.binding", "INVALID_CHECKPOINT");
  if (await digestStructuredValue("circulusd.engine.genesis-binding", 1, binding) !==
    await digestStructuredValue("circulusd.engine.genesis-binding", 1, piGenesisBinding(request)) ||
    record.requestDigest !== await piGenesisRequestDigest(request)) invalid();
  const checkpointRecord = exactRecord(record.checkpoint, ["kind", "engineKind", "sessionId", "turnId", "runtimeRevisionDigest", "adapterAbiVersion", "checkpointSchemaVersion", "checkpointSequence", "predecessorDigest", "payloadEncoding", "payloadDigest", "payloadBytes"], [], "genesis.checkpoint", "INVALID_CHECKPOINT");
  const bytes = checkpointRecord.payloadBytes;
  if (!(bytes instanceof Uint8Array) || bytes.byteLength < 1 || bytes.byteLength > maximumCheckpointBytes) invalid();
  const checkpoint = await validateAgentCheckpoint(record.checkpoint);
  if (checkpoint.sessionId !== request.sessionId || checkpoint.turnId !== request.turnId ||
    checkpoint.runtimeRevisionDigest !== request.runtime.runtimeRevisionDigest || checkpoint.adapterAbiVersion !== 2 ||
    checkpoint.checkpointSchemaVersion !== 2 || checkpoint.kind !== "genesis" || checkpoint.engineKind !== "low-level" || checkpoint.payloadEncoding !== "canonical-cbor" ||
    checkpoint.checkpointSequence !== 0 || checkpoint.predecessorDigest !== null) invalid();
  const state = exactRecord(decodeCanonicalCbor(checkpoint.payloadBytes, { maxBytes: maximumCheckpointBytes }),
    ["version", "status", "coreState", "turnInput", "beforeTurnCompleted", "awaiting", "pendingTools", "completedTools", "terminalCode"], [], "genesis.state", "INVALID_CHECKPOINT");
  if (state.version !== 1 || state.status !== "ready" || state.beforeTurnCompleted !== false ||
    state.awaiting !== null || state.terminalCode !== null || !Array.isArray(state.pendingTools) || state.pendingTools.length !== 0 ||
    !Array.isArray(state.completedTools) || state.completedTools.length !== 0 ||
    await digestStructuredValue("circulusd.session.turn-input", 1, state.turnInput) !== request.inputDigest ||
    await digestStructuredValue("circulusd.pi.genesis-core", 1, state.coreState) !==
      await digestStructuredValue("circulusd.pi.genesis-core", 1, createPiAgentCoreInitialState())) invalid();
  return { requestDigest: await piGenesisRequestDigest(request), binding: piGenesisBinding(request),
    checkpoint: { ...checkpoint, payloadBytes: new Uint8Array(checkpoint.payloadBytes) } };
}

export function encodePiGenesisConfiguration(value: PiAgentCoreAdapterConfiguration): NormalizedValue {
  const encoded = encodePiJson(value);
  encodeCanonicalCbor(encoded, { maxBytes: MAXIMUM_GENESIS_CONFIGURATION_BYTES });
  createPiAgentCoreFactory(decodePiJson(encoded) as PiAgentCoreAdapterConfiguration);
  return encoded;
}
