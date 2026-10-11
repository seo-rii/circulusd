import {
  digestBytes,
  digestStructuredValue,
  parseDigest,
  type Digest,
} from "@circulusd/protocol-types";

import { PiRuntimeError } from "./errors.ts";
import {
  assertPiGenesisBinding,
  encodePiGenesisConfiguration,
  snapshotPiGenesisRequest,
  snapshotPiGenesisScope,
  validatePiGenesisResult,
  type PiGenesisEnvironment,
  type PiGenesisRequest,
  type PiGenesisResult,
  type PiGenesisScope,
} from "./genesis.ts";
import type { PiAgentCoreAdapterConfiguration } from "./pi-agent-core-adapter.ts";
import { exactRecord } from "./validation.ts";

export const CELLD_GENESIS_COMMIT = "89e4ffc53a14ecb496d2ca5014ff9d19b0061ad9";
export const PI_GENESIS_CORE_MODULE = "circulusd/pi-genesis-core.mjs";
export const PI_GENESIS_ENTRY_MODULE = "circulusd/pi-genesis-entry.mjs";
export const PI_GENESIS_ENTRY_SOURCE =
  'import { WorkerEntrypoint } from "cloudflare:workers";\n' +
  `import { createPiGenesisEntrypointClass } from "${PI_GENESIS_CORE_MODULE}";\n` +
  'export default createPiGenesisEntrypointClass(WorkerEntrypoint);\n';

export interface PiGenesisRuntimeModule {
  readonly specifier: string;
  readonly bytes: Uint8Array;
  readonly digest: Digest;
}

export interface PiGenesisRuntimeDefinition {
  readonly runtimeRevisionDigest: Digest;
  readonly adapterAbiVersion: 2;
  readonly checkpointSchemaVersion: 2;
  readonly compatibilityDate: string;
  readonly compatibilityFlags: readonly string[];
  readonly mainModule: typeof PI_GENESIS_ENTRY_MODULE;
  readonly modules: readonly PiGenesisRuntimeModule[];
  readonly configuration: PiAgentCoreAdapterConfiguration;
}

// The trusted composition supplies a verifier for its signed immutable mapping
// from the Session runtime revision to these exact modules/configuration. A
// self-reported digest is insufficient. This port does not attest the celld
// binary, storage, isolation or native engine-genesis production capability.
export interface PiGenesisRuntimeVerifier {
  verify(binding: {
    readonly runtimeRevisionDigest: Digest;
    readonly artifactDigest: Digest;
  }): Promise<{ readonly runtimeRevisionDigest: Digest; readonly artifactDigest: Digest }>;
}

export interface CelldGenesisWorkerDefinition {
  readonly mainModule: string;
  readonly modules: Readonly<Record<string, string>>;
  readonly compatibilityDate: string;
  readonly compatibilityFlags: readonly string[];
  readonly env: PiGenesisEnvironment;
  readonly globalOutbound: null;
}

interface CelldGenesisEntrypoint {
  createGenesis(request: PiGenesisRequest): Promise<unknown>;
}

interface CelldGenesisWorker {
  getEntrypoint(): CelldGenesisEntrypoint;
}

// This is pinned celld's actual ABI, rather than SessionHost's module array or
// capability-bearing env. CELLD_WORKER_LOADER supplies this binding; loaded
// workers accept a module-name -> ESM-string map, JSON env and one RPC method.
export interface CelldGenesisLoader {
  get(name: string, getCode: () => Promise<CelldGenesisWorkerDefinition>): CelldGenesisWorker | Promise<CelldGenesisWorker>;
}

interface RuntimeSnapshot {
  readonly environment: PiGenesisEnvironment;
  readonly modules: Readonly<Record<string, string>>;
  readonly compatibilityDate: string;
  readonly compatibilityFlags: readonly string[];
}

interface RuntimeArtifactSnapshot {
  readonly runtimeRevisionDigest: Digest;
  readonly artifactDigest: Digest;
  readonly configurationDigest: Digest;
  readonly configuration: PiGenesisEnvironment["configuration"];
  readonly modules: Readonly<Record<string, string>>;
  readonly compatibilityDate: string;
  readonly compatibilityFlags: readonly string[];
}

function invalidRuntime(): never {
  throw new PiRuntimeError("INVALID_CONFIGURATION", "Pi genesis runtime is invalid or unverified");
}

function plainArray(value: unknown, maximum: number): readonly unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length > maximum ||
    Reflect.ownKeys(value).length !== value.length + 1) invalidRuntime();
  const snapshot: unknown[] = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor)) invalidRuntime();
    snapshot.push(descriptor.value);
  }
  return snapshot;
}

async function snapshotArtifact(value: PiGenesisRuntimeDefinition): Promise<RuntimeArtifactSnapshot> {
  const runtime = exactRecord(value, ["runtimeRevisionDigest", "adapterAbiVersion", "checkpointSchemaVersion",
    "compatibilityDate", "compatibilityFlags", "mainModule", "modules", "configuration"], [], "genesis.runtimeDefinition", "INVALID_CONFIGURATION");
  const revision = parseDigest(runtime.runtimeRevisionDigest);
  if (runtime.adapterAbiVersion !== 2 || runtime.checkpointSchemaVersion !== 2 || runtime.mainModule !== PI_GENESIS_ENTRY_MODULE ||
    typeof runtime.compatibilityDate !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(runtime.compatibilityDate)) invalidRuntime();
  const date = runtime.compatibilityDate;
  const parsedDate = new Date(`${date}T00:00:00.000Z`);
  if (!Number.isFinite(parsedDate.getTime()) || parsedDate.toISOString().slice(0, 10) !== date) invalidRuntime();
  const flags = plainArray(runtime.compatibilityFlags, 256).map((flag) => {
    if (typeof flag !== "string" || !/^[a-z][a-z0-9_]{0,63}$/.test(flag)) invalidRuntime();
    return flag;
  }).sort();
  if (new Set(flags).size !== flags.length) invalidRuntime();
  const configuration = encodePiGenesisConfiguration(runtime.configuration as PiAgentCoreAdapterConfiguration);
  const candidates = plainArray(runtime.modules, 256);
  if (candidates.length < 2) invalidRuntime();
  let totalBytes = 0;
  const seen = new Set<string>();
  // Clone every module before hashing or calling any asynchronous verifier.
  const modules = candidates.map((candidate) => {
    const module = exactRecord(candidate, ["specifier", "bytes", "digest"], [], "genesis.module", "INVALID_CONFIGURATION");
    if (typeof module.specifier !== "string" || module.specifier.length > 256 ||
      !/^[a-zA-Z0-9_/-]+\.m?js$/.test(module.specifier) || seen.has(module.specifier) ||
      !(module.bytes instanceof Uint8Array) || Object.getPrototypeOf(module.bytes) !== Uint8Array.prototype ||
      !(module.bytes.buffer instanceof ArrayBuffer) || module.bytes.byteLength < 1 || module.bytes.byteLength > 8 * 1_048_576) invalidRuntime();
    totalBytes += module.bytes.byteLength;
    if (totalBytes > 32 * 1_048_576) invalidRuntime();
    seen.add(module.specifier);
    const bytes = new Uint8Array(module.bytes);
    let source: string;
    try { source = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes); } catch { invalidRuntime(); }
    return { specifier: module.specifier, bytes, source, digest: parseDigest(module.digest) };
  }).sort((left, right) => left.specifier < right.specifier ? -1 : left.specifier > right.specifier ? 1 : 0);
  if (!seen.has(PI_GENESIS_CORE_MODULE) || modules.find((module) => module.specifier === PI_GENESIS_ENTRY_MODULE)?.source !== PI_GENESIS_ENTRY_SOURCE) invalidRuntime();
  for (const module of modules) if (await digestBytes(module.bytes) !== module.digest) invalidRuntime();
  const configurationDigest = await digestStructuredValue("circulusd.pi.genesis-configuration", 1, configuration);
  const artifactDigest = await digestStructuredValue("circulusd.pi.genesis-runtime-artifact", 1, {
    celldCommit: CELLD_GENESIS_COMMIT, adapterAbiVersion: 2, checkpointSchemaVersion: 2,
    compatibilityDate: date, compatibilityFlags: flags, mainModule: PI_GENESIS_ENTRY_MODULE,
    modules: modules.map((module) => ({ specifier: module.specifier, digest: module.digest })), configuration,
  });
  const moduleMap: Record<string, string> = Object.create(null);
  for (const module of modules) moduleMap[module.specifier] = module.source;
  return { runtimeRevisionDigest: revision, artifactDigest, configurationDigest, configuration,
    modules: moduleMap, compatibilityDate: date, compatibilityFlags: flags };
}

// Compute the exact artifact pinned by an externally signed runtime mapping.
// This shares the source's bounded validation and owns all mutable inputs before
// hashing; it neither verifies a mapping nor loads or attests a native runtime.
export async function piGenesisRuntimeArtifactDigest(runtime: PiGenesisRuntimeDefinition): Promise<Digest> {
  return (await snapshotArtifact(runtime)).artifactDigest;
}

async function snapshotRuntime(scopeValue: PiGenesisScope, value: PiGenesisRuntimeDefinition,
  verifier: PiGenesisRuntimeVerifier): Promise<RuntimeSnapshot> {
  const verify = verifier.verify.bind(verifier);
  const scope = snapshotPiGenesisScope(scopeValue);
  const artifact = await snapshotArtifact(value);
  const { runtimeRevisionDigest: revision, artifactDigest, configurationDigest, configuration } = artifact;
  let attestation: unknown;
  try { attestation = await verify({ runtimeRevisionDigest: revision, artifactDigest }); } catch { invalidRuntime(); }
  const verified = exactRecord(attestation, ["runtimeRevisionDigest", "artifactDigest"], [], "genesis.verifiedRuntime", "INVALID_CONFIGURATION");
  if (verified.runtimeRevisionDigest !== revision || verified.artifactDigest !== artifactDigest) invalidRuntime();
  const environment: PiGenesisEnvironment = { scope, runtimeRevisionDigest: revision, artifactDigest, configurationDigest, configuration };
  // Enforce pinned Loader's 1 MiB JSON environment limit. No capability objects
  // or credentials are passed to the loaded worker; egress remains denied.
  if (new TextEncoder().encode(JSON.stringify(environment)).byteLength > 1_048_576) invalidRuntime();
  return { environment, modules: artifact.modules, compatibilityDate: artifact.compatibilityDate,
    compatibilityFlags: artifact.compatibilityFlags };
}

function checkCancellation(signal?: AbortSignal): void {
  if (signal?.aborted) throw new DOMException("Pi genesis request canceled", "AbortError");
}

// Cancel the caller's wait and remove every listener on completion. Pinned
// celld does not cancel a remote isolate through AbortSignal; its trusted native
// bridge must enforce termination and resource deadlines separately.
function awaitCancelable<T>(operation: () => T | Promise<T>, signal?: AbortSignal): Promise<T> {
  checkCancellation(signal);
  if (signal === undefined) return Promise.resolve().then(operation);
  return new Promise<T>((resolve, reject) => {
    const cleanup = () => signal.removeEventListener("abort", abort);
    const abort = () => { cleanup(); reject(new DOMException("Pi genesis request canceled", "AbortError")); };
    signal.addEventListener("abort", abort, { once: true });
    if (signal.aborted) { abort(); return; }
    Promise.resolve().then(() => { checkCancellation(signal); return operation(); }).then(
      (value) => { cleanup(); if (signal.aborted) abort(); else resolve(value); },
      (error: unknown) => { cleanup(); if (signal.aborted) abort(); else reject(error); },
    );
  });
}

// A concrete executable-genesis operation, deliberately without ProbeProduction.
// A trusted native bridge must bind this operation and its measured Loader to
// an independently signed engine-genesis proof before Go NewServer accepts it.
export class CelldPiGenesisSource {
  readonly #loader: CelldGenesisLoader;
  readonly #runtime: RuntimeSnapshot;

  private constructor(loader: CelldGenesisLoader, runtime: RuntimeSnapshot) {
    this.#loader = loader;
    this.#runtime = runtime;
  }

  static async create(config: { readonly loader: CelldGenesisLoader; readonly verifier: PiGenesisRuntimeVerifier;
    readonly scope: PiGenesisScope; readonly runtime: PiGenesisRuntimeDefinition }): Promise<CelldPiGenesisSource> {
    if (config.loader === null || config.loader === undefined || typeof config.loader.get !== "function" ||
      config.verifier === null || config.verifier === undefined || typeof config.verifier.verify !== "function") invalidRuntime();
    return new CelldPiGenesisSource(config.loader, await snapshotRuntime(config.scope, config.runtime, config.verifier));
  }

  async createGenesis(value: PiGenesisRequest, signal?: AbortSignal): Promise<PiGenesisResult> {
    const request = await snapshotPiGenesisRequest(value);
    assertPiGenesisBinding(request, this.#runtime.environment);
    checkCancellation(signal);
    const workerIdentity = await digestStructuredValue("circulusd.pi.genesis-worker", 1, {
      scope: this.#runtime.environment.scope, runtimeRevisionDigest: this.#runtime.environment.runtimeRevisionDigest,
      artifactDigest: this.#runtime.environment.artifactDigest,
    });
    checkCancellation(signal);
    const definition: CelldGenesisWorkerDefinition = {
      mainModule: PI_GENESIS_ENTRY_MODULE, modules: { ...this.#runtime.modules },
      compatibilityDate: this.#runtime.compatibilityDate, compatibilityFlags: [...this.#runtime.compatibilityFlags],
      env: structuredClone(this.#runtime.environment), globalOutbound: null,
    };
    try {
      const worker = await awaitCancelable(() => this.#loader.get(`pi-genesis/${workerIdentity}`, async () => structuredClone(definition)), signal);
      checkCancellation(signal);
      if (worker === null || typeof worker !== "object" || typeof worker.getEntrypoint !== "function") invalidRuntime();
      const entrypoint = worker.getEntrypoint();
      if (entrypoint === null || typeof entrypoint !== "object" || typeof entrypoint.createGenesis !== "function") invalidRuntime();
      // Caller cancellation bounds this wait; remote isolate termination remains
      // a separate native bridge responsibility because celld does not propagate it.
      const result = await awaitCancelable(() => entrypoint.createGenesis(structuredClone(request)), signal);
      checkCancellation(signal);
      const validated = await validatePiGenesisResult(result, request);
      checkCancellation(signal);
      return validated;
    } catch {
      if (signal?.aborted) throw new DOMException("Pi genesis request canceled", "AbortError");
      throw new PiRuntimeError("INVALID_CHECKPOINT", "Pi genesis worker failed or returned an invalid checkpoint");
    }
  }
}
