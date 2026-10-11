import { digestBytes, digestStructuredValue, parseDigest, type Digest } from "@circulusd/protocol-types";
import type { AgentEngine, ResumeTurnContext, StartTurnContext } from "../../session-host/src/index.ts";

import { PiRuntimeError } from "./errors.ts";
import { PI_EXECUTION_CONFIGURATION_DOMAIN, snapshotPiExecutionEnvironment, type PiExecutionEnvironment } from "./execution-environment.ts";
import { PiExecutionProxy } from "./execution-proxy.ts";
import { sameExecutionBinding, snapshotExecutionRequest, type PiExecutionBinding, type PiExecutionRequest } from "./execution-rpc.ts";
import { encodePiGenesisConfiguration, snapshotPiGenesisScope, type PiGenesisScope } from "./genesis.ts";
import type { PiAgentCoreAdapterConfiguration } from "./pi-agent-core-adapter.ts";
import { exactRecord } from "./validation.ts";

export const CELLD_EXECUTION_COMMIT = "89e4ffc53a14ecb496d2ca5014ff9d19b0061ad9";
export const PI_EXECUTION_CORE_MODULE = "circulusd/pi-execution-core.mjs";
export const PI_EXECUTION_ENTRY_MODULE = "circulusd/pi-execution-entry.mjs";
export const PI_EXECUTION_ENTRY_SOURCE =
  'import { WorkerEntrypoint } from "cloudflare:workers";\n' +
  `import { createPiExecutionEntrypointClass } from "${PI_EXECUTION_CORE_MODULE}";\n` +
  'export default createPiExecutionEntrypointClass(WorkerEntrypoint);\n';
const mappingDomain = "circulusd.pi.execution-runtime-mapping";
const constructorSeal = Symbol("verified Pi execution Loader composition");
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const bufferGetter = Object.getOwnPropertyDescriptor(typedArrayPrototype, "buffer")!.get!;
const lengthGetter = Object.getOwnPropertyDescriptor(typedArrayPrototype, "byteLength")!.get!;
const offsetGetter = Object.getOwnPropertyDescriptor(typedArrayPrototype, "byteOffset")!.get!;

export interface PiExecutionRuntimeModule {
  readonly specifier: string;
  readonly bytes: Uint8Array;
  readonly digest: Digest;
}
export interface PiExecutionRuntimeDefinition {
  readonly runtimeRevisionDigest: Digest;
  readonly adapterAbiVersion: 2;
  readonly checkpointSchemaVersion: 2;
  readonly compatibilityDate: string;
  readonly compatibilityFlags: readonly string[];
  readonly mainModule: typeof PI_EXECUTION_ENTRY_MODULE;
  readonly modules: readonly PiExecutionRuntimeModule[];
  readonly configuration: PiAgentCoreAdapterConfiguration;
}
export interface PiExecutionRuntimeVerifier {
  verify(binding: { readonly runtimeRevisionDigest: Digest; readonly artifactDigest: Digest }): Promise<{
    readonly runtimeRevisionDigest: Digest;
    readonly artifactDigest: Digest;
    readonly mappingDomain: typeof mappingDomain;
  }>;
}
export interface CelldExecutionWorkerDefinition {
  readonly mainModule: string;
  readonly modules: Readonly<Record<string, string>>;
  readonly compatibilityDate: string;
  readonly compatibilityFlags: readonly string[];
  readonly env: PiExecutionEnvironment;
  readonly globalOutbound: null;
}
export interface CelldExecutionWorker {
  getEntrypoint(): unknown;
  // Pinned native disposal schedules release. Its return is not stop evidence.
  dispose(): void;
}
export interface CelldExecutionLoader {
  get(name: string, getCode: () => Promise<CelldExecutionWorkerDefinition>): CelldExecutionWorker | Promise<CelldExecutionWorker>;
}
interface RuntimeArtifact {
  readonly runtimeRevisionDigest: Digest;
  readonly artifactDigest: Digest;
  readonly configurationDigest: Digest;
  readonly configuration: PiExecutionEnvironment["configuration"];
  readonly modules: Readonly<Record<string, string>>;
  readonly compatibilityDate: string;
  readonly compatibilityFlags: readonly string[];
}
function invalidRuntime(): never {
  throw new PiRuntimeError("INVALID_CONFIGURATION", "Pi execution runtime is invalid or unverified");
}
function unavailable(): never {
  throw new PiRuntimeError("ENGINE_POISONED", "Pi execution Loader is invalid or unavailable");
}
function canceled(): DOMException { return new DOMException("Pi execution initialization canceled", "AbortError"); }

function plainArray(value: unknown, maximum: number): readonly unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length > maximum ||
      Reflect.ownKeys(value).length !== value.length + 1) invalidRuntime();
  return Array.from({ length: value.length }, (_, index) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor?.enumerable || !("value" in descriptor)) invalidRuntime();
    return descriptor.value;
  });
}
function moduleBytes(value: unknown, remaining: number): Uint8Array {
  if (!(value instanceof Uint8Array) || Object.getPrototypeOf(value) !== Uint8Array.prototype) invalidRuntime();
  const buffer = bufferGetter.call(value) as ArrayBuffer;
  const length = lengthGetter.call(value) as number;
  const offset = offsetGetter.call(value) as number;
  if (!(buffer instanceof ArrayBuffer) || Object.getPrototypeOf(buffer) !== ArrayBuffer.prototype ||
      length < 1 || length > 8 * 1_048_576 || length > remaining) invalidRuntime();
  return new Uint8Array(new Uint8Array(buffer, offset, length));
}

async function snapshotArtifact(value: PiExecutionRuntimeDefinition): Promise<RuntimeArtifact> {
  try {
    const runtime = exactRecord(value, ["runtimeRevisionDigest", "adapterAbiVersion", "checkpointSchemaVersion",
      "compatibilityDate", "compatibilityFlags", "mainModule", "modules", "configuration"], [], "execution.runtime", "INVALID_CONFIGURATION");
    const revision = parseDigest(runtime.runtimeRevisionDigest);
    if (runtime.adapterAbiVersion !== 2 || runtime.checkpointSchemaVersion !== 2 || runtime.mainModule !== PI_EXECUTION_ENTRY_MODULE ||
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
    const seen = new Set<string>();
    let totalBytes = 0;
    // Every caller-owned value is copied before the first hash or verifier wait.
    const modules = candidates.map((candidate) => {
      const module = exactRecord(candidate, ["specifier", "bytes", "digest"], [], "execution.module", "INVALID_CONFIGURATION");
      if (typeof module.specifier !== "string" || module.specifier.length > 256 ||
          !/^[a-zA-Z0-9_/-]+\.m?js$/.test(module.specifier) || seen.has(module.specifier)) invalidRuntime();
      const bytes = moduleBytes(module.bytes, 32 * 1_048_576 - totalBytes);
      totalBytes += bytes.byteLength;
      if (totalBytes > 32 * 1_048_576) invalidRuntime();
      seen.add(module.specifier);
      const source = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
      return { specifier: module.specifier, bytes, source, digest: parseDigest(module.digest) };
    }).sort((left, right) => left.specifier < right.specifier ? -1 : left.specifier > right.specifier ? 1 : 0);
    if (!seen.has(PI_EXECUTION_CORE_MODULE) ||
        modules.find((module) => module.specifier === PI_EXECUTION_ENTRY_MODULE)?.source !== PI_EXECUTION_ENTRY_SOURCE) invalidRuntime();
    for (const module of modules) if (await digestBytes(module.bytes) !== module.digest) invalidRuntime();
    const configurationDigest = await digestStructuredValue(PI_EXECUTION_CONFIGURATION_DOMAIN, 1, configuration);
    const artifactDigest = await digestStructuredValue("circulusd.pi.execution-runtime-artifact", 1, {
      celldCommit: CELLD_EXECUTION_COMMIT, adapterAbiVersion: 2, checkpointSchemaVersion: 2,
      compatibilityDate: date, compatibilityFlags: flags, mainModule: PI_EXECUTION_ENTRY_MODULE,
      modules: modules.map((module) => ({ specifier: module.specifier, digest: module.digest })), configuration,
    });
    const moduleMap: Record<string, string> = Object.create(null);
    for (const module of modules) moduleMap[module.specifier] = module.source;
    return { runtimeRevisionDigest: revision, artifactDigest, configurationDigest, configuration,
      modules: moduleMap, compatibilityDate: date, compatibilityFlags: flags };
  } catch { return invalidRuntime(); }
}

// Prepares an artifact digest for independent offline mapping/signature work;
// it does not authorize a runtime or call Loader.
export async function piExecutionRuntimeArtifactDigest(runtime: PiExecutionRuntimeDefinition): Promise<Digest> {
  return (await snapshotArtifact(runtime)).artifactDigest;
}

// Use a current-operation signal and remove its listener on every completion.
// Caller cancellation never implies remote native cancellation or termination.
async function awaitSignal<T>(work: () => T | Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) throw canceled();
  const stopped = Promise.withResolvers<never>();
  const abort = () => stopped.reject(canceled());
  signal.addEventListener("abort", abort, { once: true });
  try {
    return await Promise.race([Promise.resolve().then(() => {
      if (signal.aborted) throw canceled();
      return work();
    }), stopped.promise]);
  } finally { signal.removeEventListener("abort", abort); }
}

/** One verified artifact on one fresh loaded composition. Cached worker names
 * must not revive failed endpoints or their lifetime execution tombstones.
 * This adapter supplies no native probe, broker authority or readiness proof.
 */
export class CelldPiExecutionEngine implements AgentEngine {
  readonly #proxy: PiExecutionProxy;
  readonly #release: () => void;
  readonly #lifetime: AbortController;
  #closed = false;

  private constructor(seal: symbol, proxy: PiExecutionProxy, release: () => void, lifetime: AbortController) {
    if (seal !== constructorSeal) invalidRuntime();
    this.#proxy = proxy;
    this.#release = release;
    this.#lifetime = lifetime;
  }

  static async create(config: { readonly loader: CelldExecutionLoader; readonly verifier: PiExecutionRuntimeVerifier;
    readonly scope: PiGenesisScope; readonly runtime: PiExecutionRuntimeDefinition; readonly timeoutMs?: number },
  signal?: AbortSignal): Promise<CelldPiExecutionEngine> {
    if (signal?.aborted) throw canceled();
    let authorized = false;
    let published = false;
    const owner: { release: (() => void) | null } = { release: null };
    let timer: ReturnType<typeof setTimeout> | undefined;
    const creation = new AbortController();
    const abort = () => creation.abort();
    try {
      const value = exactRecord(config, ["loader", "verifier", "scope", "runtime"], ["timeoutMs"], "execution.composition", "INVALID_CONFIGURATION");
      const loader = value.loader as CelldExecutionLoader, verifier = value.verifier as PiExecutionRuntimeVerifier;
      const get = loader?.get, verify = verifier?.verify;
      if (typeof get !== "function" || typeof verify !== "function") invalidRuntime();
      const timeout = value.timeoutMs ?? 5000;
      if (typeof timeout !== "number" || !Number.isSafeInteger(timeout) || timeout < 1 || timeout > 30_000) invalidRuntime();
      const scope = snapshotPiGenesisScope(value.scope);
      signal?.addEventListener("abort", abort, { once: true });
      if (signal?.aborted) throw canceled();
      timer = setTimeout(abort, timeout);
      // Start this synchronously: its snapshot must finish before create first
      // yields, even when the caller mutates inputs in the same event-loop turn.
      const artifactWork = snapshotArtifact(value.runtime as PiExecutionRuntimeDefinition);
      void artifactWork.catch(() => undefined);
      const artifact = await awaitSignal(() => artifactWork, creation.signal);
      const binding: PiExecutionBinding = Object.freeze({ scope: Object.freeze(scope),
        runtimeRevisionDigest: artifact.runtimeRevisionDigest, artifactDigest: artifact.artifactDigest });
      const attestation = await awaitSignal(() => Reflect.apply(verify, verifier, [{
        runtimeRevisionDigest: binding.runtimeRevisionDigest, artifactDigest: binding.artifactDigest,
      }]), creation.signal);
      const checked = exactRecord(attestation, ["runtimeRevisionDigest", "artifactDigest", "mappingDomain"], [], "execution.verifiedRuntime", "INVALID_CONFIGURATION");
      if (checked.runtimeRevisionDigest !== binding.runtimeRevisionDigest || checked.artifactDigest !== binding.artifactDigest ||
          checked.mappingDomain !== mappingDomain) invalidRuntime();
      authorized = true;
      const environment = snapshotPiExecutionEnvironment({ ...binding,
        configuration: artifact.configuration, configurationDigest: artifact.configurationDigest });
      if (new TextEncoder().encode(JSON.stringify(environment)).byteLength > 1_048_576) invalidRuntime();
      const identity = await awaitSignal(() => digestStructuredValue("circulusd.pi.execution-worker", 1, binding), creation.signal);
      const epoch = crypto.randomUUID();
      const definition: CelldExecutionWorkerDefinition = { mainModule: PI_EXECUTION_ENTRY_MODULE,
        modules: { ...artifact.modules }, compatibilityDate: artifact.compatibilityDate,
        compatibilityFlags: [...artifact.compatibilityFlags], env: environment, globalOutbound: null };
      const loading = Promise.resolve().then(() => {
        if (creation.signal.aborted) throw canceled();
        return Reflect.apply(get, loader, [`pi-execution/${identity}/${epoch}`, async () => structuredClone(definition)]);
      }).then((worker: CelldExecutionWorker) => {
        const dispose = worker?.dispose;
        if (typeof dispose !== "function") unavailable();
        let released = false;
        const ownedRelease = () => {
          if (released) return;
          released = true;
          Reflect.apply(dispose, worker, []);
        };
        if (creation.signal.aborted && !published) {
          try { ownedRelease(); } catch { /* Native release is best-effort, not proof. */ }
          throw canceled();
        }
        owner.release = ownedRelease;
        return worker;
      });
      // get() may synchronously cancel the factory. In that case awaitSignal
      // can stop before adopting loading; late release/rejection still needs
      // an observer independent of that canceled wait.
      void loading.catch(() => undefined);
      const worker = await awaitSignal(() => loading, creation.signal);
      const getEntrypoint = worker?.getEntrypoint;
      if (typeof getEntrypoint !== "function") unavailable();
      const entrypoint = Reflect.apply(getEntrypoint, worker, []);
      if (entrypoint === null || (typeof entrypoint !== "object" && typeof entrypoint !== "function")) unavailable();
      const exchange = (entrypoint as { readonly exchange?: unknown }).exchange;
      if (typeof exchange !== "function") unavailable();
      const lifetime = new AbortController();
      const proxy = new PiExecutionProxy({ binding, timeoutMs: timeout, transport: { async exchange(input: PiExecutionRequest) {
        const request = snapshotExecutionRequest(input);
        if (!sameExecutionBinding(request.binding, binding)) unavailable();
        // Native RPC methods are pipeline proxies: .bind/.call/.apply would
        // dispatch a forbidden deeper RPC path. Reflect.apply invokes one hop.
        return awaitSignal(() => Reflect.apply(exchange, entrypoint, [request]), lifetime.signal);
      } } });
      if (creation.signal.aborted || owner.release === null) throw canceled();
      const result = new CelldPiExecutionEngine(constructorSeal, proxy, owner.release, lifetime);
      published = true;
      return result;
    } catch {
      if (owner.release !== null && !published) { try { owner.release(); } catch { /* Owned native release only. */ } }
      if (signal?.aborted) throw canceled();
      if (authorized) return unavailable();
      return invalidRuntime();
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
    }
  }

  startTurn(context: StartTurnContext) {
    if (this.#closed) unavailable();
    return this.#proxy.startTurn(context);
  }
  resumeTurn(context: ResumeTurnContext) {
    if (this.#closed) unavailable();
    return this.#proxy.resumeTurn(context);
  }
  abortTurn(turnId: string, executionId?: string): Promise<void> { return this.#proxy.abortTurn(turnId, executionId); }

  // Closes local waits and schedules one owned native stub release. Native
  // in-flight work may outlive it; this is deliberately not a stop receipt.
  dispose(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#lifetime.abort();
    try { this.#release(); } catch { unavailable(); }
  }
}
