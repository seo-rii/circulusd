import { digestStructuredValue, normalizeStringSet } from "@circulusd/protocol-types";

export type SessionHostErrorCode =
  | "INVALID_RUNTIME"
  | "RUNTIME_UNVERIFIED"
  | "RUNTIME_TOO_LARGE"
  | "MODULE_DIGEST_MISMATCH"
  | "INVALID_TURN"
  | "INVALID_AGENT_EVENT"
  | "DURABLE_COMMIT_FAILED"
  | "EVENT_BUDGET_EXCEEDED"
  | "ENGINE_ENDED_WITHOUT_BOUNDARY";

export class SessionHostError extends Error {
  readonly code: SessionHostErrorCode;

  constructor(code: SessionHostErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "SessionHostError";
    this.code = code;
  }
}

export interface RuntimeModule {
  specifier: string;
  bytes: Uint8Array;
  digest: string;
}

export interface RuntimeRevision {
  sessionId: string;
  runtimeRevisionDigest: string;
  piAdapterAbi: number;
  compatibilityDate: string;
  compatibilityFlags: string[];
  mainModule: string;
  modules: RuntimeModule[];
  limits: {
    cpuMs: number;
    subRequests: number;
  };
}

export interface RuntimeVerifier {
  verify(revision: RuntimeRevision): Promise<{
    readonly revisionDigest: string;
    readonly runtimeIdentityDigest: string;
  }>;
}

export interface BrokerBindings {
  readonly STATE: unknown;
  readonly WORKSPACE: unknown;
  readonly MODEL: unknown;
  readonly MCP: unknown;
  readonly EXECUTOR: unknown;
  readonly ARTIFACTS: unknown;
  readonly EVENTS: unknown;
}

export interface WorkerDefinition {
  readonly compatibilityDate: string;
  readonly compatibilityFlags: readonly string[];
  readonly limits: {
    readonly cpuMs: number;
    readonly subRequests: number;
  };
  readonly mainModule: string;
  readonly modules: readonly RuntimeModule[];
  readonly env: BrokerBindings;
  readonly globalOutbound: null;
}

export interface WorkerLoader {
  get(workerId: string, factory: () => Promise<WorkerDefinition>): Promise<object>;
}

export interface SessionHostLimits {
  readonly maximumModules: number;
  readonly maximumModuleBytes: number;
  readonly maximumBundleBytes: number;
  readonly maximumAuthorityBytes: number;
  // Bounds a conservative canonical binary-size estimate for both turn input
  // and AgentEvent snapshots before any structured clone is allocated.
  readonly maximumEventBytes: number;
}

export type EphemeralAgentEvent = {
  readonly type: "assistant_delta";
  readonly delta: unknown;
};

export type DurableAgentEvent =
  | {
      readonly type: "model_request";
      readonly checkpoint: unknown;
      readonly request: unknown;
    }
  | {
      readonly type: "tool_request";
      readonly checkpoint: unknown;
      readonly request: unknown;
    }
  | { readonly type: "checkpoint"; readonly checkpoint: unknown }
  | {
      readonly type: "turn_complete";
      readonly checkpoint: unknown;
      readonly result: unknown;
    }
  | {
      readonly type: "turn_error";
      readonly checkpoint: unknown;
      readonly error: unknown;
    };

export type AgentEvent = EphemeralAgentEvent | DurableAgentEvent;

export interface StartTurnContext {
  readonly turnId: string;
  readonly executionId: string;
  readonly authority: Uint8Array;
  readonly checkpoint: unknown;
}

export interface ResumeTurnContext extends StartTurnContext {
  readonly settlement: unknown;
}

export interface AgentEngine {
  startTurn(context: StartTurnContext): AsyncIterable<AgentEvent>;
  resumeTurn(context: ResumeTurnContext): AsyncIterable<AgentEvent>;
  abortTurn(turnId: string, executionId?: string): Promise<void>;
}

export interface DurableEventCommitter {
  commit(event: DurableAgentEvent): Promise<void>;
}

export interface EphemeralEventSink {
  emit(event: EphemeralAgentEvent): Promise<void>;
}

export interface DriveTurnOptions {
  readonly turnId: string;
  readonly authority: Uint8Array;
  readonly checkpoint: unknown;
  readonly committer: DurableEventCommitter;
  readonly ephemeralSink: EphemeralEventSink;
  readonly maximumEvents: number;
}

export interface ResumeTurnOptions extends DriveTurnOptions {
  readonly settlement: unknown;
}

export interface DriveTurnResult {
  readonly boundary: Extract<
    AgentEvent,
    { readonly type: "model_request" | "tool_request" | "turn_complete" | "turn_error" }
  >;
  readonly eventsObserved: number;
}

interface ValidatedDriveTurnOptions {
  readonly turnId: string;
  readonly executionId: string;
  readonly authority: Uint8Array;
  readonly maximumEvents: number;
  readonly commit: (event: DurableAgentEvent) => Promise<void>;
  readonly emit: (event: EphemeralAgentEvent) => Promise<void>;
}

const DEFAULT_LIMITS: SessionHostLimits = {
  maximumModules: 256,
  maximumModuleBytes: 8 << 20,
  maximumBundleBytes: 32 << 20,
  maximumAuthorityBytes: 64 << 10,
  maximumEventBytes: 1 << 20,
};

const MAXIMUM_COMPATIBILITY_FLAGS = 256;

const RUNTIME_FIELDS = [
  "sessionId",
  "runtimeRevisionDigest",
  "piAdapterAbi",
  "compatibilityDate",
  "compatibilityFlags",
  "mainModule",
  "modules",
  "limits",
] as const;

const textEncoder = new TextEncoder();

function validatedExactKeys(
  value: unknown,
  fields: readonly string[],
  field: string,
  code: SessionHostErrorCode,
): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new SessionHostError(code, `${field} must be an object`);
  }
  const record = value as Record<string, unknown>;
  for (const key of Reflect.ownKeys(record)) {
    if (typeof key !== "string" || !fields.includes(key)) {
      throw new SessionHostError(code, `${field} has unknown field ${String(key)}`);
    }
    const descriptor = Object.getOwnPropertyDescriptor(record, key);
    if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor)) {
      throw new SessionHostError(
        code,
        `${field}.${key} must be an enumerable accessor-free data field`,
      );
    }
  }
  for (const key of fields) {
    if (!Object.prototype.hasOwnProperty.call(record, key)) {
      throw new SessionHostError(code, `${field} is missing field ${key}`);
    }
  }
  return record;
}

function validatedStructuredClone(
  value: unknown,
  field: string,
  code: SessionHostErrorCode,
  maximumBytes: number,
): unknown {
  const pending: Array<{
    readonly path: string;
    readonly value: unknown;
    readonly depth: number;
  }> = [
    { path: field, value, depth: 0 },
  ];
  const visited = new WeakSet<object>();
  const maximumNodes = Math.min(maximumBytes, 65_536);
  let estimatedBytes = 0;
  let nodesVisited = 0;
  while (pending.length > 0) {
    const candidate = pending.pop();
    if (candidate === undefined) continue;
    nodesVisited += 1;
    if (nodesVisited > maximumNodes || candidate.depth > 128) {
      throw new SessionHostError(code, `${field} exceeds its structural budget`);
    }
    if (candidate.value === undefined) {
      throw new SessionHostError(code, `${candidate.path} cannot contain undefined`);
    }
    if (typeof candidate.value === "number") {
      if (!Number.isFinite(candidate.value) || Object.is(candidate.value, -0)) {
        throw new SessionHostError(code, `${candidate.path} must be a canonical finite number`);
      }
      estimatedBytes += 9;
      if (estimatedBytes > maximumBytes) {
        throw new SessionHostError(code, `${field} exceeds its size limit`);
      }
      continue;
    }
    if (typeof candidate.value === "string") {
      if (candidate.value.length > maximumBytes - estimatedBytes) {
        throw new SessionHostError(code, `${field} exceeds its size limit`);
      }
      estimatedBytes += textEncoder.encode(candidate.value).byteLength + 9;
      if (estimatedBytes > maximumBytes) {
        throw new SessionHostError(code, `${field} exceeds its size limit`);
      }
      continue;
    }
    if (candidate.value === null || typeof candidate.value === "boolean") {
      estimatedBytes += 9;
      if (estimatedBytes > maximumBytes) {
        throw new SessionHostError(code, `${field} exceeds its size limit`);
      }
      continue;
    }
    if (typeof candidate.value !== "object") {
      throw new SessionHostError(code, `${candidate.path} contains an unsupported value`);
    }
    if (visited.has(candidate.value)) {
      throw new SessionHostError(code, `${candidate.path} contains a repeated object reference`);
    }
    visited.add(candidate.value);
    estimatedBytes += 9;
    if (estimatedBytes > maximumBytes) {
      throw new SessionHostError(code, `${field} exceeds its size limit`);
    }

    if (candidate.value instanceof Uint8Array) {
      if (
        Object.getPrototypeOf(candidate.value) !== Uint8Array.prototype ||
        !(candidate.value.buffer instanceof ArrayBuffer) ||
        Object.getPrototypeOf(candidate.value.buffer) !== ArrayBuffer.prototype ||
        candidate.value.byteOffset !== 0 ||
        candidate.value.byteLength !== candidate.value.buffer.byteLength
      ) {
        throw new SessionHostError(code, `${candidate.path} has an unsupported byte view`);
      }
      if (candidate.value.byteLength > maximumBytes - estimatedBytes) {
        throw new SessionHostError(code, `${field} exceeds its size limit`);
      }
      estimatedBytes += candidate.value.byteLength;
      if (candidate.value.byteLength <= 4_096) {
        const byteKeys = Reflect.ownKeys(candidate.value);
        if (byteKeys.length !== candidate.value.length) {
          throw new SessionHostError(code, `${candidate.path} has a non-canonical byte view`);
        }
        for (const key of byteKeys) {
          if (
            typeof key !== "string" ||
            !/^(0|[1-9][0-9]*)$/.test(key) ||
            Number(key) >= candidate.value.length
          ) {
            throw new SessionHostError(code, `${candidate.path} has a non-canonical byte field`);
          }
          const descriptor = Object.getOwnPropertyDescriptor(candidate.value, key);
          if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor)) {
            throw new SessionHostError(code, `${candidate.path}.${key} must be a byte data field`);
          }
        }
      }
      continue;
    }
    if (candidate.value instanceof ArrayBuffer) {
      throw new SessionHostError(code, `${candidate.path} contains an unsupported raw buffer`);
    }

    const isArray = Array.isArray(candidate.value);
    const prototype = Object.getPrototypeOf(candidate.value);
    if (
      (!isArray && prototype !== Object.prototype && prototype !== null) ||
      (isArray && prototype !== Array.prototype)
    ) {
      throw new SessionHostError(code, `${candidate.path} contains an unsupported object`);
    }
    if (
      isArray &&
      (candidate.value.length > maximumNodes ||
        candidate.value.length > Math.floor((maximumBytes - estimatedBytes) / 9))
    ) {
      throw new SessionHostError(code, `${field} exceeds its structural budget`);
    }
    const ownKeys = Reflect.ownKeys(candidate.value);
    if (isArray && ownKeys.length !== candidate.value.length + 1) {
      throw new SessionHostError(code, `${candidate.path} must be a dense canonical array`);
    }
    for (const key of ownKeys) {
      if (isArray && key === "length") continue;
      if (typeof key !== "string") {
        throw new SessionHostError(code, `${candidate.path} contains a symbol field`);
      }
      if (
        isArray &&
        (!/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= candidate.value.length)
      ) {
        throw new SessionHostError(code, `${candidate.path} has a non-canonical array field`);
      }
      if (!isArray) {
        if (key.length > maximumBytes - estimatedBytes) {
          throw new SessionHostError(code, `${field} exceeds its size limit`);
        }
        estimatedBytes += textEncoder.encode(key).byteLength + 9;
        if (estimatedBytes > maximumBytes) {
          throw new SessionHostError(code, `${field} exceeds its size limit`);
        }
      }
      const descriptor = Object.getOwnPropertyDescriptor(candidate.value, key);
      if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor)) {
        throw new SessionHostError(
          code,
          `${candidate.path}.${key} must be an enumerable accessor-free data field`,
        );
      }
      pending.push({
        path: `${candidate.path}.${key}`,
        value: descriptor.value,
        depth: candidate.depth + 1,
      });
    }
  }
  try {
    return structuredClone(value);
  } catch (error) {
    throw new SessionHostError(code, `${field} is not safely cloneable`, { cause: error });
  }
}

function validatedIdentifier(value: unknown, field: string, code: SessionHostErrorCode): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 512 ||
    value.normalize("NFC") !== value ||
    textEncoder.encode(value).byteLength > 512 ||
    /\p{Cc}/u.test(value)
  ) {
    throw new SessionHostError(code, `${field} is not a canonical identifier`);
  }
  return value;
}

function validatedDataArray(
  value: unknown,
  field: string,
  code: SessionHostErrorCode,
  maximumLength: number,
  lengthCode: SessionHostErrorCode = code,
): unknown[] {
  if (!Array.isArray(value)) {
    throw new SessionHostError(code, `${field} must be an array`);
  }
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
  if (
    lengthDescriptor === undefined ||
    !("value" in lengthDescriptor) ||
    !Number.isSafeInteger(lengthDescriptor.value)
  ) {
    throw new SessionHostError(code, `${field} has an invalid array length`);
  }
  if (lengthDescriptor.value > maximumLength) {
    throw new SessionHostError(lengthCode, `${field} exceeds its bounded array length`);
  }
  const length = lengthDescriptor.value as number;
  const result: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (descriptor === undefined || !("value" in descriptor)) {
      throw new SessionHostError(code, `${field}[${index}] must be an accessor-free data field`);
    }
    result.push(descriptor.value);
  }
  for (const key of Reflect.ownKeys(value)) {
    if (key === "length") {
      continue;
    }
    if (
      typeof key !== "string" ||
      !/^(0|[1-9][0-9]*)$/.test(key) ||
      Number(key) >= length
    ) {
      throw new SessionHostError(code, `${field} has unknown field ${String(key)}`);
    }
  }
  return result;
}

export class SessionHost {
  readonly #loader: WorkerLoader;
  readonly #verifier: RuntimeVerifier;
  readonly #bindings: BrokerBindings;
  readonly #limits: SessionHostLimits;
  readonly #activeTurns = new WeakMap<AgentEngine, Set<string>>();

  constructor(config: {
    readonly loader: WorkerLoader;
    readonly verifier: RuntimeVerifier;
    readonly bindings: BrokerBindings;
    readonly limits?: Partial<SessionHostLimits>;
  }) {
    if (config.loader === undefined || config.verifier === undefined || config.bindings === undefined) {
      throw new SessionHostError("INVALID_RUNTIME", "loader, verifier, and bindings are required");
    }
    const limits = { ...DEFAULT_LIMITS, ...config.limits };
    if (
      !Number.isSafeInteger(limits.maximumModules) ||
      limits.maximumModules <= 0 ||
      !Number.isSafeInteger(limits.maximumModuleBytes) ||
      limits.maximumModuleBytes <= 0 ||
      !Number.isSafeInteger(limits.maximumBundleBytes) ||
      limits.maximumBundleBytes <= 0 ||
      !Number.isSafeInteger(limits.maximumAuthorityBytes) ||
      limits.maximumAuthorityBytes <= 0 ||
      !Number.isSafeInteger(limits.maximumEventBytes) ||
      limits.maximumEventBytes <= 0
    ) {
      throw new SessionHostError("INVALID_RUNTIME", "all SessionHost limits must be positive");
    }
    this.#loader = config.loader;
    this.#verifier = config.verifier;
    const bindingRecord = validatedExactKeys(
      config.bindings,
      ["STATE", "WORKSPACE", "MODEL", "MCP", "EXECUTOR", "ARTIFACTS", "EVENTS"],
      "bindings",
      "INVALID_RUNTIME",
    );
    for (const [name, binding] of Object.entries(bindingRecord)) {
      if (binding === null || binding === undefined) {
        throw new SessionHostError("INVALID_RUNTIME", `binding ${name} is unavailable`);
      }
    }
    this.#bindings = config.bindings;
    this.#limits = limits;
  }

  async load(runtime: RuntimeRevision): Promise<{ readonly workerId: string; readonly worker: object }> {
    validatedExactKeys(runtime, RUNTIME_FIELDS, "runtime", "INVALID_RUNTIME");
    validatedExactKeys(runtime.limits, ["cpuMs", "subRequests"], "runtime.limits", "INVALID_RUNTIME");
    const compatibilityFlags = validatedDataArray(
      runtime.compatibilityFlags,
      "runtime.compatibilityFlags",
      "INVALID_RUNTIME",
      MAXIMUM_COMPATIBILITY_FLAGS,
    );
    const sessionId = validatedIdentifier(runtime.sessionId, "sessionId", "INVALID_RUNTIME");
    const runtimeRevisionDigest = runtime.runtimeRevisionDigest;
    const piAdapterAbi = runtime.piAdapterAbi;
    const compatibilityDate = runtime.compatibilityDate;
    const cpuMs = runtime.limits.cpuMs;
    const subRequests = runtime.limits.subRequests;
    const parsedCompatibilityDate =
      typeof compatibilityDate === "string" && compatibilityDate.length === 10
        ? new Date(`${compatibilityDate}T00:00:00.000Z`)
        : null;
    if (
      !/^sess_[A-Z2-7]{25}[AEIMQUY4]$/.test(sessionId) ||
      typeof runtimeRevisionDigest !== "string" ||
      runtimeRevisionDigest.length !== 71 ||
      !/^sha256:[0-9a-f]{64}$/.test(runtimeRevisionDigest) ||
      !Number.isSafeInteger(piAdapterAbi) ||
      piAdapterAbi <= 0 ||
      typeof compatibilityDate !== "string" ||
      compatibilityDate.length !== 10 ||
      !/^\d{4}-\d{2}-\d{2}$/.test(compatibilityDate) ||
      parsedCompatibilityDate === null ||
      Number.isNaN(parsedCompatibilityDate.getTime()) ||
      parsedCompatibilityDate.toISOString().slice(0, 10) !== compatibilityDate ||
      !Number.isSafeInteger(cpuMs) ||
      cpuMs <= 0 ||
      !Number.isSafeInteger(subRequests) ||
      subRequests < 0
    ) {
      throw new SessionHostError("INVALID_RUNTIME", "runtime revision or limits are invalid");
    }
    const validatedCompatibilityFlags: string[] = [];
    for (const [index, candidate] of compatibilityFlags.entries()) {
      validatedCompatibilityFlags.push(
        validatedIdentifier(candidate, `compatibilityFlags[${index}]`, "INVALID_RUNTIME"),
      );
    }
    let canonicalCompatibilityFlags: readonly string[];
    try {
      canonicalCompatibilityFlags = normalizeStringSet(validatedCompatibilityFlags);
    } catch (error) {
      throw new SessionHostError(
        "INVALID_RUNTIME",
        "compatibilityFlags must be a unique UTF-8-sorted set",
        { cause: error },
      );
    }
    if (
      canonicalCompatibilityFlags.some(
        (flag, index) => flag !== validatedCompatibilityFlags[index],
      )
    ) {
      throw new SessionHostError(
        "INVALID_RUNTIME",
        "compatibilityFlags must be a unique UTF-8-sorted set",
      );
    }
    const mainModule = validatedIdentifier(runtime.mainModule, "mainModule", "INVALID_RUNTIME");
    const moduleCandidates = validatedDataArray(
      runtime.modules,
      "runtime.modules",
      "INVALID_RUNTIME",
      this.#limits.maximumModules,
      "RUNTIME_TOO_LARGE",
    );
    if (moduleCandidates.length === 0) {
      throw new SessionHostError("INVALID_RUNTIME", "runtime modules must be a non-empty array");
    }
    let preflightBundleBytes = 0;
    for (const [index, candidate] of moduleCandidates.entries()) {
      const record = validatedExactKeys(
        candidate,
        ["specifier", "bytes", "digest"],
        `runtime.modules[${index}]`,
        "INVALID_RUNTIME",
      );
      const specifierDescriptor = Object.getOwnPropertyDescriptor(record, "specifier");
      const digestDescriptor = Object.getOwnPropertyDescriptor(record, "digest");
      const preflightSpecifier = validatedIdentifier(
        specifierDescriptor !== undefined && "value" in specifierDescriptor
          ? specifierDescriptor.value
          : null,
        `runtime.modules[${index}].specifier`,
        "INVALID_RUNTIME",
      );
      if (
        preflightSpecifier.startsWith("/") ||
        preflightSpecifier
          .split("/")
          .some((component) => component === "" || component === "." || component === "..")
      ) {
        throw new SessionHostError(
          "INVALID_RUNTIME",
          `module specifier ${preflightSpecifier} is unsafe`,
        );
      }
      const preflightDigest =
        digestDescriptor !== undefined && "value" in digestDescriptor
          ? digestDescriptor.value
          : null;
      if (
        typeof preflightDigest !== "string" ||
        preflightDigest.length !== 71 ||
        !/^sha256:[0-9a-f]{64}$/.test(preflightDigest)
      ) {
        throw new SessionHostError(
          "INVALID_RUNTIME",
          `runtime.modules[${index}].digest is invalid`,
        );
      }
      let moduleByteLength: number;
      try {
        const descriptor = Object.getOwnPropertyDescriptor(record, "bytes");
        const bytes = descriptor !== undefined && "value" in descriptor ? descriptor.value : null;
        if (
          !(bytes instanceof Uint8Array) ||
          Object.getPrototypeOf(bytes) !== Uint8Array.prototype ||
          !(bytes.buffer instanceof ArrayBuffer) ||
          Object.getPrototypeOf(bytes.buffer) !== ArrayBuffer.prototype ||
          bytes.byteOffset !== 0 ||
          bytes.byteLength !== bytes.buffer.byteLength
        ) {
          throw new SessionHostError(
            "INVALID_RUNTIME",
            `runtime.modules[${index}].bytes is not a canonical byte view`,
          );
        }
        moduleByteLength = bytes.byteLength;
      } catch (error) {
        if (error instanceof SessionHostError) throw error;
        throw new SessionHostError(
          "INVALID_RUNTIME",
          `runtime.modules[${index}].bytes is not safely inspectable`,
          { cause: error },
        );
      }
      if (moduleByteLength > this.#limits.maximumModuleBytes) {
        throw new SessionHostError(
          "RUNTIME_TOO_LARGE",
          `runtime.modules[${index}] exceeds its limit`,
        );
      }
      preflightBundleBytes += moduleByteLength;
      if (
        !Number.isSafeInteger(preflightBundleBytes) ||
        preflightBundleBytes > this.#limits.maximumBundleBytes
      ) {
        throw new SessionHostError("RUNTIME_TOO_LARGE", "runtime bundle exceeds its limit");
      }
    }
    try {
      runtime = structuredClone(runtime);
    } catch (error) {
      throw new SessionHostError("INVALID_RUNTIME", "runtime is not safely cloneable", {
        cause: error,
      });
    }
    let verifiedRevisionDigest: string;
    let verifiedRuntimeIdentityDigest: string;
    try {
      const verified = validatedExactKeys(
        validatedStructuredClone(
          await this.#verifier.verify(structuredClone(runtime)),
          "runtime verification",
          "RUNTIME_UNVERIFIED",
          1_024,
        ),
        ["revisionDigest", "runtimeIdentityDigest"],
        "runtime verification",
        "RUNTIME_UNVERIFIED",
      );
      if (
        typeof verified.revisionDigest !== "string" ||
        typeof verified.runtimeIdentityDigest !== "string" ||
        !/^sha256:[0-9a-f]{64}$/.test(verified.runtimeIdentityDigest)
      ) {
        throw new SessionHostError(
          "RUNTIME_UNVERIFIED",
          "runtime verifier returned an invalid attestation",
        );
      }
      verifiedRevisionDigest = verified.revisionDigest;
      verifiedRuntimeIdentityDigest = verified.runtimeIdentityDigest;
    } catch (error) {
      throw new SessionHostError("RUNTIME_UNVERIFIED", "runtime signature verification failed", {
        cause: error,
      });
    }
    if (verifiedRevisionDigest !== runtimeRevisionDigest) {
      throw new SessionHostError(
        "RUNTIME_UNVERIFIED",
        "runtime verifier returned a different revision digest",
      );
    }
    let expectedRuntimeIdentityDigest: string;
    try {
      expectedRuntimeIdentityDigest = await digestStructuredValue("agent.worker-identity", 1, [
        sessionId,
        runtimeRevisionDigest,
        piAdapterAbi,
        compatibilityDate,
        canonicalCompatibilityFlags,
      ]);
    } catch (error) {
      throw new SessionHostError("RUNTIME_UNVERIFIED", "runtime identity derivation failed", {
        cause: error,
      });
    }
    if (verifiedRuntimeIdentityDigest !== expectedRuntimeIdentityDigest) {
      throw new SessionHostError(
        "RUNTIME_UNVERIFIED",
        "runtime verifier returned a different runtime identity digest",
      );
    }

    const modules: RuntimeModule[] = [];
    let totalBytes = 0;
    let previousSpecifier: Uint8Array | null = null;
    let foundMain = false;
    for (const [index, candidate] of runtime.modules.entries()) {
      const record = validatedExactKeys(
        candidate,
        ["specifier", "bytes", "digest"],
        `modules[${index}]`,
        "INVALID_RUNTIME",
      );
      const specifier = validatedIdentifier(
        record.specifier,
        `modules[${index}].specifier`,
        "INVALID_RUNTIME",
      );
      if (
        specifier.startsWith("/") ||
        specifier.split("/").some((component) => component === "" || component === "." || component === "..")
      ) {
        throw new SessionHostError("INVALID_RUNTIME", `module specifier ${specifier} is unsafe`);
      }
      const encodedSpecifier = textEncoder.encode(specifier);
      if (previousSpecifier !== null) {
        let comparison = 0;
        const length = Math.min(previousSpecifier.byteLength, encodedSpecifier.byteLength);
        for (let byteIndex = 0; byteIndex < length; byteIndex += 1) {
          const left = previousSpecifier[byteIndex];
          const right = encodedSpecifier[byteIndex];
          if (left !== right) {
            comparison = (left ?? 0) - (right ?? 0);
            break;
          }
        }
        if (comparison === 0) {
          comparison = previousSpecifier.byteLength - encodedSpecifier.byteLength;
        }
        if (comparison >= 0) {
          throw new SessionHostError(
            "INVALID_RUNTIME",
            "modules must be a unique UTF-8-sorted graph",
          );
        }
      }
      previousSpecifier = encodedSpecifier;
      if (!(record.bytes instanceof Uint8Array)) {
        throw new SessionHostError("INVALID_RUNTIME", `module ${specifier} bytes are invalid`);
      }
      if (record.bytes.byteLength > this.#limits.maximumModuleBytes) {
        throw new SessionHostError("RUNTIME_TOO_LARGE", `module ${specifier} exceeds its limit`);
      }
      totalBytes += record.bytes.byteLength;
      if (!Number.isSafeInteger(totalBytes) || totalBytes > this.#limits.maximumBundleBytes) {
        throw new SessionHostError("RUNTIME_TOO_LARGE", "runtime bundle exceeds its limit");
      }
      if (typeof record.digest !== "string" || !/^sha256:[0-9a-f]{64}$/.test(record.digest)) {
        throw new SessionHostError("INVALID_RUNTIME", `module ${specifier} digest is invalid`);
      }
      const bytes = new Uint8Array(record.bytes);
      const digestBytes = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
      const actualDigest = `sha256:${Array.from(digestBytes, (value) =>
        value.toString(16).padStart(2, "0"),
      ).join("")}`;
      if (actualDigest !== record.digest) {
        throw new SessionHostError(
          "MODULE_DIGEST_MISMATCH",
          `module ${specifier} failed digest verification`,
        );
      }
      foundMain ||= specifier === mainModule;
      modules.push({ specifier, bytes, digest: record.digest });
    }
    if (!foundMain) {
      throw new SessionHostError("INVALID_RUNTIME", "mainModule is absent from the module graph");
    }

    const workerId = `pi/${sessionId}/${expectedRuntimeIdentityDigest.replace("sha256:", "sha256-")}`;
    const worker = await this.#loader.get(workerId, async () => ({
      compatibilityDate,
      compatibilityFlags: [...canonicalCompatibilityFlags],
      limits: { cpuMs, subRequests },
      mainModule,
      modules: modules.map((module) => ({ ...module, bytes: new Uint8Array(module.bytes) })),
      env: {
        STATE: this.#bindings.STATE,
        WORKSPACE: this.#bindings.WORKSPACE,
        MODEL: this.#bindings.MODEL,
        MCP: this.#bindings.MCP,
        EXECUTOR: this.#bindings.EXECUTOR,
        ARTIFACTS: this.#bindings.ARTIFACTS,
        EVENTS: this.#bindings.EVENTS,
      },
      globalOutbound: null,
    }));
    return { workerId, worker };
  }

  async startTurn(engine: AgentEngine, options: DriveTurnOptions): Promise<DriveTurnResult> {
    validatedExactKeys(
      options,
      ["turnId", "authority", "checkpoint", "committer", "ephemeralSink", "maximumEvents"],
      "start turn options",
      "INVALID_TURN",
    );
    const validated = this.#validatedTurnOptions(options);
    const checkpoint = this.#cloneTurnValue(options.checkpoint, "checkpoint");
    if (typeof checkpoint !== "object" || checkpoint === null || Array.isArray(checkpoint)) {
      throw new SessionHostError("INVALID_TURN", "checkpoint must be an object");
    }
    return this.#beginDriving(
      engine,
      validated,
      () =>
        engine.startTurn({
          turnId: validated.turnId,
          executionId: validated.executionId,
          authority: validated.authority,
          checkpoint,
        }),
    );
  }

  async resumeTurn(engine: AgentEngine, options: ResumeTurnOptions): Promise<DriveTurnResult> {
    validatedExactKeys(
      options,
      [
        "turnId",
        "authority",
        "committer",
        "ephemeralSink",
        "maximumEvents",
        "checkpoint",
        "settlement",
      ],
      "resume turn options",
      "INVALID_TURN",
    );
    const validated = this.#validatedTurnOptions(options);
    const checkpoint = this.#cloneTurnValue(options.checkpoint, "checkpoint");
    if (typeof checkpoint !== "object" || checkpoint === null || Array.isArray(checkpoint)) {
      throw new SessionHostError("INVALID_TURN", "checkpoint must be an object");
    }
    const settlement = this.#cloneTurnValue(options.settlement, "settlement");
    return this.#beginDriving(
      engine,
      validated,
      () =>
        engine.resumeTurn({
          turnId: validated.turnId,
          executionId: validated.executionId,
          authority: validated.authority,
          checkpoint,
          settlement,
        }),
    );
  }

  async #beginDriving(
    engine: AgentEngine,
    options: ValidatedDriveTurnOptions,
    begin: () => AsyncIterable<AgentEvent>,
  ): Promise<DriveTurnResult> {
    const abortTurn = engine.abortTurn.bind(engine);
    let engineTurns = this.#activeTurns.get(engine);
    if (engineTurns === undefined) {
      engineTurns = new Set<string>();
      this.#activeTurns.set(engine, engineTurns);
    }
    if (engineTurns.has(options.turnId)) {
      throw new SessionHostError("INVALID_TURN", "turn already has an admitted execution");
    }
    engineTurns.add(options.turnId);
    try {
      try {
        const events = begin();
        return await this.#driveEvents(abortTurn, events, options);
      } catch (error) {
        if (error instanceof SessionHostError) throw error;
        try {
          await abortTurn(options.turnId, options.executionId);
        } catch {
          // Session state remains the durable failure authority when an isolate
          // cannot acknowledge the best-effort execution interrupt.
        }
        throw new SessionHostError("INVALID_AGENT_EVENT", "AgentEngine failed to start", {
          cause: error,
        });
      }
    } finally {
      engineTurns.delete(options.turnId);
      if (engineTurns.size === 0) {
        this.#activeTurns.delete(engine);
      }
    }
  }

  #validatedTurnOptions(options: DriveTurnOptions): {
    readonly turnId: string;
    readonly executionId: string;
    readonly authority: Uint8Array;
    readonly maximumEvents: number;
    readonly commit: (event: DurableAgentEvent) => Promise<void>;
    readonly emit: (event: EphemeralAgentEvent) => Promise<void>;
  } {
    const turnId = validatedIdentifier(options.turnId, "turnId", "INVALID_TURN");
    const committer = options.committer;
    const commit = committer?.commit;
    const ephemeralSink = options.ephemeralSink;
    const emit = ephemeralSink?.emit;
    let authority: Uint8Array;
    try {
      const candidate = options.authority;
      if (
        !(candidate instanceof Uint8Array) ||
        Object.getPrototypeOf(candidate) !== Uint8Array.prototype ||
        !(candidate.buffer instanceof ArrayBuffer) ||
        Object.getPrototypeOf(candidate.buffer) !== ArrayBuffer.prototype ||
        Reflect.ownKeys(candidate.buffer).length !== 0 ||
        candidate.byteOffset !== 0 ||
        candidate.byteLength !== candidate.buffer.byteLength ||
        candidate.byteLength === 0 ||
        candidate.byteLength > this.#limits.maximumAuthorityBytes
      ) {
        throw new SessionHostError("INVALID_TURN", "turn authority storage is invalid");
      }
      const authorityKeys = Reflect.ownKeys(candidate);
      if (authorityKeys.length !== candidate.byteLength) {
        throw new SessionHostError("INVALID_TURN", "turn authority byte view is not canonical");
      }
      for (const key of authorityKeys) {
        if (
          typeof key !== "string" ||
          !/^(0|[1-9][0-9]*)$/.test(key) ||
          Number(key) >= candidate.byteLength
        ) {
          throw new SessionHostError("INVALID_TURN", "turn authority has an unknown byte field");
        }
        const descriptor = Object.getOwnPropertyDescriptor(candidate, key);
        if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor)) {
          throw new SessionHostError("INVALID_TURN", "turn authority has a non-data byte field");
        }
      }
      authority = new Uint8Array(candidate);
    } catch (error) {
      if (error instanceof SessionHostError) throw error;
      throw new SessionHostError("INVALID_TURN", "turn authority storage is invalid", {
        cause: error,
      });
    }
    if (
      !Number.isSafeInteger(options.maximumEvents) ||
      options.maximumEvents <= 0 ||
      typeof commit !== "function" ||
      typeof emit !== "function"
    ) {
      throw new SessionHostError("INVALID_TURN", "turn authority, ports, or event budget is invalid");
    }
    const maximumEvents = options.maximumEvents;
    const executionEntropy = new Uint8Array(16);
    crypto.getRandomValues(executionEntropy);
    const executionId = `exec_${Array.from(executionEntropy, (value) =>
      value.toString(16).padStart(2, "0"),
    ).join("")}`;
    return {
      turnId,
      executionId,
      authority,
      maximumEvents,
      commit: (event) => commit.call(committer, event),
      emit: (event) => emit.call(ephemeralSink, event),
    };
  }

  #cloneTurnValue(value: unknown, field: string): unknown {
    return validatedStructuredClone(
      value,
      field,
      "INVALID_TURN",
      this.#limits.maximumEventBytes,
    );
  }

  async #driveEvents(
    abortTurn: (turnId: string, executionId?: string) => Promise<void>,
    events: AsyncIterable<AgentEvent>,
    options: ValidatedDriveTurnOptions,
  ): Promise<DriveTurnResult> {
    const turnId = options.turnId;
    let iterator: AsyncIterator<AgentEvent> | undefined;
    let iteratorClosed = false;
    let eventsObserved = 0;
    try {
      iterator = events[Symbol.asyncIterator]();
      while (true) {
        const next = await iterator.next();
        if (next.done) {
          throw new SessionHostError(
            "ENGINE_ENDED_WITHOUT_BOUNDARY",
            "AgentEngine ended without a terminal durable boundary",
          );
        }
        eventsObserved += 1;
        if (eventsObserved > options.maximumEvents) {
          throw new SessionHostError(
            "EVENT_BUDGET_EXCEEDED",
            `AgentEngine exceeded ${options.maximumEvents} events`,
          );
        }
        const event = next.value;
        if (typeof event !== "object" || event === null || Array.isArray(event)) {
          throw new SessionHostError("INVALID_AGENT_EVENT", "AgentEngine emitted a non-object event");
        }
        const typeDescriptor = Object.getOwnPropertyDescriptor(event, "type");
        if (typeDescriptor === undefined || !("value" in typeDescriptor)) {
          throw new SessionHostError(
            "INVALID_AGENT_EVENT",
            "AgentEvent.type must be an accessor-free data field",
          );
        }
        let fields: readonly string[];
        switch (typeDescriptor.value) {
          case "model_request":
          case "tool_request":
            fields = ["type", "checkpoint", "request"];
            break;
          case "assistant_delta":
            fields = ["type", "delta"];
            break;
          case "checkpoint":
            fields = ["type", "checkpoint"];
            break;
          case "turn_complete":
            fields = ["type", "checkpoint", "result"];
            break;
          case "turn_error":
            fields = ["type", "checkpoint", "error"];
            break;
          default:
            throw new SessionHostError("INVALID_AGENT_EVENT", "AgentEngine emitted an unknown event");
        }
        validatedExactKeys(event, fields, "AgentEvent", "INVALID_AGENT_EVENT");
        const checkpointValue = Object.getOwnPropertyDescriptor(event, "checkpoint")?.value;
        if (
          typeDescriptor.value !== "assistant_delta" &&
          (typeof checkpointValue !== "object" ||
            checkpointValue === null ||
            Array.isArray(checkpointValue))
        ) {
          throw new SessionHostError(
            "INVALID_AGENT_EVENT",
            "durable AgentEvent.checkpoint must be an object",
          );
        }
        let cloned: AgentEvent;
        try {
          cloned = validatedStructuredClone(
            event,
            "AgentEvent",
            "INVALID_AGENT_EVENT",
            this.#limits.maximumEventBytes,
          ) as AgentEvent;
        } catch (error) {
          if (error instanceof SessionHostError) throw error;
          throw new SessionHostError("INVALID_AGENT_EVENT", "AgentEvent is not serializable", {
            cause: error,
          });
        }
        if (cloned.type === "assistant_delta") {
          await options.emit(cloned as EphemeralAgentEvent);
          continue;
        }
        try {
          await options.commit(structuredClone(cloned) as DurableAgentEvent);
        } catch (error) {
          throw new SessionHostError(
            "DURABLE_COMMIT_FAILED",
            "durable AgentEvent commit failed",
            { cause: error },
          );
        }
        if (
          cloned.type === "model_request" ||
          cloned.type === "tool_request" ||
          cloned.type === "turn_complete" ||
          cloned.type === "turn_error"
        ) {
          iteratorClosed = true;
          try {
            const returnIterator = iterator.return;
            if (typeof returnIterator === "function") {
              void Promise.resolve(returnIterator.call(iterator)).catch(() => undefined);
            }
          } catch {
            // The terminal durable commit is already authoritative. Iterator
            // cleanup cannot convert it back into a failed drive.
          }
          return {
            boundary: cloned as DriveTurnResult["boundary"],
            eventsObserved,
          };
        }
      }
    } catch (error) {
      try {
        await abortTurn(turnId, options.executionId);
      } catch {
        // abortTurn is an execution interrupt. Session state remains the
        // durable abort/failure authority even if the isolate cannot respond.
      }
      if (!iteratorClosed && iterator !== undefined) {
        try {
          const returnIterator = iterator.return;
          if (typeof returnIterator === "function") {
            void Promise.resolve(returnIterator.call(iterator)).catch(() => undefined);
          }
        } catch {
          // Cleanup is best-effort and cannot block or replace the failure.
        }
      }
      if (error instanceof SessionHostError) {
        throw error;
      }
      throw new SessionHostError("INVALID_AGENT_EVENT", "AgentEngine event handling failed", {
        cause: error,
      });
    }
  }
}
