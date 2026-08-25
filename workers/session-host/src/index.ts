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
  runtimeIdentityDigest: string;
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
  verify(revision: RuntimeRevision): Promise<{ readonly revisionDigest: string }>;
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
  readonly maximumEventBytes: number;
}

export type AgentEvent =
  | { readonly type: "model_request"; readonly request: unknown }
  | { readonly type: "tool_request"; readonly request: unknown }
  | { readonly type: "assistant_delta"; readonly delta: unknown }
  | { readonly type: "checkpoint"; readonly checkpoint: unknown }
  | { readonly type: "turn_complete"; readonly result: unknown }
  | { readonly type: "turn_error"; readonly error: unknown };

export interface StartTurnContext {
  readonly turnId: string;
  readonly authority: Uint8Array;
}

export interface ResumeTurnContext extends StartTurnContext {
  readonly checkpoint: unknown;
  readonly settlement: unknown;
}

export interface AgentEngine {
  startTurn(context: StartTurnContext): AsyncIterable<AgentEvent>;
  resumeTurn(context: ResumeTurnContext): AsyncIterable<AgentEvent>;
  abortTurn(turnId: string): Promise<void>;
}

export interface DurableEventCommitter {
  commit(event: AgentEvent): Promise<void>;
}

export interface EphemeralEventSink {
  emit(event: AgentEvent): Promise<void>;
}

export interface DriveTurnOptions {
  readonly turnId: string;
  readonly authority: Uint8Array;
  readonly committer: DurableEventCommitter;
  readonly ephemeralSink: EphemeralEventSink;
  readonly maximumEvents: number;
}

export interface ResumeTurnOptions extends DriveTurnOptions {
  readonly checkpoint: unknown;
  readonly settlement: unknown;
}

export interface DriveTurnResult {
  readonly boundary: Extract<
    AgentEvent,
    { readonly type: "model_request" | "tool_request" | "turn_complete" | "turn_error" }
  >;
  readonly eventsObserved: number;
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
  "runtimeIdentityDigest",
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
    if (descriptor === undefined || !("value" in descriptor)) {
      throw new SessionHostError(code, `${field}.${key} must be an accessor-free data field`);
    }
  }
  for (const key of fields) {
    if (!Object.prototype.hasOwnProperty.call(record, key)) {
      throw new SessionHostError(code, `${field} is missing field ${key}`);
    }
  }
  return record;
}

function validatedIdentifier(value: unknown, field: string, code: SessionHostErrorCode): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
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
    for (const [index, flag] of compatibilityFlags.entries()) {
      if (typeof flag !== "string") {
        throw new SessionHostError(
          "INVALID_RUNTIME",
          `runtime.compatibilityFlags[${index}] must be a string`,
        );
      }
    }
    const moduleCandidates = validatedDataArray(
      runtime.modules,
      "runtime.modules",
      "INVALID_RUNTIME",
      this.#limits.maximumModules,
      "RUNTIME_TOO_LARGE",
    );
    for (const [index, candidate] of moduleCandidates.entries()) {
      validatedExactKeys(
        candidate,
        ["specifier", "bytes", "digest"],
        `runtime.modules[${index}]`,
        "INVALID_RUNTIME",
      );
    }
    try {
      runtime = structuredClone(runtime);
    } catch (error) {
      throw new SessionHostError("INVALID_RUNTIME", "runtime is not safely cloneable", {
        cause: error,
      });
    }
    const sessionId = validatedIdentifier(runtime.sessionId, "sessionId", "INVALID_RUNTIME");
    if (
      !/^sha256:[0-9a-f]{64}$/.test(runtime.runtimeRevisionDigest) ||
      !/^sha256:[0-9a-f]{64}$/.test(runtime.runtimeIdentityDigest) ||
      !Number.isSafeInteger(runtime.piAdapterAbi) ||
      runtime.piAdapterAbi <= 0 ||
      !/^\d{4}-\d{2}-\d{2}$/.test(runtime.compatibilityDate) ||
      !Number.isSafeInteger(runtime.limits?.cpuMs) ||
      runtime.limits.cpuMs <= 0 ||
      !Number.isSafeInteger(runtime.limits.subRequests) ||
      runtime.limits.subRequests < 0
    ) {
      throw new SessionHostError("INVALID_RUNTIME", "runtime identity or limits are invalid");
    }
    validatedExactKeys(runtime.limits, ["cpuMs", "subRequests"], "runtime.limits", "INVALID_RUNTIME");
    if (!Array.isArray(runtime.compatibilityFlags)) {
      throw new SessionHostError("INVALID_RUNTIME", "compatibilityFlags must be an array");
    }
    let previousFlag: Uint8Array | null = null;
    for (const [index, candidate] of runtime.compatibilityFlags.entries()) {
      const flag = validatedIdentifier(candidate, `compatibilityFlags[${index}]`, "INVALID_RUNTIME");
      const encoded = textEncoder.encode(flag);
      if (previousFlag !== null) {
        let comparison = previousFlag.byteLength - encoded.byteLength;
        const length = Math.min(previousFlag.byteLength, encoded.byteLength);
        for (let byteIndex = 0; byteIndex < length; byteIndex += 1) {
          const left = previousFlag[byteIndex];
          const right = encoded[byteIndex];
          if (left !== right) {
            comparison = (left ?? 0) - (right ?? 0);
            break;
          }
        }
        if (comparison >= 0) {
          throw new SessionHostError(
            "INVALID_RUNTIME",
            "compatibilityFlags must be a unique UTF-8-sorted set",
          );
        }
      }
      previousFlag = encoded;
    }
    const mainModule = validatedIdentifier(runtime.mainModule, "mainModule", "INVALID_RUNTIME");
    if (!Array.isArray(runtime.modules) || runtime.modules.length === 0) {
      throw new SessionHostError("INVALID_RUNTIME", "runtime modules must be a non-empty array");
    }
    if (runtime.modules.length > this.#limits.maximumModules) {
      throw new SessionHostError("RUNTIME_TOO_LARGE", "runtime has too many modules");
    }

    let verified;
    try {
      verified = await this.#verifier.verify(runtime);
    } catch (error) {
      throw new SessionHostError("RUNTIME_UNVERIFIED", "runtime signature verification failed", {
        cause: error,
      });
    }
    if (verified.revisionDigest !== runtime.runtimeRevisionDigest) {
      throw new SessionHostError(
        "RUNTIME_UNVERIFIED",
        "runtime verifier returned a different revision digest",
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
        let comparison = previousSpecifier.byteLength - encodedSpecifier.byteLength;
        const length = Math.min(previousSpecifier.byteLength, encodedSpecifier.byteLength);
        for (let byteIndex = 0; byteIndex < length; byteIndex += 1) {
          const left = previousSpecifier[byteIndex];
          const right = encodedSpecifier[byteIndex];
          if (left !== right) {
            comparison = (left ?? 0) - (right ?? 0);
            break;
          }
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

    const workerId = `pi/${sessionId}/${runtime.runtimeIdentityDigest.replace("sha256:", "sha256-")}`;
    const worker = await this.#loader.get(workerId, async () => ({
      compatibilityDate: runtime.compatibilityDate,
      compatibilityFlags: [...runtime.compatibilityFlags],
      limits: { cpuMs: runtime.limits.cpuMs, subRequests: runtime.limits.subRequests },
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
      ["turnId", "authority", "committer", "ephemeralSink", "maximumEvents"],
      "start turn options",
      "INVALID_TURN",
    );
    const validated = this.#validatedTurnOptions(options);
    return this.#beginDriving(
      engine,
      options,
      () =>
        engine.startTurn({
          turnId: validated.turnId,
          authority: validated.authority,
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
    return this.#beginDriving(
      engine,
      options,
      () =>
        engine.resumeTurn({
          turnId: validated.turnId,
          authority: validated.authority,
          checkpoint: structuredClone(options.checkpoint),
          settlement: structuredClone(options.settlement),
        }),
    );
  }

  async #beginDriving(
    engine: AgentEngine,
    options: DriveTurnOptions,
    begin: () => AsyncIterable<AgentEvent>,
  ): Promise<DriveTurnResult> {
    let events: AsyncIterable<AgentEvent>;
    try {
      events = begin();
    } catch (error) {
      try {
        await engine.abortTurn(options.turnId);
      } catch {
        // Session state remains the durable failure authority when an isolate
        // cannot acknowledge the best-effort execution interrupt.
      }
      throw new SessionHostError("INVALID_AGENT_EVENT", "AgentEngine failed to start", {
        cause: error,
      });
    }
    return this.#driveEvents(engine, events, options);
  }

  #validatedTurnOptions(options: DriveTurnOptions): {
    readonly turnId: string;
    readonly authority: Uint8Array;
  } {
    const turnId = validatedIdentifier(options.turnId, "turnId", "INVALID_TURN");
    if (
      !(options.authority instanceof Uint8Array) ||
      options.authority.byteLength === 0 ||
      options.authority.byteLength > this.#limits.maximumAuthorityBytes ||
      !Number.isSafeInteger(options.maximumEvents) ||
      options.maximumEvents <= 0 ||
      typeof options.committer?.commit !== "function" ||
      typeof options.ephemeralSink?.emit !== "function"
    ) {
      throw new SessionHostError("INVALID_TURN", "turn authority, ports, or event budget is invalid");
    }
    return { turnId, authority: new Uint8Array(options.authority) };
  }

  async #driveEvents(
    engine: AgentEngine,
    events: AsyncIterable<AgentEvent>,
    options: DriveTurnOptions,
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
            fields = ["type", "request"];
            break;
          case "assistant_delta":
            fields = ["type", "delta"];
            break;
          case "checkpoint":
            fields = ["type", "checkpoint"];
            break;
          case "turn_complete":
            fields = ["type", "result"];
            break;
          case "turn_error":
            fields = ["type", "error"];
            break;
          default:
            throw new SessionHostError("INVALID_AGENT_EVENT", "AgentEngine emitted an unknown event");
        }
        validatedExactKeys(event, fields, "AgentEvent", "INVALID_AGENT_EVENT");
        let encoded: string | undefined;
        try {
          encoded = JSON.stringify(event);
          structuredClone(event);
        } catch (error) {
          throw new SessionHostError("INVALID_AGENT_EVENT", "AgentEvent is not serializable", {
            cause: error,
          });
        }
        if (encoded === undefined || textEncoder.encode(encoded).byteLength > this.#limits.maximumEventBytes) {
          throw new SessionHostError("INVALID_AGENT_EVENT", "AgentEvent exceeds its size limit");
        }
        const cloned = structuredClone(event);
        if (event.type === "assistant_delta") {
          await options.ephemeralSink.emit(cloned);
          continue;
        }
        try {
          await options.committer.commit(cloned);
        } catch (error) {
          throw new SessionHostError(
            "DURABLE_COMMIT_FAILED",
            "durable AgentEvent commit failed",
            { cause: error },
          );
        }
        if (
          event.type === "model_request" ||
          event.type === "tool_request" ||
          event.type === "turn_complete" ||
          event.type === "turn_error"
        ) {
          if (iterator.return !== undefined) {
            await iterator.return();
          }
          iteratorClosed = true;
          return {
            boundary: structuredClone(event) as DriveTurnResult["boundary"],
            eventsObserved,
          };
        }
      }
    } catch (error) {
      if (!iteratorClosed && iterator?.return !== undefined) {
        try {
          await iterator.return();
        } catch {
          // The durable failure below remains authoritative; iterator cleanup
          // is best-effort and cannot convert it into a successful step.
        }
      }
      try {
        await engine.abortTurn(turnId);
      } catch {
        // abortTurn is an execution interrupt. Session state remains the
        // durable abort/failure authority even if the isolate cannot respond.
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
