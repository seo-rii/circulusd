import {
  ProtocolValidationError,
  digestBytes,
  digestStructuredValue,
  encodeCanonicalCbor,
  validateAgentCheckpoint,
  validateEngineStepResult,
  type AgentCheckpoint,
  type AgentError,
  type EffectIntent,
  type EngineStepResult,
  type NormalizedValue,
} from "@circulusd/protocol-types";

import { OpaqueTurnAuthority } from "./authority.ts";
import { decodeCanonicalCheckpointPayload } from "./codec.ts";
import { BoundaryFault, PiRuntimeError } from "./errors.ts";
import { HookDispatcher } from "./lifecycle.ts";
import {
  boundedIdentifier,
  boundedProtocolValue,
  boundedSafeInteger,
  exactRecord,
  frozenProtocolClone,
  frozenSignalContext,
  parseDigestForBoundary,
  parseEffectIntent,
  parseEffectRequestDraft,
  parseEngineSettlement,
  parseSettlementOutcome,
} from "./validation.ts";
import type {
  AgentCore,
  AgentCoreFactory,
  AgentCoreFactoryContext,
  AgentCoreInput,
  AgentCoreTransition,
  EffectRequestDraft,
  EngineBudgets,
  EngineClock,
  EngineIdentity,
  EngineSettlement,
  EngineStepContext,
  ExtensionRegistration,
  GenesisCheckpointInput,
  LowLevelPiAgentEngineOptions,
  SettledToolResult,
} from "./types.ts";

const CHECKPOINT_STATE_VERSION = 1 as const;
const CHECKPOINT_DIGEST_DOMAIN = "circulusd.session.agent-checkpoint";
const EFFECT_REQUEST_DIGEST_DOMAIN = "circulusd.session.effect-request";
const TOOL_BATCH_DIGEST_DOMAIN = "circulusd.session.tool-batch";
const DIGEST_SCHEMA_VERSION = 1;
const MAX_PENDING_ABORT_TURNS = 64;

export const DEFAULT_ENGINE_BUDGETS: EngineBudgets = Object.freeze({
  maxStepInputBytes: 5 * 1_048_576,
  maxCoreOutputBytes: 1_048_576,
  maxExtensionOutputBytes: 262_144,
  maxCheckpointBytes: 1_048_576,
  maxAssistantDeltaBytes: 65_536,
  maxEventsPerStep: 256,
  maxPendingToolCalls: 64,
  maxWallClockMs: 30_000,
});

interface WaitingEffect {
  readonly kind: "model" | "tool";
  readonly request: EffectIntent;
}

interface AdapterState {
  readonly version: typeof CHECKPOINT_STATE_VERSION;
  readonly status: "ready" | "waiting_effect" | "terminal";
  readonly coreState: NormalizedValue;
  readonly turnInput: NormalizedValue | null;
  readonly beforeTurnCompleted: boolean;
  readonly awaiting: WaitingEffect | null;
  readonly pendingTools: readonly EffectRequestDraft[];
  readonly completedTools: readonly SettledToolResult[];
  readonly terminalCode: string | null;
}

type PendingBoundary =
  | { readonly kind: "checkpoint" }
  | { readonly kind: "effect_request"; readonly request: EffectIntent }
  | { readonly kind: "turn_complete"; readonly result: NormalizedValue }
  | { readonly kind: "turn_error"; readonly error: AgentError };

interface ExecutionResult {
  readonly boundary: PendingBoundary;
  readonly state: AdapterState;
}

interface ActiveStep {
  readonly turnId: string;
  readonly controller: AbortController;
  readonly core: AgentCore;
  interruptPromise: Promise<void> | null;
}

class SystemEngineClock implements EngineClock {
  now(): number {
    return performance.now();
  }

  setTimeout(callback: () => void, delayMs: number): unknown {
    return globalThis.setTimeout(callback, delayMs);
  }

  clearTimeout(handle: unknown): void {
    globalThis.clearTimeout(handle as ReturnType<typeof globalThis.setTimeout>);
  }
}

function parseBudgets(value: Partial<EngineBudgets> | undefined): EngineBudgets {
  const record = value === undefined
    ? {}
    : exactRecord(
        value,
        [],
        Object.keys(DEFAULT_ENGINE_BUDGETS),
        "options.budgets",
        "INVALID_CONFIGURATION",
      );
  const resolved = { ...DEFAULT_ENGINE_BUDGETS, ...record };
  for (const [name, budget] of Object.entries(resolved)) {
    if (typeof budget !== "number" || !Number.isSafeInteger(budget) || budget < 1) {
      throw new PiRuntimeError(
        "INVALID_CONFIGURATION",
        `options.budgets.${name} must be a positive safe integer`,
      );
    }
  }
  return Object.freeze({
    maxStepInputBytes: Number(resolved.maxStepInputBytes),
    maxCoreOutputBytes: Number(resolved.maxCoreOutputBytes),
    maxExtensionOutputBytes: Number(resolved.maxExtensionOutputBytes),
    maxCheckpointBytes: Number(resolved.maxCheckpointBytes),
    maxAssistantDeltaBytes: Number(resolved.maxAssistantDeltaBytes),
    maxEventsPerStep: Number(resolved.maxEventsPerStep),
    maxPendingToolCalls: Number(resolved.maxPendingToolCalls),
    maxWallClockMs: Number(resolved.maxWallClockMs),
  });
}

function parseIdentity(value: EngineIdentity): EngineIdentity {
  const record = exactRecord(
    value,
    ["sessionId", "runtimeRevisionDigest", "adapterAbiVersion", "checkpointSchemaVersion"],
    [],
    "identity",
    "INVALID_CONFIGURATION",
  );
  return Object.freeze({
    sessionId: boundedIdentifier(record.sessionId, "identity.sessionId", "INVALID_CONFIGURATION"),
    runtimeRevisionDigest: parseDigestForBoundary(
      record.runtimeRevisionDigest,
      "identity.runtimeRevisionDigest",
      "INVALID_CONFIGURATION",
    ),
    adapterAbiVersion: boundedSafeInteger(
      record.adapterAbiVersion,
      1,
      "identity.adapterAbiVersion",
      "INVALID_CONFIGURATION",
    ),
    checkpointSchemaVersion: boundedSafeInteger(
      record.checkpointSchemaVersion,
      1,
      "identity.checkpointSchemaVersion",
      "INVALID_CONFIGURATION",
    ),
  });
}

function parseAdapterState(
  value: unknown,
  budgets: EngineBudgets,
): AdapterState {
  const record = exactRecord(
    value,
    [
      "version",
      "status",
      "coreState",
      "turnInput",
      "beforeTurnCompleted",
      "awaiting",
      "pendingTools",
      "completedTools",
      "terminalCode",
    ],
    [],
    "checkpoint.state",
    "INVALID_CHECKPOINT",
  );
  if (record.version !== CHECKPOINT_STATE_VERSION) {
    throw new PiRuntimeError("INVALID_CHECKPOINT", "checkpoint state version is unsupported");
  }
  if (record.status !== "ready" && record.status !== "waiting_effect" && record.status !== "terminal") {
    throw new PiRuntimeError("INVALID_CHECKPOINT", "checkpoint state status is unsupported");
  }
  if (typeof record.beforeTurnCompleted !== "boolean") {
    throw new PiRuntimeError(
      "INVALID_CHECKPOINT",
      "checkpoint beforeTurnCompleted must be a boolean",
    );
  }
  const coreState = boundedProtocolValue(
    record.coreState,
    budgets.maxCheckpointBytes,
    "checkpoint.state.coreState",
    "INVALID_CHECKPOINT",
  );
  const turnInput = record.turnInput === null
    ? null
    : boundedProtocolValue(
        record.turnInput,
        budgets.maxCheckpointBytes,
        "checkpoint.state.turnInput",
        "INVALID_CHECKPOINT",
      );
  let awaiting: WaitingEffect | null = null;
  if (record.awaiting !== null) {
    const awaitingRecord = exactRecord(
      record.awaiting,
      ["kind", "request"],
      [],
      "checkpoint.state.awaiting",
      "INVALID_CHECKPOINT",
    );
    if (awaitingRecord.kind !== "model" && awaitingRecord.kind !== "tool") {
      throw new PiRuntimeError("INVALID_CHECKPOINT", "checkpoint awaiting kind is unsupported");
    }
    awaiting = {
      kind: awaitingRecord.kind,
      request: parseEffectIntent(
        awaitingRecord.request,
        budgets.maxCheckpointBytes,
        "checkpoint.state.awaiting.request",
        "INVALID_CHECKPOINT",
      ),
    };
  }
  if (!Array.isArray(record.pendingTools) || !Array.isArray(record.completedTools)) {
    throw new PiRuntimeError(
      "INVALID_CHECKPOINT",
      "checkpoint pendingTools and completedTools must be arrays",
    );
  }
  if (
    record.pendingTools.length > budgets.maxPendingToolCalls ||
    record.completedTools.length > budgets.maxPendingToolCalls
  ) {
    throw new PiRuntimeError("INVALID_CHECKPOINT", "checkpoint tool queue exceeds its budget");
  }
  const pendingTools = record.pendingTools.map((request, index) =>
    parseEffectRequestDraft(
      request,
      budgets.maxCheckpointBytes,
      `checkpoint.state.pendingTools[${index}]`,
      "INVALID_CHECKPOINT",
    ),
  );
  const completedTools = record.completedTools.map((entry, index) => {
    const completedRecord = exactRecord(
      entry,
      ["request", "settlement"],
      [],
      `checkpoint.state.completedTools[${index}]`,
      "INVALID_CHECKPOINT",
    );
    return {
      request: parseEffectIntent(
        completedRecord.request,
        budgets.maxCheckpointBytes,
        `checkpoint.state.completedTools[${index}].request`,
        "INVALID_CHECKPOINT",
      ),
      settlement: parseSettlementOutcome(
        completedRecord.settlement,
        budgets.maxCheckpointBytes,
        `checkpoint.state.completedTools[${index}].settlement`,
        "INVALID_CHECKPOINT",
      ),
    };
  });
  const terminalCode = record.terminalCode === null
    ? null
    : boundedIdentifier(
        record.terminalCode,
        "checkpoint.state.terminalCode",
        "INVALID_CHECKPOINT",
      );
  if (record.status === "ready") {
    if (awaiting !== null || pendingTools.length !== 0 || completedTools.length !== 0 || terminalCode !== null) {
      throw new PiRuntimeError("INVALID_CHECKPOINT", "ready checkpoint contains pending state");
    }
    if ((turnInput === null) !== record.beforeTurnCompleted) {
      throw new PiRuntimeError(
        "INVALID_CHECKPOINT",
        "ready checkpoint turn input and lifecycle position disagree",
      );
    }
  } else if (record.status === "waiting_effect") {
    if (
      awaiting === null ||
      turnInput !== null ||
      !record.beforeTurnCompleted ||
      terminalCode !== null ||
      (awaiting.kind === "model" && (pendingTools.length !== 0 || completedTools.length !== 0))
    ) {
      throw new PiRuntimeError("INVALID_CHECKPOINT", "waiting checkpoint invariants are invalid");
    }
  } else if (
    awaiting !== null ||
    turnInput !== null ||
    pendingTools.length !== 0 ||
    completedTools.length !== 0 ||
    terminalCode === null ||
    !record.beforeTurnCompleted
  ) {
    throw new PiRuntimeError("INVALID_CHECKPOINT", "terminal checkpoint invariants are invalid");
  }
  const state: AdapterState = {
    version: CHECKPOINT_STATE_VERSION,
    status: record.status,
    coreState,
    turnInput,
    beforeTurnCompleted: record.beforeTurnCompleted,
    awaiting,
    pendingTools,
    completedTools,
    terminalCode,
  };
  boundedProtocolValue(
    state,
    budgets.maxCheckpointBytes,
    "checkpoint.state",
    "INVALID_CHECKPOINT",
  );
  return state;
}

function parseCoreTransition(
  value: unknown,
  budgets: EngineBudgets,
): AgentCoreTransition {
  const preliminary = exactRecord(
    value,
    ["kind", "state"],
    ["assistantDeltas", "request", "requests", "result", "error"],
    "core.output",
    "CORE_OUTPUT_INVALID",
  );
  boundedProtocolValue(
    value,
    budgets.maxCoreOutputBytes,
    "core.output",
    "CORE_OUTPUT_INVALID",
  );
  const state = boundedProtocolValue(
    preliminary.state,
    budgets.maxCoreOutputBytes,
    "core.output.state",
    "CORE_OUTPUT_INVALID",
  );
  let assistantDeltas: readonly NormalizedValue[] | undefined;
  if (Object.prototype.hasOwnProperty.call(preliminary, "assistantDeltas")) {
    if (!Array.isArray(preliminary.assistantDeltas)) {
      throw new BoundaryFault("CORE_OUTPUT_INVALID", "core.output.assistantDeltas must be an array");
    }
    if (preliminary.assistantDeltas.length + 1 > budgets.maxEventsPerStep) {
      throw new BoundaryFault(
        "EVENT_BUDGET_EXCEEDED",
        `core output exceeds ${budgets.maxEventsPerStep} events in one bounded step`,
      );
    }
    assistantDeltas = preliminary.assistantDeltas.map((delta, index) =>
      boundedProtocolValue(
        delta,
        budgets.maxAssistantDeltaBytes,
        `core.output.assistantDeltas[${index}]`,
        "CORE_OUTPUT_INVALID",
      ),
    );
  }
  const common = assistantDeltas === undefined ? { state } : { state, assistantDeltas };
  switch (preliminary.kind) {
    case "checkpoint_only": {
      exactRecord(value, ["kind", "state"], ["assistantDeltas"], "core.output", "CORE_OUTPUT_INVALID");
      return { kind: "checkpoint_only", ...common };
    }
    case "model_request": {
      const record = exactRecord(
        value,
        ["kind", "state", "request"],
        ["assistantDeltas"],
        "core.output",
        "CORE_OUTPUT_INVALID",
      );
      const request = parseEffectRequestDraft(
        record.request,
        budgets.maxCoreOutputBytes,
        "core.output.request",
        "CORE_OUTPUT_INVALID",
      );
      if (request.service !== "model") {
        throw new BoundaryFault("CORE_OUTPUT_INVALID", "model_request must target model service");
      }
      return { kind: "model_request", ...common, request };
    }
    case "tool_requests": {
      const record = exactRecord(
        value,
        ["kind", "state", "requests"],
        ["assistantDeltas"],
        "core.output",
        "CORE_OUTPUT_INVALID",
      );
      if (
        !Array.isArray(record.requests) ||
        record.requests.length === 0 ||
        record.requests.length > budgets.maxPendingToolCalls
      ) {
        throw new BoundaryFault(
          "CORE_OUTPUT_INVALID",
          `tool_requests must contain 1..${budgets.maxPendingToolCalls} requests`,
        );
      }
      const requests = record.requests.map((request, index) => {
        const parsed = parseEffectRequestDraft(
          request,
          budgets.maxCoreOutputBytes,
          `core.output.requests[${index}]`,
          "CORE_OUTPUT_INVALID",
        );
        if (parsed.service === "model") {
          throw new BoundaryFault("CORE_OUTPUT_INVALID", "tool_requests cannot target model service");
        }
        return parsed;
      });
      return { kind: "tool_requests", ...common, requests };
    }
    case "turn_complete": {
      const record = exactRecord(
        value,
        ["kind", "state", "result"],
        ["assistantDeltas"],
        "core.output",
        "CORE_OUTPUT_INVALID",
      );
      return {
        kind: "turn_complete",
        ...common,
        result: boundedProtocolValue(
          record.result,
          budgets.maxCoreOutputBytes,
          "core.output.result",
          "CORE_OUTPUT_INVALID",
        ),
      };
    }
    case "turn_error": {
      const record = exactRecord(
        value,
        ["kind", "state", "error"],
        ["assistantDeltas"],
        "core.output",
        "CORE_OUTPUT_INVALID",
      );
      const errorRecord = exactRecord(
        record.error,
        ["code", "message", "retryable"],
        ["details"],
        "core.output.error",
        "CORE_OUTPUT_INVALID",
      );
      if (typeof errorRecord.retryable !== "boolean") {
        throw new BoundaryFault("CORE_OUTPUT_INVALID", "core.output.error.retryable must be boolean");
      }
      const error: AgentError = {
        code: boundedIdentifier(errorRecord.code, "core.output.error.code", "CORE_OUTPUT_INVALID"),
        message: boundedIdentifier(
          errorRecord.message,
          "core.output.error.message",
          "CORE_OUTPUT_INVALID",
        ),
        retryable: errorRecord.retryable,
        ...(Object.prototype.hasOwnProperty.call(errorRecord, "details")
          ? {
              details: boundedProtocolValue(
                errorRecord.details,
                budgets.maxCoreOutputBytes,
                "core.output.error.details",
                "CORE_OUTPUT_INVALID",
              ),
            }
          : {}),
      };
      return { kind: "turn_error", ...common, error };
    }
    default:
      throw new BoundaryFault("CORE_OUTPUT_INVALID", "core.output.kind is unsupported");
  }
}

export class LowLevelPiAgentEngine {
  readonly #identity: EngineIdentity;
  readonly #budgets: EngineBudgets;
  readonly #clock: EngineClock;
  readonly #coreFactory: AgentCoreFactory;
  readonly #coreFactoryContext: AgentCoreFactoryContext;
  readonly #hooks: HookDispatcher;
  #initialization: Promise<void> | null = null;
  #activeStep: ActiveStep | null = null;
  readonly #pendingAbortTurnIds = new Set<string>();
  #stepClaimed = false;
  #poisoned = false;

  constructor(
    identity: EngineIdentity,
    coreFactory: AgentCoreFactory,
    options: LowLevelPiAgentEngineOptions = {},
  ) {
    this.#identity = parseIdentity(identity);
    this.#budgets = parseBudgets(options.budgets);
    this.#clock = options.clock ?? new SystemEngineClock();
    if (
      typeof this.#clock.now !== "function" ||
      typeof this.#clock.setTimeout !== "function" ||
      typeof this.#clock.clearTimeout !== "function"
    ) {
      throw new PiRuntimeError("INVALID_CONFIGURATION", "engine clock is invalid");
    }
    if (typeof coreFactory !== "function") {
      throw new PiRuntimeError("INVALID_CONFIGURATION", "AgentCore factory is required");
    }
    this.#coreFactory = coreFactory;
    this.#coreFactoryContext = frozenProtocolClone({
      sessionId: this.#identity.sessionId,
      runtimeRevisionDigest: this.#identity.runtimeRevisionDigest,
      adapterAbiVersion: this.#identity.adapterAbiVersion,
      checkpointSchemaVersion: this.#identity.checkpointSchemaVersion,
    });
    this.#hooks = new HookDispatcher(this.#identity, this.#budgets.maxExtensionOutputBytes);
  }

  registerExtension(registration: ExtensionRegistration): void {
    this.#hooks.register(registration);
  }

  initialize(): Promise<void> {
    if (this.#initialization === null) {
      const timeout = Promise.withResolvers<void>();
      const timeoutHandle = this.#clock.setTimeout(
        () =>
          timeout.reject(
            new PiRuntimeError(
              "INITIALIZATION_FAILED",
              `extension initialization exceeded ${this.#budgets.maxWallClockMs}ms`,
            ),
          ),
        this.#budgets.maxWallClockMs,
      );
      this.#initialization = Promise.race([this.#hooks.initialize(), timeout.promise]).finally(
        () => this.#clock.clearTimeout(timeoutHandle),
      );
    }
    return this.#initialization;
  }

  async createGenesisCheckpoint(input: GenesisCheckpointInput): Promise<AgentCheckpoint> {
    const record = exactRecord(
      input,
      ["turnId", "input", "initialCoreState"],
      [],
      "genesis",
      "INVALID_CONTEXT",
    );
    const turnId = boundedIdentifier(record.turnId, "genesis.turnId", "INVALID_CONTEXT");
    const state = parseAdapterState(
      {
        version: CHECKPOINT_STATE_VERSION,
        status: "ready",
        coreState: boundedProtocolValue(
          record.initialCoreState,
          this.#budgets.maxCheckpointBytes,
          "genesis.initialCoreState",
          "INVALID_CONTEXT",
        ),
        turnInput: boundedProtocolValue(
          record.input,
          this.#budgets.maxCheckpointBytes,
          "genesis.input",
          "INVALID_CONTEXT",
        ),
        beforeTurnCompleted: false,
        awaiting: null,
        pendingTools: [],
        completedTools: [],
        terminalCode: null,
      },
      this.#budgets,
    );
    const payloadBytes = encodeCanonicalCbor(state, {
      maxBytes: this.#budgets.maxCheckpointBytes,
    });
    const checkpoint: AgentCheckpoint = {
      kind: "genesis",
      engineKind: "low-level",
      adapterAbiVersion: this.#identity.adapterAbiVersion,
      checkpointSchemaVersion: this.#identity.checkpointSchemaVersion,
      runtimeRevisionDigest: this.#identity.runtimeRevisionDigest,
      sessionId: this.#identity.sessionId,
      turnId,
      checkpointSequence: 0,
      predecessorDigest: null,
      payloadEncoding: "canonical-cbor",
      payloadBytes,
      payloadDigest: await digestBytes(payloadBytes),
    };
    return validateAgentCheckpoint(checkpoint);
  }

  async step(context: EngineStepContext): Promise<EngineStepResult> {
    if (this.#poisoned) {
      throw new PiRuntimeError(
        "ENGINE_POISONED",
        "engine must be reconstructed after an interrupted bounded step",
      );
    }
    if (this.#stepClaimed) {
      throw new PiRuntimeError("STEP_IN_PROGRESS", "a bounded step is already in progress");
    }
    this.#stepClaimed = true;
    this.#hooks.seal();
    try {
    const contextRecord = exactRecord(
      context,
      ["authority", "checkpoint"],
      ["settlement", "emitDelta"],
      "stepContext",
      "INVALID_CONTEXT",
    );
    if (
      !(contextRecord.authority instanceof OpaqueTurnAuthority) ||
      !contextRecord.authority.isPresent()
    ) {
      throw new PiRuntimeError("INVALID_CONTEXT", "stepContext.authority must be opaque");
    }
    if (
      Object.prototype.hasOwnProperty.call(contextRecord, "emitDelta") &&
      typeof contextRecord.emitDelta !== "function"
    ) {
      throw new PiRuntimeError("INVALID_CONTEXT", "stepContext.emitDelta must be a function");
    }
    let checkpoint: AgentCheckpoint;
    try {
      checkpoint = await validateAgentCheckpoint(contextRecord.checkpoint);
    } catch (error) {
      if (error instanceof ProtocolValidationError) {
        throw new PiRuntimeError("INVALID_CHECKPOINT", `checkpoint is invalid: ${error.message}`, {
          cause: error,
        });
      }
      throw error;
    }
    if (
      checkpoint.engineKind !== "low-level" ||
      checkpoint.sessionId !== this.#identity.sessionId ||
      checkpoint.runtimeRevisionDigest !== this.#identity.runtimeRevisionDigest ||
      checkpoint.adapterAbiVersion !== this.#identity.adapterAbiVersion ||
      checkpoint.checkpointSchemaVersion !== this.#identity.checkpointSchemaVersion ||
      checkpoint.payloadEncoding !== "canonical-cbor"
    ) {
      throw new PiRuntimeError(
        "CHECKPOINT_IDENTITY_MISMATCH",
        "checkpoint does not belong to this exact runtime identity",
      );
    }
    const state = parseAdapterState(
      decodeCanonicalCheckpointPayload(
        checkpoint.payloadBytes,
        this.#budgets.maxCheckpointBytes,
      ),
      this.#budgets,
    );
    if (state.status === "terminal") {
      throw new PiRuntimeError("ENGINE_TERMINAL", "checkpoint is already terminal");
    }
    const hasSettlement = Object.prototype.hasOwnProperty.call(contextRecord, "settlement");
    const settlement = hasSettlement
      ? parseEngineSettlement(
          contextRecord.settlement,
          this.#budgets.maxStepInputBytes,
          "stepContext.settlement",
        )
      : null;
    boundedProtocolValue(
      { checkpoint, settlement },
      this.#budgets.maxStepInputBytes,
      "stepContext",
      "INVALID_CONTEXT",
    );
    if (state.status === "waiting_effect" && settlement === null) {
      throw new PiRuntimeError(
        "SETTLEMENT_REQUIRED",
        "the pending external effect must settle before the next engine step",
      );
    }
    if (state.status !== "waiting_effect" && settlement !== null) {
      throw new PiRuntimeError(
        "UNEXPECTED_SETTLEMENT",
        "checkpoint has no external effect settlement to consume",
      );
    }
    if (
      state.awaiting !== null &&
      settlement !== null &&
      state.awaiting.request.requestDigest !== settlement.requestDigest
    ) {
      throw new PiRuntimeError(
        "SETTLEMENT_MISMATCH",
        "settlement requestDigest does not match the checkpointed external effect",
      );
    }

    let core: AgentCore;
    try {
      core = this.#coreFactory(this.#coreFactoryContext);
    } catch (error) {
      throw new PiRuntimeError(
        "INVALID_CONFIGURATION",
        "AgentCore factory failed while reconstructing a bounded step",
        { cause: error },
      );
    }
    if (core === null || typeof core !== "object" || typeof core.advance !== "function") {
      throw new PiRuntimeError("INVALID_CONFIGURATION", "AgentCore factory returned an invalid core");
    }
    const controller = new AbortController();
    const activeStep: ActiveStep = {
      turnId: checkpoint.turnId,
      controller,
      core,
      interruptPromise: null,
    };
    this.#activeStep = activeStep;
    const startedAt = this.#clock.now();
    const abortSignal = Promise.withResolvers<never>();
    const onAbort = () => {
      const reason = controller.signal.reason;
      abortSignal.reject(
        reason instanceof BoundaryFault
          ? reason
          : new BoundaryFault("TURN_ABORTED", "bounded engine step was aborted"),
      );
    };
    controller.signal.addEventListener("abort", onAbort, { once: true });
    const timeoutHandle = this.#clock.setTimeout(() => {
      controller.abort(
        new BoundaryFault(
          "STEP_TIMEOUT",
          `bounded engine step exceeded ${this.#budgets.maxWallClockMs}ms`,
        ),
      );
      void this.#interruptActiveStep(activeStep);
    }, this.#budgets.maxWallClockMs);
    try {
      if (this.#pendingAbortTurnIds.delete(checkpoint.turnId)) {
        controller.abort(
          new BoundaryFault("TURN_ABORTED", `turn ${checkpoint.turnId} was aborted`),
        );
        void this.#interruptActiveStep(activeStep);
      }
      this.#pendingAbortTurnIds.clear();
      await Promise.race([this.initialize(), abortSignal.promise]);
      this.#throwIfAborted(controller.signal);
      const execution = this.#execute(
        core,
        state,
        settlement,
        checkpoint.turnId,
        checkpoint.checkpointSequence,
        controller.signal,
        contextRecord.emitDelta as EngineStepContext["emitDelta"],
      );
      const executed = await Promise.race([execution, abortSignal.promise]);
      if (this.#clock.now() - startedAt > this.#budgets.maxWallClockMs) {
        throw new BoundaryFault(
          "STEP_TIMEOUT",
          `bounded engine step exceeded ${this.#budgets.maxWallClockMs}ms`,
        );
      }
      const nextCheckpoint = await this.#createSuccessorCheckpoint(checkpoint, executed.state);
      this.#throwIfAborted(controller.signal);
      const result = await this.#attachCheckpoint(nextCheckpoint, executed.boundary);
      this.#throwIfAborted(controller.signal);
      return result;
    } catch (error) {
      if (error instanceof PiRuntimeError && error.code === "INITIALIZATION_FAILED") {
        throw error;
      }
      const fault = error instanceof BoundaryFault
        ? error
        : new BoundaryFault("CORE_EXECUTION_FAILED", "bounded engine step failed", {
            cause: error,
          });
      if (fault.code === "STEP_TIMEOUT" || fault.code === "TURN_ABORTED") {
        this.#poisoned = true;
        void this.#interruptActiveStep(activeStep);
      }
      controller.abort(fault);
      const terminalState: AdapterState = {
        version: CHECKPOINT_STATE_VERSION,
        status: "terminal",
        coreState: state.coreState,
        turnInput: null,
        beforeTurnCompleted: true,
        awaiting: null,
        pendingTools: [],
        completedTools: [],
        terminalCode: fault.code,
      };
      const nextCheckpoint = await this.#createSuccessorCheckpoint(checkpoint, terminalState);
      return this.#attachCheckpoint(nextCheckpoint, {
        kind: "turn_error",
        error: { code: fault.code, message: fault.message, retryable: false },
      });
    } finally {
      this.#clock.clearTimeout(timeoutHandle);
      controller.signal.removeEventListener("abort", onAbort);
      this.#activeStep = null;
    }
    } finally {
      this.#stepClaimed = false;
      this.#pendingAbortTurnIds.clear();
    }
  }

  async abortTurn(turnId: string): Promise<void> {
    boundedIdentifier(turnId, "turnId", "INVALID_CONTEXT");
    const activeStep = this.#activeStep;
    if (activeStep === null) {
      if (this.#stepClaimed) {
        if (
          this.#pendingAbortTurnIds.size >= MAX_PENDING_ABORT_TURNS &&
          !this.#pendingAbortTurnIds.has(turnId)
        ) {
          this.#pendingAbortTurnIds.clear();
        }
        this.#pendingAbortTurnIds.add(turnId);
      }
      return;
    }
    if (activeStep.turnId !== turnId) return;
    activeStep.controller.abort(
      new BoundaryFault("TURN_ABORTED", `turn ${turnId} was aborted`),
    );
    await this.#interruptActiveStep(activeStep);
  }

  #interruptActiveStep(activeStep: ActiveStep): Promise<void> {
    if (activeStep.interruptPromise !== null) return activeStep.interruptPromise;
    const finished = Promise.withResolvers<void>();
    activeStep.interruptPromise = finished.promise;
    if (activeStep.core.abortTurn === undefined) {
      finished.resolve();
      return finished.promise;
    }
    const timeout = Promise.withResolvers<void>();
    const timeoutHandle = this.#clock.setTimeout(
      () => timeout.resolve(),
      this.#budgets.maxWallClockMs,
    );
    let interrupt: Promise<unknown>;
    try {
      interrupt = Promise.resolve(activeStep.core.abortTurn(activeStep.turnId));
    } catch {
      interrupt = Promise.resolve();
    }
    void Promise.race([timeout.promise, interrupt]).then(
      () => {
        this.#clock.clearTimeout(timeoutHandle);
        finished.resolve();
      },
      () => {
        this.#clock.clearTimeout(timeoutHandle);
        finished.resolve();
      },
    );
    return finished.promise;
  }

  async #execute(
    core: AgentCore,
    initial: AdapterState,
    settlement: EngineSettlement | null,
    turnId: string,
    checkpointSequence: number,
    signal: AbortSignal,
    emitDelta: EngineStepContext["emitDelta"],
  ): Promise<ExecutionResult> {
    let coreInput: AgentCoreInput;
    let coreState = initial.coreState;
    if (settlement !== null) {
      const awaiting = initial.awaiting;
      if (awaiting === null) {
        throw new PiRuntimeError("UNEXPECTED_SETTLEMENT", "checkpoint has no awaiting effect");
      }
      let outcome = settlement.outcome;
      if (outcome.kind === "success" && awaiting.kind === "model") {
        outcome = {
          kind: "success",
          result: await this.#hooks.afterModelResponse(
            turnId,
            awaiting.request,
            outcome.result,
            signal,
          ),
        };
      }
      if (outcome.kind === "success" && awaiting.kind === "tool") {
        outcome = {
          kind: "success",
          result: await this.#hooks.afterToolCall(
            turnId,
            awaiting.request,
            outcome.result,
            signal,
          ),
        };
      }
      this.#throwIfAborted(signal);
      if (awaiting.kind === "tool") {
        const completedTools = [
          ...initial.completedTools,
          { request: awaiting.request, settlement: outcome },
        ];
        if (initial.pendingTools.length > 0) {
          return this.#issueToolBoundary(
            turnId,
            coreState,
            initial.pendingTools,
            completedTools,
            signal,
          );
        }
        coreInput = {
          kind: "tool_settlements",
          results: frozenProtocolClone(completedTools),
        };
      } else {
        coreInput = {
          kind: "effect_settlement",
          request: frozenProtocolClone(awaiting.request),
          settlement: frozenProtocolClone(outcome),
        };
      }
    } else if (initial.turnInput !== null) {
      await this.#hooks.beforeTurn(turnId, initial.turnInput, signal);
      this.#throwIfAborted(signal);
      coreInput = { kind: "turn_start", input: frozenProtocolClone(initial.turnInput) };
    } else {
      coreInput = { kind: "continue" };
    }
    let rawTransition: unknown;
    try {
      rawTransition = await core.advance(
        frozenSignalContext({
          sessionId: this.#identity.sessionId,
          turnId,
          runtimeRevisionDigest: this.#identity.runtimeRevisionDigest,
          state: coreState,
          input: coreInput,
          signal,
        }),
      );
    } catch (error) {
      if (error instanceof BoundaryFault) throw error;
      if (signal.aborted) throw signal.reason;
      throw new BoundaryFault("CORE_EXECUTION_FAILED", "AgentCore.advance failed", {
        cause: error,
      });
    }
    this.#throwIfAborted(signal);
    const transition = parseCoreTransition(rawTransition, this.#budgets);
    coreState = transition.state;
    if (transition.assistantDeltas !== undefined && emitDelta !== undefined) {
      for (const delta of transition.assistantDeltas) {
        this.#throwIfAborted(signal);
        try {
          await emitDelta(frozenProtocolClone(delta));
        } catch {
          // Ephemeral client delivery is deliberately not turn authority.
        }
      }
    }
    this.#throwIfAborted(signal);
    switch (transition.kind) {
      case "checkpoint_only":
        return {
          boundary: { kind: "checkpoint" },
          state: this.#readyState(coreState),
        };
      case "model_request": {
        const patched = parseEffectRequestDraft(
          await this.#hooks.beforeModelRequest(turnId, transition.request, signal),
          this.#budgets.maxCoreOutputBytes,
          "patched.modelRequest",
          "EXTENSION_OUTPUT_INVALID",
        );
        if (patched.service !== "model") {
          throw new BoundaryFault(
            "EXTENSION_OUTPUT_INVALID",
            "beforeModelRequest cannot change the model service",
          );
        }
        const request = await this.#intent(patched);
        return {
          boundary: { kind: "effect_request", request },
          state: {
            ...this.#readyState(coreState),
            status: "waiting_effect",
            awaiting: { kind: "model", request },
          },
        };
      }
      case "tool_requests": {
        const generatedParentOperationId = await digestStructuredValue(
          TOOL_BATCH_DIGEST_DOMAIN,
          DIGEST_SCHEMA_VERSION,
          {
            sessionId: this.#identity.sessionId,
            turnId,
            checkpointSequence,
          },
        );
        const occurrenceKeys = new Set<string>();
        const requests = transition.requests.map((request, ordinal) => {
          const occurrence = request.parentOperationId === undefined
            ? { ...request, parentOperationId: generatedParentOperationId, ordinal }
            : request;
          const occurrenceKey = `${occurrence.parentOperationId}\u0000${occurrence.ordinal}`;
          if (occurrenceKeys.has(occurrenceKey)) {
            throw new BoundaryFault(
              "CORE_OUTPUT_INVALID",
              "tool_requests contains a duplicate parentOperationId and ordinal occurrence",
            );
          }
          occurrenceKeys.add(occurrenceKey);
          return occurrence;
        });
        return this.#issueToolBoundary(
          turnId,
          coreState,
          requests,
          [],
          signal,
        );
      }
      case "turn_complete": {
        await this.#hooks.afterTurn(turnId, transition.result, signal);
        this.#throwIfAborted(signal);
        return {
          boundary: { kind: "turn_complete", result: transition.result },
          state: this.#terminalState(coreState, "TURN_COMPLETE"),
        };
      }
      case "turn_error":
        return {
          boundary: { kind: "turn_error", error: transition.error },
          state: this.#terminalState(coreState, transition.error.code),
        };
    }
  }

  async #issueToolBoundary(
    turnId: string,
    coreState: NormalizedValue,
    queue: readonly EffectRequestDraft[],
    completedTools: readonly SettledToolResult[],
    signal: AbortSignal,
  ): Promise<ExecutionResult> {
    const [head, ...pendingTools] = queue;
    if (head === undefined) {
      throw new BoundaryFault("CORE_OUTPUT_INVALID", "tool queue unexpectedly became empty");
    }
    const patched = parseEffectRequestDraft(
      await this.#hooks.beforeToolCall(turnId, head, signal),
      this.#budgets.maxCoreOutputBytes,
      "patched.toolRequest",
      "EXTENSION_OUTPUT_INVALID",
    );
    if (patched.service === "model") {
      throw new BoundaryFault(
        "EXTENSION_OUTPUT_INVALID",
        "beforeToolCall cannot change a tool request into a model request",
      );
    }
    const replayPolicyStrength = {
      safe: 0,
      "idempotency-key": 1,
      confirm: 2,
      never: 3,
    } as const;
    if (replayPolicyStrength[patched.replayPolicy] < replayPolicyStrength[head.replayPolicy]) {
      throw new BoundaryFault(
        "EXTENSION_OUTPUT_INVALID",
        "beforeToolCall cannot weaken the tool replay policy",
      );
    }
    // The downstream Broker remains responsible for authorizing the final
    // transformed operation and payload. This local clamp only preserves the
    // runtime's minimum replay-safety requirement.
    this.#throwIfAborted(signal);
    const request = await this.#intent(patched);
    return {
      boundary: { kind: "effect_request", request },
      state: {
        version: CHECKPOINT_STATE_VERSION,
        status: "waiting_effect",
        coreState,
        turnInput: null,
        beforeTurnCompleted: true,
        awaiting: { kind: "tool", request },
        pendingTools,
        completedTools,
        terminalCode: null,
      },
    };
  }

  async #intent(draft: EffectRequestDraft): Promise<EffectIntent> {
    const digestPayload = {
      service: draft.service,
      operation: draft.operation,
      replayPolicy: draft.replayPolicy,
      payload: draft.payload,
      ...(draft.parentOperationId === undefined
        ? {}
        : { parentOperationId: draft.parentOperationId, ordinal: draft.ordinal }),
    };
    return {
      ...draft,
      requestDigest: await digestStructuredValue(
        EFFECT_REQUEST_DIGEST_DOMAIN,
        DIGEST_SCHEMA_VERSION,
        digestPayload,
      ),
    };
  }

  #readyState(coreState: NormalizedValue): AdapterState {
    return {
      version: CHECKPOINT_STATE_VERSION,
      status: "ready",
      coreState,
      turnInput: null,
      beforeTurnCompleted: true,
      awaiting: null,
      pendingTools: [],
      completedTools: [],
      terminalCode: null,
    };
  }

  #terminalState(coreState: NormalizedValue, terminalCode: string): AdapterState {
    return {
      version: CHECKPOINT_STATE_VERSION,
      status: "terminal",
      coreState,
      turnInput: null,
      beforeTurnCompleted: true,
      awaiting: null,
      pendingTools: [],
      completedTools: [],
      terminalCode,
    };
  }

  #throwIfAborted(signal: AbortSignal): void {
    if (signal.aborted) {
      throw signal.reason instanceof BoundaryFault
        ? signal.reason
        : new BoundaryFault("TURN_ABORTED", "bounded engine step was aborted");
    }
  }

  async #createSuccessorCheckpoint(
    predecessor: AgentCheckpoint,
    state: AdapterState,
  ): Promise<AgentCheckpoint> {
    parseAdapterState(state, this.#budgets);
    const payloadBytes = encodeCanonicalCbor(state, {
      maxBytes: this.#budgets.maxCheckpointBytes,
    });
    const checkpoint: AgentCheckpoint = {
      kind: "engine",
      engineKind: "low-level",
      adapterAbiVersion: this.#identity.adapterAbiVersion,
      checkpointSchemaVersion: this.#identity.checkpointSchemaVersion,
      runtimeRevisionDigest: this.#identity.runtimeRevisionDigest,
      sessionId: this.#identity.sessionId,
      turnId: predecessor.turnId,
      checkpointSequence: predecessor.checkpointSequence + 1,
      predecessorDigest: await digestStructuredValue(
        CHECKPOINT_DIGEST_DOMAIN,
        DIGEST_SCHEMA_VERSION,
        predecessor,
      ),
      payloadEncoding: "canonical-cbor",
      payloadBytes,
      payloadDigest: await digestBytes(payloadBytes),
    };
    return validateAgentCheckpoint(checkpoint);
  }

  async #attachCheckpoint(
    checkpoint: AgentCheckpoint,
    boundary: PendingBoundary,
  ): Promise<EngineStepResult> {
    let result: EngineStepResult;
    switch (boundary.kind) {
      case "checkpoint":
        result = { kind: "checkpoint", checkpoint };
        break;
      case "effect_request":
        result = { kind: "effect_request", checkpoint, request: boundary.request };
        break;
      case "turn_complete":
        result = { kind: "turn_complete", checkpoint, result: boundary.result };
        break;
      case "turn_error":
        result = { kind: "turn_error", checkpoint, error: boundary.error };
        break;
    }
    return validateEngineStepResult(result);
  }
}
