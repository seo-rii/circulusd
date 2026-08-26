import {
  ProtocolValidationError,
  digestStructuredValue,
  parseAgentCheckpoint,
  validateEngineStepResult,
  type AgentCheckpoint,
} from "@circulusd/protocol-types";

import type {
  AgentEngine as SessionHostAgentEngine,
  AgentEvent,
  ResumeTurnContext,
  StartTurnContext,
} from "../../session-host/src/index.ts";
import { createOpaqueTurnAuthority } from "./authority.ts";
import { DEFAULT_ENGINE_BUDGETS } from "./engine.ts";
import { PiRuntimeError } from "./errors.ts";
import {
  boundedIdentifier,
  exactRecord,
  parseEngineSettlement,
} from "./validation.ts";
import type {
  AgentEngine as BoundedAgentEngine,
  EngineSettlement,
} from "./types.ts";

const CHECKPOINT_DIGEST_DOMAIN = "circulusd.session.agent-checkpoint";
const CHECKPOINT_DIGEST_SCHEMA_VERSION = 1;
const EFFECT_REQUEST_DIGEST_DOMAIN = "circulusd.session.effect-request";

interface ActiveExecutionOwner {
  readonly executionId: string;
  stepActive: boolean;
  abortPromise: Promise<void> | null;
  abortSettled: boolean;
}

const activeExecutionsByEngine = new WeakMap<
  BoundedAgentEngine,
  Map<string, ActiveExecutionOwner>
>();

interface ValidatedTurnStart {
  readonly turnId: string;
  readonly executionId: string;
  readonly authority: ReturnType<typeof createOpaqueTurnAuthority>;
  readonly checkpoint: AgentCheckpoint;
  readonly settlement?: EngineSettlement;
}

class PullDrivenAgentIterator implements AsyncIterableIterator<AgentEvent> {
  readonly #engine: BoundedAgentEngine;
  readonly #turnId: string;
  readonly #claimExecution: () => void;
  readonly #abortOwnedExecution: () => Promise<void>;
  readonly #releaseExecution: () => void;
  readonly #authority: ValidatedTurnStart["authority"];
  #checkpoint: AgentCheckpoint;
  #settlement: EngineSettlement | null;
  #pull: ReturnType<typeof Promise.withResolvers<IteratorResult<AgentEvent>>> | null = null;
  #resumeProducer: (() => void) | null = null;
  #producer: Promise<void> | null = null;
  #closed = false;
  #finished = false;

  constructor(
    engine: BoundedAgentEngine,
    context: ValidatedTurnStart,
    settlement: EngineSettlement | null,
    claimExecution: () => void,
    abortOwnedExecution: () => Promise<void>,
    releaseExecution: () => void,
  ) {
    this.#engine = engine;
    this.#turnId = context.turnId;
    this.#claimExecution = claimExecution;
    this.#abortOwnedExecution = abortOwnedExecution;
    this.#releaseExecution = releaseExecution;
    this.#authority = context.authority;
    this.#checkpoint = context.checkpoint;
    this.#settlement = settlement;
  }

  [Symbol.asyncIterator](): AsyncIterableIterator<AgentEvent> {
    return this;
  }

  next(): Promise<IteratorResult<AgentEvent>> {
    if (this.#closed || this.#finished) {
      return Promise.resolve({ done: true, value: undefined });
    }
    if (this.#pull !== null) {
      return Promise.reject(
        new PiRuntimeError("STEP_IN_PROGRESS", "concurrent AsyncIterator.next calls are forbidden"),
      );
    }

    const pull = Promise.withResolvers<IteratorResult<AgentEvent>>();
    this.#pull = pull;
    const resume = this.#resumeProducer;
    this.#resumeProducer = null;
    resume?.();
    if (this.#producer === null) {
      this.#producer = this.#produce();
    }
    return pull.promise;
  }

  async return(): Promise<IteratorResult<AgentEvent>> {
    if (this.#closed) {
      return { done: true, value: undefined };
    }
    const completedAtDurableBoundary = this.#finished;
    this.#closed = true;
    this.#finished = true;
    const pull = this.#pull;
    this.#pull = null;
    pull?.resolve({ done: true, value: undefined });
    const resume = this.#resumeProducer;
    this.#resumeProducer = null;
    resume?.();
    if (!completedAtDurableBoundary) {
      await this.#bestEffortAbort();
    } else {
      this.#releaseExecution();
    }
    return { done: true, value: undefined };
  }

  async throw(error?: unknown): Promise<IteratorResult<AgentEvent>> {
    await this.return();
    throw error;
  }

  async #produce(): Promise<void> {
    try {
      while (!this.#closed && !this.#finished) {
        const settlement = this.#settlement;
        this.#settlement = null;
        const predecessor = structuredClone(this.#checkpoint);
        this.#claimExecution();
        let rawStep: unknown;
        try {
          rawStep = await this.#engine.step({
            authority: this.#authority,
            checkpoint: structuredClone(predecessor),
            ...(settlement === null ? {} : { settlement: structuredClone(settlement) }),
            emitDelta: async (delta) => {
              await this.#publishAndAwaitPull({ type: "assistant_delta", delta });
            },
          });
        } finally {
          this.#releaseExecution();
        }
        const step = await validateEngineStepResult(
          rawStep,
        );
        const successor = step.checkpoint;
        const predecessorDigest = await digestStructuredValue(
          CHECKPOINT_DIGEST_DOMAIN,
          CHECKPOINT_DIGEST_SCHEMA_VERSION,
          predecessor,
        );
        if (
          successor.kind !== "engine" ||
          predecessor.checkpointSequence === Number.MAX_SAFE_INTEGER ||
          successor.checkpointSequence !== predecessor.checkpointSequence + 1 ||
          successor.predecessorDigest !== predecessorDigest ||
          successor.engineKind !== predecessor.engineKind ||
          successor.adapterAbiVersion !== predecessor.adapterAbiVersion ||
          successor.checkpointSchemaVersion !== predecessor.checkpointSchemaVersion ||
          successor.runtimeRevisionDigest !== predecessor.runtimeRevisionDigest ||
          successor.sessionId !== predecessor.sessionId ||
          successor.turnId !== predecessor.turnId ||
          successor.turnId !== this.#turnId ||
          successor.payloadEncoding !== predecessor.payloadEncoding
        ) {
          throw new PiRuntimeError(
            "INVALID_CHECKPOINT",
            "bounded AgentEngine returned a checkpoint outside the current successor chain",
          );
        }
        if (step.kind === "effect_request") {
          const request = step.request;
          const expectedRequestDigest = await digestStructuredValue(
            EFFECT_REQUEST_DIGEST_DOMAIN,
            CHECKPOINT_DIGEST_SCHEMA_VERSION,
            {
              service: request.service,
              operation: request.operation,
              replayPolicy: request.replayPolicy,
              payload: request.payload,
              ...(request.parentOperationId === undefined
                ? {}
                : {
                    parentOperationId: request.parentOperationId,
                    ordinal: request.ordinal,
                  }),
            },
          );
          if (request.requestDigest !== expectedRequestDigest) {
            throw new PiRuntimeError(
              "INVALID_CONTEXT",
              "bounded AgentEngine returned an effect request with a mismatched digest",
            );
          }
        }
        if (this.#closed) return;
        this.#checkpoint = successor;

        switch (step.kind) {
          case "checkpoint":
            await this.#publishAndAwaitPull({
              type: "checkpoint",
              checkpoint: step.checkpoint,
            });
            break;
          case "effect_request":
            this.#finishWithEvent({
              type: step.request.service === "model" ? "model_request" : "tool_request",
              checkpoint: step.checkpoint,
              request: step.request,
            });
            return;
          case "turn_complete":
            this.#finishWithEvent({
              type: "turn_complete",
              checkpoint: step.checkpoint,
              result: step.result,
            });
            return;
          case "turn_error":
            this.#finishWithEvent({
              type: "turn_error",
              checkpoint: step.checkpoint,
              error: step.error,
            });
            return;
        }
      }
    } catch (error) {
      if (this.#closed) return;
      this.#finished = true;
      await this.#bestEffortAbort();
      const pull = this.#pull;
      this.#pull = null;
      pull?.reject(error);
    }
  }

  async #publishAndAwaitPull(event: AgentEvent): Promise<void> {
    if (this.#closed) {
      throw new PiRuntimeError("ENGINE_POISONED", "AgentEvent iteration was closed");
    }
    const pull = this.#pull;
    if (pull === null) {
      throw new PiRuntimeError(
        "STEP_IN_PROGRESS",
        "AgentEngine attempted to publish without an AsyncIterator pull",
      );
    }
    const cloned = structuredClone(event);
    this.#pull = null;
    const resumed = Promise.withResolvers<void>();
    this.#resumeProducer = () => resumed.resolve();
    pull.resolve({ done: false, value: cloned });
    await resumed.promise;
    if (this.#closed) {
      throw new PiRuntimeError("ENGINE_POISONED", "AgentEvent iteration was closed");
    }
  }

  #finishWithEvent(event: AgentEvent): void {
    const pull = this.#pull;
    if (pull === null) {
      throw new PiRuntimeError(
        "STEP_IN_PROGRESS",
        "AgentEngine attempted to finish without an AsyncIterator pull",
      );
    }
    const cloned = structuredClone(event);
    this.#pull = null;
    this.#finished = true;
    pull.resolve({ done: false, value: cloned });
  }

  async #bestEffortAbort(): Promise<void> {
    try {
      await this.#abortOwnedExecution();
    } catch {
      // Session durable state remains authoritative when an isolate cannot
      // acknowledge this execution-only interrupt.
    }
  }
}

export class LowLevelPiSessionHostAdapter implements SessionHostAgentEngine {
  readonly #engine: BoundedAgentEngine;
  readonly #activeExecutions: Map<string, ActiveExecutionOwner>;

  constructor(engine: BoundedAgentEngine) {
    if (
      engine === null ||
      typeof engine !== "object" ||
      typeof engine.step !== "function" ||
      typeof engine.abortTurn !== "function"
    ) {
      throw new PiRuntimeError("INVALID_CONFIGURATION", "bounded AgentEngine is invalid");
    }
    this.#engine = engine;
    let activeExecutions = activeExecutionsByEngine.get(engine);
    if (activeExecutions === undefined) {
      activeExecutions = new Map<string, ActiveExecutionOwner>();
      activeExecutionsByEngine.set(engine, activeExecutions);
    }
    this.#activeExecutions = activeExecutions;
  }

  startTurn(context: StartTurnContext): AsyncIterable<AgentEvent> {
    const validated = this.#validatedStart(context, false);
    return new PullDrivenAgentIterator(
      this.#engine,
      validated,
      null,
      () => this.#claimExecution(validated.turnId, validated.executionId),
      () => this.#abortOwnedExecution(validated.turnId, validated.executionId),
      () => this.#releaseExecution(validated.turnId, validated.executionId),
    );
  }

  resumeTurn(context: ResumeTurnContext): AsyncIterable<AgentEvent> {
    const validated = this.#validatedStart(context, true);
    if (validated.settlement === undefined) {
      throw new PiRuntimeError("INVALID_CONTEXT", "resumeTurn settlement is required");
    }
    return new PullDrivenAgentIterator(
      this.#engine,
      validated,
      validated.settlement,
      () => this.#claimExecution(validated.turnId, validated.executionId),
      () => this.#abortOwnedExecution(validated.turnId, validated.executionId),
      () => this.#releaseExecution(validated.turnId, validated.executionId),
    );
  }

  async abortTurn(turnId: string, executionId?: string): Promise<void> {
    const validatedTurnId = boundedIdentifier(turnId, "turnId", "INVALID_CONTEXT");
    if (executionId === undefined) {
      const owner = this.#activeExecutions.get(validatedTurnId);
      if (owner === undefined) {
        await this.#engine.abortTurn(validatedTurnId);
        return;
      }
      await this.#abortExecutionRecord(validatedTurnId, owner);
      return;
    }
    const validatedExecutionId = boundedIdentifier(
      executionId,
      "executionId",
      "INVALID_CONTEXT",
    );
    return this.#abortOwnedExecution(validatedTurnId, validatedExecutionId);
  }

  #claimExecution(turnId: string, executionId: string): void {
    if (this.#activeExecutions.has(turnId)) {
      throw new PiRuntimeError("STEP_IN_PROGRESS", "turn already has an active execution owner");
    }
    this.#activeExecutions.set(turnId, {
      executionId,
      stepActive: true,
      abortPromise: null,
      abortSettled: false,
    });
  }

  async #abortOwnedExecution(turnId: string, executionId: string): Promise<void> {
    const owner = this.#activeExecutions.get(turnId);
    if (owner?.executionId !== executionId) return;
    await this.#abortExecutionRecord(turnId, owner);
  }

  #abortExecutionRecord(turnId: string, owner: ActiveExecutionOwner): Promise<void> {
    if (owner.abortPromise === null) {
      const abort = Promise.withResolvers<void>();
      owner.abortPromise = abort.promise.finally(() => {
        owner.abortSettled = true;
        this.#deleteFinishedExecution(turnId, owner);
      });
      try {
        Promise.resolve(this.#engine.abortTurn(turnId)).then(abort.resolve, abort.reject);
      } catch (error) {
        abort.reject(error);
      }
    }
    return owner.abortPromise;
  }

  #releaseExecution(turnId: string, executionId: string): void {
    const owner = this.#activeExecutions.get(turnId);
    if (owner?.executionId === executionId) {
      owner.stepActive = false;
      this.#deleteFinishedExecution(turnId, owner);
    }
  }

  #deleteFinishedExecution(turnId: string, owner: ActiveExecutionOwner): void {
    if (
      this.#activeExecutions.get(turnId) === owner &&
      !owner.stepActive &&
      (owner.abortPromise === null || owner.abortSettled)
    ) {
      this.#activeExecutions.delete(turnId);
    }
  }

  #validatedStart(
    context: StartTurnContext | ResumeTurnContext,
    resume: boolean,
  ): ValidatedTurnStart {
    const record = exactRecord(
      context,
      resume
        ? ["turnId", "executionId", "authority", "checkpoint", "settlement"]
        : ["turnId", "executionId", "authority", "checkpoint"],
      [],
      resume ? "resumeTurn" : "startTurn",
      "INVALID_CONTEXT",
    );
    const turnId = boundedIdentifier(record.turnId, "turnId", "INVALID_CONTEXT");
    const executionId = boundedIdentifier(
      record.executionId,
      "executionId",
      "INVALID_CONTEXT",
    );
    const authority = createOpaqueTurnAuthority(record.authority as Uint8Array);
    let checkpoint: AgentCheckpoint;
    try {
      checkpoint = parseAgentCheckpoint(record.checkpoint);
    } catch (error) {
      if (error instanceof ProtocolValidationError) {
        throw new PiRuntimeError("INVALID_CHECKPOINT", `checkpoint is invalid: ${error.message}`, {
          cause: error,
        });
      }
      throw error;
    }
    if (checkpoint.turnId !== turnId) {
      throw new PiRuntimeError(
        "INVALID_CONTEXT",
        "turnId does not match the current checkpoint",
      );
    }
    return {
      turnId,
      executionId,
      authority,
      checkpoint,
      ...(resume
        ? {
            settlement: parseEngineSettlement(
              record.settlement,
              DEFAULT_ENGINE_BUDGETS.maxStepInputBytes,
              "resumeTurn.settlement",
            ),
          }
        : {}),
    };
  }
}
