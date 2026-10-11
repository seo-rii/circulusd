import {
  digestStructuredValue, validateAgentCheckpoint, validateEngineStepResult,
  type AgentCheckpoint,
} from "@circulusd/protocol-types";
import type {
  AgentEngine, AgentEvent, ResumeTurnContext, StartTurnContext,
} from "../../session-host/src/index.ts";

import { PiRuntimeError } from "./errors.ts";
import {
  PI_EXECUTION_PROTOCOL, sameExecutionBinding, snapshotExecutionBinding,
  snapshotExecutionReply, snapshotExecutionRequest,
  type PiExecutionBinding, type PiExecutionReply, type PiExecutionRequest,
  type PiExecutionTransport,
} from "./execution-rpc.ts";
import { boundedIdentifier, boundedProtocolValue, exactRecord } from "./validation.ts";

const unavailable = () => new PiRuntimeError("ENGINE_POISONED", "Pi execution proxy is invalid or unavailable");
const done = (): IteratorResult<AgentEvent> => ({ done: true, value: undefined });
const maximumActiveExecutions = 64;

async function checkedEvent(input: AgentEvent, predecessor: AgentCheckpoint): Promise<AgentEvent> {
  const value = input as unknown as Record<string, unknown>;
  if (value?.type === "assistant_delta") {
    exactRecord(value, ["type", "delta"], [], "execution.event", "INVALID_CONTEXT");
    return { type: "assistant_delta", delta: boundedProtocolValue(value.delta, 65_536, "execution.delta", "INVALID_CONTEXT") };
  }
  const fields = value?.type === "model_request" || value?.type === "tool_request" ? ["type", "checkpoint", "request"] :
    value?.type === "checkpoint" ? ["type", "checkpoint"] : value?.type === "turn_complete" ? ["type", "checkpoint", "result"] :
    value?.type === "turn_error" ? ["type", "checkpoint", "error"] : [];
  if (fields.length === 0) throw unavailable();
  exactRecord(value, fields, [], "execution.event", "INVALID_CONTEXT");
  const kind = value.type === "model_request" || value.type === "tool_request" ? "effect_request" : value.type;
  const step = await validateEngineStepResult({ kind, checkpoint: value.checkpoint,
    ...(kind === "effect_request" ? { request: value.request } : {}),
    ...(kind === "turn_complete" ? { result: value.result } : {}),
    ...(kind === "turn_error" ? { error: value.error } : {}) });
  const checkpoint = step.checkpoint;
  if (predecessor.checkpointSequence === Number.MAX_SAFE_INTEGER || checkpoint.kind !== "engine" ||
      checkpoint.checkpointSequence !== predecessor.checkpointSequence + 1 ||
      checkpoint.predecessorDigest !== await digestStructuredValue("circulusd.session.agent-checkpoint", 1, predecessor) ||
      checkpoint.engineKind !== predecessor.engineKind || checkpoint.adapterAbiVersion !== predecessor.adapterAbiVersion ||
      checkpoint.checkpointSchemaVersion !== predecessor.checkpointSchemaVersion ||
      checkpoint.runtimeRevisionDigest !== predecessor.runtimeRevisionDigest || checkpoint.sessionId !== predecessor.sessionId ||
      checkpoint.turnId !== predecessor.turnId || checkpoint.payloadEncoding !== predecessor.payloadEncoding) throw unavailable();
  if (step.kind === "effect_request") {
    const request = step.request;
    if ((value.type === "model_request") !== (request.service === "model") ||
        request.requestDigest !== await digestStructuredValue("circulusd.session.effect-request", 1, {
          service: request.service, operation: request.operation, replayPolicy: request.replayPolicy, payload: request.payload,
          ...(request.parentOperationId === undefined ? {} : { parentOperationId: request.parentOperationId, ordinal: request.ordinal }),
        })) throw unavailable();
    return { type: value.type as "model_request" | "tool_request", checkpoint, request };
  }
  if (step.kind === "checkpoint") return { type: "checkpoint", checkpoint };
  if (step.kind === "turn_complete") return { type: "turn_complete", checkpoint, result: step.result };
  return { type: "turn_error", checkpoint, error: step.error };
}

interface IteratorDriver {
  claim(iterator: ProxyIterator): Promise<void>;
  release(iterator: ProxyIterator): void;
  exchange(request: PiExecutionRequest): Promise<PiExecutionReply>;
  validate<T>(work: () => Promise<T>): Promise<T>;
  fail(): never;
}
type OpeningRequest = Extract<PiExecutionRequest, { operation: "start" | "resume" }>;

class ProxyIterator implements AsyncIterableIterator<AgentEvent> {
  readonly #initial: OpeningRequest;
  readonly #driver: IteratorDriver;
  #checkpoint: AgentCheckpoint;
  #claimed = false;
  #opened = false;
  #closed = false;
  #failed = false;
  #pulling = false;
  #sequence = 0;
  #closing: Promise<void> | null = null;

  constructor(initial: OpeningRequest, driver: IteratorDriver) {
    this.#initial = initial;
    this.#checkpoint = initial.checkpoint as AgentCheckpoint;
    this.#driver = driver;
  }

  [Symbol.asyncIterator](): AsyncIterableIterator<AgentEvent> { return this; }
  get executionId(): string { return this.#initial.executionId; }
  get closing(): Promise<void> | null { return this.#closing; }
  get closed(): boolean { return this.#closed; }

  fail(): void { this.#failed = true; this.#closed = true; }

  control(operation: "close" | "abort"): PiExecutionRequest {
    const { protocol, version, binding, turnId, executionId } = this.#initial;
    return { protocol, version, binding, turnId, executionId, operation, sequence: 0 };
  }

  async next(): Promise<IteratorResult<AgentEvent>> {
    if (this.#failed) throw unavailable();
    if (this.#closed) return done();
    if (this.#pulling) throw new PiRuntimeError("STEP_IN_PROGRESS", "concurrent Pi execution pulls are forbidden");
    this.#pulling = true;
    try {
      if (!this.#claimed) {
        await this.#driver.claim(this);
        this.#claimed = true;
        if (this.#closed) { this.#driver.release(this); return done(); }
      }
      if (!this.#opened) {
        this.#checkpoint = await this.#driver.validate(() => validateAgentCheckpoint(this.#checkpoint));
        if (this.#closed) return done();
        await this.#driver.exchange(this.#initial);
        this.#opened = true;
      }
      if (this.#closed) return done();
      if (this.#sequence === Number.MAX_SAFE_INTEGER) return this.#driver.fail();
      const reply = await this.#driver.exchange({ ...this.control("close"), operation: "pull", sequence: ++this.#sequence });
      if (this.#closed) return done();
      if (reply.status === "done") {
        this.#closed = true;
        this.#driver.release(this);
        return done();
      }
      if (reply.status !== "event") return this.#driver.fail();
      const event = await this.#driver.validate(() => checkedEvent(reply.event, this.#checkpoint));
      if (this.#closed) return done();
      if (event.type !== "assistant_delta") this.#checkpoint = structuredClone(event.checkpoint) as AgentCheckpoint;
      return { done: false, value: event };
    } catch (error) {
      if (this.#failed) throw unavailable();
      if (error instanceof PiRuntimeError && error.code === "ENGINE_POISONED") throw unavailable();
      if (this.#closed) return done();
      if (error instanceof PiRuntimeError && error.code === "STEP_IN_PROGRESS" && !this.#claimed) throw error;
      return this.#driver.fail();
    } finally { this.#pulling = false; }
  }

  async stop(operation: "close" | "abort"): Promise<void> {
    if (this.#closing !== null) return this.#closing;
    if (this.#closed) return;
    this.#closed = true;
    this.#closing = (async () => {
      try {
        if (this.#claimed) await this.#driver.exchange(this.control(operation));
      } catch {
        // A failed interrupt poisons the proxy; it proves no native termination.
      } finally { this.#driver.release(this); }
    })();
    return this.#closing;
  }

  async return(): Promise<IteratorResult<AgentEvent>> { await this.stop("close"); return done(); }
  async throw(error?: unknown): Promise<IteratorResult<AgentEvent>> { await this.stop("close"); throw error; }
}

/** Trusted host-side execution port. This neither authorizes broker effects nor
 * proves remote isolate termination. An ambiguous exchange requires a fresh
 * independently constructed composition; retries never advance this iterator.
 */
export class PiExecutionProxy implements AgentEngine {
  readonly #binding: PiExecutionBinding;
  readonly #exchange: PiExecutionTransport["exchange"];
  readonly #timeoutMs: number;
  readonly #active = new Map<string, ProxyIterator>();
  readonly #pending = new Set<ReturnType<typeof Promise.withResolvers<never>>>();
  #poisoned = false;

  constructor(config: { readonly binding: PiExecutionBinding; readonly transport: PiExecutionTransport; readonly timeoutMs?: number }) {
    try {
      const value = exactRecord(config, ["binding", "transport"], ["timeoutMs"], "execution.proxy", "INVALID_CONFIGURATION");
      this.#binding = snapshotExecutionBinding(value.binding);
      const transport = value.transport as PiExecutionTransport;
      const exchange = transport?.exchange;
      if (typeof exchange !== "function") throw unavailable();
      this.#exchange = exchange.bind(transport);
      const timeout = value.timeoutMs ?? 5_000;
      if (typeof timeout !== "number" || !Number.isSafeInteger(timeout) || timeout < 1 || timeout > 30_000) throw unavailable();
      this.#timeoutMs = timeout;
    } catch { throw new PiRuntimeError("INVALID_CONFIGURATION", "Pi execution proxy configuration is invalid"); }
  }

  startTurn(context: StartTurnContext): AsyncIterable<AgentEvent> { return this.#iterator(context, false); }
  resumeTurn(context: ResumeTurnContext): AsyncIterable<AgentEvent> { return this.#iterator(context, true); }

  async abortTurn(turnId: string, executionId?: string): Promise<void> {
    try {
      const turn = boundedIdentifier(turnId, "execution.turnId", "INVALID_CONTEXT");
      const execution = executionId === undefined ? undefined : boundedIdentifier(executionId, "execution.executionId", "INVALID_CONTEXT");
      const owner = this.#active.get(turn);
      if (owner !== undefined && (execution === undefined || owner.executionId === execution)) await owner.stop("abort");
    } catch { throw unavailable(); }
  }

  #iterator(context: StartTurnContext | ResumeTurnContext, resume: boolean): ProxyIterator {
    try {
      if (this.#poisoned) throw unavailable();
      const value = exactRecord(context, ["turnId", "executionId", "authority", "checkpoint", ...(resume ? ["settlement"] : [])], [], "execution.context", "INVALID_CONTEXT");
      const initial = snapshotExecutionRequest({ protocol: PI_EXECUTION_PROTOCOL, version: 1, binding: this.#binding,
        turnId: value.turnId, executionId: value.executionId, sequence: 0, operation: resume ? "resume" : "start",
        authority: value.authority, checkpoint: value.checkpoint, ...(resume ? { settlement: value.settlement } : {}) }) as OpeningRequest;
      return new ProxyIterator(initial, {
        claim: async (iterator) => {
          if (this.#poisoned) throw unavailable();
          const owner = this.#active.get(initial.turnId);
          if (owner !== undefined) {
            if (owner.closing === null) throw new PiRuntimeError("STEP_IN_PROGRESS", "turn already has an active Pi execution");
            // A committed host boundary can finish before its bounded close
            // exchange. Keep the old owner/capacity fence until that exchange
            // verifies cleanup, then admit at most one waiting continuation.
            await owner.closing;
            if (this.#poisoned) throw unavailable();
            if (iterator.closed) return;
            if (this.#active.has(initial.turnId)) throw new PiRuntimeError("STEP_IN_PROGRESS", "turn already has an active Pi execution");
          }
          if (this.#active.size >= maximumActiveExecutions) throw new PiRuntimeError("STEP_IN_PROGRESS", "Pi execution proxy capacity is exhausted");
          this.#active.set(initial.turnId, iterator);
        },
        release: (iterator) => { if (this.#active.get(initial.turnId) === iterator) this.#active.delete(initial.turnId); },
        exchange: (request) => this.#request(request), validate: (work) => this.#bounded(work), fail: () => this.#poison(),
      });
    } catch { throw this.#poisoned ? unavailable() : new PiRuntimeError("INVALID_CONTEXT", "Pi execution context is invalid"); }
  }

  async #request(request: PiExecutionRequest): Promise<PiExecutionReply> {
    return this.#bounded(async () => {
      const reply = snapshotExecutionReply(await this.#exchange(snapshotExecutionRequest(request)));
      if (!sameExecutionBinding(reply.binding, request.binding) || reply.turnId !== request.turnId ||
          reply.executionId !== request.executionId || reply.operation !== request.operation || reply.sequence !== request.sequence) throw unavailable();
      return reply;
    });
  }

  async #bounded<T>(work: () => Promise<T>): Promise<T> {
    if (this.#poisoned) throw unavailable();
    const timeout = Promise.withResolvers<never>();
    const canceled = Promise.withResolvers<never>();
    this.#pending.add(canceled);
    const timer = setTimeout(() => timeout.reject(unavailable()), this.#timeoutMs);
    try {
      return await Promise.race([Promise.resolve().then(() => {
        if (this.#poisoned) throw unavailable();
        return work();
      }), timeout.promise, canceled.promise]);
    }
    catch { return this.#poison(); }
    finally { clearTimeout(timer); this.#pending.delete(canceled); }
  }

  #poison(): never {
    if (!this.#poisoned) {
      this.#poisoned = true;
      for (const pending of this.#pending) pending.reject(unavailable());
      for (const iterator of this.#active.values()) {
        iterator.fail();
        const request = iterator.control("abort");
        // Bounded cleanup has no retries and bypasses the poisoned data path.
        const timer = Promise.withResolvers<void>();
        const handle = setTimeout(() => timer.resolve(), this.#timeoutMs);
        void Promise.race([Promise.resolve().then(() => this.#exchange(snapshotExecutionRequest(request))).then(() => undefined), timer.promise])
          .catch(() => undefined).finally(() => clearTimeout(handle));
      }
      this.#active.clear();
    }
    throw unavailable();
  }
}
