import type { AgentEngine, AgentEvent } from "../../session-host/src/index.ts";

import {
  invalidExecution, sameExecutionBinding, snapshotExecutionBinding,
  snapshotExecutionReply, snapshotExecutionRequest,
  type PiExecutionBinding, type PiExecutionReply, type PiExecutionRequest,
} from "./execution-rpc.ts";
import { exactRecord } from "./validation.ts";

interface Execution {
  readonly turnId: string;
  readonly executionId: string;
  stopped: ReturnType<typeof Promise.withResolvers<void>> | null;
  retired: boolean;
  sequence: number;
  pulling: boolean;
  iterator: AsyncIterator<AgentEvent> | null;
  abort: (() => Promise<void>) | null;
  cleanup: Promise<void> | null;
  escalateAbort: (() => Promise<void>) | null;
}

function limit(value: unknown, fallback: number, maximum: number): number {
  if (value === undefined) return fallback;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1 || value > maximum) invalidExecution();
  return value;
}

// One endpoint owns every execution identity for its entire lifetime. Retired
// identities stay bounded and are never evicted: a delayed open cannot revive
// an execution that the trusted host already closed or aborted.
export class PiExecutionEndpoint {
  readonly #binding: PiExecutionBinding;
  readonly #createEngine: () => AgentEngine;
  readonly #maximumExecutions: number;
  readonly #maximumLifetimeExecutions: number;
  readonly #executions = new Map<string, Execution>();
  readonly #owners = new Map<string, string>();
  #disposed = false;

  constructor(config: {
    readonly binding: PiExecutionBinding;
    readonly createEngine: () => AgentEngine;
    readonly maximumExecutions?: number;
    readonly maximumLifetimeExecutions?: number;
  }) {
    try {
      const value = exactRecord(config, ["binding", "createEngine"],
        ["maximumExecutions", "maximumLifetimeExecutions"], "execution.endpoint", "INVALID_CONTEXT");
      if (typeof value.createEngine !== "function") invalidExecution();
      this.#binding = snapshotExecutionBinding(value.binding);
      this.#createEngine = value.createEngine as () => AgentEngine;
      this.#maximumExecutions = limit(value.maximumExecutions, 64, 64);
      this.#maximumLifetimeExecutions = limit(value.maximumLifetimeExecutions, 1024, 4096);
    } catch { invalidExecution(); }
  }

  async exchange(input: PiExecutionRequest): Promise<PiExecutionReply> {
    try {
      const request = snapshotExecutionRequest(input);
      if (!sameExecutionBinding(request.binding, this.#binding)) invalidExecution();
      const execution = this.#executions.get(request.executionId);
      if (execution !== undefined && execution.turnId !== request.turnId) invalidExecution();
      // A poisoned/disposed endpoint accepts only cleanup of an already owned
      // identity. Transport callers must still be able to finish peer cleanup.
      if (this.#disposed && (execution === undefined ||
          (request.operation !== "close" && request.operation !== "abort"))) invalidExecution();
      if (request.operation === "start" || request.operation === "resume") {
        if (execution !== undefined || this.#owners.has(request.turnId) ||
            this.#owners.size >= this.#maximumExecutions) invalidExecution();
        const opened = this.#register(request);
        this.#owners.set(request.turnId, request.executionId);
        try {
          const engine = this.#createEngine();
          if (engine === null || typeof engine !== "object" || typeof engine.startTurn !== "function" ||
              typeof engine.resumeTurn !== "function" || typeof engine.abortTurn !== "function") invalidExecution();
          opened.abort = engine.abortTurn.bind(engine, request.turnId, request.executionId);
          const context = { turnId: request.turnId, executionId: request.executionId,
            authority: request.authority, checkpoint: request.checkpoint };
          const events = request.operation === "start" ? engine.startTurn(context) :
            engine.resumeTurn({ ...context, settlement: request.settlement });
          if (events === null || typeof events !== "object" || typeof events[Symbol.asyncIterator] !== "function") invalidExecution();
          const iterator = events[Symbol.asyncIterator]();
          if (iterator === null || typeof iterator !== "object") invalidExecution();
          opened.iterator = iterator;
          if (typeof iterator.next !== "function") invalidExecution();
          return this.#reply(request, "opened");
        } catch {
          this.#retire(opened);
          void this.#cleanup(opened, true).catch(() => undefined);
          // Construction performs no pull. Failed construction retains its
          // identity; it cannot be retried with a different engine/context.
          invalidExecution();
        }
      }
      if (request.operation === "pull") {
        if (execution === undefined || execution.retired || execution.pulling ||
            request.sequence !== execution.sequence + 1) invalidExecution();
        execution.sequence = request.sequence;
        execution.pulling = true;
        const stopped = Promise.withResolvers<void>();
        execution.stopped = stopped;
        try {
          const iterator = execution.iterator;
          if (iterator === null) invalidExecution();
          const next = Promise.resolve().then(() => execution.retired ? null : iterator.next());
          const outcome = await Promise.race([
            next,
            stopped.promise.then(() => null),
          ]);
          if (execution.retired || outcome === null) return this.#reply(request, "done");
          const result = exactRecord(outcome, ["done"], ["value"], "execution.iteratorResult", "INVALID_CONTEXT");
          if (typeof result.done !== "boolean") invalidExecution();
          if (result.done) {
            this.#retire(execution);
            await this.#cleanup(execution, false);
            return this.#reply(request, "done");
          }
          const event = this.#event(result.value);
          return snapshotExecutionReply({ ...this.#header(request), status: "event", event });
        } catch {
          this.#retire(execution);
          void this.#cleanup(execution, true).catch(() => undefined);
          invalidExecution();
        } finally {
          execution.pulling = false;
          execution.stopped = null;
        }
      }
      const closing = execution ?? this.#register(request);
      this.#retire(closing);
      await this.#cleanup(closing, request.operation === "abort");
      return this.#reply(request, request.operation === "close" ? "closed" : "aborted");
    } catch { return invalidExecution(); }
  }

  // Cooperative disposal blocks new work and unblocks caller pulls. Existing
  // owned cleanup controls remain available for idempotent transport shutdown.
  // It does not destroy the native isolate or establish a host resource limit.
  async dispose(): Promise<void> {
    this.#disposed = true;
    const pending: Promise<void>[] = [];
    for (const execution of this.#executions.values()) {
      this.#retire(execution);
      pending.push(this.#cleanup(execution, true));
    }
    const results = await Promise.allSettled(pending);
    if (results.some((result) => result.status === "rejected")) invalidExecution();
  }

  #register(request: PiExecutionRequest): Execution {
    if (this.#executions.size >= this.#maximumLifetimeExecutions) invalidExecution();
    const execution: Execution = { turnId: request.turnId, executionId: request.executionId,
      stopped: null, retired: false, sequence: 0, pulling: false,
      iterator: null, abort: null, cleanup: null, escalateAbort: null };
    this.#executions.set(request.executionId, execution);
    return execution;
  }

  #retire(execution: Execution): void {
    execution.retired = true;
    execution.stopped?.resolve();
  }

  #cleanup(execution: Execution, abort: boolean): Promise<void> {
    if (execution.cleanup === null) {
      const iterator = execution.iterator;
      const abortOwned = execution.abort;
      execution.iterator = null;
      execution.abort = null;
      let abortion: Promise<void> | null = null;
      const abortOnce = () => {
        if (abortion === null && abortOwned !== null) {
          abortion = Promise.resolve().then(() => abortOwned()).then(() => undefined);
          // An escalated abort may settle before a blocked iterator.return.
          // Observe rejection now, then include its result in cleanup below.
          void abortion.catch(() => undefined);
        }
        return abortion ?? Promise.resolve();
      };
      execution.escalateAbort = abortOnce;
      if (abort) void abortOnce();
      let cleaned = false;
      execution.cleanup = Promise.resolve().then(async () => {
        const operations: Promise<void>[] = [];
        // Read/invoke return inside the promise so even a failed method access
        // remains a cleanup result and triggers the owned abort fallback.
        if (iterator !== null) operations.push(Promise.resolve().then(() => iterator.return?.()).then(() => undefined));
        const results = await Promise.allSettled(operations);
        // Close escalation before taking the final abort snapshot. Otherwise
        // a later control could start an abort after capacity was released.
        execution.escalateAbort = null;
        if (results.some((result) => result.status === "rejected")) void abortOnce();
        const abortResults = abortion === null ? [] : await Promise.allSettled([abortion]);
        if ([...results, ...abortResults].some((result) => result.status === "rejected")) invalidExecution();
        cleaned = true;
      }).finally(() => {
        execution.escalateAbort = null;
        // Resident capacity remains fenced until all cooperative cleanup
        // settles. Stalled cleanup cannot admit unbounded replacement engines.
        if (cleaned) {
          if (this.#owners.get(execution.turnId) === execution.executionId) this.#owners.delete(execution.turnId);
        } else {
          // A failed cooperative cleanup provides no evidence that its engine
          // stopped. Require a fresh endpoint rather than admitting replacement.
          this.#disposed = true;
          // Failure retires every peer before starting cooperative cleanup.
          // Their pending pulls stop immediately; each cleanup is memoized, so
          // another failure cannot recurse or duplicate an owned abort.
          for (const peer of this.#executions.values()) {
            if (peer === execution) continue;
            this.#retire(peer);
            void this.#cleanup(peer, true).catch(() => undefined);
          }
        }
      });
    } else if (abort) void execution.escalateAbort?.();
    return execution.cleanup;
  }

  #reply(request: PiExecutionRequest, status: "opened" | "done" | "closed" | "aborted"): PiExecutionReply {
    return snapshotExecutionReply({ ...this.#header(request), status });
  }

  #header(request: PiExecutionRequest) {
    const { protocol, version, binding, turnId, executionId, sequence, operation } = request;
    return { protocol, version, binding, turnId, executionId, sequence, operation };
  }

  #event(input: unknown): AgentEvent {
    if (input === null || typeof input !== "object") invalidExecution();
    const descriptor = Object.getOwnPropertyDescriptor(input, "type");
    if (descriptor === undefined || !("value" in descriptor)) invalidExecution();
    const fields = descriptor.value === "assistant_delta" ? ["type", "delta"] :
      descriptor.value === "checkpoint" ? ["type", "checkpoint"] :
      descriptor.value === "model_request" || descriptor.value === "tool_request" ? ["type", "checkpoint", "request"] :
      descriptor.value === "turn_complete" ? ["type", "checkpoint", "result"] :
      descriptor.value === "turn_error" ? ["type", "checkpoint", "error"] : null;
    if (fields === null) invalidExecution();
    return exactRecord(input, fields, [], "execution.event", "INVALID_CONTEXT") as unknown as AgentEvent;
  }
}
