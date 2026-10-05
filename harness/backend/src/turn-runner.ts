import { getRandomValues } from "node:crypto";

import {
  LowLevelPiAgentEngine,
  createOpaqueTurnAuthority,
  createPiAgentCoreFactory,
  createPiAgentCoreInitialState,
  decodePiAgentCoreModelContext,
  decodePiAgentCoreModelSettlement,
  encodePiAgentCoreModelSettlement,
  type AgentCoreFactory,
  type EngineIdentity,
  type EngineSettlement,
  type PiAgentCoreAdapterConfiguration,
  type PiAgentCoreModelConfiguration,
} from "@circulusd/pi-runtime";
import type { AgentCheckpoint, EffectIntent, NormalizedValue } from "@circulusd/protocol-types";
import type { AssistantMessage, Context, Message, Tool, UserMessage } from "@earendil-works/pi-ai";

import { textOfContent, toolCallsOf, type ModelProvider } from "./providers/index.ts";
import type { Session, TranscriptEntry, TurnError, TurnRecord, TurnStatus } from "./session.ts";
import { executeTool, type ToolDefinition } from "./tools.ts";

export interface TurnRuntime {
  readonly provider: ModelProvider;
  readonly tools: readonly ToolDefinition[];
  readonly configuration: PiAgentCoreAdapterConfiguration;
  readonly factory: AgentCoreFactory;
  readonly identity: (sessionId: string) => EngineIdentity;
  readonly historyInjection: boolean;
}

export function createTurnRuntime(options: Omit<TurnRuntime, "factory">): TurnRuntime {
  return { ...options, factory: createPiAgentCoreFactory(options.configuration) };
}

export interface CheckpointSummary {
  readonly kind: AgentCheckpoint["kind"];
  readonly sequence: number;
  readonly payloadDigest: string;
  readonly predecessorDigest: string | null;
  readonly payloadBytes: number;
}

/**
 * Per-turn ceilings. The engine itself has no step limit, so a model that
 * keeps calling tools (or a runner bug) would otherwise spin until someone
 * aborts; a real gateway would enforce a budget here too.
 */
export const MAX_TOOL_CALLS_PER_TURN = 50;
export const MAX_ENGINE_STEPS_PER_TURN = 1_000;

export function summarizeCheckpoint(checkpoint: AgentCheckpoint): CheckpointSummary {
  return {
    kind: checkpoint.kind,
    sequence: checkpoint.checkpointSequence,
    payloadDigest: checkpoint.payloadDigest,
    predecessorDigest: checkpoint.predecessorDigest,
    payloadBytes: checkpoint.payloadBytes.byteLength,
  };
}

/**
 * Drive one turn through circulusd's LowLevelPiAgentEngine exactly the way
 * the workerd conformance fixture does: genesis checkpoint, then bounded
 * `step()` calls. Every effect request the engine emits (model or tool) is
 * committed to the session log, dispatched here, and fed back as a
 * settlement bound to the request digest. Each successor checkpoint is
 * chained to its predecessor by the engine itself.
 */
export async function runTurn(session: Session, turn: TurnRecord, runtime: TurnRuntime): Promise<void> {
  const { turnId } = turn;
  const signal = turn.controller.signal;
  const engine = new LowLevelPiAgentEngine(runtime.identity(session.id), runtime.factory);
  // The engine insists on a plain Uint8Array (a Node Buffer is rejected).
  const authority = createOpaqueTurnAuthority(getRandomValues(new Uint8Array(32)));
  const onAbort = (): void => {
    engine.abortTurn(turnId).catch(() => undefined);
  };
  signal.addEventListener("abort", onAbort, { once: true });

  let checkpoint: AgentCheckpoint | null = null;
  let settlement: EngineSettlement | undefined;
  let steps = 0;
  const budget = { toolCalls: 0 };
  try {
    checkpoint = await engine.createGenesisCheckpoint({
      turnId,
      input: { prompt: turn.prompt, timestamp: Date.now() },
      initialCoreState: createPiAgentCoreInitialState(),
    });
    session.commit("turn.accepted", turnId, {
      prompt: turn.prompt,
      checkpoint: summarizeCheckpoint(checkpoint),
    });

    for (;;) {
      if (signal.aborted) {
        finish(session, turn, "aborted", { code: "TURN_ABORTED", message: "turn aborted by client" }, checkpoint, steps);
        return;
      }
      steps += 1;
      if (steps > MAX_ENGINE_STEPS_PER_TURN) {
        engine.abortTurn(turnId).catch(() => undefined);
        finish(session, turn, "failed", { code: "TURN_STEP_LIMIT", message: `turn exceeded ${MAX_ENGINE_STEPS_PER_TURN} engine steps` }, checkpoint, steps);
        return;
      }
      const step = await engine.step({
        authority,
        checkpoint: structuredClone(checkpoint),
        ...(settlement === undefined ? {} : { settlement: structuredClone(settlement) }),
      });
      checkpoint = step.checkpoint;
      settlement = undefined;

      switch (step.kind) {
        case "checkpoint":
          session.commit("checkpoint", turnId, { step: steps, checkpoint: summarizeCheckpoint(checkpoint) });
          continue;
        case "effect_request":
          settlement = await dispatchEffect(session, turn, step.request, checkpoint, runtime, budget);
          continue;
        case "turn_complete": {
          const message = decodePiAgentCoreModelSettlement(step.result);
          const text = textOfContent(message.content);
          session.remember(
            { role: "user", text: turn.prompt, turnId },
            { role: "assistant", text, turnId },
          );
          turn.result = text;
          finish(session, turn, "completed", null, checkpoint, steps, {
            message: {
              text,
              content: message.content as NormalizedValue,
              stopReason: message.stopReason,
              usage: message.usage as unknown as NormalizedValue,
            },
          });
          return;
        }
        case "turn_error":
          finish(
            session,
            turn,
            signal.aborted ? "aborted" : "failed",
            { code: step.error.code, message: step.error.message },
            checkpoint,
            steps,
          );
          return;
      }
    }
  } catch (error) {
    finish(
      session,
      turn,
      signal.aborted ? "aborted" : "failed",
      {
        code: signal.aborted ? "TURN_ABORTED" : "TURN_RUNNER_FAILED",
        message: errorMessage(error),
      },
      checkpoint,
      steps,
    );
  } finally {
    signal.removeEventListener("abort", onAbort);
  }
}

async function dispatchEffect(
  session: Session,
  turn: TurnRecord,
  request: EffectIntent,
  checkpoint: AgentCheckpoint,
  runtime: TurnRuntime,
  budget: { toolCalls: number },
): Promise<EngineSettlement> {
  const { turnId } = turn;
  const signal = turn.controller.signal;
  const base = {
    requestDigest: request.requestDigest,
    service: request.service,
    operation: request.operation,
    replayPolicy: request.replayPolicy,
    ...(request.ordinal === undefined ? {} : { ordinal: request.ordinal }),
    checkpoint: summarizeCheckpoint(checkpoint),
  };

  if (request.service === "model") {
    const payload = request.payload as { readonly context?: unknown };
    const decoded = decodePiAgentCoreModelContext(payload.context);
    const captured: Context = {
      ...(typeof decoded.systemPrompt === "string" ? { systemPrompt: decoded.systemPrompt } : {}),
      messages: decoded.messages as Message[],
      ...(Array.isArray(decoded.tools) ? { tools: decoded.tools as Tool[] } : {}),
    };
    const { context, injected } = runtime.historyInjection
      ? injectHistory(captured, session.transcript, runtime.provider.configuration)
      : { context: captured, injected: 0 };
    session.commit("model.started", turnId, {
      ...base,
      model: runtime.provider.configuration.id,
      contextMessages: context.messages.length,
      historyInjected: injected,
    });
    try {
      const message = await runtime.provider.complete({
        context,
        signal,
        onDelta: (text) => {
          session.emit("model.delta", turnId, { requestDigest: request.requestDigest, text });
        },
        onThinking: (text) => {
          session.emit("model.thinking", turnId, { requestDigest: request.requestDigest, text });
        },
      });
      const result = encodePiAgentCoreModelSettlement(message);
      session.commit("model.settled", turnId, {
        ...base,
        outcome: "success",
        stopReason: message.stopReason,
        text: textOfContent(message.content),
        toolCalls: toolCallsOf(message.content).map((call) => ({
          id: call.id,
          name: call.name,
          arguments: call.arguments,
        })),
        usage: message.usage,
      });
      return { requestDigest: request.requestDigest, outcome: { kind: "success", result } };
    } catch (error) {
      const outcome: EngineSettlement["outcome"] = signal.aborted
        ? { kind: "interrupted_unknown", reason: "turn aborted while the model request was in flight" }
        : {
            kind: "error",
            code: errorCode(error, "MODEL_PROVIDER_FAILED"),
            message: errorMessage(error),
            retryable: false,
          };
      session.commit("model.settled", turnId, { ...base, outcome: outcome.kind, error: outcome });
      return { requestDigest: request.requestDigest, outcome };
    }
  }

  if (request.service === "external-tool") {
    const payload = request.payload as {
      readonly toolCall?: { readonly id?: unknown; readonly name?: unknown; readonly arguments?: unknown };
    };
    const toolCall = payload.toolCall ?? {};
    const toolCallId = typeof toolCall.id === "string" ? toolCall.id : "";
    const name = typeof toolCall.name === "string" ? toolCall.name : "";
    const args =
      toolCall.arguments !== null && typeof toolCall.arguments === "object" && !Array.isArray(toolCall.arguments)
        ? (toolCall.arguments as Record<string, unknown>)
        : {};
    budget.toolCalls += 1;
    if (budget.toolCalls > MAX_TOOL_CALLS_PER_TURN) {
      const outcome: EngineSettlement["outcome"] = {
        kind: "error",
        code: "TOOL_CALL_LIMIT",
        message: `turn exceeded ${MAX_TOOL_CALLS_PER_TURN} tool calls`,
        retryable: false,
      };
      session.commit("effect.rejected", turnId, { ...base, toolCallId, name, error: outcome });
      return { requestDigest: request.requestDigest, outcome };
    }
    session.commit("tool.started", turnId, { ...base, toolCallId, name, arguments: args });
    const execution = await executeTool(runtime.tools, name, args, {
      sessionId: session.id,
      turnId,
      toolCallId,
      signal,
      effect: { requestDigest: request.requestDigest, replayPolicy: request.replayPolicy, operation: request.operation },
    });
    session.emit("tool.stdout", turnId, { toolCallId, name, text: execution.text });
    session.commit("tool.completed", turnId, {
      ...base,
      toolCallId,
      name,
      isError: execution.isError,
      text: execution.text,
    });
    return {
      requestDigest: request.requestDigest,
      outcome: {
        kind: "success",
        result: {
          version: 1,
          toolCallId,
          toolName: name,
          content: [{ type: "text", text: execution.text }],
          isError: execution.isError,
          timestamp: Date.now(),
        },
      },
    };
  }

  const outcome: EngineSettlement["outcome"] = {
    kind: "error",
    code: "EFFECT_SERVICE_UNSUPPORTED",
    message: `effect service "${request.service}" is not wired in circulusd-test`,
    retryable: false,
  };
  session.commit("effect.rejected", turnId, { ...base, error: outcome });
  return { requestDigest: request.requestDigest, outcome };
}

/**
 * The circulusd Pi adapter starts every turn from a fresh state, so the
 * transcript of earlier turns is not part of the captured model context.
 * For a chat-style test UI we prepend it at the gateway boundary; it is
 * reported on each `model.started` event as `historyInjected`.
 */
function injectHistory(
  context: Context,
  transcript: readonly TranscriptEntry[],
  model: PiAgentCoreModelConfiguration,
): { readonly context: Context; readonly injected: number } {
  if (transcript.length === 0) return { context, injected: 0 };
  const kept = fitHistory(transcript, historyBudgetChars(context, model));
  if (kept.length === 0) return { context, injected: 0 };
  const history: Message[] = kept.map((entry) =>
    entry.role === "user" ? userMessage(entry.text) : assistantMessage(entry.text, model),
  );
  return { context: { ...context, messages: [...history, ...context.messages] }, injected: history.length };
}

/** Rough characters-per-token used to keep the injected history inside the context window. */
const HISTORY_CHARS_PER_TOKEN = 4;

/**
 * Characters of history that fit next to the current context: the window
 * minus room for the answer and minus what the captured context already
 * takes. A long chat would otherwise grow past the window and fail (or, with
 * Ollama, be truncated silently from the front, which loses the system prompt).
 */
export function historyBudgetChars(context: Context, model: PiAgentCoreModelConfiguration): number {
  const windowChars = (model.contextWindow - model.maxTokens) * HISTORY_CHARS_PER_TOKEN;
  const used = JSON.stringify(context).length;
  return Math.max(0, windowChars - used);
}

/** Keeps the most recent entries that fit `budgetChars`, starting at a user turn so pairs stay intact. */
export function fitHistory(transcript: readonly TranscriptEntry[], budgetChars: number): readonly TranscriptEntry[] {
  let total = 0;
  for (const entry of transcript) total += entry.text.length;
  let start = 0;
  while (start < transcript.length && total > budgetChars) {
    total -= (transcript[start] as TranscriptEntry).text.length;
    start += 1;
  }
  while (start < transcript.length && (transcript[start] as TranscriptEntry).role !== "user") start += 1;
  return start === 0 ? transcript : transcript.slice(start);
}

function userMessage(text: string): UserMessage {
  return { role: "user", content: text, timestamp: Date.now() };
}

function assistantMessage(text: string, model: PiAgentCoreModelConfiguration): AssistantMessage {
  return {
    role: "assistant",
    content: [{ type: "text", text }],
    api: model.api,
    provider: model.provider,
    model: model.id,
    usage: {
      input: 0,
      output: 0,
      cacheRead: 0,
      cacheWrite: 0,
      totalTokens: 0,
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
    },
    stopReason: "stop",
    timestamp: Date.now(),
  };
}

function finish(
  session: Session,
  turn: TurnRecord,
  status: Exclude<TurnStatus, "running">,
  error: TurnError | null,
  checkpoint: AgentCheckpoint | null,
  steps: number,
  extra: Record<string, unknown> = {},
): void {
  turn.status = status;
  turn.error = error;
  turn.finishedAt = Date.now();
  if (session.activeTurn === turn) session.activeTurn = null;
  const type = status === "completed" ? "turn.completed" : status === "aborted" ? "turn.aborted" : "turn.failed";
  session.commit(type, turn.turnId, {
    status,
    steps,
    ...(error === null ? {} : { error }),
    ...(checkpoint === null ? {} : { checkpoint: summarizeCheckpoint(checkpoint) }),
    ...extra,
  });
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}

function errorCode(error: unknown, fallback: string): string {
  if (error !== null && typeof error === "object" && typeof (error as { code?: unknown }).code === "string") {
    return (error as { code: string }).code;
  }
  return fallback;
}
