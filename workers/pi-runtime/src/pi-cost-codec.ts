import type { Context } from "@earendil-works/pi-ai";
import type { EffectIntent, NormalizedValue } from "@circulusd/protocol-types";

import { PiRuntimeError } from "./errors.ts";
import { boundedProtocolValue, exactRecord } from "./validation.ts";

export const PI_AGENT_CORE_MODEL_PROTOCOL_VERSION = 2 as const;
export const PI_AGENT_CORE_COST_ENCODING = "pi-cost-decimal-v1" as const;
const maximumValueBytes = 4 << 20;
const costFields = ["input", "output", "cacheRead", "cacheWrite", "total"] as const;

export interface DecodedPiAssistantRecord {
  readonly [field: string]: unknown;
  readonly role: "assistant";
  readonly content: unknown;
  readonly api: unknown;
  readonly provider: unknown;
  readonly model: unknown;
  readonly stopReason: unknown;
  readonly timestamp: unknown;
  readonly usage: Readonly<Record<string, unknown>> & {
    readonly input: unknown;
    readonly output: unknown;
    readonly cacheRead: unknown;
    readonly cacheWrite: unknown;
    readonly totalTokens: unknown;
    readonly cost: Readonly<Record<(typeof costFields)[number], number>>;
  };
}

export interface DecodedPiContextRecord {
  readonly [field: string]: unknown;
  readonly messages: readonly unknown[];
}

function assistantRecords(value: unknown) {
  const message = exactRecord(
    value,
    ["role", "content", "api", "provider", "model", "usage", "stopReason", "timestamp"],
    ["responseModel", "responseId", "errorMessage", "rawStopReason", "endTurn"],
    "piModel.message",
    "INVALID_CONTEXT",
  );
  const usage = exactRecord(
    message.usage,
    ["input", "output", "cacheRead", "cacheWrite", "totalTokens", "cost"],
    ["cacheWrite1h", "reasoning"],
    "piModel.message.usage",
    "INVALID_CONTEXT",
  );
  const cost = exactRecord(
    usage.cost, costFields, ["encoding"], "piModel.message.usage.cost", "INVALID_CONTEXT",
  );
  if (message.role !== "assistant") {
    throw new PiRuntimeError("INVALID_CONTEXT", "Pi model response must be an assistant message");
  }
  return { message, usage, cost };
}

function checkedCost(value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || Object.is(value, -0)) {
    throw new PiRuntimeError("INVALID_CONTEXT", "Pi cost must be a finite nonnegative number without negative zero");
  }
  return value;
}

function decodedCost(value: unknown): number {
  if (typeof value !== "string" || value.length > 32) {
    throw new PiRuntimeError("INVALID_CONTEXT", "encoded Pi cost must be a bounded decimal string");
  }
  const number = checkedCost(Number(value));
  if (number.toString() !== value) {
    throw new PiRuntimeError("INVALID_CONTEXT", "encoded Pi cost is not a canonical Number decimal");
  }
  return number;
}

/**
 * Number.toString() and Number() round-trip the exact Pi binary64 value. No
 * currency quantum, rounding, or conversion to a potentially unsafe integer is
 * introduced. The encoding tag also disambiguates legacy integer-only costs.
 */
export function encodePiAgentCoreAssistantMessage(value: unknown): NormalizedValue {
  const { message, usage, cost } = assistantRecords(value);
  if (cost.encoding !== undefined) {
    throw new PiRuntimeError("INVALID_CONTEXT", "provider Pi costs must be numeric, not already encoded");
  }
  const encodedCost = Object.fromEntries(costFields.map((field) => [field, checkedCost(cost[field]).toString()]));
  return boundedProtocolValue({
    ...message,
    usage: { ...usage, cost: { encoding: PI_AGENT_CORE_COST_ENCODING, ...encodedCost } },
  }, maximumValueBytes, "piModel.encodedMessage", "INVALID_CONTEXT");
}

/** Converts costs only; callers must still validate the remaining Pi fields. */
export function decodePiAgentCoreAssistantMessage(value: unknown): DecodedPiAssistantRecord {
  const normalized = boundedProtocolValue(value, maximumValueBytes, "piModel.message", "INVALID_CONTEXT");
  const { message, usage, cost } = assistantRecords(normalized);
  let decode: (value: unknown) => number;
  if (cost.encoding === undefined) {
    // Existing v1 zero/integer-cost settlements and ABI/state-v2 checkpoints
    // remain readable. Fractional legacy wire values are never canonical CBOR.
    decode = checkedCost;
  } else {
    if (cost.encoding !== PI_AGENT_CORE_COST_ENCODING) {
      throw new PiRuntimeError("INVALID_CONTEXT", "Pi cost encoding is unsupported");
    }
    decode = decodedCost;
  }
  const numericCost = {
    input: decode(cost.input), output: decode(cost.output), cacheRead: decode(cost.cacheRead),
    cacheWrite: decode(cost.cacheWrite), total: decode(cost.total),
  };
  return {
    ...message,
    role: "assistant",
    content: message.content,
    api: message.api,
    provider: message.provider,
    model: message.model,
    stopReason: message.stopReason,
    timestamp: message.timestamp,
    usage: {
      ...usage,
      input: usage.input,
      output: usage.output,
      cacheRead: usage.cacheRead,
      cacheWrite: usage.cacheWrite,
      totalTokens: usage.totalTokens,
      cost: numericCost,
    },
  };
}

/** Provider producers call this before the integer-only durable state boundary. */
export function encodePiAgentCoreModelSettlement(message: unknown): NormalizedValue {
  return { version: PI_AGENT_CORE_MODEL_PROTOCOL_VERSION, message: encodePiAgentCoreAssistantMessage(message) };
}

export function decodePiAgentCoreModelSettlement(value: unknown): DecodedPiAssistantRecord {
  const result = exactRecord(value, ["version", "message"], [], "piModel.settlement", "INVALID_CONTEXT");
  const { cost } = assistantRecords(result.message);
  if (
    (result.version === 1 && cost.encoding !== undefined) ||
    (result.version === PI_AGENT_CORE_MODEL_PROTOCOL_VERSION && cost.encoding !== PI_AGENT_CORE_COST_ENCODING) ||
    (result.version !== 1 && result.version !== PI_AGENT_CORE_MODEL_PROTOCOL_VERSION)
  ) {
    throw new PiRuntimeError("INVALID_CONTEXT", "Pi settlement version and cost encoding disagree");
  }
  return decodePiAgentCoreAssistantMessage(result.message);
}

export function encodePiAgentCoreModelContext(value: Context): NormalizedValue {
  return boundedProtocolValue({
    ...value,
    messages: value.messages.map((message) => message.role === "assistant"
      ? encodePiAgentCoreAssistantMessage(message)
      : message),
  }, maximumValueBytes, "piModel.context", "INVALID_CONTEXT");
}

/** Decode v2 costs without asserting that the transcript is a valid Pi Context. */
export function decodePiAgentCoreModelContext(value: unknown): DecodedPiContextRecord {
  const normalized = boundedProtocolValue(value, maximumValueBytes, "piModel.context", "INVALID_CONTEXT");
  const context = exactRecord(normalized, ["messages"], ["systemPrompt", "tools"], "piModel.context", "INVALID_CONTEXT");
  if (!Array.isArray(context.messages)) {
    throw new PiRuntimeError("INVALID_CONTEXT", "Pi model context messages must be an array");
  }
  return {
    ...context,
    messages: context.messages.map((message) =>
      message !== null && typeof message === "object" && message.role === "assistant"
        ? decodePiAgentCoreAssistantMessage(message)
        : message),
  };
}

/** Adapt raw Pi v1 responses only for an exact pending Pi model request. */
export function normalizePiAgentCoreSettlement(value: unknown, request: EffectIntent | null): unknown {
  const payload = request?.payload;
  if (
    request?.service !== "model" || request.operation !== "complete" ||
    payload === null || typeof payload !== "object" || Array.isArray(payload) || payload instanceof Uint8Array ||
    payload.protocol !== "pi-agent-core" || (payload.version !== 1 && payload.version !== PI_AGENT_CORE_MODEL_PROTOCOL_VERSION)
  ) return value;
  // Preserve the existing validation/terminal-error path for canonical legacy
  // inputs. Inspect only own data fields while locating an actual raw fraction.
  let candidate: unknown = value;
  for (const field of ["outcome", "result", "message", "usage", "cost"]) {
    if (candidate === null || typeof candidate !== "object") return value;
    const descriptor = Object.getOwnPropertyDescriptor(candidate, field);
    if (descriptor === undefined || !("value" in descriptor)) return value;
    candidate = descriptor.value;
  }
  if (candidate === null || typeof candidate !== "object" || !costFields.some((field) => {
    const descriptor = Object.getOwnPropertyDescriptor(candidate, field);
    return descriptor !== undefined && "value" in descriptor && typeof descriptor.value === "number" && !Number.isSafeInteger(descriptor.value);
  })) return value;
  const settlement = exactRecord(value, ["requestDigest", "outcome"], [], "piModel.engineSettlement", "INVALID_CONTEXT");
  const outcome = exactRecord(settlement.outcome, ["kind"], ["result", "code", "message", "retryable", "reason"], "piModel.outcome", "INVALID_CONTEXT");
  if (outcome.kind !== "success") return value;
  const result = exactRecord(outcome.result, ["version", "message"], [], "piModel.settlement", "INVALID_CONTEXT");
  const { cost } = assistantRecords(result.message);
  if (result.version !== 1 || costFields.every((field) => Number.isSafeInteger(cost[field]))) return value;
  return {
    ...settlement,
    outcome: { ...outcome, result: encodePiAgentCoreModelSettlement(result.message) },
  };
}
