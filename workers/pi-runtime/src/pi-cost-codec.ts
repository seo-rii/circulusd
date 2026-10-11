import type { Context } from "@earendil-works/pi-ai";
import type { EffectIntent, NormalizedValue } from "@circulusd/protocol-types";

import { PiRuntimeError } from "./errors.ts";
import { decodePiJson, encodePiJson, validatePiJson } from "./pi-json-codec.ts";
import { boundedProtocolValue, exactRecord } from "./validation.ts";

export const PI_AGENT_CORE_MODEL_PROTOCOL_VERSION = 2 as const;
export const PI_AGENT_CORE_COST_ENCODING = "pi-cost-decimal-v1" as const;
const maximumValueBytes = 4 << 20;
const costFields = ["input", "output", "cacheRead", "cacheWrite", "total"] as const;

// Keep malformed tool JSON distinguishable from the assistant/cost envelope so
// the adapter preserves its existing PI_TOOL_CALL_INVALID terminal error.
export class PiToolArgumentsEncodingError extends PiRuntimeError {
  constructor(cause: unknown) {
    super("INVALID_CONTEXT", "Pi tool call arguments are not valid encoded JSON", { cause });
    this.name = "PiToolArgumentsEncodingError";
  }
}

function assistantContent(content: unknown, encode: boolean): unknown {
  let source: unknown;
  try {
    source = encode ? validatePiJson(content) : content;
  } catch (error) {
    throw new PiToolArgumentsEncodingError(error);
  }
  if (!Array.isArray(source)) return source;
  return source.map((block: unknown) => {
    if (
      block === null || typeof block !== "object" || Array.isArray(block) ||
      block instanceof Uint8Array || !("type" in block) || block.type !== "toolCall" ||
      !("arguments" in block)
    ) return block;
    try {
      return {
        ...block,
        arguments: encode ? encodePiJson(block.arguments) : decodePiJson(block.arguments as NormalizedValue),
      };
    } catch (error) {
      throw new PiToolArgumentsEncodingError(error);
    }
  });
}

function contextTools(tools: unknown, encode: boolean): unknown {
  const source = encode ? validatePiJson(tools) : tools;
  if (!Array.isArray(source)) return source;
  return source.map((tool: unknown) => {
    if (
      tool === null || typeof tool !== "object" || Array.isArray(tool) ||
      tool instanceof Uint8Array || !("parameters" in tool)
    ) return tool;
    return {
      ...tool,
      parameters: encode ? encodePiJson(tool.parameters) : decodePiJson(tool.parameters as NormalizedValue),
    };
  });
}

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
    content: assistantContent(message.content, true),
    usage: { ...usage, cost: { encoding: PI_AGENT_CORE_COST_ENCODING, ...encodedCost } },
  }, maximumValueBytes, "piModel.encodedMessage", "INVALID_CONTEXT");
}

/** Converts costs and tool JSON; callers must still validate the remaining Pi fields. */
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
    content: assistantContent(message.content, false),
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
    ...(value.tools === undefined ? {} : { tools: contextTools(value.tools, true) }),
  }, maximumValueBytes, "piModel.context", "INVALID_CONTEXT");
}

/** Restore costs and tool JSON without asserting that the transcript is a valid Pi Context. */
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
    ...(context.tools === undefined ? {} : { tools: contextTools(context.tools, false) }),
  };
}

function ownDataField(value: unknown, field: string): unknown {
  if (value === null || typeof value !== "object") return undefined;
  const descriptor = Object.getOwnPropertyDescriptor(value, field);
  return descriptor !== undefined && "value" in descriptor ? descriptor.value : undefined;
}

function hasRawToolArgumentNumber(message: unknown): boolean {
  // Inspect a bounded clone, never provider-supplied getters or array methods.
  // Already encoded wrappers are left to the normal durable validation path.
  let content: unknown;
  try {
    content = validatePiJson(ownDataField(message, "content"));
  } catch {
    return false;
  }
  if (!Array.isArray(content)) return false;
  for (const block of content) {
    if (ownDataField(block, "type") !== "toolCall") continue;
    const pending = [ownDataField(block, "arguments")];
    while (pending.length > 0) {
      const value = pending.pop();
      if (typeof value === "number" && !Number.isSafeInteger(value)) return true;
      if (value !== null && typeof value === "object") {
        for (const entry of Object.values(value)) pending.push(entry);
      }
    }
  }
  return false;
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
  const message = ownDataField(ownDataField(ownDataField(value, "outcome"), "result"), "message");
  const cost = ownDataField(ownDataField(message, "usage"), "cost");
  const rawCost = costFields.some((field) => {
    const number = ownDataField(cost, field);
    return typeof number === "number" && !Number.isSafeInteger(number);
  });
  if (!rawCost && !hasRawToolArgumentNumber(message)) return value;
  const settlement = exactRecord(value, ["requestDigest", "outcome"], [], "piModel.engineSettlement", "INVALID_CONTEXT");
  const outcome = exactRecord(settlement.outcome, ["kind"], ["result", "code", "message", "retryable", "reason"], "piModel.outcome", "INVALID_CONTEXT");
  if (outcome.kind !== "success") return value;
  const result = exactRecord(outcome.result, ["version", "message"], [], "piModel.settlement", "INVALID_CONTEXT");
  if (result.version !== 1) return value;
  return {
    ...settlement,
    outcome: { ...outcome, result: encodePiAgentCoreModelSettlement(result.message) },
  };
}
