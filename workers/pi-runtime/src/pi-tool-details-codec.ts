import type { EffectIntent, NormalizedValue } from "@circulusd/protocol-types";

import { PiRuntimeError } from "./errors.ts";
import { decodePiJson, encodePiJson, validatePiJson } from "./pi-json-codec.ts";
import { boundedProtocolValue, exactRecord } from "./validation.ts";

export const PI_AGENT_CORE_TOOL_DETAILS_ENCODING = "pi-tool-details-json-v1" as const;
const maximumValueBytes = 4 << 20;

function ownDataField(value: unknown, field: string): unknown {
  if (value === null || typeof value !== "object") return undefined;
  const descriptor = Object.getOwnPropertyDescriptor(value, field);
  return descriptor !== undefined && "value" in descriptor ? descriptor.value : undefined;
}

function hasRawDetailsNumber(details: unknown): boolean {
  let source: unknown;
  try { source = validatePiJson(details); } catch { return false; }
  const pending = [source];
  while (pending.length > 0) {
    const value = pending.pop();
    if (typeof value === "number" && !Number.isSafeInteger(value)) return true;
    if (value !== null && typeof value === "object") {
      for (const entry of Object.values(value)) pending.push(entry);
    }
  }
  return false;
}

function detailsFields(message: Record<string, unknown>, encode: boolean): Record<string, unknown> {
  if (message.detailsEncoding !== undefined) {
    if (message.detailsEncoding !== PI_AGENT_CORE_TOOL_DETAILS_ENCODING || message.details === undefined) {
      throw new PiRuntimeError("INVALID_CONTEXT", "Pi tool details encoding is unsupported or missing details");
    }
    return { ...message, details: encode ? encodePiJson(message.details) : decodePiJson(message.details as NormalizedValue) };
  }
  // Legacy metadata is opaque protocol data, including wrapper-like objects.
  // Only raw finite JSON numbers require a new, explicitly tagged representation.
  if (encode && message.details !== undefined && hasRawDetailsNumber(message.details)) {
    return { ...message, detailsEncoding: PI_AGENT_CORE_TOOL_DETAILS_ENCODING, details: encodePiJson(message.details) };
  }
  return message;
}

/** Provider producers encode optional finite JSON metadata before durable storage. */
export function encodePiAgentCoreToolResult(value: unknown): NormalizedValue {
  const result = exactRecord(value,
    ["version", "toolCallId", "toolName", "content", "isError", "timestamp"],
    ["details"], "piTool.result", "INVALID_CONTEXT");
  if (result.version !== 1) throw new PiRuntimeError("INVALID_CONTEXT", "Pi tool result version is unsupported");
  return boundedProtocolValue({
    ...result,
    ...(result.details === undefined ? {} : {
      detailsEncoding: PI_AGENT_CORE_TOOL_DETAILS_ENCODING,
      details: encodePiJson(result.details),
    }),
  }, maximumValueBytes, "piTool.encodedResult", "INVALID_CONTEXT");
}

/** Retain the tag in Pi messages so captured contexts can encode details again. */
export function decodePiAgentCoreToolResultMessage(value: unknown): unknown {
  const message = exactRecord(value,
    ["role", "toolCallId", "toolName", "content", "isError", "timestamp"],
    ["details", "detailsEncoding"], "piTool.message", "INVALID_CONTEXT");
  return detailsFields(message, false);
}

export function encodePiAgentCoreToolResultMessage(value: unknown): unknown {
  const message = exactRecord(value,
    ["role", "toolCallId", "toolName", "content", "isError", "timestamp"],
    ["details", "detailsEncoding"], "piTool.message", "INVALID_CONTEXT");
  return detailsFields(message, true);
}

/** Adapt raw details only for the exact pending Pi external tool call. */
export function normalizePiAgentCoreToolSettlement(value: unknown, request: EffectIntent | null): unknown {
  const payload = request?.payload;
  const call = ownDataField(payload, "toolCall");
  const outcome = ownDataField(value, "outcome");
  const result = ownDataField(outcome, "result");
  if (
    request?.service !== "external-tool" || request.operation !== "call" ||
    ownDataField(payload, "protocol") !== "pi-agent-core" || ownDataField(payload, "version") !== 1 ||
    ownDataField(value, "requestDigest") !== request.requestDigest || ownDataField(outcome, "kind") !== "success" ||
    ownDataField(result, "version") !== 1 || ownDataField(result, "detailsEncoding") !== undefined ||
    ownDataField(call, "type") !== "toolCall" ||
    typeof ownDataField(call, "id") !== "string" || typeof ownDataField(call, "name") !== "string" ||
    ownDataField(result, "toolCallId") !== ownDataField(call, "id") ||
    ownDataField(result, "toolName") !== ownDataField(call, "name") ||
    !hasRawDetailsNumber(ownDataField(result, "details"))
  ) return value;
  const settlement = exactRecord(value, ["requestDigest", "outcome"], [], "piTool.engineSettlement", "INVALID_CONTEXT");
  const success = exactRecord(settlement.outcome, ["kind", "result"], [], "piTool.outcome", "INVALID_CONTEXT");
  return { ...settlement, outcome: { ...success, result: encodePiAgentCoreToolResult(success.result) } };
}
