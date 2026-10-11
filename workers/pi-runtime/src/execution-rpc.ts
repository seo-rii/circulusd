import {
  assertUnicodeScalarString, isDigest, parseAgentCheckpoint, type Digest,
} from "@circulusd/protocol-types";
import type { AgentEvent } from "../../session-host/src/index.ts";

import { PiRuntimeError } from "./errors.ts";
import { snapshotPiGenesisScope, type PiGenesisScope } from "./genesis.ts";
import { boundedIdentifier, exactRecord } from "./validation.ts";

export const PI_EXECUTION_PROTOCOL = "circulusd.pi.execution";
export const PI_EXECUTION_MAX_REQUEST_BYTES = 6 * 1_048_576;
export const PI_EXECUTION_MAX_REPLY_BYTES = 2 * 1_048_576;
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const byteLengthGetter = Object.getOwnPropertyDescriptor(typedArrayPrototype, "byteLength")!.get!;
const byteOffsetGetter = Object.getOwnPropertyDescriptor(typedArrayPrototype, "byteOffset")!.get!;
const bufferGetter = Object.getOwnPropertyDescriptor(typedArrayPrototype, "buffer")!.get!;
export interface PiExecutionBinding {
  readonly scope: PiGenesisScope;
  readonly runtimeRevisionDigest: Digest;
  readonly artifactDigest: Digest;
}
interface Header {
  readonly protocol: typeof PI_EXECUTION_PROTOCOL;
  readonly version: 1;
  readonly binding: PiExecutionBinding;
  readonly turnId: string;
  readonly executionId: string;
  readonly sequence: number;
}
export type PiExecutionOperation = "start" | "resume" | "pull" | "close" | "abort";
export type PiExecutionRequest = Header & (
  | { readonly operation: "start"; readonly authority: Uint8Array; readonly checkpoint: unknown }
  | { readonly operation: "resume"; readonly authority: Uint8Array; readonly checkpoint: unknown; readonly settlement: unknown }
  | { readonly operation: "pull" | "close" | "abort" }
);
export type PiExecutionReply = Header & { readonly operation: PiExecutionOperation } & (
  | { readonly status: "opened" | "done" | "closed" | "aborted" }
  | { readonly status: "event"; readonly event: AgentEvent }
);
export interface PiExecutionTransport {
  exchange(request: PiExecutionRequest): Promise<unknown>;
}
export function invalidExecution(): never {
  throw new PiRuntimeError("INVALID_CONTEXT", "Pi execution RPC is invalid or unavailable");
}

// RPC uses structured-clone primitives. Unlike the durable integer-only CBOR
// codec, raw Pi settlements may contain finite fractional numbers. Inspect
// descriptors before allocating a copy: never invoke accessors, serialize
// capabilities, or trust structuredClone to enforce a byte budget.
export function snapshotExecutionValue(value: unknown, maximumBytes: number): unknown {
  let bytes = 0, items = 0;
  const seen = new WeakSet<object>(), encoder = new TextEncoder();
  const charge = (size: number) => { bytes += size; if (bytes > maximumBytes) invalidExecution(); };
  const string = (text: string) => {
    if (text.length > maximumBytes - bytes) invalidExecution();
    assertUnicodeScalarString(text, "execution RPC string");
    charge(16 + encoder.encode(text).byteLength);
    return text;
  };
  const copy = (input: unknown, depth: number): unknown => {
    if (depth > 64 || ++items > 1_000_000) invalidExecution();
    charge(16);
    if (input === null || typeof input === "boolean") return input;
    if (typeof input === "number") {
      if (!Number.isFinite(input) || Object.is(input, -0)) invalidExecution();
      return input;
    }
    if (typeof input === "string") return string(input);
    if (input instanceof Uint8Array) {
      if (Object.getPrototypeOf(input) !== Uint8Array.prototype) invalidExecution();
      const buffer = bufferGetter.call(input) as ArrayBuffer;
      const byteLength = byteLengthGetter.call(input) as number;
      const byteOffset = byteOffsetGetter.call(input) as number;
      if (!(buffer instanceof ArrayBuffer) || Object.getPrototypeOf(buffer) !== ArrayBuffer.prototype) invalidExecution();
      charge(byteLength);
      return new Uint8Array(new Uint8Array(buffer, byteOffset, byteLength));
    }
    if (typeof input !== "object" || input === null || seen.has(input)) invalidExecution();
    seen.add(input);
    const keys = Reflect.ownKeys(input);
    if (keys.length > 1_000_000 - items) invalidExecution();
    if (Array.isArray(input)) {
      if (Object.getPrototypeOf(input) !== Array.prototype || keys.length !== input.length + 1) invalidExecution();
      const result: unknown[] = [];
      for (let index = 0; index < input.length; index++) {
        const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
        if (!descriptor?.enumerable || !("value" in descriptor)) invalidExecution();
        result.push(copy(descriptor.value, depth + 1));
      }
      return result;
    }
    const prototype = Object.getPrototypeOf(input);
    if (prototype !== Object.prototype && prototype !== null) invalidExecution();
    const result: Record<string, unknown> = {};
    for (const key of keys) {
      if (typeof key !== "string") invalidExecution();
      const descriptor = Object.getOwnPropertyDescriptor(input, key);
      if (!descriptor?.enumerable || !("value" in descriptor)) invalidExecution();
      string(key);
      Object.defineProperty(result, key, { enumerable: true, writable: true, configurable: true,
        value: copy(descriptor.value, depth + 1) });
    }
    return result;
  };
  try {
    if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1) invalidExecution();
    return copy(value, 0);
  } catch { return invalidExecution(); }
}

export function snapshotExecutionBinding(value: unknown): PiExecutionBinding {
  try {
    const binding = exactRecord(value, ["scope", "runtimeRevisionDigest", "artifactDigest"], [], "execution.binding", "INVALID_CONTEXT");
    if (!isDigest(binding.runtimeRevisionDigest) || !isDigest(binding.artifactDigest)) invalidExecution();
    return Object.freeze({ scope: Object.freeze(snapshotPiGenesisScope(binding.scope as PiGenesisScope)),
      runtimeRevisionDigest: binding.runtimeRevisionDigest, artifactDigest: binding.artifactDigest });
  } catch { return invalidExecution(); }
}
export function sameExecutionBinding(left: PiExecutionBinding, right: PiExecutionBinding): boolean {
  return left.scope.tenantId === right.scope.tenantId && left.scope.workspaceId === right.scope.workspaceId &&
    left.scope.sessionId === right.scope.sessionId && left.scope.actorSubjectId === right.scope.actorSubjectId &&
    left.runtimeRevisionDigest === right.runtimeRevisionDigest &&
    left.artifactDigest === right.artifactDigest;
}
const headerFields = ["protocol", "version", "binding", "turnId", "executionId", "sequence", "operation"];
function header(value: Record<string, unknown>): Header & { operation: PiExecutionOperation } {
  if (value.protocol !== PI_EXECUTION_PROTOCOL || value.version !== 1 ||
      !["start", "resume", "pull", "close", "abort"].includes(value.operation as string) ||
      typeof value.sequence !== "number" || !Number.isSafeInteger(value.sequence) || value.sequence < 0 ||
      (value.operation === "pull" ? value.sequence < 1 : value.sequence !== 0)) invalidExecution();
  return { protocol: PI_EXECUTION_PROTOCOL, version: 1, binding: snapshotExecutionBinding(value.binding),
    turnId: boundedIdentifier(value.turnId, "execution.turnId", "INVALID_CONTEXT"),
    executionId: boundedIdentifier(value.executionId, "execution.executionId", "INVALID_CONTEXT"),
    sequence: value.sequence, operation: value.operation as PiExecutionOperation };
}
export function snapshotExecutionRequest(input: unknown): PiExecutionRequest {
  try {
    const value = snapshotExecutionValue(input, PI_EXECUTION_MAX_REQUEST_BYTES) as Record<string, unknown>;
    const operation = value?.operation;
    const fields = operation === "start" ? ["authority", "checkpoint"] : operation === "resume" ? ["authority", "checkpoint", "settlement"] : [];
    exactRecord(value, [...headerFields, ...fields], [], "execution.request", "INVALID_CONTEXT");
    const base = header(value);
    if (base.operation !== "start" && base.operation !== "resume") return base as PiExecutionRequest;
    const authority = value.authority;
    if (!(authority instanceof Uint8Array) || authority.byteLength < 1 || authority.byteLength > 4096) invalidExecution();
    const checkpoint = parseAgentCheckpoint(value.checkpoint);
    if ((checkpoint.kind !== "engine" && checkpoint.kind !== "genesis") || checkpoint.engineKind !== "low-level" || checkpoint.adapterAbiVersion !== 2 ||
        checkpoint.checkpointSchemaVersion !== 2 || checkpoint.payloadEncoding !== "canonical-cbor" ||
        checkpoint.sessionId !== base.binding.scope.sessionId || checkpoint.turnId !== base.turnId ||
        checkpoint.runtimeRevisionDigest !== base.binding.runtimeRevisionDigest) invalidExecution();
    return base.operation === "start" ? { ...base, operation: "start", authority, checkpoint } :
      { ...base, operation: "resume", authority, checkpoint, settlement: value.settlement };
  } catch { return invalidExecution(); }
}
export function snapshotExecutionReply(input: unknown): PiExecutionReply {
  try {
    const value = snapshotExecutionValue(input, PI_EXECUTION_MAX_REPLY_BYTES) as Record<string, unknown>;
    exactRecord(value, [...headerFields, "status", ...(value?.status === "event" ? ["event"] : [])], [], "execution.reply", "INVALID_CONTEXT");
    const base = header(value);
    const allowed = base.operation === "start" || base.operation === "resume" ? ["opened"] :
      base.operation === "pull" ? ["event", "done"] : base.operation === "close" ? ["closed"] : ["aborted"];
    if (!allowed.includes(value.status as string)) invalidExecution();
    if (value.status !== "event") return { ...base, status: value.status as "opened" | "done" | "closed" | "aborted" };
    const event = value.event as Record<string, unknown>;
    const fields = event?.type === "assistant_delta" ? ["type", "delta"] : event?.type === "checkpoint" ? ["type", "checkpoint"] :
      event?.type === "model_request" || event?.type === "tool_request" ? ["type", "checkpoint", "request"] :
        event?.type === "turn_complete" ? ["type", "checkpoint", "result"] : event?.type === "turn_error" ? ["type", "checkpoint", "error"] : null;
    if (fields === null) invalidExecution();
    exactRecord(event, fields, [], "execution.event", "INVALID_CONTEXT");
    if (event.type !== "assistant_delta") {
      const checkpoint = parseAgentCheckpoint(event.checkpoint);
      if (checkpoint.kind !== "engine" || checkpoint.engineKind !== "low-level" || checkpoint.adapterAbiVersion !== 2 ||
          checkpoint.checkpointSchemaVersion !== 2 || checkpoint.payloadEncoding !== "canonical-cbor" ||
          checkpoint.sessionId !== base.binding.scope.sessionId || checkpoint.turnId !== base.turnId ||
          checkpoint.runtimeRevisionDigest !== base.binding.runtimeRevisionDigest) invalidExecution();
      event.checkpoint = checkpoint;
    }
    return { ...base, status: "event", event: event as AgentEvent };
  } catch { return invalidExecution(); }
}
