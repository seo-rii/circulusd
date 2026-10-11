import { encodeCanonicalCbor, normalizeProtocolValue, parseDigest, parseEngineStepResult } from "@circulusd/protocol-types";
import { sessionError } from "./errors.ts";
import type { SessionBrokerAuthority, SessionBrokerCommand, SessionBrokerPolicy, SessionBrokerRequest, SessionBrokerSnapshot } from "./broker-types.ts";
import type { SessionAggregateState } from "./types.ts";

const encoder = new TextEncoder();
export function brokerExact(value: unknown, fields: readonly string[], field: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value) ||
    (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) {
    sessionError("INVALID_ARGUMENT", `${field} must be a plain object`);
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.length || fields.some((key) => !Object.hasOwn(value, key)) ||
    keys.some((key) => typeof key !== "string" || !fields.includes(key) ||
      !Object.getOwnPropertyDescriptor(value, key)?.enumerable ||
      !("value" in Object.getOwnPropertyDescriptor(value, key)!))) {
    sessionError("INVALID_ARGUMENT", `${field} fields do not match the broker schema`);
  }
  return value as Record<string, unknown>;
}
export function brokerInteger(value: unknown, field: string, minimum = 0): asserts value is number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum) {
    sessionError("INVALID_ARGUMENT", `${field} must be a bounded integral value`);
  }
}
export function brokerIdentifier(value: unknown, field: string): asserts value is string {
  if (typeof value !== "string" || value.length === 0 || !value.isWellFormed() ||
    value !== value.normalize("NFC") || encoder.encode(value).byteLength > 256 || /\p{Cc}/u.test(value)) {
    sessionError("INVALID_ARGUMENT", `${field} must be a canonical bounded identifier`);
  }
}
export function brokerOpaque(value: unknown, field: string): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array) || value.byteLength !== 32) {
    sessionError("INVALID_ARGUMENT", `${field} must contain exactly 32 opaque bytes`);
  }
}
export function brokerFence(value: unknown): void {
  const fence = brokerExact(value, ["turnLeaseGeneration", "placementGeneration", "sandboxGeneration", "authorizationGeneration"], "fence");
  for (const [key, generation] of Object.entries(fence)) brokerInteger(generation, key);
}
function budget(value: unknown): void {
  const fields = brokerExact(value, ["maximumEvents", "maximumEphemeralBytes", "maximumWallClockMs"], "budget");
  for (const [key, maximum] of Object.entries(fields)) brokerInteger(maximum, key, 1);
  if (fields.maximumEvents !== 1) sessionError("INVALID_ARGUMENT", "a broker grant authorizes exactly one durable engine boundary");
}
export function parseSessionBrokerPolicy(value: unknown): SessionBrokerPolicy {
  const fields = brokerExact(value, ["engineStepLimits", "preparationTTLms"], "broker policy");
  budget(fields.engineStepLimits);
  brokerInteger(fields.preparationTTLms, "preparationTTLms", 1);
  return structuredClone(value) as SessionBrokerPolicy;
}
export function parseSessionBrokerAuthority(value: unknown): SessionBrokerAuthority {
  const fields = brokerExact(value, ["tenantId", "workspaceId", "sessionId", "actorSubjectId", "expectedAuthorizationGeneration"], "broker authority");
  for (const key of ["tenantId", "workspaceId", "sessionId", "actorSubjectId"]) brokerIdentifier(fields[key], key);
  brokerInteger(fields.expectedAuthorizationGeneration, "expectedAuthorizationGeneration");
  return structuredClone(value) as SessionBrokerAuthority;
}
export function assertSessionBrokerAuthority(state: SessionAggregateState, value: unknown): void {
  const authority = parseSessionBrokerAuthority(value);
  if (authority.tenantId !== state.tenantId || authority.workspaceId !== state.workspaceId ||
    authority.sessionId !== state.sessionId || authority.actorSubjectId !== state.userId) {
    sessionError("PERMISSION_DENIED", "broker authority belongs to another Session or principal");
  }
  if (authority.expectedAuthorizationGeneration !== state.authorizationGeneration) {
    sessionError("STALE_GENERATION", "broker authority is stale");
  }
}
function effectKey(value: unknown): void {
  const key = brokerExact(value, ["turnId", "effectId", "invocationId", "requestDigest"], "effect key");
  for (const field of ["turnId", "effectId", "invocationId"]) brokerIdentifier(key[field], field);
  parseDigest(key.requestDigest);
}
function snapshot(value: unknown): asserts value is SessionBrokerSnapshot {
  const fields = brokerExact(value, ["turnId", "eventSequence", "checkpointDigest", "fence", "activeEffect"], "snapshot");
  brokerIdentifier(fields.turnId, "snapshot.turnId");
  brokerInteger(fields.eventSequence, "snapshot.eventSequence");
  parseDigest(fields.checkpointDigest);
  brokerFence(fields.fence);
  if (fields.activeEffect !== null) {
    const effect = brokerExact(fields.activeEffect, ["effectId", "invocationId", "requestDigest", "phase", "dispatchAttempt"], "snapshot.activeEffect");
    brokerIdentifier(effect.effectId, "effectId");
    brokerIdentifier(effect.invocationId, "invocationId");
    parseDigest(effect.requestDigest);
    brokerInteger(effect.dispatchAttempt, "dispatchAttempt");
    if (!["prepared", "dispatched", "externally_committed", "settled", "blocked"].includes(effect.phase as string)) {
      sessionError("INVALID_ARGUMENT", "snapshot effect phase is invalid");
    }
  }
}
export function brokerPublicError(value: unknown): void {
  const error = brokerExact(value, ["code", "reason", "message", "retryable", "retryAfterMs", "metadata", "requestId"], "public error");
  brokerInteger(error.code, "error.code");
  brokerInteger(error.retryAfterMs, "error.retryAfterMs");
  if (typeof error.reason !== "string" || typeof error.message !== "string" || typeof error.retryable !== "boolean" ||
    error.metadata === null || typeof error.metadata !== "object" || Array.isArray(error.metadata) ||
    Object.values(error.metadata).some((entry) => typeof entry !== "string")) sessionError("INVALID_ARGUMENT", "public error fields are invalid");
  if (error.requestId !== null) brokerIdentifier(error.requestId, "error.requestId");
  encodeCanonicalCbor(normalizeProtocolValue(value), { maxBytes: 1_048_576 });
}

const base = ["snapshot", "operationKey"];
const effectBase = [...base, "key", "operationDigest"];
const operationFields: Readonly<Record<string, readonly string[]>> = {
  "read-turn": [],
  "lookup-operation": ["kind", "operationKey", "operationDigest"],
  "acquire-step": [...base, "nowUnixMs", "budget"],
  "commit-step": [...base, "requestDigest", "permitOpaque", "nowUnixMs", "step"],
  dispatch: [...effectBase, "preparationOpaque", "providerRequestId", "providerRouteDigest", "nowUnixMs", "deadlineUnixMs"],
  "claim-start": ["snapshot", "key", "dispatchOpaque", "commandDigest", "nowUnixMs"],
  confirm: [...effectBase, "dispatchAttempt", "providerRequestId", "providerRouteDigest", "externalCommitId", "resultRef"],
  settle: [...effectBase, "dispatchAttempt", "externalCommitId", "resultRef", "error", "settlement"],
  block: [...effectBase, "reason"],
  "prepare-retry": [...effectBase, "nowUnixMs", "deadlineUnixMs", "userConfirmed"],
  "settle-recovery": [...effectBase, "kind", "error"],
};

export function parseSessionBrokerRequest(value: unknown): SessionBrokerRequest {
  const request = brokerExact(value, ["operation", "body"], "broker request");
  if (typeof request.operation !== "string" || !Object.hasOwn(operationFields, request.operation)) {
    sessionError("INVALID_ARGUMENT", "unknown broker operation");
  }
  const body = brokerExact(request.body, operationFields[request.operation]!, `${request.operation} body`);
  // Preserve canonical key/number constraints before any archive lookup.
  const normalized = normalizeProtocolValue(value);
  const encoded = encodeCanonicalCbor(normalized, { maxBytes: 8 * 1_048_576 });
  if (!encoded.byteLength) sessionError("INVALID_ARGUMENT", "empty broker request");
  if ("snapshot" in body) snapshot(body.snapshot);
  if ("key" in body) effectKey(body.key);
  for (const key of ["operationKey", "externalCommitId"]) if (key in body) brokerIdentifier(body[key], key);
  for (const key of ["providerRequestId", "resultRef"]) if (key in body && body[key] !== null) brokerIdentifier(body[key], key);
  for (const key of ["operationDigest", "requestDigest", "providerRouteDigest", "commandDigest"]) if (key in body) parseDigest(body[key]);
  for (const key of ["nowUnixMs", "deadlineUnixMs", "dispatchAttempt"]) if (key in body) brokerInteger(body[key], key, key === "nowUnixMs" ? 0 : 1);
  for (const key of ["permitOpaque", "preparationOpaque", "dispatchOpaque"]) if (key in body) brokerOpaque(body[key], key);
  if ("budget" in body) budget(body.budget);
  if ("step" in body) parseEngineStepResult(body.step);
  if ("error" in body && body.error !== null) brokerPublicError(body.error);
  if ("reason" in body) brokerPublicError(body.reason);
  if ("userConfirmed" in body && typeof body.userConfirmed !== "boolean") sessionError("INVALID_ARGUMENT", "userConfirmed must be boolean");
  if (request.operation === "lookup-operation" && !["dispatch", "confirmation", "settlement", "recovery_settlement", "block"].includes(body.kind as string)) {
    sessionError("INVALID_ARGUMENT", "unknown broker receipt kind");
  }
  if (request.operation === "settle-recovery" && !["failed", "interrupted_unknown"].includes(body.kind as string)) {
    sessionError("INVALID_ARGUMENT", "unknown recovery settlement kind");
  }
  return structuredClone(value) as SessionBrokerRequest;
}

// Shared by archive planning and apply: a malformed internal command must not
// reach the index before the same strict validator that will execute it.
export function validateSessionBrokerCommandShape(command: SessionBrokerCommand): void {
  brokerExact(command, ["kind", "commandId", "expectedEventSequence", "operationKey", "operationKeyDigest", "authority", "host", "operation", "body"], "broker command");
  parseSessionBrokerAuthority(command.authority);
  parseSessionBrokerRequest({ operation: command.operation, body: command.body });
  brokerIdentifier(command.commandId, "commandId"); brokerIdentifier(command.operationKey, "operationKey");
  brokerInteger(command.expectedEventSequence, "expectedEventSequence"); parseDigest(command.operationKeyDigest);
  brokerExact(command.host, ["policy", "opaque", "secondaryOpaque", "effectId", "invocationId"], "broker host context");
  parseSessionBrokerPolicy(command.host.policy);
  brokerOpaque(command.host.opaque, "host opaque"); brokerOpaque(command.host.secondaryOpaque, "host secondaryOpaque");
  brokerIdentifier(command.host.effectId, "host effectId"); brokerIdentifier(command.host.invocationId, "host invocationId");
}
