import {
  digestStructuredValue, encodeCanonicalCbor, parseDigest, parseNormalizedValue,
  type Digest, type NormalizedValue,
} from "@circulusd/protocol-types";
import { sessionError } from "../session/errors.ts";
import type { SessionAggregateState, TurnAdmissionReceipt } from "../session/types.ts";

export interface SessionAdmissionPlanningRequest {
  tenantId: string;
  actorSubjectId: string;
  sessionId: string;
  expectedAuthorizationGeneration: number;
  proposedTurnId: string;
  input: NormalizedValue;
  inputDigest: Digest;
  idempotencyKeyDigest: Digest;
  requestDigest: Digest;
}

function exact(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value) ||
    Object.keys(value).length !== fields.length || fields.some((field) => !Object.hasOwn(value, field))) {
    sessionError("INVALID_ARGUMENT", "invalid admission planning shape");
  }
  return value as Record<string, unknown>;
}

export const ADMISSION_PLANNING_FIELDS = Object.freeze([
  "tenantId", "actorSubjectId", "sessionId", "expectedAuthorizationGeneration", "proposedTurnId",
  "input", "inputDigest", "idempotencyKeyDigest", "requestDigest",
] as const);

export function parseSessionAdmissionPlanningRequest(value: unknown): SessionAdmissionPlanningRequest {
  const record = exact(value, ADMISSION_PLANNING_FIELDS);
  for (const [field, prefix] of [["tenantId", "tenant"], ["actorSubjectId", "subject"],
    ["sessionId", "sess"], ["proposedTurnId", "turn"]]) {
    if (typeof record[field!] !== "string" || !new RegExp(`^${prefix}_[A-Z2-7]{25}[AEIMQUY4]$`).test(record[field!] as string)) {
      sessionError("INVALID_ARGUMENT", "invalid admission scope");
    }
  }
  const generation = record.expectedAuthorizationGeneration;
  if (typeof generation !== "number" || !Number.isSafeInteger(generation) || generation < 1) {
    sessionError("INVALID_ARGUMENT", "invalid admission authorization generation");
  }
  const input = parseNormalizedValue(record.input);
  const messages = exact(input, ["messages"]).messages;
  if (!Array.isArray(messages) || messages.length < 1 || messages.length > 1024) {
    sessionError("INVALID_ARGUMENT", "invalid admission messages");
  }
  for (const candidate of messages) {
    const message = exact(candidate, ["role", "content"]);
    if (message.role !== "user" || typeof message.content !== "string" || message.content.length === 0) {
      sessionError("INVALID_ARGUMENT", "invalid admission message");
    }
  }
  encodeCanonicalCbor(input, { maxBytes: 1_048_576, maxDepth: 64, maxItems: 100_000 });
  return {
    tenantId: record.tenantId as string, actorSubjectId: record.actorSubjectId as string,
    sessionId: record.sessionId as string, expectedAuthorizationGeneration: generation,
    proposedTurnId: record.proposedTurnId as string, input,
    inputDigest: parseDigest(record.inputDigest), idempotencyKeyDigest: parseDigest(record.idempotencyKeyDigest),
    requestDigest: parseDigest(record.requestDigest),
  };
}

export function sessionAdmissionHostPolicy(value: unknown): number | null {
  if (value === undefined) return null;
  try {
    const record = exact(typeof value === "string" ? JSON.parse(value) : value, ["turnLeaseTTLms"]);
    const ttl = record.turnLeaseTTLms;
    if (typeof ttl !== "number" || !Number.isSafeInteger(ttl) || ttl < 1 || ttl > 300_000) throw new Error("invalid TTL");
    return ttl;
  } catch { sessionError("FAILED_PRECONDITION", "trusted Session admission policy is invalid"); }
}

// Run this before any receipt index or blob access. A receipt cannot extend a
// stale principal's authority to the current Session generation.
export function assertSessionAdmissionPlanningAuthority(state: SessionAggregateState, request: SessionAdmissionPlanningRequest): void {
  if (request.tenantId !== state.tenantId || request.actorSubjectId !== state.userId || request.sessionId !== state.sessionId) {
    sessionError("PERMISSION_DENIED", "admission scope belongs to another principal");
  }
  if (request.expectedAuthorizationGeneration !== state.authorizationGeneration) {
    sessionError("STALE_GENERATION", "admission authority is stale");
  }
}

export async function validateSessionAdmissionPlanningDigests(request: SessionAdmissionPlanningRequest): Promise<void> {
  const messages = (request.input as { messages: { role: string; content: string }[] }).messages
    .map((message) => [message.role, message.content]);
  if (await digestStructuredValue("circulusd.session.turn-input", 1, request.input) !== request.inputDigest ||
    await digestStructuredValue("circulusd.public.turn.create", 1, { sessionId: request.sessionId, messages }) !== request.requestDigest) {
    sessionError("DIGEST_MISMATCH", "admission digests do not bind the full input");
  }
}

export async function planSessionAdmission(state: SessionAggregateState, request: SessionAdmissionPlanningRequest,
  receipt: TurnAdmissionReceipt | null, now: number, ttl: number): Promise<NormalizedValue> {
  const scope = {
    tenantId: state.tenantId, workspaceId: state.workspaceId, actorSubjectId: state.userId,
    sessionId: state.sessionId, expectedAuthorizationGeneration: state.authorizationGeneration,
    proposedTurnId: request.proposedTurnId, inputDigest: request.inputDigest,
    idempotencyKeyDigest: request.idempotencyKeyDigest, requestDigest: request.requestDigest,
  };
  if (receipt !== null) {
    if (receipt.idempotencyKeyDigest !== request.idempotencyKeyDigest) sessionError("FAILED_PRECONDITION", "archived admission identity changed");
    if (receipt.inputDigest !== request.inputDigest || receipt.requestDigest !== request.requestDigest) {
      sessionError("IDEMPOTENCY_CONFLICT", "admission key was reused with another input");
    }
    return { kind: "replay", ...scope, admission: { turnId: receipt.turnId, turnSequence: receipt.turnSequence,
      activated: receipt.activated, version: state.eventSequence } };
  }
  if ((state.status !== "ready" && state.status !== "running") || state.runtimePointer.candidateRevision !== null) {
    sessionError("FAILED_PRECONDITION", "Session is not accepting new turns");
  }
  if (state.activeTurn?.status === "needs_confirmation") sessionError("NEEDS_CONFIRMATION", "Session requires confirmation");
  const leaseGeneration = state.nextTurnSequence + 1;
  if (!Number.isSafeInteger(now) || now < 0 || !Number.isSafeInteger(now + ttl) ||
    !Number.isSafeInteger(leaseGeneration) || !Number.isSafeInteger(state.eventSequence + 1)) {
    sessionError("FAILED_PRECONDITION", "admission time or generation is exhausted");
  }
  const commandDigest = await digestStructuredValue("circulusd.session.admission-plan-command", 1, request as unknown as NormalizedValue);
  return { kind: "new", ...scope, commandId: `admission:${commandDigest}`,
    expectedEventSequence: state.eventSequence, turnLeaseGeneration: leaseGeneration,
    leaseExpiresAt: now + ttl, plannedAt: now,
    runtime: { runtimeRevisionDigest: state.runtimeRevisionDigest, engineKind: state.engineKind,
      adapterAbiVersion: state.adapterAbiVersion, checkpointSchemaVersion: state.checkpointSchemaVersion } };
}
